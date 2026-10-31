#!/usr/bin/env python3
import os, re, ssl, sys, urllib.request, urllib.error, urllib.parse, hashlib

HOST = "9taux6shw8cpbvs5.instances.ctfcup.online"
OUT = "/tmp/web-out"
os.makedirs(OUT, exist_ok=True)
ctx = ssl._create_unverified_context()
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
seen = set()
results = []

def safe_name(url):
    p = urllib.parse.urlparse(url)
    s = (p.scheme + "_" + p.netloc + p.path + ("_" + p.query if p.query else ""))
    return re.sub(r'[^A-Za-z0-9_.-]+', '_', s).strip('_')[:180] or 'root'

def fetch(url, method='GET', data=None, extra=None, save=True):
    if url in seen:
        return None
    seen.add(url)
    h = {"User-Agent": UA, "Accept": "*/*", "Accept-Language": "ru,en;q=0.8"}
    if extra:
        h.update(extra)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with opener.open(req, timeout=15) as r:
            body = r.read(2_000_000)
            status = r.status
            headers = list(r.headers.items())
    except urllib.error.HTTPError as e:
        body = e.read(2_000_000)
        status = e.code
        headers = list(e.headers.items())
    except Exception as e:
        results.append(f"ERROR {method} {url}: {type(e).__name__}: {e}")
        return None
    sha = hashlib.sha256(body).hexdigest()[:12]
    fn = safe_name(url) + f".{status}.{sha}.bin"
    if save:
        open(os.path.join(OUT, fn), 'wb').write(body)
    text = body[:2500].decode('utf-8', 'replace').replace('\r', '\\r')
    results.append(f"=== {method} {url}\nSTATUS {status} BYTES {len(body)} SHA {sha} FILE {fn}\n" +
                   "\n".join(f"{k}: {v}" for k, v in headers) + "\n---BODY---\n" + text + "\n")
    return status, headers, body

# DNS and roots
roots = []
for scheme in ('http', 'https'):
    r = fetch(f'{scheme}://{HOST}/')
    if r:
        roots.append((f'{scheme}://{HOST}/', r))

# Crawl same-origin asset/link URLs found in root bodies (bounded)
queue = []
for base, (_, _, body) in roots:
    txt = body.decode('utf-8', 'replace')
    for m in re.finditer(r'''(?:href|src|action)=["']([^"']+)["']''', txt, re.I):
        u = urllib.parse.urljoin(base, m.group(1))
        if urllib.parse.urlparse(u).netloc == HOST:
            queue.append(u)
    # URLs in JS-ish text
    for m in re.finditer(r'''["']((?:/|https?://)[^"'\s<>]{1,240})["']''', txt):
        u = urllib.parse.urljoin(base, m.group(1))
        if urllib.parse.urlparse(u).netloc == HOST and len(queue) < 250:
            queue.append(u)

for u in queue[:80]:
    fetch(u)

# Common paths on both schemes, bounded and informative
paths = [
 '/robots.txt','/sitemap.xml','/.well-known/security.txt','/favicon.ico',
 '/login','/logout','/admin','/panel','/console','/dashboard','/status','/health','/healthz',
 '/api','/api/','/api/status','/api/health','/api/info','/api/version','/api/openapi.json','/openapi.json',
 '/swagger','/swagger/','/docs','/redoc','/api/docs','/debug','/metrics','/config','/settings',
 '/cgi-bin/luci','/luci','/ubus','/rpc','/jsonrpc','/tr069','/acs','/management','/maintenance',
 '/diag','/diagnostics','/trace','/ping','/terminal','/shell','/ws','/socket.io/','/sockjs-node/info',
 '/.git/HEAD','/.env','/backup','/dump','/logs','/log','/session','/sessions','/memory','/pcap','/capture'
]
for scheme in ('http', 'https'):
    for p in paths:
        fetch(f'{scheme}://{HOST}{p}', save=False)

open(os.path.join(OUT, 'SUMMARY.txt'), 'w', encoding='utf-8').write("\n".join(results))
print(f"wrote {len(results)} results")
