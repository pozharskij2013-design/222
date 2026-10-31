#!/usr/bin/env python3
import os, pty, select, subprocess, sys, time, signal

HOST = "icssys2xpbxp94s8@instances.ctfcup.online"
cmds = open("probe/cmds.txt", "rb").read()
timeout_total = int(os.environ.get("DRIVE_TIMEOUT", "90"))

master, slave = pty.openpty()
proc = subprocess.Popen(
    ["ssh", "-tt", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
     "-o", "ConnectTimeout=15", "-o", "LogLevel=ERROR", HOST],
    stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    env={**os.environ, "TERM": "dumb"})
os.close(slave)
os.set_blocking(master, False)

out = bytearray()
start = time.time()
sent = False
last_rx = time.time()
while time.time() - start < timeout_total:
    r, _, _ = select.select([master], [], [], 0.2)
    if master in r:
        try:
            data = os.read(master, 65536)
        except OSError:
            break
        if not data:
            break
        out += data
        last_rx = time.time()
    if not sent and (time.time() - last_rx > 2.5 or time.time() - start > 12):
        os.write(master, b"\n")
        time.sleep(0.5)
        os.write(master, cmds.replace(b"\n", b"\r\n"))
        os.write(master, b"echo DONE_$((6*7))\r\n")
        sent = True
    if sent and b"DONE_42" in bytes(out):
        break
    if proc.poll() is not None:
        break

open("/tmp/out.txt", "wb").write(bytes(out))
try:
    proc.kill()
except Exception:
    pass
print(f"captured {len(out)} bytes, sent={sent}", file=sys.stderr)
