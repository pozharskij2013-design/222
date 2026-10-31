#!/usr/bin/env python3
import os, pty, select, subprocess, sys, time

HOST = "pfe1fsab36w2q3rc@instances.ctfcup.online"
blob = open(sys.argv[1], "rb").read() if len(sys.argv) > 1 else b""

master, slave = pty.openpty()
proc = subprocess.Popen(
    ["ssh", "-tt", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
     "-o", "ConnectTimeout=15", "-o", "LogLevel=ERROR", HOST],
    stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    env={**os.environ, "TERM": "dumb"})
os.close(slave)
os.set_blocking(master, False)

buf = bytearray()
pos = 0

def pump():
    global buf
    try:
        while True:
            r, _, _ = select.select([master], [], [], 0)
            if master not in r:
                break
            d = os.read(master, 65536)
            if not d:
                break
            buf += d
    except OSError:
        pass

def wait_for(marker, timeout=30):
    global pos
    end = time.time() + timeout
    while time.time() < end:
        pump()
        i = buf.find(marker, pos)
        if i >= 0:
            pos = i + len(marker)
            return True
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    pump()
    i = buf.find(marker, pos)
    if i >= 0:
        pos = i + len(marker)
        return True
    print(f"TIMEOUT waiting {marker!r}", file=sys.stderr)
    return False

def send(line):
    os.write(master, line.encode() + b"\r\n")

def cmd(line, marker, timeout=30):
    send(line)
    return wait_for(marker, timeout)

# boot
wait_for(b"built-in shell", 25)
time.sleep(1)
cmd("export PS1='P> '; echo READ''Y1", b"READY1", 20)

# test printf escapes: A \102=B C \x44=D E  -> "ABCDE" if \x supported
segstart = pos
cmd(r"printf 'A\102C\x44E\n'; echo TST''9", b"TST9", 20)
testseg = bytes(buf[segstart:pos])
hex_ok = b"ABCDE" in testseg
print("hex_ok:", hex_ok, "testseg:", testseg[-120:], file=sys.stderr)

# upload blob via printf escapes
FNAME = f"/tmp/e{int(time.time()) % 10000000}"
CH = 120
n = 0
for off in range(0, len(blob), CH):
    chunk = blob[off:off + CH]
    if hex_ok:
        esc = "".join(f"\\x{b:02x}" for b in chunk)
    else:
        esc = "".join(f"\\{b:03o}" for b in chunk)
    redir = ">" if off == 0 else ">>"
    marker = f"UPK{n}".encode()
    ok = cmd(f"printf '{esc}' {redir} {FNAME}; echo UPK''{n}", marker, 30)
    if not ok:
        print(f"upload failed at chunk {n}", file=sys.stderr)
        break
    n += 1

cmd(f"ls -la {FNAME}; echo LSZ''1", b"LSZ1", 20)
cmd(f"echo BCAT''_S; cat {FNAME}; echo BCAT''_E", b"BCAT_E", 30)
cmd(f"chmod 755 {FNAME}; echo CHM''1", b"CHM1", 20)
send(FNAME)
send("echo RC=$?; echo ALL''DONE")
wait_for(b"ALLDONE", 90)
time.sleep(1)
pump()

open("/tmp/out.txt", "wb").write(bytes(buf))
try:
    proc.kill()
except Exception:
    pass
print(f"captured {len(buf)} bytes, blob {len(blob)} bytes in {n} chunks", file=sys.stderr)
