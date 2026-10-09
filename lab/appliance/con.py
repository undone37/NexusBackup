#!/usr/bin/env python3
"""Drives the lab appliance's serial console (root autologin, lab image only).

  con.py wait [timeout]            wait for the root shell
  con.py run 'cmd' [timeout]       run a shell command, print its output, exit with its status
  con.py put LOCAL REMOTE [mode]   copy a file (base64 over the console)
  con.py get REMOTE                print a remote file (base64 over the console)
  con.py script FILE [timeout]     run a local shell script in the VM

env CONSOLE: console socket (default /home/ah/nexus-lab/appliance/console.sock)
"""
import base64
import os
import re
import secrets
import socket
import sys
import time

SOCK = os.environ.get("CONSOLE", "/home/ah/nexus-lab/appliance/console.sock")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\r")


class Console:
    def __init__(self):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        self.buf = b""

    def send(self, data: bytes):
        self.s.sendall(data)

    def until(self, pattern: bytes, timeout: float):
        rx = re.compile(pattern, re.S)
        end = time.time() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[: m.start()], self.buf[m.end():]
                return out, m
            left = end - time.time()
            if left <= 0:
                raise TimeoutError(f"no {pattern!r} within {timeout}s; got {self.buf[-400:]!r}")
            self.s.settimeout(min(left, 1.0))
            try:
                d = self.s.recv(65536)
            except socket.timeout:
                continue
            if not d:
                raise EOFError("console closed")
            self.buf += d

    def shell(self, timeout=300):
        """Gets a clean prompt-less shell: no echo, no kernel messages on the console."""
        tok = secrets.token_hex(4)
        end = time.time() + timeout
        while True:
            self.send(b"\x03\n stty -echo; bind \'set enable-bracketed-paste off\' 2>/dev/null; PS1=; PS2=; export PAGER=cat SYSTEMD_PAGER= SYSTEMD_COLORS=0 TERM=dumb; dmesg -n 1 2>/dev/null; echo READY-" + tok.encode() + b"\n")
            try:
                self.until(b"READY-" + tok.encode() + b"\r?\n", 5)
                return
            except TimeoutError:
                if time.time() > end:
                    raise

    def run(self, cmd: str, timeout=600):
        tok = secrets.token_hex(6)
        self.send((cmd + f"\n echo END-{tok}-$?-\n").encode())
        out, m = self.until(rf"END-{tok}-(\d+)-\r?\n".encode(), timeout)
        return ANSI.sub(b"", out), int(m.group(1))


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    c = Console()
    if a[0] == "wait":
        c.shell(float(a[1]) if len(a) > 1 else 600)
        return
    c.shell(30)
    if a[0] == "run":
        out, rc = c.run(a[1], float(a[2]) if len(a) > 2 else 600)
        sys.stdout.buffer.write(out)
        sys.exit(rc)
    if a[0] == "put":
        data = base64.b64encode(open(a[1], "rb").read()).decode()
        remote = a[2]
        mode = a[3] if len(a) > 3 else "0600"
        tmp = f"/run/con-put-{secrets.token_hex(4)}"
        c.run(f"umask 077; : > {tmp}")
        for i in range(0, len(data), 1000):
            c.run(f"echo {data[i:i + 1000]} >> {tmp}")
        out, rc = c.run(f"base64 -d {tmp} > '{remote}' && chmod {mode} '{remote}'; r=$?; rm -f {tmp}; exit_ok() {{ return $r; }}; exit_ok")
        sys.stdout.buffer.write(out)
        sys.exit(rc)
    if a[0] == "script":
        data = base64.b64encode(open(a[1], "rb").read()).decode()
        tmp = f"/run/con-script-{secrets.token_hex(4)}.sh"
        c.run(f"umask 077; : > {tmp}")
        for i in range(0, len(data), 1000):
            c.run(f"echo {data[i:i + 1000]} >> {tmp}.b64")
        out, rc = c.run(
            f"base64 -d {tmp}.b64 > {tmp}; rm -f {tmp}.b64; bash {tmp} {' '.join(a[3:])}; r=$?; rm -f {tmp}; (exit $r)",
            float(a[2]) if len(a) > 2 else 600,
        )
        sys.stdout.buffer.write(out)
        sys.exit(rc)
    if a[0] == "get":
        out, rc = c.run(f"base64 -w0 '{a[1]}'; echo")
        if rc == 0:
            sys.stdout.buffer.write(base64.b64decode(out.strip()))
        sys.exit(rc)
    print(__doc__, file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
