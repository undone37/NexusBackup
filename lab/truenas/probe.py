#!/usr/bin/env python3
"""Probes the appliance key on the TrueNAS lab VM: everything but the forced
command's protocol must be refused (shell, sftp, port forwarding, tty, symlink escape).

  probe.py        exit 0 if every probe behaves
"""
import os
import subprocess
import sys

LAB = os.environ.get("LAB", "/home/ah/nexus-lab")
D = f"{LAB}/truenas"
BASE = ["ssh", "-p", "12222", "-i", f"{D}/nexus_ed25519", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={D}/known_hosts", "-o", "ConnectTimeout=10"]
TARGET = "nexusbackup@127.0.0.1"


def run(extra, cmd=None, stdin=b"", timeout=30):
    args = BASE + extra + [TARGET] + ([cmd] if cmd is not None else [])
    try:
        r = subprocess.run(args, input=stdin, capture_output=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return -1, b"", "timeout"


ok = True


def expect(name, cond, detail=""):
    global ok
    print(("ok   " if cond else "FAIL ") + name + ("" if cond else f": {detail}"))
    ok &= cond


rc, out, err = run([], "hello")
expect("hello answers", rc == 0 and out.startswith(b"nexus-fc 1"), err)
for cmd in ["id", "bash -i", "cat /etc/shadow", "walk tank/other nexus-1-1", "walk tank/data nexus-1-1;id",
            "read tank/data ../x", "diff tank/data x y", ""]:
    rc, out, err = run([], cmd)
    expect(f"refused {cmd!r}", rc != 0 and b"uid=" not in out and "nexus-fc" in err, f"rc={rc} out={out[:80]!r} {err}")
rc, out, err = run(["-s"], "sftp")
expect("sftp subsystem refused", rc != 0 and not out.startswith(b"\x00\x00"), f"rc={rc} {err}")
rc, out, err = run(["-t"], "hello")
expect("no tty", "PTY allocation request failed" in err or rc != 0 or b"nexus-fc" in out, err)
rc, out, err = run(["-N", "-L", "12345:127.0.0.1:443", "-o", "ExitOnForwardFailure=yes"], None, timeout=10)
expect("port forwarding refused", rc != 0, f"rc={rc} {err}")
# symlinks inside a snapshot (data.sh: links/root -> /, links/shadow -> /etc/shadow)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import asyncio  # noqa: E402
import tn  # noqa: E402


async def snaps():
    ws, rpc = await tn.connect()
    async with ws:
        return await rpc.call("pool.snapshot.query", [["dataset", "=", "tank/data"]], {"select": ["snapshot_name"]})

names = [s["snapshot_name"] for s in asyncio.run(snaps()) if s["snapshot_name"].startswith("nexus-")]
if names:
    snap = names[-1]
    for path in [b"links/root/etc/shadow", b"links/shadow", b"links/root", b"links/../../../etc/shadow"]:
        rc, out, err = run([], f"read tank/data {snap}", path + b"\0")
        expect(f"no read of {path.decode()}", rc != 0 and b"root:" not in out and "nexus-fc: " in err, err)
    rc, out, err = run([], f"read tank/data {snap}", b"secret/key.txt\0")
    expect("root-only file readable through sudo", rc == 0 and b"topsecret" in out, err)
else:
    expect("a nexus snapshot of tank/data exists (run a backup first)", False)
sys.exit(0 if ok else 1)
