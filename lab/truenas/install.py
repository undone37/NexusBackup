#!/usr/bin/env python3
"""Unattended TrueNAS install through the installer's own JSON-RPC 2.0 WebSocket API
(`python3 -m truenas_installer --server`, port 8080, started by the live ISO).

  install.py ws://127.0.0.1:18080/ws [admin-password]

Installs to the 20 GB disk (the two 8 GB disks stay for the data pool), creates the
`truenas_admin` user with the given password (or a random one, written to
$LAB/truenas/admin-password), then powers the installer off.
"""
import asyncio
import json
import os
import secrets
import sys
import time

import websockets

URL = sys.argv[1]
PW = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else secrets.token_urlsafe(18)
LAB = os.environ.get("LAB", "/home/ah/nexus-lab")


class Rpc:
    def __init__(self, ws):
        self.ws, self.n = ws, 0

    async def call(self, method, *params, timeout=60):
        self.n += 1
        await self.ws.send(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": list(params)}))
        end = time.time() + timeout
        while True:
            msg = json.loads(await asyncio.wait_for(self.ws.recv(), max(1, end - time.time())))
            if msg.get("method") == "installation_progress":
                p = msg["params"][0]
                print(f"  [{int(p['progress'] * 100):3d}%] {p['message']}", flush=True)
                continue
            if msg.get("id") != self.n:
                continue
            if "error" in msg:
                raise RuntimeError(f"{method}: {msg['error']}")
            return msg.get("result")


async def main():
    end = time.time() + 600
    while True:
        try:
            ws = await websockets.connect(URL, open_timeout=5, max_size=2**24)
            break
        except Exception as e:  # installer still booting
            if time.time() > end:
                raise SystemExit(f"installer API not reachable: {e}")
            await asyncio.sleep(5)
    async with ws:
        rpc = Rpc(ws)
        info = await rpc.call("system_info")
        print("installer:", info, flush=True)
        if not await rpc.call("is_adopted"):
            await rpc.call("adopt")
        disks = await rpc.call("list_disks")
        boot = [d["name"] for d in disks if 18 << 30 < d["size"] < 22 << 30]
        if len(boot) != 1:
            raise SystemExit(f"cannot pick the boot disk from {disks}")
        print("installing to", boot[0], flush=True)
        await rpc.call(
            "install",
            {"disks": boot, "set_pmbr": False, "authentication": {"username": "truenas_admin", "password": PW}},
            timeout=1800,
        )
        os.makedirs(f"{LAB}/truenas", exist_ok=True)
        fd = os.open(f"{LAB}/truenas/admin-password", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, PW.encode() + b"\n")
        os.close(fd)
        print("installation completed", flush=True)


asyncio.run(main())
