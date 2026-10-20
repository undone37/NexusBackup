#!/usr/bin/env python3
"""Small TrueNAS JSON-RPC 2.0 WebSocket client for the lab (wss://…/api/current).

  tn.py call METHOD [JSON-PARAMS...]     login as truenas_admin, print the result as JSON
  tn.py cert                             print the API certificate (PEM)

env TN_URL (default wss://$TN_HOST:$TN_API_PORT/api/current; TN_HOST 127.0.0.1, TN_API_PORT 18444: the local
QEMU lab; a VM on the PVE lab host: TN_HOST=<its address> TN_API_PORT=443 TN_SSH_PORT=22), LAB (default /home/ah/nexus-lab)
Lab only: the certificate is not verified here (provision.py pins it for the appliance).
"""
import asyncio
import json
import os
import ssl
import sys
import time

import websockets

LAB = os.environ.get("LAB", "/home/ah/nexus-lab")
HOST = os.environ.get("TN_HOST", "127.0.0.1")
SSH_PORT = os.environ.get("TN_SSH_PORT", "12222")
URL = os.environ.get("TN_URL", f"wss://{HOST}:{os.environ.get('TN_API_PORT', '18444')}/api/current")


class Rpc:
    def __init__(self, ws):
        self.ws, self.n = ws, 0

    async def call(self, method, *params, timeout=300):
        self.n += 1
        await self.ws.send(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": list(params)}))
        end = time.time() + timeout
        while True:
            msg = json.loads(await asyncio.wait_for(self.ws.recv(), max(1, end - time.time())))
            if msg.get("id") != self.n:
                continue  # notifications
            if "error" in msg:
                raise RuntimeError(f"{method}: {json.dumps(msg['error'])[:2000]}")
            return msg.get("result")

    async def job(self, method, *params, timeout=900):
        """Calls a job method and waits for it; returns the job result."""
        jid = await self.call(method, *params)
        end = time.time() + timeout
        while time.time() < end:
            j = (await self.call("core.get_jobs", [["id", "=", jid]]))[0]
            if j["state"] == "SUCCESS":
                return j["result"]
            if j["state"] in ("FAILED", "ABORTED"):
                raise RuntimeError(f"{method}: job {j['state']}: {j.get('error')}")
            await asyncio.sleep(2)
        raise TimeoutError(f"{method}: job {jid} still running")


def ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


async def connect(password=None):
    ws = await websockets.connect(URL, ssl=ctx(), max_size=2**26, open_timeout=20)
    rpc = Rpc(ws)
    pw = password or open(f"{LAB}/truenas/admin-password").read().strip()
    r = await rpc.call("auth.login_ex", {"mechanism": "PASSWORD_PLAIN", "username": "truenas_admin", "password": pw})
    if r.get("response_type") != "SUCCESS":
        raise SystemExit(f"login failed: {r}")
    return ws, rpc


def cert_pem():
    host, port = URL.split("//")[1].split("/")[0].rsplit(":", 1)
    return ssl.get_server_certificate((host, int(port)))


async def main():
    a = sys.argv[1:]
    if a[:1] == ["cert"]:
        print(cert_pem(), end="")
        return
    if a[:1] != ["call"] or len(a) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    ws, rpc = await connect()
    async with ws:
        print(json.dumps(await rpc.call(a[1], *[json.loads(p) for p in a[2:]]), indent=1))


if __name__ == "__main__":
    asyncio.run(main())
