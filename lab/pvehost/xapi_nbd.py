#!/usr/bin/env python3
"""XAPI JSON-RPC over HTTPS as the XCP-ng connector would use it (lab, #40): login, the NBD export of a VDI.
  xapi_nbd.py HOST VDI_UUID   (root password on stdin) -> {"export", "address", "port", "subject"}
"""
import json, ssl, sys, urllib.request
host, vdi_uuid = sys.argv[1], sys.argv[2]
pw = sys.stdin.readline().strip()
ctx = ssl._create_unverified_context()  # lab: the host's self-signed certificate
n = 0
def call(method, *params):
    global n
    n += 1
    body = json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": n}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(f"https://{host}/jsonrpc", body,
                                                                 {"Content-Type": "application/json"}), context=ctx))
    if "error" in r:
        sys.exit(f"{method}: {r['error']}")
    return r["result"]
s = call("session.login_with_password", "root", pw, "1.0", "nexus-lab-https")
vdi = call("VDI.get_by_uuid", s, vdi_uuid)
info = call("VDI.get_nbd_info", s, vdi)[0]
print(json.dumps({"export": info["exportname"], "address": info["address"], "port": info["port"], "subject": info["subject"]}))
