#!/usr/bin/env python3
"""Minimal QMP client: qmp.py SOCKET COMMAND [JSON-ARGS]
e.g. qmp.py pve1.qmp system_powerdown
     qmp.py install.qmp screendump '{"filename":"/tmp/s.png","format":"png"}'"""
import json
import socket
import sys

sock = socket.socket(socket.AF_UNIX)
sock.connect(sys.argv[1])
f = sock.makefile("rw")
f.readline()  # greeting
cmds = [{"execute": "qmp_capabilities"}, {"execute": sys.argv[2]}]
if len(sys.argv) > 3:
    cmds[1]["arguments"] = json.loads(sys.argv[3])
for c in cmds:
    f.write(json.dumps(c) + "\n")
    f.flush()
    while True:  # skip async events
        r = json.loads(f.readline())
        if "event" not in r:
            break
print(json.dumps(r))
sys.exit(1 if "error" in r else 0)
