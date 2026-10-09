#!/usr/bin/env python3
"""Run a local shell script on the TrueNAS lab VM as truenas_admin (lab key, pinned host key).

  sh.py SCRIPT [ARGS...]     script is sent on stdin to `bash -s -- ARGS`; exit status is passed on
"""
import os
import subprocess
import sys

LAB = os.environ.get("LAB", "/home/ah/nexus-lab")
D = f"{LAB}/truenas"
if len(sys.argv) < 2:
    sys.exit(__doc__)
with open(sys.argv[1], "rb") as f:
    r = subprocess.run(
        ["ssh", "-p", "12222", "-i", f"{D}/admin_ed25519", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", f"UserKnownHostsFile={D}/known_hosts", "truenas_admin@127.0.0.1", "bash", "-s", "--", *sys.argv[2:]],
        stdin=f,
    )
sys.exit(r.returncode)
