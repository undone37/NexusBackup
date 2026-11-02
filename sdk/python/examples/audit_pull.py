#!/usr/bin/env python3
"""Read-only reporting with an API token: failed jobs and open alerts of the last day, then a SIEM-style pull of
the audit log: every entry after the last seq seen (kept in a state file), one JSON object per line.

    export NEXUS_URL=https://backup.example.com:8443
    export NEXUS_TOKEN=nxt_...            # My account -> API tokens, scope Read only (a security officer's)
    export NEXUS_CA=/etc/ssl/nexusbackup-ca.pem
    python3 audit_pull.py audit.seq >> audit.jsonl
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from nexusbackup import Client


def main() -> int:
    state = Path(sys.argv[1] if len(sys.argv) > 1 else "audit.seq")
    c = Client.from_env()
    day = int(time.time()) - 86400
    for j in c.list_jobs(state="failed", limit=200):
        if (j.get("finished") or 0) >= day:
            print(f"failed job {j['id']:>7} {j['kind']:<16} {j['tenant']}", file=sys.stderr)
    for a in c.list_alerts(state="open"):
        print(f"open alert {a.get('severity', ''):<8} {a.get('message', '')}", file=sys.stderr)
    after = int(state.read_text()) if state.exists() else None
    last = after
    for e in c.iter_audit(after=after, page_size=1000):
        print(json.dumps(e, separators=(",", ":")))
        last = e["seq"]
    if last is not None:
        state.write_text(f"{last}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
