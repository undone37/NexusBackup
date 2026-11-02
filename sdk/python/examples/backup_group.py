#!/usr/bin/env python3
"""Back up a protection group now, wait for the job, then list the group's newest snapshots.

Uses an operator API token (My account -> API tokens, scope Operator or Backup). With --keep-until beyond the
allowed days the request needs approval: the script prints the approval request and stops.

    export NEXUS_URL=https://backup.example.com:8443
    export NEXUS_TOKEN=nxt_...
    export NEXUS_FINGERPRINT=AB:CD:...       # Settings -> Certificate; python3 -m nexusbackup fingerprint URL
    python3 backup_group.py --group web
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

from nexusbackup import Client, JobFailedError, NexusBackupError


def main() -> int:
    p = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    p.add_argument("--group", required=True, help="the group's name or id")
    p.add_argument("--failed-only", action="store_true", help="only the members whose last backup failed")
    p.add_argument("--keep-until", help="lock the new snapshots until this day (YYYY-MM-DD)")
    p.add_argument("--timeout", type=float, default=4 * 3600, help="seconds to wait (default 4 h)")
    a = p.parse_args()

    c = Client.from_env()
    try:
        print("API version", c.check_compatibility())
        groups = c.list_groups()
        group = next((g for g in groups if a.group in (str(g["id"]), g["name"])), None)
        if group is None:
            print("no such group; groups:", ", ".join(g["name"] for g in groups))
            return 2
        keep = None
        if a.keep_until:
            keep = datetime.strptime(a.keep_until, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        print(f"backing up {group['name']} (tenant {group['tenant']}) ...")
        out = c.backup_group(
            group["id"], tenant=group["tenant"], failed_only=a.failed_only, keep_until=keep, timeout=a.timeout
        )
        if out.approval_pending:
            print(f"the request needs approval: approval request {out.quorum_id} (Approvals in the web UI)")
            return 0
        job = out.job or {}
        print(f"job {out.job_id}: {job.get('state')}, finished {job.get('finished')}")
        snaps = [s for s in c.list_snapshots(tenant=group["tenant"]) if s.get("time", 0) >= (job.get("started") or 0)]
        for s in snaps[:10]:
            name = s.get("label") or s.get("source")
            print(f"  {name}  {s.get('time')}  {s.get('size')} bytes, locked until {s.get('lock_until')}")
    except JobFailedError as e:
        print(f"job {e.job_id} {e.state}: {e.reason}")
        return 1
    except NexusBackupError as e:
        print("error:", e)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
