"""NexusBackup for PegaProx: the parts without Flask or PegaProx (tested by test_core.py).

The plugin reads NexusBackup's REST API with an API token (scope `read`, or `backup` to start backups) and
shows, per Proxmox VE guest of a PegaProx cluster, the protection group, the newest backup and its age against
the group's schedule, the next scheduled run, the retention lock, the newest restore test and open alerts.
"""
import hashlib
import hmac
import http.client
import json
import re
import ssl
import urllib.parse

# a backup is "late" when it is older than this many schedule periods (one missed run is tolerated)
LATE_PERIODS = 2


def schedule_period(schedule):
    """Seconds between two runs of a NexusBackup schedule (`daily 22:00`, `every 4h`, `every 15m`,
    `weekly sun 03:00`, `monthly 1 02:00`, `hourly`), None when unknown."""
    s = (schedule or "").strip().lower()
    m = re.match(r"^every\s+(\d+)\s*([mhd])\b", s)
    if m:
        return int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
    for word, secs in (("hourly", 3600), ("daily", 86400), ("weekly", 7 * 86400), ("monthly", 31 * 86400)):
        if s.startswith(word):
            return secs
    return None


def guest_rows(vms, tenant, groups, policies, snapshots, tests, alerts, now, source_id=None):
    """One row per PegaProx guest (`vms`: dicts with vmid, name, type, status) with its NexusBackup state.

    `groups`, `policies`, `snapshots`, `tests`, `alerts` are the JSON lists of the NexusBackup API (GET /groups,
    /policies, /snapshots, /restore-tests, /alerts) for the cluster's tenant; `source_id` limits the groups to one
    NexusBackup PVE source (two clusters in one tenant share `vm-<vmid>` snapshot names)."""
    pol = {p["id"]: p for p in policies}
    mine = [g for g in groups if g.get("tenant") == tenant and (source_id is None or g.get("source_id") == source_id)]
    newest = {}
    for s in snapshots:
        if s.get("tenant") != tenant:
            continue
        cur = newest.get(s["source"])
        if cur is None or s["time"] > cur["time"]:
            newest[s["source"]] = s
    tested = {}
    for t in tests:
        if t.get("tenant") == tenant and (t["source"] not in tested or t["finished"] > tested[t["source"]]["finished"]):
            tested[t["source"]] = t
    rows = []
    for vm in vms:
        vmid = int(vm["vmid"])
        source = f"{'ct' if vm.get('type') == 'lxc' else 'vm'}-{vmid}"
        group = next((g for g in mine if vmid in [int(x) for x in g.get("resolved_guests") or g.get("guests") or []
                                                    if str(x).isdigit()]), None)
        snap = newest.get(source)
        period = schedule_period(pol.get(group["policy_id"], {}).get("schedule")) if group else None
        age = now - snap["time"] if snap else None
        last_job = (group or {}).get("last_backup") or {}
        open_alerts = [a for a in alerts if a.get("tenant") == tenant and not a.get("resolved_at")
                       and source in (a.get("key") or "")]
        if group is None:
            state = "unprotected"
        elif snap is None:
            state = "never"
        elif last_job.get("state") == "failed" or (period and age > LATE_PERIODS * period):
            state = "late"
        else:
            state = "ok"
        test = tested.get(source)
        rows.append({
            "vmid": vmid,
            "name": vm.get("name") or source,
            "type": vm.get("type", "qemu"),
            "status": vm.get("status"),
            "source": source,
            "state": state,
            "group": group and {"id": group["id"], "name": group["name"],
                                "policy": pol.get(group["policy_id"], {}).get("name"),
                                "next_backup": group.get("next_backup"),
                                "paused": bool(group.get("paused_until"))},
            "last_backup": snap and {"time": snap["time"], "age_s": age, "lock_until": snap.get("lock_until"),
                                     "offsite": bool(snap.get("offsite"))},
            "restore_test": test and {"state": test["state"], "finished": test["finished"]},
            "alerts": [a.get("message", "") for a in open_alerts][:5],
        })
    return rows


def summary(rows):
    out = {"total": len(rows)}
    for r in rows:
        out[r["state"]] = out.get(r["state"], 0) + 1
    return out


class Appliance:
    """A NexusBackup appliance: base URL, API token and the SHA-256 of its certificate (DER, hex, colons
    allowed). The certificate is pinned: appliances use a self-signed one by default, and a pin is stricter
    than a CA anyway."""

    def __init__(self, url, token, cert_sha256, timeout=10):
        if not url.startswith("https://"):
            raise ValueError("url: https:// only")
        if not token.startswith("nxt_"):
            raise ValueError("token: a NexusBackup API token (nxt_...)")
        self.url = url.rstrip("/")
        self.token = token
        self.pin = cert_sha256.replace(":", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", self.pin):
            raise ValueError("cert_sha256: the SHA-256 of the appliance certificate (64 hex digits)")
        self.timeout = timeout

    def call(self, method, path, body=None):
        u = urllib.parse.urlsplit(self.url)
        # the pin replaces CA and host name checks: verified on the open connection, before the token is sent
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=self.timeout)
        try:
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True)
            if der is None or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self.pin):
                raise RuntimeError("the appliance certificate does not match cert_sha256 (nothing was sent)")
            conn.request(method, "/api/v1" + path, body=None if body is None else json.dumps(body), headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            })
            r = conn.getresponse()
            data = r.read(32 << 20)
        except (OSError, http.client.HTTPException) as e:
            raise RuntimeError(f"NexusBackup not reachable: {e}") from None
        finally:
            conn.close()
        try:
            v = json.loads(data or b"null")
        except ValueError:
            v = None
        if r.status >= 400:
            msg = v.get("error") if isinstance(v, dict) else None
            raise RuntimeError(f"NexusBackup answered {r.status}: {msg or r.reason}")
        return v

    def state(self, tenant):
        q = f"?tenant={urllib.parse.quote(tenant)}"
        return {
            "groups": self.call("GET", "/groups"),
            "policies": self.call("GET", "/policies"),
            "snapshots": self.call("GET", "/snapshots" + q),
            "tests": self.call("GET", "/restore-tests" + q),
            "alerts": self.call("GET", "/alerts"),
        }

    def backup(self, tenant, group_id, vmid):
        """Starts a backup of one guest of its group (a `backup` or `operator` token)."""
        return self.call("POST", "/jobs", {"kind": "backup", "tenant": tenant,
                                           "params": {"group_id": group_id, "guests": [vmid]}})
