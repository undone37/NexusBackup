# nexusbackup: Python SDK for the NexusBackup REST API

A synchronous client for the NexusBackup appliance (`/api/v1`), standard library only, Python 3.10+, typed
(`py.typed`). Overview, design and versioning: [`sdk/README.md`](../README.md).

```sh
pip install ./sdk/python            # from a checkout; nothing is published to PyPI yet
```

## Connecting

```python
import os
from nexusbackup import Client

# API token (My account -> API tokens; scope Read only, Operator or Backup)
c = Client("https://backup.example.com:8443", token=os.environ["NEXUS_TOKEN"], ca_file="nexus-ca.pem")

# or from the environment, as nexusctl: NEXUS_URL, NEXUS_TOKEN, NEXUS_CA, and NEXUS_FINGERPRINT
c = Client.from_env()

# a person (what tokens never do: approve, the audit CSV, the restore point simulator); signs out at the end
with Client.login("https://192.0.2.10:8443", "alice", password, totp="123456", fingerprint="AB:CD:...") as sec:
    sec.approve(12)
```

TLS: the system trust store by default; `ca_file=` / `ca_data=` trust only that CA or the appliance's self-signed
certificate (its name must match the URL); `fingerprint=` pins the certificate's SHA-256 (`AB:CD:...` as shown under
Settings -> Certificate, or plain hex) and skips the name and chain checks; `verify=False` checks nothing. To read
a server's fingerprint for trust on first use: `python3 -m nexusbackup fingerprint https://192.0.2.10:8443`, then
compare it with the appliance's before pinning it.

## Workflows

```python
from nexusbackup import JobFailedError

out = c.backup_group(3, failed_only=True)          # waits until the backup job has finished (default 1 h)
print(out.state, out.job_id, out.job["finished"])  # "done"

out = c.backup_group(3, keep_until=1798761600)     # beyond the allowed days: needs approval
if out.approval_pending:
    print("waiting for approval", out.quorum_id)

out = c.start_job("verify", "acme", {"source": "vm-100"}, wait=False)
c.wait_job(out.job_id, timeout=None)               # later; None waits without a limit

try:
    c.start_job("backup", "acme", {"group_id": 3})
except JobFailedError as e:
    print(e.job_id, e.state, e.reason)              # the result's error or the last log line

c.pause_group(3, until=1798761600)
c.resume_group(3)
for s in c.list_snapshots(tenant="acme", source="vm-100"):
    print(s["time"], s["size"], s["lock_until"])
for hit in c.iter_files("invoice", tenant="acme", ext="pdf"):   # all pages
    print(hit["source"], hit["path"], len(hit["versions"]))
for a in c.list_alerts(state="open"):
    c.acknowledge_alert(a["id"], "known, ticket 4711")
```

`wait=False` returns at once with `state == "pending"` and the `job_id`; `c.wait_job(id)` waits later. Failed or
cancelled jobs raise `JobFailedError`, a timeout `WaitTimeoutError` (the job goes on running).

## Every operation

`c.api` has one method per operation of the API description, named after its `operationId` in snake case, with
path parameters as arguments, the body as `body` and query parameters as keywords (`from` is `from_`):

```python
c.api.get_dashboard()
c.api.list_audit_entries(actor="alice", limit=100)
answer = c.api.create_job({"kind": "offsite", "tenant": "acme", "params": {}})   # {"id": ...} or {"quorum_id": ...}
c.wait(answer, job_id=answer.get("id"))      # what start_job does
c.call("getJob", {"id": 4711})               # the same by operationId
c.request("GET", "/jobs", query={"limit": 5}) # anything below /api/v1
```

Answers are decoded: JSON to dicts and lists, CSV to `str`, downloads to `bytes`.

## Audit log and usage

```python
for e in c.iter_audit(action="job.", from_=1793534400):   # pages through all matches, oldest first
    print(e["seq"], e["actor"], e["action"])
for e in c.iter_audit(after=last_seq):                    # SIEM pull: everything after the last seq seen
    ...
open("usage.csv", "w").write(c.usage_csv("2026-10"))
with Client.login(url, "sec", password, totp=code) as s:  # the CSV export needs a person's session
    open("audit.csv", "w").write(s.audit_csv(tenant="acme"))
```

## Errors

All derive from `NexusBackupError`. API errors are `ApiError` with `status` and `message` (the API's `error` text):
`BadRequestError` 400, `AuthenticationError` 401, `PermissionDeniedError` 403, `NotFoundError` 404,
`ConflictError` 409, `RateLimitedError` 429. Also `TlsError`, `SessionRequiredError` (an operation tokens cannot
reach), `JobFailedError`, `WaitTimeoutError`.

## Tests

```sh
cd sdk/python && python3 -m pytest -q        # local stub servers on 127.0.0.1, no network
```

Examples: [`examples/backup_group.py`](examples/backup_group.py) (back up a group with an operator token and list
the new snapshots), [`examples/audit_pull.py`](examples/audit_pull.py) (read-only reporting and a SIEM-style audit
pull with a read token).
