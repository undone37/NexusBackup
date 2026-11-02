from __future__ import annotations

import pytest

import nexusbackup
from nexusbackup import (
    Client,
    ConflictError,
    JobFailedError,
    NotFoundError,
    SessionRequiredError,
    WaitTimeoutError,
)

TOKEN = "nxt_0123abcd_" + "0" * 64  # not a real token


def client(stub, **kw) -> Client:
    return Client(stub.url, token=TOKEN, **kw)


def job(jid: int, state: str, **over):
    j = {"id": jid, "kind": "backup", "tenant": "acme", "state": state, "params": {"group_id": 3}, "log": ""}
    j.update(over)
    return j


def test_token_header_and_json(stub):
    stub.on("GET", "/jobs", (200, [job(1, "ok")]))
    out = client(stub).list_jobs(state="ok", limit=5)
    assert out[0]["id"] == 1
    (r,) = stub.requests("GET", "/jobs")
    assert r.query == {"state": "ok", "limit": "5"}
    assert r.headers["Authorization"] == f"Bearer {TOKEN}"
    assert "Cookie" not in r.headers and "X-CSRF-Token" not in r.headers
    assert r.headers["User-Agent"] == f"nexusbackup-python/{nexusbackup.__version__}"


def test_query_and_path_encoding(stub):
    stub.on("GET", "/audit", (200, []))
    stub.on("POST", "/groups/7/resume", (200, {"ok": True}))
    stub.on("GET", "/snapshots", (200, []))
    c = client(stub)
    c.api.resume_group(7)
    assert stub.seen[-1].body == {}  # POST without a documented body still sends JSON
    c.api.list_audit_entries(from_=10, to=20, actor=None, tenant="acme")
    assert stub.requests("GET", "/audit")[0].query == {"from": "10", "to": "20", "tenant": "acme"}
    c.list_snapshots(source="vm-100", held=True)
    assert stub.requests("GET", "/snapshots")[0].query == {"source": "vm-100", "held": "true"}
    stub.on("GET", "/sources/a%2Fb/inventory", (200, {"guests": []}))
    assert c.call("getSourceInventory", {"id": "a/b"}) == {"guests": []}


def test_errors_carry_the_api_message(stub):
    stub.on("GET", "/jobs/99", (404, {"error": "not found"}))
    stub.on("POST", "/jobs", (409, {"error": "a backup of this group is already queued"}))
    c = client(stub)
    with pytest.raises(NotFoundError) as e:
        c.get_job(99)
    assert e.value.status == 404 and e.value.message == "not found"
    assert str(e.value) == "GET /jobs/99: HTTP 404: not found"
    with pytest.raises(ConflictError, match="already queued"):
        c.start_job("backup", "acme", {"group_id": 3})


def test_error_without_json_body(stub):
    stub.on("GET", "/hardware", (502, "bad gateway"))
    with pytest.raises(nexusbackup.ApiError) as e:
        client(stub).api.get_hardware()
    assert e.value.status == 502 and e.value.message == "bad gateway"


def test_missing_arguments_fail_before_sending(stub):
    c = client(stub)
    with pytest.raises(ValueError, match="path parameter"):
        c.call("getJob", {})
    with pytest.raises(ValueError, match="body is required"):
        c.call("createJob")
    with pytest.raises(ValueError, match="unknown operationId"):
        c.call("noSuchThing")
    assert stub.seen == []


def test_session_only_operations_refuse_tokens(stub):
    c = client(stub)
    with pytest.raises(SessionRequiredError):
        c.approve(12)
    with pytest.raises(SessionRequiredError):
        c.audit_csv()
    assert stub.seen == []


def test_login_session_csrf_and_logout(stub):
    stub.on(
        "POST",
        "/auth/login",
        (200, {"user": {"name": "alice"}, "csrf": "c" * 32}, {"Set-Cookie": "nx_session=s3ss; HttpOnly; Secure"}),
    )
    stub.on("GET", "/quorum", (200, [{"id": 12, "state": "pending"}]))
    stub.on("POST", "/quorum/12/approve", (200, {"id": 12, "state": "executed"}))
    stub.on("POST", "/auth/logout", (200, {"ok": True}))
    with Client.login(stub.url, "alice", "pw", totp="123456") as c:
        assert c.is_session and c.session["user"]["name"] == "alice"
        assert c.list_approval_requests(state="pending")[0]["id"] == 12
        out = c.approve(12)
    login, get, approve, logout = stub.seen
    assert login.body == {"name": "alice", "password": "pw", "totp": "123456"}
    assert "Authorization" not in login.headers
    assert get.headers["Cookie"] == "nx_session=s3ss" and "X-CSRF-Token" not in get.headers
    assert approve.headers["X-CSRF-Token"] == "c" * 32
    assert logout.path == "/api/v1/auth/logout" and logout.headers["X-CSRF-Token"] == "c" * 32
    assert out.done and out.state == "done" and out.quorum_id == 12
    assert not c.is_session


def test_login_failure(stub):
    stub.on("POST", "/auth/login", (401, {"error": "invalid credentials"}))
    with pytest.raises(nexusbackup.AuthenticationError, match="invalid credentials"):
        Client.login(stub.url, "alice", "bad")
    assert stub.seen[0].body == {"name": "alice", "password": "bad"}


def test_start_job_waits_until_finished(stub):
    stub.on("POST", "/jobs", (202, {"id": 41}))
    stub.on("GET", "/jobs/41", (200, job(41, "queued")), (200, job(41, "running")), (200, job(41, "ok")))
    out = client(stub).start_job("verify", "acme", {"snapshot": "s1"}, interval=0.01)
    assert out.done and out.state == "done" and out.job_id == 41 and out.job["state"] == "ok"
    assert stub.requests("POST", "/jobs")[0].body == {"kind": "verify", "tenant": "acme", "params": {"snapshot": "s1"}}
    assert len(stub.requests("GET", "/jobs/41")) == 3


@pytest.mark.parametrize("state", ["failed", "cancelled"])
def test_failed_job_raises_with_the_reason(stub, state):
    stub.on("POST", "/jobs", (202, {"id": 42}))
    stub.on("GET", "/jobs/42", (200, job(42, state, log="[pve] connecting\n[pve] guest 100 is locked\n")))
    with pytest.raises(JobFailedError, match="guest 100 is locked") as e:
        client(stub).start_job("backup", "acme", {"group_id": 3})
    assert e.value.state == state and e.value.job_id == 42
    assert str(e.value) == f"job 42 (backup) {state}: [pve] guest 100 is locked"


def test_failed_job_prefers_the_result_error(stub):
    stub.on("GET", "/jobs/5", (200, job(5, "failed", result={"error": "store full"}, log="x\n")))
    with pytest.raises(JobFailedError, match="store full"):
        client(stub).wait_job(5)


def test_wait_timeout_and_no_wait(stub):
    stub.on("POST", "/jobs", (202, {"id": 43}))
    stub.on("GET", "/jobs/43", (200, job(43, "running")))
    c = client(stub)
    with pytest.raises(WaitTimeoutError, match="still running") as e:
        c.start_job("backup", "acme", {"group_id": 3}, timeout=0.2, interval=0.05)
    assert e.value.job_id == 43
    n = len(stub.requests("GET", "/jobs/43"))
    out = c.start_job("backup", "acme", {"group_id": 3}, wait=False)
    assert out.state == "pending" and out.job_id == 43 and not out.done
    assert len(stub.requests("GET", "/jobs/43")) == n


def test_job_needing_approval(stub):
    stub.on("POST", "/jobs", (202, {"quorum_id": 9}))
    out = client(stub).start_job("backup", "acme", {"group_id": 3, "keep_until": 1798761600})
    assert out.approval_pending and out.quorum_id == 9 and out.job_id is None
    assert stub.requests("GET") == []


def test_wait_other_answers(stub):
    c = client(stub)
    assert c.wait({"ok": True}).state == "ok"
    assert c.wait(None).done
    assert c.wait({"approvals": "disabled", "executed": True, "quorum_id": 3}).state == "ok"
    assert stub.seen == []


def test_backup_group_reads_the_tenant(stub):
    stub.on("GET", "/groups", (200, [{"id": 3, "tenant": "acme", "name": "web"}]))
    stub.on("POST", "/jobs", (202, {"id": 44}))
    stub.on("GET", "/jobs/44", (200, job(44, "ok")))
    out = client(stub).backup_group(3, failed_only=True, keep_until=1798761600)
    assert out.done
    assert stub.requests("POST", "/jobs")[0].body == {
        "kind": "backup",
        "tenant": "acme",
        "params": {"group_id": 3, "failed_only": True, "keep_until": 1798761600},
    }
    with pytest.raises(nexusbackup.NexusBackupError, match="no protection group 4"):
        client(stub).backup_group(4)


def test_approve_that_starts_a_job(stub):
    c = client(stub)
    c._cookie, c._csrf = "s", "c"
    stub.on("POST", "/quorum/7/approve", (200, {"id": 7, "state": "executed", "job_id": 45}))
    stub.on("GET", "/jobs/45", (200, job(45, "ok")))
    out = c.approve(7)
    assert out.state == "done" and out.job_id == 45
    stub.on("POST", "/quorum/8/approve", (200, {"id": 8, "state": "pending", "waiting_for": ["acme"]}))
    out = c.approve(8)
    assert out.approval_pending and out.quorum_id == 8


def test_pause_and_acknowledge(stub):
    stub.on("POST", "/groups/3/pause", (200, {"ok": True}))
    stub.on("POST", "/alerts/5/ack", (200, {"ok": True}))
    c = client(stub)
    c.pause_group(3)
    c.pause_group(3, until=1798761600)
    c.acknowledge_alert(5, "known, ticket 4711")
    c.acknowledge_alert(5)
    pauses = [r.body for r in stub.requests("POST", "/groups/3/pause")]
    assert pauses == [{"until": None}, {"until": 1798761600}]
    acks = [r.body for r in stub.requests("POST", "/alerts/5/ack")]
    assert acks == [{"note": "known, ticket 4711"}, {}]


def test_iter_audit_pages_by_seq(stub):
    pages = [[{"seq": 1}, {"seq": 2}], [{"seq": 3}, {"seq": 4}], [{"seq": 5}]]
    stub.on("GET", "/audit", *[(200, p) for p in pages])
    seqs = [e["seq"] for e in client(stub).iter_audit(page_size=2, actor="alice")]
    assert seqs == [1, 2, 3, 4, 5]
    qs = [r.query for r in stub.requests("GET", "/audit")]
    assert qs[0] == {"limit": "2", "order": "asc", "actor": "alice"}
    assert qs[1]["after"] == "2" and qs[2]["after"] == "4"


def test_iter_audit_newest_first(stub):
    stub.on("GET", "/audit", (200, [{"seq": 9}, {"seq": 8}]), (200, []))
    assert [e["seq"] for e in client(stub).iter_audit(newest_first=True, page_size=2)] == [9, 8]
    qs = [r.query for r in stub.requests("GET", "/audit")]
    assert qs[0]["order"] == "desc" and "before" not in qs[0] and qs[1]["before"] == "8"


def test_iter_files_follows_the_cursor(stub):
    stub.on(
        "GET",
        "/files/search",
        (200, {"hits": [{"path": "/etc/hosts"}], "next": "c2"}),
        (200, {"hits": [{"path": "/etc/hostname"}], "next": None}),
    )
    hits = [h["path"] for h in client(stub).iter_files("host", source="vm-100")]
    assert hits == ["/etc/hosts", "/etc/hostname"]
    qs = [r.query for r in stub.requests("GET", "/files/search")]
    assert qs[0] == {"q": "host", "source": "vm-100"} and qs[1]["cursor"] == "c2"


def test_csv_downloads(stub):
    stub.on("GET", "/audit.csv", (200, "seq,ts,actor\n1,2,alice\n"))
    stub.on("GET", "/usage", (200, "month,tenant\n2026-10,acme\n"))
    c = client(stub)
    assert c.usage_csv("2026-10").startswith("month,tenant")
    assert stub.requests("GET", "/usage")[0].query == {"month": "2026-10", "format": "csv"}
    c._cookie, c._csrf = "s", "c"
    assert c.audit_csv(actor="alice", from_=1).startswith("seq,ts,actor")
    assert stub.requests("GET", "/audit.csv")[0].query == {"actor": "alice", "from": "1"}


def test_compatibility(stub):
    current, newer = {"info": {"version": nexusbackup.API_VERSION}}, {"info": {"version": "2"}}
    stub.on("GET", "/openapi.json", (200, current), (200, newer))
    c = client(stub)
    assert c.check_compatibility() == nexusbackup.API_VERSION
    with pytest.raises(nexusbackup.NexusBackupError, match="API version 2"):
        c.check_compatibility()


def test_constructor_checks():
    with pytest.raises(ValueError, match="nxt_"):
        Client("https://backup.example.com", token="secret")
    with pytest.raises(ValueError, match="only for localhost"):
        Client("http://backup.example.com", token=TOKEN)
    with pytest.raises(ValueError, match="64 hex"):
        Client("https://backup.example.com", token=TOKEN, fingerprint="AB:CD")


def test_from_env(stub, monkeypatch):
    monkeypatch.setenv("NEXUS_URL", stub.url)
    monkeypatch.setenv("NEXUS_TOKEN", TOKEN)
    monkeypatch.delenv("NEXUS_CA", raising=False)
    monkeypatch.delenv("NEXUS_FINGERPRINT", raising=False)
    stub.on("GET", "/auth/me", (200, {"user": {"name": "ci"}, "csrf": ""}))
    assert Client.from_env().api.get_me()["user"]["name"] == "ci"
    assert stub.seen[0].headers["Authorization"] == f"Bearer {TOKEN}"
