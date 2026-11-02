"""The NexusBackup client: authentication, the generated operations (`Client.api`) and the common workflows."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import quote, urlencode

from . import __version__
from ._operations import API_VERSION, OPERATIONS, Operations
from ._transport import Transport
from .errors import (
    ApiError,
    JobFailedError,
    NexusBackupError,
    SessionRequiredError,
    WaitTimeoutError,
    api_error,
)

if TYPE_CHECKING:  # typing.Self is 3.11+; annotations are not evaluated at runtime
    from typing_extensions import Self

SESSION_COOKIE = "nx_session"
TOKEN_PREFIX = "nxt_"
FINISHED = ("ok", "failed", "cancelled")


@dataclass(frozen=True)
class Outcome:
    """What became of an action.

    `state`:
    - `done`: the job `job_id` finished `ok` (`job` is its `GET /jobs/{id}` answer), or an approval was carried out;
    - `pending`: the job `job_id` is queued or running, not waited for (`wait=False`);
    - `approval_pending`: the action needs approval; approval request `quorum_id` waits for a second person
      (web UI: Approvals, or `Client.approve` as that person);
    - `ok`: applied directly by the API (no job).
    """

    state: str
    job_id: int | None = None
    quorum_id: int | None = None
    response: Any = None
    """the answer to the action itself"""
    job: dict[str, Any] | None = field(default=None)
    """`GET /jobs/{id}` when waited for"""

    @property
    def done(self) -> bool:
        return self.state in ("done", "ok")

    @property
    def approval_pending(self) -> bool:
        return self.state == "approval_pending"


class _Api(Operations):
    def __init__(self, client: Client) -> None:
        self._client = client

    def _call(self, operation_id: str, path: dict[str, Any], query: dict[str, Any], body: Any) -> Any:
        return self._client.call(operation_id, path, query, body)


class Client:
    """A connection to one appliance.

    With an API token (`nxt_...`, My account -> API tokens; scope read, operator or backup)::

        c = Client("https://backup.example.com:8443", token=os.environ["NEXUS_TOKEN"], ca_file="ca.pem")

    or as a person (password and TOTP code, for what tokens never do: approving, the audit CSV, the
    restore point simulator), signed out at the end of the `with` block::

        with Client.login(url, "alice", password, totp="123456", fingerprint="AB:CD:...") as c:
            c.approve(12)

    TLS: the system trust store by default; `ca_file`/`ca_data` for a private CA or the appliance's
    self-signed certificate (the name in it must match the URL's host); `fingerprint` pins the certificate's
    SHA-256 instead (no name or chain check: for the self-signed certificate reached by an address it does
    not name); `verify=False` checks nothing (tests only).

    `api` has one method per operation of the API description (generated, see `nexusbackup._operations`);
    the methods here wrap the common workflows and wait for jobs.
    """

    def __init__(
        self,
        url: str,
        token: str | None = None,
        *,
        ca_file: str | None = None,
        ca_data: str | None = None,
        fingerprint: str | None = None,
        verify: bool = True,
        timeout: float = 60.0,
    ) -> None:
        if token is not None and not token.startswith(TOKEN_PREFIX):
            raise ValueError("token: an API token (nxt_...), created under My account -> API tokens")
        self._transport = Transport(
            url, verify=verify, ca_file=ca_file, ca_data=ca_data, fingerprint=fingerprint, timeout=timeout
        )
        self._token = token
        self._cookie: str | None = None
        self._csrf: str | None = None
        self.session: dict[str, Any] | None = None
        """the sign-in answer (`user`, `csrf`) of a session client"""
        self.api = _Api(self)

    # --- construction and authentication -------------------------------------------------------------

    @classmethod
    def from_env(cls, **kwargs: Any) -> Client:
        """`NEXUS_URL`, `NEXUS_TOKEN`, `NEXUS_CA` (PEM file) as nexusctl; `NEXUS_FINGERPRINT`."""
        url = os.environ.get("NEXUS_URL")
        if not url:
            raise NexusBackupError("NEXUS_URL is not set")
        kwargs.setdefault("ca_file", os.environ.get("NEXUS_CA") or None)
        kwargs.setdefault("fingerprint", os.environ.get("NEXUS_FINGERPRINT") or None)
        return cls(url, os.environ.get("NEXUS_TOKEN") or None, **kwargs)

    @classmethod
    def login(cls, url: str, user: str, password: str, totp: str | None = None, **kwargs: Any) -> Client:
        """Sign in as a person (`POST /auth/login`) and return a session client.

        `totp`: the current code of the account's authenticator (a code is accepted once). Accounts under the
        passkey policy and single sign-on accounts cannot sign in here: use the web UI. Use the client as a
        context manager or call `logout()`: every sign-in is a session of the account.
        """
        c = cls(url, **kwargs)
        body: dict[str, Any] = {"name": user, "password": password}
        if totp:
            body["totp"] = totp
        resp, answer = c._exchange("POST", "/auth/login", None, body, None)
        cookie = None
        for k, v in resp.headers:
            if k.lower() == "set-cookie" and v.startswith(SESSION_COOKIE + "="):
                cookie = v.split(";", 1)[0].split("=", 1)[1]
        if not cookie:
            raise NexusBackupError("sign-in: no session cookie in the answer")
        if not isinstance(answer, dict) or not answer.get("csrf"):
            raise NexusBackupError("sign-in: no CSRF token in the answer")
        c._cookie = cookie
        c._csrf = answer["csrf"]
        c.session = answer
        return c

    def logout(self) -> None:
        """End the session (no-op for token clients)."""
        if self._cookie is None:
            return
        try:
            self.api.logout()
        finally:
            self._cookie = self._csrf = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()

    @property
    def is_session(self) -> bool:
        return self._cookie is not None

    # --- raw access ------------------------------------------------------------------------------------

    def call(
        self,
        operation_id: str,
        path: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        body: Any = None,
        *,
        timeout: float | None = None,
    ) -> Any:
        """Call an operation by its operationId (what the `api` methods do)."""
        op = OPERATIONS.get(operation_id)
        if op is None:
            raise ValueError(f"unknown operationId {operation_id!r}")
        if op.auth and not op.token and self._token is not None and self._cookie is None:
            raise SessionRequiredError(
                f"{operation_id} ({op.method} {op.path}) is not reachable with an API token: use Client.login"
            )
        path = path or {}
        missing = [p for p in op.path_params if path.get(p) in (None, "")]
        if missing:
            raise ValueError(f"{operation_id}: missing path parameter(s) {', '.join(missing)}")
        target = op.path
        for p in op.path_params:
            target = target.replace("{" + p + "}", quote(str(path[p]), safe=""))
        if body is None and op.body == "required":
            raise ValueError(f"{operation_id}: a request body is required")
        if body is None and op.method in ("POST", "PUT"):
            body = {}
        return self.request(op.method, target, query=query, body=body, timeout=timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: Any = None,
        timeout: float | None = None,
    ) -> Any:
        """Any request below `/api/v1` (`path` like `/jobs`). Returns JSON decoded, text as str, else bytes."""
        return self._exchange(method, path, query, body, timeout)[1]

    def _exchange(
        self, method: str, path: str, query: dict[str, Any] | None, body: Any, timeout: float | None
    ) -> tuple[Any, Any]:
        target = "/api/v1" + path
        q = {k: _query_value(v) for k, v in (query or {}).items() if v is not None}
        if q:
            target += "?" + urlencode(q)
        headers = {"Accept": "application/json", "User-Agent": f"nexusbackup-python/{__version__}"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if self._cookie is not None:
            headers["Cookie"] = f"{SESSION_COOKIE}={self._cookie}"
            if method != "GET" and self._csrf:
                headers["X-CSRF-Token"] = self._csrf
        elif self._token is not None:
            headers["Authorization"] = f"Bearer {self._token}"
        resp = self._transport.send(method, target, headers, data, timeout)
        value = _decode(resp.content_type, resp.data)
        if resp.status >= 400:
            msg = value.get("error") if isinstance(value, dict) else None
            if not isinstance(msg, str):
                msg = value if isinstance(value, str) and value else f"HTTP {resp.status}"
            raise api_error(resp.status, msg, method, path, value)
        return resp, value

    # --- jobs ------------------------------------------------------------------------------------------

    def wait(
        self,
        answer: Any,
        *,
        job_id: int | None = None,
        timeout: float | None = 3600.0,
        interval: float = 3.0,
        wait: bool = True,
    ) -> Outcome:
        """Turn the answer of an action into an `Outcome`, waiting for its job.

        The job is `job_id`, else the answer's `job_id` (an approval that started one). Raises `JobFailedError`
        when the job fails or is cancelled and `WaitTimeoutError` when it still runs after `timeout` seconds
        (None: no limit). A `quorum_id` is returned as `approval_pending`, never waited for: a second person
        decides, possibly days later.
        """
        if not isinstance(answer, dict):
            return Outcome("ok", response=answer)
        if answer.get("quorum_id") is not None and answer.get("approvals") != "disabled":
            return Outcome("approval_pending", quorum_id=answer["quorum_id"], response=answer)
        jid = job_id if job_id is not None else answer.get("job_id")
        if isinstance(jid, int) and not isinstance(jid, bool):
            if not wait:
                return Outcome("pending", job_id=jid, response=answer)
            return self.wait_job(jid, timeout=timeout, interval=interval, response=answer)
        return Outcome("ok", response=answer)

    def wait_job(
        self, job_id: int, *, timeout: float | None = 3600.0, interval: float = 3.0, response: Any = None
    ) -> Outcome:
        """Poll `GET /jobs/{id}` until the job has finished (raises on failed, cancelled and timeout)."""
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            job = cast("dict[str, Any]", self.api.get_job(job_id))
            state = job.get("state")
            if state == "ok":
                return Outcome("done", job_id=job_id, response=response, job=job)
            if state in FINISHED:
                raise JobFailedError(job)
            if deadline is not None and time.monotonic() + interval > deadline:
                raise WaitTimeoutError(job_id, cast(float, timeout), job)
            time.sleep(interval)

    def list_jobs(self, **filters: Any) -> list[dict[str, Any]]:
        """Jobs, newest first (`state`, `kind`, `tenant`, `limit` up to 1000)."""
        return cast("list[dict[str, Any]]", self.api.list_jobs(**filters))

    def get_job(self, job_id: int) -> dict[str, Any]:
        """One job with its log (`state` queued, running, ok, failed or cancelled; `progress` while running)."""
        return cast("dict[str, Any]", self.api.get_job(job_id))

    def start_job(
        self,
        kind: str,
        tenant: str,
        params: dict[str, Any] | None = None,
        *,
        wait: bool = True,
        timeout: float | None = 3600.0,
        interval: float = 3.0,
    ) -> Outcome:
        """Start a job (`POST /jobs`, operator scope) and wait until it has finished (`wait=False`: return at
        once with `state == "pending"`). Some requests need approval (a lock beyond the allowed days, restores
        in vault mode): then the outcome is `approval_pending`."""
        answer = self.api.create_job({"kind": kind, "tenant": tenant, "params": params or {}})
        jid = answer.get("id") if isinstance(answer, dict) and answer.get("quorum_id") is None else None
        return self.wait(answer, job_id=jid, wait=wait, timeout=timeout, interval=interval)

    def backup_group(
        self,
        group_id: int,
        *,
        tenant: str | None = None,
        guests: list[Any] | None = None,
        failed_only: bool = False,
        keep_until: int | datetime | None = None,
        wait: bool = True,
        timeout: float | None = 3600.0,
        interval: float = 3.0,
    ) -> Outcome:
        """Back up a protection group now (as the scheduler would). `tenant`: the group's (read from `GET
        /groups` when not given); `guests`: only these members; `failed_only`: only the members whose last
        backup failed; `keep_until` (unix seconds or an aware datetime): lock the new snapshots until then."""
        if tenant is None:
            group = next((g for g in self.list_groups() if g.get("id") == group_id), None)
            if group is None:
                raise NexusBackupError(f"no protection group {group_id}")
            tenant = str(group["tenant"])
        params: dict[str, Any] = {"group_id": group_id}
        if guests is not None:
            params["guests"] = list(guests)
        if failed_only:
            params["failed_only"] = True
        if keep_until is not None:
            params["keep_until"] = _unix(keep_until)
        return self.start_job("backup", tenant, params, wait=wait, timeout=timeout, interval=interval)

    def cancel_job(self, job_id: int) -> dict[str, Any]:
        """Cancel a queued or running job."""
        return cast("dict[str, Any]", self.api.cancel_job(job_id))

    # --- inventory and data ------------------------------------------------------------------------------

    def list_sources(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self.api.list_sources())

    def list_groups(self) -> list[dict[str, Any]]:
        return cast("list[dict[str, Any]]", self.api.list_groups())

    def list_snapshots(self, **filters: Any) -> list[dict[str, Any]]:
        """Snapshots (`tenant`, `source`, `held`): local / offsite, lock, verification, holds."""
        return cast("list[dict[str, Any]]", self.api.list_snapshots(**filters))

    def pause_group(self, group_id: int, until: int | datetime | None = None) -> dict[str, Any]:
        """Pause a group's schedule, until a time (unix seconds or an aware datetime) or indefinitely."""
        return cast("dict[str, Any]", self.api.pause_group(group_id, body={"until": _unix(until)}))

    def resume_group(self, group_id: int) -> dict[str, Any]:
        return cast("dict[str, Any]", self.api.resume_group(group_id))

    def iter_files(self, q: str, **filters: Any) -> Iterator[dict[str, Any]]:
        """Every hit of the file search (one per file with its versions), following the `next` cursor.
        Filters as `GET /files/search` (`tenant`, `source`, `group`, `kind`, `ext`, `deleted`, `limit`, ...)."""
        cursor = filters.pop("cursor", None)
        while True:
            page = self.api.search_files(q=q, cursor=cursor, **filters)
            yield from page.get("hits") or []
            cursor = page.get("next")
            if not cursor:
                return

    def usage(self, month: str | None = None, tenant: str | None = None) -> dict[str, Any]:
        """Monthly usage per tenant (billing); `month` as YYYY-MM, default the running month."""
        return cast("dict[str, Any]", self.api.get_usage(month=month, tenant=tenant))

    def usage_csv(self, month: str | None = None, tenant: str | None = None) -> str:
        return cast("str", self.api.get_usage(month=month, tenant=tenant, format="csv"))

    # --- alerts --------------------------------------------------------------------------------------------

    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]:
        """Alerts (`acked`, `state` open, resolved or all, `category`)."""
        return cast("list[dict[str, Any]]", self.api.list_alerts(**filters))

    def acknowledge_alert(self, alert_id: int, note: str | None = None) -> dict[str, Any]:
        body = {"note": note} if note else None
        return cast("dict[str, Any]", self.api.acknowledge_alert(alert_id, body=body))

    # --- approvals ---------------------------------------------------------------------------------------

    def list_approval_requests(self, state: str | None = None) -> list[dict[str, Any]]:
        """Approval requests (`state` pending, executed, rejected, ...)."""
        return cast("list[dict[str, Any]]", self.api.list_approval_requests(state=state))

    def approve(
        self, quorum_id: int, *, wait: bool = True, timeout: float | None = 3600.0, interval: float = 3.0
    ) -> Outcome:
        """Approve and carry out another person's request (a person's session: administrator, security officer
        or the tenant's approver). `done` once carried out (and, when it started a job, once that job has
        finished); `approval_pending` while tenant approvers still have to decide."""
        answer = self.api.approve_request(quorum_id)
        if isinstance(answer, dict) and answer.get("state") == "pending":
            return Outcome("approval_pending", quorum_id=quorum_id, response=answer)
        out = self.wait(answer, wait=wait, timeout=timeout, interval=interval)
        if out.state == "ok":
            return Outcome("done", quorum_id=quorum_id, response=answer)
        return out

    def reject(self, quorum_id: int) -> dict[str, Any]:
        return cast("dict[str, Any]", self.api.reject_request(quorum_id))

    # --- audit log: paging and CSV -----------------------------------------------------------------------

    def iter_audit(
        self, *, newest_first: bool = False, page_size: int = 500, **filters: Any
    ) -> Iterator[dict[str, Any]]:
        """All audit entries matching the filters (`actor`, `action` prefix, `target` substring, `from_`, `to`,
        `tenant`; `after`/`before` = start after/before this seq), fetched page by page."""
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size: 1 to 1000")
        cursor_key = "before" if newest_first else "after"
        cursor = filters.pop(cursor_key, None)
        while True:
            page = self.api.list_audit_entries(
                limit=page_size, order="desc" if newest_first else "asc", **{cursor_key: cursor}, **filters
            )
            yield from page
            if len(page) < page_size:
                return
            cursor = page[-1]["seq"]

    def audit_csv(self, **filters: Any) -> str:
        """The audit log as CSV, every matching entry oldest first, with the hash chain columns (a person's
        session: administrator, security officer or tenant administrator)."""
        return cast("str", self.call("exportAuditCsv", {}, _filters(filters), timeout=600))

    # --- compatibility -----------------------------------------------------------------------------------

    def api_version(self) -> str:
        """The appliance's API version (`info.version` of its `GET /openapi.json`)."""
        return str(self.api.get_open_api()["info"]["version"])

    def check_compatibility(self) -> str:
        """Raise `NexusBackupError` unless the appliance speaks the API version this SDK was generated for."""
        v = self.api_version()
        if v != API_VERSION:
            raise NexusBackupError(f"the appliance speaks API version {v}; this SDK is for version {API_VERSION}")
        return v


def _unix(v: int | datetime | None) -> int | None:
    if v is None:
        return None
    return int(v.timestamp()) if isinstance(v, datetime) else int(v)


def _filters(filters: dict[str, Any]) -> dict[str, Any]:
    """Python keywords for the API's query names (`from_` -> `from`)."""
    return {k.rstrip("_"): v for k, v in filters.items()}


def _query_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _decode(content_type: str, data: bytes) -> Any:
    ct = content_type.split(";")[0].strip().lower()
    if ct == "application/json" or ct.endswith("+json"):
        return json.loads(data) if data else None
    if ct.startswith("text/"):
        return data.decode("utf-8", "replace")
    if not ct and not data:
        return None
    return data


__all__ = ["ApiError", "Client", "Outcome"]
