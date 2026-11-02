"""Exceptions of the NexusBackup SDK. Everything raised on purpose derives from `NexusBackupError`."""

from __future__ import annotations

from typing import Any


class NexusBackupError(Exception):
    """Base class of the SDK's errors."""


class TlsError(NexusBackupError):
    """The appliance's certificate was refused (untrusted, wrong name, or not the pinned fingerprint)."""


class SessionRequiredError(NexusBackupError):
    """The operation is not reachable with an API token (`x-token: false`): sign in as a person (`Client.login`)."""


class ApiError(NexusBackupError):
    """The API answered with an error status. `message` is the API's `{"error": "..."}` text."""

    def __init__(self, status: int, message: str, method: str, path: str, body: Any = None) -> None:
        super().__init__(f"{method} {path}: HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.method = method
        self.path = path
        self.body = body


class BadRequestError(ApiError):
    """400: the request is invalid (the message says why)."""


class AuthenticationError(ApiError):
    """401: no valid session or token (expired, revoked, wrong credentials)."""


class PermissionDeniedError(ApiError):
    """403: the role, the token's scope or a lockdown does not allow it."""


class NotFoundError(ApiError):
    """404: no such job, source, group, approval request, ..."""


class ConflictError(ApiError):
    """409: conflicts with the current state, e.g. a job of the group is already queued."""


class RateLimitedError(ApiError):
    """429: too many failed sign-ins; try again later."""


_BY_STATUS: dict[int, type[ApiError]] = {
    400: BadRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    429: RateLimitedError,
}


def api_error(status: int, message: str, method: str, path: str, body: Any = None) -> ApiError:
    """The `ApiError` subclass for `status`."""
    return _BY_STATUS.get(status, ApiError)(status, message, method, path, body)


def job_reason(job: dict[str, Any]) -> str:
    """Why a job failed: `result.error`, else the last line of its log."""
    result = job.get("result")
    if isinstance(result, dict) and isinstance(result.get("error"), str) and result["error"]:
        return str(result["error"])
    lines = [line.strip() for line in str(job.get("log") or "").splitlines() if line.strip()]
    return lines[-1] if lines else "no reason given"


class JobFailedError(NexusBackupError):
    """A job ended `failed` or `cancelled`. `job` is its `GET /jobs/{id}` answer (with the log)."""

    def __init__(self, job: dict[str, Any]) -> None:
        self.job = job
        self.job_id = job.get("id")
        self.state = job.get("state")
        self.reason = job_reason(job)
        super().__init__(f"job {self.job_id} ({job.get('kind')}) {self.state}: {self.reason}")


class WaitTimeoutError(NexusBackupError):
    """A job was still queued or running when the wait timed out; it goes on running on the appliance."""

    def __init__(self, job_id: int, timeout: float, job: dict[str, Any] | None) -> None:
        state = (job or {}).get("state", "queued")
        super().__init__(f"job {job_id}: still {state} after {timeout:g} s")
        self.job_id = job_id
        self.timeout = timeout
        self.job = job
