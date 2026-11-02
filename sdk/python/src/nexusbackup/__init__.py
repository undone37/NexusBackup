"""Python SDK for the NexusBackup appliance REST API (`/api/v1`).

    from nexusbackup import Client
    c = Client("https://backup.example.com:8443", token="nxt_...", fingerprint="AB:CD:...")
    for j in c.list_jobs(state="failed", limit=20):
        print(j["id"], j["kind"], j["tenant"])

The SDK's major version is the API version it was generated for (`API_VERSION`).
"""

from __future__ import annotations

__version__ = "1.0.0"

from ._operations import API_VERSION, OPERATIONS, Operation
from ._transport import get_server_fingerprint
from .client import Client, Outcome
from .errors import (
    ApiError,
    AuthenticationError,
    BadRequestError,
    ConflictError,
    JobFailedError,
    NexusBackupError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
    SessionRequiredError,
    TlsError,
    WaitTimeoutError,
)

__all__ = [
    "API_VERSION",
    "OPERATIONS",
    "ApiError",
    "AuthenticationError",
    "BadRequestError",
    "Client",
    "ConflictError",
    "JobFailedError",
    "NexusBackupError",
    "NotFoundError",
    "Operation",
    "Outcome",
    "PermissionDeniedError",
    "RateLimitedError",
    "SessionRequiredError",
    "TlsError",
    "WaitTimeoutError",
    "__version__",
    "get_server_fingerprint",
]
