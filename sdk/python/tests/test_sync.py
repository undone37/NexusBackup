"""The SDK covers the API description: the generated table equals what sdk/codegen.py makes of
crates/web-api/openapi.json, and every operation is callable."""

from __future__ import annotations

import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

import nexusbackup
from nexusbackup._operations import Operations

ROOT = Path(__file__).resolve().parents[3]
SPEC = json.loads((ROOT / "crates/web-api/openapi.json").read_text())


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()


def test_generated_code_is_current():
    r = subprocess.run(
        [sys.executable, str(ROOT / "sdk/codegen.py"), "--check"], check=False, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr


def test_every_operation_is_covered():
    in_spec = {
        op["operationId"]: (m.upper(), p, op.get("x-token", True) is not False)
        for p, item in SPEC["paths"].items()
        for m, op in item.items()
        if m in ("get", "put", "post", "delete", "patch")
    }
    assert set(nexusbackup.OPERATIONS) == set(in_spec)
    for oid, op in nexusbackup.OPERATIONS.items():
        assert (op.method, op.path, op.token) == in_spec[oid]
        method = getattr(Operations, snake(oid))
        params = inspect.signature(method).parameters
        for p in op.path_params:
            assert p in params, f"{oid}: {p}"


def test_version_follows_the_api():
    assert nexusbackup.__version__.split(".")[0] == nexusbackup.API_VERSION == SPEC["info"]["version"]
    pyproject = (ROOT / "sdk/python/pyproject.toml").read_text()
    assert f'version = "{nexusbackup.__version__}"' in pyproject
    psd1 = (ROOT / "sdk/powershell/NexusBackup/NexusBackup.psd1").read_text()
    assert f"ModuleVersion        = '{nexusbackup.__version__}'" in psd1
