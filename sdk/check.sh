#!/usr/bin/env bash
# The SDK gate: the generated operation tables match crates/web-api/openapi.json, the Python tests, the
# PowerShell tests (Pester) and lint where available. No network beyond 127.0.0.1, except --container (pulls
# images and modules for the parts this machine lacks). CI runs `sdk/check.sh --container` (job sdk).
#
#   sdk/check.sh              sync check + pytest + Pester (local pwsh with Pester 5, else skipped with a note)
#   sdk/check.sh --container  also: Python 3.10 with ruff and mypy, and Pester + PSScriptAnalyzer in podman
set -euo pipefail
cd "$(dirname "$0")/.."
container=0
[ "${1:-}" = "--container" ] && container=1

step() { printf 'sdk/check.sh: %s\n' "$*" >&2; }

step "codegen --check"
python3 sdk/codegen.py --check

step "pytest (python $(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])'))"
(cd sdk/python && python3 -m pytest -q -p no:cacheprovider)

has_pester() {
	command -v pwsh >/dev/null &&
		pwsh -NoProfile -NonInteractive -Command \
			'if (Get-Module -ListAvailable Pester | Where-Object Version -ge ([version]"5.3")) { exit 0 } else { exit 1 }' 2>/dev/null
}

if has_pester; then
	step "Pester (local pwsh)"
	pwsh -NoProfile -NonInteractive -File sdk/powershell/tests/run.ps1
elif [ $container = 0 ]; then
	step "Pester: no local pwsh with Pester 5; skipped (run: sdk/check.sh --container)"
fi

if [ $container = 1 ]; then
	command -v podman >/dev/null || { step "podman missing"; exit 1; }
	step "python 3.10: ruff, mypy, pytest (podman)"
	podman run --rm -v "$PWD/sdk:/sdk:ro,Z" -w /tmp docker.io/library/python:3.10-slim sh -ec '
		pip install -q --disable-pip-version-check --root-user-action=ignore pytest ruff==0.17.3 mypy >/dev/null
		cp -r /sdk/python /tmp/py && cd /tmp/py
		ruff check src tests examples && ruff format --check --line-length 120 src tests examples
		mypy
		python -m pytest -q -p no:cacheprovider tests/test_client.py tests/test_tls.py'
	if ! has_pester; then
		step "Pester + PSScriptAnalyzer (podman, mcr.microsoft.com/powershell)"
		podman run --rm -v "$PWD:/src:ro,Z" -w /src mcr.microsoft.com/powershell:latest \
			pwsh -NoProfile -NonInteractive -File sdk/powershell/tests/run.ps1 -Install
	fi
fi
step "ok"
