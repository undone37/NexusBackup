#!/usr/bin/env bash
# Phase 14c in the appliance VM: the emergency console gate.
#   lab/appliance/e2e.sh boot setup && lab/appliance/console-gate.sh
# The VM has no VGA, so nobody can type on the real tty2: this checks the real
# nexus-console-gate.service (running, domain, getty@tty2 masked) and drives a second
# instance of the same binary through `systemd-run --pty` from the lab's serial root
# shell (same unit context: init_t -> nexus_consolegate_t, so SELinux is exercised the
# same way), once with a one-time code from the API (m5-api.sh step console) and once
# with the recovery key from the setup journal. Then: the shells ran as unconfined_t,
# audit + alerts + banner in the catalog and the API (step console-check), no AVCs.
# env: as lab/appliance/e2e.sh (LAB, ROOT, PORT, CONSOLE)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export PORT=${PORT:-28443}
export ROOT=${ROOT:-$LAB/appliance/root}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
con() { "$here/con.py" "$@"; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }

log "real gate on tty2"
# in a subshell: `set -e` must not end the serial root shell itself
con run '( set -e
systemctl is-active nexus-console-gate.service
test "$(systemctl is-enabled getty@tty2.service)" = masked
ps -eo label,tty,comm | grep "nexus_consolegate_t.*tty2.*nexus-console-g" # comm: 15 chars
ls -ldZ /var/lib/nexus/console-unlock | grep -E "^drwx------\. .*nexus-webapi nexus-webapi .*nexus_console_unlock_t"
ls -dZ /run/nexus-console-gate | grep nexus_consolegate_var_run_t )'

log "one-time code from the API"
"$here/e2e.sh" api console
code=$(cat "$ROOT/run/api/console-code")
rk=$(con run "journalctl -u nexus-setup -o cat --no-pager | sed -n 's/^RECOVERY KEY (shown once, record it now): //p' | tail -1" | tr -d '\r\n')
[ -n "$rk" ] || { log "FAIL: recovery key not found in the setup journal"; exit 1; }

# GATE_CODE / GATE_RK: a wrong code first (rate limiter + audit), then the code; then the recovery key
GATE_CODE=$code GATE_RK=$rk python3 - "$here" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[1])
import con

c = con.Console()
c.shell(30)
RUNS = iter(range(1, 100))


def resync():
    # after a --pty session: a sane terminal and a full command round trip before the next start
    c.shell(60)
    c.run("stty sane; stty -echo; sleep 1", 30)


def gate_cmd():
    # a fresh unit name per run: the previous instance may still be finishing its audit
    return (f"systemd-run --pty --quiet --wait --collect --unit=nexus-console-gate-lab-{next(RUNS)} "
            "-E NEXUS_CONSOLE_GATE_STATE=/run/nexus-console-gate/lab-attempts "
            "/usr/libexec/nexus/nexus-console-gate --once\n")
PROMPT = rb"Unlock code or recovery key: "


def session(secret, hours=None):
    c.send(gate_cmd().encode())
    c.until(PROMPT, 60)
    c.send(secret.encode() + b"\r")
    if hours is not None:
        c.until(rb"Shell duration in hours \(1-8\) \[1\]: ", 30)
        c.send(hours.encode() + b"\r")
    out, _ = c.until(rb"leave it with `exit`\.", 30)
    print(con.ANSI.sub(b"", out).decode(errors="replace").strip()[-300:])
    c.send(b"id -Z; id -u; echo GATE-OK-$((40+2))\r")
    out, _ = c.until(rb"GATE-OK-42", 30)
    text = con.ANSI.sub(b"", out).decode(errors="replace")
    assert "unconfined_t" in text, text
    print("shell context:", [l for l in text.splitlines() if "unconfined_t" in l][-1].strip())
    c.send(b"exit\r")
    c.until(rb"Root shell ended \(exit\)\.", 30)
    resync()


# a wrong code is rejected and counted
c.send(gate_cmd().encode())
c.until(PROMPT, 60)
c.send(b"AAAAA-AAAAA-AAAAA-AAAAA\r")
c.until(rb"Not accepted \(1 of 5 attempts per 15 min\)\.", 30)
c.until(PROMPT, 30)
c.send(os.environ["GATE_CODE"].encode() + b"\r")
c.until(rb"Code #\d+ accepted", 30)
c.until(rb"leave it with `exit`\.", 30)
c.send(b"id -Z; echo GATE-OK-$((40+2))\r")
out, _ = c.until(rb"GATE-OK-42", 30)
assert b"unconfined_t" in out, out
c.send(b"exit\r")
c.until(rb"Root shell ended \(exit\)\.", 30)
resync()
print("code: accepted once, shell unconfined_t")
# the same code again: consumed
c.send(gate_cmd().encode())
c.until(PROMPT, 60)
c.send(os.environ["GATE_CODE"].encode() + b"\r")
c.until(rb"Not accepted", 30)
c.until(PROMPT, 60)
c.send(b"\x04")  # EOF at the prompt ends the gate
c.until(rb"\x04|\n", 30)
resync()
print("code: second use refused")
session(os.environ["GATE_RK"], hours="1")
print("recovery key: shell unconfined_t")
PY

log "catalog, files and AVCs"
con run '( rm -f /run/nexus-console-gate/lab-attempts
python3 - <<"EOF"
import json, sqlite3
db = sqlite3.connect("file:/var/lib/nexus/catalog/catalog.db?mode=ro", uri=True)
acts = [a for (a,) in db.execute("SELECT action FROM audit WHERE action LIKE ? ORDER BY seq", ("console.%",))]
print("audit:", acts)
assert acts.count("console.root_shell") == 2 and acts.count("console.root_shell_end") == 2, acts
assert acts.count("console.unlock_failed") >= 2, acts
assert db.execute("SELECT value FROM settings WHERE key = ?", ("console_shell_active",)).fetchone() is None
n = db.execute("SELECT COUNT(*) FROM alerts WHERE kind = ? AND severity = ?", ("console_root_shell", "critical")).fetchone()[0]
assert n == 2, n
print("OK")
EOF
test -z "$(ls -A /var/lib/nexus/console-unlock)"
ausearch -m avc,user_avc,selinux_err -ts boot 2>&1 | grep -E "consolegate|console_unlock|unconfined_t" && exit 1 || echo "no console AVCs" )'
"$here/e2e.sh" api console-check
log "console gate: ok"
