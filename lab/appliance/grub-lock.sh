#!/usr/bin/env bash
# Phase 18 in the appliance VM: the boot menu password and no passwordless rescue shells.
#   lab/appliance/e2e.sh boot setup && lab/appliance/grub-lock.sh
# 1. State: setup wrote /etc/nexus/grub-user.cfg, nexus-grub-password installed it as
#    /boot/grub2/user.cfg, rescue.target masked, emergency.service forces
#    SYSTEMD_SULOGIN_FORCE=0, root locked, kernel command line has rd.shell=0 (kargs.d),
#    the password printed by `nexus-setup grub-password` matches the hash.
# 2. GRUB on the serial line (lab only: /boot/grub2/console.cfg, which bootupd's static
#    grub.cfg sources), reboot, stop the 1 s menu timeout: `e` and `c` ask for a user and
#    password, a wrong password is refused, root + the derived password opens the editor,
#    and the default entry boots without any password.
# env: as lab/appliance/e2e.sh (LAB, CONSOLE)
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
LAB=${LAB:-/home/ah/nexus-lab}
export CONSOLE=${CONSOLE:-$LAB/appliance/console.sock}
con() { "$here/con.py" "$@"; }
T0=$(date +%s)
log() { printf '[%4ss] %s\n' $(($(date +%s) - T0)) "$*" >&2; }

log "state after setup"
con run '( set -e
systemctl is-active -q nexus-grub-password.service || systemctl show -p Result --value nexus-grub-password.service | grep -qx success
cmp /etc/nexus/grub-user.cfg /boot/grub2/user.cfg
grep -qE "^GRUB2_PASSWORD=grub\.pbkdf2\.sha512\.10000\.[0-9A-F]+\.[0-9A-F]+$" /boot/grub2/user.cfg
stat -c %a /boot/grub2/user.cfg | grep -qx 600
ls -Z /etc/nexus/grub-user.cfg | grep -q nexus_grub_user_t
grep -q "password_pbkdf2 root" /boot/grub2/grub.cfg
test "$(systemctl is-enabled rescue.target)" = masked
systemctl show -p Environment emergency.service | grep -q SYSTEMD_SULOGIN_FORCE=0
grep -q "^root:!" /etc/shadow
grep -qw rd.shell=0 /proc/cmdline
journalctl -b -o cat --no-pager | grep -c "avc:.*denied" | grep -qx 0 || { journalctl -b -o cat | grep "avc:.*denied" | tail; false; } )'

rk=$(con run "journalctl -u nexus-setup -o cat --no-pager | sed -n 's/^RECOVERY KEY (shown once, record it now): //p' | tail -1" | tr -d '\r\n')
[ -n "$rk" ] || { log "FAIL: recovery key not found in the setup journal"; exit 1; }
pw=$(con run "echo '$rk' | /usr/libexec/nexus/nexus-setup grub-password 2>/dev/null | sed -n 's/^Password: \([a-z ]*\)  .*/\1/p' | tr -d ' '" | tr -d '\r\n')
[ ${#pw} = 20 ] || { log "FAIL: no 20-letter password from nexus-setup grub-password: '$pw'"; exit 1; }
# the hash in /boot is that password's (python's hashlib on the appliance)
con run "python3 -I -c 'import hashlib,sys; h=open(\"/boot/grub2/user.cfg\").read().strip().split(\".\"); sys.exit(hashlib.pbkdf2_hmac(\"sha512\", b\"$pw\", bytes.fromhex(h[4]), int(h[3]), 64).hex().upper() != h[5])'"

log "GRUB on the serial line (lab only), reboot"
con run '( set -e
ro=$(findmnt -no OPTIONS /boot | tr , "\n" | grep -qx ro && echo 1 || true)
[ -z "$ro" ] || mount -o remount,rw /boot
printf "serial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console\n" > /boot/grub2/console.cfg
[ -z "$ro" ] || mount -o remount,ro /boot )'

GRUB_PW=$pw python3 - "$here" <<'PY'
import os, sys, time
sys.path.insert(0, sys.argv[1])
import con

c = con.Console()
c.shell(30)
c.send(b"systemctl reboot\n")
# keep pressing "up" until the menu is on the line: any key stops the 1 s timeout
MENU = b"highlighted"
end = time.time() + 300
while MENU not in c.buf:
    if time.time() > end:
        sys.exit(f"FAIL: no GRUB menu on the serial line; got {c.buf[-400:]!r}")
    c.send(b"\x1b[A")
    try:
        c.until(MENU, 0.2)
        break
    except TimeoutError:
        pass
time.sleep(1)
c.buf = b""


def login(key, pw):
    c.send(key)
    c.until(rb"Enter username:", 10)
    c.send(b"root\r")
    c.until(rb"Enter password:", 10)
    c.send(pw.encode() + b"\r")


login(b"e", "wrong-password")
c.until(MENU, 15)  # refused: back in the menu
print("e: user/password asked, wrong password refused")
c.buf = b""
login(b"c", "wrong-password")
c.until(MENU, 15)
print("c: user/password asked, wrong password refused")
c.buf = b""
login(b"e", os.environ["GRUB_PW"])
c.until(rb"(linux|ostree=)", 15)  # the entry's script in the editor
print("e: root + derived password opens the editor")
c.send(b"\x1b")  # leave the editor unchanged
c.until(MENU, 15)
c.send(b"\r")  # the default entry: unrestricted, no password
c.shell(600)
print("default entry booted without a password")
PY

log "remove the lab's serial GRUB console again"
con run '( set -e
ro=$(findmnt -no OPTIONS /boot | tr , "\n" | grep -qx ro && echo 1 || true)
[ -z "$ro" ] || mount -o remount,rw /boot
rm -f /boot/grub2/console.cfg
[ -z "$ro" ] || mount -o remount,ro /boot )'
log "OK"
