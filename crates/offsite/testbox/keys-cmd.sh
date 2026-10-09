#!/bin/sh
# AuthorizedKeysCommand: prints the client key unless the account already has
# MAX_CONN authenticated connections (each has one "sshd-session: tenant@notty" process,
# the unprivileged post-auth child). Refusing the key makes the extra connection fail at auth time,
# which is how a client sees Hetzner's "max. 10 simultaneous connections".
# Racy (two logins at 9 may both pass): good enough for tests.
[ "$1" = tenant ] || exit 0
max=$(cat /etc/ssh/maxconn 2>/dev/null || echo 10)
n=$(pgrep -c -f "^sshd-session: tenant@notty" || true)
if [ "${n:-0}" -ge "$max" ]; then
    echo "keys-cmd: tenant has $n/$max connections, refusing" >&2
    exit 0
fi
cat /etc/ssh/hostkey/client.pub
