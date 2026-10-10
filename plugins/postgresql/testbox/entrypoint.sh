#!/bin/bash
# sshd (key of target/pg-testbox/client_ed25519 for user postgres) + TLS files, then the image's entrypoint
set -e
home=/var/lib/postgresql
chmod 755 "$home" # sshd StrictModes (the image makes it 1777)
install -d -m 700 -o postgres -g postgres "$home/.ssh"
install -m 600 -o postgres -g postgres /testbox/client_ed25519.pub "$home/.ssh/authorized_keys"
install -m 600 -o postgres -g postgres /testbox/server.key "$home/server.key"
install -m 644 -o postgres -g postgres /testbox/server.crt "$home/server.crt"
/usr/sbin/sshd -h /testbox/ssh_host_ed25519_key -o PasswordAuthentication=no -o PermitRootLogin=no
exec docker-entrypoint.sh "$@" -c ssl=on -c ssl_cert_file="$home/server.crt" -c ssl_key_file="$home/server.key"
