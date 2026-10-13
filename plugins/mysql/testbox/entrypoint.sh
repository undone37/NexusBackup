#!/bin/bash
# sshd (key of target/my-testbox/client_ed25519 for user mysql) + TLS files, then the image's entrypoint
# with binlog (ROW) and TLS
set -e
home=/home/mysql
install -d -m 700 -o mysql -g mysql "$home/.ssh"
install -m 600 -o mysql -g mysql /testbox/client_ed25519.pub "$home/.ssh/authorized_keys"
install -d -m 755 /etc/nexus-tls
install -m 600 -o mysql -g mysql /testbox/server.key /etc/nexus-tls/server.key
install -m 644 /testbox/server.crt /etc/nexus-tls/server.crt
/usr/sbin/sshd -h /testbox/ssh_host_ed25519_key -o PasswordAuthentication=no -o PermitRootLogin=no -o UsePAM=no
exec docker-entrypoint.sh "$@" --ssl-cert=/etc/nexus-tls/server.crt --ssl-key=/etc/nexus-tls/server.key \
	--server-id=1 --log-bin=mysql-bin --binlog-format=ROW --log-bin-trust-function-creators=1
