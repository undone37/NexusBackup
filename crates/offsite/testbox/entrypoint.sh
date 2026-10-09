#!/bin/sh
set -e
echo "${MAX_CONN:-10}" >/etc/ssh/maxconn
exec /usr/sbin/sshd -D -e
