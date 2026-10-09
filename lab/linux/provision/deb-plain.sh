#!/bin/bash
# Debian 13 as shipped: ext4 on a partition, no LVM -> no snapshots, the agent reads
# live (fallback mode, consistent=false). MariaDB with sample data.
. /var/tmp/nexus-lab/common.sh

say "packages"
apt-get update -q >/dev/null
apt-get install -y -q mariadb-server acl attr libcap2-bin >/dev/null
systemctl enable --now mariadb >/dev/null 2>&1
mariadb -e "CREATE DATABASE sample; USE sample; CREATE TABLE t (id INT PRIMARY KEY, v CHAR(32)) ENGINE=InnoDB;
	INSERT INTO t SELECT seq, MD5(seq) FROM seq_1_to_200000;"
mariadb -N -e "SELECT COUNT(*) FROM sample.t"
say "sample data"
mkdata /home/lab/data
chown -R lab:lab /home/lab/data/docs
findmnt -t ext4 -o TARGET,SOURCE,FSTYPE
