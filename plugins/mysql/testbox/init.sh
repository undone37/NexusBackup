#!/bin/bash
# first start only: the plugin's account (backup privileges + what dump restores need)
set -e
if command -v mariadb >/dev/null; then
	cli=mariadb pw=$MARIADB_ROOT_PASSWORD extra="BINLOG MONITOR, SET USER"
else
	cli=mysql pw=$MYSQL_ROOT_PASSWORD extra="REPLICATION CLIENT, BACKUP_ADMIN, SET_ANY_DEFINER, ALLOW_NONEXISTENT_DEFINER"
fi
"$cli" -uroot -p"$pw" <<-EOF
	CREATE USER 'nexus'@'%' IDENTIFIED BY '$NEXUS_PASSWORD';
	GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, PROCESS, RELOAD, REPLICATION SLAVE, $extra,
	  CREATE, ALTER, DROP, INSERT, INDEX, REFERENCES, CREATE VIEW, CREATE ROUTINE, ALTER ROUTINE, EXECUTE,
	  CREATE TEMPORARY TABLES ON *.* TO 'nexus'@'%';
EOF
