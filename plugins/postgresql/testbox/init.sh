#!/bin/bash
# first start only: the plugin's least-privilege role + replication over TCP
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" -c \
	"CREATE ROLE nexus LOGIN REPLICATION CREATEDB PASSWORD '$NEXUS_PASSWORD'; GRANT pg_read_all_data TO nexus;"
echo "host replication all all scram-sha-256" >>"$PGDATA/pg_hba.conf"
