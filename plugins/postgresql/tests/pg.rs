//! The plugin binary in the real sandbox against a real PostgreSQL (testbox/run.sh,
//! rootless podman): validate, guests, logical dump → restore to the source and to
//! an alternate server (compared with pg_dump), cluster base backup + incremental
//! WAL → point-in-time restore over SSH, started and queried; recovery to an LSN and
//! a named restore point, tablespaces remapped, started by the plugin (1.2.0); HA:
//! the primary among several servers, a new base backup after a failover.
//! Without podman (or with NEXUS_PG_TESTBOX=skip) every test prints why and passes.

use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const RUN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testbox/run.sh");

/// Tests share the testbox: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn testbox(test: &str) -> Option<&'static HashMap<String, String>> {
    static ENV: OnceLock<Option<HashMap<String, String>>> = OnceLock::new();
    let env = ENV.get_or_init(|| {
        if std::env::var("NEXUS_PG_TESTBOX").as_deref() == Ok("skip") {
            return None;
        }
        if !Command::new("podman")
            .arg("info")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            return None;
        }
        let st = Command::new(RUN).arg("start").status().expect("run.sh");
        assert!(st.success(), "testbox/run.sh start failed");
        let out = Command::new(RUN).arg("env").output().expect("run.sh env");
        Some(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.strip_prefix("export NEXUS_PG_")?.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.trim_matches('\'').to_owned()))
                .collect(),
        )
    });
    if env.is_none() {
        eprintln!("SKIP {test}: podman not available (or NEXUS_PG_TESTBOX=skip)");
    }
    env.as_ref()
}

struct Box {
    env: &'static HashMap<String, String>,
}

impl Box {
    fn var(&self, k: &str) -> &str {
        &self.env[k]
    }

    /// psql as the superuser inside a container (`alt` = the alternate server).
    fn psql(&self, alt: bool, db: &str, sql: &str) -> String {
        self.psql_port(alt, 5432, db, sql)
    }

    fn psql_port(&self, alt: bool, port: u16, db: &str, sql: &str) -> String {
        let ct = self.container(alt);
        let port = port.to_string();
        let o = Command::new("podman")
            .args([
                "exec",
                "-u",
                "postgres",
                &ct,
                "psql",
                "-p",
                &port,
                "-v",
                "ON_ERROR_STOP=1",
                "-qtAX",
                "-d",
                db,
                "-c",
                sql,
            ])
            .output()
            .unwrap();
        assert!(o.status.success(), "psql {sql}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }

    fn container(&self, alt: bool) -> String {
        let c = self.var("CONTAINER").to_owned();
        if alt {
            format!("{c}-alt")
        } else {
            c
        }
    }

    fn exec(&self, args: &[&str]) -> (bool, String) {
        let ct = self.container(false);
        let o = Command::new("podman")
            .args(["exec", "-u", "postgres", &ct])
            .args(args)
            .output()
            .unwrap();
        (
            o.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
        )
    }

    /// pg_dump of a database, normalized (comments and the random \restrict key removed).
    fn pg_dump(&self, alt: bool, db: &str, what: &str) -> String {
        let ct = self.container(alt);
        let o = Command::new("podman")
            .args([
                "exec",
                "-u",
                "postgres",
                &ct,
                "pg_dump",
                what,
                "--no-owner",
                "--no-privileges",
                "-d",
                db,
            ])
            .output()
            .unwrap();
        assert!(o.status.success(), "pg_dump: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| {
                !l.is_empty() && !l.starts_with("--") && !l.starts_with("\\restrict") && !l.starts_with("\\unrestrict")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn config(&self) -> Value {
        json!({
            "host": "127.0.0.1",
            "port": self.var("PORT").parse::<u16>().unwrap(),
            "user": "nexus",
            "password": self.var("PASSWORD"),
            "sslmode": "verify-full",
            "ca_cert": std::fs::read_to_string(self.var("CA")).unwrap(),
            "restore_host": "127.0.0.1",
            "restore_port": self.var("ALT_PORT").parse::<u16>().unwrap(),
            "restore_user": "postgres",
            "restore_password": self.var("SUPER_PASSWORD"),
            "ssh_host": "127.0.0.1",
            "ssh_port": self.var("SSH_PORT").parse::<u16>().unwrap(),
            "ssh_user": "postgres",
            // as a web form's password field delivers it: without line breaks
            "ssh_key": std::fs::read_to_string(self.var("SSH_KEY")).unwrap().replace('\n', " "),
            "ssh_host_key": self.var("SSH_HOST_KEY"),
            "databases_exclude": ["app_*", "pitr*", "postgres"],
        })
    }

    fn host(&self) -> Host {
        let mut h = Host::binary(
            MANIFEST.as_ref(),
            env!("CARGO_BIN_EXE_postgresql").as_ref(),
            "postgresql",
        )
        .unwrap();
        h.timeout = Duration::from_secs(300);
        h
    }
}

const SCHEMA: &str = r#"
CREATE EXTENSION citext;
CREATE SCHEMA shop;
CREATE TYPE shop.status AS ENUM ('new', 'paid', 'it''s shipped');
CREATE DOMAIN shop.qty AS integer DEFAULT 1 CONSTRAINT qty_pos CHECK (VALUE > 0);
CREATE TYPE shop.addr AS (street text, zip varchar(10));
CREATE FUNCTION shop.touch() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN NEW.updated := now(); RETURN NEW; END$$;
CREATE FUNCTION shop.net(numeric) RETURNS numeric LANGUAGE sql IMMUTABLE AS $$ SELECT $1 * 0.81 $$;
CREATE TABLE shop.customer (id serial PRIMARY KEY, email citext UNIQUE NOT NULL, name text COLLATE "C",
  addr shop.addr, note text);
CREATE TABLE shop.orders (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer int NOT NULL REFERENCES shop.customer (id) ON DELETE CASCADE, status shop.status DEFAULT 'new',
  qty shop.qty, price numeric(10,2) CHECK (price >= 0), net numeric GENERATED ALWAYS AS (shop.net(price)) STORED,
  updated timestamptz, payload jsonb, raw bytea);
CREATE INDEX orders_payload ON shop.orders USING gin (payload);
CREATE INDEX orders_big ON shop.orders ((price * 2)) WHERE qty > 1;
CREATE TRIGGER orders_touch BEFORE UPDATE ON shop.orders FOR EACH ROW EXECUTE FUNCTION shop.touch();
CREATE TABLE public.events (id int, at date NOT NULL, msg text) PARTITION BY RANGE (at);
CREATE TABLE public.events_2025 PARTITION OF public.events FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
CREATE TABLE public.events_rest PARTITION OF public.events DEFAULT;
ALTER TABLE public.events ADD PRIMARY KEY (id, at);
CREATE INDEX events_msg ON public.events (msg);
CREATE UNLOGGED TABLE public.cache (k text PRIMARY KEY, v text);
CREATE SEQUENCE public.ticket START 1000 INCREMENT 7;
CREATE VIEW shop.v_paid AS SELECT o.id, c.email FROM shop.orders o JOIN shop.customer c ON c.id = o.customer
  WHERE o.status = 'paid';
CREATE VIEW shop.v_paid_count AS SELECT count(*) AS n FROM shop.v_paid;
CREATE MATERIALIZED VIEW shop.mv_totals AS SELECT customer, sum(price) AS total FROM shop.orders GROUP BY customer;
CREATE UNIQUE INDEX mv_totals_c ON shop.mv_totals (customer);
CREATE FUNCTION shop.paid_count() RETURNS bigint LANGUAGE sql BEGIN ATOMIC SELECT n FROM shop.v_paid_count; END;
INSERT INTO shop.customer (email, name, addr, note) SELECT 'user' || g || '@Example.com', 'Name ' || g,
  ROW('Street ' || g, lpad(g::text, 5, '0'))::shop.addr,
  CASE WHEN g % 3 = 0 THEN NULL ELSE E'tab\there\nnew line \\ backslash ü' END FROM generate_series(1, 500) g;
INSERT INTO shop.orders (customer, status, qty, price, payload, raw) SELECT 1 + g % 500,
  (ARRAY['new', 'paid', 'it''s shipped']::shop.status[])[1 + g % 3], 1 + g % 4, g * 1.5,
  jsonb_build_object('g', g, 'tags', ARRAY['a', 'b']), decode(md5(g::text), 'hex') FROM generate_series(1, 3000) g;
UPDATE shop.orders SET status = 'paid' WHERE id % 10 = 0;
INSERT INTO public.events SELECT g, DATE '2025-06-01' + g, 'evt ' || g FROM generate_series(1, 400) g;
INSERT INTO public.cache VALUES ('a', 'b');
SELECT nextval('public.ticket'), nextval('public.ticket');
REFRESH MATERIALIZED VIEW shop.mv_totals;
"#;

fn reset(b: &Box, alt: bool, dbs: &[&str]) {
    for db in dbs {
        b.psql(alt, "postgres", &format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"));
    }
}

#[test]
fn validate_guests_dump_and_restore() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = testbox("validate_guests_dump_and_restore") else {
        return;
    };
    let b = Box { env };
    reset(&b, false, &["app", "app_copy", "shop2"]);
    reset(&b, true, &["app"]);
    b.psql(false, "postgres", "CREATE DATABASE app");
    b.psql(false, "postgres", "CREATE DATABASE shop2");
    b.psql(false, "app", SCHEMA);
    let h = b.host();
    let cfg = b.config();

    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:?}", h.log());
    let mut bad = cfg.clone();
    bad["password"] = json!("wrong");
    let v = h.validate(&bad).unwrap();
    assert_eq!(
        (v["valid"].as_bool(), v["field"].as_str()),
        (Some(false), Some("password")),
        "{v}"
    );
    // the testbox certificate is not signed by a public CA
    let mut bad = cfg.clone();
    bad["host"] = json!("localhost");
    bad["ca_cert"] = json!(""); // = the public web PKI roots
    let v = h.validate(&bad).unwrap();
    assert_eq!(v["valid"], false, "{v}");
    let mut bad = cfg.clone();
    bad["ssh_host_key"] = json!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl");
    let v = h.validate(&bad).unwrap();
    assert_eq!(
        (
            v["field"].as_str(),
            v["message"].as_str().is_some_and(|m| m.contains("host key"))
        ),
        (Some("ssh_host"), true),
        "{v}"
    );

    let g = h.guests(&cfg).unwrap();
    let ids: Vec<&str> = g["guests"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|x| x["id"].as_str())
        .collect();
    assert_eq!(ids, ["app", "shop2"], "{g}");

    let r = h.backup(&cfg, Some("app")).unwrap();
    assert_eq!(
        (r.source.as_str(), r.streams, r.consistent),
        ("plugin-postgresql-1-app", 1, true),
        "{:?}",
        h.log()
    );
    assert!(r.summary.contains("rows"), "{}", r.summary);

    // to the source under another name: identical schema and data (as pg_dump sees them)
    let out = h
        .restore(&cfg, &r.source, r.time, "to_target", json!({"database": "app_copy"}))
        .unwrap();
    assert!(out.summary.contains("restored into app_copy"), "{}", out.summary);
    for what in ["--schema-only", "--data-only"] {
        let (a, c) = (b.pg_dump(false, "app", what), b.pg_dump(false, "app_copy", what));
        if a != c {
            let d: Vec<_> = a.lines().zip(c.lines()).filter(|(x, y)| x != y).take(5).collect();
            panic!("{what} differs: {d:#?}");
        }
    }
    assert_eq!(
        b.psql(
            false,
            "app_copy",
            "SELECT shop.paid_count() > 0, nextval('public.ticket')"
        ),
        "t|1014"
    );
    assert_eq!(
        b.psql(
            false,
            "app_copy",
            "INSERT INTO shop.orders (customer, price) VALUES (1, 1) RETURNING id"
        ),
        "3001"
    );

    // a second restore under the same name is refused
    let e = h.restore(&cfg, &r.source, r.time, "to_target", json!({"database": "app_copy"}));
    assert!(format!("{:#}", e.unwrap_err()).contains("exists"));

    // to the alternate server
    let out = h
        .restore(
            &cfg,
            &r.source,
            r.time,
            "to_target",
            json!({"database": "app", "server": "alternate"}),
        )
        .unwrap();
    assert!(out.summary.contains("alternate"), "{}", out.summary);
    assert_eq!(
        b.pg_dump(true, "app", "--data-only"),
        b.pg_dump(false, "app", "--data-only")
    );
}

#[test]
fn cluster_backup_and_point_in_time_restore() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = testbox("cluster_backup_and_point_in_time_restore") else {
        return;
    };
    let b = Box { env };
    reset(&b, false, &["pitr"]);
    drop_tablespace(&b);
    for d in ["pitr1", "pitr2", "pitr3"] {
        let dir = format!("/var/lib/postgresql/{d}");
        b.exec(&["pg_ctl", "-D", &dir, "-m", "immediate", "stop"]);
        b.exec(&["rm", "-rf", &dir]);
    }
    b.psql(false, "postgres", "CREATE DATABASE pitr");
    b.psql(
        false,
        "pitr",
        "CREATE TABLE t (id int PRIMARY KEY, at timestamptz DEFAULT clock_timestamp())",
    );
    let h = b.host();
    let cfg = b.config();

    let full = h.backup(&cfg, None).unwrap();
    assert!(full.summary.starts_with("full:"), "{} {:?}", full.summary, h.log());
    assert!(full.files > 500 && full.consistent, "{}", full.files);
    // the full snapshot recovers to the end of its base backup only
    let fr = &full.meta.as_ref().expect("snapshot meta")["recoverable"];
    assert_eq!((&fr["from_lsn"], &fr["from_time"]), (&fr["to_lsn"], &fr["to_time"]), "{fr}");

    b.psql(false, "pitr", "INSERT INTO t (id) SELECT generate_series(1, 100)");
    std::thread::sleep(Duration::from_millis(1100));
    let t1 = b.psql(false, "postgres", "SELECT now()::text");
    std::thread::sleep(Duration::from_millis(1100));
    b.psql(false, "pitr", "INSERT INTO t (id) SELECT generate_series(101, 200)");
    let inc = h.backup(&cfg, None).unwrap();
    assert!(inc.summary.starts_with("incremental:"), "{} {:?}", inc.summary, h.log());
    assert_eq!(inc.base, Some(full.time));
    assert!(
        inc.unchanged + 10 > full.files,
        "data/ reused: {} of {}",
        inc.unchanged,
        full.files
    );
    assert!(
        inc.transferred < 64 << 20,
        "only WAL is transferred: {}",
        inc.transferred
    );
    // recoverable range: base backup end → this run's marker commit
    let ir = &inc.meta.as_ref().unwrap()["recoverable"];
    assert_eq!(ir["from_lsn"], fr["from_lsn"]);
    assert!(ir["to_time"].as_u64() >= ir["from_time"].as_u64() && ir["to_lsn"] != ir["from_lsn"], "{ir}");
    // WAL-only frequent runs: nothing changed = only the (partial) last segments again
    let idle = h.backup(&cfg, None).unwrap();
    assert!(idle.summary.starts_with("incremental:"), "{}", idle.summary);
    assert!(idle.transferred <= 2 * (16 << 20), "{}", idle.transferred);

    b.psql(false, "pitr", "INSERT INTO t (id) SELECT generate_series(201, 300)");
    // the marker of the next run lies in a later second than this commit (to_time = its floor)
    std::thread::sleep(Duration::from_millis(1100));
    let inc2 = h.backup(&cfg, None).unwrap();
    assert!(inc2.summary.starts_with("incremental:"), "{}", inc2.summary);
    assert!(inc2.unchanged >= inc.unchanged, "{} {}", inc2.unchanged, inc.unchanged);
    // the end of the recoverable range is reachable by time (the marker commit follows it)
    let to_time = inc2.meta.as_ref().unwrap()["recoverable"]["to_time"].as_u64().unwrap();
    let to_text = b.psql(false, "postgres", &format!("SELECT to_timestamp({to_time})::text"));

    // to t1: only the first batch
    let r = h
        .restore(
            &cfg,
            &inc2.source,
            inc2.time,
            "pitr",
            json!({"directory": "/var/lib/postgresql/pitr1", "target_time": t1, "port": 5499}),
        )
        .unwrap();
    assert!(
        r.summary.contains("restored to /var/lib/postgresql/pitr1"),
        "{}",
        r.summary
    );
    assert_eq!(start_and_count(&b, "pitr1", 5499), "100");
    // to the end of the backup
    h.restore(
        &cfg,
        &inc2.source,
        inc2.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/pitr2", "port": 5498}),
    )
    .unwrap();
    assert_eq!(start_and_count(&b, "pitr2", 5498), "300");
    for d in ["pitr4"] {
        let dir = format!("/var/lib/postgresql/{d}");
        b.exec(&["pg_ctl", "-D", &dir, "-m", "immediate", "stop"]);
        b.exec(&["rm", "-rf", &dir]);
    }
    h.restore(
        &cfg,
        &inc2.source,
        inc2.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/pitr4", "port": 5495, "target_time": to_text}),
    )
    .unwrap();
    assert_eq!(start_and_count(&b, "pitr4", 5495), "300");
    // the base backup alone (full snapshot: only the WAL in its pg_wal)
    h.restore(
        &cfg,
        &full.source,
        full.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/pitr3", "port": 5497}),
    )
    .unwrap();
    assert_eq!(start_and_count(&b, "pitr3", 5497), "0");
    // never into an existing directory
    let e = h.restore(
        &cfg,
        &inc2.source,
        inc2.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/pitr2"}),
    );
    assert!(format!("{:#}", e.unwrap_err()).contains("must not exist"));
    // a logical restore of a cluster snapshot is refused with a reason
    let e = h.restore(&cfg, &inc2.source, inc2.time, "to_target", json!({"database": "x"}));
    assert!(format!("{:#}", e.unwrap_err()).contains("no database dump"));
    // the slot is gone (dropped by an admin): the WAL chain is broken, a full backup follows
    b.psql(false, "postgres", "SELECT pg_drop_replication_slot('nexusbackup')");
    b.psql(false, "pitr", "INSERT INTO t (id) VALUES (301)");
    let again = h.backup(&cfg, None).unwrap();
    assert!(again.summary.starts_with("full:"), "{} {:?}", again.summary, h.log());
}

fn drop_tablespace(b: &Box) {
    reset(b, false, &["pitrts"]);
    b.psql(false, "postgres", "DROP TABLESPACE IF EXISTS nexus_ts");
}

fn stop_rm(b: &Box, dirs: &[&str]) {
    for d in dirs {
        let dir = format!("/var/lib/postgresql/{d}");
        b.exec(&["pg_ctl", "-D", &dir, "-m", "immediate", "stop"]);
        b.exec(&["rm", "-rf", &dir]);
    }
}

/// Recovery to an LSN and to a named restore point, a tablespace moved to a new
/// directory, PostgreSQL started by the plugin.
#[test]
fn restore_targets_tablespaces_and_start() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = testbox("restore_targets_tablespaces_and_start") else {
        return;
    };
    let b = Box { env };
    drop_tablespace(&b);
    stop_rm(&b, &["ts_src", "lsn1", "lsn1_ts", "rp1", "rp1_ts", "nots"]);
    b.exec(&["mkdir", "-m", "700", "/var/lib/postgresql/ts_src"]);
    b.psql(false, "postgres", "CREATE TABLESPACE nexus_ts LOCATION '/var/lib/postgresql/ts_src'");
    b.psql(false, "postgres", "CREATE DATABASE pitrts");
    b.psql(false, "pitrts", "CREATE TABLE t (id int PRIMARY KEY) TABLESPACE nexus_ts");
    let oid = b.psql(false, "postgres", "SELECT oid FROM pg_tablespace WHERE spcname = 'nexus_ts'");
    let h = b.host();
    let cfg = b.config();
    let full = h.backup(&cfg, None).unwrap();
    assert!(full.summary.starts_with("full:"), "{} {:?}", full.summary, h.log());

    b.psql(false, "pitrts", "INSERT INTO t SELECT generate_series(1, 100)");
    let lsn = b.psql(false, "postgres", "SELECT pg_current_wal_lsn()");
    b.psql(false, "pitrts", "INSERT INTO t SELECT generate_series(101, 200)");
    b.psql(false, "postgres", "SELECT pg_create_restore_point('nexus_rp')");
    b.psql(false, "pitrts", "INSERT INTO t SELECT generate_series(201, 300)");
    let inc = h.backup(&cfg, None).unwrap();
    assert!(inc.summary.starts_with("incremental:"), "{} {:?}", inc.summary, h.log());

    // tablespaces need a new directory each
    let e = h.restore(
        &cfg,
        &inc.source,
        inc.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/nots"}),
    );
    let e = format!("{:#}", e.unwrap_err());
    assert!(e.contains(&format!("{oid} (/var/lib/postgresql/ts_src)")), "{e}");
    // two targets at once are refused
    let e = h.restore(
        &cfg,
        &inc.source,
        inc.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/nots", "target_lsn": lsn, "target_name": "nexus_rp"}),
    );
    assert!(format!("{:#}", e.unwrap_err()).contains("at most one"));

    // to the LSN, tablespace by oid, started by the plugin
    let r = h
        .restore(
            &cfg,
            &inc.source,
            inc.time,
            "pitr",
            json!({"directory": "/var/lib/postgresql/lsn1", "target_lsn": lsn, "port": 5494, "start": true,
                   "tablespaces": [format!("{oid}=/var/lib/postgresql/lsn1_ts")]}),
        )
        .unwrap();
    assert!(r.summary.contains("PostgreSQL started"), "{}", r.summary);
    assert!(r.summary.contains(&format!("tablespaces {oid} → /var/lib/postgresql/lsn1_ts")), "{}", r.summary);
    assert_eq!(wait_and_count(&b, "lsn1", 5494, "pitrts"), "100");
    assert_eq!(
        b.psql_port(false, 5494, "postgres", &format!("SELECT pg_tablespace_location({oid})")),
        "/var/lib/postgresql/lsn1_ts"
    );
    b.exec(&["pg_ctl", "-D", "/var/lib/postgresql/lsn1", "-m", "fast", "stop"]);

    // to the named restore point, tablespace by its old path, started here
    h.restore(
        &cfg,
        &inc.source,
        inc.time,
        "pitr",
        json!({"directory": "/var/lib/postgresql/rp1", "target_name": "nexus_rp", "port": 5493,
               "tablespaces": ["/var/lib/postgresql/ts_src=/var/lib/postgresql/rp1_ts"]}),
    )
    .unwrap();
    assert_eq!(start_and_count_db(&b, "rp1", 5493, "pitrts"), "200");

    stop_rm(&b, &["lsn1", "lsn1_ts", "rp1", "rp1_ts"]);
    drop_tablespace(&b);
    b.exec(&["rm", "-rf", "/var/lib/postgresql/ts_src"]);
}

/// HA: the configured host is a standby, the primary is found among `hosts`; after
/// a failover (the replica promoted, the old primary unreachable) the next backup
/// is a full one from the new primary.
#[test]
fn ha_primary_and_failover() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(env) = testbox("ha_primary_and_failover") else {
        return;
    };
    let b = Box { env };
    drop_tablespace(&b);
    stop_rm(&b, &["replica"]);
    let home = "/var/lib/postgresql";
    let (ok, out) = b.exec(&[
        "env",
        &format!("PGPASSWORD={}", b.var("SUPER_PASSWORD")),
        "pg_basebackup",
        "-h",
        "127.0.0.1",
        "-U",
        "postgres",
        "-D",
        &format!("{home}/replica"),
        "-R",
        "-X",
        "stream",
        "-c",
        "fast",
    ]);
    assert!(ok, "pg_basebackup: {out}");
    let (ok, out) = b.exec(&[
        "pg_ctl",
        "-D",
        &format!("{home}/replica"),
        "-l",
        "/tmp/replica.log",
        "-o",
        &format!(
            "-p 5433 -c listen_addresses=0.0.0.0 -c ssl=on -c ssl_cert_file={home}/server.crt -c ssl_key_file={home}/server.key"
        ),
        "-w",
        "start",
    ]);
    assert!(ok, "replica start: {out} {}", b.exec(&["cat", "/tmp/replica.log"]).1);
    assert_eq!(b.psql_port(false, 5433, "postgres", "SELECT pg_is_in_recovery()"), "t");

    let (port, rport) = (b.var("PORT").to_owned(), b.var("REPLICA_PORT").to_owned());
    let h = b.host();
    let mut cfg = b.config();
    cfg["port"] = json!(rport.parse::<u16>().unwrap());
    cfg["hosts"] = json!([format!("127.0.0.1:{port}")]);
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:?}", h.log());
    let want = format!("servers: 127.0.0.1:{rport} standby, 127.0.0.1:{port} primary");
    assert!(h.log().iter().any(|l| l.contains(&want)), "{:?}", h.log());
    let full = h.backup(&cfg, None).unwrap();
    assert!(
        full.summary.starts_with("full:") && full.summary.ends_with(&format!("(from 127.0.0.1:{port})")),
        "{}",
        full.summary
    );
    // no primary at all: validate names the hosts field
    let mut none = cfg.clone();
    none["hosts"] = json!(["127.0.0.1:9"]);
    let v = h.validate(&none).unwrap();
    assert_eq!(v["field"], "hosts", "{v}");

    // failover: the replica becomes the primary (timeline 2), the old one is gone
    let (ok, out) = b.exec(&["pg_ctl", "-D", &format!("{home}/replica"), "-w", "promote"]);
    assert!(ok, "promote: {out}");
    let mut after = b.config();
    after["port"] = json!(9); // the old primary: nothing listens there
    after["hosts"] = json!([format!("127.0.0.1:{rport}")]);
    let again = h.backup(&after, None).unwrap();
    assert!(
        again.summary.starts_with("full:") && again.summary.ends_with(&format!("(from 127.0.0.1:{rport})")),
        "{} {:?}",
        again.summary,
        h.log()
    );
    assert!(h.log().iter().any(|l| l.contains("timeline changed")), "{:?}", h.log());
    assert_eq!(again.meta.as_ref().unwrap()["recoverable"]["timeline"], 2);
    stop_rm(&b, &["replica"]);
}

/// Waits for the end of recovery of a server the plugin started, counts t in `db`.
fn wait_and_count(b: &Box, d: &str, port: u16, db: &str) -> String {
    let t0 = Instant::now();
    while b.psql_port(false, port, "postgres", "SELECT pg_is_in_recovery()") != "f" {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "recovery did not end: {}",
            b.exec(&["cat", &format!("/var/lib/postgresql/{d}/nexus_restore.log")]).1
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    b.psql_port(false, port, db, "SELECT count(*) FROM t")
}

/// Starts PostgreSQL on a restored data directory, waits for the end of recovery, counts t.
fn start_and_count(b: &Box, d: &str, port: u16) -> String {
    start_and_count_db(b, d, port, "pitr")
}

fn start_and_count_db(b: &Box, d: &str, port: u16, db: &str) -> String {
    let dir = format!("/var/lib/postgresql/{d}");
    let log = format!("/tmp/{d}.log");
    let (ok, out) = b.exec(&[
        "pg_ctl",
        "-D",
        &dir,
        "-l",
        &log,
        "-o",
        "-c listen_addresses=''",
        "-w",
        "-t",
        "120",
        "start",
    ]);
    assert!(ok, "pg_ctl start: {out} {}", b.exec(&["cat", &log]).1);
    let t0 = Instant::now();
    while b.psql_port(false, port, "postgres", "SELECT pg_is_in_recovery()") != "f" {
        assert!(
            t0.elapsed() < Duration::from_secs(120),
            "recovery did not end: {}",
            b.exec(&["cat", &log]).1
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let n = b.psql_port(false, port, db, "SELECT count(*) FROM t");
    b.exec(&["pg_ctl", "-D", &dir, "-m", "fast", "stop"]);
    n
}
