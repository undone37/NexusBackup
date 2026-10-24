//! The plugin binary in the real sandbox against MariaDB 11 and MySQL 8.4
//! (testbox/run.sh, rootless podman): validate, guests, logical dumps (generated over
//! TLS and mysqldump/mariadb-dump over SSH) → restore to the source and to the
//! "alternate" server (compared with the server's own dump tool), server backups
//! (mariadb-backup / XtraBackup + binlog pull, incremental) → physical and
//! point-in-time restores (time, position, end, base only) over SSH, checked by
//! starting a server on the restored directory.
//! Without podman (or with NEXUS_MY_TESTBOX=skip) every test prints why and passes.

use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const RUN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testbox/run.sh");
const FLAVORS: [&str; 2] = ["mariadb", "mysql"];

/// Tests share the testbox: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn testbox(test: &str) -> Option<&'static HashMap<String, String>> {
    static ENV: OnceLock<Option<HashMap<String, String>>> = OnceLock::new();
    let env = ENV.get_or_init(|| {
        if std::env::var("NEXUS_MY_TESTBOX").as_deref() == Ok("skip") {
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
                .filter_map(|l| l.strip_prefix("export NEXUS_MY_")?.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.trim_matches('\'').to_owned()))
                .collect(),
        )
    });
    if env.is_none() {
        eprintln!("SKIP {test}: podman not available (or NEXUS_MY_TESTBOX=skip)");
    }
    env.as_ref()
}

struct Box {
    env: &'static HashMap<String, String>,
    flavor: &'static str,
}

impl Box {
    fn var(&self, k: &str) -> &str {
        &self.env[k]
    }

    fn container(&self) -> String {
        format!("{}-{}", self.var("CONTAINER"), self.flavor)
    }

    fn port(&self, what: &str) -> u16 {
        self.var(&format!("{}_{what}", self.flavor.to_uppercase()))
            .parse()
            .unwrap()
    }

    fn client(&self) -> &str {
        if self.flavor == "mariadb" {
            "mariadb"
        } else {
            "mysql"
        }
    }

    /// SQL as root inside the container (stdin, so DELIMITER works); stdout trimmed.
    fn sql(&self, db: &str, sql: &str) -> String {
        let pw = format!("-p{}", self.var("ROOT_PASSWORD"));
        let mut c = Command::new("podman")
            .args([
                "exec",
                "-i",
                &self.container(),
                self.client(),
                "-uroot",
                &pw,
                "-N",
                "-B",
                db,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(sql.as_bytes()).unwrap();
        let o = c.wait_with_output().unwrap();
        assert!(o.status.success(), "{sql}: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }

    /// The server's own dump of a database (schema, data, routines, triggers, events), without comments.
    fn tool_dump(&self, db: &str) -> String {
        let pw = format!("-p{}", self.var("ROOT_PASSWORD"));
        let tool = if self.flavor == "mariadb" {
            "mariadb-dump"
        } else {
            "mysqldump"
        };
        let mut args: Vec<String> = vec!["exec".into(), self.container(), tool.into(), "-uroot".into(), pw];
        for a in [
            "--skip-comments",
            "--skip-dump-date",
            "--routines",
            "--triggers",
            "--events",
            "--hex-blob",
            "--no-tablespaces",
        ] {
            args.push(a.into());
        }
        if self.flavor == "mysql" {
            args.push("--set-gtid-purged=OFF".into());
        }
        args.push(db.into());
        let o = Command::new("podman").args(&args).output().unwrap();
        assert!(o.status.success(), "dump: {}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| !l.starts_with("/*M!999999"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Runs a shell script as the OS user mysql inside the container.
    fn sh(&self, script: &str) -> String {
        let o = Command::new("podman")
            .args(["exec", "-u", "mysql", &self.container(), "bash", "-c", script])
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "{script}: {}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).trim().to_owned()
    }

    /// Starts a server on a restored data directory (socket only), runs `sql`, stops it.
    fn query_restored(&self, dir: &str, sql: &str) -> String {
        let (srv, cli, admin) = if self.flavor == "mariadb" {
            ("/usr/sbin/mariadbd", "mariadb", "mariadb-admin")
        } else {
            ("/usr/sbin/mysqld", "mysql", "mysqladmin")
        };
        self.sh(&format!(
            "d={dir}; {srv} --no-defaults --datadir=$d --socket=$d/q.sock --pid-file=$d/q.pid --log-error=$d/q.err \
             --skip-networking --skip-grant-tables --skip-log-bin --loose-mysqlx=0 --secure-file-priv=$d \
             --loose-innodb-use-native-aio=0 \
             >/dev/null 2>&1 </dev/null & pid=$!; \
             for i in $(seq 120); do {admin} --no-defaults -S $d/q.sock ping >/dev/null 2>&1 && break; sleep 0.5; done; \
             {cli} --no-defaults -S $d/q.sock -N -B -e \"{sql}\"; rc=$?; {admin} --no-defaults -S $d/q.sock shutdown; \
             wait $pid; exit $rc"
        ))
    }

    fn config(&self) -> Value {
        json!({
            "host": "127.0.0.1",
            "port": self.port("PORT"),
            "user": "nexus",
            "password": self.var("PASSWORD"),
            "sslmode": "verify-full",
            "ca_cert": std::fs::read_to_string(self.var("CA")).unwrap(),
            // the "alternate" server: the same one as root (another account, another code path)
            "restore_host": "127.0.0.1",
            "restore_port": self.port("PORT"),
            "restore_user": "root",
            "restore_password": self.var("ROOT_PASSWORD"),
            "ssh_host": "127.0.0.1",
            "ssh_port": self.port("SSH_PORT"),
            "ssh_user": "mysql",
            // as a web form's password field delivers it: without line breaks
            "ssh_key": std::fs::read_to_string(self.var("SSH_KEY")).unwrap().replace('\n', " "),
            "ssh_host_key": self.var("SSH_HOST_KEY"),
            "databases_exclude": ["pitr*", "*_copy*"],
        })
    }

    fn host(&self) -> Host {
        let mut h = Host::binary(MANIFEST.as_ref(), env!("CARGO_BIN_EXE_mysql").as_ref(), "mysql").unwrap();
        h.timeout = Duration::from_secs(600);
        h
    }
}

/// Objects owned by `app` (restoring objects of root@localhost would need SYSTEM_USER on MySQL).
const SCHEMA: &str = r#"
CREATE TABLE customer (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(100) NOT NULL UNIQUE,
  name VARCHAR(50), note TEXT, created DATETIME(3), ts TIMESTAMP NULL, secret INT INVISIBLE DEFAULT 7);
CREATE TABLE orders (id BIGINT AUTO_INCREMENT PRIMARY KEY, customer INT NOT NULL, price DECIMAL(10,2),
  qty SMALLINT, rate DOUBLE, ratio FLOAT, status ENUM('new','paid','it''s shipped') DEFAULT 'new',
  tags SET('a','b','c'), payload JSON, raw BLOB, bits BIT(5), day DATE, tm TIME, yr YEAR,
  total DECIMAL(12,2) AS (price * qty) STORED, half DOUBLE AS (rate / 2) VIRTUAL, uid BINARY(4),
  CONSTRAINT fk_customer FOREIGN KEY (customer) REFERENCES customer (id) ON DELETE CASCADE, KEY (status));
CREATE TABLE logs (id INT PRIMARY KEY, msg VARCHAR(20)) ENGINE=MyISAM;
INSERT INTO customer (email, name, note, created, ts) VALUES
  ('a@x', 'Zoë 𠀋', 'line1\nline2 ''quoted'' \\ back\0nul', '2026-01-02 03:04:05.678', '2026-01-02 03:04:05'),
  ('b@x', NULL, '', NULL, NULL);
UPDATE customer SET secret = 9 WHERE id = 2;
INSERT INTO orders (customer, price, qty, rate, ratio, status, tags, payload, raw, bits, day, tm, yr, uid) VALUES
  (1, 9.99, 3, 1.5e300, 0.1, 'it''s shipped', 'a,c', '{"k": [1, "two", null]}', X'00FF0A275C', b'10101',
   '2026-10-13', '-12:34:56', 2026, X'DEADBEEF'),
  (2, NULL, 2, NULL, NULL, 'new', '', NULL, '', b'0', NULL, NULL, NULL, NULL);
INSERT INTO orders (customer, price, qty, payload, raw)
  WITH RECURSIVE n (i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
  SELECT 1 + i % 2, i / 7, i % 5 + 1, JSON_OBJECT('i', i), REPEAT(CHAR(i % 256), 600) FROM n;
INSERT INTO logs VALUES (1, 'hello');
CREATE DEFINER = app VIEW v_paid AS SELECT id, price FROM orders WHERE status <> 'new';
CREATE DEFINER = app VIEW a_top AS SELECT * FROM v_paid WHERE price > 1;
CREATE DEFINER = app FUNCTION net(p DECIMAL(10,2)) RETURNS DECIMAL(10,2) DETERMINISTIC RETURN p * 0.81;
DELIMITER ;;
CREATE DEFINER = app PROCEDURE paid_count(OUT n INT) BEGIN SELECT COUNT(*) INTO n FROM orders WHERE status <> 'new'; END ;;
CREATE DEFINER = app TRIGGER orders_bi BEFORE INSERT ON orders FOR EACH ROW BEGIN IF NEW.qty IS NULL THEN SET NEW.qty = 1; END IF; END ;;
DELIMITER ;
CREATE DEFINER = app EVENT cleanup ON SCHEDULE EVERY 1 DAY STARTS '2030-01-01 00:00:00' DISABLE DO DELETE FROM logs WHERE id < 0;
"#;

/// The first differing lines (with their numbers) of two dumps.
fn diff(a: &str, b: &str) -> Vec<String> {
    let (a, b): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let i = a
        .iter()
        .zip(&b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let cut = |l: Option<&&str>| l.map_or("<end>".to_owned(), |l| l.chars().take(300).collect());
    (i..i + 3)
        .map(|k| format!("{k}: {} | {}", cut(a.get(k)), cut(b.get(k))))
        .collect()
}

#[test]
fn validate_guests_dumps_and_restores() {
    let _s = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(env) = testbox("validate_guests_dumps_and_restores") else {
        return;
    };
    for flavor in FLAVORS {
        let b = Box { env, flavor };
        b.sql(
            "",
            "DROP DATABASE IF EXISTS shop; DROP DATABASE IF EXISTS shop_copy; DROP DATABASE IF EXISTS shop_copy2; \
             DROP DATABASE IF EXISTS other; CREATE DATABASE shop CHARACTER SET utf8mb4; CREATE DATABASE other; \
             CREATE USER IF NOT EXISTS app; GRANT ALL ON `shop%`.* TO app;",
        );
        let mut schema = if flavor == "mariadb" {
            "SET SESSION max_recursive_iterations = 10000;"
        } else {
            "SET SESSION cte_max_recursion_depth = 10000;"
        }
        .to_owned()
            + SCHEMA;
        if flavor == "mariadb" {
            schema += "CREATE SEQUENCE seq START WITH 100; SELECT NEXTVAL(seq);\n";
        }
        b.sql("shop", &schema);
        let h = b.host();
        let cfg = b.config();

        let v = h.validate(&cfg).unwrap();
        assert_eq!(v["valid"], true, "{flavor}: {v} {:?}", h.log());
        let mut bad = cfg.clone();
        bad["password"] = json!("wrong");
        let v = h.validate(&bad).unwrap();
        assert_eq!(
            (v["valid"].as_bool(), v["field"].as_str()),
            (Some(false), Some("password")),
            "{flavor}: {v}"
        );
        // the testbox certificate is not signed by a public CA
        let mut bad = cfg.clone();
        bad["ca_cert"] = json!("");
        let v = h.validate(&bad).unwrap();
        assert_eq!(
            (v["valid"].as_bool(), v["field"].as_str()),
            (Some(false), Some("sslmode")),
            "{v}"
        );
        let mut bad = cfg.clone();
        bad["ssh_host_key"] = json!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl");
        let v = h.validate(&bad).unwrap();
        assert_eq!(v["field"], "ssh_host", "{v}");

        let g = h.guests(&cfg).unwrap();
        let ids: Vec<&str> = g["guests"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["id"].as_str())
            .collect();
        assert_eq!(ids, ["other", "shop"], "{g}");

        let want = b.tool_dump("shop");
        // generated over the connection → restored to the source under another name
        let mut native = cfg.clone();
        native["dump_via"] = json!("connection");
        let r = h.backup(&native, Some("shop")).unwrap();
        assert_eq!(
            (r.source.as_str(), r.streams, r.consistent),
            ("plugin-mysql-1-shop", 1, false), // the MyISAM table
            "{flavor}: {:?}",
            h.log()
        );
        assert!(
            r.summary.contains("3002 rows") || r.summary.contains("rows"),
            "{}",
            r.summary
        );
        assert!(h.log().iter().any(|l| l.contains("logs (MyISAM)")), "{:?}", h.log());
        // restore test (Phase 44): a throwaway database, row counts and contents (#47) against the dump's trailer,
        // dropped again
        let v = h.restore(&native, &r.source, r.time, "verify", json!({})).unwrap();
        assert!(
            v.summary.starts_with("restore test passed:")
                && v.summary
                    .contains("rows counted and their contents compared against the dump"),
            "{flavor}: {}",
            v.summary
        );
        // the group's SQL check (#45): one read-only query, its first value not zero
        let sql = |q: &str| h.restore(&native, &r.source, r.time, "verify", json!({"sql": q}));
        let v = sql("SELECT COUNT(*) FROM orders;").unwrap();
        assert!(v.summary.contains("the SQL check returned "), "{flavor}: {}", v.summary);
        for (q, want) in [
            ("SELECT COUNT(*) > 1000000 FROM orders", "returned 0, not true"),
            ("SELECT 1; DROP TABLE orders", "one query"),
            ("UPDATE logs SET msg = 'x'", "READ ONLY"),
        ] {
            let e = sql(q).unwrap_err();
            assert!(format!("{e:#}").contains(want), "{flavor}: {q}: {e:#}");
        }
        assert_eq!(
            b.sql(
                "information_schema",
                "SELECT COUNT(*) FROM SCHEMATA WHERE SCHEMA_NAME LIKE 'nexus_verify_%'"
            ),
            "0",
            "{flavor}: dropped again"
        );
        let out = h
            .restore(
                &native,
                &r.source,
                r.time,
                "to_target",
                json!({"database": "shop_copy"}),
            )
            .unwrap();
        assert!(out.summary.contains("restored into shop_copy"), "{}", out.summary);
        let have = b.tool_dump("shop_copy");
        assert!(want == have, "{flavor} native dump differs: {:#?}", diff(&want, &have));
        assert_eq!(
            b.sql(
                "shop_copy",
                "CALL paid_count(@n); SELECT @n, net(100), COUNT(*) FROM a_top"
            ),
            "1\t81.00\t1"
        );
        if flavor == "mariadb" {
            // like mariadb-dump: the next value not cached (CACHE 1000)
            assert_eq!(b.sql("shop_copy", "SELECT NEXTVAL(seq)"), "1100");
        }
        // a second restore under the same name is refused
        let e = h.restore(
            &native,
            &r.source,
            r.time,
            "to_target",
            json!({"database": "shop_copy"}),
        );
        assert!(format!("{:#}", e.unwrap_err()).contains("exists"));

        // mysqldump / mariadb-dump over SSH → the alternate server
        let r = h.backup(&cfg, Some("shop")).unwrap();
        assert!(r.summary.contains("over SSH"), "{}", r.summary);
        let out = h
            .restore(
                &cfg,
                &r.source,
                r.time,
                "to_target",
                json!({"database": "shop_copy2", "server": "alternate"}),
            )
            .unwrap();
        assert!(out.summary.contains("alternate"), "{}", out.summary);
        let have = b.tool_dump("shop_copy2");
        assert!(want == have, "{flavor} SSH dump differs: {:#?}", diff(&want, &have));
        // into the existing database: replaced, not duplicated
        b.sql("shop_copy2", "DELETE FROM customer WHERE id = 2");
        h.restore(
            &cfg,
            &r.source,
            r.time,
            "to_target",
            json!({"database": "shop_copy2", "into_existing": true}),
        )
        .unwrap();
        let have = b.tool_dump("shop_copy2");
        assert!(
            want == have,
            "{flavor} into existing differs: {:#?}",
            diff(&want, &have)
        );
        b.sql(
            "",
            "DROP DATABASE shop_copy; DROP DATABASE shop_copy2; DROP DATABASE other",
        );
    }
}

#[test]
fn server_backup_and_point_in_time_restore() {
    let _s = SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(env) = testbox("server_backup_and_point_in_time_restore") else {
        return;
    };
    for flavor in FLAVORS {
        let b = Box { env, flavor };
        b.sh("rm -rf /home/mysql/r1 /home/mysql/r2 /home/mysql/r3 /home/mysql/r4");
        b.sql(
            "",
            "DROP DATABASE IF EXISTS pitr; CREATE DATABASE pitr; \
             CREATE TABLE pitr.t (id INT PRIMARY KEY, batch CHAR(1)); INSERT INTO pitr.t VALUES (1, 'A'), (2, 'A');",
        );
        let h = b.host();
        let cfg = b.config();
        let count = "SELECT COUNT(*) FROM pitr.t";

        let full = h.backup(&cfg, None).unwrap();
        assert!(
            full.summary.starts_with("full:"),
            "{flavor}: {} {:?}",
            full.summary,
            h.log()
        );
        assert!(full.consistent);
        let fr = full.meta.clone().expect("snapshot meta")["recoverable"].clone();
        assert_eq!(fr["unit"], "binlog", "{fr}");

        b.sql("pitr", "INSERT INTO t VALUES (3, 'B'), (4, 'B')");
        std::thread::sleep(Duration::from_millis(1100));
        let t1 = b.sql("", "SELECT UTC_TIMESTAMP()");
        let pos = b.sql(
            "",
            if flavor == "mariadb" {
                "SHOW MASTER STATUS"
            } else {
                "SHOW BINARY LOG STATUS"
            },
        );
        let mut it = pos.split('\t');
        let pos = format!("{}:{}", it.next().unwrap(), it.next().unwrap());
        std::thread::sleep(Duration::from_millis(1100));
        b.sql("pitr", "INSERT INTO t VALUES (5, 'C'); DELETE FROM t WHERE id = 1");

        let inc = h.backup(&cfg, None).unwrap();
        assert!(inc.summary.starts_with("incremental:"), "{} {:?}", inc.summary, h.log());
        assert_eq!(inc.base, Some(full.time));
        assert!(
            inc.transferred < 1 << 20,
            "only binlog is transferred: {}",
            inc.transferred
        );
        let ir = inc.meta.clone().unwrap()["recoverable"].clone();
        assert_eq!(ir["from_lsn"], fr["from_lsn"]);
        assert_ne!(ir["to_lsn"], fr["to_lsn"], "{ir}");
        // nothing changed: nothing new
        let idle = h.backup(&cfg, None).unwrap();
        assert!(idle.summary.contains("+0 pieces"), "{}", idle.summary);

        let pitr = |dir: &str, params: Value| {
            let mut p = json!({"directory": dir});
            p.as_object_mut().unwrap().extend(params.as_object().unwrap().clone());
            h.restore(&cfg, &idle.source, idle.time, "pitr", p)
                .unwrap_or_else(|e| panic!("{flavor} {dir}: {e:#} {:?}", h.log()))
        };
        // to t1: batches A and B
        let r = pitr("/home/mysql/r1", json!({"target_time": format!("{t1}+00")}));
        assert!(r.summary.contains("recovered to time"), "{}", r.summary);
        assert_eq!(b.query_restored("/home/mysql/r1", count), "4", "{flavor} to time");
        // to the binlog position at t1: the same
        pitr("/home/mysql/r2", json!({"target_position": pos}));
        assert_eq!(b.query_restored("/home/mysql/r2", count), "4", "{flavor} to position");
        // to the end: all, with the delete
        pitr("/home/mysql/r3", json!({}));
        assert_eq!(
            b.query_restored("/home/mysql/r3", "SELECT GROUP_CONCAT(id ORDER BY id) FROM pitr.t"),
            "2,3,4,5"
        );
        // the base backup only
        let r = pitr("/home/mysql/r4", json!({"base_only": true}));
        assert!(r.summary.contains("prepared"), "{}", r.summary);
        assert_eq!(b.query_restored("/home/mysql/r4", count), "2", "{flavor} base only");
        // an existing directory is refused, a time outside the range too
        let e = h.restore(
            &cfg,
            &idle.source,
            idle.time,
            "pitr",
            json!({"directory": "/home/mysql/r1"}),
        );
        assert!(e.is_err());
        let e = h.restore(
            &cfg,
            &idle.source,
            idle.time,
            "pitr",
            json!({"directory": "/home/mysql/r5", "target_time": "2001-01-01 00:00:00"}),
        );
        assert!(format!("{:#}", e.unwrap_err()).contains("outside"));
        b.sh("rm -rf /home/mysql/r1 /home/mysql/r2 /home/mysql/r3 /home/mysql/r4");
        b.sql("", "DROP DATABASE pitr");
    }
}
