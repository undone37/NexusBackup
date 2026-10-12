//! Phase 15e/f in the scheduler loop against fake connectors: PVE exclude disks and
//! parallel guests in nexus-pve's config, cancelling a parallel run stops every
//! reported vzdump task, a partial failure retries only the failed guest; agent
//! backups carry the merged filters (source + policy) and the agent's limits;
//! agent certificates are renewed automatically (second pin, promotion, audit,
//! alert resolved) and a re-enrollment keeps the agent id.

use catalog::secret::{agent_token_location, SchedulerKey};
use catalog::Catalog;
use chunkstore::{Keyring, Options};
use scheduler::run::KeySource;
use scheduler::{Config, Scheduler};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const A: &str = "0123456789abcdef";
const FP: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const FP2: &str = "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34";
const FP3: &str = "ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56ef56";

fn opts() -> Options {
    Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    }
}

fn q<T: catalog::rusqlite::types::FromSql>(db: &Catalog, sql: &str) -> T {
    db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn script(path: &Path, body: &str) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
        .unwrap();
    f.write_all(format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
}

fn job(db: &Catalog, kind: &str, p: Value) -> i64 {
    let c = db.conn();
    c.execute(
        "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1,'acme',?2,'queued','alice',0)",
        catalog::rusqlite::params![kind, p.to_string()],
    )
    .unwrap();
    c.last_insert_rowid()
}

fn state(db: &Catalog, id: i64) -> (String, String) {
    db.conn()
        .query_row("SELECT state, log FROM jobs WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
}

fn config(p: &Path) -> Config {
    Config {
        catalog: p.join("catalog/catalog.db"),
        store_base: p.join("store"),
        offsite_state_base: p.join("offsite"),
        escrow_base: p.join("escrow"),
        downloads: p.join("downloads"),
        runtime_dir: p.join("run"),
        state_dir: p.join("state"),
        pve_bin: p.join("nexus-pve"),
        offsite_bin: p.join("nexus-offsite-missing"),
        agentctl_bin: p.join("nexus-agentctl"),
        alerts_config: p.join("alerts.json"),
        nft_allowed: p.join("nft/allowed.json"),
        firewall_settle_secs: 0,
        alert_retry_secs: [0, 0],
        capacity_threshold: 2.0,
        inventory_secs: 0,
        cancel_grace_secs: 2,
        refresh_secs: 0,
        ..Default::default()
    }
}

fn scheduler(p: &Path, cfg: &Config) -> (Arc<Catalog>, Scheduler) {
    fs::create_dir_all(p.join("catalog")).unwrap();
    fs::create_dir_all(p.join("nft")).unwrap();
    fs::create_dir_all(&cfg.state_dir).unwrap();
    let db = Arc::new(Catalog::open(&cfg.catalog).unwrap());
    let k: KeySource = Arc::new(|t: &str| Ok(Keyring::new(t, &[(1, [42; 32])])));
    let s = Scheduler::new(cfg.clone(), db.clone(), k, opts).unwrap();
    (db, s)
}

fn run(s: &mut Scheduler, db: &Catalog) {
    for _ in 0..10 {
        s.tick(catalog::now()).unwrap();
        s.wait_idle(Duration::from_secs(30)).unwrap();
        if q::<i64>(db, "SELECT COUNT(*) FROM jobs WHERE state='queued' AND (not_before IS NULL OR not_before <= strftime('%s','now'))") == 0 {
            return;
        }
    }
    panic!("jobs still queued");
}

#[test]
fn pve_exclude_disks_parallel_cancel_and_retry() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    script(
        &p.join("nexus-pve"),
        &format!(
            r#"D={d}
cfg="$1"; shift
echo "$@" >> $D/calls
case "$1" in
  backup-all) cp "$cfg" $D/last-pve.json
     echo "upid: UPID:n1:0001:A:vzdump:100:root@pam:" >&2
     echo "upid: UPID:n2:0002:B:vzdump:101:root@pam:" >&2
     if [ -e $D/slow ]; then sleep 30; fi
     echo "committed vm-100/5000"
     if [ -e $D/fail-101 ]; then echo "backup of guest 101 failed: vzdump error" >&2; exit 1; fi
     echo "committed vm-101/5000";;
  task-stop) ;;
  push-index) ;;
  *) ;;
esac"#,
            d = p.display()
        ),
    );
    let cfg = config(p);
    let (db, mut s) = scheduler(p, &cfg);
    let src = json!({"api": {"host": "pve", "ca_pem": "CA", "token_id": "t@pve!x", "token_secret": "s3cret"},
                     "storage": "nx", "fleecing_storage": "local",
                     "nodes": {"n1": {"host": "10.0.0.1", "key_pem": "KEY", "known_hosts_text": "10.0.0.1 ssh-ed25519 AAA"}}});
    db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name) VALUES ('acme');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'pve', 'pve', '{src}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES (1, 'p', 'daily 22:00', '{{\"daily\":2}}', 0);
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests, exclude_disks, exclude_disks_mode,
               parallel_guests) VALUES (1, 'acme', 1, 1, 'vms', '[100,101]',
               '{{\"*\":[\"scsi1\"],\"101\":[\"virtio2\"]}}', 'omit', 2);"
        ))
        .unwrap();

    // config: device names per vmid, restore mode, parallelism
    let b = job(&db, "backup", json!({"group_id": 1}));
    run(&mut s, &db);
    assert_eq!(state(&db, b).0, "ok", "{}", state(&db, b).1);
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-pve.json")).unwrap()).unwrap();
    assert_eq!(c["vmids"], json!([100, 101]));
    assert_eq!(c["parallel"], 2);
    assert_eq!(c["exclude_disks_mode"], "omit");
    assert_eq!(
        c["exclude_disks"],
        json!({"100": ["drive-scsi1"], "101": ["drive-scsi1", "drive-virtio2"]})
    );

    // cancel during a parallel run: both reported vzdump tasks are stopped
    fs::write(p.join("slow"), "").unwrap();
    fs::write(p.join("calls"), "").unwrap();
    let c = job(&db, "backup", json!({"group_id": 1}));
    s.tick(catalog::now()).unwrap();
    let t = Instant::now();
    while !fs::read_to_string(p.join("calls")).unwrap().contains("backup-all") {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(300));
    db.conn()
        .execute("UPDATE jobs SET cancel_by = 'alice' WHERE id = ?1", [c])
        .unwrap();
    while state(&db, c).0 == "running" || state(&db, c).0 == "queued" {
        assert!(t.elapsed() < Duration::from_secs(25), "cancel took too long");
        s.tick(catalog::now()).unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    s.wait_idle(Duration::from_secs(10)).unwrap();
    assert_eq!(state(&db, c).0, "cancelled", "{}", state(&db, c).1);
    let calls = fs::read_to_string(p.join("calls")).unwrap();
    assert!(
        calls.contains("task-stop UPID:n2:0002:B:vzdump:101:root@pam:"),
        "{calls}"
    );
    assert!(
        calls.contains("task-stop UPID:n1:0001:A:vzdump:100:root@pam:"),
        "{calls}"
    );
    fs::remove_file(p.join("slow")).unwrap();

    // one guest fails: the retry backs up only that guest
    fs::write(p.join("fail-101"), "").unwrap();
    let f = job(&db, "backup", json!({"group_id": 1}));
    s.tick(catalog::now()).unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    s.collect();
    assert_eq!(state(&db, f).0, "failed");
    let r: Value = serde_json::from_str(&q::<String>(&db, &format!("SELECT result FROM jobs WHERE id={f}"))).unwrap();
    assert_eq!(r["failed_guests"], json!([101]), "{r}");
    let retry: String = q(
        &db,
        &format!("SELECT params FROM jobs WHERE retry_of = {f} AND kind = 'backup'"),
    );
    let retry: Value = serde_json::from_str(&retry).unwrap();
    assert_eq!(retry["guests"], json!([101]), "{retry}");
}

#[test]
fn agent_filters_limits_renewal_and_reenroll() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    // FP: enrolled; renew issues FP2 (confirmed) or, with `half`, FP3 and dies before RenewOk
    script(
        &p.join("nexus-agentctl"),
        &format!(
            r#"D={d}
cfg="$1"; shift
echo "$@" >> $D/calls
cp "$cfg" $D/last-$1.json
id={A}
now=$(date +%s)
case "$1" in
  backup) cur=$(sed -n 's/.*"cert_sha256": "\([0-9a-f]*\)".*/\1/p' "$cfg" | head -1)
          [ -e $D/present ] && cur=$(cat $D/present)
          echo 'agent-cert {{"agent_id":"'$id'","cert_sha256":"'$cur'","not_before":'$((now-3600))',"not_after":'$((now+20*86400))'}}'
          echo "committed host-$id/$now in 1.0s: 3 entries, 30 bytes, 0 unchanged files, 2 chunks transferred (30 bytes, 2 new)";;
  renew) if [ -e $D/half ]; then
           echo 'renew-issued {{"agent_id":"'$id'","cert_sha256":"{FP3}","not_before":'$now',"not_after":'$((now+3650*86400))'}}'
           echo "agent error: connection reset" >&2; exit 1
         fi
         echo 'renew-issued {{"agent_id":"'$id'","cert_sha256":"{FP2}","not_before":'$now',"not_after":'$((now+3650*86400))'}}'
         echo 'renewed {{"agent_id":"'$id'","cert_sha256":"{FP2}","not_before":'$now',"not_after":'$((now+3650*86400))'}}';;
  enroll) echo 'enrolled {{"agent_id":"'$id'","cert_sha256":"{FP}","appliance_id":"x"}}'
          echo 'agent-cert {{"agent_id":"'$id'","cert_sha256":"{FP}","not_before":'$now',"not_after":'$((now+3650*86400))'}}';;
  *) exit 2;;
esac"#,
            d = p.display()
        ),
    );
    let cfg = config(p);
    let (db, mut s) = scheduler(p, &cfg);
    let src = json!({"agent_id": A, "paths": ["/"], "excludes": ["*.tmp"], "include": ["/home", "/etc"],
                     "exclude_regex": ["\\.bak$"], "cross_mounts": true, "skip_fstypes": ["tmpfs"]});
    db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name) VALUES ('acme');
             INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at, limits) VALUES
               ('{A}', 'acme', 'web01', '10.0.0.9', 7444, '{FP}', strftime('%s','now'), '{{\"bwlimit\":1000000,\"nice\":10}}');
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'linux', 'web01', '{src}');
             INSERT INTO policies (id, name, schedule, gfs, offsite, file_filters) VALUES
               (1, 'gold', 'daily 22:00', '{{\"daily\":2}}', 0, '{{\"exclude\":[\"/var/cache/**\"],\"exclude_regex\":[\"~$\"]}}');
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES (1, 'acme', 1, 1, 'hosts', '[\"{A}\"]');"
        ))
        .unwrap();

    // the backup config: source + policy filters, the agent's limits; the session
    // reports the certificate (expires in 20 days: renewal due)
    let b = job(&db, "backup", json!({"group_id": 1}));
    run(&mut s, &db);
    assert_eq!(state(&db, b).0, "ok", "{}", state(&db, b).1);
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-backup.json")).unwrap()).unwrap();
    assert_eq!(c["backup"]["excludes"], json!(["*.tmp", "/var/cache/**"]));
    assert_eq!(
        c["backup"]["filters"],
        json!({"include": ["/home", "/etc"], "exclude_regex": ["\\.bak$", "~$"], "cross_mounts": true,
               "skip_fstypes": ["tmpfs"]})
    );
    assert_eq!(c["backup"]["limits"], json!({"bwlimit": 1000000, "nice": 10}));

    // the following refresh ticks: expiry alert (20 days left), automatic renewal
    // (second pin first, then the new certificate only), alert resolved
    run(&mut s, &db);
    assert_eq!(
        q::<String>(
            &db,
            &format!("SELECT severity FROM alerts WHERE key = 'cert_expiry:agent:{A}'")
        ),
        "warning"
    );

    let r: (String, String) = db
        .conn()
        .query_row("SELECT state, params FROM jobs WHERE kind = 'agent_renew'", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(r.0, "ok");
    assert!(r.1.contains("\"auto\":true"));
    let (cur, next, exp): (String, Option<String>, i64) = db
        .conn()
        .query_row(
            "SELECT cert_sha256, cert_sha256_next, cert_expires FROM agents",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((cur.as_str(), next), (FP2, None));
    assert!(exp > catalog::now() + 3000 * 86400);
    assert_eq!(
        q::<i64>(&db, "SELECT COUNT(*) FROM audit WHERE action = 'agent.cert_renewed'"),
        1
    );
    assert_eq!(
        q::<i64>(
            &db,
            &format!("SELECT COUNT(*) FROM alerts WHERE key = 'cert_expiry:agent:{A}' AND resolved_at IS NULL")
        ),
        0,
        "the expiry alert is resolved"
    );
    run(&mut s, &db);
    assert_eq!(
        q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE kind = 'agent_renew'"),
        1,
        "not due again"
    );

    // "Renew certificate now" that breaks after the CSR was signed: the new
    // fingerprint is a second pin; the next session presenting it confirms it
    fs::write(p.join("half"), "").unwrap();
    let h = job(&db, "agent_renew", json!({"agent_id": A}));
    run(&mut s, &db);
    assert_eq!(state(&db, h).0, "failed");
    assert_eq!(q::<String>(&db, "SELECT cert_sha256_next FROM agents"), FP3);
    assert_eq!(q::<String>(&db, "SELECT cert_sha256 FROM agents"), FP2);
    fs::write(p.join("present"), FP3).unwrap();
    let b2 = job(&db, "backup", json!({"agent_id": A}));
    run(&mut s, &db);
    assert_eq!(state(&db, b2).0, "ok");
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-backup.json")).unwrap()).unwrap();
    assert_eq!(
        (
            c["agent"]["cert_sha256"].as_str(),
            c["agent"]["cert_sha256_next"].as_str()
        ),
        (Some(FP2), Some(FP3))
    );
    assert_eq!(
        c["backup"]["filters"]["exclude_regex"],
        json!(["\\.bak$"]),
        "outside a group: no policy filters"
    );
    let (cur, next): (String, Option<String>) = db
        .conn()
        .query_row("SELECT cert_sha256, cert_sha256_next FROM agents", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((cur.as_str(), next), (FP3, None));

    // re-enrollment (agent lost its key): same id, groups and snapshots keep pointing at it
    let (sk, _) = SchedulerKey::load_or_create(&cfg.secrets_key_path()).unwrap();
    let sealed = sk
        .public()
        .seal(&agent_token_location(A, "10.0.0.9", 7444), &"d1".repeat(32))
        .unwrap();
    db.conn()
        .execute(
            "UPDATE agents SET token_hash = ?1, token_expires = ?2",
            catalog::rusqlite::params![sealed, catalog::now() + 3600],
        )
        .unwrap();
    let e = job(&db, "agent_enroll", json!({"agent_id": A}));
    run(&mut s, &db);
    assert_eq!(state(&db, e).0, "ok", "{}", state(&db, e).1);
    let (id, cur, exp): (String, String, i64) = db
        .conn()
        .query_row("SELECT id, cert_sha256, cert_expires FROM agents", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!((id.as_str(), cur.as_str()), (A, FP));
    assert!(exp > catalog::now() + 3000 * 86400);
    assert_eq!(
        q::<String>(&db, "SELECT guests FROM groups WHERE id = 1"),
        format!("[\"{A}\"]")
    );
}
