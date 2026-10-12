//! Linux agent jobs in the scheduler loop against a fake `nexus-agentctl`:
//! enrollment bookkeeping (sealed token → job dir, fingerprint recorded, token
//! cleared), group backups → retention, alerts for failed and inconsistent
//! backups, restore_files / file listing configs, host-* snapshot refresh,
//! firewall allow-list.

use catalog::secret::{agent_token_location, SchedulerKey};
use catalog::Catalog;
use chunkstore::{Index, Keyring, Options, Store, TreeEntry, TreeKind};
use scheduler::run::KeySource;
use scheduler::{Config, Scheduler};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const A: &str = "0123456789abcdef";
const B: &str = "fedcba9876543210";
const FP: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

fn keys(t: &str) -> Keyring {
    Keyring::new(t, &[(1, [42; 32])])
}

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

#[test]
fn agent_jobs_lifecycle() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path();
    script(
        &p.join("nexus-agentctl"),
        &format!(
            r#"D={d}
cfg="$1"; shift
echo "$@" >> $D/calls
stat -c %a "$cfg" > $D/mode; cp "$cfg" $D/last-$1.json
id=$(sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' "$cfg" | head -1)
case "$1" in
  enroll) cat "$(dirname "$cfg")/token" > $D/token-copy
          echo 'agent-info {{"agent_id":"'$id'","version":"1.0.0","os":"Debian 13"}}'
          echo 'enrolled {{"agent_id":"'$id'","cert_sha256":"{FP}","appliance_id":"x"}}';;
  backup) if [ -e $D/fail-backup ]; then echo "agent error 500: snapshot failed" >&2; exit 1; fi
          echo 'agent-info {{"agent_id":"'$id'","version":"1.0.1","os":"Debian 13"}}'
          echo "committed host-$id/5000 in 1.0s: 3 entries, 30 bytes, 0 unchanged files, 2 chunks transferred (30 bytes, 2 new)"
          if [ -e $D/inconsistent ]; then echo "inconsistent host-$id/5000: consistent=false (2 files changed while read without a snapshot)"; fi;;
  restore) echo 'restored {{"target":"/srv","files":2,"dirs":1,"bytes":10,"errors":0}}';;
  update) echo "updating";;
  files) if [ "$4" = get ]; then echo x > "$5"; echo "1 entries written to $5"
         else echo '[{{"name":"etc","kind":"dir"}}]'; fi;;
  *) exit 2;;
esac"#,
            d = p.display()
        ),
    );
    fs::create_dir_all(p.join("nft")).unwrap();
    let cfg = Config {
        catalog: p.join("catalog/catalog.db"),
        store_base: p.join("store"),
        offsite_state_base: p.join("offsite"),
        escrow_base: p.join("escrow"),
        downloads: p.join("downloads"),
        runtime_dir: p.join("run"),
        state_dir: p.join("state"),
        pve_bin: p.join("nexus-pve-missing"),
        offsite_bin: p.join("nexus-offsite-missing"),
        agentctl_bin: p.join("nexus-agentctl"),
        agent_update_dir: p.join("agent-update"),
        alerts_config: p.join("alerts.json"),
        nft_allowed: p.join("nft/allowed.json"),
        firewall_settle_secs: 0,
        alert_retry_secs: [0, 0],
        capacity_threshold: 2.0,
        ..Default::default()
    };
    fs::create_dir_all(p.join("catalog")).unwrap();
    let db = Arc::new(Catalog::open(&cfg.catalog).unwrap());
    // the scheduler's key exists before the web-api sealed the token to it
    fs::create_dir_all(&cfg.state_dir).unwrap();
    let (sk, _) = SchedulerKey::load_or_create(&cfg.secrets_key_path()).unwrap();
    let digest = "d1".repeat(32);
    let sealed = sk
        .public()
        .seal(&agent_token_location(A, "10.0.0.9", 7444), &digest)
        .unwrap();
    let src = json!({"agent_id": A, "paths": ["/etc", "/srv"], "excludes": ["*.tmp"], "hooks": true});
    db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenants (name) VALUES ('acme');
             INSERT INTO agents (id, tenant, name, host, port, token_hash, token_expires) VALUES
               ('{A}', 'acme', 'web01', '10.0.0.9', 7444, '{sealed}', {exp}),
               ('{B}', 'acme', 'db01', '10.0.0.10', 7445, NULL, NULL);
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'linux', 'web01', '{src}'),
               (2, 'acme', 'linux', 'db01', '{{\"agent_id\":\"{B}\",\"paths\":[\"/\"]}}');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
               (1, 'gold', 'daily 22:00', '{{\"daily\":2,\"weekly\":0,\"monthly\":0,\"yearly\":0}}', 0);
             -- failures alert right away (no retries, Phase 13b)
             UPDATE policies SET retry = '{{\"count\":0,\"delay_min\":5}}';
             INSERT INTO groups (id, tenant, source_id, policy_id, name, guests) VALUES
               (1, 'acme', 1, 1, 'hosts', '[\"{A}\"]'), (2, 'acme', 2, 1, 'db', '[\"{B}\"]');",
            exp = catalog::now() + 3600
        ))
        .unwrap();
    // a host snapshot already in the store: refreshed into `snapshots`
    let store = Store::open(p.join("store/acme"), keys("acme"), opts()).unwrap();
    let (id, _) = store.insert_chunk(b"hello").unwrap();
    let entry = TreeEntry {
        path: b"etc/hostname".to_vec(),
        kind: TreeKind::File,
        mode: 0o100644,
        uid: 0,
        gid: 0,
        size: 5,
        mtime_ns: 0,
        ctime_ns: 0,
        inode: 1,
        rdev: 0,
        link_target: None,
        xattrs: vec![],
        chunks: vec![id],
        inconsistent: false,
    };
    store
        .commit_snapshot(
            &format!("host-{A}"),
            4000,
            &[("tree", Index::Tree { entries: vec![entry] })],
        )
        .unwrap();
    drop(store);

    let k: KeySource = Arc::new(|t: &str| Ok(keys(t)));
    let mut s = Scheduler::new(cfg.clone(), db.clone(), k, opts).unwrap();
    let wait = Duration::from_secs(30);
    let run = |s: &mut Scheduler| {
        for _ in 0..10 {
            s.tick(catalog::now()).unwrap();
            s.wait_idle(wait).unwrap();
            if q::<i64>(&db, "SELECT COUNT(*) FROM jobs WHERE state='queued'") == 0 {
                return;
            }
        }
        panic!("jobs still queued");
    };

    // enrollment: sealed digest opened into the 0600 job dir, fingerprint recorded, token gone
    let e = job(&db, "agent_enroll", json!({"agent_id": A}));
    // the agent was created after the last tick: starting its job first puts it into the
    // firewall allow-list (lab: enrollment right after creation failed, "No route to host")
    s.start_jobs().unwrap();
    let allowed = fs::read_to_string(p.join("nft/allowed.json")).unwrap();
    assert!(allowed.contains("10.0.0.9") && allowed.contains("7444"), "{allowed}");
    run(&mut s);
    assert_eq!(state(&db, e).0, "ok", "{}", state(&db, e).1);
    assert_eq!(fs::read_to_string(p.join("token-copy")).unwrap(), digest);
    assert_eq!(fs::read_to_string(p.join("mode")).unwrap().trim(), "600");
    let (fp, tok, ver): (String, Option<String>, String) = db
        .conn()
        .query_row(
            &format!("SELECT cert_sha256, token_hash, version FROM agents WHERE id='{A}'"),
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!((fp.as_str(), tok, ver.as_str()), (FP, None, "1.0.0"));
    assert_eq!(
        q::<i64>(&db, "SELECT COUNT(*) FROM audit WHERE action='agent.enrolled'"),
        1
    );
    let r: Value = serde_json::from_str(&q::<String>(&db, &format!("SELECT result FROM jobs WHERE id={e}"))).unwrap();
    assert_eq!(r["cert_sha256"], FP);
    assert_eq!(
        q::<i64>(
            &db,
            "SELECT COUNT(*) FROM snapshots WHERE source='host-0123456789abcdef' AND local=1"
        ),
        1
    );
    // the token is single use: a second enrollment cannot start
    let e2 = job(&db, "agent_enroll", json!({"agent_id": A}));
    run(&mut s);
    assert_eq!(state(&db, e2).0, "failed");

    // group backup → retention for host-<id>; config carries paths, CA, pin
    let b = job(&db, "backup", json!({"group_id": 1}));
    run(&mut s);
    assert_eq!(state(&db, b).0, "ok", "{}", state(&db, b).1);
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-backup.json")).unwrap()).unwrap();
    assert_eq!(c["backup"]["paths"], json!(["/etc", "/srv"]));
    assert_eq!(c["backup"]["hooks"], true);
    assert_eq!(c["agent"]["cert_sha256"], FP);
    assert_eq!(c["agent"]["port"], 7444);
    assert_eq!(c["ca_dir"], json!(p.join("state/agent-ca")));
    assert_eq!(c["job"], b);
    let r: Value = serde_json::from_str(&q::<String>(&db, &format!("SELECT result FROM jobs WHERE id={b}"))).unwrap();
    assert_eq!(r["source"], format!("host-{A}"));
    assert_eq!(r["consistent"], true);
    assert_eq!(r["transferred_bytes"], 30);
    let ret: String = q(&db, "SELECT log FROM jobs WHERE kind='retention'");
    assert!(ret.contains(&format!("retention host-{A}")), "{ret}");
    assert_eq!(
        q::<String>(&db, &format!("SELECT version FROM agents WHERE id='{A}'")),
        "1.0.1"
    );

    // inconsistent backup: ok + warning alert
    fs::write(p.join("inconsistent"), "").unwrap();
    job(&db, "backup", json!({"agent_id": A}));
    run(&mut s);
    assert_eq!(
        q::<i64>(
            &db,
            "SELECT COUNT(*) FROM alerts WHERE kind='backup_inconsistent' AND severity='warning'"
        ),
        1
    );
    let r: Value = serde_json::from_str(&q::<String>(
        &db,
        "SELECT result FROM jobs WHERE kind='backup' ORDER BY id DESC LIMIT 1",
    ))
    .unwrap();
    assert_eq!(r["consistent"], false, "{r}");
    fs::remove_file(p.join("inconsistent")).unwrap();

    // failed agent backup: critical alert
    fs::write(p.join("fail-backup"), "").unwrap();
    let f = job(&db, "backup", json!({"group_id": 1}));
    run(&mut s);
    assert_eq!(state(&db, f).0, "failed");
    let msg: String = q(
        &db,
        "SELECT message FROM alerts WHERE kind='job_failed' ORDER BY id DESC LIMIT 1",
    );
    assert!(msg.contains("snapshot failed"), "{msg}");
    fs::remove_file(p.join("fail-backup")).unwrap();

    // not enrolled: the job fails before anything runs
    let n = job(&db, "backup", json!({"group_id": 2}));
    run(&mut s);
    let (st, log) = state(&db, n);
    assert_eq!(st, "failed");
    assert!(log.contains("not enrolled"), "{log}");

    // restore_files
    let r = job(
        &db,
        "restore_files",
        json!({"source": format!("host-{A}"), "time": 4000, "paths": ["/etc"], "target": "/srv",
               "overwrite": "if_older", "confirm": "web01", "agent_id": A}),
    );
    run(&mut s);
    assert_eq!(state(&db, r).0, "ok", "{}", state(&db, r).1);
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-restore.json")).unwrap()).unwrap();
    assert_eq!(
        c["restore"],
        json!({"source_agent": A, "time": 4000, "paths": ["/etc"], "target": "/srv", "overwrite": "if_older", "confirm": "web01"})
    );
    let res: Value = serde_json::from_str(&q::<String>(&db, &format!("SELECT result FROM jobs WHERE id={r}"))).unwrap();
    assert_eq!(res["files"], 2);

    // file listing / download of a host snapshot
    let l = job(
        &db,
        "files_list",
        json!({"source": format!("host-{A}"), "time": 4000, "path": "/"}),
    );
    let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let g = job(
        &db,
        "files_get",
        json!({"source": format!("host-{A}"), "time": 4000, "paths": ["/etc"], "format": "zip", "download_token": token}),
    );
    run(&mut s);
    let res: Value = serde_json::from_str(&q::<String>(&db, &format!("SELECT result FROM jobs WHERE id={l}"))).unwrap();
    assert_eq!(res["entries"][0]["name"], "etc");
    assert_eq!(state(&db, g).0, "ok");
    assert!(p.join(format!("downloads/{token}.zip")).exists());
    let calls = fs::read_to_string(p.join("calls")).unwrap();
    assert!(calls.contains(&format!("files {A} 4000 ls /")), "{calls}");

    // update
    let u = job(&db, "agent_update", json!({"agent_id": A}));
    run(&mut s);
    assert_eq!(state(&db, u).0, "ok");
    let c: Value = serde_json::from_str(&fs::read_to_string(p.join("last-update.json")).unwrap()).unwrap();
    assert_eq!(c["update_dir"], json!(p.join("agent-update")));

    // the firewall allow-list contains the agents
    let fw = fs::read_to_string(p.join("nft/allowed.json")).unwrap();
    assert!(
        fw.contains("10.0.0.9") && fw.contains("7444") && fw.contains("7445"),
        "{fw}"
    );
    // job dirs (token!) are gone
    assert_eq!(fs::read_dir(p.join("run")).unwrap().count(), 0);
    assert!(db.verify_audit().unwrap() > 0);
}
