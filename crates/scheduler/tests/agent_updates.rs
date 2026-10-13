//! Phase 27: agent updates in the scheduler loop against a fake `nexus-agentctl`:
//! the release chosen for `agent_update` jobs, rollouts in waves (canary, soak,
//! concurrency), busy agents retried instead of failed, unreachable / blacked-out /
//! busy agents held back, the failure threshold pausing a rollout with its alerts,
//! automatic mode, and rollbacks only for approved rollouts.

use agent_core::releases::testing::Signer;
use catalog::agent_updates::{self as au, Spec};
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
use std::time::Duration;

const FP: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";
const AGENTS: [&str; 4] = [
    "a000000000000001",
    "a000000000000002",
    "a000000000000003",
    "a000000000000004",
];

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

struct Env {
    _d: tempfile::TempDir,
    p: std::path::PathBuf,
    db: Arc<Catalog>,
    s: Scheduler,
}

impl Env {
    fn new() -> Env {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().to_owned();
        // update-result per agent: fail-<id> fails, busy-<id> answers busy once
        script(
            &p.join("nexus-agentctl"),
            &format!(
                r#"D={d}
cfg="$1"; shift
id=$(sed -n 's/.*"id": "\([0-9a-f]*\)".*/\1/p' "$cfg" | head -1)
cp "$cfg" $D/last-$id.json
echo "$1 $id" >> $D/calls
v=$(sed -n 's/.*"version": "\([0-9.]*\)".*/\1/p' "$cfg" | head -1)
case "$1" in
  update)
    echo 'agent-info {{"agent_id":"'$id'","version":"0.1.0","os":"Debian GNU/Linux 13","caps":["update2","arch=x86_64","install=deb"]}}'
    if [ -e $D/busy-$id ]; then rm $D/busy-$id
      echo 'update-result {{"agent_id":"'$id'","state":"busy","version":"0.1.0","error":"agent error 409: jobs are running"}}'; exit 1; fi
    if [ -e $D/fail-$id ]; then
      echo 'update-result {{"agent_id":"'$id'","state":"failed","version":"0.1.0","error":"package install failed (exit-code, exit status 100)"}}'; exit 1; fi
    echo 'agent-info {{"agent_id":"'$id'","version":"'$v'","os":"Debian GNU/Linux 13","caps":["update2","arch=x86_64","install=deb"]}}'
    echo 'update-result {{"agent_id":"'$id'","state":"ok","version":"'$v'","error":""}}';;
  *) exit 2;;
esac"#,
                d = p.display()
            ),
        );
        fs::create_dir_all(p.join("nft")).unwrap();
        // the release store: 0.2.0 and 0.3.0 from the image, signed with a pinned key
        let signer = Signer::new();
        fs::create_dir_all(p.join("keys")).unwrap();
        fs::write(p.join("keys/release.pub"), signer.public_pem()).unwrap();
        for v in ["0.2.0", "0.3.0"] {
            signer.write_release(
                &p.join("image"),
                v,
                &[(
                    &format!("linux-x86_64/nexus-agent_{v}_amd64.deb"),
                    "deb",
                    "linux",
                    "x86_64",
                    v.as_bytes(),
                )],
            );
        }
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
            agent_update_dir: p.join("image"),
            agent_release_upload: p.join("upload"),
            agent_release_keys: p.join("keys"),
            alerts_config: p.join("alerts.json"),
            nft_allowed: p.join("nft/allowed.json"),
            firewall_settle_secs: 0,
            alert_retry_secs: [0, 0],
            capacity_threshold: 2.0,
            inventory_secs: 0,
            agent_poll_secs: 0,
            ..Default::default()
        };
        fs::create_dir_all(p.join("catalog")).unwrap();
        let db = Arc::new(Catalog::open(&cfg.catalog).unwrap());
        let mut sql = String::from(
            "INSERT INTO tenants (name) VALUES ('acme');
             INSERT INTO policies (id, name, schedule, gfs, offsite) VALUES
               (1, 'gold', 'daily 22:00', '{\"daily\":2,\"weekly\":0,\"monthly\":0,\"yearly\":0}', 0);
             INSERT INTO sources (id, tenant, kind, name, config) VALUES (1, 'acme', 'linux', 'web', '{}');",
        );
        for (i, a) in AGENTS.iter().enumerate() {
            sql.push_str(&format!(
                "INSERT INTO agents (id, tenant, name, host, port, cert_sha256, enrolled_at, version, os) VALUES
                   ('{a}', 'acme', 'host{i}', '10.0.0.{i}', 7444, '{FP}', 1, '0.1.0', 'Debian GNU/Linux 13');"
            ));
        }
        // paused: no scheduled backups of the group get in the way of the busy checks
        sql.push_str(&format!(
            "INSERT INTO groups (id, tenant, source_id, policy_id, name, guests, paused_until) \
             VALUES (1, 'acme', 1, 1, 'web', '[\"{}\"]', 9999999999);",
            AGENTS[3]
        ));
        db.conn().execute_batch(&sql).unwrap();
        let k: KeySource = Arc::new(|t: &str| Ok(Keyring::new(t, &[(1, [42; 32])])));
        let s = Scheduler::new(cfg, db.clone(), k, Options::default).unwrap();
        Env { _d: d, p, db, s }
    }

    /// One scheduler round: tick (rollouts queue jobs), run them, wait.
    fn round(&mut self) {
        self.s.tick(catalog::now()).unwrap();
        self.s.wait_idle(Duration::from_secs(30)).unwrap();
        self.s.tick(catalog::now()).unwrap();
        self.s.wait_idle(Duration::from_secs(30)).unwrap();
    }

    fn rollout(&self, spec: Value) -> i64 {
        let spec: Spec = serde_json::from_value(spec).unwrap();
        au::create(&self.db.conn(), &spec, "alice", None, false, "running", catalog::now()).unwrap()
    }

    fn items(&self, id: i64) -> Vec<(String, i64, String)> {
        let c = self.db.conn();
        let mut st = c
            .prepare("SELECT agent_id, wave, state FROM agent_rollout_items WHERE rollout_id = ?1 ORDER BY agent_id")
            .unwrap();
        st.query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn state(&self, id: i64) -> String {
        q(&self.db, &format!("SELECT state FROM agent_rollouts WHERE id = {id}"))
    }

    fn calls(&self) -> String {
        fs::read_to_string(self.p.join("calls")).unwrap_or_default()
    }
}

#[test]
fn single_update_uses_the_recommended_release_and_records_the_state() {
    let mut e = Env::new();
    let a = AGENTS[0];
    e.db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_update','acme',?1,'queued','alice',0)",
            [json!({"agent_id": a}).to_string()],
        )
        .unwrap();
    e.round();
    let cfg: Value = serde_json::from_str(&fs::read_to_string(e.p.join(format!("last-{a}.json"))).unwrap()).unwrap();
    assert_eq!(cfg["update"]["version"], "0.3.0", "the newest signed release");
    assert_eq!(cfg["update"]["rollback"], false);
    assert_eq!(cfg["update"]["dirs"], json!([e.p.join("image"), e.p.join("upload")]));
    let (st, target, att, arch, install): (String, String, i64, String, String) =
        e.db.conn()
            .query_row(
                "SELECT update_state, update_target, update_attempts, arch, install FROM agents WHERE id = ?1",
                [a],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
    assert_eq!(
        (st.as_str(), target.as_str(), att, arch.as_str(), install.as_str()),
        ("ok", "0.3.0", 1, "x86_64", "deb")
    );
    // a failure: agent_update_failed instead of job_failed, resolved by the next success
    fs::write(e.p.join(format!("fail-{a}")), "").unwrap();
    e.db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_update','acme',?1,'queued','alice',0)",
            [json!({"agent_id": a, "version": "0.2.0"}).to_string()],
        )
        .unwrap();
    e.round();
    assert_eq!(
        q::<String>(&e.db, &format!("SELECT update_state FROM agents WHERE id = '{a}'")),
        "failed"
    );
    assert!(
        q::<String>(&e.db, &format!("SELECT update_error FROM agents WHERE id = '{a}'")).contains("exit status 100")
    );
    assert_eq!(
        q::<i64>(
            &e.db,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'agent_update_failed' AND resolved_at IS NULL"
        ),
        1
    );
    assert_eq!(
        q::<i64>(&e.db, "SELECT COUNT(*) FROM alerts WHERE kind = 'job_failed'"),
        0
    );
    fs::remove_file(e.p.join(format!("fail-{a}"))).unwrap();
    e.db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_update','acme',?1,'queued','alice',0)",
            [json!({"agent_id": a, "version": "0.3.0"}).to_string()],
        )
        .unwrap();
    e.round();
    assert_eq!(
        q::<i64>(
            &e.db,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'agent_update_failed' AND resolved_at IS NULL"
        ),
        0
    );
    // a rollback outside an approved rollback rollout never reaches the agent
    let before = e.calls().lines().count();
    e.db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('agent_update','acme',?1,'queued','alice',0)",
            [json!({"agent_id": a, "version": "0.2.0", "rollback": true, "rollout_id": 99}).to_string()],
        )
        .unwrap();
    e.round();
    assert_eq!(e.calls().lines().count(), before);
    assert_eq!(
        q::<String>(&e.db, "SELECT state FROM jobs ORDER BY id DESC LIMIT 1"),
        "failed"
    );
}

#[test]
fn rollout_waves_busy_retry_and_holds() {
    let mut e = Env::new();
    let [a1, a2, a3, a4] = AGENTS;
    // a2 answers busy once; a3 is unreachable; a4's group is in a blackout window
    fs::write(e.p.join(format!("busy-{a2}")), "").unwrap();
    e.db.conn()
        .execute_batch(&format!(
            "UPDATE agents SET reachable = 0 WHERE id = '{a3}';
             UPDATE policies SET blackout = '[{{\"from\":\"00:00\",\"to\":\"23:59\"}}]';"
        ))
        .unwrap();
    let id = e.rollout(json!({"version": "0.2.0", "canary": 1, "soak_minutes": 0, "concurrency": 2}));
    let items = e.items(id);
    assert_eq!(
        items[0],
        (a1.to_string(), 0, "waiting".to_string()),
        "the first agent is the canary"
    );
    assert!(items[1..].iter().all(|i| i.1 == 1));
    // round 1: only the canary
    e.round();
    assert_eq!(e.calls().lines().collect::<Vec<_>>(), [format!("update {a1}")]);
    assert_eq!(e.items(id)[0].2, "ok");
    // round 2+: the rest, two at a time; a2 busy -> waiting -> ok later
    for _ in 0..4 {
        e.round();
    }
    let it = e.items(id);
    assert_eq!(it[1].2, "ok", "{it:?}");
    assert_eq!(
        q::<i64>(
            &e.db,
            &format!("SELECT attempts FROM agent_rollout_items WHERE agent_id = '{a2}'")
        ),
        1,
        "a busy answer is no attempt"
    );
    assert_eq!(it[2].2, "waiting", "unreachable: picked up when back");
    assert_eq!(it[3].2, "waiting", "group in a blackout window");
    assert_eq!(e.state(id), "running");
    assert!(!e.calls().contains(a3) && !e.calls().contains(a4));
    // a4 busy with a backup, a3 back online; blackout over
    e.db.conn()
        .execute_batch(&format!(
            "UPDATE agents SET reachable = 1 WHERE id = '{a3}';
             UPDATE policies SET blackout = '[]';
             INSERT INTO jobs (kind, tenant, params, state, requested_by, created)
               VALUES ('backup','acme','{{\"group_id\":1}}','running','scheduler',0);"
        ))
        .unwrap();
    e.round();
    let it = e.items(id);
    assert_eq!((it[2].2.as_str(), it[3].2.as_str()), ("ok", "waiting"));
    e.db.conn()
        .execute_batch("UPDATE jobs SET state = 'failed' WHERE kind = 'backup'")
        .unwrap();
    e.round();
    e.round();
    let jobs: Vec<(i64, String, String, String)> =
        e.db.conn()
            .prepare("SELECT id, kind, state, params FROM jobs ORDER BY id")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
    assert!(e.items(id).iter().all(|i| i.2 == "ok"), "{:?} {jobs:?}", e.items(id));
    assert_eq!(e.state(id), "done");
    assert_eq!(
        q::<i64>(&e.db, "SELECT COUNT(*) FROM agents WHERE update_state = 'ok'"),
        4
    );
}

#[test]
fn failures_pause_rollouts_and_windows_hold_them() {
    let mut e = Env::new();
    let [a1, a2, a3, _] = AGENTS;
    // a failed canary pauses at once
    fs::write(e.p.join(format!("fail-{a1}")), "").unwrap();
    let id = e.rollout(json!({"version": "0.2.0", "canary": 1, "soak_minutes": 0}));
    e.round();
    e.round();
    assert_eq!(e.state(id), "paused");
    assert!(q::<String>(&e.db, &format!("SELECT reason FROM agent_rollouts WHERE id = {id}")).contains("canary"));
    assert_eq!(
        q::<i64>(
            &e.db,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'rollout_paused' AND resolved_at IS NULL"
        ),
        1
    );
    assert_eq!(e.calls().lines().count(), 1, "nothing after the failed canary");
    // resumed by an admin (web-api): the alert resolves, the rest runs; two more
    // failures reach the threshold of 3
    fs::write(e.p.join(format!("fail-{a2}")), "").unwrap();
    fs::write(e.p.join(format!("fail-{a3}")), "").unwrap();
    e.db.conn()
        .execute(
            "UPDATE agent_rollouts SET state = 'running', wave = 1, reason = NULL WHERE id = ?1",
            [id],
        )
        .unwrap();
    for _ in 0..3 {
        e.round();
    }
    assert_eq!(e.state(id), "paused");
    assert!(q::<String>(&e.db, &format!("SELECT reason FROM agent_rollouts WHERE id = {id}")).contains("threshold 3"));
    assert_eq!(
        q::<i64>(
            &e.db,
            "SELECT COUNT(*) FROM alerts WHERE kind = 'agent_update_failed' AND resolved_at IS NULL"
        ),
        3
    );
    // a maintenance window that is not open: nothing starts
    let w = {
        let h = (catalog::now() / 3600 + 3) % 24;
        json!([{"from": format!("{h:02}:00"), "to": format!("{:02}:00", (h + 1) % 24)}])
    };
    let before = e.calls().lines().count();
    e.db.conn()
        .execute("UPDATE agent_rollouts SET state = 'cancelled'", [])
        .unwrap();
    let id2 = e.rollout(json!({"version": "0.3.0", "canary": 0, "windows": w}));
    e.round();
    assert_eq!(e.calls().lines().count(), before);
    assert!(e.items(id2).iter().all(|i| i.2 == "waiting"));
}

#[test]
fn automatic_mode_starts_one_rollout_per_release_and_rollbacks_wait_for_approval() {
    let mut e = Env::new();
    e.db.conn()
        .execute_batch(
            "INSERT INTO agent_update_settings (tenant, mode, canary, soak_minutes, updated, updated_by)
               VALUES ('acme', 'automatic', 1, 0, 1, 'alice');",
        )
        .unwrap();
    e.round();
    let (n, v, auto): (i64, String, bool) =
        e.db.conn()
            .query_row(
                "SELECT COUNT(*), MAX(version), MAX(automatic) FROM agent_rollouts",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    assert_eq!((n, v.as_str(), auto), (1, "0.3.0", true));
    for _ in 0..4 {
        e.round();
    }
    assert_eq!(q::<String>(&e.db, "SELECT state FROM agent_rollouts"), "done");
    // nothing new: no second rollout
    e.s.tick(catalog::now() + 3600).unwrap();
    assert_eq!(q::<i64>(&e.db, "SELECT COUNT(*) FROM agent_rollouts"), 1);

    // a rollback rollout waits for its approval; rejected = rejected
    let spec: Spec = serde_json::from_value(json!({"version": "0.2.0", "rollback": true, "canary": 0})).unwrap();
    let id = au::create(
        &e.db.conn(),
        &spec,
        "alice",
        None,
        false,
        "pending_approval",
        catalog::now(),
    )
    .unwrap();
    e.db.conn()
        .execute_batch(&format!(
            "INSERT INTO quorum (id, action, params, requested_by, created, state) VALUES
               (7, 'agent.rollback', '{{\"rollout_id\":{id}}}', 'alice', 1, 'pending');
             UPDATE agent_rollouts SET quorum_id = 7 WHERE id = {id};"
        ))
        .unwrap();
    let before = e.calls().lines().count();
    e.round();
    assert_eq!(e.state(id), "pending_approval");
    assert_eq!(e.calls().lines().count(), before);
    // approved (the web-api starts it): rollback jobs carry the flag, the agent rolls back
    e.db.conn()
        .execute_batch(&format!(
            "UPDATE quorum SET state = 'executed'; UPDATE agent_rollouts SET state = 'running' WHERE id = {id};"
        ))
        .unwrap();
    for _ in 0..3 {
        e.round();
    }
    let cfg: Value =
        serde_json::from_str(&fs::read_to_string(e.p.join(format!("last-{}.json", AGENTS[0]))).unwrap()).unwrap();
    assert_eq!(
        (cfg["update"]["version"].as_str(), cfg["update"]["rollback"].as_bool()),
        (Some("0.2.0"), Some(true))
    );
    assert_eq!(e.state(id), "done");
    // a rejected one never starts
    let id = au::create(
        &e.db.conn(),
        &spec,
        "alice",
        None,
        false,
        "pending_approval",
        catalog::now(),
    );
    assert!(id.is_err(), "nobody runs something newer than 0.2.0 any more");
    let spec3: Spec = serde_json::from_value(json!({"version": "0.3.0", "canary": 0})).unwrap();
    let id = au::create(
        &e.db.conn(),
        &spec3,
        "alice",
        None,
        false,
        "pending_approval",
        catalog::now(),
    )
    .unwrap();
    e.db.conn()
        .execute_batch(&format!(
            "INSERT INTO quorum (id, action, params, requested_by, created, state) VALUES
               (8, 'agent.rollback', '{{}}', 'alice', 1, 'rejected');
             UPDATE agent_rollouts SET quorum_id = 8 WHERE id = {id};"
        ))
        .unwrap();
    e.round();
    assert_eq!(e.state(id), "rejected");
    assert!(e.items(id).iter().all(|i| i.2 == "cancelled"));
}
