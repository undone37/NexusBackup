use super::*;

const DAY: i64 = 86400;

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// Stands in for nexus-config-backup: answers the next request with `state`.
fn helper(dir: PathBuf, state: &'static str) -> std::thread::JoinHandle<Value> {
    std::thread::spawn(move || {
        let req = dir.join("request.json");
        for _ in 0..400 {
            if let Ok(b) = fs::read(&req) {
                fs::remove_file(&req).unwrap();
                let r: Value = serde_json::from_slice(&b).unwrap();
                fs::write(dir.join("latest.bundle"), b"NXCFGB1\0sealed").unwrap();
                let st = json!({"id": r["id"], "state": state, "created": 1_800_000_000, "appliance": r["appliance"],
                                "bytes": 14, "sha256": "ab", "files": ["var/lib/nexus/catalog/catalog.db"],
                                "error": "kek.recovery: No such file"});
                fs::write(dir.join("status.json"), st.to_string()).unwrap();
                return r;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("no request");
    })
}

fn config_env(offsite_ok: bool) -> (Env, Scheduler) {
    let mut e = env(4);
    let p = e.d.path().to_owned();
    e.cfg.config_backup_dir = p.join("cfgb");
    fs::create_dir_all(&e.cfg.config_backup_dir).unwrap();
    e.cfg.config_backup_timeout_secs = 20;
    script(
        &p.join("offsite"),
        &format!(
            "echo \"$@\" >> {}/offsite-calls; {}",
            p.display(),
            if offsite_ok { "echo uploaded" } else { "echo 'connection refused' >&2; exit 1" }
        ),
    );
    e.cfg.offsite_bin = p.join("offsite");
    // t1 has an offsite target, t2 none
    e.db.conn()
        .execute(
            "UPDATE tenants SET offsite = ?1 WHERE name = 't1'",
            [json!({"remote": {"type": "local", "path": p.join("box")}}).to_string()],
        )
        .unwrap();
    let s = sched(&e);
    (e, s)
}

/// Bundle by the helper (request/answer), result recorded, one upload per
/// target, the offsite tool called with `config-put`, alerts raised and resolved.
#[test]
fn backup_then_upload_to_every_target() {
    let (e, mut s) = config_env(true);
    let id = manual(&s, "config_backup", "-", json!({}));
    let h = helper(e.cfg.config_backup_dir.clone(), "done");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    let req = h.join().unwrap();
    assert_eq!(req["id"], id);
    let appliance = catalog::setting(&s.db.conn(), crate::config_backup::APPLIANCE_ID).unwrap().unwrap();
    assert_eq!(req["appliance"], appliance.as_str());
    assert_eq!(appliance.len(), 16);
    assert_eq!(state(&s, id), "ok");
    let result: String = s
        .db
        .conn()
        .query_row("SELECT result FROM jobs WHERE id = ?1", [id], |r| r.get(0))
        .unwrap();
    assert!(result.contains("\"bytes\":14"), "{result}");

    assert_eq!(
        count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'config_upload'"),
        1,
        "t1 only"
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'config_upload' AND state = 'ok'"), 1);
    let calls = fs::read_to_string(e.d.path().join("offsite-calls")).unwrap();
    assert!(
        calls.contains(&format!("config-put {}/latest.bundle {appliance} 1800000000", e.cfg.config_backup_dir.display())),
        "{calls}"
    );
    // the same id on the next run
    assert_eq!(s.appliance_id().unwrap(), appliance);
}

#[test]
fn failures_raise_keyed_warnings_that_resolve() {
    let (e, mut s) = config_env(false);
    let open = |s: &Scheduler, key: &str| {
        count(
            s,
            &format!("SELECT COUNT(*) FROM alerts WHERE key = '{key}' AND severity = 'warning' AND resolved_at IS NULL"),
        )
    };
    manual(&s, "config_backup", "-", json!({}));
    let h = helper(e.cfg.config_backup_dir.clone(), "error");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    h.join().unwrap();
    assert_eq!(open(&s, "config_backup"), 1);
    let msg: String = s
        .db
        .conn()
        .query_row("SELECT message FROM alerts WHERE key = 'config_backup'", [], |r| r.get(0))
        .unwrap();
    assert!(msg.contains("kek.recovery"), "{msg}");
    assert_eq!(count(&s, "SELECT COUNT(*) FROM jobs WHERE kind = 'config_upload'"), 0);

    manual(&s, "config_backup", "-", json!({}));
    let h = helper(e.cfg.config_backup_dir.clone(), "done");
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    h.join().unwrap();
    assert_eq!(open(&s, "config_backup"), 0, "resolved by the next success");
    // the upload fails: its own alert per target
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(open(&s, "config_backup:t1"), 1);
}

/// Daily, scheduler-queued (first sight waits), never twice at once; not
/// queued where the helper is not installed.
#[test]
fn daily_schedule() {
    let (e, mut s) = config_env(true);
    let jobs = |s: &Scheduler| count(s, "SELECT COUNT(*) FROM jobs WHERE kind = 'config_backup'");
    let t0 = 1_791_763_200; // 2026-10-12 00:00 UTC
    s.now = t0;
    s.queue_config_backup(t0).unwrap();
    assert_eq!(jobs(&s), 0, "first sight");
    s.now = t0 + 3 * 3600; // after 02:30
    s.queue_config_backup(s.now).unwrap();
    assert_eq!(jobs(&s), 1);
    s.queue_config_backup(s.now + 60).unwrap();
    assert_eq!(jobs(&s), 1, "queued one is not duplicated");
    s.db.conn().execute("UPDATE jobs SET state = 'ok'", []).unwrap();
    s.now = t0 + DAY + 3 * 3600;
    s.queue_config_backup(s.now).unwrap();
    assert_eq!(jobs(&s), 2);

    fs::remove_dir(&e.cfg.config_backup_dir).ok();
    s.db.conn().execute("UPDATE jobs SET state = 'ok'", []).unwrap();
    s.now = t0 + 2 * DAY + 3 * 3600;
    s.queue_config_backup(s.now).unwrap();
    assert_eq!(jobs(&s), 2, "no helper dir: nothing queued");
}
