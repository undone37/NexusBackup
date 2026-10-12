use super::*;

const RK: &str = "1a2b-3c4d-5e6f-7a8b-9c0d-1e2f-3a4b-5c6d-7e8f-9a0b-1c2d-3e4f-5a6b-7c8d-9e0f-1a2b";

fn count(s: &Scheduler, sql: &str) -> i64 {
    s.db.conn().query_row(sql, [], |r| r.get(0)).unwrap()
}

/// A fake nexus-offsite: records its arguments; `list --json` prints a listing;
/// `attach` checks the one-time key file (content, mode) and removes it.
fn offsite_env() -> (Env, Scheduler) {
    let mut e = env(2);
    let p = e.d.path().to_owned();
    let bin = p.join("offsite");
    script(
        &bin,
        &format!(
            r#"echo "$@" >> {calls}
case "$2" in
  list) echo '[{{"source":"vm-100","time":5,"size":10,"lock_until":0,"inventory":true,"remote":true,"local":false}}]';;
  attach) [ "$(stat -c %a "$3")" = 600 ] && [ "$(cat "$3")" = "{RK}" ] || exit 1; rm "$3"; echo attached;;
esac"#,
            calls = p.join("offsite-calls").display()
        ),
    );
    e.cfg.offsite_bin = bin;
    let s = sched(&e);
    let o = json!({"remote": {"type": "sftp", "host": "box.example", "port": 23, "user": "u1",
                              "host_key": "ssh-ed25519 AAA", "key_file": "/etc/nexus/ssh/offsite"}});
    s.db.conn()
        .execute("UPDATE tenants SET offsite = ?1 WHERE name = 't1'", [o.to_string()])
        .unwrap();
    (e, s)
}

fn calls(e: &Env) -> String {
    fs::read_to_string(e.d.path().join("offsite-calls")).unwrap_or_default()
}

#[test]
fn offsite_list_and_fetch_back() {
    let (e, mut s) = offsite_env();
    let list = manual(&s, "offsite_list", "t1", json!({}));
    let fetch = manual(&s, "offsite_restore", "t1", json!({"source": "vm-100", "time": 5}));
    let bad = manual(&s, "offsite_restore", "t1", json!({"source": "../x", "time": 5}));
    let none = manual(&s, "offsite_list", "t2", json!({}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    s.start_jobs().unwrap(); // the fetch waits for the list (same tenant key)
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, list), "ok");
    let r: String =
        s.db.conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [list], |r| r.get(0))
            .unwrap();
    let r: Value = serde_json::from_str(&r).unwrap();
    assert_eq!(r["snapshots"][0]["source"], "vm-100");
    assert_eq!(state(&s, fetch), "ok");
    let c = calls(&e);
    assert!(c.contains(" list --json\n"), "{c}");
    assert!(c.contains(" restore vm-100 5 604800\n"), "7-day local keep: {c}");
    assert_eq!(state(&s, bad), "failed");
    assert_eq!(state(&s, none), "failed", "t2 has no offsite target");
}

/// Attach: approved request + the sealed key in the job; the key leaves the
/// row when the job is planned, reaches the CLI as a 0600 file only, and
/// never shows up in the audit log; success creates the tenant.
#[test]
fn attach_offsite_copy() {
    let (e, mut s) = offsite_env();
    let target = json!({"remote": {"type": "sftp", "host": "box2.example", "port": 2323, "user": "u2",
                                   "host_key": "ssh-ed25519 BBB", "key_file": "/etc/nexus/ssh/offsite"}});
    let now = catalog::now();
    let q = |name: &str, decided: i64| -> i64 {
        let c = s.db.conn();
        c.execute(
            "INSERT INTO quorum (action, params, requested_by, created, decided_by, decided_at, state)
             VALUES ('tenant.attach_offsite', ?1, 'sam', ?2, 'ada', ?2, 'approved')",
            params![json!({"name": name, "offsite": target}).to_string(), decided],
        )
        .unwrap();
        c.last_insert_rowid()
    };
    let (ok_q, old_q) = (q("newco", now), q("oldco", now - 73 * 3600));
    assert_eq!(
        s.attach_targets().unwrap(),
        vec![("box2.example".to_owned(), 2323)],
        "egress only for approved requests inside the window"
    );
    let pk = s.secrets.public();
    let seal = |id: i64, t: &str, key: &str| pk.seal(&catalog::secret::attach_key_location(id, t), key).unwrap();
    // wrong key first: the job fails, the request stays approved
    let wrong = manual(
        &s,
        "offsite_attach",
        "newco",
        json!({"attach_quorum": ok_q, "recovery_key": seal(ok_q, "newco", "nope")}),
    );
    // a key sealed for another request does not open here
    let moved = manual(
        &s,
        "offsite_attach",
        "newco",
        json!({"attach_quorum": ok_q, "recovery_key": seal(old_q, "oldco", RK)}),
    );
    let expired = manual(
        &s,
        "offsite_attach",
        "oldco",
        json!({"attach_quorum": old_q, "recovery_key": seal(old_q, "oldco", RK)}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    for id in [wrong, moved, expired] {
        assert_eq!(state(&s, id), "failed", "job {id}");
    }
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM jobs WHERE json_extract(params, '$.recovery_key') IS NOT NULL"
        ),
        0,
        "every key left its job row"
    );
    assert_eq!(count(&s, "SELECT COUNT(*) FROM tenants WHERE name = 'newco'"), 0);
    assert_eq!(
        count(
            &s,
            &format!("SELECT COUNT(*) FROM quorum WHERE id = {ok_q} AND state = 'approved'")
        ),
        1
    );

    let good = manual(
        &s,
        "offsite_attach",
        "newco",
        json!({"attach_quorum": ok_q, "recovery_key": seal(ok_q, "newco", RK)}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    assert_eq!(state(&s, good), "ok");
    assert!(calls(&e).contains(" attach "), "{}", calls(&e));
    let o: String =
        s.db.conn()
            .query_row("SELECT offsite FROM tenants WHERE name = 'newco'", [], |r| r.get(0))
            .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&o).unwrap(), target);
    assert_eq!(
        count(
            &s,
            &format!("SELECT COUNT(*) FROM quorum WHERE id = {ok_q} AND state = 'executed'")
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            "SELECT COUNT(*) FROM audit WHERE action = 'tenant.attach_offsite' AND target = 'tenant/newco'"
        ),
        1
    );
    assert_eq!(
        count(
            &s,
            &format!("SELECT COUNT(*) FROM audit WHERE details LIKE '%{}%'", &RK[..9])
        ),
        0
    );
    assert!(
        s.attach_targets().unwrap().is_empty(),
        "executed: no more egress of its own"
    );
    assert_eq!(
        fs::read_dir(&e.cfg.runtime_dir).unwrap().count(),
        0,
        "job dirs (and key files) removed"
    );
    // used up
    let again = manual(
        &s,
        "offsite_attach",
        "newco",
        json!({"attach_quorum": ok_q, "recovery_key": seal(ok_q, "newco", RK)}),
    );
    s.start_jobs().unwrap();
    assert_eq!(state(&s, again), "failed");
}
