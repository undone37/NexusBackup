use super::*;
use chunkstore::{Index, Store, TreeEntry, TreeKind};

fn entry(path: &str, size: u64) -> TreeEntry {
    TreeEntry {
        path: path.as_bytes().to_vec(),
        kind: TreeKind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        mtime_ns: 1_000_000_000,
        ctime_ns: 0,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: Vec::new(),
        chunks: Vec::new(),
        inconsistent: false,
    }
}

fn store(e: &Env, tenant: &str) -> Store {
    Store::open(
        e.cfg.store_base.join(tenant),
        Keyring::new(tenant, &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap()
}

fn commit(st: &Store, time: u64, v: Vec<TreeEntry>) {
    st.commit_snapshot("host-a1", time, &[("tree", Index::Tree { entries: v })])
        .unwrap();
}

fn run(s: &mut Scheduler, kind: &str, tenant: &str, p: Value) -> (String, Value) {
    let id = manual(s, kind, tenant, p);
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let (st, r): (String, Option<String>) =
        s.db.conn()
            .query_row("SELECT state, result FROM jobs WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    (st, serde_json::from_str(&r.unwrap_or_default()).unwrap_or_default())
}

fn flag(s: &Scheduler, time: i64) -> Option<String> {
    s.db.conn()
        .query_row(
            "SELECT anomaly FROM snapshots WHERE tenant='t1' AND source='host-a1' AND time=?1",
            [time],
            |r| r.get(0),
        )
        .unwrap()
}

/// `file_changes` counts the changes against the previous snapshot into
/// `backup_stats`; a mass rename flags the snapshot and raises the `anomaly`
/// alert naming the newest clean snapshot; `snapshot_diff` pages through the
/// paths, only in the job's tenant.
#[test]
fn file_changes_flag_and_diff() {
    let e = env(1);
    let t1 = store(&e, "t1");
    let files: Vec<String> = (0..120).map(|i| format!("docs/f{i:03}.docx")).collect();
    commit(&t1, 1, files.iter().map(|p| entry(p, 10)).collect());
    let mut day2: Vec<TreeEntry> = files.iter().map(|p| entry(p, 10)).collect();
    day2[0].size = 11;
    day2.push(entry("docs/new.docx", 1));
    commit(&t1, 2, day2);
    let mut day3: Vec<TreeEntry> = files[100..].iter().map(|p| entry(p, 10)).collect();
    day3.extend(files[..100].iter().map(|p| entry(&format!("{p}.lockbit"), 10)));
    day3.push(entry("docs/HOW_TO_DECRYPT.txt", 1));
    commit(&t1, 3, day3);
    let mut s = sched(&e);
    for t in 1..=3 {
        s.db.conn()
            .execute(
                "INSERT INTO snapshots (tenant, source, time, local, offsite) VALUES ('t1', 'host-a1', ?1, 1, 0)",
                [t],
            )
            .unwrap();
        s.record_stats("t1", &stats_line("host-a1", t, 1 << 20, 1 << 19))
            .unwrap();
    }
    let counts = |s: &Scheduler, t: i64| -> (Option<i64>, Option<i64>, Option<i64>) {
        s.db.conn()
            .query_row(
                "SELECT files_added, files_changed, files_deleted FROM backup_stats WHERE source='host-a1' AND time=?1",
                [t],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    };

    // the first snapshot has nothing to compare with
    let (st, r) = run(&mut s, "file_changes", "t1", json!({"source": "host-a1", "time": 1}));
    assert_eq!((st.as_str(), &r["indexed"]), ("ok", &json!(false)));
    let (_, r) = run(&mut s, "file_changes", "t1", json!({"source": "host-a1", "time": 2}));
    assert_eq!(r["base"], 1);
    assert_eq!(counts(&s, 2), (Some(1), Some(1), Some(0)));
    assert_eq!(flag(&s, 2), None);
    assert!(alerts_of(&s, "anomaly").is_empty());

    // snapshot 2 flagged by hand: "last good" skips it
    s.db.conn()
        .execute("UPDATE snapshots SET anomaly='test' WHERE time=2", [])
        .unwrap();
    let (_, r) = run(&mut s, "file_changes", "t1", json!({"source": "host-a1", "time": 3}));
    assert_eq!(counts(&s, 3), (Some(101), Some(0), Some(101)), "{r}");
    let why = flag(&s, 3).unwrap();
    assert!(why.contains("ransom-note") && why.contains("mass rename"), "{why}");
    let a = alerts_of(&s, "anomaly");
    assert_eq!(a.len(), 1);
    assert!(
        a[0].1.starts_with("file-level anomaly on t1/host-a1: snapshot 3:")
            && a[0].1.ends_with("last snapshot before: host-a1/1"),
        "{}",
        a[0].1
    );
    // a cleared flag counts as clean
    s.db.conn()
        .execute("UPDATE snapshots SET anomaly_cleared_at=9 WHERE time=2", [])
        .unwrap();
    assert_eq!(
        s.last_clean("t1", "host-a1", 3).unwrap(),
        "last snapshot before: host-a1/2"
    );
    // the setting switches the signals off (counts stay)
    catalog::set_setting(&s.db.conn(), "anomaly", r#"{"enabled": false}"#).unwrap();
    s.db.conn()
        .execute("UPDATE snapshots SET anomaly=NULL WHERE time=3", [])
        .unwrap();
    run(&mut s, "file_changes", "t1", json!({"source": "host-a1", "time": 3}));
    assert_eq!(flag(&s, 3), None);
    // admins' extra patterns
    catalog::set_setting(&s.db.conn(), "anomaly", r#"{"ransom_notes": ["*.lockbit"]}"#).unwrap();
    let (_, r) = run(&mut s, "file_changes", "t1", json!({"source": "host-a1", "time": 3}));
    assert_eq!(r["notes_total"], 101);

    // the diff: one page of deletions from 1 to 3
    let (st, r) = run(
        &mut s,
        "snapshot_diff",
        "t1",
        json!({"source": "host-a1", "base": 1, "time": 3, "change": "deleted", "offset": 10, "limit": 5}),
    );
    assert_eq!(st, "ok");
    assert_eq!((r["total"].as_u64(), r["added"].as_u64()), (Some(100), Some(101)));
    let paths: Vec<&str> = r["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["docs/f010.docx", "docs/f011.docx", "docs/f012.docx", "docs/f013.docx", "docs/f014.docx"]);
    // default base = the previous snapshot
    let (_, r) = run(&mut s, "snapshot_diff", "t1", json!({"source": "host-a1", "time": 2}));
    assert_eq!((r["base"].as_u64(), r["total"].as_u64()), (Some(1), Some(2)));
    // another tenant's store has no such snapshot; bad parameters fail
    store(&e, "t2");
    let (st, _) = run(&mut s, "snapshot_diff", "t2", json!({"source": "host-a1", "time": 3, "base": 1}));
    assert_eq!(st, "failed");
    for bad in [
        json!({"source": "host-a1", "time": 3, "base": 3}),
        json!({"source": "host-a1", "time": 3, "change": "x"}),
        json!({"source": "../x", "time": 3}),
        json!({"source": "host-a1", "time": 3, "limit": 5000}),
    ] {
        let (st, _) = run(&mut s, "snapshot_diff", "t1", bad.clone());
        assert_eq!(st, "failed", "{bad}");
    }
}

/// Backups queue `file_changes` for their tree snapshots; VM/CT snapshots wait
/// for their `file_index` job.
#[test]
fn changes_follow_backups() {
    let e = env(1);
    let s = sched(&e);
    let log = format!(
        "{}{}",
        stats_line("host-a1", 5, 1, 1),
        stats_line("vm-100", 5, 1, 1)
    );
    s.queue_changes_after_backup("t1", &log).unwrap();
    let jobs: Vec<String> =
        s.db.conn()
            .prepare("SELECT params FROM jobs WHERE kind='file_changes'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|x| x.unwrap())
            .collect();
    assert_eq!(jobs, [r#"{"source":"host-a1","time":5}"#]);
}
