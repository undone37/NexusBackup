use super::*;
use chunkstore::{Index, Store, TreeEntry, TreeKind};

fn entry(path: &str, size: u64, mtime: i64) -> TreeEntry {
    TreeEntry {
        path: path.as_bytes().to_vec(),
        kind: TreeKind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        mtime_ns: mtime * 1_000_000_000,
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

fn tree(v: Vec<TreeEntry>) -> [(&'static str, Index); 1] {
    [("tree", Index::Tree { entries: v })]
}

fn run(s: &mut Scheduler, kind: &str, tenant: &str, p: Value) -> (i64, Value) {
    let id = manual(s, kind, tenant, p);
    // follow-ups of earlier jobs (retention) may hold the same key first
    for _ in 0..5 {
        s.start_jobs().unwrap();
        s.wait_idle(Duration::from_secs(20)).unwrap();
    }
    let (st, log, r): (String, String, Option<String>) =
        s.db.conn()
            .query_row("SELECT state, log, result FROM jobs WHERE id=?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
    assert_eq!(st, "ok", "{kind}: {log}");
    (id, serde_json::from_str(&r.unwrap_or_default()).unwrap_or_default())
}

/// The search runs in the scheduler with the tenant's keyring, sees only that
/// tenant's store, collapses versions; the backfill writes missing indexes once.
#[test]
fn file_search_and_backfill() {
    let e = env(4);
    let t1 = store(&e, "t1");
    t1.commit_snapshot("host-a1", 1, &tree(vec![entry("home/ann/report.txt", 5, 10)]))
        .unwrap();
    t1.commit_snapshot("host-a1", 2, &tree(vec![entry("home/ann/report.txt", 5, 10)]))
        .unwrap();
    t1.commit_snapshot("share-2", 3, &tree(vec![entry("Report.TXT", 7, 11)]))
        .unwrap();
    store(&e, "t2")
        .commit_snapshot("host-b1", 4, &tree(vec![entry("report-of-t2.txt", 1, 1)]))
        .unwrap();
    let mut s = sched(&e);

    let id = manual(&s, "file_search", "t1", json!({"query": "report*"}));
    s.start_jobs().unwrap();
    assert_eq!(
        s.running(),
        vec![(id, format!("search:{id}"))],
        "never waits for the tenant"
    );
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let r: Value =
        s.db.conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| {
                Ok(serde_json::from_str(&r.get::<_, String>(0)?).unwrap())
            })
            .unwrap();
    assert_eq!(r["scanned"], 3);
    let m = r["matches"].as_array().unwrap();
    assert_eq!(m.len(), 2, "{r}");
    assert_eq!((&m[0]["source"], &m[0]["times"]), (&json!("share-2"), &json!([3])));
    assert_eq!(
        (&m[1]["path"], &m[1]["times"]),
        (&json!("home/ann/report.txt"), &json!([2, 1]))
    );

    let (_, r) = run(
        &mut s,
        "file_search",
        "t2",
        json!({"query": "report", "case_sensitive": true}),
    );
    let paths: Vec<&Value> = r["matches"].as_array().unwrap().iter().map(|m| &m["path"]).collect();
    assert_eq!(paths, [&json!("report-of-t2.txt")]);

    // snapshots from before the name index: the backfill writes them, once
    fs::remove_file(e.cfg.store_base.join("t1/snapshots/host-a1/1/names")).unwrap();
    let (_, r) = run(&mut s, "file_index", "t1", json!({}));
    assert_eq!(r, json!({"built": 1, "skipped": 2}));
    let (_, r) = run(&mut s, "file_index", "t1", json!({}));
    assert_eq!(r, json!({"built": 0, "skipped": 3}));
    assert!(e.cfg.store_base.join("t1/snapshots/host-a1/1/names").exists());
}

/// A backup of a group with `index_files` queues `file_index` for its VM/CT
/// snapshots; that job runs nexus-pve `files <vmid> <time> index` store-only.
#[test]
fn vm_index_follows_group_backups() {
    let mut e = env(4);
    let p = e.d.path().to_owned();
    script(
        &p.join("pve2"),
        &format!(
            "echo \"$@\" >> {0}/calls2\ncase \"$2\" in backup-all) echo committed vm-100/5;; files|ct-files) echo '{{\"entries\": 3, \"complete\": true}}';; esac",
            p.display()
        ),
    );
    e.cfg.pve_bin = p.join("pve2");
    let mut s = sched(&e);
    let index_jobs = |s: &Scheduler| -> Vec<Value> {
        s.db.conn()
            .prepare("SELECT params FROM jobs WHERE kind='file_index' ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|x| serde_json::from_str(&x.unwrap()).unwrap())
            .collect()
    };
    run(&mut s, "backup", "t1", json!({"group_id": 1}));
    assert!(index_jobs(&s).is_empty(), "off by default");
    s.db.conn()
        .execute("UPDATE groups SET index_files = 1 WHERE id = 1", [])
        .unwrap();
    run(&mut s, "backup", "t1", json!({"group_id": 1}));
    let jobs = index_jobs(&s);
    assert_eq!(jobs, vec![json!({"source": "vm-100", "time": 5})]);
    // the queued job (and any later one) runs nexus-pve against the store only
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(20)).unwrap();
    let r: String =
        s.db.conn()
            .query_row(
                "SELECT result FROM jobs WHERE kind='file_index' AND state='ok'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&r).unwrap()["entries"], 3);
    let calls = fs::read_to_string(p.join("calls2")).unwrap();
    assert!(calls.lines().any(|l| l.ends_with("files 100 5 index")), "{calls}");
    let job = Job {
        id: 99,
        kind: "file_index".into(),
        tenant: "t1".into(),
        params: json!({"source": "ct-300", "time": 7}),
    };
    let plan = s.plan(&job).unwrap();
    assert_eq!(plan.key, "guest:t1/ct-300");
    let Step::Cli { args, .. } = &plan.steps[0] else {
        panic!()
    };
    assert_eq!(&args[1..], ["ct-files", "300", "7", "index"]);
    let cfg: Value = serde_json::from_slice(&plan.files[0].1).unwrap();
    assert!(cfg.get("api").is_none(), "no PVE credentials: {cfg}");
    for bad in [json!({"source": "host-x", "time": 1}), json!({"source": "vm-1"})] {
        let job = Job {
            params: bad,
            ..job.clone()
        };
        assert!(s.plan(&job).is_err());
    }
}
