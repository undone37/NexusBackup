//! nexus-index end to end on a real chunk store: versions over snapshots,
//! deleted files, rules, VM guest paths from the volume report, Windows agent
//! drive letters, incremental appends, retention (a deleted snapshot),
//! paging, sealing at rest, restart.

use chunkstore::{Index, Keyring, NameIndex, Options, Store, TreeEntry, TreeKind};
use fileindex::service::{Config, Service};
use index_proto::{Deleted, Hit, SearchReq, SourceRules};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

fn keys() -> Keyring {
    Keyring::new("acme", &[(1, [3; 32])])
}

fn e(path: &str, size: u64, mtime: i64) -> TreeEntry {
    TreeEntry {
        path: path.as_bytes().to_vec(),
        kind: if size == u64::MAX {
            TreeKind::Dir
        } else {
            TreeKind::File
        },
        mode: 0o644,
        uid: 0,
        gid: 0,
        size: if size == u64::MAX { 0 } else { size },
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

fn commit(s: &Store, src: &str, t: u64, es: Vec<TreeEntry>) {
    s.commit_snapshot(src, t, &[("tree", Index::Tree { entries: es })])
        .unwrap();
}

fn svc(base: &Path) -> Arc<Service> {
    let cfg = Config {
        store_base: base.join("store"),
        index_base: base.join("index"),
        floor_mb: 0,
        sync_secs: 3600,
        ..Config::default()
    };
    Service::new(cfg, Arc::new(|_| Ok(keys())))
}

fn find(s: &Service, q: &str) -> Vec<Hit> {
    s.search(&SearchReq {
        tenant: "acme".into(),
        q: q.into(),
        limit: 50,
        ..Default::default()
    })
    .unwrap()
    .hits
}

#[test]
fn versions_rules_paths_retention_paging() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(
        d.path().join("store/acme"),
        keys(),
        Options {
            min_lock_secs: 0,
            ..Options::default()
        },
    )
    .unwrap();
    let base = || {
        vec![
            e("etc", u64::MAX, 1),
            e("etc/passwd", 900, 5),
            e("usr/bin/ls", 1000, 5),
            e("var/lib/mysql/ibdata1", 4096, 5),
        ]
    };
    let mut s100 = base();
    s100.push(e("home/ann/report.txt", 5, 10));
    commit(&store, "host-a1", 100, s100);
    let mut s200 = base();
    s200.push(e("home/ann/report.txt", 6, 20));
    s200.push(e("home/ann/Angebot Müller.docx", 77, 30));
    commit(&store, "host-a1", 200, s200);
    let mut s300 = base();
    s300.push(e("home/ann/Angebot Müller.docx", 77, 30));
    commit(&store, "host-a1", 300, s300);
    // a Windows agent: drive letters on top
    commit(
        &store,
        "host-w1",
        150,
        vec![
            e("C/Users/ann/Plan.xlsx", 10, 40),
            e("C/Windows/notepad.exe", 9, 1),
            e("D/Data/x.pdf", 3, 2),
        ],
    );
    // a VM snapshot listed by nexus-fsindex: name index + volume report
    let disk = store.store_image(&[0u8; 512][..], 4096).unwrap();
    store.commit_snapshot("vm-100", 160, &[("drive-scsi0", disk)]).unwrap();
    let mut n = NameIndex::default();
    for (p, k) in [
        ("vda1", 1),
        ("vda1/etc", 1),
        ("vda1/etc/hosts", 0),
        ("vda2", 1),
        ("vda2/ann", 1),
        ("vda2/ann/cv.pdf", 0),
    ] {
        n.push(p, 11, 50, k);
    }
    store.write_names("vm-100", 160, &n).unwrap();
    let vol = |b: &str, m: &str| fsindex::VolumeRec {
        volume: fsindex::Volume {
            browse: b.into(),
            state: "indexed".into(),
            mount: Some(m.into()),
            ..Default::default()
        },
        reads: Vec::new(),
    };
    let rep = fsindex::Report {
        version: 1,
        volumes: vec![vol("vda1", "/"), vol("vda2", "/home")],
    };
    store
        .write_snap_file("vm-100", 160, fsindex::REPORT_FILE, &serde_json::to_vec(&rep).unwrap())
        .unwrap();

    let s = svc(d.path());
    s.sync("acme").unwrap();
    let st = s.status(Some("acme")).unwrap();
    assert_eq!(st.tenants[0].snapshots_indexed, 5, "{st:?}");
    assert_eq!(st.tenants[0].snapshots_pending, 0);

    // versions, newest first; deleted in 300
    let h = find(&s, "report");
    assert_eq!(h.len(), 1, "{h:?}");
    assert_eq!(
        (h[0].source.as_str(), h[0].path.as_str(), h[0].browse.as_str()),
        ("host-a1", "/home/ann/report.txt", "home/ann/report.txt")
    );
    let v: Vec<_> = h[0]
        .versions
        .iter()
        .map(|v| (v.size, v.mtime, v.first, v.gone))
        .collect();
    assert_eq!(v, [(6, 20, 200, Some(300)), (5, 10, 100, Some(200))]);
    // name glob, words, extension, deleted files, path prefix
    assert_eq!(find(&s, "*.DOCX")[0].path, "/home/ann/Angebot Müller.docx");
    assert_eq!(find(&s, "angebot müller")[0].versions.len(), 1);
    let ext = s
        .search(&SearchReq {
            tenant: "acme".into(),
            ext: Some(vec!["pdf".into()]),
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    let mut pdfs: Vec<_> = ext.hits.iter().map(|h| h.path.as_str()).collect();
    pdfs.sort();
    assert_eq!(pdfs, ["/home/ann/cv.pdf", "D:/Data/x.pdf"]);
    let del = s
        .search(&SearchReq {
            tenant: "acme".into(),
            deleted: Deleted::Only,
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        del.hits.iter().map(|h| h.path.as_str()).collect::<Vec<_>>(),
        ["/home/ann/report.txt"]
    );
    assert!(find(&s, "/usr/bin").is_empty(), "default exclude");
    assert_eq!(
        find(&s, "/var/lib/mysql")[0].path,
        "/var/lib/mysql/ibdata1",
        "/var stays"
    );
    // the VM's guest paths, browse paths for the actions
    let h = find(&s, "/etc/hosts");
    assert_eq!(
        (h[0].source.as_str(), h[0].browse.as_str()),
        ("vm-100", "vda1/etc/hosts")
    );
    assert_eq!(find(&s, "cv.pdf")[0].path, "/home/ann/cv.pdf");
    // Windows agent: drive letters, Windows excluded by default
    assert_eq!(find(&s, "plan.xlsx")[0].path, "C:/Users/ann/Plan.xlsx");
    assert!(find(&s, "notepad").is_empty());
    let r = s
        .search(&SearchReq {
            tenant: "acme".into(),
            q: "report".into(),
            limit: 50,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(r.sources["host-a1"].indexed, [100, 200, 300]);

    // sealed at rest: no names in the index files
    for f in std::fs::read_dir(d.path().join("index/acme")).unwrap() {
        let b = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!b.windows(6).any(|w| w == b"report" || w == b"passwd"));
    }

    // incremental: a new snapshot appends
    let mut s400 = base();
    s400.push(e("home/ann/new.txt", 1, 60));
    commit(&store, "host-a1", 400, s400);
    s.sync("acme").unwrap();
    assert_eq!(find(&s, "new.txt").len(), 1);
    let h = find(&s, "Angebot");
    assert_eq!(h[0].versions[0].gone, Some(400), "closed by the append");

    // retention: snapshot 100 goes, its only version with it
    store.delete_snapshot("host-a1", 100).unwrap();
    s.sync("acme").unwrap();
    let v: Vec<_> = find(&s, "report")[0]
        .versions
        .iter()
        .map(|v| (v.first, v.gone))
        .collect();
    assert_eq!(v, [(200, Some(300))]);

    // rules: exclude /home/ann for host-a1
    let mut cfg = BTreeMap::new();
    cfg.insert(
        "host-a1".to_string(),
        SourceRules {
            exclude: vec!["/home/ann".into()],
            ..Default::default()
        },
    );
    assert!(s.configure("acme", cfg.clone()).unwrap());
    assert!(!s.configure("acme", cfg).unwrap(), "unchanged");
    s.sync("acme").unwrap();
    assert!(find(&s, "report").is_empty());
    assert_eq!(find(&s, "passwd").len(), 1);

    // restart: the state comes from the sealed payload
    drop(s);
    let s = svc(d.path());
    assert!(find(&s, "report").is_empty(), "rules kept");
    assert_eq!(find(&s, "cv.pdf").len(), 1);
    // a rebuild from the name indexes gives the same answers
    s.rebuild("acme").unwrap();
    assert_eq!(find(&s, "cv.pdf").len(), 1);
    assert!(find(&s, "report").is_empty());
}

#[test]
fn paging_has_no_gaps_or_duplicates() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path().join("store/acme"), keys(), Options::default()).unwrap();
    let files = |n: u64| {
        (0..n)
            .map(|i| e(&format!("data/file-{i:03}.txt"), i, 1))
            .collect::<Vec<_>>()
    };
    commit(&store, "share-1", 1, files(130));
    // a second version of every tenth file
    let mut v2 = files(130);
    for (i, x) in v2.iter_mut().enumerate() {
        if i % 10 == 0 {
            x.size += 1000;
        }
    }
    commit(&store, "share-1", 2, v2);
    let s = svc(d.path());
    s.sync("acme").unwrap();
    let mut all = Vec::new();
    let mut cursor = None;
    for _ in 0..10 {
        let r = s
            .search(&SearchReq {
                tenant: "acme".into(),
                q: "file-*".into(),
                limit: 50,
                cursor: cursor.clone(),
                ..Default::default()
            })
            .unwrap();
        all.extend(r.hits.into_iter().map(|h| (h.path, h.versions.len())));
        cursor = r.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(all.len(), 130);
    let mut paths: Vec<_> = all.iter().map(|x| x.0.clone()).collect();
    paths.dedup();
    assert_eq!(paths.len(), 130, "no duplicates");
    assert!(paths.windows(2).all(|w| w[0] < w[1]), "ordered by path");
    assert_eq!(all.iter().filter(|x| x.1 == 2).count(), 13);
}
