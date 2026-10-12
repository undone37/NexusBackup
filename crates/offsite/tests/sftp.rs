//! SftpRemote against the Storage-Box-like testbox (crates/offsite/testbox).
//! Run:  crates/offsite/testbox/run.sh start && eval "$(crates/offsite/testbox/run.sh env)"
//!       cargo test -p offsite --test sftp -- --nocapture
//! Without the NEXUS_TESTBOX_* environment every test prints why and passes.

use chunkstore::retention::Gfs;
use chunkstore::{Keyring, Options as StoreOptions, Store};
use offsite::remote::{conformance, Remote};
use offsite::sftp::{SftpConfig, SftpRemote};
use offsite::target::{Options, Target};
use rand::RngCore;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Tests share one server (and drop/restart it): run them one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

struct Box {
    cfg: SftpConfig,
    ctl: String,
    max_conn: usize,
    _serial: MutexGuard<'static, ()>,
}

fn testbox(test: &str) -> Option<Box> {
    let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let var = |k: &str| std::env::var(format!("NEXUS_TESTBOX_{k}")).ok();
    let (Some(host), Some(port), Some(user), Some(key), Some(kh), Some(ctl)) = (
        var("HOST"),
        var("PORT"),
        var("USER"),
        var("KEY"),
        var("KNOWN_HOSTS"),
        var("CTL"),
    ) else {
        eprintln!(
            "SKIP {test}: NEXUS_TESTBOX_* not set (crates/offsite/testbox/run.sh start; eval \"$(… run.sh env)\")"
        );
        return None;
    };
    let mut cfg = SftpConfig::new(&host, &user, key, &kh);
    cfg.port = port.parse().unwrap();
    cfg.base_dir = format!("t-{}-{test}", std::process::id());
    cfg.backoff = Duration::from_millis(200);
    cfg.request_timeout = Duration::from_secs(20);
    let max_conn = var("MAX_CONN").and_then(|v| v.parse().ok()).unwrap_or(10);
    Some(Box {
        cfg,
        ctl,
        max_conn,
        _serial: serial,
    })
}

impl Box {
    fn remote(&self) -> SftpRemote {
        SftpRemote::new(self.cfg.clone()).unwrap()
    }

    fn ctl(&self, cmd: &str) {
        let st = Command::new(&self.ctl).arg(cmd).status().unwrap();
        assert!(st.success(), "run.sh {cmd}");
    }
}

fn random(n: usize) -> Vec<u8> {
    let mut v = vec![0; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

fn mib_s(bytes: usize, d: Duration) -> String {
    format!("{:.0} MiB/s", bytes as f64 / (1 << 20) as f64 / d.as_secs_f64())
}

#[test]
fn sftp_conformance_and_remove_dir() {
    let Some(b) = testbox("conf") else { return };
    let r = b.remote();
    conformance(&r);
    r.put("d/e/f", b"x").unwrap();
    assert!(r.remove_dir("d/e").is_err(), "rmdir must not remove a non-empty dir");
    assert_eq!(r.get("d/e/f", 0, None).unwrap(), b"x");
    r.delete("d/e/f").unwrap();
    r.remove_dir("d/e").unwrap();
    r.remove_dir("d").unwrap();
    assert!(r.list("d").unwrap().is_empty());
    assert_eq!(r.delete("nope").unwrap_err().kind(), ErrorKind::NotFound);
    assert_eq!(r.get("nope", 0, None).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(r.get("a/b", 0, None).is_err(), "a directory is not a file");
    r.put("empty", b"").unwrap();
    assert_eq!(r.get("empty", 0, None).unwrap(), b"");
    assert!(r.get("empty", 0, Some(1)).is_err(), "short read is an error");
    let (total, avail) = r.usage().unwrap();
    assert!(total > 0 && avail <= total);
    let top: Vec<_> = r.list("").unwrap().into_iter().map(|e| e.0).collect();
    assert!(top.contains(&"empty".to_string()) && !top.iter().any(|n| n.contains(".tmp-")));
}

#[test]
fn sftp_wrong_host_key_fails() {
    let Some(b) = testbox("hostkey") else { return };
    // any other valid key: the client's own public key
    let other = std::fs::read_to_string(format!("{}.pub", b.cfg.key_file.display())).unwrap();
    let mut cfg = b.cfg.clone();
    cfg.host_key = other;
    let t = Instant::now();
    let e = SftpRemote::new(cfg).unwrap().connect().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::InvalidData, "{e}");
    assert!(t.elapsed() < Duration::from_secs(5), "no retries on host key mismatch");
    let mut cfg = b.cfg.clone();
    cfg.host_key = "[127.0.0.1]:23 ssh-ed25519 notbase64".into();
    assert!(SftpRemote::new(cfg).is_err());
    b.remote().connect().unwrap();
}

#[test]
fn sftp_parallel_puts_and_gets() {
    let Some(b) = testbox("par") else { return };
    let r = b.remote();
    const THREADS: usize = 4;
    const N: usize = 20;
    const SIZE: usize = 8 << 20;
    let blobs: Vec<Vec<Vec<u8>>> = (0..THREADS).map(|_| (0..N).map(|_| random(SIZE)).collect()).collect();
    let t = Instant::now();
    std::thread::scope(|s| {
        for (i, blobs) in blobs.iter().enumerate() {
            let r = &r;
            s.spawn(move || {
                for (j, blob) in blobs.iter().enumerate() {
                    r.put(&format!("p/{i}/{j}.pack"), blob).unwrap();
                }
            });
        }
    });
    let up = t.elapsed();
    let t = Instant::now();
    std::thread::scope(|s| {
        for (i, blobs) in blobs.iter().enumerate() {
            let r = &r;
            s.spawn(move || {
                for (j, blob) in blobs.iter().enumerate() {
                    assert!(r.get(&format!("p/{i}/{j}.pack"), 0, None).unwrap() == *blob);
                }
            });
        }
    });
    let down = t.elapsed();
    let total = THREADS * N * SIZE;
    println!(
        "parallel {THREADS}x{N}x8MiB: put {:?} ({}), get {:?} ({})",
        up,
        mib_s(total, up),
        down,
        mib_s(total, down)
    );
    for i in 0..THREADS {
        assert_eq!(r.list(&format!("p/{i}")).unwrap().len(), N);
        for j in 0..N {
            r.delete(&format!("p/{i}/{j}.pack")).unwrap();
        }
    }
}

#[test]
fn sftp_big_put_range_gets() {
    let Some(b) = testbox("big") else { return };
    let mut cfg = b.cfg.clone();
    cfg.max_connections = 1;
    let r = SftpRemote::new(cfg).unwrap();
    let data = random(64 << 20);
    let t = Instant::now();
    r.put("packs/aa/big.pack", &data).unwrap();
    let up = t.elapsed();
    let t = Instant::now();
    assert!(r.get("packs/aa/big.pack", 0, None).unwrap() == data);
    let down = t.elapsed();
    println!(
        "single connection 64 MiB: put {up:?} ({}), get {down:?} ({})",
        mib_s(data.len(), up),
        mib_s(data.len(), down)
    );
    assert_eq!(r.list("packs/aa").unwrap(), vec![("big.pack".into(), 64 << 20, false)]);
    for (off, len) in [
        (0u64, 1u64),
        (12345, 4 << 20),
        ((64 << 20) - 12, 12),
        (33 << 20, 1 << 20),
        (7, 261121),
    ] {
        let got = r.get("packs/aa/big.pack", off, Some(len)).unwrap();
        assert!(got == data[off as usize..(off + len) as usize], "range {off}+{len}");
    }
    assert_eq!(
        r.get("packs/aa/big.pack", (64 << 20) - 12, None).unwrap(),
        data[(64 << 20) - 12..]
    );
    assert!(
        r.get("packs/aa/big.pack", (64 << 20) - 4, Some(8)).is_err(),
        "range past EOF"
    );
    assert_eq!(
        r.put("packs/aa/big.pack", b"x").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    r.delete("packs/aa/big.pack").unwrap();
}

#[test]
fn sftp_reconnects_after_drop_and_restart() {
    let Some(b) = testbox("reconn") else { return };
    let r = b.remote();
    r.put("x", b"before").unwrap();
    b.ctl("drop"); // kills the pooled connection server-side
    assert_eq!(r.get("x", 0, None).unwrap(), b"before");
    b.ctl("restart");
    let t = Instant::now();
    r.put("y", b"after").unwrap();
    println!("first op after container restart: {:?}", t.elapsed());
    assert_eq!(r.list("").unwrap().len(), 2);
    r.delete("x").unwrap();
    r.delete("y").unwrap();
}

#[test]
fn sftp_connection_limit() {
    let Some(b) = testbox("limit") else { return };
    let mut cfg = b.cfg.clone();
    cfg.max_connections = 11;
    assert_eq!(SftpRemote::new(cfg).err().unwrap().kind(), ErrorKind::InvalidInput);
    // the box itself refuses connection max+1 at auth (and our client gives up
    // after its retries); wait for connections of earlier tests to go away
    std::thread::sleep(Duration::from_secs(1));
    let mut cfg = b.cfg.clone();
    cfg.max_connections = 1;
    cfg.retries = 0;
    let held: Vec<_> = (0..b.max_conn)
        .map(|_| {
            let r = SftpRemote::new(cfg.clone()).unwrap();
            r.connect().unwrap();
            r
        })
        .collect();
    let e = SftpRemote::new(cfg.clone()).unwrap().connect().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    drop(held);
    // connections are closed asynchronously; with retries the next one gets in
    cfg.retries = 4;
    SftpRemote::new(cfg).unwrap().connect().unwrap();
}

// ---- the offsite engine (copy of tests/target.rs) over SFTP ----

fn keys() -> Keyring {
    Keyring::new("tenant1", &[(1, [5; 32])])
}

fn store(dir: &Path) -> Store {
    Store::open(
        dir,
        keys(),
        StoreOptions {
            min_lock_secs: 0,
            gc_grace_secs: 0,
            ..Default::default()
        },
    )
    .unwrap()
}

/// 48 pseudo-random 64 KiB chunks; snapshot `v` changes chunk `v % 48`.
fn image(v: u64) -> Vec<u8> {
    let mut x = 0x2545F4914F6CDD1Du64;
    (0..48 * 65536usize)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i / 65536 == (v % 48) as usize {
                (x as u8) ^ (v as u8 | 1)
            } else {
                x as u8
            }
        })
        .collect()
}

fn backup(s: &Store, t: u64, v: u64) {
    let idx = s.store_image(&image(v)[..], 65536).unwrap();
    s.commit_snapshot("vm-1", t, &[("disk", idx)]).unwrap();
}

fn restored(s: &Store, t: u64) -> Vec<u8> {
    let m = s.load_manifest("vm-1", t).unwrap();
    let mut out = Vec::new();
    s.write_chunks(s.load_index(&m, "disk").unwrap().chunk_ids(), &mut out)
        .unwrap();
    out
}

#[test]
fn sftp_target_upload_dr_retention_gc_verify() {
    let Some(b) = testbox("target") else { return };
    let box_ = b.remote();
    let d = tempfile::tempdir().unwrap();
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    let day = 86400;
    let opts = || Options {
        uploaders: 3,
        ..Default::default()
    };
    let timer = Instant::now();

    for v in 0..3 {
        backup(&a, now - (5 - v) * day, v);
    }
    let mut t = Target::open(&a, &box_, d.path().join("state-a"), opts()).unwrap();
    let st = t.upload().unwrap();
    assert_eq!(
        (st.snapshots, st.chunks),
        (3, 48 + 3),
        "48 base chunks + one changed chunk per snapshot"
    );
    assert_eq!(t.upload().unwrap().snapshots, 0, "idempotent");
    backup(&a, now - 2 * day, 3);
    let st = t.upload().unwrap();
    assert_eq!((st.snapshots, st.chunks), (1, 1), "dedup against offsite inventory");
    assert!(t.check_inventory().unwrap().ok());
    println!("target over sftp: upload {:?}", timer.elapsed());

    // DR: fresh appliance, same tenant keys, only the box
    let timer = Instant::now();
    let b2 = store(&d.path().join("b"));
    let mut tb = Target::open(&b2, &box_, d.path().join("state-b"), opts()).unwrap();
    assert_eq!(tb.rebuild_from_remote().unwrap(), t.pack_count());
    assert_eq!(tb.snapshots().unwrap().len(), 4);
    tb.restore("vm-1", now - 2 * day).unwrap();
    assert_eq!(restored(&b2, now - 2 * day), image(3));
    b2.verify(|_| true)
        .map(|r| assert!(r.missing.is_empty() && r.corrupt.is_empty()))
        .unwrap();
    println!(
        "target over sftp: DR (rebuild + restore + verify) {:?}",
        timer.elapsed()
    );

    // independent offsite retention: keep 1 daily -> 3 snapshots go (their locks were "now")
    let timer = Instant::now();
    let (kept, deleted, locked) = t
        .apply_retention(
            &Gfs {
                recent: 0,
                daily: 1,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
            &Default::default(),
        )
        .unwrap();
    assert_eq!((kept, deleted, locked), (1, 3, 0));
    assert!(box_.list("snapshots/vm-1").unwrap().len() == 1);
    let (_, _, locked) = t
        .apply_retention(
            &Gfs {
                recent: 0,
                daily: 0,
                weekly: 0,
                monthly: 0,
                yearly: 0,
            },
            &Default::default(),
        )
        .unwrap();
    assert_eq!(locked, 1, "offsite lock holds");
    println!("target over sftp: retention {:?}", timer.elapsed());

    // GC: packs are mostly live -> force a repack with threshold 0
    let timer = Instant::now();
    let mut t = Target::open(
        &a,
        &box_,
        d.path().join("state-a"),
        Options {
            repack_threshold: 0.0,
            ..opts()
        },
    )
    .unwrap();
    let g = t.gc().unwrap();
    assert!(g.packs_repacked >= 1 && g.packs_deleted >= 1, "{g:?}");
    assert!(t.check_inventory().unwrap().ok());
    assert_eq!(t.verify_sample(10).unwrap().1, 0);
    println!("target over sftp: GC + inventory + verify_sample {:?}", timer.elapsed());

    // after GC, a second DR still restores the kept snapshot bit-exactly
    let timer = Instant::now();
    let c = store(&d.path().join("c"));
    let mut tc = Target::open(&c, &box_, d.path().join("state-c"), opts()).unwrap();
    tc.rebuild_from_remote().unwrap();
    tc.restore("vm-1", now - 2 * day).unwrap();
    assert_eq!(restored(&c, now - 2 * day), image(3));
    println!("target over sftp: second DR {:?}", timer.elapsed());

    // monitoring: a pack deleted behind our back is reported
    let (id, pack) = box_
        .list("packs")
        .unwrap()
        .into_iter()
        .find_map(|(pp, _, _)| {
            box_.list(&format!("packs/{pp}"))
                .unwrap()
                .first()
                .map(|f| (pp, f.0.clone()))
        })
        .unwrap();
    box_.delete(&format!("packs/{id}/{pack}")).unwrap();
    assert!(!t.check_inventory().unwrap().ok());
}
