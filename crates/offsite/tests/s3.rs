//! S3 backend against MinIO with Object Lock (crates/offsite/testbox-s3/run.sh).
//! Without `NEXUS_S3_ENDPOINT` every test prints SKIP and passes.
//! Each test works under its own random prefix; locked objects stay until the
//! test container is removed (`run.sh stop`).

mod common;

use chunkstore::retention::Gfs;
use common::{backup, image, restored, store, DAY};
use offsite::pack;
use offsite::remote::{conformance, Remote};
use offsite::s3::{S3Config, S3Remote};
use offsite::target::{Options, Target};
use std::io::ErrorKind;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn prefix(name: &str) -> String {
    format!("test-{name}-{:016x}", rand::random::<u64>())
}

/// Config for the restricted appliance user (`admin = true`: MinIO root).
pub fn cfg(name: &str, admin: bool) -> Option<S3Config> {
    let Some(endpoint) = env("NEXUS_S3_ENDPOINT") else {
        eprintln!("SKIP: NEXUS_S3_ENDPOINT not set (crates/offsite/testbox-s3/run.sh start)");
        return None;
    };
    let (ak, sk) = if admin {
        ("NEXUS_S3_ADMIN_ACCESS_KEY", "NEXUS_S3_ADMIN_SECRET_KEY")
    } else {
        ("NEXUS_S3_ACCESS_KEY", "NEXUS_S3_SECRET_KEY")
    };
    let mut c = S3Config::new(
        &endpoint,
        &env("NEXUS_S3_REGION").unwrap_or("us-east-1".into()),
        &env("NEXUS_S3_BUCKET").unwrap(),
        &env(ak).unwrap(),
        &env(sk).unwrap(),
    );
    c.path_style = true;
    c.prefix = prefix(name);
    c.ca_pem = env("NEXUS_S3_CA").map(|p| std::fs::read(p).unwrap());
    c.lock = true;
    c.retries = 1;
    Some(c)
}

#[test]
fn s3_conformance() {
    let Some(c) = cfg("conf", false) else { return };
    let r = S3Remote::new(c).unwrap();
    conformance(&r);
    assert!(r.list("").unwrap().iter().any(|(n, _, d)| n == "a" && *d));
    // past the end of an object
    r.put("x", b"abc").unwrap();
    assert_eq!(r.get("x", 3, None).unwrap(), b"");
    assert_eq!(r.get("x", 1, Some(5)).unwrap_err().kind(), ErrorKind::UnexpectedEof);
    assert_eq!(r.get("missing", 0, None).unwrap_err().kind(), ErrorKind::NotFound);
    r.put("empty", b"").unwrap();
    assert_eq!(r.get("empty", 0, None).unwrap(), b"");
    assert_eq!(r.list("").unwrap().iter().filter(|e| !e.2).count(), 2);
}

/// Two writers racing for the same new key: HEAD passes for both, then
/// `If-None-Match: *` lets exactly one win.
#[test]
fn s3_conditional_put_race() {
    let Some(c) = cfg("race", false) else { return };
    let r = S3Remote::new(c).unwrap();
    for i in 0..20 {
        let key = format!("k{i}");
        let wins: usize = std::thread::scope(|s| {
            let hs: Vec<_> = (0..4u8)
                .map(|t| {
                    let (r, key) = (&r, &key);
                    s.spawn(move || match r.put(key, &[t; 1000]) {
                        Ok(()) => 1,
                        Err(e) if e.kind() == ErrorKind::AlreadyExists => 0,
                        Err(e) => panic!("{e}"),
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        assert_eq!(wins, 1, "{key}");
    }
}

#[test]
fn s3_pagination() {
    let Some(c) = cfg("page", false) else { return };
    let r = S3Remote::new(c).unwrap();
    // more than one page of 1000 keys
    std::thread::scope(|s| {
        for t in 0..8 {
            let r = &r;
            s.spawn(move || {
                for i in (t..1100).step_by(8) {
                    r.put(&format!("d/f{i:05}"), b"x").unwrap();
                }
            });
        }
    });
    r.put("d/sub/x", b"y").unwrap();
    let l = r.list("d").unwrap();
    assert_eq!(l.len(), 1101);
    assert_eq!(l.last().unwrap(), &("sub".to_string(), 0, true));
    assert_eq!(l[0], ("f00000".to_string(), 1, false));
}

#[test]
fn s3_object_lock() {
    let Some(c) = cfg("lock", false) else { return };
    let mut admin_cfg = cfg("x", true).unwrap();
    admin_cfg.prefix = c.prefix.clone();
    let r = S3Remote::new(c.clone()).unwrap();
    let admin = S3Remote::new(admin_cfg).unwrap();
    assert!(r.supports_locks());

    let until = now() + 300;
    r.put_locked("snap/manifest", b"locked data", until).unwrap();
    let info = r.head("snap/manifest").unwrap().unwrap();
    assert_eq!(info.retain_until, Some(until));
    assert_eq!(info.lock_mode.as_deref(), Some("COMPLIANCE"));
    let v = info.version_id.clone().unwrap();

    // overwrite: refused (HEAD and If-None-Match)
    assert_eq!(
        r.put("snap/manifest", b"x").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    // deleting the version: the appliance user may not (policy), root may not (lock)
    let e = r.delete_version("snap/manifest", &v).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    let e = admin.delete_version("snap/manifest", &v).unwrap_err();
    eprintln!("root deleting a locked version: {e}");
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    // shortening the lock is refused by S3; extend_lock keeps the longer date
    r.extend_lock("snap/manifest", until - 100).unwrap();
    assert_eq!(r.lock_of("snap/manifest").unwrap(), Some(until));
    r.extend_lock("snap/manifest", until + 600).unwrap();
    assert_eq!(r.lock_of("snap/manifest").unwrap(), Some(until + 600));

    // a plain delete only adds a delete marker: hidden, but the version survives
    r.delete("snap/manifest").unwrap();
    assert_eq!(r.get("snap/manifest", 0, None).unwrap_err().kind(), ErrorKind::NotFound);
    assert!(r.list("snap").unwrap().is_empty());
    assert!(admin.delete_version("snap/manifest", &v).is_err(), "still locked");

    // unlocked objects (lock date in the past) are fine to put
    r.put_locked("plain", b"x", now() - 10).unwrap();
    assert_eq!(r.lock_of("plain").unwrap(), None);
    assert_eq!(r.lock_of("nope").unwrap_err().kind(), ErrorKind::NotFound);
    // without lock support configured, put_locked does not lock
    let mut nl = c;
    nl.lock = false;
    let nl = S3Remote::new(nl).unwrap();
    nl.put_locked("nl", b"x", now() + 300).unwrap();
    assert_eq!(r.lock_of("nl").unwrap(), None);
}

#[test]
fn s3_auth_and_tls_errors() {
    let Some(c) = cfg("auth", false) else { return };
    let mut bad = c.clone();
    bad.secret_key = "wrong".into();
    let e = S3Remote::new(bad).unwrap().list("").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
    assert!(e.to_string().contains("SignatureDoesNotMatch"), "{e}");
    // the public web PKI does not know the testbox certificate
    let mut pki = c.clone();
    pki.ca_pem = None;
    assert!(S3Remote::new(pki).unwrap().list("").is_err());
    // the appliance user cannot touch other buckets
    let mut other = c;
    other.bucket = "other-bucket".into();
    let e = S3Remote::new(other).unwrap().put("x", b"x").unwrap_err();
    assert!(
        matches!(e.kind(), ErrorKind::PermissionDenied | ErrorKind::Other),
        "{e}"
    );
}

#[test]
fn s3_multipart_100mib() {
    let Some(mut c) = cfg("mp", false) else { return };
    c.retries = 3;
    let r = S3Remote::new(c).unwrap();
    let mut x = 0x9E3779B97F4A7C15u64;
    let data: Vec<u8> = (0..100usize << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    let t = Instant::now();
    r.put_locked("packs/ab/big.pack", &data, now() + 300).unwrap();
    let up = t.elapsed();
    let info = r.head("packs/ab/big.pack").unwrap().unwrap();
    assert_eq!(info.size, data.len() as u64);
    assert!(info.etag.ends_with("-7"), "16 MiB parts: {}", info.etag);
    assert!(info.retain_until.is_some(), "lock set on CreateMultipartUpload");
    let t = Instant::now();
    let back = r.get("packs/ab/big.pack", 0, None).unwrap();
    let down = t.elapsed();
    assert!(back == data);
    let off = (16 << 20) - 5;
    assert_eq!(
        r.get("packs/ab/big.pack", off, Some(10)).unwrap(),
        &data[off as usize..off as usize + 10]
    );
    assert_eq!(
        r.put("packs/ab/big.pack", &data).unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    let mib = data.len() as f64 / (1 << 20) as f64;
    eprintln!(
        "multipart 100 MiB: put {:.0} MiB/s, get {:.0} MiB/s",
        mib / up.as_secs_f64(),
        mib / down.as_secs_f64()
    );
}

fn gfs(daily: u32) -> Gfs {
    Gfs {
        recent: 0,
        daily,
        weekly: 0,
        monthly: 0,
        yearly: 0,
    }
}

/// The tests/target.rs flow against MinIO with Object Lock: upload, lock
/// extension by retention, GC skipping locked packs, inventory, verify, DR.
#[test]
fn s3_target_engine() {
    let Some(c) = cfg("target", false) else { return };
    let mut admin_cfg = cfg("x", true).unwrap();
    admin_cfg.prefix = c.prefix.clone();
    let rem = S3Remote::new(c.clone()).unwrap();
    let admin = S3Remote::new(admin_cfg).unwrap();
    let d = tempfile::tempdir().unwrap();
    let a = store(&d.path().join("a"));
    let now = a.compliance_now().unwrap();
    let opts = || Options {
        uploaders: 4,
        repack_threshold: 0.0,
        ..Default::default()
    };
    let mut t = Target::open(&a, &rem, d.path().join("state-a"), opts()).unwrap();
    let t0 = Instant::now();
    let times: Vec<u64> = (0..4).map(|v| now - (5 - v) * DAY).collect();
    for (v, &time) in times.iter().enumerate() {
        backup(&a, time, v as u64);
        t.upload().unwrap();
    }
    eprintln!("upload of 4 snapshots (52 chunks, 4 packs): {:?}", t0.elapsed());
    assert_eq!(t.pack_count(), 4);
    assert!(t.check_inventory().unwrap().ok());
    t.put_if_missing("keys/kek.recovery", b"wrapped").unwrap();

    // keep the newest: retention locks its packs and files on S3 (14 days)
    let (kept, deleted, _) = t.apply_retention(&gfs(1), &Default::default()).unwrap();
    assert_eq!((kept, deleted), (1, 3));
    let w = times[3] + 14 * DAY;
    let key = format!("snapshots/vm-1/{}", times[3]);
    assert_eq!(rem.lock_of(&format!("{key}/manifest")).unwrap(), Some(w));
    assert_eq!(rem.lock_of(&format!("{key}/disk.idx")).unwrap(), Some(w));
    let locked: Vec<String> = t.pack_ids().into_iter().filter(|p| t.pack_lock(p) == w).collect();
    assert_eq!(locked.len(), 3);
    for p in &locked {
        assert_eq!(rem.lock_of(&pack::remote_path(p)).unwrap(), Some(w));
    }
    t.protect("keys/kek.recovery").unwrap();
    assert_eq!(rem.lock_of("keys/kek.recovery").unwrap(), Some(w));
    // deleted snapshots are gone (delete markers); MinIO may still list their
    // "directories" as common prefixes until the markers expire, empty ones
    let with_manifest = rem
        .list("snapshots/vm-1")
        .unwrap()
        .into_iter()
        .filter(|(n, _, _)| {
            rem.list(&format!("snapshots/vm-1/{n}"))
                .unwrap()
                .iter()
                .any(|f| f.0 == "manifest")
        })
        .count();
    assert_eq!(with_manifest, 1);

    // GC: the unlocked dead pack goes, the locked ones stay
    let g = t.gc().unwrap();
    assert_eq!((g.packs_deleted, g.packs_locked, g.packs_repacked), (1, 3, 0), "{g:?}");
    assert!(t.check_inventory().unwrap().ok());
    assert_eq!(t.verify_sample(10).unwrap(), (3, 0));

    // even the bucket owner cannot destroy a locked pack version
    let p = pack::remote_path(&locked[0]);
    let v = rem.head(&p).unwrap().unwrap().version_id.unwrap();
    assert_eq!(
        admin.delete_version(&p, &v).unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );

    // DR from S3 alone: packs, snapshot, and the extended lock come back
    let t1 = Instant::now();
    let rem_b = S3Remote::new(c.clone()).unwrap();
    let b = store(&d.path().join("b"));
    let mut tb = Target::open(&b, &rem_b, d.path().join("state-b"), opts()).unwrap();
    assert_eq!(tb.rebuild_from_remote().unwrap(), 3);
    assert_eq!(tb.snapshots().unwrap(), vec![("vm-1".to_string(), times[3])]);
    assert_eq!(tb.max_lock().unwrap(), w);
    assert_eq!(tb.pack_lock(&locked[0]), w);
    tb.restore("vm-1", times[3]).unwrap();
    assert_eq!(restored(&b, times[3]), image(3));
    eprintln!("DR rebuild + restore: {:?}", t1.elapsed());
    let (_, deleted, still) = tb.apply_retention(&gfs(0), &Default::default()).unwrap();
    assert_eq!((deleted, still), (0, 1), "DR copy knows the extended lock");

    // monitoring: a pack deleted behind our back (delete marker) is reported,
    // while its locked version is still there for recovery
    rem.delete(&p).unwrap();
    let inv = t.check_inventory().unwrap();
    assert_eq!(inv.missing, vec![p.clone()]);
    assert!(
        admin.delete_version(&p, &v).is_err(),
        "version survives the delete marker"
    );
}
