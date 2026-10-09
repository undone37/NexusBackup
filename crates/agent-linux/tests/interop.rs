//! Interop: the real agent (in-process `server::Agent`) driven by the real appliance
//! library `agent-conn` (enroll, backup into a chunk store, incremental backup without
//! transfer, restore), before the VM lab. No root needed (fallback mode).

use agent_conn::backup::{self, Spec};
use agent_conn::ca::Ca;
use agent_conn::map::MapDb;
use agent_conn::restore::{self, Spec as RestoreSpec};
use agent_conn::tls::{session_config, Session};
use agent_conn::{enroll, source_name, TREE_INDEX};
use agent_proto::Overwrite;
use chunkstore::{Index, Keyring, Options, Store, TreeKind};
use nexus_agent::config::{Paths, Settings};
use nexus_agent::server::Agent;
use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const ID: &str = "0123456789abcdef";
const TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const T: Duration = Duration::from_secs(30);

fn rnd(n: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn session(ca: &Ca, port: u16, pin: &str) -> Session {
    let mut s = Session::connect("127.0.0.1", port, session_config(ca, ID, Some(pin)).unwrap(), T).unwrap();
    let info = s.hello(ID).unwrap();
    assert_eq!(info.agent_id, ID);
    s
}

#[test]
fn real_agent_with_agent_conn() {
    // data on a real file system (tmpfs volumes are refused like /proc)
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let data = d.path().join("host/srv");
    fs::create_dir_all(data.join("etc/ssh")).unwrap();
    fs::create_dir_all(data.join("db")).unwrap();
    fs::write(data.join("etc/hostname"), b"web01\n").unwrap();
    fs::write(data.join("etc/ssh/sshd_config"), b"PermitRootLogin no\n").unwrap();
    fs::set_permissions(data.join("etc/ssh/sshd_config"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(data.join("db/data.bin"), rnd(5_000_000, 1)).unwrap();
    fs::write(data.join("db/copy.bin"), rnd(5_000_000, 1)).unwrap(); // dedup
    fs::write(data.join("empty"), b"").unwrap();
    fs::hard_link(data.join("etc/hostname"), data.join("hostname.link")).unwrap();
    std::os::unix::fs::symlink("etc/hostname", data.join("host")).unwrap();

    // the agent: init + serve
    let paths = Paths {
        config: d.path().join("agent/etc"),
        state: d.path().join("agent/state"),
        run: d.path().join("agent/run"),
    };
    nexus_agent::init(&paths, TOKEN, None).unwrap();
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    let mut agent = Agent::new(paths.clone(), settings).unwrap();
    agent.exit_on_update = false;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || Arc::new(agent).serve(l));

    // the appliance: CA, enrollment
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let bad = enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest("WRONG"), ID, T);
    assert!(bad.is_err());
    let e = enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T).unwrap();
    // EnrollDone has no answer; the appliance confirms with an mTLS Hello (retries)
    let mut s = None;
    for _ in 0..100 {
        if let Ok(mut c) = Session::connect(
            "127.0.0.1",
            port,
            session_config(&ca, ID, Some(&e.cert_sha256)).unwrap(),
            T,
        ) {
            if c.hello(ID).is_ok() {
                s = Some(c);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    s.expect("mTLS Hello after enrollment").close();
    assert!(!paths.token().exists());

    let opts = Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    };
    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("acme", &[(1, [9; 32])]), opts).unwrap();
    let spec = |job| Spec {
        job,
        paths: vec![data.to_string_lossy().into_owned()],
        excludes: vec![],
        hooks: false,
    };
    let run = |job: u64| {
        let mut map = MapDb::open(&store_dir).unwrap();
        let mut s = session(&ca, port, &e.cert_sha256);
        let r = backup::backup(&store, &mut map, &mut s, ID, &spec(job), &mut |l| eprintln!("{l}")).unwrap();
        s.close();
        r
    };

    // full backup
    let r1 = run(1);
    assert!(!r1.consistent, "fallback mode without root");
    assert!(r1.wanted_chunks > 0);
    assert!(r1.scan.errors.is_empty(), "{:?}", r1.scan.errors);
    // second backup: everything unchanged, nothing transferred
    std::thread::sleep(Duration::from_millis(1100)); // distinct snapshot time
    let r2 = run(2);
    assert_eq!(r2.base, Some(r1.time));
    assert_eq!(r2.wanted_chunks, 0, "no transfer when nothing changed");
    assert_eq!(r2.scan.read_bytes, 0, "unchanged files are not re-read");
    assert!(r2.unchanged >= 5);
    // mapping index lost: the appliance Wants chunks of `unchanged` files, the agent
    // re-reads them from the files
    fs::remove_file(store_dir.join("agent-map.db")).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let r3 = run(3);
    assert_eq!(r3.scan.read_bytes, 0);
    assert!(
        r3.wanted_chunks > 0 && r3.wanted_chunks == r1.wanted_chunks,
        "{} vs {}",
        r3.wanted_chunks,
        r1.wanted_chunks
    );
    let r2 = r3;

    // the tree snapshot has host-relative paths including the mountpoint prefix
    let m = store.load_manifest(&source_name(ID), r2.time).unwrap();
    let Index::Tree { entries } = store.load_index(&m, TREE_INDEX).unwrap() else {
        panic!("not a tree")
    };
    let rel = data.strip_prefix("/").unwrap().to_string_lossy().into_owned();
    assert!(entries
        .iter()
        .any(|e| e.path == format!("{rel}/db/data.bin").as_bytes() && e.kind == TreeKind::File));

    // restore into a fresh directory
    let target = d.path().join("restored");
    let map = MapDb::open(&store_dir).unwrap();
    let mut s = session(&ca, port, &e.cert_sha256);
    let stats = restore::restore(
        &store,
        &map,
        &mut s,
        &RestoreSpec {
            job: 3,
            source_agent: ID.into(),
            time: r2.time,
            paths: vec![data.to_string_lossy().into_owned()],
            target: target.to_string_lossy().into_owned(),
            overwrite: Overwrite::Never,
            confirm: "web01".into(),
        },
        &mut |l| eprintln!("{l}"),
    )
    .unwrap();
    s.close();
    assert!(stats.errors.is_empty(), "{:?}", stats.errors);
    let out = target.join(&rel);
    for f in [
        "etc/hostname",
        "etc/ssh/sshd_config",
        "db/data.bin",
        "db/copy.bin",
        "empty",
        "hostname.link",
    ] {
        assert_eq!(fs::read(out.join(f)).unwrap(), fs::read(data.join(f)).unwrap(), "{f}");
        let (a, b) = (fs::metadata(data.join(f)).unwrap(), fs::metadata(out.join(f)).unwrap());
        assert_eq!(a.mode(), b.mode(), "{f}");
        assert_eq!((a.mtime(), a.mtime_nsec()), (b.mtime(), b.mtime_nsec()), "{f}");
    }
    assert_eq!(fs::read_link(out.join("host")).unwrap(), Path::new("etc/hostname"));
    assert_eq!(
        fs::metadata(out.join("hostname.link")).unwrap().ino(),
        fs::metadata(out.join("etc/hostname")).unwrap().ino()
    );
}
