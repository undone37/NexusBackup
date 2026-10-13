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
    // compressible text: travels as ChunkLz4 (random .bin data above travels raw)
    let log: Vec<u8> = (0..60_000)
        .flat_map(|i| format!("2026-10-10T12:00:{:02} web01 nginx: GET /index.html 200\n", i % 60).into_bytes())
        .collect();
    fs::write(data.join("etc/app.log"), &log).unwrap();
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
        filters: Default::default(),
        limits: Default::default(),
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
    // LZ4 on the wire: the ~3.2 MB log compresses to a fraction, random data goes raw
    assert!(
        r1.wire_bytes + 2_000_000 < r1.wanted_bytes,
        "wire {} vs raw {}",
        r1.wire_bytes,
        r1.wanted_bytes
    );
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
            source: source_name(ID),
            time: r2.time,
            paths: vec![data.to_string_lossy().into_owned()],
            target: target.to_string_lossy().into_owned(),
            overwrite: Overwrite::Never,
            confirm: "web01".into(),
            target_agent: ID.into(),
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

    // the same snapshot as if restored onto another host (Phase 15b): the real agent
    // takes uid/gid -1 (owner = the restoring user), content and modes arrive
    let other = d.path().join("other");
    let mut s = session(&ca, port, &e.cert_sha256);
    let stats = restore::restore(
        &store,
        &map,
        &mut s,
        &RestoreSpec {
            job: 4,
            source: source_name(ID),
            time: r2.time,
            paths: vec![data.to_string_lossy().into_owned()],
            target: other.to_string_lossy().into_owned(),
            overwrite: Overwrite::Never,
            confirm: "web01".into(),
            target_agent: "fedcba9876543210".into(),
        },
        &mut |l| eprintln!("{l}"),
    )
    .unwrap();
    s.close();
    assert!(stats.errors.is_empty(), "{:?}", stats.errors);
    let f = other.join(&rel).join("etc/ssh/sshd_config");
    assert_eq!(
        fs::read(&f).unwrap(),
        fs::read(data.join("etc/ssh/sshd_config")).unwrap()
    );
    let m = fs::metadata(&f).unwrap();
    assert_eq!(m.mode() & 0o7777, 0o600);
    // SAFETY: plain libc getters
    assert_eq!((m.uid(), m.gid()), unsafe { (libc::geteuid(), libc::getegid()) });
}

/// Starts an initialised + enrolled agent on `paths`; returns (port, pin).
fn enrolled_agent(paths: &Paths, ca: &Ca) -> (u16, String) {
    nexus_agent::init(paths, TOKEN, None).unwrap();
    let port = serve(paths);
    let e = enroll::enroll(ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T).unwrap();
    for _ in 0..100 {
        if let Ok(mut c) = Session::connect(
            "127.0.0.1",
            port,
            session_config(ca, ID, Some(&e.cert_sha256)).unwrap(),
            T,
        ) {
            if c.hello(ID).is_ok() {
                c.close();
                return (port, e.cert_sha256);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("no mTLS session after enrollment");
}

fn serve(paths: &Paths) -> u16 {
    let settings = Settings {
        hook_owner: nexus_agent::sys::geteuid(),
        ..Default::default()
    };
    let mut agent = Agent::new(paths.clone(), settings).unwrap();
    agent.exit_on_update = false;
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || Arc::new(agent).serve(l));
    port
}

/// Phase 15e/f: include roots + regex excludes and the bandwidth limit travel in
/// `PrepareEx`; the certificate is renewed over the session, the old pin stops
/// working for new connections, the new one survives an agent restart.
#[test]
fn filters_limits_and_certificate_renewal() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let data = d.path().join("host/srv");
    fs::create_dir_all(data.join("keep/sub")).unwrap();
    fs::create_dir_all(data.join("other")).unwrap();
    fs::write(data.join("keep/a.bin"), rnd(3_000_000, 2)).unwrap();
    fs::write(data.join("keep/sub/b.log"), b"log").unwrap();
    fs::write(data.join("keep/sub/c.txt"), b"c").unwrap();
    fs::write(data.join("other/x"), b"x").unwrap();
    let paths = Paths {
        config: d.path().join("agent/etc"),
        state: d.path().join("agent/state"),
        run: d.path().join("agent/run"),
    };
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let (port, pin) = enrolled_agent(&paths, &ca);

    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("acme", &[(1, [9; 32])]), Options::default()).unwrap();
    let mut map = MapDb::open(&store_dir).unwrap();
    let mut s = session(&ca, port, &pin);
    assert!(s.has_cap(agent_proto::CAP_PREPARE2) && s.has_cap(agent_proto::CAP_RENEW));
    let spec = Spec {
        job: 1,
        paths: vec![data.to_string_lossy().into_owned()],
        excludes: vec![],
        hooks: false,
        filters: agent_proto::Filters {
            include: vec![data.join("keep").to_string_lossy().into_owned()],
            exclude_regex: vec![r"\.log$".into()],
            ..Default::default()
        },
        limits: agent_proto::Limits {
            bwlimit: 1_000_000,
            nice: 5,
        },
    };
    let t = std::time::Instant::now();
    let r = backup::backup(&store, &mut map, &mut s, ID, &spec, &mut |l| eprintln!("{l}")).unwrap();
    s.close();
    // 3 MB of random data at 1 MB/s with one second of burst: about two seconds
    assert!(t.elapsed() >= Duration::from_millis(1800), "{:?}", t.elapsed());
    assert!(r.prepare_hook_log.contains("priority"), "{}", r.prepare_hook_log);
    let m = store.load_manifest(&source_name(ID), r.time).unwrap();
    let Index::Tree { entries } = store.load_index(&m, TREE_INDEX).unwrap() else {
        panic!("not a tree")
    };
    let rel = data.strip_prefix("/").unwrap().to_string_lossy().into_owned();
    let names: Vec<String> = entries
        .iter()
        .map(|e| String::from_utf8_lossy(&e.path).trim_start_matches(&rel).to_owned())
        .collect();
    // plus the machine layout the appliance adds (docs/bmr.md)
    assert_eq!(
        names,
        [
            "",
            "/keep",
            "/keep/a.bin",
            "/keep/sub",
            "/keep/sub/c.txt",
            ".nexus-system",
            ".nexus-system/layout.json"
        ]
    );

    // renewal over the session
    let mut s = session(&ca, port, &pin);
    let mut issued = None;
    let n = agent_conn::renew::renew(&ca, &mut s, ID, &mut |r| issued = Some(r.cert_sha256.clone())).unwrap();
    s.close();
    assert_eq!(issued.as_deref(), Some(n.cert_sha256.as_str()));
    assert_ne!(n.cert_sha256, pin);
    assert!(n.not_after - n.not_before > 9 * 365 * 86400);
    // new connections present the new certificate: the old pin fails, both pins pass
    assert!(
        Session::connect("127.0.0.1", port, session_config(&ca, ID, Some(&pin)).unwrap(), T)
            .and_then(|mut c| c.hello(ID))
            .is_err()
    );
    let mut c = Session::connect(
        "127.0.0.1",
        port,
        agent_conn::tls::session_config_pins(&ca, ID, &[&pin, &n.cert_sha256]).unwrap(),
        T,
    )
    .unwrap();
    c.hello(ID).unwrap();
    assert_eq!(c.peer_cert().unwrap().0, n.cert_sha256);
    c.close();
    // the swap is on disk: a restarted agent serves the new identity
    let port2 = serve(&paths);
    session(&ca, port2, &n.cert_sha256).close();
}

/// Phase 24: a local user requests a backup over the UI socket, the appliance's
/// poll delivers a session summary, picks the request up and acknowledges it.
#[test]
fn endpoint_status_poll_and_request() {
    use agent_proto::{ApplianceStatus, SessionKind, SessionResult, Summary, UiPolicy};
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let run = tempfile::tempdir().unwrap(); // socket paths are short (SUN_LEN)
    let paths = Paths {
        config: d.path().join("agent/etc"),
        state: d.path().join("agent/state"),
        run: run.path().to_path_buf(),
    };
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    nexus_agent::init(&paths, TOKEN, None).unwrap();
    let mut agent = Agent::new(paths.clone(), Settings::default()).unwrap();
    agent.exit_on_update = false;
    let agent = Arc::new(agent);
    fs::create_dir_all(&paths.run).unwrap();
    let ul = agent_core::ui::unix::bind(&paths.ui_socket(), None).unwrap();
    let a = agent.clone();
    std::thread::spawn(move || agent_core::ui::unix::serve(a, ul));
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let a = agent.clone();
    std::thread::spawn(move || a.serve(l));
    let mut ui = agent_ui_proto::Client::connect(paths.ui_socket()).unwrap();
    assert!(ui.request_backup().is_err(), "not enrolled yet");
    let e = enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T).unwrap();
    std::thread::sleep(Duration::from_millis(200));

    let req = ui.request_backup().unwrap();
    assert!(matches!(ui.request_backup(), Err(agent_ui_proto::Error::Refused(m)) if m.contains("try again")));
    assert_eq!(ui.status().unwrap().state, agent_ui_proto::AgentState::Requested);

    let status = ApplianceStatus {
        appliance: "nexus01".into(),
        now: 1,
        next_run: Some(4_000_000_000),
        ui_policy: UiPolicy {
            header: "ACME".into(),
            ..Default::default()
        },
        policy_version: 4,
    };
    let target = |ack: Vec<String>, summaries: Vec<Summary>| agent_conn::poll::Target {
        id: ID.into(),
        host: "127.0.0.1".into(),
        port,
        pins: vec![e.cert_sha256.clone()],
        status: status.clone(),
        ack,
        summaries,
    };
    let sum = Summary {
        job: 7,
        kind: SessionKind::Backup,
        started: 100,
        ended: 200,
        result: SessionResult::Success,
        read_bytes: 1000,
        transferred_bytes: 400,
        new_bytes: 300,
        warnings: 0,
        first_error: String::new(),
        snapshot_time: Some(150),
        log_tail: vec!["scan: 3 entries".into()],
    };
    let mut out = vec![];
    agent_conn::poll::poll_all(&ca, &[target(vec![], vec![sum])], 4, T, &mut |v| out.push(v));
    let v = &out[0];
    assert_eq!(v["ok"], true, "{v}");
    assert_eq!(v["poll"], true);
    assert_eq!(v["delivered"], serde_json::json!([7]));
    assert_eq!(v["requests"][0]["id"], req.request_id.as_str());
    assert_eq!(v["policy_version"], 4);
    assert!(v["power"].is_object());

    let st = ui.status().unwrap();
    assert_eq!((st.agent_id.as_str(), st.enrolled, st.reachable), (ID, true, true));
    assert_eq!(st.managed_by.as_deref(), Some("nexus01"));
    assert_eq!(st.ui_policy.header.as_deref(), Some("ACME"));
    assert_eq!((st.last_success, st.next_run), (Some(200), Some(4_000_000_000)));
    let s = ui.sessions(Some(10)).unwrap();
    assert_eq!((s.len(), s[0].id, s[0].new_bytes), (1, 7, 300));
    assert_eq!(ui.session(7).unwrap().log_tail, vec!["scan: 3 entries".to_string()]);

    // acknowledged: gone; the agent stays idle
    let mut out = vec![];
    agent_conn::poll::poll_all(&ca, &[target(vec![req.request_id], vec![])], 1, T, &mut |v| out.push(v));
    assert_eq!(out[0]["requests"], serde_json::json!([]));
    assert_eq!(ui.status().unwrap().state, agent_ui_proto::AgentState::Idle);
    // an unreachable agent: an error line, no panic
    let mut bad = target(vec![], vec![]);
    bad.port = 1;
    let mut out = vec![];
    agent_conn::poll::poll_all(&ca, &[bad], 1, T, &mut |v| out.push(v));
    assert_eq!(out[0]["ok"], false);
}
