//! Bare-metal recovery protocol end to end, without disks: the real Linux agent
//! backs up a directory (the machine layout lands in the snapshot), then a rescue
//! agent — a test platform that records `RescueApply` / `RescueFinish` and restores
//! into a temporary directory instead of recreating disks — is enrolled with the
//! recovery token and recovered by `agent_conn::rescue::recover`. The disk side is
//! covered by the plan unit tests and the QEMU lab (lab/linux/bmr.sh).

use agent_conn::backup::{self, Spec};
use agent_conn::ca::Ca;
use agent_conn::map::MapDb;
use agent_conn::tls::{session_config, Session};
use agent_conn::{enroll, rescue};
use agent_core::cache::Cache;
use agent_core::server::Agent;
use agent_core::server::{Ctx, HostInfo, Platform, PreparedJob, Refused, ScanError, ScanOutput};
use agent_proto::layout::{Layout, LAYOUT_PATH};
use agent_proto::{Entry, Filters, Overwrite, Volume};
use chunkstore::{Keyring, Options, Store};
use nexus_agent::config::{Paths, Settings};
use nexus_agent::restore::Restore;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ID: &str = "0123456789abcdef";
const RESCUE_ID: &str = "fedcba9876543210";
const TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const RECOVERY: &str = "NBSWY3DPEB3W64TMMQQGC3TEEE";
const T: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Calls {
    layout: Option<Layout>,
    finished: bool,
}

struct FakeRescue {
    target: PathBuf,
    calls: Arc<Mutex<Calls>>,
}

impl Platform for FakeRescue {
    type Job = ();
    type Restore = Restore;
    fn host_info(&self) -> HostInfo {
        HostInfo {
            hostname: "nexus-rescue".into(),
            caps: vec!["restore".into(), "xattrs".into(), agent_proto::CAP_RESCUE.into()],
            ..Default::default()
        }
    }
    fn list_volumes(&self) -> Vec<Volume> {
        vec![]
    }
    fn prepare(
        &self,
        _: Ctx,
        _: u64,
        _: &[String],
        _: &[String],
        _: &Filters,
        _: bool,
    ) -> Result<PreparedJob<()>, Refused> {
        Err(Refused(403, "no".into()))
    }
    fn scan(
        &self,
        _: Ctx,
        _: &mut (),
        _: u64,
        _: Option<u64>,
        _: Option<&Cache>,
        _: &mut dyn FnMut(Entry) -> io::Result<()>,
    ) -> Result<ScanOutput, ScanError> {
        Err(ScanError::Refused(Refused(403, "no".into())))
    }
    fn release_snapshots(&self, _: Ctx, _: &mut (), _: u64, _: bool) -> String {
        String::new()
    }
    fn finish_job(&self, _: Ctx, _: (), _: u64, _: bool) -> String {
        String::new()
    }
    fn restore_begin(&self, _: Ctx, job: u64, target: &str, o: Overwrite, confirm: &str) -> io::Result<Restore> {
        assert_eq!(o, Overwrite::Always);
        Restore::begin(job, target, o, confirm)
    }
    fn update(&self, _: Ctx, _: &str, _: &[u8], _: &[u8]) -> Result<String, String> {
        Err("no".into())
    }
    fn restart_after_update(&self) -> ! {
        unreachable!()
    }
    fn rescue_apply(&self, _: Ctx, _: u64, layout: &str) -> Result<(String, String), Refused> {
        self.calls.lock().unwrap().layout = Some(serde_json::from_str(layout).unwrap());
        Ok((self.target.to_string_lossy().into_owned(), "recreated\nmounted".into()))
    }
    fn rescue_finish(&self, _: Ctx, _: u64) -> Result<(String, String), Refused> {
        self.calls.lock().unwrap().finished = true;
        Ok((self.target.to_string_lossy().into_owned(), "grub installed".into()))
    }
}

fn serve<P: Platform>(agent: Agent<P>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || Arc::new(agent).serve(l));
    port
}

fn mtls(ca: &Ca, port: u16, id: &str, pin: &str) -> Session {
    for _ in 0..100 {
        if let Ok(mut c) = Session::connect("127.0.0.1", port, session_config(ca, id, Some(pin)).unwrap(), T) {
            if c.hello(id).is_ok() {
                return c;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("no mTLS session");
}

#[test]
fn layout_in_snapshot_and_recovery_onto_rescue_agent() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let data = d.path().join("host/srv");
    fs::create_dir_all(data.join("etc")).unwrap();
    fs::write(data.join("etc/hostname"), b"web01\n").unwrap();
    let ca = Ca::load_or_create(&d.path().join("ca")).unwrap();
    let opts = Options {
        min_lock_secs: 0,
        gc_grace_secs: 0,
        ..Default::default()
    };
    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("acme", &[(1, [9; 32])]), opts).unwrap();

    // the original host: backup with layout
    let paths = Paths {
        config: d.path().join("agent/etc"),
        state: d.path().join("agent/state"),
        run: d.path().join("agent/run"),
    };
    nexus_agent::init(&paths, TOKEN, None).unwrap();
    let mut agent: Agent<nexus_agent::server::Linux> = Agent::new(
        paths,
        Settings {
            hook_owner: nexus_agent::sys::geteuid(),
            ..Default::default()
        },
    )
    .unwrap();
    agent.exit_on_update = false;
    let port = serve(agent);
    let e = enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T).unwrap();
    let mut s = mtls(&ca, port, ID, &e.cert_sha256);
    assert!(s.has_cap(agent_proto::CAP_LAYOUT));
    let mut map = MapDb::open(&store_dir).unwrap();
    let spec = Spec {
        job: 1,
        paths: vec![data.to_string_lossy().into_owned()],
        excludes: vec![],
        hooks: false,
        filters: Default::default(),
        limits: Default::default(),
        file_hashes: false,
    };
    let r = backup::backup(&store, &mut map, &mut s, ID, &spec, &mut |l| eprintln!("{l}")).unwrap();
    s.close();
    let json = rescue::load_layout(&store, ID, r.time).unwrap();
    let stored: Layout = serde_json::from_str(&json).unwrap();
    assert_eq!(stored.version, agent_proto::layout::LAYOUT_VERSION);
    assert_eq!(stored.hostname, nexus_agent::sys::uname().1);

    // a plain agent is no rescue agent
    let mut s = mtls(&ca, port, ID, &e.cert_sha256);
    let err = rescue::recover(
        &store,
        &map,
        &mut s,
        &rescue::Spec {
            job: 2,
            agent: ID.into(),
            time: r.time,
            reboot: false,
        },
        &mut |_| {},
        &mut |_| {},
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("not a rescue agent"));
    s.close();

    // the rescue agent: enrolled with the recovery token under its own id
    let rpaths = Paths {
        config: d.path().join("rescue/etc"),
        state: d.path().join("rescue/state"),
        run: d.path().join("rescue/run"),
    };
    agent_core::init(&rpaths, RECOVERY, None, "nexus-rescue").unwrap();
    let calls = Arc::new(Mutex::new(Calls::default()));
    let target = d.path().join("target");
    let fake = FakeRescue {
        target: target.clone(),
        calls: calls.clone(),
    };
    let rport = serve(Agent::with_platform(fake, rpaths, Settings::default()).unwrap());
    assert!(
        enroll::enroll(&ca, "127.0.0.1", rport, &agent_proto::token_digest(TOKEN), RESCUE_ID, T).is_err(),
        "the host's enrollment token does not enroll the rescue agent"
    );
    let e2 = enroll::enroll(
        &ca,
        "127.0.0.1",
        rport,
        &agent_proto::token_digest(RECOVERY),
        RESCUE_ID,
        T,
    )
    .unwrap();
    let mut s = mtls(&ca, rport, RESCUE_ID, &e2.cert_sha256);
    let mut steps = vec![];
    let mut lines = vec![];
    let st = rescue::recover(
        &store,
        &map,
        &mut s,
        &rescue::Spec {
            job: 3,
            agent: ID.into(),
            time: r.time,
            reboot: false,
        },
        &mut |l| lines.push(l.to_string()),
        &mut |x| steps.push(x.to_string()),
    )
    .unwrap();
    s.close();
    assert_eq!(steps, ["apply", "restore", "finish"]);
    assert!(lines.iter().any(|l| l.contains("grub installed")), "{lines:?}");
    assert!(st.errors.is_empty(), "{:?}", st.errors);
    let c = calls.lock().unwrap();
    assert_eq!(c.layout.as_ref(), Some(&stored));
    assert!(c.finished);
    let rel = data.strip_prefix("/").unwrap();
    assert_eq!(fs::read(target.join(rel).join("etc/hostname")).unwrap(), b"web01\n");
    assert!(
        target.join(LAYOUT_PATH).exists(),
        "the layout file is restored too (removed by RescueFinish)"
    );
}
