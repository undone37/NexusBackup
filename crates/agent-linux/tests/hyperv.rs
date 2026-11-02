//! Agent protocol v1.10 Hyper-V host backups (docs/hyperv-design.md M1) over a real mTLS session, against a fake
//! Hyper-V platform whose "frozen checkpoint disks" are files: the VM list, a backup committed as `hv-<id>` with
//! byte-identical disk images and `hyperv.json`, the checkpoint kept as a reference point; a failed read removes
//! it, a disconnect too, and an agent that is no Hyper-V host refuses.

use agent_conn::ca::Ca;
use agent_conn::enroll;
use agent_conn::tls::{session_config, Session};
use agent_core::cache::Cache;
use agent_core::server::Agent;
use agent_core::server::{Ctx, HostInfo, Platform, PreparedJob, Refused, ScanError, ScanOutput};
use agent_proto::{Entry, Filters, Message, Overwrite, Volume, BLOCK_SIZE, CAP_HYPERV};
use nexus_agent::config::{Paths, Settings};
use nexus_agent::restore::Restore;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ID: &str = "0123456789abcdef";
const TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const T: Duration = Duration::from_secs(30);

const VM: &str = "5A1C2F0E-7B3D-4E6F-9A8B-0C1D2E3F4A5B";

/// A Hyper-V host with one VM of two disks (files); `finished` records each `hv_finish(keep)`.
struct FakeHv {
    hyperv: bool,
    disks: Vec<(PathBuf, u64)>,
    finished: Arc<Mutex<Vec<bool>>>,
}

impl Platform for FakeHv {
    type Job = ();
    type Restore = Restore;
    fn host_info(&self) -> HostInfo {
        HostInfo {
            hostname: "nexus-proxy".into(),
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
        Restore::begin(job, target, o, confirm)
    }
    fn update(&self, _: Ctx, _: &str, _: &[u8], _: &[u8]) -> Result<String, String> {
        Err("no".into())
    }
    fn restart_after_update(&self) -> ! {
        unreachable!()
    }
    fn hyperv(&self) -> bool {
        self.hyperv
    }
    fn hv_list(&self) -> Result<String, String> {
        Ok(format!(
            r#"[{{"id":"{VM}","name":"web","state":"Running","generation":2}}]"#
        ))
    }
    fn hv_prepare(&self, vm: &str, base: Option<&serde_json::Value>) -> Result<(String, Vec<PathBuf>), String> {
        if vm != VM {
            return Err(format!("no VM {vm}"));
        }
        // with the base "rct:1": disk 0 changed in its second block, disk 1 has no valid base
        let changed = |i: usize| match (base.and_then(|b| b["rct"][i].as_str()), i) {
            (Some("rct:1"), 0) => format!("[[{},100]]", BLOCK_SIZE + 10),
            _ => "null".into(),
        };
        let disks: Vec<String> = self
            .disks
            .iter()
            .enumerate()
            .map(|(i, (_, size))| {
                format!(
                    r#"{{"name":"scsi0-{i}","target":{},"size":{size},"changed":{}}}"#,
                    i + 1,
                    changed(i)
                )
            })
            .collect();
        let json = format!(
            r#"{{"vm":"{VM}","name":"web","consistency":"crash","disks":[{}]}}"#,
            disks.join(",")
        );
        Ok((json, self.disks.iter().map(|(p, _)| p.clone()).collect()))
    }
    fn hv_finish(&self, _prepared: &str, keep: bool) -> Result<String, String> {
        self.finished.lock().unwrap().push(keep);
        Ok(if keep {
            r#"{"reference_point":"rp1","rct":["rct:1","rct:1b"]}"#.into()
        } else {
            "{}".into()
        })
    }
}

fn session(d: &std::path::Path, p: FakeHv, name: &str) -> Session {
    let ca = Ca::load_or_create(&d.join("ca")).unwrap();
    let paths = Paths {
        config: d.join(name).join("etc"),
        state: d.join(name).join("state"),
        run: d.join(name).join("run"),
    };
    agent_core::init(&paths, TOKEN, None, "nexus-hv").unwrap();
    let agent = Agent::with_platform(p, paths, Settings::default()).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || Arc::new(agent).serve(l));
    let e = enroll::enroll(&ca, "127.0.0.1", port, &agent_proto::token_digest(TOKEN), ID, T).unwrap();
    for _ in 0..100 {
        if let Ok(mut c) = Session::connect(
            "127.0.0.1",
            port,
            session_config(&ca, ID, Some(&e.cert_sha256)).unwrap(),
            T,
        ) {
            if c.hello(ID).is_ok() {
                return c;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("no mTLS session");
}

#[test]
fn hyperv_vm_backup() {
    use agent_conn::hyperv;
    use agent_conn::map::MapDb;
    use chunkstore::{Index, Keyring, Options, Store};
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let mut disks = Vec::new();
    let mut data = Vec::new();
    for (i, size) in [2 * BLOCK_SIZE + 512, BLOCK_SIZE].into_iter().enumerate() {
        let bytes: Vec<u8> = (0..size).map(|n| ((n + i as u64) % 241) as u8).collect();
        let p = d.path().join(format!("disk{i}.vhdx-frozen"));
        fs::write(&p, &bytes).unwrap();
        disks.push((p, size));
        data.push(bytes);
    }
    let store_dir = d.path().join("store");
    let store = Store::open(&store_dir, Keyring::new("acme", &[(1, [9; 32])]), Options::default()).unwrap();
    let mut map = MapDb::open(&store_dir).unwrap();
    let finished = Arc::new(Mutex::new(Vec::new()));
    let fake = |hyperv: bool, disks: Vec<(PathBuf, u64)>| FakeHv {
        hyperv,
        disks,
        finished: finished.clone(),
    };

    // not a Hyper-V host: no capability, the messages are refused
    let mut s = session(d.path(), fake(false, disks.clone()), "plain");
    assert!(!s.has_cap(CAP_HYPERV));
    assert!(format!("{:#}", hyperv::list(&mut s).unwrap_err()).contains("no Hyper-V"));
    s.send(&Message::HvList).unwrap();
    assert!(format!("{:#}", s.recv().unwrap_err()).contains("403"));
    s.close();

    let mut s = session(d.path(), fake(true, disks.clone()), "hv");
    assert!(s.has_cap(CAP_HYPERV));
    assert_eq!(hyperv::list(&mut s).unwrap()[0]["id"], VM);
    let r = hyperv::backup(&store, &mut map, &mut s, 5, VM, &mut |_| {}).unwrap();
    assert_eq!(r.source, hyperv::source_name(VM));
    assert_eq!(r.finished["reference_point"], "rp1");
    assert_eq!(*finished.lock().unwrap(), [true]);
    let m = store.load_manifest(&r.source, r.time).unwrap();
    for (i, want) in data.iter().enumerate() {
        let idx = store.load_index(&m, &format!("scsi0-{i}")).unwrap();
        assert!(matches!(idx, Index::Fixed { .. }));
        let mut rd = store.image_reader(&idx).unwrap();
        let mut buf = vec![0; rd.size() as usize];
        rd.read_at(0, &mut buf).unwrap();
        assert!(buf == *want, "disk {i} differs");
    }
    let Index::Dynamic { entries } = store.load_index(&m, "config").unwrap() else {
        panic!("config is not a file index")
    };
    assert_eq!(entries[0].path, hyperv::CONFIG_FILE);
    let Index::Dynamic { entries } = store.load_index(&m, "config").unwrap() else {
        unreachable!()
    };
    let mut cfg = Vec::new();
    for id in &entries[0].chunks {
        cfg.extend(store.read_chunk(id).unwrap());
    }
    let cfg: serde_json::Value = serde_json::from_slice(&cfg).unwrap();
    assert_eq!(
        cfg["reference"]["rct"][0], "rct:1",
        "the next run's base is in the snapshot"
    );
    // #39 M2: a second run with that base reads only disk 0's changed block (disk 1: no valid base, in full)
    data[0][BLOCK_SIZE as usize + 20] ^= 0xff;
    fs::write(&disks[0].0, &data[0]).unwrap();
    let r2 = hyperv::backup(&store, &mut map, &mut s, 6, VM, &mut |_| {}).unwrap();
    assert!(r2.time > r.time);
    assert_eq!((r2.disks[0].1.blocks, r2.disks[1].1.blocks), (1, 1));
    let m2 = store.load_manifest(&r2.source, r2.time).unwrap();
    for (i, want) in data.iter().enumerate() {
        let idx = store.load_index(&m2, &format!("scsi0-{i}")).unwrap();
        let mut rd = store.image_reader(&idx).unwrap();
        let mut buf = vec![0; rd.size() as usize];
        rd.read_at(0, &mut buf).unwrap();
        assert!(buf == *want, "incremental disk {i} differs");
    }
    // only the prepared job's disks are readable, at their own job ids
    let e = hyperv::backup(
        &store,
        &mut map,
        &mut s,
        7,
        "00000000-0000-0000-0000-000000000000",
        &mut |_| {},
    );
    assert!(format!("{:#}", e.unwrap_err()).contains("no VM"));
    s.send(&Message::BlockScan {
        job: 6 * 16 + 1,
        target: 1,
        size: BLOCK_SIZE,
        ranges: vec![(0, 1)],
    })
    .unwrap();
    assert!(
        format!("{:#}", s.recv().unwrap_err()).contains("403"),
        "a finished job's disks are gone"
    );
    s.close();

    // a disk that cannot be read: nothing committed, the checkpoint removed
    finished.lock().unwrap().clear();
    let mut gone = disks.clone();
    gone[1].0 = d.path().join("missing");
    let mut s = session(d.path(), fake(true, gone), "hv2");
    let before = store.list_snapshots().unwrap().len();
    let e = hyperv::backup(&store, &mut map, &mut s, 8, VM, &mut |_| {}).unwrap_err();
    assert!(format!("{e:#}").contains("scsi0-1"), "{e:#}");
    assert_eq!(store.list_snapshots().unwrap().len(), before);
    assert_eq!(*finished.lock().unwrap(), [false]);

    // a connection that drops after HvPrepare: the agent removes the checkpoint itself
    finished.lock().unwrap().clear();
    s.send(&Message::HvPrepare { job: 9, vm: VM.into() }).unwrap();
    assert!(matches!(s.recv().unwrap(), Message::HvPrepared { job: 9, .. }));
    s.close();
    for _ in 0..100 {
        if !finished.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(*finished.lock().unwrap(), [false]);
}
