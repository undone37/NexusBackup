//! Agent protocol v1.9 block reads (the VMware proxy role, docs/vmware-design.md) over a real mTLS session:
//! refused unless `proxy = on`, then the hashes of the requested 4 MiB blocks, their data on `Want`, the job
//! gone after `Release`; a wrong disk size or a range beyond the disk is refused.

use agent_conn::ca::Ca;
use agent_conn::enroll;
use agent_conn::tls::{session_config, Session};
use agent_core::cache::Cache;
use agent_core::server::Agent;
use agent_core::server::{Ctx, HostInfo, Platform, PreparedJob, Refused, ScanError, ScanOutput};
use agent_proto::{Entry, Filters, Message, Overwrite, Volume, BLOCK_SIZE, CAP_BLOCK_READ};
use nexus_agent::config::{Paths, Settings};
use nexus_agent::restore::Restore;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const ID: &str = "0123456789abcdef";
const TOKEN: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOA";
const T: Duration = Duration::from_secs(30);

/// A proxy whose "hot-added disk" at 0:1 is a file.
struct FakeProxy {
    disk: PathBuf,
}

impl Platform for FakeProxy {
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
    fn block_device(&self, target: u32) -> Result<PathBuf, String> {
        if target == 1 {
            Ok(self.disk.clone())
        } else {
            Err(format!("no disk at SCSI target 0:{target}"))
        }
    }
}

fn session(d: &std::path::Path, disk: PathBuf, proxy: bool, name: &str) -> Session {
    let ca = Ca::load_or_create(&d.join("ca")).unwrap();
    let paths = Paths {
        config: d.join(name).join("etc"),
        state: d.join(name).join("state"),
        run: d.join(name).join("run"),
    };
    agent_core::init(&paths, TOKEN, None, "nexus-proxy").unwrap();
    let agent = Agent::with_platform(
        FakeProxy { disk },
        paths,
        Settings {
            proxy,
            ..Default::default()
        },
    )
    .unwrap();
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

/// The agent's refusal (Session::recv turns `Error` into an Err): "agent error <code>: …".
fn refused(s: &mut Session, m: Message) -> String {
    s.send(&m).unwrap();
    match s.recv() {
        Err(e) => format!("{e:#}"),
        Ok(m) => panic!("expected a refusal, got {}", agent_conn::name(&m)),
    }
}

fn scan(job: u64, target: u32, size: u64, ranges: Vec<(u64, u64)>) -> Message {
    Message::BlockScan {
        job,
        target,
        size,
        ranges,
    }
}

#[test]
fn block_reads_of_a_hot_added_disk() {
    let d = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    // two full blocks and a short last one
    let size = 2 * BLOCK_SIZE + 123_456;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let disk = d.path().join("disk.img");
    fs::write(&disk, &data).unwrap();
    let want =
        |b: u64| *blake3::hash(&data[(b * BLOCK_SIZE) as usize..((b + 1) * BLOCK_SIZE).min(size) as usize]).as_bytes();

    // an ordinary agent: no capability, refused
    let mut s = session(d.path(), disk.clone(), false, "plain");
    assert!(!s.has_cap(CAP_BLOCK_READ));
    let e = refused(&mut s, scan(1, 1, size, vec![(0, 3)]));
    assert!(e.contains("403") && e.contains("proxy = on"), "{e}");
    s.close();

    let mut s = session(d.path(), disk.clone(), true, "proxy");
    assert!(s.has_cap(CAP_BLOCK_READ));
    // the disk's size must match, the ranges must lie on it, only targets 1..15 exist
    for (sz, ranges) in [(size + 1, vec![(0, 1)]), (size, vec![(2, 2)])] {
        let e = refused(&mut s, scan(9, 1, sz, ranges));
        assert!(e.contains("400"), "{e}");
    }
    let e = refused(&mut s, scan(9, 2, size, vec![(0, 1)]));
    assert!(e.contains("403") && e.contains("0:2"), "{e}");

    // blocks 0 and 2 (a changed-block list), then their data
    s.send(&Message::BlockScan {
        job: 7,
        target: 1,
        size,
        ranges: vec![(0, 1), (2, 1)],
    })
    .unwrap();
    let mut got = Vec::new();
    loop {
        match s.recv().unwrap() {
            Message::BlockHashes { job, first, hashes } => {
                assert_eq!(job, 7);
                got.extend(hashes.into_iter().enumerate().map(|(i, h)| (first + i as u64, h)));
            }
            Message::BlockScanDone { job, blocks, bytes } => {
                assert_eq!((job, blocks, bytes), (7, 2, BLOCK_SIZE + 123_456));
                break;
            }
            m => panic!("{}", agent_conn::name(&m)),
        }
    }
    assert_eq!(got, [(0, want(0)), (2, want(2))]);
    s.send(&Message::Want {
        job: 7,
        hashes: vec![want(2), want(0)],
    })
    .unwrap();
    for b in [2, 0] {
        match s.recv().unwrap() {
            Message::Chunk { hash, data: c } => {
                assert_eq!(hash, want(b));
                assert_eq!(
                    &c[..],
                    &data[(b * BLOCK_SIZE) as usize..((b + 1) * BLOCK_SIZE).min(size) as usize]
                );
            }
            m => panic!("{}", agent_conn::name(&m)),
        }
    }
    assert!(matches!(s.recv().unwrap(), Message::WantDone));
    s.send(&Message::Release { job: 7, success: true }).unwrap();
    assert!(matches!(s.recv().unwrap(), Message::Released { job: 7, .. }));
    let e = refused(
        &mut s,
        Message::Want {
            job: 7,
            hashes: vec![want(0)],
        },
    );
    assert!(e.contains("404"), "the job is gone: {e}");
    s.close();
}
