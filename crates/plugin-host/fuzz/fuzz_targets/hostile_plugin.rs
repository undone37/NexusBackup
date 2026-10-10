//! A hostile plugin (docs/plugin-system.md "Trust split"): whatever bytes it writes
//! to its stdout, the host's message handling (framing, validation, backup ordering,
//! Unchanged checks, restore/validate/guests/mount loops) must not panic, must not
//! allocate without bound, and may only commit snapshots whose entries are valid.
#![no_main]

use chunkstore::{Index, Keyring, Options, Store, TreeEntry, TreeKind};
use libfuzzer_sys::fuzz_target;
use plugin_host::backup::{self, Bounds};
use plugin_host::restore::{self, Snapshot};
use plugin_host::sandbox::Peer;
use plugin_host::ops;
use plugin_proto::{read_msg, Message};
use std::sync::OnceLock;
use std::time::Duration;

const SRC: &str = "plugin-fz-1";

fn store() -> &'static Store {
    static S: OnceLock<(tempfile::TempDir, Store)> = OnceLock::new();
    let (_, s) = S.get_or_init(|| {
        let d = tempfile::tempdir_in("/dev/shm").unwrap();
        let opts = Options {
            min_lock_secs: 0,
            ..Options::default()
        };
        let s = Store::open(d.path(), Keyring::new("fuzz", &[(1, [1; 32])]), opts).unwrap();
        let (c, n) = s.store_file(&b"hello"[..]).unwrap();
        let e = TreeEntry {
            path: b"a.txt".to_vec(),
            kind: TreeKind::File,
            mode: 0o100644,
            uid: 0,
            gid: 0,
            size: n,
            mtime_ns: 1,
            ctime_ns: 1,
            inode: 1,
            rdev: 0,
            link_target: None,
            xattrs: vec![],
            chunks: c,
            inconsistent: false,
        };
        s.commit_snapshot(SRC, 1, &[("files", Index::Tree { entries: vec![e] })]).unwrap();
        (d, s)
    });
    s
}

/// The plugin side is a byte string: frames are read from it; host messages are dropped.
struct Replay<'a> {
    data: &'a [u8],
}

impl Peer for Replay<'_> {
    fn send(&mut self, _m: &Message) -> anyhow::Result<()> {
        Ok(())
    }
    fn recv(&mut self) -> anyhow::Result<Message> {
        read_msg(&mut self.data).map_err(|e| anyhow::anyhow!("{e}"))
    }
    fn poll(&mut self, _wait: Duration) -> anyhow::Result<Option<Message>> {
        self.recv().map(Some)
    }
    fn set_idle(&mut self, _idle: Option<Duration>) {}
    fn violation(&mut self, why: &str) -> anyhow::Error {
        anyhow::anyhow!("violation: {why}")
    }
    fn finish(&mut self) {}
}

fuzz_target!(|data: &[u8]| {
    let Some((&op, rest)) = data.split_first() else { return };
    let s = store();
    let mut peer = Replay { data: rest };
    let mut out = |_: &str| {};
    match op % 4 {
        0 => {
            let r = backup::run(
                s,
                &mut peer,
                &backup::Params {
                    job: 1,
                    kind: "fz",
                    config: "{}",
                    params: serde_json::json!({}),
                    source: SRC,
                    bounds: Bounds {
                        max_entries: 10_000,
                        ..Bounds::default()
                    },
                },
                &mut out,
            );
            if let Ok(r) = r {
                let snap = Snapshot::load(s, SRC, r.time).unwrap();
                for e in &snap.files {
                    assert!(plugin_proto::valid_path(&e.path));
                }
                s.delete_snapshot(SRC, r.time).unwrap();
            }
        }
        1 => {
            let snap = Snapshot::load(s, SRC, 1).unwrap();
            let _ = restore::run(
                s,
                &mut peer,
                &snap,
                &restore::Params {
                    job: 1,
                    kind: "fz",
                    config: "{}",
                    restore: "x",
                    params: serde_json::json!({}),
                    max_log_bytes: 1 << 16,
                },
                &mut out,
            );
        }
        2 => {
            let p = ops::Params {
                job: 1,
                kind: "fz",
                config: "{}",
            };
            let _ = ops::validate(&mut peer, &p, &mut out);
            let _ = ops::guests(&mut Replay { data: rest }, &p, &mut out);
        }
        _ => {
            let snap = Snapshot::load(s, SRC, 1).unwrap();
            let p = ops::Params {
                job: 1,
                kind: "fz",
                config: "{}",
            };
            let _ = ops::mount(s, &mut peer, &snap, &p, serde_json::json!({}), Duration::from_millis(1), &mut out);
        }
    }
});
