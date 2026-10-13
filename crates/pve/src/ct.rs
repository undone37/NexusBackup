//! Container (LXC) backup and restore (contract: docs/pve-connector.md,
//! "Container backup flow" / "Container restore flow").
//!
//! Backup: the node's `backup_container` sends records over `ssh ct-stream <vmid>`
//! (tag byte, u32 big-endian length, payload): `C` pct.conf, `D` tar data (repeated),
//! `E` `ok` | `fail <msg>`. We chunk the tar stream into one dynamic index entry,
//! commit, and only then answer `ok\n` on the same connection.
//!
//! Restore: `ssh ct-restore-serve <archive>` gets a u64 big-endian length followed by
//! exactly that many bytes of the snapshot's tar stream.

use crate::backup::{config_entry, Cluster, Job, Kill, SshNode};
use anyhow::{bail, Context, Result};
use chunkstore::{FileEntry, FileStats, Index, Manifest, Store};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process::Stdio;
use std::time::Duration;

/// Name of the dynamic index and of its single entry holding the tar stream.
pub const ROOT: &str = "root.tar";
/// Container config file inside the `config` index.
pub const CONFIG_FILE: &str = "pct.conf";
const RECORD_MAX: usize = 16 << 20;

pub fn source_name(vmid: u32) -> String {
    format!("ct-{vmid}")
}

/// The `root.tar` entry of a container snapshot.
pub fn root_tar(store: &Store, m: &Manifest) -> Result<FileEntry> {
    let Index::Dynamic { entries } = store.load_index(m, ROOT)? else {
        bail!("{ROOT} index is not dynamic")
    };
    entries
        .into_iter()
        .find(|e| e.path == ROOT)
        .with_context(|| format!("{ROOT} index without {ROOT} entry"))
}

/// Reader over the node's record stream: `config()` first, then `Read` yields the
/// tar bytes until the `E` record, whose status is available from `end()`.
/// A stream that ends before `E` is an `UnexpectedEof` error, never a short file.
pub struct Records<R> {
    inner: R,
    left: usize,
    end: Option<String>,
}

fn bad(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl<R: Read> Records<R> {
    pub fn new(inner: R) -> Self {
        Records {
            inner,
            left: 0,
            end: None,
        }
    }

    fn header(&mut self) -> io::Result<(u8, usize)> {
        let mut h = [0u8; 5];
        self.inner.read_exact(&mut h).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(e.kind(), "container stream ended without status")
            } else {
                e
            }
        })?;
        let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
        if len > RECORD_MAX {
            return Err(bad(format!("record of {len} bytes")));
        }
        Ok((h[0], len))
    }

    fn payload(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0; len];
        self.inner.read_exact(&mut v)?;
        Ok(v)
    }

    /// The `C` record (pct.conf); must be the first record.
    pub fn config(&mut self) -> io::Result<String> {
        match self.header()? {
            (b'C', len) => Ok(String::from_utf8_lossy(&self.payload(len)?).into_owned()),
            (t, _) => Err(bad(format!("expected config record, got tag {t:#04x}"))),
        }
    }

    /// Status of the `E` record once `read` returned EOF.
    pub fn end(&self) -> Option<&str> {
        self.end.as_deref()
    }
}

impl<R: Read> Read for Records<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !buf.is_empty() && self.end.is_none() {
            if self.left > 0 {
                let n = buf.len().min(self.left);
                let n = self.inner.read(&mut buf[..n])?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated data record"));
                }
                self.left -= n;
                return Ok(n);
            }
            match self.header()? {
                (b'D', len) => self.left = len,
                (b'E', len) => self.end = Some(String::from_utf8_lossy(&self.payload(len)?).into_owned()),
                (t, _) => return Err(bad(format!("unexpected record tag {t:#04x}"))),
            }
        }
        Ok(0)
    }
}

/// Reads the whole record stream into the store; returns (pct.conf, tar stats).
pub fn read_stream(store: &Store, r: impl Read) -> Result<(String, FileStats)> {
    let mut rec = Records::new(r);
    let config = rec.config()?;
    let stats = store.store_file_stats(&mut rec)?;
    match rec.end() {
        Some("ok") => Ok((config, stats)),
        Some(e) => bail!("node: {e}"),
        None => bail!("container stream without status"),
    }
}

impl Cluster {
    /// One backup run of a container. The snapshot is committed before the node
    /// gets `ok`; returns the manifest and the dedup stats of the tar stream.
    pub fn backup_ct(&self, store: &Store, vmid: u32) -> Result<(Manifest, FileStats)> {
        let (node, kind) = self.guest(vmid)?;
        if kind != "lxc" {
            bail!("guest {vmid} is not a container ({kind})");
        }
        let ssh = self.ssh(&node)?;
        let upid = self.api.start_backup(&node, vmid, &self.storage, None)?;
        let job = self.wait_job(&node, ssh, vmid, &upid, "lxc")?;

        let mut child = Kill(
            ssh.cmd(&format!("ct-stream {vmid}"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut stdin = child.0.stdin.take().unwrap();
        let stdout = BufReader::with_capacity(
            1 << 20,
            chunkstore::progress::Reader {
                inner: catalog::schedule::Throttled {
                    inner: child.0.stdout.take().unwrap(),
                    limit: self.read_limit.clone(),
                },
                // the tar stream's size is unknown up front: bytes and rate only
                meter: chunkstore::progress::Meter::new("tar stream", 1, 1, None),
            },
        );
        let (m, stats) = match pull_ct(store, vmid, &job, stdout) {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string().replace(['\n', '\r'], " ");
                let _ = writeln!(stdin, "fail {msg}");
                // dropping `child` kills ssh, so a node still sending cannot block us
                return Err(e);
            }
        };
        writeln!(stdin, "ok")
            .and_then(|_| stdin.flush())
            .context("send ok to the node")?;
        drop(stdin);
        let st = child.0.wait()?;
        if !st.success() {
            eprintln!("warning: ct-stream for CT {vmid} exited with {st} after commit");
        }
        let exit = self.api.wait_task(&node, &upid, Duration::from_secs(3600))?;
        if exit != "OK" {
            eprintln!("warning: vzdump task for CT {vmid} ended with {exit}; snapshot kept");
        }
        let log = self.api.task_log(&node, &upid).unwrap_or_default();
        let level = crate::consistency::ct_level(&log);
        println!("{}", crate::consistency::line(&source_name(vmid), m.time, level));
        Ok((m, stats))
    }

    /// Full restore of snapshot `ct-<vmid>/<time>` as unprivileged CT `target` on
    /// `node` with the options of `crate::restore`.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_ct(
        &self,
        store: &Store,
        vmid: u32,
        time: u64,
        node: &str,
        target: u32,
        target_storage: &str,
        opts: &crate::restore::RestoreOpts,
    ) -> Result<crate::restore::Restored> {
        let m = store.load_manifest(&source_name(vmid), time)?;
        let root = root_tar(store, &m)?;
        let conf = crate::backup::read_config(store, &m, CONFIG_FILE)?.unwrap_or_default();
        let ssh = self.ssh(node)?;
        let archive = format!("nexus-{vmid}-{time}");
        let volid = format!("{}:backup/{archive}", self.storage);
        let name = crate::restore::conf_value(&conf, "hostname");
        let stamp = crate::restore::stamp(crate::restore::unix_now());
        crate::restore::run(
            self,
            "lxc",
            node,
            target,
            vmid,
            &volid,
            target_storage,
            name.as_deref(),
            opts,
            &stamp,
            |params| {
                let upid = self.api.start_restore(node, "lxc", params)?;
                let mut served = false;
                loop {
                    if let Some(exit) = self.api.task_status(node, &upid)? {
                        if exit != "OK" {
                            let log = self.api.task_log(node, &upid).unwrap_or_default();
                            bail!("restore task ended with {exit}: {}", log.join("\n"));
                        }
                        return Ok(());
                    }
                    if !served {
                        if let Ok(out) = ssh.run(&format!("restore-job {archive}"), None) {
                            let req: serde_json::Value = serde_json::from_slice(&out).context("restore job JSON")?;
                            if req["type"].as_str() != Some("lxc") {
                                bail!("pending restore request for {archive} is not a container restore");
                            }
                            serve_ct(store, ssh, &archive, &root).context("serve container archive")?;
                            served = true;
                            continue;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            },
        )
    }
}

fn pull_ct(store: &Store, vmid: u32, job: &Job, r: impl Read) -> Result<(Manifest, FileStats)> {
    let (config, stats) = read_stream(store, r)?;
    let root = FileEntry {
        path: ROOT.into(),
        mode: 0o640,
        size: stats.size,
        mtime: 0,
        chunks: stats.chunks.clone(),
    };
    let mut cfg = vec![config_entry(store, CONFIG_FILE, &config)?];
    if let Some(fw) = &job.firewall {
        cfg.push(config_entry(store, "firewall.fw", fw)?);
    }
    let m = store.commit_snapshot(
        &source_name(vmid),
        job.time()?,
        &[
            (ROOT, Index::Dynamic { entries: vec![root] }),
            ("config", Index::Dynamic { entries: cfg }),
        ],
    )?;
    Ok((m, stats))
}

fn serve_ct(store: &Store, ssh: &SshNode, archive: &str, root: &FileEntry) -> Result<()> {
    let mut child = Kill(
        ssh.cmd(&format!("ct-restore-serve {archive}"))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?,
    );
    let mut w = BufWriter::with_capacity(1 << 20, child.0.stdin.take().unwrap());
    w.write_all(&root.size.to_be_bytes())?;
    store.write_chunks(&root.chunks, &mut w)?;
    w.flush()?;
    drop(w);
    let st = child.0.wait()?;
    if !st.success() {
        bail!("ct-restore-serve exited with {st}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn read_all(stream: &[u8]) -> io::Result<(String, Vec<u8>, Option<String>)> {
        let mut r = Records::new(stream);
        let cfg = r.config()?;
        let mut data = Vec::new();
        // tiny reads exercise record boundaries
        let mut buf = [0u8; 3];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        Ok((cfg, data, r.end().map(str::to_owned)))
    }

    #[test]
    fn records_roundtrip() {
        let s = [
            rec(b'C', b"arch: amd64\n"),
            rec(b'D', b"hello "),
            rec(b'D', b""),
            rec(b'D', b"world"),
            rec(b'E', b"ok"),
        ]
        .concat();
        let (cfg, data, end) = read_all(&s).unwrap();
        assert_eq!(cfg, "arch: amd64\n");
        assert_eq!(data, b"hello world");
        assert_eq!(end.as_deref(), Some("ok"));
    }

    #[test]
    fn records_fail_status() {
        let s = [rec(b'C', b""), rec(b'D', b"x"), rec(b'E', b"fail tar failed (exit 2)")].concat();
        let (_, data, end) = read_all(&s).unwrap();
        assert_eq!(data, b"x");
        assert_eq!(end.as_deref(), Some("fail tar failed (exit 2)"));
    }

    #[test]
    fn records_truncated_is_error() {
        let full = [rec(b'C', b"c"), rec(b'D', b"abcdef")].concat();
        // no E record
        assert_eq!(read_all(&full).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        // cut inside the data record
        assert_eq!(
            read_all(&full[..full.len() - 2]).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        // cut inside a header
        assert_eq!(read_all(&full[..8]).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn stream_commit_dedup_and_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let keys = chunkstore::Keyring::new("t", &[(1, [7; 32])]);
        let store = Store::open(dir.path(), keys, chunkstore::Options::default()).unwrap();
        let tar = pseudo_random(3 << 20, 42);
        let stream = |data: &[u8]| {
            let mut s = rec(b'C', b"arch: amd64\nhostname: ct200\nunprivileged: 1\n");
            for c in data.chunks(1 << 20) {
                s.extend(rec(b'D', c));
            }
            s.extend(rec(b'E', b"ok"));
            s
        };
        let job: Job =
            serde_json::from_str(r#"{"type":"lxc","vmid":200,"archive":"nexus-200-1760000000","firewall":null}"#)
                .unwrap();
        let (m, st) = pull_ct(&store, 200, &job, &stream(&tar)[..]).unwrap();
        assert_eq!((m.source.as_str(), m.time), ("ct-200", 1760000000));
        assert_eq!(st.size, tar.len() as u64);
        assert_eq!(st.new_bytes, st.size);

        // same data again: everything deduplicated
        let job2: Job =
            serde_json::from_str(r#"{"type":"lxc","archive":"nexus-200-1760000100","firewall":"[OPTIONS]\n"}"#)
                .unwrap();
        let (m2, st2) = pull_ct(&store, 200, &job2, &stream(&tar)[..]).unwrap();
        assert_eq!((st2.new_chunks, st2.new_bytes), (0, 0));

        let root = root_tar(&store, &m2).unwrap();
        let mut back = Vec::new();
        store.write_chunks(&root.chunks, &mut back).unwrap();
        assert_eq!(back, tar);

        // a failed stream commits nothing
        let mut bad = stream(&tar);
        bad.truncate(bad.len() - 7);
        bad.extend(rec(b'E', b"fail tar failed"));
        let job3: Job = serde_json::from_str(r#"{"type":"lxc","archive":"nexus-200-1760000200"}"#).unwrap();
        assert!(pull_ct(&store, 200, &job3, &bad[..]).is_err());
        assert_eq!(store.list_snapshots().unwrap().len(), 2);

        let idx = crate::backup::build_index(&store).unwrap();
        let a = &idx["archives"];
        assert_eq!(a.as_array().unwrap().len(), 2);
        assert_eq!(a[0]["volname"], "backup/nexus-200-1760000000");
        assert_eq!(a[0]["type"], "lxc");
        assert_eq!(a[0]["vmid"], 200);
        assert_eq!(a[0]["size"], tar.len() as u64);
        assert_eq!(a[0]["config"], "arch: amd64\nhostname: ct200\nunprivileged: 1\n");
        assert_eq!(a[0]["firewall"], serde_json::Value::Null);
        assert_eq!(a[1]["firewall"], "[OPTIONS]\n");
        assert_eq!(a[1]["devices"], serde_json::json!([]));
    }

    #[test]
    fn records_reject_bad_input() {
        assert!(read_all(&rec(b'D', b"x")).is_err(), "data before config");
        let s = [rec(b'C', b""), rec(b'X', b"")].concat();
        assert_eq!(read_all(&s).unwrap_err().kind(), io::ErrorKind::InvalidData);
        let mut huge = rec(b'C', b"");
        huge.extend_from_slice(&[b'D', 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(read_all(&huge).unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
