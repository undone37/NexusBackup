//! The SSH side: commands of the forced command ([`crate::fc`]) and their
//! output streams. [`Transport`] builds the process (real: `ssh`, tests: the
//! forced-command script run locally by bash).

use crate::{diff, stream, walk};
use anyhow::{bail, Context, Result};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::thread::JoinHandle;

pub trait Transport {
    /// A process that runs `cmd` as the forced command's `SSH_ORIGINAL_COMMAND`.
    fn command(&self, cmd: &str) -> Command;
}

#[derive(Clone, Debug)]
pub struct Ssh {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key: PathBuf,
    pub known_hosts: PathBuf,
}

impl Transport for Ssh {
    /// Host key pinned via known_hosts (no TOFU), key only, no agent, no tty.
    fn command(&self, cmd: &str) -> Command {
        let mut c = Command::new("ssh");
        c.arg("-i")
            .arg(&self.key)
            .arg("-p")
            .arg(self.port.to_string())
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ClearAllForwardings=yes",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", self.known_hosts.display()))
            .arg("-T")
            .arg("-l")
            .arg(&self.user)
            .arg("--")
            .arg(&self.host)
            .arg(cmd);
        c
    }
}

/// Captures stderr in a thread (bounded), so a full pipe never blocks the remote side.
fn stderr_reader(child: &mut Child) -> JoinHandle<String> {
    let mut e = child.stderr.take().expect("stderr piped");
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut e).take(64 << 10).read_to_end(&mut buf);
        let _ = std::io::copy(&mut e, &mut std::io::sink());
        String::from_utf8_lossy(&buf).trim().to_owned()
    })
}

fn finish(cmd: &str, mut child: Child, err: JoinHandle<String>) -> Result<()> {
    let st = child.wait()?;
    let msg = err.join().unwrap_or_default();
    if !st.success() {
        bail!("{cmd}: {st}: {}", msg.escape_debug());
    }
    Ok(())
}

fn check_args(ds: &str, snaps: &[&str]) -> Result<()> {
    // `nexus-<id>-<time>` exactly as parse_snap_name accepts it
    let snap_ok = |s: &str| {
        s.strip_prefix("nexus-")
            .and_then(|r| r.split_once('-'))
            .and_then(|(id, _)| (!id.starts_with('0')).then(|| id.parse::<u64>().ok())?)
            .is_some_and(|id| crate::parse_snap_name(id, s).is_some())
    };
    if !crate::valid_dataset(ds) || !snaps.iter().all(|s| snap_ok(s)) {
        bail!("invalid dataset or snapshot name");
    }
    Ok(())
}

pub struct Remote<'a> {
    pub t: &'a dyn Transport,
    /// bytes received over SSH (diff + walk + tar)
    pub received: u64,
}

impl<'a> Remote<'a> {
    pub fn new(t: &'a dyn Transport) -> Self {
        Remote { t, received: 0 }
    }

    fn spawn(&self, cmd: &str, stdin: bool) -> Result<(Child, ChildStdout, JoinHandle<String>)> {
        let mut child = self
            .t
            .command(cmd)
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn ssh")?;
        let out = child.stdout.take().unwrap();
        let err = stderr_reader(&mut child);
        Ok((child, out, err))
    }

    pub fn hello(&mut self) -> Result<String> {
        let (child, out, err) = self.spawn("hello", false)?;
        let mut v = Vec::new();
        out.take(256).read_to_end(&mut v)?;
        finish("hello", child, err)?;
        let s = String::from_utf8_lossy(&v).trim().to_owned();
        if !s.starts_with("nexus-fc ") {
            bail!("unexpected answer to hello: {:?} (is the forced command installed?)", s);
        }
        Ok(s)
    }

    /// `zfs diff -FH ds@from ds@to`, parsed against the dataset's mount point.
    pub fn diff(&mut self, ds: &str, from: &str, to: &str, mountpoint: &str) -> Result<Vec<diff::Line>> {
        check_args(ds, &[from, to])?;
        let cmd = format!("diff {ds} {from} {to}");
        let (child, out, err) = self.spawn(&cmd, false)?;
        let mut v = Vec::new();
        out.take(diff::MAX_OUTPUT as u64 + 1).read_to_end(&mut v)?;
        self.received += v.len() as u64;
        finish(&cmd, child, err)?;
        diff::parse(&v, mountpoint.as_bytes())
    }

    pub fn walk(&mut self, ds: &str, snap: &str) -> Result<Vec<walk::WalkEntry>> {
        check_args(ds, &[snap])?;
        let cmd = format!("walk {ds} {snap}");
        let (mut child, out, err) = self.spawn(&cmd, false)?;
        let mut counted = Counted { r: out, n: 0 };
        let res = walk::read_all(&mut BufReader::with_capacity(1 << 20, &mut counted));
        self.received += counted.n;
        if res.is_err() {
            let _ = child.kill();
        }
        let entries = res.with_context(|| format!("{cmd}: {}", "invalid walk output"))?;
        finish(&cmd, child, err)?;
        Ok(entries)
    }

    /// Sends `paths` (validated, relative) and hands the tar stream to `f`.
    pub fn read<T>(
        &mut self,
        ds: &str,
        snap: &str,
        paths: Vec<Vec<u8>>,
        f: impl FnOnce(&mut stream::Reader<BufReader<ChildStdout>>) -> Result<T>,
    ) -> Result<T> {
        check_args(ds, &[snap])?;
        if paths.is_empty() || !paths.iter().all(|p| crate::valid_rel_path(p)) {
            bail!("read: invalid path list");
        }
        let cmd = format!("read {ds} {snap}");
        let (mut child, out, err) = self.spawn(&cmd, true)?;
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            let mut w = std::io::BufWriter::new(&mut stdin);
            for p in paths {
                w.write_all(&p)?;
                w.write_all(&[0])?;
            }
            w.flush()
        });
        let mut tar = stream::Reader::new(BufReader::with_capacity(1 << 20, out));
        let res = f(&mut tar).and_then(|v| tar.finish(1 << 20).map(|_| v));
        self.received += tar.bytes;
        if res.is_err() {
            let _ = child.kill();
        }
        let wrote = writer.join();
        let done = finish(&cmd, child, err);
        match (res, done) {
            // the remote error (e.g. a refused path) explains the broken stream
            (Err(e), Err(d)) => Err(d.context(format!("content stream: {e:#}"))),
            (Err(e), Ok(())) => Err(e.context(format!("{cmd}: invalid content stream"))),
            (Ok(_), Err(d)) => Err(d),
            (Ok(v), Ok(())) if matches!(wrote, Ok(Ok(()))) => Ok(v),
            (Ok(_), Ok(())) => bail!("{cmd}: sending the path list failed"),
        }
    }
}

struct Counted<R> {
    r: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        let n = self.r.read(b)?;
        self.n += n as u64;
        Ok(n)
    }
}
