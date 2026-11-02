//! Restore of a vStor backup's files back into the vStor (#137 contract step 4, docs/nexusstor-design.md): a new
//! `nexusbackup-restore-*` directory on NexusStor, the snapshot's entries below the chosen path streamed as records
//! (the framing of NexusStor's `files` answer) in batches, finished; aborted on a failure.

use crate::proto::Nst;
use anyhow::{Context, Result};
use base64::Engine;
use plugin_sdk::proto::{Kind, Meta};
use plugin_sdk::{error, Ctx, Source};
use serde_json::{json, Map, Value};
use std::io::Read;

/// File data per records request (NexusStor takes 64 MiB).
const BATCH: u64 = 48 << 20;
/// A file larger than this goes in parts (`"append": true` for the later ones).
const PART: u64 = 32 << 20;

/// What a restore sent: (entries, bytes, entries left out here).
#[derive(Default, Debug, PartialEq)]
pub struct Sent {
    pub entries: u64,
    pub bytes: u64,
    pub skipped: Vec<String>,
}

/// The header of one record; None for entry kinds NexusStor does not restore (hard links, devices, ...).
pub fn header(rel: &str, m: &Meta, size: u64, append: bool) -> Option<Value> {
    let ty = match m.kind.unwrap_or(Kind::File) {
        Kind::File => "file",
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        _ => return None,
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut xattrs = Map::new();
    let mut acl = None;
    for (k, v) in &m.xattrs {
        match std::str::from_utf8(k) {
            Ok("system.nfs4_acl") => acl = Some(b64.encode(v)),
            Ok(k) if k.starts_with("user.") => {
                xattrs.insert(k.to_owned(), json!(b64.encode(v)));
            }
            _ => {}
        }
    }
    let mut h = json!({
        "path": rel, "type": ty, "mode": m.mode & 0o7777, "size": size,
        "mtime": m.mtime_ns.div_euclid(1_000_000_000), "mtime_ns": m.mtime_ns.rem_euclid(1_000_000_000),
    });
    if !xattrs.is_empty() {
        h["xattrs"] = Value::Object(xattrs);
    }
    if let Some(a) = acl {
        h["nfs4_acl"] = json!(a);
    }
    if let Some(t) = &m.link_target {
        h["target"] = json!(String::from_utf8_lossy(t));
    }
    if append {
        h["append"] = json!(true);
    }
    Some(h)
}

/// Sends one batch of records.
type Flush<'a> = Box<dyn FnMut(&[u8]) -> Result<()> + 'a>;

/// Records collected up to [`BATCH`] bytes of file data, then handed to `flush`.
pub struct Batcher<'a> {
    buf: Vec<u8>,
    data: u64,
    flush: Flush<'a>,
    pub sent: Sent,
}

impl<'a> Batcher<'a> {
    pub fn new(flush: impl FnMut(&[u8]) -> Result<()> + 'a) -> Self {
        Batcher {
            buf: Vec::new(),
            data: 0,
            flush: Box::new(flush),
            sent: Sent::default(),
        }
    }

    fn push_record(&mut self, head: &Value, data: &[u8]) -> Result<()> {
        if self.data + data.len() as u64 > BATCH && !self.buf.is_empty() {
            self.flush_now()?;
        }
        self.buf.extend_from_slice(head.to_string().as_bytes());
        self.buf.push(b'\n');
        self.buf.extend_from_slice(data);
        self.data += data.len() as u64;
        Ok(())
    }

    /// One snapshot entry at `rel` (relative to the restore directory), its data from `r`.
    pub fn entry(&mut self, rel: &str, m: &Meta, r: &mut dyn Read) -> Result<()> {
        let is_file = m.kind.unwrap_or(Kind::File) == Kind::File;
        if header(rel, m, 0, false).is_none() {
            self.sent
                .skipped
                .push(format!("{rel}: {:?} entries are not restored into a vStor", m.kind));
            return Ok(());
        }
        if !is_file {
            self.push_record(&header(rel, m, 0, false).unwrap_or_default(), &[])?;
            self.sent.entries += 1;
            return Ok(());
        }
        let mut left = m.size;
        let mut first = true;
        loop {
            let n = left.min(PART);
            let mut part = Vec::with_capacity(n as usize);
            r.take(n).read_to_end(&mut part)?;
            anyhow::ensure!(
                part.len() as u64 == n,
                "{rel}: {} of {n} bytes read from the snapshot",
                part.len()
            );
            let head = header(rel, m, n, !first).context("file header")?;
            self.push_record(&head, &part)?;
            self.sent.bytes += n;
            left -= n;
            first = false;
            if left == 0 {
                break;
            }
        }
        self.sent.entries += 1;
        Ok(())
    }

    fn flush_now(&mut self) -> Result<()> {
        if !self.buf.is_empty() {
            (self.flush)(&self.buf)?;
        }
        self.buf.clear();
        self.data = 0;
        Ok(())
    }

    pub fn finish(mut self) -> Result<Sent> {
        self.flush_now()?;
        Ok(self.sent)
    }
}

/// `path` (a path of the snapshot, `data` by default) -> (the vStor directory the restore directory goes into, the
/// prefix stripped from the entries): `data/projects` -> (`data`, `data/`), `data` -> (`data`, `data/`).
pub fn placement(path: &str) -> (String, String) {
    match path.rsplit_once('/') {
        Some((parent, _)) => (parent.to_owned(), format!("{parent}/")),
        None => (path.to_owned(), format!("{path}/")),
    }
}

/// `to_vstor`: the entries at and below `params.path` into a new `nexusbackup-restore-<into>` directory of the vStor.
pub fn to_vstor(ctx: &Ctx, src: &mut Source, nst: &Nst, vstor: &str) -> Result<String> {
    let p = &ctx.params["params"];
    let path = p["path"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("data")
        .trim_matches('/')
        .to_owned();
    if !plugin_sdk::proto::valid_path(path.as_bytes())
        || !(path == "data" || path.starts_with("data/") || path == "s3" || path.starts_with("s3/"))
    {
        return Err(error(22, "params.path: data, s3 or a path below them"));
    }
    let snap = ctx.params["snapshot"]["time"].as_u64().unwrap_or_default();
    let suffix = p["into"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map_or_else(|| snap.to_string(), str::to_owned);
    let into = format!("nexusbackup-restore-{suffix}");
    let (dir, strip) = placement(&path);
    let (id, target) = nst.restore_start(vstor, &dir, &into)?;
    ctx.info(format!("restoring {path} into {vstor}:{target}"));
    let res = (|| -> Result<Sent> {
        let mut b = Batcher::new(|body| {
            let r = nst.restore_records(&id, body)?;
            for e in r["errors"].as_array().into_iter().flatten().take(20) {
                ctx.warn(format!("NexusStor: {}", e.as_str().unwrap_or_default()));
            }
            Ok(())
        });
        src.files(&[path.clone().into_bytes()], |item, data| {
            let full = String::from_utf8_lossy(&item.path).into_owned();
            let rel = full.strip_prefix(&strip).unwrap_or(&full);
            if rel.is_empty() || full == path && item.meta.kind == Some(Kind::Dir) && dir == path {
                return Ok(());
            }
            b.entry(rel, &item.meta, data)
        })?;
        b.finish()
    })();
    let sent = match res {
        Ok(s) => s,
        Err(e) => {
            if let Err(a) = nst.restore_abort(&id) {
                ctx.warn(format!("aborting the restore on NexusStor failed: {a:#}"));
            }
            return Err(e);
        }
    };
    for s in sent.skipped.iter().take(20) {
        ctx.warn(s.clone());
    }
    let f = nst.restore_finish(&id)?;
    let failed = f["failed"].as_u64().unwrap_or(0);
    let msg = format!(
        "{} entries ({} bytes) restored into {vstor}:{target}{}{}",
        f["files"].as_u64().unwrap_or(sent.entries),
        f["bytes"].as_u64().unwrap_or(sent.bytes),
        if failed > 0 {
            format!(", {failed} failed on NexusStor (job log)")
        } else {
            String::new()
        },
        if sent.skipped.is_empty() {
            String::new()
        } else {
            format!(", {} left out (hard links, devices)", sent.skipped.len())
        },
    );
    if failed > 0 {
        return Err(error(5, msg));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(kind: Kind, size: u64) -> Meta {
        Meta {
            kind: Some(kind),
            mode: 0o100644,
            size,
            mtime_ns: 1_700_000_000_123_000_000,
            xattrs: vec![
                (b"user.DOSATTRIB".to_vec(), vec![1, 2]),
                (b"system.nfs4_acl".to_vec(), vec![0, 1]),
                (b"security.selinux".to_vec(), b"x".to_vec()),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn headers() {
        let h = header("projects/a.txt", &meta(Kind::File, 3), 3, false).unwrap();
        assert_eq!(h["type"], "file");
        assert_eq!(h["mode"], 0o644);
        assert_eq!(
            (h["mtime"].as_i64(), h["mtime_ns"].as_i64()),
            (Some(1_700_000_000), Some(123_000_000))
        );
        assert_eq!(h["xattrs"], json!({"user.DOSATTRIB": "AQI="}), "user.* only");
        assert_eq!(h["nfs4_acl"], "AAE=");
        assert!(h.get("append").is_none());
        assert!(header("x", &meta(Kind::Hardlink, 0), 0, false).is_none());
        assert_eq!(placement("data/projects"), ("data".into(), "data/".into()));
        assert_eq!(placement("data"), ("data".into(), "data/".into()));
    }

    /// Batches stay under the limit; a large file goes in parts, the later ones appended.
    #[test]
    fn batches_and_parts() {
        let mut bodies: Vec<Vec<u8>> = Vec::new();
        let mut b = Batcher::new(|body| {
            bodies.push(body.to_vec());
            Ok(())
        });
        let big = PART * 2 + 5;
        b.entry("big.bin", &meta(Kind::File, big), &mut std::io::repeat(7).take(big))
            .unwrap();
        b.entry("d", &meta(Kind::Dir, 0), &mut std::io::empty()).unwrap();
        let sent = b.finish().unwrap();
        assert_eq!((sent.entries, sent.bytes), (2, big));
        assert!(bodies.len() >= 2, "split into requests");
        assert!(bodies.iter().all(|x| x.len() as u64 <= BATCH + (1 << 20)));
        let heads: Vec<Value> = bodies
            .iter()
            .flat_map(|body| {
                let mut out = vec![];
                let mut rest = &body[..];
                while !rest.is_empty() {
                    let nl = rest.iter().position(|c| *c == b'\n').unwrap();
                    let h: Value = serde_json::from_slice(&rest[..nl]).unwrap();
                    let n = h["size"].as_u64().unwrap() as usize;
                    rest = &rest[nl + 1 + n..];
                    out.push(h);
                }
                out
            })
            .collect();
        let parts: Vec<(u64, bool)> = heads
            .iter()
            .filter(|h| h["path"] == "big.bin")
            .map(|h| (h["size"].as_u64().unwrap(), h["append"] == true))
            .collect();
        assert_eq!(parts, vec![(PART, false), (PART, true), (5, true)]);
        assert_eq!(heads.last().unwrap()["type"], "dir");
    }
}
