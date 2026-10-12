//! Validate, ListGuests and Mount.

use crate::backup::{msg_name, LogSink};
use crate::restore::Snapshot;
use crate::sandbox::Peer;
use crate::{escape, level_name};
use anyhow::{bail, Result};
use chunkstore::{ChunkId, Store, TreeKind};
use plugin_proto::{valid_guest_id, BaseInfo, Message, Op, TaggedGuest, API};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct Params<'a> {
    pub job: u64,
    pub kind: &'a str,
    pub config: &'a str,
}

fn init(p: &Params, op: Op, params: Value, base: Option<BaseInfo>, state: Option<Vec<u8>>) -> Message {
    Message::Init {
        api: API,
        job: p.job,
        kind: p.kind.to_owned(),
        op,
        config: p.config.to_owned(),
        params: params.to_string(),
        base,
        state,
    }
}

/// Connectivity + permission check. Result: `{"valid": true}` or `{"valid": false, "field", "message"}`.
pub fn validate(peer: &mut dyn Peer, p: &Params, out: &mut dyn FnMut(&str)) -> Result<Value> {
    peer.send(&init(p, Op::Validate, json!({}), None, None))?;
    loop {
        match peer.recv()? {
            Message::Log { level, text } => out(&format!("plugin[{}]: {}", level_name(level), escape(&text, 4000))),
            Message::Progress { .. } => {}
            Message::Valid => {
                peer.finish();
                return Ok(json!({"valid": true}));
            }
            Message::Invalid { field, message } => {
                peer.finish();
                return Ok(json!({"valid": false, "field": escape(&field, 200), "message": escape(&message, 2000)}));
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {} during validate", msg_name(&other)))),
        }
    }
}

/// Guests (e.g. databases). Invalid ids are dropped with a log line. Result: `{"guests": [...]}`.
pub fn guests(peer: &mut dyn Peer, p: &Params, out: &mut dyn FnMut(&str)) -> Result<Value> {
    peer.send(&init(p, Op::ListGuests, json!({}), None, None))?;
    loop {
        match peer.recv()? {
            Message::Log { level, text } => out(&format!("plugin[{}]: {}", level_name(level), escape(&text, 4000))),
            Message::Progress { .. } => {}
            m @ (Message::Guests { .. } | Message::TaggedGuests { .. }) => {
                peer.finish();
                let list: Vec<TaggedGuest> = match m {
                    Message::Guests { list } => list.into_iter().map(TaggedGuest::from).collect(),
                    Message::TaggedGuests { list } => list,
                    _ => unreachable!(),
                };
                if list.len() > 10_000 {
                    bail!("plugin listed more than 10000 guests");
                }
                let mut seen = std::collections::HashSet::new();
                let mut ok: Vec<Value> = Vec::new();
                for TaggedGuest { id, title, size, tags } in list {
                    if !valid_guest_id(&id) || !seen.insert(id.clone()) {
                        out(&format!(
                            "plugin: guest id {} dropped (invalid or duplicate)",
                            escape(&id, 80)
                        ));
                        continue;
                    }
                    // tags (v1.5): printable, trimmed; others are dropped (escaping would change them)
                    let tags: Vec<String> = tags
                        .into_iter()
                        .filter(|t| !t.is_empty() && escape(t, 128) == *t && t.trim() == t)
                        .collect();
                    ok.push(json!({"id": id, "title": escape(&title, 200), "size": size, "tags": tags}));
                }
                return Ok(json!({ "guests": ok }));
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {} during list guests", msg_name(&other)))),
        }
    }
}

/// Random access to the files of a snapshot (chunk offsets computed on first use).
struct Reader<'a> {
    store: &'a Store,
    offsets: HashMap<Vec<u8>, Vec<u64>>,
    cached: Option<(ChunkId, Vec<u8>)>,
}

impl Reader<'_> {
    fn chunk(&mut self, id: &ChunkId) -> Result<&[u8]> {
        if self.cached.as_ref().is_none_or(|(c, _)| c != id) {
            self.cached = Some((*id, self.store.read_chunk(id)?));
        }
        Ok(&self.cached.as_ref().unwrap().1)
    }

    fn read(&mut self, e: &chunkstore::TreeEntry, off: u64, len: u32) -> Result<Vec<u8>> {
        if !self.offsets.contains_key(&e.path) {
            let mut v = Vec::with_capacity(e.chunks.len() + 1);
            let mut pos = 0u64;
            v.push(0);
            for c in &e.chunks {
                pos += self.chunk(c)?.len() as u64;
                v.push(pos);
            }
            self.offsets.insert(e.path.clone(), v);
        }
        let offs = self.offsets[&e.path].clone();
        let end = (off.saturating_add(u64::from(len))).min(*offs.last().unwrap_or(&0));
        let mut out = Vec::new();
        let mut pos = off;
        while pos < end {
            let i = offs.partition_point(|&o| o <= pos) - 1;
            let data = self.chunk(&e.chunks[i])?;
            let a = (pos - offs[i]) as usize;
            let b = ((end - offs[i]) as usize).min(data.len());
            out.extend_from_slice(&data[a..b]);
            pos = offs[i] + b as u64;
        }
        Ok(out)
    }
}

/// Mount: the plugin presents the snapshot (e.g. a temporary read-only instance) and
/// reads files on demand until the time is up; then the host sends `Unmount`.
/// Result: `{"info": …, "reads": n, "bytes": n, "summary": …}`.
pub fn mount(
    store: &Store,
    peer: &mut dyn Peer,
    snap: &Snapshot,
    p: &Params,
    params: Value,
    duration: Duration,
    out: &mut dyn FnMut(&str),
) -> Result<Value> {
    peer.send(&init(
        p,
        Op::Mount,
        snap.init_params(json!({"params": params, "minutes": duration.as_secs() / 60})),
        Some(BaseInfo { time: snap.time }),
        snap.state.clone(),
    ))?;
    let mut log = LogSink {
        out,
        left: 4 << 20,
        last_progress: None,
    };
    let mut reader = Reader {
        store,
        offsets: HashMap::new(),
        cached: None,
    };
    let mut info = None;
    let (mut reads, mut bytes) = (0u64, 0u64);
    let mut until: Option<Instant> = None;
    let mut unmounted = false;
    loop {
        let m = match (until, unmounted) {
            (Some(u), false) => {
                // mounted: the plugin may be quiet until the end of the mount time
                let now = Instant::now();
                if now >= u {
                    peer.send(&Message::Unmount)?;
                    unmounted = true;
                    peer.set_idle(Some(Duration::from_secs(120)));
                    continue;
                }
                match peer.poll(u - now)? {
                    Some(m) => m,
                    None => continue,
                }
            }
            _ => peer.recv()?,
        };
        match m {
            Message::Log { level, text } => log.log(level, &text),
            Message::Progress { done, total, text } => log.progress(done, total, &text),
            Message::MountReady { info: i } if info.is_none() => {
                let i = escape(&i, 4000);
                (log.out)(&format!(
                    "mount-ready {}",
                    json!({"info": i, "minutes": duration.as_secs() / 60})
                ));
                info = Some(i);
                until = Some(Instant::now() + duration);
            }
            Message::ReadFile { path, offset, len } if info.is_some() => {
                match snap.file(&path).filter(|e| e.kind == TreeKind::File) {
                    Some(e) => {
                        let data = reader.read(e, offset, len)?;
                        reads += 1;
                        bytes += data.len() as u64;
                        peer.send(&Message::FileData { bytes: data })?;
                    }
                    None => peer.send(&Message::Error {
                        code: 2,
                        message: "no such file in the snapshot".into(),
                    })?,
                }
            }
            Message::Done { summary, .. } => {
                peer.finish();
                return Ok(json!({"info": info, "reads": reads, "bytes": bytes, "summary": escape(&summary, 4000)}));
            }
            Message::Error { code, message } => {
                peer.finish();
                bail!("plugin reported an error ({code}): {}", escape(&message, 2000));
            }
            other => return Err(peer.violation(&format!("unexpected message {} during mount", msg_name(&other)))),
        }
    }
}
