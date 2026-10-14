//! The parent side: runs the sandboxed helper, serves its reads from the
//! snapshot, records which chunks each volume's parse read (the per-volume
//! cache key for the next snapshot) and collects the volumes and entries.
//! A helper that dies inside a volume (crash, rlimit) is restarted with that
//! volume marked `failed`; at most [`MAX_RESTARTS`] times.
//!
//! Phase 32: with `Helper::parts` > 1, that many helpers (each single-threaded
//! and sandboxed as before) walk the NTFS / ext4 volumes together, each its
//! share of the directory trees ([`crate::Part`]); the parent serves them on one
//! thread each, so chunks are read and decrypted in parallel, and merges their
//! listings. Other file systems are listed by helper 0 alone.

use crate::proto::{decode_entries, read_frame, write_frame, Config};

use crate::Part;
use crate::{DirRec, Entry, Limits, Volume};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub const MAX_RESTARTS: usize = 3;

/// The snapshot's disks, as the parent reads them (from the chunk store);
/// shared by the helpers of one listing (Phase 32), so `read` takes `&self`.
pub trait Source: Sync {
    /// index names, in micro-VM attach order
    fn names(&self) -> Vec<String>;
    fn size(&self, disk: usize) -> u64;
    /// bytes per chunk of the disk's fixed index (read-set granularity)
    fn chunk_size(&self, disk: usize) -> u64;
    fn read(&self, disk: usize, off: u64, buf: &mut [u8]) -> io::Result<()>;
    /// Phase 31c: directory `rel` of volume `key` as the previous snapshot listed
    /// it, if nothing its listing read changed since: (its entries, its record with
    /// `deps` in this snapshot's disk numbers). `None`: list it.
    fn dir(&self, _key: &str, _rel: &str) -> Option<(Vec<Entry>, DirRec)> {
        None
    }
}

/// One volume of the listing.
#[derive(Debug, Default)]
pub struct Listed {
    pub volume: Volume,
    pub entries: Vec<Entry>,
    /// (disk, chunk index) the parse read
    pub reads: BTreeSet<(usize, u64)>,
    /// not parsed: the caller fills it from its cache
    pub reused: bool,
    /// Phase 31c: the directories of the parse (listed or taken over), for the next snapshot
    pub dirs: Vec<DirRec>,
}

/// How to run the helper.
#[derive(Clone, Debug)]
pub struct Helper {
    pub bin: std::path::PathBuf,
    /// RLIMIT_AS of the helper
    pub mem_mb: u64,
    /// helpers walking one NTFS / ext4 volume together (1 = one helper)
    pub parts: u32,
}

impl Helper {
    pub fn new(bin: &Path) -> Helper {
        Helper {
            bin: bin.to_owned(),
            mem_mb: 2048,
            parts: 1,
        }
    }
}

/// File systems whose trees the helpers split ([`crate::Part`]).
fn split(fs: &str) -> bool {
    fs == "ntfs" || fs == "ext4"
}

enum Run {
    Done,
    /// the helper died with this volume open (key)
    Crashed(String, String),
}

/// Lists all volumes. `reuse(v)`: the caller has an unchanged listing of `v`
/// (answer: skip the parse, `Listed::reused`).
pub fn list(
    src: &dyn Source,
    helper: &Helper,
    limits: Limits,
    reuse: &mut (dyn FnMut(&Volume) -> bool + Send),
) -> io::Result<Vec<Listed>> {
    list_with_progress(src, helper, limits, reuse, &mut |_, _, _| {})
}

/// [`list`] with live progress: `progress(volume, entries so far, the walker's
/// estimate)` while a volume is parsed (after each batch of entries; the
/// caller throttles).
pub fn list_with_progress(
    src: &dyn Source,
    helper: &Helper,
    limits: Limits,
    reuse: &mut (dyn FnMut(&Volume) -> bool + Send),
    progress: &mut (dyn FnMut(&Volume, u64, Option<u64>) + Send),
) -> io::Result<Vec<Listed>> {
    let k = helper.parts.max(1);
    if k == 1 {
        return list_part(src, helper, limits, reuse, progress);
    }
    let reuse = Mutex::new(reuse);
    let progress = Mutex::new(progress);
    // entries so far per (volume, part): progress reports their sum
    let counts: Mutex<HashMap<(String, u32), u64>> = Mutex::new(HashMap::new());
    let parts: Vec<io::Result<Vec<Listed>>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..k)
            .map(|i| {
                let (reuse, progress, counts) = (&reuse, &progress, &counts);
                s.spawn(move || {
                    let lim = Limits {
                        part: Part { index: i, count: k },
                        ..limits
                    };
                    // helpers 1.. leave everything but NTFS / ext4 to helper 0
                    let mut re = |v: &Volume| (i > 0 && !split(&v.fs)) || (reuse.lock().unwrap())(v);
                    let mut pr = |v: &Volume, n: u64, e: Option<u64>| {
                        let sum = {
                            let mut c = counts.lock().unwrap();
                            c.insert((v.key.clone(), i), n);
                            c.iter().filter(|((key, _), _)| *key == v.key).map(|(_, n)| n).sum()
                        };
                        (progress.lock().unwrap())(v, sum, e);
                    };
                    list_part(src, helper, lim, &mut re, &mut pr)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(io::Error::other("a listing thread panicked")))
            })
            .collect()
    });
    let mut parts = parts.into_iter();
    let mut out = parts.next().expect("at least one part")?;
    for p in parts {
        merge(&mut out, p?);
    }
    Ok(out)
}

/// Adds the NTFS / ext4 volumes of another helper's share to helper 0's listing.
fn merge(out: &mut [Listed], part: Vec<Listed>) {
    let rank = |s: &str| match s {
        "failed" => 3,
        "partial" => 2,
        "indexed" => 1,
        _ => 0,
    };
    for p in part.into_iter().filter(|p| !p.reused && split(&p.volume.fs)) {
        let Some(l) = out.iter_mut().find(|l| l.volume.key == p.volume.key) else {
            continue; // helper 0 found no such volume: nothing to add to
        };
        if l.reused {
            continue;
        }
        if rank(&p.volume.state) > rank(&l.volume.state) {
            l.volume.state = p.volume.state.clone();
            l.volume.reason = p.volume.reason.clone();
        }
        l.volume.windows |= p.volume.windows;
        l.volume.dedup_files += p.volume.dedup_files;
        l.volume.skipped_entries += p.volume.skipped_entries;
        l.reads.extend(p.reads);
        l.entries.extend(p.entries);
        l.dirs.extend(p.dirs);
        if l.volume.state == "failed" {
            l.entries.clear();
            l.reads.clear();
            l.dirs.clear();
        }
        // deterministic, whatever share finished first
        l.entries.sort_by(|a, b| a.path.cmp(&b.path));
        l.volume.entries = l.entries.len() as u64;
    }
}

/// One helper's listing (with restarts after crashes).
fn list_part(
    src: &dyn Source,
    helper: &Helper,
    limits: Limits,
    reuse: &mut (dyn FnMut(&Volume) -> bool + Send),
    progress: &mut (dyn FnMut(&Volume, u64, Option<u64>) + Send),
) -> io::Result<Vec<Listed>> {
    let mut out: Vec<Listed> = Vec::new();
    let mut known: HashMap<String, usize> = HashMap::new();
    let mut crashed: BTreeSet<String> = BTreeSet::new();
    for attempt in 0..=MAX_RESTARTS {
        match run_once(src, helper, limits, reuse, progress, &mut out, &mut known, &crashed)? {
            Run::Done => return Ok(out),
            Run::Crashed(key, why) => {
                eprintln!(
                    "fsindex: helper failed on volume {key}: {why} (attempt {})",
                    attempt + 1
                );
                if let Some(&i) = known.get(&key) {
                    let l = &mut out[i];
                    l.entries.clear();
                    l.reads.clear();
                    l.dirs.clear();
                    l.volume.entries = 0;
                    l.volume.state = "failed".into();
                    l.volume.reason = Some(format!("{} parser failed on this volume ({why})", l.volume.fs));
                }
                crashed.insert(key);
            }
        }
    }
    Err(io::Error::other("the file system helper failed repeatedly"))
}

#[allow(clippy::too_many_arguments)]
fn run_once(
    src: &dyn Source,
    helper: &Helper,
    limits: Limits,
    reuse: &mut (dyn FnMut(&Volume) -> bool + Send),
    progress: &mut (dyn FnMut(&Volume, u64, Option<u64>) + Send),
    out: &mut Vec<Listed>,
    known: &mut HashMap<String, usize>,
    crashed: &BTreeSet<String>,
) -> io::Result<Run> {
    let names = src.names();
    let mut child = Command::new(&helper.bin)
        .arg("--helper")
        .arg("--mem-mb")
        .arg(helper.mem_mb.to_string())
        .arg("--cpu-secs")
        .arg((limits.budget_secs + 120).to_string())
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", helper.bin.display())))?;
    let mut w = BufWriter::new(child.stdin.take().unwrap());
    let mut r = BufReader::with_capacity(1 << 20, child.stdout.take().unwrap());
    let cfg = Config {
        disks: names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.clone(), src.size(i)))
            .collect(),
        limits,
        cache_bytes: 128 << 20,
    };
    let mut current: Option<usize> = None;
    let mut expect: Option<u64> = None;
    let mut total = 0u64;
    let result = (|| -> io::Result<Run> {
        write_frame(&mut w, b'C', &serde_json::to_vec(&cfg)?)?;
        w.flush()?;
        let mut buf = Vec::new();
        loop {
            let (tag, p) = match read_frame(&mut r) {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    return match current.map(|i| out[i].volume.key.clone()) {
                        Some(k) => Ok(Run::Crashed(k, "helper exited".into())),
                        None => Err(io::Error::other("the file system helper exited early")),
                    };
                }
                Err(e) => return Err(e),
            };
            match tag {
                b'R' if p.len() == 16 => {
                    let disk = u32::from_le_bytes(p[0..4].try_into().unwrap()) as usize;
                    let off = u64::from_le_bytes(p[4..12].try_into().unwrap());
                    let len = u32::from_le_bytes(p[12..16].try_into().unwrap()) as u64;
                    let ok = disk < names.len()
                        && len > 0
                        && len <= crate::proto::MAX_READ as u64
                        && off.checked_add(len).is_some_and(|e| e <= src.size(disk));
                    if !ok {
                        write_frame(&mut w, b'F', b"read outside the disk")?;
                    } else {
                        buf.resize(len as usize, 0);
                        match src.read(disk, off, &mut buf) {
                            Ok(()) => {
                                if let Some(i) = current {
                                    let cs = src.chunk_size(disk).max(1);
                                    for c in off / cs..=(off + len - 1) / cs {
                                        out[i].reads.insert((disk, c));
                                    }
                                }
                                write_frame(&mut w, b'D', &buf)?;
                            }
                            Err(e) => write_frame(&mut w, b'F', e.to_string().as_bytes())?,
                        }
                    }
                    w.flush()?;
                }
                b'B' => {
                    let v: Volume = crate::proto::parse_volume(&p)?;
                    let parseable = v.state.is_empty();
                    let i = match known.get(&v.key) {
                        Some(&i) => i,
                        None => {
                            out.push(Listed {
                                volume: v.clone(),
                                ..Default::default()
                            });
                            known.insert(v.key.clone(), out.len() - 1);
                            out.len() - 1
                        }
                    };
                    // already listed by an earlier helper run, crashed before, or cached
                    let done_before = !out[i].volume.state.is_empty() && parseable;
                    let skip = parseable && (done_before || crashed.contains(&v.key) || out[i].reused || reuse(&v));
                    if skip && !done_before && !crashed.contains(&v.key) {
                        out[i].reused = true;
                    }
                    write_frame(&mut w, b'A', &[u8::from(!skip)])?;
                    w.flush()?;
                    current = (!skip).then_some(i);
                    expect = None;
                    if !skip {
                        out[i].entries.clear();
                        out[i].reads.clear();
                        out[i].dirs.clear();
                        progress(&out[i].volume, 0, None);
                    }
                }
                b'E' => {
                    let i = current.ok_or_else(|| io::Error::other("entries outside a volume"))?;
                    let before = out[i].entries.len();
                    decode_entries(&p, &mut out[i].entries)?;
                    total += (out[i].entries.len() - before) as u64;
                    if total > limits.max_entries + 1 {
                        return Err(io::Error::other("the helper sent more entries than allowed"));
                    }
                    progress(&out[i].volume, out[i].entries.len() as u64, expect);
                }
                b'U' => {
                    // Phase 31c: may the helper take directory `rel` over from the previous snapshot?
                    let i = current.ok_or_else(|| io::Error::other("directory query outside a volume"))?;
                    #[derive(serde::Deserialize)]
                    struct Q {
                        rel: String,
                        own: bool,
                        #[serde(default)]
                        layout: String,
                    }
                    let q: Q =
                        serde_json::from_slice(&p).map_err(|e| io::Error::other(format!("directory query: {e}")))?;
                    // only with the same volume layout (a moved MFT moves the records a read set names)
                    let hit = src
                        .dir(&out[i].volume.key, &q.rel)
                        .filter(|(_, r)| !q.layout.is_empty() && r.layout == q.layout);
                    match hit {
                        Some((entries, rec)) => {
                            write_frame(&mut w, b'Y', &serde_json::to_vec(&rec.subdirs)?)?;
                            if q.own {
                                total += entries.len() as u64;
                                out[i].entries.extend(entries);
                                out[i].volume.dedup_files += rec.dedup;
                                out[i].volume.skipped_entries += rec.skipped;
                                out[i].dirs.push(rec);
                                progress(&out[i].volume, out[i].entries.len() as u64, expect);
                            }
                        }
                        None => write_frame(&mut w, b'N', &[])?,
                    }
                    w.flush()?;
                }
                b'L' => {
                    // Phase 31c: an owned directory was listed: its record with the chunks it read
                    let i = current.ok_or_else(|| io::Error::other("directory record outside a volume"))?;
                    #[derive(serde::Deserialize)]
                    struct K {
                        rec: DirRec,
                        blocks: Vec<(usize, u64)>,
                    }
                    let k: K =
                        serde_json::from_slice(&p).map_err(|e| io::Error::other(format!("directory record: {e}")))?;
                    let mut deps: Vec<(u32, u64)> = k
                        .blocks
                        .iter()
                        .filter(|(d, _)| *d < names.len())
                        .map(|&(d, b)| (d as u32, b * crate::proto::BLOCK / src.chunk_size(d).max(1)))
                        .collect();
                    deps.sort_unstable();
                    deps.dedup();
                    out[i].dirs.push(DirRec { deps, ..k.rec });
                }
                b'P' if p.len() == 8 => {
                    let i = current.ok_or_else(|| io::Error::other("estimate outside a volume"))?;
                    expect = Some(u64::from_le_bytes(p[..8].try_into().unwrap()));
                    progress(&out[i].volume, out[i].entries.len() as u64, expect);
                }
                b'Z' => {
                    let v: Volume = crate::proto::parse_volume(&p)?;
                    let i = *known
                        .get(&v.key)
                        .ok_or_else(|| io::Error::other("end of an unknown volume"))?;
                    if v.state.is_empty() {
                        return Err(io::Error::other("volume ended without a state"));
                    }
                    let n = out[i].entries.len() as u64;
                    out[i].volume = Volume { entries: n, ..v };
                    current = None;
                }
                b'Q' => return Ok(Run::Done),
                b'X' => {
                    return Err(io::Error::other(format!(
                        "fsindex helper: {}",
                        String::from_utf8_lossy(&p)
                    )))
                }
                _ => return Err(io::Error::other(format!("unexpected frame {tag:#x} from the helper"))),
            }
        }
    })();
    drop(w);
    drop(r);
    let status = child.wait();
    match result {
        Ok(Run::Crashed(k, _)) => Ok(Run::Crashed(
            k,
            status.map_or_else(|e| e.to_string(), |s| s.to_string()),
        )),
        Ok(Run::Done) => {
            let s = status?;
            if !s.success() {
                return Err(io::Error::other(format!("the file system helper ended with {s}")));
            }
            Ok(Run::Done)
        }
        Err(e) => match current.map(|i| out[i].volume.key.clone()) {
            // a broken pipe inside a volume: the helper died there
            Some(k) if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof) => Ok(
                Run::Crashed(k, status.map_or_else(|e| e.to_string(), |s| s.to_string())),
            ),
            _ => Err(e),
        },
    }
}
