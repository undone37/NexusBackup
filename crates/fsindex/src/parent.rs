//! The parent side: runs the sandboxed helper, serves its reads from the
//! snapshot, records which chunks each volume's parse read (the per-volume
//! cache key for the next snapshot) and collects the volumes and entries.
//! A helper that dies inside a volume (crash, rlimit) is restarted with that
//! volume marked `failed`; at most [`MAX_RESTARTS`] times.

use crate::proto::{decode_entries, read_frame, write_frame, Config};
use crate::{Entry, Limits, Volume};
use std::collections::{BTreeSet, HashMap};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub const MAX_RESTARTS: usize = 3;

/// The snapshot's disks, as the parent reads them (from the chunk store).
pub trait Source {
    /// index names, in micro-VM attach order
    fn names(&self) -> Vec<String>;
    fn size(&self, disk: usize) -> u64;
    /// bytes per chunk of the disk's fixed index (read-set granularity)
    fn chunk_size(&self, disk: usize) -> u64;
    fn read(&mut self, disk: usize, off: u64, buf: &mut [u8]) -> io::Result<()>;
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
}

/// How to run the helper.
#[derive(Clone, Debug)]
pub struct Helper {
    pub bin: std::path::PathBuf,
    /// RLIMIT_AS of the helper
    pub mem_mb: u64,
}

impl Helper {
    pub fn new(bin: &Path) -> Helper {
        Helper {
            bin: bin.to_owned(),
            mem_mb: 2048,
        }
    }
}

enum Run {
    Done,
    /// the helper died with this volume open (key)
    Crashed(String, String),
}

/// Lists all volumes. `reuse(v)`: the caller has an unchanged listing of `v`
/// (answer: skip the parse, `Listed::reused`).
pub fn list(src: &mut dyn Source, helper: &Helper, limits: Limits, reuse: &mut dyn FnMut(&Volume) -> bool) -> io::Result<Vec<Listed>> {
    let mut out: Vec<Listed> = Vec::new();
    let mut known: HashMap<String, usize> = HashMap::new();
    let mut crashed: BTreeSet<String> = BTreeSet::new();
    for attempt in 0..=MAX_RESTARTS {
        match run_once(src, helper, limits, reuse, &mut out, &mut known, &crashed)? {
            Run::Done => return Ok(out),
            Run::Crashed(key, why) => {
                eprintln!("fsindex: helper failed on volume {key}: {why} (attempt {})", attempt + 1);
                if let Some(&i) = known.get(&key) {
                    let l = &mut out[i];
                    l.entries.clear();
                    l.reads.clear();
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

fn run_once(
    src: &mut dyn Source,
    helper: &Helper,
    limits: Limits,
    reuse: &mut dyn FnMut(&Volume) -> bool,
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
        disks: names.iter().enumerate().map(|(i, n)| (n.clone(), src.size(i))).collect(),
        limits,
        cache_bytes: 128 << 20,
    };
    let mut current: Option<usize> = None;
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
                    let v: Volume = serde_json::from_slice(&p)?;
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
                    if !skip {
                        out[i].entries.clear();
                        out[i].reads.clear();
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
                }
                b'Z' => {
                    let v: Volume = serde_json::from_slice(&p)?;
                    let i = *known.get(&v.key).ok_or_else(|| io::Error::other("end of an unknown volume"))?;
                    if v.state.is_empty() {
                        return Err(io::Error::other("volume ended without a state"));
                    }
                    let n = out[i].entries.len() as u64;
                    out[i].volume = Volume { entries: n, ..v };
                    current = None;
                }
                b'Q' => return Ok(Run::Done),
                b'X' => return Err(io::Error::other(format!("fsindex helper: {}", String::from_utf8_lossy(&p)))),
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
            Some(k) if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::UnexpectedEof) => {
                Ok(Run::Crashed(k, status.map_or_else(|e| e.to_string(), |s| s.to_string())))
            }
            _ => Err(e),
        },
    }
}
