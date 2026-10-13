//! YARA scan of a snapshot inside the micro-VM (Phase 21e, docs/malware-scan.md).
//! The `yara`/`yarac` CLIs (Debian `yara`, libyara) run here, never on the
//! appliance: hostile files are only parsed in the VM (no network, read-only
//! disks). Rules come from the appliance (admin-supplied, no feed).
//!
//! - `rules`: writes the rule files to /tmp/yara and compiles them with
//!   `yarac` (one namespace per file, so equal rule names do not collide).
//! - `scan`: walks every mounted guest file system (symlinks never followed)
//!   and hands the regular files to `yara --scan-list` in batches.
//! - `scantar`: the appliance streams a tar of a file-tree snapshot (or the
//!   root tar of a container); each batch of files is unpacked into tmpfs
//!   under numbered names, scanned and removed.
//!
//! Limits: files over `max_size` are skipped, `file_timeout` per file
//! (`yara -a`), `threads` scanner threads (`-p`, at most the VM's vCPUs) and
//! an overall `budget`: afterwards `yara` is killed and the report says
//! `complete: false`. `stop_on_match` (scan back, Phase 29: only "is this
//! snapshot clean?" matters) kills `yara` at the first match and ends the
//! scan: `stopped: true`, `complete: false`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DIR: &str = "/tmp/yara";
/// files per `yara` run (the list file stays small)
const BATCH_FILES: usize = 2000;
/// bytes unpacked into tmpfs per run (`scantar`)
const BATCH_BYTES: u64 = 128 << 20;
/// matches kept in a report (all are counted)
pub(crate) const MATCHES_KEPT: usize = 1000;
const MAX_FRAME: u32 = 16 << 20;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub name: String,
    pub text: String,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    pub max_size: u64,
    pub file_timeout: u32,
    /// seconds for the whole scan
    pub budget: u64,
    pub threads: u32,
    /// end the scan at the first match
    #[serde(default)]
    pub stop_on_match: bool,
}

#[derive(Serialize, Debug, PartialEq)]
pub(crate) struct Match {
    pub rule: String,
    pub path: String,
}

#[derive(Serialize, Debug, Default)]
pub(crate) struct Report {
    /// files handed to the scanner
    pub files: u64,
    /// larger than `max_size`
    pub skipped: u64,
    /// unreadable files, names the list format cannot carry, scanner errors
    pub errors: u64,
    pub matches: Vec<Match>,
    pub matches_total: u64,
    /// false: the budget ran out, or stopped at a match
    pub complete: bool,
    /// ended at the first match (`stop_on_match`)
    pub stopped: bool,
    pub seconds: u64,
}

/// Rule file names double as YARA namespaces: no `:` or `/`.
pub(crate) fn valid_rule_name(n: &str) -> bool {
    (1..=64).contains(&n.len())
        && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn rules_file() -> PathBuf {
    Path::new(DIR).join("rules.yarc")
}

/// Writes and compiles the rules; returns the number of files.
pub(crate) fn compile(rules: &[Rule]) -> io::Result<usize> {
    if rules.is_empty() {
        return Err(crate::err("no rules"));
    }
    let _ = fs::remove_dir_all(DIR);
    fs::create_dir_all(Path::new(DIR).join("src"))?;
    let mut args = vec!["-w".to_owned()];
    for r in rules {
        if !valid_rule_name(&r.name) {
            return Err(crate::err(format!("invalid rule file name {:?}", r.name)));
        }
        let p = Path::new(DIR).join("src").join(&r.name);
        fs::write(&p, &r.text)?;
        args.push(format!("{}:{}", r.name, p.display()));
    }
    args.push(rules_file().display().to_string());
    let out = Command::new("yarac").args(&args).output()?;
    if !out.status.success() {
        let e = String::from_utf8_lossy(&out.stderr);
        let e: String = e.trim().chars().take(2000).collect();
        return Err(crate::err(format!("rules do not compile: {e}")));
    }
    Ok(rules.len())
}

/// `namespace:rule path` (yara `-e`) → (rule, path).
pub(crate) fn parse_match(line: &str) -> Option<(&str, &str)> {
    let (rule, path) = line.split_once(' ')?;
    (!rule.is_empty() && !path.is_empty()).then_some((rule, path))
}

pub(crate) struct Scan {
    pub limits: Limits,
    pub deadline: Instant,
    pub started: Instant,
    pub report: Report,
}

impl Scan {
    pub(crate) fn new(limits: Limits) -> Self {
        let now = Instant::now();
        Scan {
            limits,
            deadline: now + Duration::from_secs(limits.budget),
            started: now,
            report: Report {
                complete: true,
                ..Default::default()
            },
        }
    }

    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// Out of budget or stopped at a match: nothing more is scanned
    /// (`complete` turns false).
    fn halted(&mut self) -> bool {
        if self.report.stopped || self.expired() {
            self.report.complete = false;
            return true;
        }
        false
    }

    fn found(&mut self, rule: &str, path: String) {
        if self.limits.stop_on_match {
            self.report.stopped = true;
            self.report.complete = false;
        }
        self.report.matches_total += 1;
        if self.report.matches.len() < MATCHES_KEPT {
            self.report.matches.push(Match {
                rule: rule.to_owned(),
                path,
            });
        }
    }

    /// Runs `yara` over `files` (scan path, reported path); kills it at the deadline.
    fn run(&mut self, files: &[(PathBuf, String)]) -> io::Result<()> {
        if files.is_empty() || self.halted() {
            return Ok(());
        }
        let list = Path::new(DIR).join("list");
        let mut body = Vec::new();
        for (p, _) in files {
            body.extend_from_slice(p.as_os_str().as_encoded_bytes());
            body.push(b'\n');
        }
        fs::write(&list, body)?;
        let back: HashMap<&Path, &str> = files.iter().map(|(p, r)| (p.as_path(), r.as_str())).collect();
        let mut child = Command::new("yara")
            .args(["-C", "-e", "-w", "-N"])
            .args(["-a", &self.limits.file_timeout.to_string()])
            .args(["-p", &self.limits.threads.max(1).to_string()])
            .arg("--scan-list")
            .arg(rules_file())
            .arg(&list)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (out, err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let errs = std::thread::spawn(move || BufReader::new(err).lines().map_while(Result::ok).count() as u64);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(l) => {
                    if let Some((rule, p)) = parse_match(&l) {
                        let path = back.get(Path::new(p)).map_or_else(|| p.to_owned(), |s| s.to_string());
                        self.found(rule, path);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            if self.halted() {
                let _ = child.kill();
                break;
            }
        }
        let _ = child.wait();
        self.report.errors += errs.join().unwrap_or(0);
        self.report.files += files.len() as u64;
        Ok(())
    }

    /// Walks the mounted file systems (`/mnt<mountpoint>`) without following
    /// symlinks and scans the regular files.
    pub(crate) fn mounts(&mut self, mountpoints: &[String]) -> io::Result<()> {
        let mut batch: Vec<(PathBuf, String)> = Vec::new();
        for mp in mountpoints {
            let mut dirs = vec![PathBuf::from(format!("{}{mp}", crate::MNT))];
            while let Some(d) = dirs.pop() {
                if self.halted() {
                    return Ok(());
                }
                let Ok(rd) = fs::read_dir(&d) else {
                    self.report.errors += 1;
                    continue;
                };
                for e in rd.flatten() {
                    let p = e.path();
                    let Ok(md) = fs::symlink_metadata(&p) else {
                        self.report.errors += 1;
                        continue;
                    };
                    if md.is_dir() {
                        dirs.push(p);
                    } else if md.is_file() {
                        if md.len() > self.limits.max_size {
                            self.report.skipped += 1;
                            continue;
                        }
                        let raw = p.as_os_str().as_encoded_bytes();
                        if raw.contains(&b'\n') {
                            self.report.errors += 1; // the list is line-based
                            continue;
                        }
                        let shown = p
                            .to_string_lossy()
                            .strip_prefix(crate::MNT)
                            .unwrap_or_default()
                            .to_owned();
                        batch.push((p, shown));
                        if batch.len() >= BATCH_FILES {
                            self.run(&batch)?;
                            batch.clear();
                        }
                    }
                }
            }
        }
        self.run(&batch)
    }

    /// Scans the regular files of a tar stream (unpacked batch by batch into
    /// tmpfs under numbered names). After the budget the rest is read and dropped.
    pub(crate) fn tar(&mut self, r: impl Read) -> io::Result<()> {
        let tmp = Path::new(DIR).join("batch");
        fs::create_dir_all(&tmp)?;
        let mut batch: Vec<(PathBuf, String)> = Vec::new();
        let mut bytes = 0u64;
        let mut a = tar::Archive::new(r);
        for e in a.entries()? {
            let mut e = e?;
            if self.halted() || e.header().entry_type() != tar::EntryType::Regular {
                continue; // the iterator skips the data
            }
            let size = e.header().size()?;
            if size > self.limits.max_size {
                self.report.skipped += 1;
                continue;
            }
            let shown = String::from_utf8_lossy(&e.path_bytes()).into_owned();
            let p = tmp.join(batch.len().to_string());
            match fs::File::create(&p).and_then(|mut f| io::copy(&mut e, &mut f)) {
                Ok(_) => {}
                Err(_) => {
                    self.report.errors += 1;
                    let _ = fs::remove_file(&p);
                    continue;
                }
            }
            batch.push((p, shown));
            bytes += size;
            if batch.len() >= BATCH_FILES || bytes >= BATCH_BYTES {
                self.run(&batch)?;
                for (p, _) in batch.drain(..) {
                    let _ = fs::remove_file(p);
                }
                bytes = 0;
            }
        }
        self.run(&batch)?;
        let _ = fs::remove_dir_all(&tmp);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Report {
        self.report.seconds = self.started.elapsed().as_secs();
        self.report
    }
}

/// Decodes `[u32 BE len][bytes]` frames from the appliance; a zero-length
/// frame ends the stream.
pub(crate) struct FrameReader<R> {
    pub r: R,
    pub left: u32,
    pub done: bool,
}

impl<R: Read> Read for FrameReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut len = [0u8; 4];
            self.r.read_exact(&mut len)?;
            self.left = u32::from_be_bytes(len);
            if self.left == 0 {
                self.done = true;
                return Ok(0);
            }
            if self.left > MAX_FRAME {
                return Err(crate::err("frame too large"));
            }
        }
        let n = buf.len().min(self.left as usize);
        let n = self.r.read(&mut buf[..n])?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.left -= n as u32;
        Ok(n)
    }
}

impl<R: Read> FrameReader<R> {
    /// Reads to the end frame (after an error: keeps the protocol in sync).
    pub(crate) fn drain(&mut self) -> io::Result<()> {
        io::copy(self, &mut io::sink()).map(|_| ())
    }
}

/// `scantar`: answers `{"ok":"send"}`, reads the framed tar, replies with the report.
pub(crate) fn serve_tar(r: &mut impl BufRead, w: &mut impl Write, limits: Limits) -> io::Result<serde_json::Value> {
    crate::send_line(w, &serde_json::json!({"ok": "send"}))?;
    let mut fr = FrameReader {
        r,
        left: 0,
        done: false,
    };
    let mut s = Scan::new(limits);
    let res = s.tar(&mut fr);
    fr.drain()?;
    res?;
    Ok(serde_json::to_value(s.finish())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_names() {
        for ok in ["ransom.yar", "a", "x-1_2.yara"] {
            assert!(valid_rule_name(ok), "{ok}");
        }
        for bad in ["", ".hidden", "a:b", "a/b", "a b", &"x".repeat(65)] {
            assert!(!valid_rule_name(bad), "{bad}");
        }
    }

    #[test]
    fn match_lines() {
        assert_eq!(
            parse_match("r.yar:EICAR /vda1/home/a b.txt"),
            Some(("r.yar:EICAR", "/vda1/home/a b.txt"))
        );
        assert_eq!(parse_match("nothing"), None);
        assert_eq!(parse_match(" /x"), None);
    }

    #[test]
    fn frames_end_and_limit() {
        let wire = [
            &2u32.to_be_bytes()[..],
            b"ab",
            &1u32.to_be_bytes(),
            b"c",
            &0u32.to_be_bytes(),
            b"next",
        ]
        .concat();
        let mut fr = FrameReader {
            r: &wire[..],
            left: 0,
            done: false,
        };
        let mut v = Vec::new();
        fr.read_to_end(&mut v).unwrap();
        assert_eq!(v, b"abc");
        assert_eq!(fr.r, b"next");
        let huge = (MAX_FRAME + 1).to_be_bytes();
        let mut fr = FrameReader {
            r: &huge[..],
            left: 0,
            done: false,
        };
        assert!(fr.read(&mut [0u8; 8]).is_err());
        // drain after a partial read keeps the stream in sync
        let mut fr = FrameReader {
            r: &wire[..],
            left: 0,
            done: false,
        };
        fr.read_exact(&mut [0u8; 1]).unwrap();
        fr.drain().unwrap();
        assert_eq!(fr.r, b"next");
    }

    #[test]
    fn expired_budget_marks_incomplete() {
        let mut s = Scan::new(Limits {
            max_size: 10,
            file_timeout: 1,
            budget: 0,
            threads: 1,
            stop_on_match: false,
        });
        s.run(&[(PathBuf::from("/nonexistent"), "x".into())]).unwrap();
        let r = s.finish();
        assert!(!r.complete);
        assert!(!r.stopped);
        assert_eq!(r.files, 0);
    }

    /// stop_on_match: the first match ends the scan; later batches are not run.
    /// Without it every match is collected and the scan goes on.
    #[test]
    fn stop_on_match_ends_the_scan() {
        let limits = |stop_on_match| Limits {
            max_size: 10,
            file_timeout: 1,
            budget: 3600,
            threads: 1,
            stop_on_match,
        };
        let mut s = Scan::new(limits(true));
        s.found("r:X", "/a".into());
        s.run(&[(PathBuf::from("/nonexistent"), "x".into())]).unwrap();
        let r = s.finish();
        assert!(r.stopped && !r.complete);
        assert_eq!((r.matches_total, r.files), (1, 0));
        let mut s = Scan::new(limits(false));
        s.found("r:X", "/a".into());
        s.found("r:X", "/b".into());
        assert!(!s.halted());
        let r = s.finish();
        assert!(!r.stopped && r.complete);
        assert_eq!(r.matches_total, 2);
        // the appliance sends the field only for scan back: absent = false
        let l: Limits = serde_json::from_str(r#"{"max_size":1,"file_timeout":1,"budget":1,"threads":1}"#).unwrap();
        assert!(!l.stop_on_match);
    }
}
