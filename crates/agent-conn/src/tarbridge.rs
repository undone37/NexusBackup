//! VM/CT files onto an agent: `nexus-pve files|ct-files … get <x.tar>` (restore
//! micro-VM, or the container's tar stream) writes the selected paths as a tar into
//! the downloads directory; this bridge turns that tar into the restore protocol
//! (`crate::restore`): pass 1 builds the entries (data cut into `MAX_CHUNK` pieces,
//! plain BLAKE3 per piece), pass 2 sends each batch's entries and then re-reads the
//! archive for their data. Owners are never mapped (another host by definition).
//!
//! Supported: regular files, directories, symlinks, hard links (to entries of the
//! same archive), FIFOs, long names (GNU/PAX). Skipped: devices, sockets, names with
//! `..`, anything below an earlier symlink. Sparse files arrive fully allocated;
//! xattrs/ACLs are not in the archive (the download tar has none either).

use crate::restore::{batches, begin, end, send_chunk, Skipped, Spec, Target};
use crate::tls::Session;
use crate::valid_rel_path;
use agent_proto::{Entry, Hash, Kind, Message, ScanStats, MAX_CHUNK};
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use tar::EntryType;

/// `./a/b/`, `/a/b` → `a/b`; "" for the root; None for unsafe names.
fn norm(raw: &[u8]) -> Option<Vec<u8>> {
    let mut p = raw;
    loop {
        match p {
            [b'/', r @ ..] => p = r,
            [b'.', b'/', r @ ..] => p = r,
            _ => break,
        }
    }
    while let [r @ .., b'/'] = p {
        p = r;
    }
    if p.is_empty() || p == b"." {
        return Some(Vec::new());
    }
    valid_rel_path(p).then(|| p.to_vec())
}

/// Fills `buf` from `r` up to its length; returns the bytes read (short only at EOF).
fn fill(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Pass 1: the restorable entries of the archive with their position (ordinal)
/// in it, adapted for `target`.
pub fn scan(r: impl Read, target: &Target, sk: &mut Skipped) -> Result<Vec<(usize, Entry)>> {
    let mut out = Vec::new();
    let mut links: Vec<Vec<u8>> = Vec::new();
    let mut buf = vec![0u8; MAX_CHUNK];
    let mut ar = tar::Archive::new(r);
    for (i, e) in ar.entries()?.enumerate() {
        let mut e = e?;
        let Some(path) = norm(&e.path_bytes()) else {
            sk.entries += 1;
            continue;
        };
        if path.is_empty() {
            continue; // the archive root is the target directory
        }
        if links
            .iter()
            .any(|l| path.starts_with(l) && path.get(l.len()) == Some(&b'/'))
        {
            sk.entries += 1; // would be written through a symlink
            continue;
        }
        let h = e.header().clone();
        let kind = match h.entry_type() {
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => Kind::File,
            EntryType::Directory => Kind::Dir,
            EntryType::Symlink => Kind::Symlink,
            EntryType::Link => Kind::Hardlink,
            EntryType::Fifo => Kind::Fifo,
            EntryType::Char | EntryType::Block => Kind::Device,
            _ => {
                sk.entries += 1;
                continue;
            }
        };
        let link_target = match kind {
            Kind::Symlink => Some(e.link_name_bytes().context("symlink without target")?.into_owned()),
            Kind::Hardlink => match e.link_name_bytes().and_then(|l| norm(&l)).filter(|l| !l.is_empty()) {
                Some(l) => Some(l),
                None => {
                    sk.entries += 1;
                    continue;
                }
            },
            _ => None,
        };
        let mut chunks: Vec<(Hash, u32)> = Vec::new();
        let mut size = 0u64;
        if kind == Kind::File {
            loop {
                let n = fill(&mut e, &mut buf)?;
                if n == 0 {
                    break;
                }
                chunks.push((*blake3::hash(&buf[..n]).as_bytes(), n as u32));
                size += n as u64;
            }
        }
        if kind == Kind::Symlink {
            links.push(path.clone());
        }
        let mut en = Entry {
            path,
            kind,
            mode: h.mode()?,
            // owners are dropped anyway (another host); tolerate empty fields
            uid: h.uid().unwrap_or(0) as u32,
            gid: h.gid().unwrap_or(0) as u32,
            size,
            mtime_ns: (h.mtime().unwrap_or(0) as i64).saturating_mul(1_000_000_000),
            ctime_ns: 0,
            inode: 0,
            rdev: 0,
            link_target,
            xattrs: Vec::new(),
            chunks,
            unchanged: false,
            inconsistent: false,
        };
        if target.adapt(&mut en, sk) {
            out.push((i, en));
        }
    }
    Ok(out)
}

/// Restores the files of the tar `path` onto the agent (always "another host").
pub fn restore_tar(s: &mut Session, path: &Path, spec: &Spec, log: &mut dyn FnMut(&str)) -> Result<ScanStats> {
    let target = Target::of(s, false);
    let lz4 = s.has_cap(agent_proto::CAP_LZ4);
    let mut sk = Skipped::default();
    let items = scan(BufReader::new(File::open(path)?), &target, &mut sk)?;
    if items.is_empty() {
        bail!("no restorable entries in the selection");
    }
    begin(s, spec)?;
    let (mut files, mut bytes) = (0u64, 0u64);
    let mut buf = vec![0u8; MAX_CHUNK];
    let mut ar = tar::Archive::new(BufReader::new(File::open(path)?));
    let mut it = ar.entries()?.enumerate();
    for batch in batches(&items, |(_, e)| e.chunks.len()) {
        let out: Vec<Entry> = batch.iter().map(|(_, e)| e.clone()).collect();
        s.send(&Message::RestoreEntries { batch: out })?;
        for (idx, e) in batch.iter().filter(|(_, e)| e.kind == Kind::File) {
            let mut data = loop {
                let (i, x) = it.next().context("archive shrank while restoring")?;
                if i == *idx {
                    break x?;
                }
            };
            files += 1;
            for (h, len) in &e.chunks {
                let n = fill(&mut data, &mut buf[..*len as usize])?;
                if n != *len as usize || blake3::hash(&buf[..n]).as_bytes() != h {
                    bail!("archive changed while restoring");
                }
                bytes += n as u64;
                send_chunk(s, lz4, buf[..n].to_vec())?;
            }
        }
    }
    let stats = end(s, &sk, log)?;
    log(&format!(
        "sent {} entries ({files} files, {bytes} bytes) of {}/{} to {}",
        items.len(),
        spec.source,
        spec.time,
        spec.target
    ));
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(b: &mut tar::Builder<Vec<u8>>, path: &str, t: EntryType, data: &[u8], link: Option<&str>) {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(t);
        h.set_mode(if t == EntryType::Directory { 0o755 } else { 0o4750 });
        h.set_uid(1000);
        h.set_gid(1000);
        h.set_mtime(1_760_000_000);
        h.set_size(data.len() as u64);
        match link {
            Some(l) => b.append_link(&mut h, path, l).unwrap(),
            None => b.append_data(&mut h, path, data).unwrap(),
        }
    }

    /// Raw entry name (bypasses the tar crate's own path checks).
    fn raw(b: &mut tar::Builder<Vec<u8>>, name: &str, t: EntryType, link: Option<&str>) {
        let mut h = tar::Header::new_gnu();
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(l) = link {
            h.as_old_mut().linkname[..l.len()].copy_from_slice(l.as_bytes());
        }
        h.set_entry_type(t);
        h.set_mode(0o644);
        h.set_size(0);
        h.set_cksum();
        b.append(&h, &[][..]).unwrap();
    }

    #[test]
    fn tar_entries_become_restore_entries() {
        let long = format!("sda1/{}/file.txt", "x".repeat(150));
        let big: Vec<u8> = (0..MAX_CHUNK + 1000).map(|i| (i % 251) as u8).collect();
        let mut b = tar::Builder::new(Vec::new());
        add(&mut b, "./", EntryType::Directory, b"", None);
        add(&mut b, "sda1/", EntryType::Directory, b"", None);
        add(&mut b, "sda1/etc/hostname", EntryType::Regular, b"vm100\n", None);
        add(&mut b, "sda1/big.bin", EntryType::Regular, &big, None);
        add(&mut b, "sda1/empty", EntryType::Regular, b"", None);
        add(&mut b, "sda1/lnk", EntryType::Symlink, b"", Some("/etc"));
        add(&mut b, "sda1/hl", EntryType::Link, b"", Some("sda1/etc/hostname"));
        add(&mut b, &long, EntryType::Regular, b"long", None);
        add(&mut b, "sda1/fifo", EntryType::Fifo, b"", None);
        add(&mut b, "sda1/null", EntryType::Char, b"", None);
        raw(&mut b, "../../evil", EntryType::Regular, None);
        raw(&mut b, "sda1/lnk/passwd", EntryType::Regular, None);
        raw(&mut b, "sda1/hl2", EntryType::Link, Some("../../etc/shadow"));
        let tar = b.into_inner().unwrap();

        let target = Target {
            xattrs: true,
            ..Default::default()
        };
        let mut sk = Skipped::default();
        let v = scan(&tar[..], &target, &mut sk).unwrap();
        let names: Vec<(String, Kind)> = v
            .iter()
            .map(|(_, e)| (String::from_utf8_lossy(&e.path).into_owned(), e.kind))
            .collect();
        assert_eq!(
            names,
            [
                ("sda1".to_string(), Kind::Dir),
                ("sda1/etc/hostname".into(), Kind::File),
                ("sda1/big.bin".into(), Kind::File),
                ("sda1/empty".into(), Kind::File),
                ("sda1/lnk".into(), Kind::Symlink),
                ("sda1/hl".into(), Kind::Hardlink),
                (long.clone(), Kind::File),
                ("sda1/fifo".into(), Kind::Fifo),
            ]
        );
        assert_eq!(
            sk.entries, 4,
            "device, ../, below a symlink, hard link out of the archive"
        );
        let (_, big_e) = &v[2];
        assert_eq!(big_e.size, big.len() as u64);
        assert_eq!(
            big_e.chunks.iter().map(|c| c.1 as usize).collect::<Vec<_>>(),
            [MAX_CHUNK, 1000]
        );
        assert_eq!(big_e.chunks[1].0, *blake3::hash(&big[MAX_CHUNK..]).as_bytes());
        let (_, f) = &v[1];
        assert_eq!(
            (f.uid, f.gid, f.mode),
            (u32::MAX, u32::MAX, 0o750),
            "no owners, no setuid"
        );
        assert_eq!(f.mtime_ns, 1_760_000_000_000_000_000);
        assert!(v[3].1.chunks.is_empty());
        assert_eq!(v[4].1.link_target.as_deref(), Some(&b"/etc"[..]));
        assert_eq!(v[5].1.link_target.as_deref(), Some(&b"sda1/etc/hostname"[..]));
        // ordinals point back into the archive for pass 2
        assert_eq!(v.iter().map(|(i, _)| *i).collect::<Vec<_>>(), [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn names_are_normalised() {
        assert_eq!(norm(b"./a/b/"), Some(b"a/b".to_vec()));
        assert_eq!(norm(b"/a"), Some(b"a".to_vec()));
        assert_eq!(norm(b"./"), Some(vec![]));
        assert_eq!(norm(b"a/../b"), None);
        assert_eq!(norm(b"a//b"), None);
    }
}
