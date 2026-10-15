//! Download with conversion (contract v1.9, `nexus-pluginhost export`): the selected
//! part of a mailbox snapshot as
//!
//! - `eml` — as stored: one `.eml` per message in its folder (like the plain download);
//! - `mbox` — one RFC 4155 mbox per mail folder (`mail/Inbox.mbox`,
//!   `mail/Inbox/Projects.mbox`; "mboxrd": `>*From ` lines get one more `>`, LF line
//!   endings), for Thunderbird, Apple Mail, mutt, …;
//! - `pst` — Outlook data files (Unicode PST, [`crate::pst`]): the mail folders below
//!   "Top of Personal Folders" (Recoverable Items "Deletions" as
//!   `Recoverable Items/Deletions`), split into several files of at most
//!   `pst_max_gb` GB each (default 20, Outlook's limit is 50).
//!
//! Everything that is not mail (calendars `.ics`, contacts `.vcf`, files, threads)
//! is copied unchanged. No network and no credentials: the plugin only reads the
//! snapshot and writes the download's files. Messages are read one at a time (at most
//! 512 MiB each); the PST writer keeps only per-block and per-row metadata in memory.

use crate::format::decode_name;
use crate::mail;
use crate::pst::PstWriter;
use plugin_sdk::proto::Kind;
use plugin_sdk::{error, Ctx, Export, Output, Result};
use std::collections::BTreeMap;
use std::io;

const MAX_MESSAGE: u64 = 512 << 20;

struct Entry {
    path: String,
    size: u64,
}

/// Mail folder of a message path (`mail/Inbox/x.eml` → `mail/Inbox`), if it is mail.
fn mail_folder(path: &str) -> Option<&str> {
    let (dir, name) = path.rsplit_once('/')?;
    let top = dir.split('/').next()?;
    (name.ends_with(".eml") && dir.contains('/') && (top == "mail" || top == "recoverable")).then_some(dir)
}

/// PST folder names of a snapshot mail folder.
fn pst_path(dir: &str) -> Vec<String> {
    let mut segs = dir.split('/');
    let top = segs.next().unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    if top == "recoverable" {
        out.push("Recoverable Items".into());
    }
    out.extend(segs.map(decode_name));
    out
}

fn copy(ex: &mut Export, path: &str) -> Result<u64> {
    let mut out = ex.output(path)?;
    let n = io::copy(&mut ex.reader(path.as_bytes()), &mut out)?;
    out.finish()?;
    Ok(n)
}

/// Writes PST files `<base>.pst`, `<base>-2.pst`, … of at most `max` bytes each
/// (`open` creates an output, `close` completes a finished one).
struct Psts<W: io::Write + io::Seek> {
    base: String,
    title: String,
    max: u64,
    cur: Option<PstWriter<W>>,
    files: Vec<String>,
}

impl<W: io::Write + io::Seek> Psts<W> {
    fn finish(&mut self, close: &mut dyn FnMut(W) -> Result<()>) -> Result<()> {
        if let Some(w) = self.cur.take() {
            close(w.finish()?)?;
        }
        Ok(())
    }

    fn add(
        &mut self,
        open: &mut dyn FnMut(&str) -> Result<W>,
        close: &mut dyn FnMut(W) -> Result<()>,
        folder: &[String],
        eml: &[u8],
    ) -> Result<()> {
        // room for the message (converted ≤ 2× its MIME size) and the folder tables
        let full = self.cur.as_ref().is_some_and(|w| {
            w.messages > 0 && w.size() + 2 * eml.len() as u64 + 512 * w.messages + (4 << 20) > self.max
        });
        if full {
            self.finish(close)?;
        }
        if self.cur.is_none() {
            let n = self.files.len() + 1;
            let (name, title) = if n == 1 {
                (format!("{}.pst", self.base), self.title.clone())
            } else {
                (format!("{}-{n}.pst", self.base), format!("{} ({n})", self.title))
            };
            let digest = ring::digest::digest(&ring::digest::SHA256, name.as_bytes());
            let uid: [u8; 16] = digest.as_ref()[..16].try_into().unwrap();
            self.cur = Some(PstWriter::new(open(&name)?, &title, uid)?);
            self.files.push(name);
        }
        let w = self.cur.as_mut().unwrap();
        let f = w.folder(folder);
        w.add_message(f, mail::to_pst(eml))?;
        Ok(())
    }
}

pub fn run(ctx: &Ctx, ex: &mut Export) -> Result<String> {
    let p = &ctx.params["params"];
    let format = p["mail_format"].as_str().unwrap_or("eml");
    if !matches!(format, "eml" | "mbox" | "pst") {
        return Err(error(22, "mail_format: eml, mbox or pst"));
    }
    let max_gb = p["pst_max_gb"].as_u64().unwrap_or(20);
    if !(1..=50).contains(&max_gb) {
        return Err(error(22, "pst_max_gb: 1..=50"));
    }
    let mut entries = Vec::new();
    ex.list(|e| {
        if e.meta.kind == Some(Kind::File) {
            entries.push(Entry {
                path: String::from_utf8_lossy(&e.path).into_owned(),
                size: e.meta.size,
            });
        }
        Ok(())
    })?;
    let total = entries.len() as u64;
    let mut folders: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
    let mut other = Vec::new();
    for e in &entries {
        match mail_folder(&e.path).filter(|_| format != "eml") {
            Some(dir) => folders.entry(dir.to_owned()).or_default().push(e),
            None => other.push(e),
        }
    }
    let (mut done, mut messages, mut copied, mut skipped) = (0u64, 0u64, 0u64, 0u64);
    for e in other {
        copy(ex, &e.path)?;
        copied += 1;
        done += 1;
        if done.is_multiple_of(200) {
            ex.progress(done, total, &format!("{done} of {total} items"));
        }
    }
    let guest = p["guest"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| plugin_sdk::proto::parse_source_name(ctx.params["snapshot"]["source"].as_str()?)?.2)
        .unwrap_or_else(|| "mailbox".into());
    let mut psts: Psts<Output> = Psts {
        base: guest.clone(),
        title: format!("Microsoft 365 {guest}"),
        max: max_gb * 1_000_000_000,
        cur: None,
        files: Vec::new(),
    };
    // one folder at a time, its messages in snapshot order
    for (dir, msgs) in &folders {
        let mut mbox = match format {
            "mbox" => Some(io::BufWriter::with_capacity(
                4 << 20,
                ex.output(&format!("{dir}.mbox"))?,
            )),
            _ => None,
        };
        for e in msgs {
            if e.size > MAX_MESSAGE {
                ctx.warn(format!("{}: larger than 512 MiB, skipped", e.path));
                skipped += 1;
                continue;
            }
            let eml = ex.read_all(e.path.as_bytes(), MAX_MESSAGE)?;
            match &mut mbox {
                Some(w) => mail::mbox_append(w, &eml)?,
                None => {
                    let mut open = |n: &str| ex.output(n);
                    psts.add(&mut open, &mut |o: Output| o.finish(), &pst_path(dir), &eml)?;
                }
            }
            messages += 1;
            done += 1;
            if done.is_multiple_of(200) {
                ex.progress(done, total, &format!("{done} of {total} items"));
            }
        }
        if let Some(w) = mbox {
            w.into_inner().map_err(std::io::IntoInnerError::into_error)?.finish()?;
        }
    }
    psts.finish(&mut |o: Output| o.finish())?;
    let mut summary = match format {
        "mbox" => format!("{messages} messages as mbox ({} folders)", folders.len()),
        "pst" => format!("{messages} messages as PST ({})", psts.files.join(", ")),
        _ => format!("{copied} items as stored"),
    };
    if format != "eml" && copied > 0 {
        summary.push_str(&format!(", {copied} other items as stored"));
    }
    if skipped > 0 {
        summary.push_str(&format!(", {skipped} messages over 512 MiB skipped"));
    }
    Ok(format!("exported {summary}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_paths() {
        assert_eq!(mail_folder("mail/Inbox/a ~1.eml"), Some("mail/Inbox"));
        assert_eq!(mail_folder("mail/Inbox/Sub%2Fx/a.eml"), Some("mail/Inbox/Sub%2Fx"));
        assert_eq!(
            mail_folder("recoverable/Deletions/a.eml"),
            Some("recoverable/Deletions")
        );
        assert_eq!(mail_folder("calendar/Calendar/e.ics"), None);
        assert_eq!(mail_folder("mail/x.eml"), None);
        assert_eq!(mail_folder("onedrive/mail/a.eml"), None);
        assert_eq!(pst_path("mail/Inbox/Sub%2Fx"), ["Inbox", "Sub/x"]);
        assert_eq!(pst_path("recoverable/Deletions"), ["Recoverable Items", "Deletions"]);
    }

    /// Messages in the "Inbox" of a PST (read with outlook-pst).
    fn inbox_count(pst: Vec<u8>) -> usize {
        use outlook_pst::messaging::store::{Store, UnicodeStore};
        let f = outlook_pst::UnicodePstFile::read_from(Box::new(io::Cursor::new(pst))).unwrap();
        let store = UnicodeStore::read(std::rc::Rc::new(f)).unwrap();
        let ipm = store
            .open_folder(&store.properties().ipm_sub_tree_entry_id().unwrap())
            .unwrap();
        for row in ipm.hierarchy_table().unwrap().rows_matrix() {
            let id = store
                .properties()
                .make_entry_id(outlook_pst::ndb::node_id::NodeId::from(u32::from(row.id())))
                .unwrap();
            let f = store.open_folder(&id).unwrap();
            if f.properties().display_name().unwrap() == "Inbox" {
                return f.contents_table().unwrap().rows_matrix().count();
            }
        }
        0
    }

    #[test]
    fn pst_split_by_size() {
        let max = 12_000_000;
        let mut psts: Psts<io::Cursor<Vec<u8>>> = Psts {
            base: "u.x".into(),
            title: "t".into(),
            max,
            cur: None,
            files: Vec::new(),
        };
        let mut done = Vec::new();
        let mut close = |w: io::Cursor<Vec<u8>>| {
            done.push(w.into_inner());
            Ok(())
        };
        let body: String = (0..150_000).map(|i| char::from(b'a' + (i * 7 % 26) as u8)).collect();
        for i in 0..60 {
            let eml = format!(
                "From: a@example.com\r\nSubject: m{i}\r\nContent-Type: application/octet-stream; name=x.bin\r\n\r\n{body}\r\n"
            );
            psts.add(
                &mut |_| Ok(io::Cursor::new(Vec::new())),
                &mut close,
                &["Inbox".into()],
                eml.as_bytes(),
            )
            .unwrap();
        }
        psts.finish(&mut close).unwrap();
        assert!(done.len() >= 2, "{} files", done.len());
        assert_eq!(psts.files[..2], ["u.x.pst".to_owned(), "u.x-2.pst".to_owned()]);
        assert!(
            done.iter().all(|f| f.len() as u64 <= max),
            "{:?}",
            done.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert_eq!(done.into_iter().map(inbox_count).sum::<usize>(), 60);
    }
}
