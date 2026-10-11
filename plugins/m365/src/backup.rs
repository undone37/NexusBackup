//! Backup of one guest into the snapshot tree:
//!
//! ```text
//! u.<user>   mail/<folder>/…/<subject> ~<hash>.eml        MIME as Exchange returns it
//!            calendar/<calendar>/<date> <subject> ~<hash>.ics
//!            contacts/<folder>/…/<name> ~<hash>.vcf
//!            onedrive/<path>                               files as they are
//! s.<site>   libraries/<library>/<path>
//! t.<team>   files/<path>                                  the team's document library
//!            channels/<channel>/<date> <subject> ~<hash>.json   thread: root + replies
//! ```
//!
//! Every directory and file carries its Graph id in the xattr `user.m365.id` (and
//! files their version tag — changeKey / cTag — in `user.m365.tag`). The previous
//! snapshot is read back with `BaseList` (contract v1.3), so the plugin knows each
//! item's previous path and metadata without keeping item lists in the 1 MiB state
//! blob. The state blob keeps only the Graph delta links (per mail folder and per
//! drive) and the time of the last Teams export.
//!
//! Incremental: mail folders and drives are read with Graph delta queries (with a
//! delta link only the changes come back; everything else is taken over from the
//! base); calendars and contacts are listed completely (Graph v1.0 has no delta for
//! non-expanded events) and compared; Teams channel messages come from the export
//! API filtered by `lastModifiedDateTime`. An item whose id, path, version tag and
//! time equal the base entry is sent as `Unchanged` (the host reuses its data);
//! anything else is downloaded. Renamed folders therefore re-send their items.

use crate::format::{encode_name, item_name, parse_time, rfc3339, short_hash};
use crate::graph::{self, enc, Graph};
use crate::{Config, Guest};
use plugin_sdk::proto::MAX_STATE;
use plugin_sdk::{error, BackupResult, BaseEntry, Ctx, Kind, Meta, Result, Sink};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

pub const X_ID: &[u8] = b"user.m365.id";
pub const X_TAG: &[u8] = b"user.m365.tag";

pub const PROTECTED_API_HELP: &str = "Microsoft has not enabled the protected Teams APIs for this app: channel \
messages can only be exported after Microsoft approves the request (https://aka.ms/teamsgraph/requestaccess; see \
docs/m365.md). Until then disable \"Teams: channel messages\" — team files are backed up without it.";

const PREFER_IDS: &str = "IdType=\"ImmutableId\", odata.maxpagesize=200";

/// Overlap of consecutive Teams export windows (clock skew, late index updates).
const TEAMS_OVERLAP: i64 = 600;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Export API URL (`getAllMessages`) of a team, optionally since a time.
pub fn teams_export_url(c: &Config, team: &str, since: Option<i64>, top: u32) -> String {
    let mut u = format!("/teams/{}/channels/getAllMessages?$top={top}", enc(team));
    if let Some(m) = &c.teams_model {
        u.push_str(&format!("&model={}", enc(m)));
    }
    if let Some(s) = since {
        u.push_str(&format!(
            "&$filter={}",
            enc(&format!("lastModifiedDateTime gt {}", rfc3339(s)))
        ));
    }
    u
}

// ---- state blob ------------------------------------------------------------------

#[derive(Default, Debug)]
struct State {
    /// `mail:<folder id>` / `drive:<drive id>` → delta link
    delta: BTreeMap<String, String>,
    /// start of the last Teams export (seconds)
    teams_since: Option<i64>,
}

impl State {
    fn load(raw: Option<&[u8]>) -> State {
        let Some(v) = raw.and_then(|r| serde_json::from_slice::<Value>(r).ok()) else {
            return State::default();
        };
        State {
            delta: v["delta"]
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                        .collect()
                })
                .unwrap_or_default(),
            teams_since: v["teams_since"].as_i64(),
        }
    }

    /// JSON, bounded by the protocol's state limit: if needed the longest delta links
    /// are dropped (those containers are listed completely next time — that costs
    /// requests, not downloads).
    fn encode(mut self, ctx: &Ctx) -> Vec<u8> {
        let enc = |s: &State| {
            serde_json::to_vec(&json!({"v": 1, "delta": s.delta, "teams_since": s.teams_since})).unwrap_or_default()
        };
        let limit = MAX_STATE - 4096;
        let mut out = enc(&self);
        let mut dropped = 0;
        while out.len() > limit && !self.delta.is_empty() {
            // drop the longest links until the estimate fits, then encode again
            let mut size = out.len();
            let mut by_len: Vec<(usize, String)> = self
                .delta
                .iter()
                .map(|(k, v)| (k.len() + v.len() + 8, k.clone()))
                .collect();
            by_len.sort_unstable_by(|a, b| b.0.cmp(&a.0));
            for (n, k) in by_len {
                if size <= limit {
                    break;
                }
                self.delta.remove(&k);
                size = size.saturating_sub(n);
                dropped += 1;
            }
            out = enc(&self);
        }
        if dropped > 0 {
            ctx.warn(format!(
                "{dropped} delta links did not fit the state blob: those folders are listed completely next time"
            ));
        }
        out
    }
}

// ---- the base snapshot -----------------------------------------------------------

fn xattr<'a>(m: &'a Meta, k: &[u8]) -> Option<&'a str> {
    m.xattrs
        .iter()
        .find(|(n, _)| n == k)
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

/// The previous snapshot of this guest, indexed by path, Graph id and parent id.
pub struct Prev {
    entries: Vec<BaseEntry>,
    by_path: HashMap<Vec<u8>, usize>,
    by_id: HashMap<String, usize>,
    children: HashMap<String, Vec<usize>>,
}

fn parent_path(p: &[u8]) -> Option<&[u8]> {
    p.iter().rposition(|b| *b == b'/').map(|i| &p[..i])
}

fn basename(p: &[u8]) -> &[u8] {
    p.iter().rposition(|b| *b == b'/').map_or(p, |i| &p[i + 1..])
}

impl Prev {
    pub fn new(entries: Vec<BaseEntry>) -> Prev {
        let by_path: HashMap<Vec<u8>, usize> = entries.iter().enumerate().map(|(i, e)| (e.path.clone(), i)).collect();
        let mut by_id = HashMap::new();
        let mut children: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            if let Some(id) = xattr(&e.meta, X_ID) {
                by_id.insert(id.to_owned(), i);
            }
            let parent = parent_path(&e.path)
                .and_then(|p| by_path.get(p))
                .and_then(|&j| xattr(&entries[j].meta, X_ID));
            if let Some(p) = parent {
                children.entry(p.to_owned()).or_default().push(i);
            }
        }
        Prev {
            entries,
            by_path,
            by_id,
            children,
        }
    }

    fn get(&self, id: &str) -> Option<&BaseEntry> {
        self.by_id.get(id).map(|&i| &self.entries[i])
    }

    /// Files and directories whose parent directory had id `parent`.
    fn children(&self, parent: &str) -> impl Iterator<Item = &BaseEntry> {
        self.children
            .get(parent)
            .into_iter()
            .flatten()
            .map(|&i| &self.entries[i])
    }

    fn parent_id(&self, e: &BaseEntry) -> Option<&str> {
        let p = parent_path(&e.path)?;
        xattr(&self.entries[*self.by_path.get(p)?].meta, X_ID)
    }
}

/// Item metadata of a not-yet-sent item (from Graph or from the base).
#[derive(Clone, Debug)]
struct Item {
    name: String,
    tag: String,
    mtime_ns: i64,
}

impl Item {
    fn from_base(e: &BaseEntry) -> Item {
        Item {
            name: String::from_utf8_lossy(basename(&e.path)).into_owned(),
            tag: xattr(&e.meta, X_TAG).unwrap_or_default().to_owned(),
            mtime_ns: e.meta.mtime_ns,
        }
    }
}

fn time_ns(v: &Value) -> i64 {
    v.as_str().and_then(parse_time).unwrap_or(0)
}

// ---- output ----------------------------------------------------------------------

/// The snapshot being written: unique paths, `Unchanged` decisions, counters.
struct Out<'a> {
    sink: &'a mut Sink,
    used: HashSet<Vec<u8>>,
    items: u64,
    unchanged: u64,
    downloaded: u64,
    skipped: u64,
}

fn xattrs(id: &str, tag: Option<&str>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut x = vec![(X_ID.to_vec(), id.as_bytes().to_vec())];
    if let Some(t) = tag {
        x.push((X_TAG.to_vec(), t.as_bytes().to_vec()));
    }
    x
}

impl Out<'_> {
    /// A free path: `path`, or (on a clash) with ` ~<hash of id>` before the extension.
    fn claim(&mut self, path: String, id: &str) -> String {
        let p = if self.used.contains(path.as_bytes()) {
            let (stem, ext) = match path.rfind('.').filter(|&i| i > path.rfind('/').map_or(0, |s| s + 1)) {
                Some(i) => (&path[..i], &path[i..]),
                None => (path.as_str(), ""),
            };
            format!("{stem} ~{}{ext}", short_hash(id))
        } else {
            path
        };
        self.used.insert(p.clone().into_bytes());
        p
    }

    fn dir(&mut self, path: &str, id: &str) -> Result<()> {
        if !self.used.insert(path.as_bytes().to_vec()) {
            return Ok(());
        }
        self.sink.entry(
            path.as_bytes(),
            Meta {
                kind: Some(Kind::Dir),
                mode: 0o40755,
                xattrs: xattrs(id, None),
                ..Default::default()
            },
        )
    }

    /// `Unchanged` if the base has this id at this path with the same tag, time (and size).
    fn unchanged(&mut self, prev: &Prev, path: &str, id: &str, it: &Item, size: Option<u64>) -> Result<bool> {
        let Some(b) = prev.get(id) else { return Ok(false) };
        let same = b.path == path.as_bytes()
            && b.meta.kind == Some(Kind::File)
            && xattr(&b.meta, X_TAG).unwrap_or_default() == it.tag
            && b.meta.mtime_ns == it.mtime_ns
            && size.is_none_or(|s| s == b.meta.size);
        if same {
            self.sink.unchanged(path.as_bytes(), b.meta.clone())?;
            self.items += 1;
            self.unchanged += 1;
        }
        Ok(same)
    }

    fn file(&mut self, path: &str, id: &str, it: &Item, size: u64, data: &mut dyn std::io::Read) -> Result<()> {
        self.sink.file(
            path.as_bytes(),
            Meta {
                kind: Some(Kind::File),
                mode: 0o100644,
                size,
                mtime_ns: it.mtime_ns,
                xattrs: xattrs(id, Some(&it.tag)),
                ..Default::default()
            },
            data,
        )?;
        self.items += 1;
        self.downloaded += size;
        Ok(())
    }

    fn bytes(&mut self, path: &str, id: &str, it: &Item, b: &[u8]) -> Result<()> {
        self.file(path, id, it, b.len() as u64, &mut &b[..])
    }
}

/// One container read with a delta query: the changed items (`None` = removed) and
/// whether they are changes against the base (`true`) or the complete content.
struct Delta {
    items: Vec<(String, Option<Value>)>,
    incremental: bool,
    link: Option<String>,
}

fn delta_item(items: &mut Vec<(String, Option<Value>)>, v: Value) {
    if let Some(id) = v["id"].as_str().map(str::to_owned) {
        let removed = v.get("@removed").is_some() || v.get("deleted").is_some_and(|d| !d.is_null());
        items.push((id, (!removed).then_some(v)));
    }
}

/// Delta round: with the stored link if any (an expired link falls back to a full round).
fn delta(ctx: &Ctx, g: &mut Graph, link: Option<&String>, initial: &str, headers: &[(&str, String)]) -> Result<Delta> {
    if let Some(l) = link {
        let mut items = Vec::new();
        match g.pages(l, headers, |v| {
            delta_item(&mut items, v);
            Ok(())
        }) {
            Ok(link) => {
                return Ok(Delta {
                    items,
                    incremental: true,
                    link,
                })
            }
            Err(e) if matches!(graph::status(&e), Some(400) | Some(404) | Some(410)) => {
                ctx.warn(format!("delta link no longer valid ({e:#}): full listing"));
            }
            Err(e) => return Err(e),
        }
    }
    let mut items = Vec::new();
    let link = g.pages(initial, headers, |v| {
        delta_item(&mut items, v);
        Ok(())
    })?;
    Ok(Delta {
        items,
        incremental: false,
        link,
    })
}

/// Everything one backup needs.
struct Run<'a, 'b> {
    ctx: &'a Ctx,
    c: &'a Config,
    g: Graph,
    prev: Prev,
    old: State,
    new: State,
    out: Out<'b>,
    notes: Vec<String>,
}

pub fn run(ctx: &Ctx, c: &Config, g: Graph, guest: &Guest, sink: &mut Sink) -> Result<BackupResult> {
    let started = now();
    let prev = Prev::new(sink.base_list()?);
    let old = if sink.has_base() {
        State::load(ctx.state.as_deref())
    } else {
        State::default()
    };
    let mut r = Run {
        ctx,
        c,
        g,
        prev,
        old,
        new: State::default(),
        out: Out {
            sink,
            used: HashSet::new(),
            items: 0,
            unchanged: 0,
            downloaded: 0,
            skipped: 0,
        },
        notes: Vec::new(),
    };
    match guest {
        Guest::User(u) => {
            if !(c.exchange || c.onedrive) {
                return Err(error(
                    22,
                    "users are backed up for Exchange or OneDrive; both are disabled",
                ));
            }
            if c.exchange && r.mail(u)? {
                r.calendars(u)?;
                r.contacts(u)?;
            }
            if c.onedrive {
                match r.g.get(&format!("/users/{}/drive?$select=id", enc(u)), &[]) {
                    Ok(d) => {
                        let id = d["id"].as_str().unwrap_or_default().to_owned();
                        r.drive("onedrive", &id)?;
                    }
                    Err(e) if graph::status(&e) == Some(404) => r.note("no OneDrive"),
                    Err(e) => return Err(e),
                }
            }
        }
        Guest::Site(..) => {
            if !c.sharepoint {
                return Err(error(22, "SharePoint is disabled in the source"));
            }
            let site = guest
                .site_id(c.sharepoint_host.as_deref().unwrap_or_default())
                .unwrap_or_default();
            let mut libs = Vec::new();
            r.g.pages(
                &format!("/sites/{}/drives?$select=id,name,driveType", enc(&site)),
                &[],
                |d| {
                    libs.push(d);
                    Ok(())
                },
            )?;
            r.out.dir("libraries", "libraries")?;
            for (name, d) in unique_names(libs, "name") {
                let id = d["id"].as_str().unwrap_or_default().to_owned();
                r.drive(&format!("libraries/{}", encode_name(&name)), &id)?;
            }
        }
        Guest::Team(t) => {
            if !(c.teams || c.teams_messages) {
                return Err(error(22, "Teams is disabled in the source"));
            }
            if c.teams {
                let d = r.g.get(&format!("/groups/{}/drive?$select=id", enc(t)), &[])?;
                let id = d["id"].as_str().unwrap_or_default().to_owned();
                r.drive("files", &id)?;
            }
            if c.teams_messages {
                r.channels(t, started)?;
            }
        }
    }
    let Run {
        ctx,
        g,
        new,
        out,
        notes,
        ..
    } = r;
    let summary = format!(
        "{} items ({} unchanged), {} MiB downloaded, {} Graph requests ({} throttled, {} retried){}",
        out.items,
        out.unchanged,
        out.downloaded >> 20,
        g.stats.requests,
        g.stats.throttled,
        g.stats.retries,
        if notes.is_empty() {
            String::new()
        } else {
            format!("; {}", notes.join("; "))
        }
    );
    if out.skipped > 0 {
        ctx.info(format!("{} items vanished while the backup ran (skipped)", out.skipped));
    }
    Ok(BackupResult {
        state: Some(new.encode(ctx)),
        consistent: true,
        summary,
    })
}

/// Display names made unique (`name`, `name (2)`, …) in a stable order (by id).
fn unique_names(mut v: Vec<Value>, key: &str) -> Vec<(String, Value)> {
    v.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let mut seen: HashMap<String, u32> = HashMap::new();
    v.into_iter()
        .map(|x| {
            let n = x[key].as_str().unwrap_or_default().to_owned();
            let c = seen.entry(n.to_lowercase()).or_insert(0);
            *c += 1;
            let n = if *c == 1 { n } else { format!("{n} ({c})") };
            (n, x)
        })
        .collect()
}

/// Graph path of an item id (immutable ids may contain URL-special characters).
fn seg(id: &str) -> String {
    enc(id)
}

impl Run<'_, '_> {
    fn note(&mut self, s: &str) {
        self.ctx.info(s);
        self.notes.push(s.into());
    }

    fn prefer(&self) -> [(&'static str, String); 1] {
        [("prefer", PREFER_IDS.to_owned())]
    }

    // ---- Exchange ----------------------------------------------------------------

    /// Mail folders and messages; false if the user has no (cloud) mailbox.
    fn mail(&mut self, u: &str) -> Result<bool> {
        let h = self.prefer();
        let mut folders: HashMap<String, (Option<String>, String)> = HashMap::new();
        let r = self.g.pages(
            &format!("/users/{}/mailFolders/delta?$select=displayName,parentFolderId", enc(u)),
            &h,
            |f| {
                if f.get("@removed").is_none() {
                    if let Some(id) = f["id"].as_str() {
                        folders.insert(
                            id.to_owned(),
                            (
                                f["parentFolderId"].as_str().map(str::to_owned),
                                f["displayName"].as_str().unwrap_or_default().to_owned(),
                            ),
                        );
                    }
                }
                Ok(())
            },
        );
        match r {
            Ok(_) => {}
            Err(e) if graph::status(&e) == Some(404) => {
                self.note("no Exchange Online mailbox");
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
        let paths = folder_paths(&folders, "mail");
        self.out.dir("mail", "mail")?;
        let mut sorted: Vec<(&String, &String)> = paths.iter().collect();
        sorted.sort_by(|a, b| a.1.cmp(b.1));
        for (fid, fpath) in sorted {
            self.out.dir(fpath, &format!("mf:{fid}"))?;
            let key = format!("mail:{fid}");
            let initial = format!(
                "/users/{}/mailFolders/{}/messages/delta?$select=subject,lastModifiedDateTime,changeKey",
                enc(u),
                seg(fid)
            );
            let d = delta(self.ctx, &mut self.g, self.old.delta.get(&key), &initial, &h)?;
            let mut cur: BTreeMap<String, Item> = BTreeMap::new();
            if d.incremental {
                for b in self.prev.children(&format!("mf:{fid}")) {
                    if let Some(id) = xattr(&b.meta, X_ID).and_then(|i| i.strip_prefix("m:")) {
                        cur.insert(id.to_owned(), Item::from_base(b));
                    }
                }
            }
            for (id, v) in d.items {
                match v {
                    None => {
                        cur.remove(&id);
                    }
                    Some(m) => {
                        cur.insert(
                            id.clone(),
                            Item {
                                name: item_name(m["subject"].as_str().unwrap_or_default(), &id, "eml"),
                                tag: m["changeKey"].as_str().unwrap_or_default().to_owned(),
                                mtime_ns: time_ns(&m["lastModifiedDateTime"]),
                            },
                        );
                    }
                }
            }
            for (id, it) in cur {
                let xid = format!("m:{id}");
                let path = self.out.claim(format!("{fpath}/{}", it.name), &xid);
                if self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                    continue;
                }
                match self
                    .g
                    .get_bytes(&format!("/users/{}/messages/{}/$value", enc(u), seg(&id)), &h)
                {
                    Ok(mime) => self.out.bytes(&path, &xid, &it, &mime)?,
                    Err(e) if graph::status(&e) == Some(404) => self.out.skipped += 1,
                    Err(e) => return Err(e),
                }
            }
            if let Some(l) = d.link {
                self.new.delta.insert(key, l);
            }
        }
        Ok(true)
    }

    fn calendars(&mut self, u: &str) -> Result<()> {
        let h = [(
            "prefer",
            "outlook.timezone=\"UTC\", IdType=\"ImmutableId\", odata.maxpagesize=100".to_owned(),
        )];
        let mut cals = Vec::new();
        self.g
            .pages(&format!("/users/{}/calendars?$select=id,name", enc(u)), &h, |c| {
                cals.push(c);
                Ok(())
            })?;
        self.out.dir("calendar", "calendar")?;
        for (name, cal) in unique_names(cals, "name") {
            let cid = cal["id"].as_str().unwrap_or_default().to_owned();
            let cpath = format!("calendar/{}", encode_name(&name));
            self.out.dir(&cpath, &format!("cal:{cid}"))?;
            let mut events = Vec::new();
            self.g.pages(
                &format!("/users/{}/calendars/{}/events?$top=100", enc(u), seg(&cid)),
                &h,
                |e| {
                    events.push(e);
                    Ok(())
                },
            )?;
            for e in events {
                let Some(id) = e["id"].as_str() else { continue };
                let xid = format!("e:{id}");
                let date = e["start"]["dateTime"]
                    .as_str()
                    .and_then(|d| d.get(..10))
                    .unwrap_or_default();
                let it = Item {
                    name: item_name(
                        &format!("{date} {}", e["subject"].as_str().unwrap_or_default()),
                        id,
                        "ics",
                    ),
                    tag: e["changeKey"].as_str().unwrap_or_default().to_owned(),
                    mtime_ns: time_ns(&e["lastModifiedDateTime"]),
                };
                let path = self.out.claim(format!("{cpath}/{}", it.name), &xid);
                if !self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                    self.out
                        .bytes(&path, &xid, &it, crate::format::event_ics(&e).as_bytes())?;
                }
            }
        }
        Ok(())
    }

    fn contacts(&mut self, u: &str) -> Result<()> {
        let h = self.prefer();
        // (folder path, contacts URL, id) — the default folder is not in contactFolders
        let mut folders = vec![(
            "contacts/Contacts".to_owned(),
            format!("/users/{}/contacts?$top=100", enc(u)),
            "pf:default".to_owned(),
        )];
        let mut queue = vec![(
            format!("/users/{}/contactFolders?$top=100", enc(u)),
            "contacts".to_owned(),
        )];
        while let Some((url, parent)) = queue.pop() {
            let mut list = Vec::new();
            self.g.pages(&url, &h, |f| {
                list.push(f);
                Ok(())
            })?;
            for (name, f) in unique_names(list, "displayName") {
                let id = f["id"].as_str().unwrap_or_default().to_owned();
                let mut path = format!("{parent}/{}", encode_name(&name));
                if path == "contacts/Contacts" {
                    path = format!("contacts/Contacts ~{}", short_hash(&id));
                }
                folders.push((
                    path.clone(),
                    format!("/users/{}/contactFolders/{}/contacts?$top=100", enc(u), seg(&id)),
                    format!("pf:{id}"),
                ));
                if folders.len() < 1000 {
                    queue.push((
                        format!("/users/{}/contactFolders/{}/childFolders?$top=100", enc(u), seg(&id)),
                        path,
                    ));
                }
            }
        }
        folders.sort();
        self.out.dir("contacts", "contacts")?;
        for (fpath, url, fid) in folders {
            self.out.dir(&fpath, &fid)?;
            let mut list = Vec::new();
            self.g.pages(&url, &h, |p| {
                list.push(p);
                Ok(())
            })?;
            for p in list {
                let Some(id) = p["id"].as_str() else { continue };
                let xid = format!("p:{id}");
                let label = p["displayName"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or(p["emailAddresses"][0]["address"].as_str())
                    .unwrap_or_default();
                let it = Item {
                    name: item_name(label, id, "vcf"),
                    tag: p["changeKey"].as_str().unwrap_or_default().to_owned(),
                    mtime_ns: time_ns(&p["lastModifiedDateTime"]),
                };
                let path = self.out.claim(format!("{fpath}/{}", it.name), &xid);
                if !self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                    self.out
                        .bytes(&path, &xid, &it, crate::format::contact_vcf(&p).as_bytes())?;
                }
            }
        }
        Ok(())
    }

    // ---- drives (OneDrive, document libraries, team files) -----------------------

    fn drive(&mut self, root_path: &str, drive: &str) -> Result<()> {
        let key = format!("drive:{drive}");
        let pre = format!("d:{drive}/");
        let initial = format!(
            "/drives/{}/root/delta?$select=id,name,parentReference,file,folder,package,root,size,lastModifiedDateTime,cTag,eTag,deleted",
            enc(drive)
        );
        let d = delta(self.ctx, &mut self.g, self.old.delta.get(&key), &initial, &[])?;
        #[derive(Clone)]
        struct Node {
            parent: Option<String>,
            name: String,
            dir: bool,
            size: u64,
            item: Item,
        }
        let mut nodes: HashMap<String, Node> = HashMap::new();
        let mut root: Option<String> = None;
        if d.incremental {
            for e in self.prev.entries.iter() {
                let Some(id) = xattr(&e.meta, X_ID).and_then(|i| i.strip_prefix(&pre)) else {
                    continue;
                };
                if e.path == root_path.as_bytes() {
                    root = Some(id.to_owned());
                    continue;
                }
                let it = Item::from_base(e);
                nodes.insert(
                    id.to_owned(),
                    Node {
                        parent: self
                            .prev
                            .parent_id(e)
                            .and_then(|p| p.strip_prefix(&pre))
                            .map(str::to_owned),
                        name: it.name.clone(),
                        dir: e.meta.kind == Some(Kind::Dir),
                        size: e.meta.size,
                        item: it,
                    },
                );
            }
        }
        for (id, v) in d.items {
            let Some(v) = v else {
                nodes.remove(&id);
                continue;
            };
            if v.get("root").is_some_and(|r| !r.is_null()) {
                root = Some(id);
                continue;
            }
            let dir = v.get("folder").is_some() || v.get("package").is_some();
            if !dir && v.get("file").is_none() {
                continue;
            }
            let name = encode_name(v["name"].as_str().unwrap_or_default());
            nodes.insert(
                id,
                Node {
                    parent: v["parentReference"]["id"].as_str().map(str::to_owned),
                    name: name.clone(),
                    dir,
                    size: v["size"].as_u64().unwrap_or(0),
                    item: Item {
                        name,
                        tag: v["cTag"].as_str().or(v["eTag"].as_str()).unwrap_or_default().to_owned(),
                        mtime_ns: time_ns(&v["lastModifiedDateTime"]),
                    },
                },
            );
        }
        let root = match root {
            Some(r) => r,
            None => self.g.get(&format!("/drives/{}/root?$select=id", enc(drive)), &[])?["id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        };
        // paths: walk up to the root (items whose chain does not reach it were deleted with a folder)
        let mut paths: HashMap<String, Option<String>> = HashMap::new();
        paths.insert(root.clone(), Some(root_path.to_owned()));
        fn resolve(
            id: &str,
            nodes: &HashMap<String, Node>,
            paths: &mut HashMap<String, Option<String>>,
            depth: u32,
        ) -> Option<String> {
            if let Some(p) = paths.get(id) {
                return p.clone();
            }
            let n = nodes.get(id)?;
            let p = if depth > 2000 {
                None
            } else {
                n.parent
                    .as_deref()
                    .and_then(|par| resolve(par, nodes, paths, depth + 1))
                    .map(|pp| format!("{pp}/{}", n.name))
            };
            paths.insert(id.to_owned(), p.clone());
            p
        }
        let mut list: Vec<(String, String)> = nodes
            .keys()
            .filter_map(|id| resolve(id, &nodes, &mut paths, 0).map(|p| (p, id.clone())))
            .collect();
        list.sort();
        self.out.dir(root_path, &format!("{pre}{root}"))?;
        for (path, id) in list {
            let n = &nodes[&id];
            let xid = format!("{pre}{id}");
            if n.dir {
                self.out.dir(&path, &xid)?;
                continue;
            }
            let path = self.out.claim(path, &xid);
            if self.out.unchanged(&self.prev, &path, &xid, &n.item, Some(n.size))? {
                continue;
            }
            let mut dl = self
                .g
                .download(&format!("/drives/{}/items/{}/content", enc(drive), seg(&id)), n.size);
            match dl.start() {
                Ok(()) => {}
                Err(e) if graph::status(&e) == Some(404) => {
                    self.out.skipped += 1;
                    continue;
                }
                Err(e) => return Err(e),
            }
            self.out.file(&path, &xid, &n.item, n.size, &mut dl)?;
        }
        if let Some(l) = d.link {
            self.new.delta.insert(key, l);
        }
        Ok(())
    }

    // ---- Teams channel messages ----------------------------------------------------

    fn channels(&mut self, t: &str, started: i64) -> Result<()> {
        let mut chans = Vec::new();
        self.g.pages(
            &format!("/teams/{}/channels?$select=id,displayName,membershipType", enc(t)),
            &[],
            |c| {
                chans.push(c);
                Ok(())
            },
        )?;
        self.out.dir("channels", "channels")?;
        let mut chan_path: HashMap<String, String> = HashMap::new();
        let mut chan_name: HashMap<String, String> = HashMap::new();
        for (name, ch) in unique_names(chans, "displayName") {
            let id = ch["id"].as_str().unwrap_or_default().to_owned();
            let p = format!("channels/{}", encode_name(&name));
            self.out.dir(&p, &format!("ch:{id}"))?;
            chan_path.insert(id.clone(), p);
            chan_name.insert(id, name);
        }
        let since = self.old.teams_since.map(|s| s - TEAMS_OVERLAP);
        // root id → (channel id, messages of the thread seen in the export)
        let mut threads: BTreeMap<String, (String, Vec<Value>)> = BTreeMap::new();
        let url = teams_export_url(self.c, t, since, 50);
        let r = self.g.pages(&url, &[], |m| {
            let Some(id) = m["id"].as_str() else { return Ok(()) };
            let root = m["replyToId"].as_str().unwrap_or(id).to_owned();
            let ch = m["channelIdentity"]["channelId"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            threads.entry(root).or_insert_with(|| (ch, Vec::new())).1.push(m);
            Ok(())
        });
        if let Err(e) = r {
            if graph::is_protected_api_denied(&e) {
                return Err(error(13, PROTECTED_API_HELP));
            }
            return Err(e);
        }
        let mut written: HashSet<String> = HashSet::new();
        for (root, (ch, mut msgs)) in threads {
            if since.is_some() {
                // only the changed messages came back: fetch the whole thread
                msgs.clear();
                let base = format!("/teams/{}/channels/{}/messages/{}", enc(t), seg(&ch), seg(&root));
                match self.g.get(&base, &[]) {
                    Ok(m) => msgs.push(m),
                    Err(e) if graph::status(&e) == Some(404) => {}
                    Err(e) if graph::is_protected_api_denied(&e) => return Err(error(13, PROTECTED_API_HELP)),
                    Err(e) => return Err(e),
                }
                self.g.pages(&format!("{base}/replies?$top=50"), &[], |m| {
                    msgs.push(m);
                    Ok(())
                })?;
            }
            let Some(cpath) = chan_path.get(&ch).cloned() else {
                self.ctx
                    .warn(format!("a thread of an unknown channel ({ch}) was skipped"));
                continue;
            };
            let root_msg = msgs.iter().find(|m| m["id"].as_str() == Some(root.as_str())).cloned();
            let mut replies: Vec<Value> = msgs
                .into_iter()
                .filter(|m| m["id"].as_str() != Some(root.as_str()))
                .collect();
            replies.sort_by(|a, b| a["createdDateTime"].as_str().cmp(&b["createdDateTime"].as_str()));
            replies.dedup_by(|a, b| a["id"] == b["id"]);
            let mtime = root_msg
                .iter()
                .chain(&replies)
                .map(|m| time_ns(&m["lastModifiedDateTime"]).max(time_ns(&m["createdDateTime"])))
                .max()
                .unwrap_or(0);
            let first = root_msg.as_ref().or(replies.first());
            let created = first
                .and_then(|m| m["createdDateTime"].as_str())
                .and_then(parse_time)
                .map(|ns| crate::format::short_stamp(ns.div_euclid(1_000_000_000)))
                .unwrap_or_default();
            let label = first
                .map(|m| {
                    m["subject"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| {
                            crate::format::body_text(&m["body"])
                                .chars()
                                .take(40)
                                .collect::<String>()
                        })
                })
                .unwrap_or_default();
            let xid = format!("t:{root}");
            let it = Item {
                name: item_name(&format!("{created} {label}"), &root, "json"),
                tag: format!("{mtime}/{}", replies.len()),
                mtime_ns: mtime,
            };
            let path = self.out.claim(format!("{cpath}/{}", it.name), &xid);
            written.insert(root.clone());
            if self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                continue;
            }
            let doc = json!({
                "channel": {"id": ch, "displayName": chan_name.get(&ch)},
                "root": root_msg,
                "replies": replies,
            });
            let b = serde_json::to_vec_pretty(&doc)?;
            self.out.bytes(&path, &xid, &it, &b)?;
        }
        if since.is_some() {
            // threads without changes since the last export: taken over from the base
            let base_threads: Vec<BaseEntry> = self
                .prev
                .entries
                .iter()
                .filter(|e| {
                    xattr(&e.meta, X_ID)
                        .and_then(|i| i.strip_prefix("t:"))
                        .is_some_and(|r| !written.contains(r))
                })
                .cloned()
                .collect();
            for b in base_threads {
                let xid = xattr(&b.meta, X_ID).unwrap_or_default().to_owned();
                let ch = self
                    .prev
                    .parent_id(&b)
                    .and_then(|p| p.strip_prefix("ch:"))
                    .map(str::to_owned);
                let it = Item::from_base(&b);
                let path = match ch.as_ref().and_then(|c| chan_path.get(c)) {
                    Some(cp) => format!("{cp}/{}", it.name),
                    None => {
                        // the channel is gone: keep the thread where it was
                        let pp = String::from_utf8_lossy(parent_path(&b.path).unwrap_or_default()).into_owned();
                        self.out.dir(&pp, &format!("ch:{}", ch.clone().unwrap_or_default()))?;
                        String::from_utf8_lossy(&b.path).into_owned()
                    }
                };
                let path = self.out.claim(path, &xid);
                if self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                    continue;
                }
                // moved (renamed channel): the thread must be sent again
                let root = xid.trim_start_matches("t:").to_owned();
                let Some(ch) = ch else { continue };
                let base = format!("/teams/{}/channels/{}/messages/{}", enc(t), seg(&ch), seg(&root));
                let mut msgs = Vec::new();
                match self.g.get(&base, &[]) {
                    Ok(m) => msgs.push(m),
                    Err(e) if graph::status(&e) == Some(404) => {}
                    Err(e) => return Err(e),
                }
                let root_msg = msgs.pop();
                let mut replies = Vec::new();
                self.g.pages(&format!("{base}/replies?$top=50"), &[], |m| {
                    replies.push(m);
                    Ok(())
                })?;
                replies.sort_by(|a, b| a["createdDateTime"].as_str().cmp(&b["createdDateTime"].as_str()));
                let doc = json!({
                    "channel": {"id": ch, "displayName": chan_name.get(&ch)},
                    "root": root_msg,
                    "replies": replies,
                });
                let b = serde_json::to_vec_pretty(&doc)?;
                self.out.bytes(&path, &xid, &it, &b)?;
            }
        }
        self.new.teams_since = Some(started);
        Ok(())
    }
}

/// Paths of mail folders (`<top>/<name>/<name>…`) from id → (parent id, name); folders
/// whose parent is not in the list hang below `<top>` (the mailbox root is not listed).
fn folder_paths(f: &HashMap<String, (Option<String>, String)>, top: &str) -> HashMap<String, String> {
    let mut out: HashMap<String, String> = HashMap::new();
    for id in f.keys() {
        let mut chain = Vec::new();
        let mut cur = Some(id.as_str());
        while let Some(c) = cur {
            if chain.len() > 64 || chain.contains(&c) {
                break;
            }
            let Some((parent, _)) = f.get(c) else { break };
            chain.push(c);
            cur = parent.as_deref();
        }
        let p = chain
            .iter()
            .rev()
            .map(|c| encode_name(&f[*c].1))
            .collect::<Vec<_>>()
            .join("/");
        out.insert(id.clone(), format!("{top}/{p}"));
    }
    // sibling folders with the same name (case-insensitive in Exchange, rare): disambiguate
    let mut seen: HashMap<String, u32> = HashMap::new();
    let mut ids: Vec<&String> = f.keys().collect();
    ids.sort();
    for id in ids {
        let p = out[id].clone();
        let n = seen.entry(p.to_lowercase()).or_insert(0);
        *n += 1;
        if *n > 1 {
            out.insert(id.clone(), format!("{p} ~{}", short_hash(id)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mail_folder_paths() {
        let f: HashMap<String, (Option<String>, String)> = [
            ("a", Some("root"), "Inbox"),
            ("b", Some("a"), "Projects/2026"),
            ("c", Some("root"), "Sent Items"),
            ("x", Some("y"), "loop"),
            ("y", Some("x"), "loop2"),
        ]
        .into_iter()
        .map(|(id, p, n)| (id.to_owned(), (p.map(str::to_owned), n.to_owned())))
        .collect();
        let p = folder_paths(&f, "mail");
        assert_eq!(p["a"], "mail/Inbox");
        assert_eq!(p["b"], "mail/Inbox/Projects%2F2026");
        assert_eq!(p["c"], "mail/Sent Items");
        assert!(p["x"].starts_with("mail/"), "cycles end");
    }

    #[test]
    fn prev_index() {
        let e = |p: &str, id: &str, kind: Kind| BaseEntry {
            path: p.as_bytes().to_vec(),
            meta: Meta {
                kind: Some(kind),
                xattrs: xattrs(id, Some("t1")),
                ..Default::default()
            },
        };
        let prev = Prev::new(vec![
            e("mail", "mail", Kind::Dir),
            e("mail/Inbox", "mf:1", Kind::Dir),
            e("mail/Inbox/a ~1.eml", "m:1", Kind::File),
            e("mail/Inbox/b ~2.eml", "m:2", Kind::File),
        ]);
        assert_eq!(prev.children("mf:1").count(), 2);
        assert_eq!(prev.get("m:2").unwrap().path, b"mail/Inbox/b ~2.eml");
        assert_eq!(prev.parent_id(prev.get("m:1").unwrap()), Some("mf:1"));
        assert_eq!(Item::from_base(prev.get("m:1").unwrap()).name, "a ~1.eml");
    }

    #[test]
    fn state_roundtrip() {
        let mut st = State::default();
        st.delta.insert("mail:1".into(), "https://graph/x?token=1".into());
        st.teams_since = Some(42);
        let raw = serde_json::to_vec(&json!({"v": 1, "delta": st.delta, "teams_since": 42})).unwrap();
        let back = State::load(Some(&raw));
        assert_eq!((back.delta, back.teams_since), (st.delta, Some(42)));
        assert!(State::load(Some(b"garbage")).delta.is_empty());
    }

    #[test]
    fn names_unique() {
        let v = vec![
            json!({"id": "2", "name": "Docs"}),
            json!({"id": "1", "name": "docs"}),
            json!({"id": "3", "name": "Other"}),
        ];
        let n: Vec<String> = unique_names(v, "name").into_iter().map(|x| x.0).collect();
        assert_eq!(n, ["docs", "Docs (2)", "Other"]);
    }
}
