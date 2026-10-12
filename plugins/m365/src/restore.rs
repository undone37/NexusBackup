//! Restores (`to_original`, `to_other`): the selected snapshot content is written
//! into a **new** folder of the original or another user / site / team, so nothing
//! that exists is ever overwritten:
//!
//! - mail → a new top-level mail folder (subfolders recreated), messages imported as MIME;
//!   Recoverable Items "Deletions" → `<folder>/Restored deleted items`;
//! - calendars → one new calendar per backed-up calendar (`<folder> – <name>`), events
//!   created from the Graph JSON in the `.ics` (without attendees: no invitations go out);
//! - contacts → a new contact folder with one subfolder per backed-up folder;
//! - OneDrive / team files → `<folder>/…` in the target's drive; site libraries →
//!   `<folder>/…` in the target site's library of the same name (else the default
//!   library, `<folder>/<library>/…`); uploads use `conflictBehavior=fail`;
//! - Teams threads → a new channel per backed-up channel created in migration mode
//!   (original authors and times), completed at the end; private / shared channel
//!   files → `<folder>/…` in the site of the target team's channel of the same name;
//! - Microsoft 365 groups: files (groups that are not teams) → `<folder>/…` in the
//!   group's drive. Conversations and the group calendar are download-only: Graph
//!   v1.0 offers no application permission to create group posts or group events.
//!
//! - chats (`chats/`) are download only.
//!
//! `to_other` may run into another Microsoft 365 tenant (another source of this
//! kind, job parameter `target_source_id`; the host then runs the plugin with that
//! source's config and credentials): tenant migration, recovery into a new tenant.
//! The target is resolved in that tenant; Teams messages are skipped there (their
//! authors are users of the original tenant, migration import needs them).
//!
//! Download (mail as .eml, events .ics, contacts .vcf, files as they are, threads
//! .json) is the appliance's generic download and never reaches the plugin.

use crate::format::{decode_name, embedded_graph, for_create, short_stamp};
use crate::graph::{self, enc, Graph};
use crate::{site_guest, Config, Guest};
use anyhow::{bail, Context};
use base64::Engine;
use plugin_sdk::proto::{parse_source_name, valid_path};
use plugin_sdk::{error, Ctx, FileItem, Kind, Result, Source};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

/// Name of the restore folder: printable, no characters SharePoint/OneDrive refuse.
fn folder_ok(s: &str) -> bool {
    !s.trim().is_empty()
        && s.chars().count() <= 100
        && s == s.trim()
        && !s.ends_with('.')
        && !s.chars().any(|c| c.is_control() || "\"*:<>?/\\|#%".contains(c))
}

/// Where restored items go.
struct Target {
    /// user / team id, or Graph site id
    id: String,
    folder: String,
    stamp: String,
    /// path of folders below the restore folder → id (per kind)
    mail: HashMap<Vec<String>, String>,
    calendars: HashMap<String, String>,
    contact_root: Option<String>,
    contacts: HashMap<String, String>,
    /// (drive, folder path) → item id
    dirs: HashMap<(String, Vec<String>), String>,
    drive: Option<String>,
    site_drives: Option<Vec<(String, String)>>,
    /// backed-up channel dir → new channel id
    channels: HashMap<String, String>,
    /// private / shared channel dir → drive of the target's channel of that name
    channel_drives: HashMap<String, Option<String>>,
    counts: HashMap<&'static str, u64>,
    /// restoring into another source (another M365 tenant)
    other_tenant: bool,
}

pub fn run(ctx: &Ctx, c: &Config, mut g: Graph, src: &mut Source) -> Result<String> {
    let action = ctx.params["restore"].as_str().unwrap_or_default();
    let p = &ctx.params["params"];
    let source = ctx.params["snapshot"]["source"].as_str().unwrap_or_default();
    let guest = ctx.params["guest"]
        .as_str()
        .map(str::to_owned)
        .or_else(|| parse_source_name(source).and_then(|x| x.2))
        .and_then(|g| Guest::parse(&g))
        .ok_or_else(|| error(22, "this snapshot is not one of a user, site, team or group"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let stamp = short_stamp(now);
    let folder = p["folder"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Restored {stamp}"));
    if !folder_ok(&folder) {
        return Err(error(22, "folder: 1–100 characters, none of \" * : < > ? / \\ | # %"));
    }
    let sp_host = c.sharepoint_host.clone().unwrap_or_default();
    let other_tenant = ctx.params["target_source_id"].is_u64();
    if other_tenant && action != "to_other" {
        return Err(error(
            22,
            "into another source only \"to another user / site / team\" restores",
        ));
    }
    let id = match action {
        "to_original" => match &guest {
            Guest::User(u) | Guest::Team(u) | Guest::Group(u) => u.clone(),
            Guest::Site(..) => guest.site_id(&sp_host).unwrap_or_default(),
        },
        "to_other" => {
            let t = p["target"].as_str().map(str::trim).filter(|t| !t.is_empty());
            let t = t.ok_or_else(|| error(22, "target: required"))?;
            resolve_target(&mut g, &guest, t)?
        }
        a => return Err(error(22, format!("unknown restore {a:?}"))),
    };
    let mut paths: Vec<Vec<u8>> = p["paths"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str())
        .map(|x| x.trim_matches('/').as_bytes().to_vec())
        .collect();
    if let Some(bad) = paths.iter().find(|x| !valid_path(x)) {
        return Err(error(
            22,
            format!("paths: {:?} is not a snapshot path", String::from_utf8_lossy(bad)),
        ));
    }
    if paths.is_empty() {
        paths = ctx.params["top"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str())
            .map(|x| x.as_bytes().to_vec())
            .collect();
    }
    let mut t = Target {
        id,
        folder,
        stamp,
        mail: HashMap::new(),
        calendars: HashMap::new(),
        contact_root: None,
        contacts: HashMap::new(),
        dirs: HashMap::new(),
        drive: None,
        site_drives: None,
        channels: HashMap::new(),
        channel_drives: HashMap::new(),
        counts: HashMap::new(),
        other_tenant,
    };
    ctx.info(format!(
        "restoring into {:?} of {}{}",
        t.folder,
        t.id,
        if other_tenant {
            format!(" (tenant {} of source {})", c.tenant_id, ctx.params["target_source_id"])
        } else {
            String::new()
        }
    ));
    let mut done = 0u64;
    let r = src.files(&paths, |item, data| {
        if item.meta.kind != Some(Kind::File) {
            return Ok(());
        }
        put(&mut g, &guest, &mut t, item, data).with_context(|| String::from_utf8_lossy(&item.path).into_owned())?;
        done += 1;
        if done.is_multiple_of(100) {
            ctx.progress(done, 0, format!("{done} items"));
        }
        Ok(())
    });
    // migration channels must be completed even if the restore failed half-way
    for (name, ch) in &t.channels {
        let url = format!("/teams/{}/channels/{}/completeMigration", enc(&t.id), enc(ch));
        if let Err(e) = g.post(&url, json!({})) {
            ctx.warn(format!("completing the restored channel {name:?} failed: {e:#}"));
        }
    }
    r?;
    let mut counts: Vec<String> = t.counts.iter().map(|(k, v)| format!("{v} {k}")).collect();
    counts.sort();
    Ok(format!(
        "restored {} into \"{}\" ({}; {} Graph requests, {} throttled)",
        if counts.is_empty() {
            "nothing".into()
        } else {
            counts.join(", ")
        },
        t.folder,
        t.id,
        g.stats.requests,
        g.stats.throttled
    ))
}

/// The target object of `to_other`, of the same type as the snapshot's guest:
/// user (UPN or id), site (URL `https://host/sites/x` or Graph site id), team (id or exact name).
fn resolve_target(g: &mut Graph, guest: &Guest, t: &str) -> Result<String> {
    let not_found = |e: anyhow::Error| match graph::status(&e) {
        Some(404) | Some(400) => error(22, format!("target {t:?} not found")),
        _ => e,
    };
    Ok(match guest {
        Guest::User(_) => g
            .get(&format!("/users/{}?$select=id", enc(t)), &[])
            .map_err(not_found)?["id"]
            .as_str()
            .context("user without id")?
            .to_owned(),
        Guest::Site(..) => {
            let path = if let Some(rest) = t.strip_prefix("https://") {
                let (host, p) = rest.split_once('/').unwrap_or((rest, ""));
                let p = p.trim_end_matches('/');
                if p.is_empty() {
                    format!("/sites/{}", enc(host))
                } else {
                    let segs: Vec<String> = p.split('/').map(enc).collect();
                    format!("/sites/{}:/{}", enc(host), segs.join("/"))
                }
            } else if site_guest(t).is_some() {
                format!("/sites/{}", enc(t))
            } else {
                return Err(error(
                    22,
                    "target: a site URL (https://contoso.sharepoint.com/sites/x) or site id",
                ));
            };
            g.get(&format!("{path}?$select=id"), &[]).map_err(not_found)?["id"]
                .as_str()
                .context("site without id")?
                .to_owned()
        }
        Guest::Team(_) | Guest::Group(_) => {
            let team = matches!(guest, Guest::Team(_));
            let (one, list) = if team {
                ("/teams", "/teams?$select=id,displayName&$top=999".to_owned())
            } else {
                ("/groups", format!("{}&$top=999", crate::UNIFIED_GROUPS))
            };
            let what = if team { "team" } else { "group" };
            let guid = t.len() == 36 && t.bytes().filter(|b| *b == b'-').count() == 4;
            if guid {
                g.get(&format!("{one}/{}?$select=id", enc(t)), &[]).map_err(not_found)?["id"]
                    .as_str()
                    .context("object without id")?
                    .to_owned()
            } else {
                let mut found = Vec::new();
                g.pages(&list, &[], |x| {
                    if x["displayName"].as_str() == Some(t) {
                        found.push(x["id"].as_str().unwrap_or_default().to_owned());
                    }
                    Ok(())
                })?;
                match found.len() {
                    1 => found.remove(0),
                    0 => return Err(error(22, format!("target: no {what} named {t:?}"))),
                    _ => {
                        return Err(error(
                            22,
                            format!("target: several {what}s are named {t:?}; use the {what} id"),
                        ))
                    }
                }
            }
        }
    })
}

fn segments(item: &FileItem) -> Vec<String> {
    String::from_utf8_lossy(&item.path)
        .split('/')
        .map(str::to_owned)
        .collect()
}

fn read_all(data: &mut dyn Read, size: u64) -> Result<Vec<u8>> {
    let mut b = Vec::with_capacity(size.min(256 << 20) as usize);
    data.read_to_end(&mut b)?;
    Ok(b)
}

fn put(g: &mut Graph, guest: &Guest, t: &mut Target, item: &FileItem, data: &mut dyn Read) -> Result<()> {
    let s = segments(item);
    match (guest, s[0].as_str()) {
        (Guest::User(_), "mail") if s.len() >= 3 => {
            let fid = mail_folder(g, t, &s[1..s.len() - 1])?;
            let mime = read_all(data, item.meta.size)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&mime);
            let url = g.url(&format!("/users/{}/mailFolders/{}/messages", enc(&t.id), enc(&fid)));
            g.call(
                reqwest::Method::POST,
                &url,
                graph::Body::Bytes(b64.into_bytes(), "text/plain"),
                &[],
            )?;
            *t.counts.entry("messages").or_default() += 1;
        }
        (Guest::User(_), "recoverable") if s.len() >= 3 => {
            let mut names = vec!["Restored deleted items".to_owned()];
            names.extend(s[2..s.len() - 1].iter().cloned());
            let fid = mail_folder(g, t, &names)?;
            let mime = read_all(data, item.meta.size)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&mime);
            let url = g.url(&format!("/users/{}/mailFolders/{}/messages", enc(&t.id), enc(&fid)));
            g.call(
                reqwest::Method::POST,
                &url,
                graph::Body::Bytes(b64.into_bytes(), "text/plain"),
                &[],
            )?;
            *t.counts.entry("deleted messages").or_default() += 1;
        }
        (Guest::Group(_), "conversations" | "calendar") => {
            *t.counts
                .entry("group conversations / events (download only, skipped)")
                .or_default() += 1;
        }
        (Guest::Team(_), "channel-files") if s.len() >= 3 => {
            if !t.channel_drives.contains_key(&s[1]) {
                let d = private_channel_drive(g, &t.id, &decode_name(&s[1]))?;
                t.channel_drives.insert(s[1].clone(), d);
            }
            let Some(drive) = t.channel_drives[&s[1]].clone() else {
                *t.counts
                    .entry("channel files without a private/shared channel of that name (skipped)")
                    .or_default() += 1;
                return Ok(());
            };
            let mut dir = vec![t.folder.clone()];
            dir.extend(s[2..s.len() - 1].iter().map(|x| decode_name(x)));
            upload(g, t, &drive, dir, &decode_name(&s[s.len() - 1]), item.meta.size, data)?;
        }
        (Guest::User(_), "calendar") if s.len() == 3 => {
            let Some(ev) = embedded_graph(&String::from_utf8_lossy(&read_all(data, item.meta.size)?)) else {
                bail!("not an event of this plugin (no {})", crate::format::GRAPH_PROP);
            };
            let cal = match t.calendars.get(&s[1]) {
                Some(c) => c.clone(),
                None => {
                    let name = format!("{} – {}", t.folder, decode_name(&s[1]));
                    let c = g.post(&format!("/users/{}/calendars", enc(&t.id)), json!({"name": name}))?;
                    let id = c["id"].as_str().context("calendar without id")?.to_owned();
                    t.calendars.insert(s[1].clone(), id.clone());
                    id
                }
            };
            g.post(
                &format!("/users/{}/calendars/{}/events", enc(&t.id), enc(&cal)),
                for_create(ev, true),
            )?;
            *t.counts.entry("events").or_default() += 1;
        }
        (Guest::User(_), "contacts") if s.len() >= 3 => {
            let Some(p) = embedded_graph(&String::from_utf8_lossy(&read_all(data, item.meta.size)?)) else {
                bail!("not a contact of this plugin (no {})", crate::format::GRAPH_PROP);
            };
            let key = s[1..s.len() - 1].join("/");
            let fid = match t.contacts.get(&key) {
                Some(f) => f.clone(),
                None => {
                    let root = match &t.contact_root {
                        Some(r) => r.clone(),
                        None => {
                            let r = g.post(
                                &format!("/users/{}/contactFolders", enc(&t.id)),
                                json!({"displayName": t.folder}),
                            )?;
                            let r = r["id"].as_str().context("contact folder without id")?.to_owned();
                            t.contact_root = Some(r.clone());
                            r
                        }
                    };
                    let name: Vec<String> = s[1..s.len() - 1].iter().map(|x| decode_name(x)).collect();
                    let f = g.post(
                        &format!("/users/{}/contactFolders/{}/childFolders", enc(&t.id), enc(&root)),
                        json!({"displayName": name.join(" – ")}),
                    )?;
                    let f = f["id"].as_str().context("contact folder without id")?.to_owned();
                    t.contacts.insert(key, f.clone());
                    f
                }
            };
            g.post(
                &format!("/users/{}/contactFolders/{}/contacts", enc(&t.id), enc(&fid)),
                for_create(p, false),
            )?;
            *t.counts.entry("contacts").or_default() += 1;
        }
        (Guest::User(_), "onedrive") | (Guest::Team(_) | Guest::Group(_), "files") if s.len() >= 2 => {
            let drive = match &t.drive {
                Some(d) => d.clone(),
                None => {
                    let url = match guest {
                        Guest::User(_) => format!("/users/{}/drive?$select=id", enc(&t.id)),
                        _ => format!("/groups/{}/drive?$select=id", enc(&t.id)),
                    };
                    let d = g.get(&url, &[])?["id"].as_str().context("drive without id")?.to_owned();
                    t.drive = Some(d.clone());
                    d
                }
            };
            let mut dir = vec![t.folder.clone()];
            dir.extend(s[1..s.len() - 1].iter().map(|x| decode_name(x)));
            upload(g, t, &drive, dir, &decode_name(&s[s.len() - 1]), item.meta.size, data)?;
        }
        (Guest::Site(..), "libraries") if s.len() >= 3 => {
            if t.site_drives.is_none() {
                let mut v = Vec::new();
                g.pages(&format!("/sites/{}/drives?$select=id,name", enc(&t.id)), &[], |d| {
                    v.push((
                        d["name"].as_str().unwrap_or_default().to_owned(),
                        d["id"].as_str().unwrap_or_default().to_owned(),
                    ));
                    Ok(())
                })?;
                t.site_drives = Some(v);
            }
            let lib = decode_name(&s[1]);
            let same = t
                .site_drives
                .iter()
                .flatten()
                .find(|(n, _)| n.eq_ignore_ascii_case(&lib))
                .map(|x| x.1.clone());
            let (drive, mut dir) = match same {
                Some(d) => (d, vec![t.folder.clone()]),
                None => {
                    let d = match &t.drive {
                        Some(d) => d.clone(),
                        None => {
                            let d = g.get(&format!("/sites/{}/drive?$select=id", enc(&t.id)), &[])?["id"]
                                .as_str()
                                .context("drive without id")?
                                .to_owned();
                            t.drive = Some(d.clone());
                            d
                        }
                    };
                    (d, vec![t.folder.clone(), lib])
                }
            };
            dir.extend(s[2..s.len() - 1].iter().map(|x| decode_name(x)));
            upload(g, t, &drive, dir, &decode_name(&s[s.len() - 1]), item.meta.size, data)?;
        }
        (Guest::User(_), "chats") => {
            *t.counts.entry("chat files (download only, skipped)").or_default() += 1;
        }
        (Guest::Team(_), "channels") if t.other_tenant => {
            *t.counts.entry("channel messages (other tenant, skipped)").or_default() += 1;
        }
        (Guest::Team(_), "channels") if s.len() == 3 => {
            let doc: Value = serde_json::from_slice(&read_all(data, item.meta.size)?).context("thread JSON")?;
            let ch = match t.channels.get(&s[1]) {
                Some(c) => c.clone(),
                None => {
                    let mut name = format!("{} (restored {})", decode_name(&s[1]), t.stamp);
                    if name.chars().count() > 50 {
                        name = name.chars().take(50).collect();
                    }
                    let c = g.post(
                        &format!("/teams/{}/channels", enc(&t.id)),
                        json!({
                            "@microsoft.graph.channelCreationMode": "migration",
                            "displayName": name.trim(),
                            "description": format!("Restored by NexusBackup ({})", t.folder),
                            "membershipType": "standard",
                            "createdDateTime": "2000-01-01T00:00:00Z",
                        }),
                    )?;
                    let id = c["id"].as_str().context("channel without id")?.to_owned();
                    t.channels.insert(s[1].clone(), id.clone());
                    id
                }
            };
            let base = format!("/teams/{}/channels/{}/messages", enc(&t.id), enc(&ch));
            let Some(root) = doc["root"].as_object().map(|_| &doc["root"]) else {
                *t.counts.entry("threads without root (skipped)").or_default() += 1;
                return Ok(());
            };
            if !importable(root) {
                *t.counts.entry("messages not importable (skipped)").or_default() += 1;
                return Ok(());
            }
            let r = g.post(&base, import(root))?;
            let rid = r["id"].as_str().context("message without id")?.to_owned();
            *t.counts.entry("channel messages").or_default() += 1;
            for rep in doc["replies"].as_array().into_iter().flatten() {
                if importable(rep) {
                    g.post(&format!("{base}/{}/replies", enc(&rid)), import(rep))?;
                    *t.counts.entry("channel messages").or_default() += 1;
                } else {
                    *t.counts.entry("messages not importable (skipped)").or_default() += 1;
                }
            }
        }
        _ => {
            *t.counts.entry("unknown items (skipped)").or_default() += 1;
        }
    }
    Ok(())
}

/// Files drive of the target team's private or shared channel named `name`.
fn private_channel_drive(g: &mut Graph, team: &str, name: &str) -> Result<Option<String>> {
    let mut id = None;
    g.pages(
        &format!("/teams/{}/channels?$select=id,displayName,membershipType", enc(team)),
        &[],
        |c| {
            if crate::separate_channel(&c) && c["displayName"].as_str() == Some(name) {
                id = c["id"].as_str().map(str::to_owned);
            }
            Ok(())
        },
    )?;
    match id {
        Some(ch) => crate::channel_drive(g, team, &ch),
        None => Ok(None),
    }
}

/// Messages Graph can import: from a user, not deleted.
fn importable(m: &Value) -> bool {
    m["from"]["user"]["id"].is_string() && m["deletedDateTime"].is_null()
}

fn import(m: &Value) -> Value {
    let mut v = json!({
        "createdDateTime": m["createdDateTime"],
        "from": {"user": {
            "id": m["from"]["user"]["id"],
            "displayName": m["from"]["user"]["displayName"],
            "userIdentityType": "aadUser",
        }},
        "body": m["body"],
    });
    if let Some(s) = m["subject"].as_str().filter(|s| !s.is_empty()) {
        v["subject"] = json!(s);
    }
    v
}

/// Mail folder `<restore folder>/<names…>` in the target mailbox (created on demand).
fn mail_folder(g: &mut Graph, t: &mut Target, names: &[String]) -> Result<String> {
    let mut key: Vec<String> = Vec::new();
    let mut parent: Option<String> = None;
    for n in std::iter::once(t.folder.clone()).chain(names.iter().map(|x| decode_name(x))) {
        key.push(n.clone());
        if let Some(id) = t.mail.get(&key) {
            parent = Some(id.clone());
            continue;
        }
        let url = match &parent {
            None => format!("/users/{}/mailFolders", enc(&t.id)),
            Some(p) => format!("/users/{}/mailFolders/{}/childFolders", enc(&t.id), enc(p)),
        };
        let f = g.post(&url, json!({"displayName": n}))?;
        let id = f["id"].as_str().context("mail folder without id")?.to_owned();
        t.mail.insert(key.clone(), id.clone());
        parent = Some(id);
    }
    parent.context("no mail folder")
}

/// Uploads one file to `dir` (created on demand; the first component is the new restore folder).
fn upload(
    g: &mut Graph,
    t: &mut Target,
    drive: &str,
    dir: Vec<String>,
    name: &str,
    size: u64,
    data: &mut dyn Read,
) -> Result<()> {
    let mut parent = "root".to_owned();
    for i in 0..dir.len() {
        let key = (drive.to_owned(), dir[..=i].to_vec());
        if let Some(id) = t.dirs.get(&key) {
            parent = id.clone();
            continue;
        }
        let f = g.post(
            &format!("/drives/{}/items/{}/children", enc(drive), enc(&parent)),
            json!({"name": dir[i], "folder": {}, "@microsoft.graph.conflictBehavior": "fail"}),
        );
        let f = match f {
            Err(e) if i == 0 && graph::status(&e) == Some(409) => {
                return Err(error(
                    17,
                    format!(
                        "the folder {:?} exists already in the target; choose another folder name",
                        dir[0]
                    ),
                ))
            }
            r => r?,
        };
        parent = f["id"].as_str().context("folder without id")?.to_owned();
        t.dirs.insert(key, parent.clone());
    }
    g.upload(
        &format!("/drives/{}/items/{}:/{}:", enc(drive), enc(&parent), enc(name)),
        size,
        data,
    )?;
    *t.counts.entry("files").or_default() += 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_names() {
        assert!(folder_ok("Restored 2026-10-11 1430"));
        for bad in ["", " x", "a/b", "a:b", "x.", &"x".repeat(101), "a#b"] {
            assert!(!folder_ok(bad), "{bad:?}");
        }
    }
}
