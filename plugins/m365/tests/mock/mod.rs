//! A local Microsoft Graph + Entra token endpoint mock (HTTPS, HTTP/1.1, one thread
//! per connection) for the M365 plugin's tests and for development
//! (`cargo run -p m365-plugin --example graph-mock`). It implements the subset of
//! Graph v1.0 the plugin uses, with the behaviour that matters for backups:
//!
//! - token endpoint: client-credentials grant with a client assertion; the JWT is
//!   verified like Entra does (PS256 signature with the registered certificate's key,
//!   `x5t#S256`, `aud` = token URL, `iss` = `sub` = client id, `exp`/`nbf`, `jti` replay);
//! - every Graph call needs a valid, unexpired bearer token (401 otherwise);
//! - delta queries (mail messages per folder, drives) with delta links; paging with
//!   `@odata.nextLink` (page size settable);
//! - injectable throttling (429/503 + `Retry-After`), token revocation, broken
//!   download ranges, protected Teams APIs denied;
//! - downloads via a 302 redirect to a range-capable URL, uploads (simple PUT and
//!   upload sessions with `Content-Range`), folder / message / event / contact /
//!   channel creation, Teams migration-mode channels.

#![allow(dead_code)]

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const TENANT: &str = "contoso.onmicrosoft.com";
pub const CLIENT_ID: &str = "11111111-2222-3333-4444-555555555555";
pub const SP_HOST: &str = "contoso.sharepoint.com";
pub const CERT: &str = include_str!("../data/test-app.crt");
pub const KEY: &str = include_str!("../data/test-app.key");
/// Fixed "old" time of seeded objects (2026-01-01T00:00:00Z).
pub const OLD: i64 = 1_767_225_600;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

pub fn iso(secs: i64) -> String {
    m365_plugin::format::rfc3339(secs)
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub upn: String,
    pub name: String,
    pub member: bool,
    pub mailbox: bool,
    pub drive: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Folder {
    pub id: String,
    pub user: String,
    pub parent: Option<String>,
    pub name: String,
    pub seq: u64,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct Msg {
    pub id: String,
    pub user: String,
    pub folder: String,
    pub subject: String,
    pub mime: Vec<u8>,
    pub change_key: String,
    pub modified: i64,
    pub seq: u64,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub drive: String,
    pub parent: Option<String>,
    pub name: String,
    pub folder: bool,
    pub content: Vec<u8>,
    pub modified: i64,
    pub ctag: String,
    pub seq: u64,
    pub deleted: bool,
}

#[derive(Clone, Debug)]
pub struct Site {
    pub id: String,
    pub name: String,
    pub url: String,
    pub personal: bool,
    pub drives: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub drive: String,
    /// (id, name, migration mode, completed)
    pub channels: Vec<(String, String, bool, bool)>,
}

/// One injected failure: requests whose path contains `path` get `status` (`count` times).
#[derive(Clone, Debug)]
pub struct Fault {
    pub path: String,
    pub status: u16,
    pub count: u32,
}

#[derive(Default)]
pub struct Tenant {
    pub port: u16,
    pub seq: u64,
    pub n: u64,
    pub users: Vec<User>,
    pub folders: Vec<Folder>,
    pub messages: Vec<Msg>,
    /// calendars (id, user, name) and events (calendar id, json)
    pub calendars: Vec<(String, String, String)>,
    pub events: Vec<(String, Value)>,
    /// contact folders (id, user, parent folder id or None = top level, name); contacts (folder id or "default-<user>", json)
    pub contact_folders: Vec<(String, String, Option<String>, String)>,
    pub contacts: Vec<(String, Value)>,
    pub drives: Vec<(String, String)>,
    pub items: Vec<Item>,
    pub sites: Vec<Site>,
    pub teams: Vec<Team>,
    /// chat messages (team, json with "_seq"/"_modified" stripped on output)
    pub chat: Vec<(String, Value)>,
    // controls
    pub page_size: usize,
    pub faults: Vec<Fault>,
    pub protected_api: bool,
    pub token_lifetime: u64,
    /// the certificate registered on the app (`x5t#S256`)
    pub registered: String,
    pub public_key: Vec<u8>,
    pub revoke_after: Option<u32>,
    pub break_downloads: u32,
    pub deny: HashSet<String>,
    // observations
    pub tokens: HashMap<String, i64>,
    pub jtis: HashSet<String>,
    pub assertions_ok: u32,
    pub requests: Vec<String>,
    sessions: HashMap<String, (String, String, String, Vec<u8>)>,
}

pub struct Mock {
    pub port: u16,
    pub ca_pem: String,
    pub t: Arc<Mutex<Tenant>>,
}

struct Req {
    method: String,
    path: String,
    raw_query: Vec<(String, String)>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Req {
    fn q(&self, k: &str) -> Option<String> {
        self.raw_query.iter().find(|(n, _)| n == k).map(|(_, v)| pct_decode(v))
    }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// send only this many body bytes, then close (a broken download)
    cut: Option<usize>,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            o.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
            i += 3;
            continue;
        }
        o.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&o).into_owned()
}

fn j(status: u16, v: Value) -> Resp {
    Resp {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: v.to_string().into_bytes(),
        cut: None,
    }
}

fn gerr(status: u16, code: &str, message: &str) -> Resp {
    j(status, json!({"error": {"code": code, "message": message}}))
}

fn not_found() -> Resp {
    gerr(404, "itemNotFound", "The resource could not be found.")
}

pub const PROTECTED: &str = "Invoked API requires Protected API access in application-only context when not using \
Resource Specific Consent. Visit https://docs.microsoft.com/en-us/graph/teams-protected-apis for more details.";

pub fn mime(subject: &str, body: &str, id: &str) -> Vec<u8> {
    format!(
        "From: Alice <alice@contoso.test>\r\nTo: Bob <bob@contoso.test>\r\nSubject: {subject}\r\n\
         Date: Thu, 01 Jan 2026 10:00:00 +0000\r\nMessage-ID: <{}@mock>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n",
        B64URL.encode(id)
    )
    .into_bytes()
}

impl Tenant {
    fn bump(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn next(&mut self) -> u64 {
        self.n += 1;
        self.n
    }

    pub fn guid(&mut self) -> String {
        let n = self.next();
        format!("{n:08x}-1234-4abc-8def-{:012x}", n * 7919)
    }

    /// Exchange-like id with characters that must be URL-encoded.
    fn exid(&mut self, p: &str) -> String {
        let n = self.next();
        format!("AAMk{p}{n}+/x=")
    }

    pub fn add_user(&mut self, name: &str, mailbox: bool, onedrive: bool) -> String {
        let id = self.guid();
        let drive = onedrive.then(|| {
            let d = format!("b!user{}", self.next());
            self.drives.push((d.clone(), format!("OneDrive {name}")));
            self.root(&d);
            d
        });
        self.users.push(User {
            id: id.clone(),
            upn: format!("{}@contoso.test", name.to_lowercase()),
            name: name.into(),
            member: true,
            mailbox,
            drive,
        });
        if mailbox {
            self.calendars
                .push((format!("cal-{id}"), id.clone(), "Calendar".into()));
        }
        id
    }

    fn root(&mut self, drive: &str) -> String {
        let id = format!("root-{drive}");
        let seq = self.bump();
        self.items.push(Item {
            id: id.clone(),
            drive: drive.into(),
            parent: None,
            name: "root".into(),
            folder: true,
            content: vec![],
            modified: OLD,
            ctag: String::new(),
            seq,
            deleted: false,
        });
        id
    }

    pub fn drive_root(&self, drive: &str) -> String {
        format!("root-{drive}")
    }

    pub fn user_drive(&self, user: &str) -> String {
        self.users.iter().find(|u| u.id == user).unwrap().drive.clone().unwrap()
    }

    pub fn add_folder(&mut self, user: &str, parent: Option<&str>, name: &str) -> String {
        let id = self.exid("fold");
        let seq = self.bump();
        self.folders.push(Folder {
            id: id.clone(),
            user: user.into(),
            parent: Some(parent.map_or_else(|| format!("msgfolderroot-{user}"), str::to_owned)),
            name: name.into(),
            seq,
            deleted: false,
        });
        id
    }

    pub fn folder_by_name(&self, user: &str, name: &str) -> Option<&Folder> {
        self.folders
            .iter()
            .find(|f| f.user == user && f.name == name && !f.deleted)
    }

    pub fn add_message(&mut self, user: &str, folder: &str, subject: &str, body: &str) -> String {
        let id = self.exid("msg");
        let seq = self.bump();
        self.messages.push(Msg {
            mime: mime(subject, body, &id),
            id: id.clone(),
            user: user.into(),
            folder: folder.into(),
            subject: subject.into(),
            change_key: format!("ck{seq}"),
            modified: OLD + seq as i64,
            seq,
            deleted: false,
        });
        id
    }

    pub fn msg(&mut self, id: &str) -> &mut Msg {
        self.messages.iter_mut().find(|m| m.id == id).unwrap()
    }

    pub fn update_message(&mut self, id: &str, subject: &str, body: &str) {
        let seq = self.bump();
        let m = self.msg(id);
        m.subject = subject.into();
        m.mime = mime(subject, body, id);
        m.change_key = format!("ck{seq}");
        m.modified = OLD + seq as i64;
        m.seq = seq;
    }

    pub fn move_message(&mut self, id: &str, folder: &str) {
        // with immutable ids a move keeps the id: removed from one folder's delta, added to the other's
        let seq = self.bump();
        let m = self.msg(id);
        m.folder = folder.into();
        m.seq = seq;
    }

    pub fn delete_message(&mut self, id: &str) {
        let seq = self.bump();
        let m = self.msg(id);
        m.deleted = true;
        m.seq = seq;
    }

    pub fn add_event(&mut self, user: &str, subject: &str) -> String {
        let id = self.exid("ev");
        let seq = self.bump();
        let ev = json!({
            "id": id, "iCalUId": format!("uid-{id}"), "subject": subject, "changeKey": format!("ck{seq}"),
            "lastModifiedDateTime": iso(OLD + seq as i64), "createdDateTime": iso(OLD),
            "start": {"dateTime": "2026-10-12T09:00:00.0000000", "timeZone": "UTC"},
            "end": {"dateTime": "2026-10-12T10:00:00.0000000", "timeZone": "UTC"},
            "body": {"contentType": "html", "content": format!("<p>{subject} agenda</p>")},
            "attendees": [{"type": "required", "emailAddress": {"name": "Bob", "address": "bob@contoso.test"}}],
            "organizer": {"emailAddress": {"name": "Alice", "address": "alice@contoso.test"}},
            "isAllDay": false,
        });
        self.events.push((format!("cal-{user}"), ev));
        id
    }

    pub fn add_contact(&mut self, user: &str, folder: Option<&str>, name: &str) -> String {
        let id = self.exid("ct");
        let seq = self.bump();
        let c = json!({
            "id": id, "displayName": name, "givenName": name.split(' ').next(), "surname": name.split(' ').nth(1),
            "emailAddresses": [{"address": format!("{}@example.test", name.to_lowercase().replace(' ', "."))}],
            "changeKey": format!("ck{seq}"), "lastModifiedDateTime": iso(OLD + seq as i64),
        });
        self.contacts
            .push((folder.map_or_else(|| format!("default-{user}"), str::to_owned), c));
        id
    }

    pub fn add_contact_folder(&mut self, user: &str, parent: Option<&str>, name: &str) -> String {
        let id = self.exid("cf");
        self.contact_folders
            .push((id.clone(), user.into(), parent.map(str::to_owned), name.into()));
        id
    }

    pub fn add_item(&mut self, drive: &str, parent: &str, name: &str, content: Option<Vec<u8>>) -> String {
        let id = format!("01ITEM{}", self.next());
        let seq = self.bump();
        self.items.push(Item {
            id: id.clone(),
            drive: drive.into(),
            parent: Some(parent.into()),
            name: name.into(),
            folder: content.is_none(),
            content: content.unwrap_or_default(),
            modified: OLD + seq as i64,
            ctag: format!("\"c:{{{id}}},{seq}\""),
            seq,
            deleted: false,
        });
        id
    }

    pub fn item(&mut self, id: &str) -> &mut Item {
        self.items.iter_mut().find(|i| i.id == id).unwrap()
    }

    pub fn update_item(&mut self, id: &str, content: Vec<u8>) {
        let seq = self.bump();
        let i = self.item(id);
        i.content = content;
        i.modified = OLD + seq as i64;
        i.ctag = format!("\"c:{{{id}}},{seq}\"");
        i.seq = seq;
    }

    pub fn rename_item(&mut self, id: &str, name: &str) {
        let seq = self.bump();
        let i = self.item(id);
        i.name = name.into();
        i.seq = seq;
    }

    /// Deletes an item; like OneDrive, children of a deleted folder are not reported separately.
    pub fn delete_item(&mut self, id: &str) {
        let seq = self.bump();
        let i = self.item(id);
        i.deleted = true;
        i.seq = seq;
    }

    /// Items (with paths) of a drive below its root, for assertions.
    pub fn tree(&self, drive: &str) -> Vec<(String, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        for i in self
            .items
            .iter()
            .filter(|i| i.drive == drive && !i.deleted && i.parent.is_some())
        {
            let mut p = vec![i.name.clone()];
            let mut cur = i.parent.clone();
            let mut alive = true;
            while let Some(c) = cur {
                let Some(x) = self.items.iter().find(|x| x.id == c) else {
                    break;
                };
                if x.deleted {
                    alive = false;
                }
                if x.parent.is_none() {
                    break;
                }
                p.push(x.name.clone());
                cur = x.parent.clone();
            }
            if alive {
                p.reverse();
                out.push((p.join("/"), (!i.folder).then(|| i.content.clone())));
            }
        }
        out.sort();
        out
    }

    pub fn add_site(&mut self, name: &str, libraries: &[&str]) -> String {
        let (s, w) = (self.guid(), self.guid());
        let id = format!("{SP_HOST},{s},{w}");
        let mut drives = Vec::new();
        for l in libraries {
            let d = format!("b!site{}", self.next());
            self.drives.push((d.clone(), (*l).to_owned()));
            self.root(&d);
            drives.push(d);
        }
        self.sites.push(Site {
            id: id.clone(),
            name: name.into(),
            url: format!("https://{SP_HOST}/sites/{}", name.to_lowercase()),
            personal: false,
            drives,
        });
        id
    }

    pub fn site(&self, id: &str) -> &Site {
        self.sites.iter().find(|s| s.id == id).unwrap()
    }

    pub fn add_team(&mut self, name: &str, channels: &[&str]) -> String {
        let id = self.guid();
        let d = format!("b!team{}", self.next());
        self.drives.push((d.clone(), "Documents".into()));
        self.root(&d);
        let mut ch = Vec::new();
        for c in channels {
            ch.push((
                format!("19:{}@thread.tacv2", self.next()),
                (*c).to_owned(),
                false,
                false,
            ));
        }
        self.teams.push(Team {
            id: id.clone(),
            name: name.into(),
            drive: d,
            channels: ch,
        });
        id
    }

    pub fn team(&self, id: &str) -> &Team {
        self.teams.iter().find(|t| t.id == id).unwrap()
    }

    /// A channel message (root if `reply_to` is None); `modified` defaults to an old time.
    pub fn add_chat(
        &mut self,
        team: &str,
        channel: &str,
        user: &str,
        text: &str,
        reply_to: Option<&str>,
        modified: Option<i64>,
    ) -> String {
        let id = format!("{}", 1_700_000_000_000u64 + self.next());
        let seq = self.bump();
        let t = modified.unwrap_or(OLD + seq as i64);
        let m = json!({
            "id": id, "replyToId": reply_to, "messageType": "message",
            "createdDateTime": iso(t), "lastModifiedDateTime": iso(t), "deletedDateTime": null,
            "subject": if reply_to.is_none() { json!(format!("Topic {text}")) } else { Value::Null },
            "from": {"user": {"id": user, "displayName": "Alice", "userIdentityType": "aadUser"}},
            "body": {"contentType": "html", "content": format!("<p>{text}</p>")},
            "channelIdentity": {"teamId": team, "channelId": channel},
        });
        self.chat.push((team.into(), m));
        id
    }

    pub fn edit_chat(&mut self, id: &str, text: &str, modified: i64) {
        let m = &mut self.chat.iter_mut().find(|(_, m)| m["id"] == id).unwrap().1;
        m["body"]["content"] = json!(format!("<p>{text}</p>"));
        m["lastModifiedDateTime"] = json!(iso(modified));
    }

    fn origin(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn item_json(&self, i: &Item) -> Value {
        let mut v = json!({
            "id": i.id, "name": i.name, "lastModifiedDateTime": iso(i.modified),
            "eTag": format!("\"{{{}}},{}\"", i.id, i.seq),
            "parentReference": {"id": i.parent, "driveId": i.drive},
        });
        if i.deleted {
            v["deleted"] = json!({"state": "deleted"});
        } else if i.parent.is_none() {
            v["root"] = json!({});
            v["folder"] = json!({"childCount": 0});
        } else if i.folder {
            v["folder"] = json!({"childCount": 0});
        } else {
            v["file"] = json!({"mimeType": "application/octet-stream"});
            v["size"] = json!(i.content.len());
            v["cTag"] = json!(i.ctag);
        }
        v
    }

    // ---- paging -------------------------------------------------------------------

    /// One page of `all`; nextLink with `skip`, the last page of a delta query a deltaLink.
    fn page(&self, req: &Req, all: Vec<Value>, delta_upto: Option<u64>) -> Resp {
        let skip: usize = req.q("skip").and_then(|s| s.parse().ok()).unwrap_or(0);
        let n = self.page_size.max(1);
        let keep: Vec<(String, String)> = req
            .raw_query
            .iter()
            .filter(|(k, _)| !["skip", "token", "upto"].contains(&k.as_str()))
            .cloned()
            .collect();
        let qs = |extra: &[(&str, String)]| {
            let mut parts: Vec<String> = keep.iter().map(|(k, v)| format!("{k}={v}")).collect();
            parts.extend(extra.iter().map(|(k, v)| format!("{k}={v}")));
            format!("{}{}?{}", self.origin(), req.path, parts.join("&"))
        };
        let end = (skip + n).min(all.len());
        let mut v = json!({"value": all.get(skip..end).unwrap_or_default()});
        let mut extra: Vec<(&str, String)> = Vec::new();
        if let Some(t) = req.q("token") {
            extra.push(("token", t));
        }
        if let Some(u) = delta_upto {
            extra.push(("upto", u.to_string()));
        }
        if end < all.len() {
            let mut e = extra.clone();
            e.push(("skip", end.to_string()));
            v["@odata.nextLink"] = json!(qs(&e));
        } else if let Some(u) = delta_upto {
            v["@odata.deltaLink"] = json!(qs(&[("token", u.to_string())]));
        }
        j(200, v)
    }

    /// (token, upto) of a delta request.
    fn delta_window(&self, req: &Req) -> (Option<u64>, u64) {
        let token = req.q("token").and_then(|t| t.parse().ok());
        let upto = req.q("upto").and_then(|t| t.parse().ok()).unwrap_or(self.seq);
        (token, upto)
    }

    // ---- token endpoint -------------------------------------------------------------

    fn token(&mut self, tenant: &str, req: &Req) -> Resp {
        let bad = |status: u16, err: &str, desc: &str| {
            j(
                status,
                json!({"error": err, "error_description": desc, "error_codes": [0]}),
            )
        };
        if tenant != TENANT {
            return bad(
                400,
                "invalid_request",
                &format!(
                    "AADSTS90002: Tenant '{tenant}' not found. Check to make sure you have the correct tenant ID."
                ),
            );
        }
        let form: HashMap<String, String> = String::from_utf8_lossy(&req.body)
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_owned(), pct_decode(v)))
            .collect();
        let f = |k: &str| form.get(k).cloned().unwrap_or_default();
        if f("grant_type") != "client_credentials"
            || f("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            || !f("scope").ends_with("/.default")
        {
            return bad(
                400,
                "invalid_request",
                "AADSTS900144: malformed client credentials request",
            );
        }
        if f("client_id") != CLIENT_ID {
            return bad(
                400,
                "unauthorized_client",
                &format!(
                    "AADSTS700016: Application with identifier '{}' was not found in the directory.",
                    f("client_id")
                ),
            );
        }
        let jwt = f("client_assertion");
        let parts: Vec<&str> = jwt.split('.').collect();
        let fail = |m: &str| {
            bad(
                401,
                "invalid_client",
                &format!("AADSTS700027: Client assertion failed signature validation. ({m})"),
            )
        };
        if parts.len() != 3 {
            return fail("not a JWT");
        }
        let dec = |s: &str| -> Value {
            B64URL
                .decode(s)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null)
        };
        let (h, c) = (dec(parts[0]), dec(parts[1]));
        if h["alg"] != "PS256" || h["typ"] != "JWT" {
            return fail("alg");
        }
        if h["x5t#S256"].as_str() != Some(self.registered.as_str()) {
            return fail("unknown certificate");
        }
        let sig = B64URL.decode(parts[2]).unwrap_or_default();
        let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PSS_2048_8192_SHA256, &self.public_key);
        if pk
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .is_err()
        {
            return fail("signature");
        }
        let aud = format!("{}/{TENANT}/oauth2/v2.0/token", self.origin());
        let t = now();
        if c["aud"] != aud.as_str()
            || c["iss"] != CLIENT_ID
            || c["sub"] != CLIENT_ID
            || c["exp"].as_i64().is_none_or(|e| e < t)
            || c["nbf"].as_i64().is_none_or(|n| n > t + 300)
        {
            return bad(
                400,
                "invalid_client",
                "AADSTS700024: Client assertion is not within its valid time range / audience.",
            );
        }
        let jti = c["jti"].as_str().unwrap_or_default().to_owned();
        if jti.is_empty() || !self.jtis.insert(jti) {
            return bad(400, "invalid_client", "AADSTS700021: Client assertion replayed.");
        }
        self.assertions_ok += 1;
        let tok = format!("tok{}", self.next());
        self.tokens.insert(tok.clone(), t + self.token_lifetime as i64);
        j(
            200,
            json!({"token_type": "Bearer", "expires_in": self.token_lifetime, "ext_expires_in": self.token_lifetime, "access_token": tok}),
        )
    }

    fn authorized(&mut self, req: &Req) -> bool {
        let Some(t) = req.headers.get("authorization").and_then(|a| a.strip_prefix("Bearer ")) else {
            return false;
        };
        self.tokens.get(t).is_some_and(|exp| *exp >= now())
    }

    // ---- Graph ------------------------------------------------------------------------

    fn handle(&mut self, req: &Req) -> Resp {
        let p: Vec<String> = req.path.trim_start_matches('/').split('/').map(pct_decode).collect();
        let ps: Vec<&str> = p.iter().map(String::as_str).collect();
        self.requests.push(format!(
            "{} {}{}",
            req.method,
            req.path,
            if req.raw_query.is_empty() {
                String::new()
            } else {
                format!(
                    "?{}",
                    req.raw_query
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join("&")
                )
            }
        ));
        if let Some(f) = self
            .faults
            .iter_mut()
            .find(|f| f.count > 0 && req.path.contains(&f.path))
        {
            f.count -= 1;
            let mut r = gerr(
                f.status,
                if f.status == 429 {
                    "TooManyRequests"
                } else {
                    "ServiceUnavailable"
                },
                "slow down",
            );
            r.headers.push(("retry-after".into(), "1".into()));
            return r;
        }
        match (req.method.as_str(), ps.as_slice()) {
            ("POST", [tenant, "oauth2", "v2.0", "token"]) => return self.token(tenant, req),
            ("GET", ["_dl", d, i]) => return self.download(d, i, req),
            ("PUT", ["_up", s]) => return self.upload_part(s, req),
            _ => {}
        }
        let Some(("v1.0", g)) = ps.split_first().map(|(a, b)| (*a, b)) else {
            return not_found();
        };
        if !self.authorized(req) {
            return gerr(
                401,
                "InvalidAuthenticationToken",
                "Access token has expired or is not yet valid.",
            );
        }
        if let Some(n) = self.revoke_after.as_mut() {
            if *n == 0 {
                self.revoke_after = None;
                self.tokens.clear();
                return gerr(
                    401,
                    "InvalidAuthenticationToken",
                    "Access token has expired or is not yet valid.",
                );
            }
            *n -= 1;
        }
        if self.deny.iter().any(|d| req.path.contains(d.as_str())) {
            return gerr(
                403,
                "Authorization_RequestDenied",
                "Insufficient privileges to complete the operation.",
            );
        }
        self.graph(req, g)
    }

    fn user(&self, id: &str) -> Option<&User> {
        self.users
            .iter()
            .find(|u| u.id.eq_ignore_ascii_case(id) || u.upn.eq_ignore_ascii_case(id))
    }

    fn graph(&mut self, req: &Req, g: &[&str]) -> Resp {
        let m = req.method.as_str();
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        match (m, g) {
            ("GET", ["users"]) => {
                let all = self
                    .users
                    .iter()
                    .map(|u| {
                        json!({"id": u.id, "displayName": u.name, "userPrincipalName": u.upn,
                                    "userType": if u.member { "Member" } else { "Guest" }})
                    })
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["users", u]) => match self.user(u) {
                Some(u) => j(200, json!({"id": u.id, "userPrincipalName": u.upn})),
                None => not_found(),
            },
            ("GET", ["users", u, "drive"]) => match self.user(u).and_then(|u| u.drive.clone()) {
                Some(d) => j(200, json!({"id": d})),
                None => gerr(404, "ResourceNotFound", "User's mysite not found."),
            },
            ("GET" | "POST", ["users", u, ..]) if self.user(u).is_some_and(|x| !x.mailbox) => gerr(
                404,
                "MailboxNotEnabledForRESTAPI",
                "The mailbox is either inactive, soft-deleted, or is hosted on-premise.",
            ),
            ("GET", ["users", u, "mailFolders"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let all = self
                    .folders
                    .iter()
                    .filter(|f| {
                        f.user == uid && !f.deleted && f.parent.as_deref() == Some(&format!("msgfolderroot-{uid}"))
                    })
                    .map(|f| json!({"id": f.id, "displayName": f.name}))
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["users", u, "mailFolders", "delta"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let all = self
                    .folders
                    .iter()
                    .filter(|f| f.user == uid && !f.deleted)
                    .map(|f| json!({"id": f.id, "displayName": f.name, "parentFolderId": f.parent}))
                    .collect();
                let upto = self.seq;
                self.page(req, all, Some(upto))
            }
            ("GET", ["users", u, "mailFolders", f, "messages", "delta"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                if !self.folders.iter().any(|x| x.id == *f && x.user == uid) {
                    return not_found();
                }
                let (token, upto) = self.delta_window(req);
                let all = self
                    .messages
                    .iter()
                    .filter(|x| x.user == uid && x.seq <= upto)
                    .filter_map(|x| match token {
                        None if x.folder == *f && !x.deleted => Some(self.msg_json(x)),
                        None => None,
                        // changes: in the folder now, or left it / deleted since the token
                        Some(t) if x.seq > t && x.folder == *f && !x.deleted => Some(self.msg_json(x)),
                        Some(t) if x.seq > t => Some(
                            json!({"id": x.id, "@removed": {"reason": if x.deleted { "deleted" } else { "changed" }}}),
                        ),
                        _ => None,
                    })
                    .collect();
                self.page(req, all, Some(upto))
            }
            ("GET", ["users", u, "messages", id, "$value"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                match self
                    .messages
                    .iter()
                    .find(|x| x.id == *id && x.user == uid && !x.deleted)
                {
                    Some(x) => Resp {
                        status: 200,
                        headers: vec![("content-type".into(), "message/rfc822".into())],
                        body: x.mime.clone(),
                        cut: None,
                    },
                    None => not_found(),
                }
            }
            ("POST", ["users", u, "mailFolders"]) | ("POST", ["users", u, "mailFolders", _, "childFolders"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let parent = if g.len() == 5 {
                    g[3].to_owned()
                } else {
                    format!("msgfolderroot-{uid}")
                };
                let name = body["displayName"].as_str().unwrap_or_default().to_owned();
                if self.folders.iter().any(|f| {
                    f.user == uid
                        && f.parent.as_deref() == Some(&parent)
                        && f.name.eq_ignore_ascii_case(&name)
                        && !f.deleted
                }) {
                    return gerr(
                        409,
                        "ErrorFolderExists",
                        "A folder with the specified name already exists.",
                    );
                }
                let par = (g.len() == 5).then_some(parent.as_str());
                let id = self.add_folder(&uid, par, &name);
                j(201, json!({"id": id, "displayName": name}))
            }
            ("POST", ["users", u, "mailFolders", f, "messages"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                if req.headers.get("content-type").map(String::as_str) != Some("text/plain") {
                    return gerr(400, "ErrorInvalidRequest", "expected MIME as base64 text/plain");
                }
                let Ok(mime) = B64.decode(String::from_utf8_lossy(&req.body).trim()) else {
                    return gerr(400, "ErrorMimeContentInvalidBase64String", "invalid base64");
                };
                let subject = String::from_utf8_lossy(&mime)
                    .lines()
                    .find_map(|l| l.strip_prefix("Subject: ").map(str::to_owned))
                    .unwrap_or_default();
                let id = self.add_message(&uid, f, &subject, "");
                self.msg(&id).mime = mime;
                j(201, json!({"id": id, "subject": subject}))
            }
            ("GET", ["users", u, "calendars"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let all = self
                    .calendars
                    .iter()
                    .filter(|c| c.1 == uid)
                    .map(|c| json!({"id": c.0, "name": c.2}))
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["users", _, "calendars", c, "events"]) => {
                let all = self.events.iter().filter(|e| e.0 == *c).map(|e| e.1.clone()).collect();
                self.page(req, all, None)
            }
            ("POST", ["users", u, "calendars"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let id = format!("cal-new{}", self.next());
                let name = body["name"].as_str().unwrap_or_default().to_owned();
                self.calendars.push((id.clone(), uid, name.clone()));
                j(201, json!({"id": id, "name": name}))
            }
            ("POST", ["users", _, "calendars", c, "events"]) => {
                if body.get("id").is_some() || body.get("attendees").is_some() {
                    return gerr(
                        400,
                        "ErrorInvalidProperty",
                        "read-only property or attendees in a restore",
                    );
                }
                let mut ev = body.clone();
                let id = self.exid("ev");
                ev["id"] = json!(id);
                self.events.push(((*c).to_owned(), ev));
                j(201, json!({"id": id}))
            }
            ("GET", ["users", u, "contacts"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let all = self
                    .contacts
                    .iter()
                    .filter(|c| c.0 == format!("default-{uid}"))
                    .map(|c| c.1.clone())
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["users", u, "contactFolders"]) | ("GET", ["users", u, "contactFolders", _, "childFolders"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let parent = (g.len() == 5).then(|| g[3].to_owned());
                let all = self
                    .contact_folders
                    .iter()
                    .filter(|f| f.1 == uid && f.2 == parent)
                    .map(|f| json!({"id": f.0, "displayName": f.3}))
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["users", _, "contactFolders", f, "contacts"]) => {
                let all = self
                    .contacts
                    .iter()
                    .filter(|c| c.0 == *f)
                    .map(|c| c.1.clone())
                    .collect();
                self.page(req, all, None)
            }
            ("POST", ["users", u, "contactFolders"]) | ("POST", ["users", u, "contactFolders", _, "childFolders"]) => {
                let uid = self.user(u).map(|x| x.id.clone()).unwrap_or_default();
                let parent = (g.len() == 5).then(|| g[3].to_owned());
                let name = body["displayName"].as_str().unwrap_or_default().to_owned();
                if self
                    .contact_folders
                    .iter()
                    .any(|f| f.1 == uid && f.2 == parent && f.3 == name)
                {
                    return gerr(
                        409,
                        "ErrorFolderExists",
                        "A folder with the specified name already exists.",
                    );
                }
                let id = self.add_contact_folder(&uid, parent.as_deref(), &name);
                j(201, json!({"id": id}))
            }
            ("POST", ["users", _, "contactFolders", f, "contacts"]) => {
                if body.get("id").is_some() || body.get("changeKey").is_some() {
                    return gerr(400, "ErrorInvalidProperty", "read-only property");
                }
                let mut c = body.clone();
                let id = self.exid("ct");
                c["id"] = json!(id);
                self.contacts.push(((*f).to_owned(), c));
                j(201, json!({"id": id}))
            }
            // ---- sites
            ("GET", ["sites", "root"]) => j(
                200,
                json!({"id": format!("{SP_HOST},root,root"), "siteCollection": {"hostname": SP_HOST}}),
            ),
            ("GET", ["sites", "getAllSites"]) => {
                let mut all: Vec<Value> = self
                    .sites
                    .iter()
                    .map(|s| json!({"id": s.id, "displayName": s.name, "webUrl": s.url, "isPersonalSite": s.personal}))
                    .collect();
                all.push(json!({"id": format!("contoso-my.sharepoint.com,{},{}", "aaaaaaaa-0000-4000-8000-000000000001", "aaaaaaaa-0000-4000-8000-000000000002"),
                                "displayName": "Alice OneDrive", "isPersonalSite": true}));
                self.page(req, all, None)
            }
            ("GET", ["sites", host, rest @ ..]) if host.ends_with(':') => {
                let url = format!("https://{}/{}", host.trim_end_matches(':'), rest.join("/"));
                match self.sites.iter().find(|s| s.url.eq_ignore_ascii_case(&url)) {
                    Some(s) => j(200, json!({"id": s.id, "displayName": s.name})),
                    None => not_found(),
                }
            }
            ("GET", ["sites", s]) => match self.sites.iter().find(|x| x.id == *s) {
                Some(s) => j(200, json!({"id": s.id, "displayName": s.name})),
                None => not_found(),
            },
            ("GET", ["sites", s, "drives"]) => match self.sites.iter().find(|x| x.id == *s) {
                Some(site) => {
                    let all = site
                        .drives
                        .iter()
                        .map(|d| {
                            let name = self.drives.iter().find(|x| x.0 == *d).map(|x| x.1.clone());
                            json!({"id": d, "name": name, "driveType": "documentLibrary"})
                        })
                        .collect();
                    self.page(req, all, None)
                }
                None => not_found(),
            },
            ("GET", ["sites", s, "drive"]) => match self.sites.iter().find(|x| x.id == *s) {
                Some(site) => j(200, json!({"id": site.drives[0]})),
                None => not_found(),
            },
            // ---- teams
            ("GET", ["groups", t, "drive"]) => match self.teams.iter().find(|x| x.id == *t) {
                Some(team) => j(200, json!({"id": team.drive})),
                None => not_found(),
            },
            ("GET", ["teams"]) => {
                let all = self
                    .teams
                    .iter()
                    .map(|t| json!({"id": t.id, "displayName": t.name}))
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["teams", t]) => match self.teams.iter().find(|x| x.id == *t) {
                Some(team) => j(200, json!({"id": team.id, "displayName": team.name})),
                None => not_found(),
            },
            ("GET", ["teams", t, "channels"]) => match self.teams.iter().find(|x| x.id == *t) {
                Some(team) => {
                    let all = team
                        .channels
                        .iter()
                        .filter(|c| !c.2 || c.3)
                        .map(|c| json!({"id": c.0, "displayName": c.1, "membershipType": "standard"}))
                        .collect();
                    self.page(req, all, None)
                }
                None => not_found(),
            },
            ("GET", ["teams", t, "channels", "getAllMessages"]) => {
                if !self.protected_api {
                    return gerr(403, "Forbidden", PROTECTED);
                }
                let since = req.q("$filter").and_then(|f| {
                    f.strip_prefix("lastModifiedDateTime gt ")
                        .and_then(m365_plugin::format::parse_time)
                        .map(|ns| ns / 1_000_000_000)
                });
                let all = self
                    .chat
                    .iter()
                    .filter(|(team, m)| {
                        team == t
                            && since.is_none_or(|s| {
                                m["lastModifiedDateTime"]
                                    .as_str()
                                    .and_then(m365_plugin::format::parse_time)
                                    .is_some_and(|x| x / 1_000_000_000 > s)
                            })
                    })
                    .map(|(_, m)| m.clone())
                    .collect();
                self.page(req, all, None)
            }
            ("GET", ["teams", t, "channels", c, "messages", id]) => {
                if !self.protected_api {
                    return gerr(403, "Forbidden", PROTECTED);
                }
                match self
                    .chat
                    .iter()
                    .find(|(team, m)| team == t && m["id"] == *id && m["channelIdentity"]["channelId"] == *c)
                {
                    Some((_, m)) => j(200, m.clone()),
                    None => not_found(),
                }
            }
            ("GET", ["teams", t, "channels", _, "messages", id, "replies"]) => {
                if !self.protected_api {
                    return gerr(403, "Forbidden", PROTECTED);
                }
                let all = self
                    .chat
                    .iter()
                    .filter(|(team, m)| team == t && m["replyToId"] == *id)
                    .map(|(_, m)| m.clone())
                    .collect();
                self.page(req, all, None)
            }
            ("POST", ["teams", t, "channels"]) => {
                if body["@microsoft.graph.channelCreationMode"] != "migration" || body["createdDateTime"].is_null() {
                    return gerr(400, "BadRequest", "only migration-mode channels in this mock");
                }
                let name = body["displayName"].as_str().unwrap_or_default().to_owned();
                if name.chars().count() > 50 {
                    return gerr(400, "BadRequest", "channel name too long");
                }
                let id = format!("19:{}@thread.tacv2", self.next());
                match self.teams.iter_mut().find(|x| x.id == *t) {
                    Some(team) => {
                        team.channels.push((id.clone(), name.clone(), true, false));
                        j(201, json!({"id": id, "displayName": name}))
                    }
                    None => not_found(),
                }
            }
            ("POST", ["teams", t, "channels", c, "messages"])
            | ("POST", ["teams", t, "channels", c, "messages", _, "replies"]) => {
                let migrating = self
                    .teams
                    .iter()
                    .find(|x| x.id == *t)
                    .and_then(|x| x.channels.iter().find(|ch| ch.0 == *c))
                    .is_some_and(|ch| ch.2 && !ch.3);
                if !migrating || body["createdDateTime"].is_null() || body["from"]["user"]["id"].is_null() {
                    return gerr(
                        403,
                        "Forbidden",
                        "messages can only be imported into channels in migration mode",
                    );
                }
                let reply_to = (g.len() == 7).then(|| g[5].to_owned());
                let (tt, cc) = ((*t).to_owned(), (*c).to_owned());
                let id = self.add_chat(
                    &tt,
                    &cc,
                    body["from"]["user"]["id"].as_str().unwrap_or_default(),
                    "",
                    reply_to.as_deref(),
                    None,
                );
                let m = &mut self.chat.last_mut().unwrap().1;
                m["body"] = body["body"].clone();
                m["createdDateTime"] = body["createdDateTime"].clone();
                m["subject"] = body["subject"].clone();
                j(201, json!({"id": id}))
            }
            ("POST", ["teams", t, "channels", c, "completeMigration"]) => {
                match self
                    .teams
                    .iter_mut()
                    .find(|x| x.id == *t)
                    .and_then(|x| x.channels.iter_mut().find(|ch| ch.0 == *c))
                {
                    Some(ch) => {
                        ch.3 = true;
                        Resp {
                            status: 204,
                            headers: vec![],
                            body: vec![],
                            cut: None,
                        }
                    }
                    None => not_found(),
                }
            }
            // ---- drives
            ("GET", ["drives", d, "root"]) => j(200, json!({"id": self.drive_root(d)})),
            ("GET", ["drives", d, "root", "delta"]) => {
                if !self.drives.iter().any(|x| x.0 == *d) {
                    return not_found();
                }
                let (token, upto) = self.delta_window(req);
                let all = self
                    .items
                    .iter()
                    .filter(|i| i.drive == *d && i.seq <= upto)
                    .filter(|i| match token {
                        None => !i.deleted,
                        Some(t) => i.seq > t,
                    })
                    .map(|i| self.item_json(i))
                    .collect();
                self.page(req, all, Some(upto))
            }
            ("GET", ["drives", d, "items", i, "content"]) => {
                if !self.items.iter().any(|x| x.id == *i && x.drive == *d && !x.deleted) {
                    return not_found();
                }
                Resp {
                    status: 302,
                    headers: vec![("location".into(), format!("{}/_dl/{d}/{i}?tempauth=xyz", self.origin()))],
                    body: vec![],
                    cut: None,
                }
            }
            ("POST", ["drives", d, "items", parent, "children"]) => {
                let parent = if *parent == "root" {
                    self.drive_root(d)
                } else {
                    (*parent).to_owned()
                };
                let name = body["name"].as_str().unwrap_or_default().to_owned();
                if self.items.iter().any(|x| {
                    x.drive == *d
                        && x.parent.as_deref() == Some(parent.as_str())
                        && x.name.eq_ignore_ascii_case(&name)
                        && !x.deleted
                }) {
                    return gerr(409, "nameAlreadyExists", "The specified item name already exists.");
                }
                let id = self.add_item(d, &parent, &name, None);
                j(201, json!({"id": id, "name": name, "folder": {}}))
            }
            ("PUT", ["drives", d, "items", parent, name, "content"])
                if parent.ends_with(':') && name.ends_with(':') =>
            {
                let parent = parent.trim_end_matches(':').to_owned();
                let name = name.trim_end_matches(':').to_owned();
                if req.q("@microsoft.graph.conflictBehavior").as_deref() != Some("fail") {
                    return gerr(400, "invalidRequest", "this mock expects conflictBehavior=fail");
                }
                self.create_file(d, &parent, &name, req.body.clone())
            }
            ("POST", ["drives", d, "items", parent, name, "createUploadSession"])
                if parent.ends_with(':') && name.ends_with(':') =>
            {
                if body["item"]["@microsoft.graph.conflictBehavior"] != "fail" {
                    return gerr(400, "invalidRequest", "this mock expects conflictBehavior=fail");
                }
                let sid = format!("s{}", self.next());
                self.sessions.insert(
                    sid.clone(),
                    (
                        (*d).to_owned(),
                        parent.trim_end_matches(':').to_owned(),
                        name.trim_end_matches(':').to_owned(),
                        Vec::new(),
                    ),
                );
                j(
                    200,
                    json!({"uploadUrl": format!("{}/_up/{sid}", self.origin()), "expirationDateTime": iso(now() + 3600)}),
                )
            }
            _ => gerr(
                400,
                "BadRequest",
                &format!("mock: {m} /{} not implemented", g.join("/")),
            ),
        }
    }

    fn msg_json(&self, x: &Msg) -> Value {
        json!({"id": x.id, "subject": x.subject, "changeKey": x.change_key,
               "lastModifiedDateTime": iso(x.modified), "parentFolderId": x.folder})
    }

    fn create_file(&mut self, d: &str, parent: &str, name: &str, content: Vec<u8>) -> Resp {
        if self.items.iter().any(|x| {
            x.drive == d && x.parent.as_deref() == Some(parent) && x.name.eq_ignore_ascii_case(name) && !x.deleted
        }) {
            return gerr(409, "nameAlreadyExists", "The specified item name already exists.");
        }
        let size = content.len();
        let id = self.add_item(d, parent, name, Some(content));
        j(201, json!({"id": id, "name": name, "size": size}))
    }

    fn download(&mut self, d: &str, i: &str, req: &Req) -> Resp {
        let Some(item) = self.items.iter().find(|x| x.id == i && x.drive == d && !x.deleted) else {
            return not_found();
        };
        let c = item.content.clone();
        let (status, body, range) = match req.headers.get("range").and_then(|r| r.strip_prefix("bytes=")) {
            Some(r) => {
                let (a, b) = r.split_once('-').unwrap();
                let a: usize = a.parse().unwrap();
                let b: usize = b.parse::<usize>().unwrap().min(c.len() - 1);
                (206, c[a..=b].to_vec(), Some(format!("bytes {a}-{b}/{}", c.len())))
            }
            None => (200, c, None),
        };
        let mut r = Resp {
            status,
            headers: vec![("content-type".into(), "application/octet-stream".into())],
            cut: None,
            body,
        };
        if let Some(cr) = range {
            r.headers.push(("content-range".into(), cr));
        }
        if self.break_downloads > 0 && r.body.len() > 1 {
            self.break_downloads -= 1;
            r.cut = Some(r.body.len() / 2);
        }
        r
    }

    fn upload_part(&mut self, sid: &str, req: &Req) -> Resp {
        if req.headers.contains_key("authorization") {
            return gerr(
                401,
                "invalidRequest",
                "upload URLs are pre-authenticated: no Authorization header",
            );
        }
        let Some((d, parent, name, mut data)) = self.sessions.remove(sid) else {
            return not_found();
        };
        let cr = req.headers.get("content-range").cloned().unwrap_or_default();
        let Some((range, total)) = cr.strip_prefix("bytes ").and_then(|r| r.split_once('/')) else {
            return gerr(400, "invalidRange", "Content-Range missing");
        };
        let (a, b) = range.split_once('-').unwrap();
        let (a, b, total): (usize, usize, usize) = (a.parse().unwrap(), b.parse().unwrap(), total.parse().unwrap());
        if a != data.len()
            || b + 1 - a != req.body.len()
            || (b + 1 < total && !req.body.len().is_multiple_of(320 * 1024))
        {
            return gerr(
                416,
                "invalidRange",
                "fragment out of order or not a multiple of 320 KiB",
            );
        }
        data.extend_from_slice(&req.body);
        if data.len() == total {
            return self.create_file(&d, &parent, &name, data);
        }
        let next = data.len();
        self.sessions.insert(sid.to_owned(), (d, parent, name, data));
        j(202, json!({"nextExpectedRanges": [format!("{next}-")]}))
    }
}

fn read_req(r: &mut impl BufRead) -> Option<Req> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut it = line.split_whitespace();
    let method = it.next()?.to_owned();
    let target = it.next()?.to_owned();
    let mut headers = HashMap::new();
    loop {
        let mut h = String::new();
        r.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let len: usize = headers.get("content-length").and_then(|l| l.parse().ok()).unwrap_or(0);
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).ok()?;
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let raw_query = q
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (pct_decode(k), v.to_owned())
        })
        .collect();
    Some(Req {
        method,
        path: path.to_owned(),
        raw_query,
        headers,
        body,
    })
}

fn reason(s: u16) -> &'static str {
    match s {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

impl Mock {
    pub fn start() -> Mock {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut cp = CertificateParams::new(Vec::<String>::new()).unwrap();
        cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        cp.distinguished_name.push(rcgen::DnType::CommonName, "Graph mock CA");
        let ca = cp.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let sp = CertificateParams::new(vec!["127.0.0.1".to_owned(), "localhost".to_owned()]).unwrap();
        let cert = sp.signed_by(&key, &ca, &ca_key).unwrap();
        let cfg = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
                )
                .unwrap(),
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        // the app registration: the test certificate, its public key for signature checks
        let cert_der = pem::parse(CERT).unwrap().contents().to_vec();
        let kp = ring::signature::RsaKeyPair::from_pkcs8(pem::parse(KEY).unwrap().contents()).unwrap();
        let t = Arc::new(Mutex::new(Tenant {
            port,
            page_size: 100,
            protected_api: true,
            token_lifetime: 3600,
            registered: B64URL.encode(ring::digest::digest(&ring::digest::SHA256, &cert_der)),
            public_key: ring::signature::KeyPair::public_key(&kp).as_ref().to_vec(),
            ..Default::default()
        }));
        let tt = t.clone();
        std::thread::spawn(move || {
            for tcp in l.incoming().flatten() {
                let cfg = cfg.clone();
                let t = tt.clone();
                std::thread::spawn(move || {
                    let tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), tcp);
                    let mut r = BufReader::new(tls);
                    while let Some(req) = read_req(&mut r) {
                        let resp = t.lock().unwrap().handle(&req);
                        let w = r.get_mut();
                        let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
                        for (k, v) in &resp.headers {
                            head.push_str(&format!("{k}: {v}\r\n"));
                        }
                        head.push_str(&format!("content-length: {}\r\n\r\n", resp.body.len()));
                        let body = &resp.body[..resp.cut.unwrap_or(resp.body.len())];
                        if w.write_all(head.as_bytes()).is_err() || w.write_all(body).is_err() || w.flush().is_err() {
                            break;
                        }
                        if resp.cut.is_some() {
                            w.conn.send_close_notify();
                            let _ = w.flush();
                            let _ = w.sock.shutdown(std::net::Shutdown::Both);
                            break;
                        }
                    }
                });
            }
        });
        Mock {
            port,
            ca_pem: ca.pem(),
            t,
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Tenant> {
        self.t.lock().unwrap()
    }

    /// Source config pointing every endpoint at the mock.
    pub fn config(&self) -> Value {
        json!({
            "tenant_id": TENANT, "client_id": CLIENT_ID, "certificate": CERT, "private_key": KEY,
            "exchange": true, "onedrive": true, "sharepoint": true, "teams": true, "teams_messages": true,
            "sharepoint_host": SP_HOST, "onedrive_host": "contoso-my.sharepoint.com",
            "graph_host": "127.0.0.1", "login_host": "127.0.0.1", "port": self.port, "ca_cert": self.ca_pem,
        })
    }

    pub fn count(&self, pat: &str) -> usize {
        self.lock().requests.iter().filter(|r| r.contains(pat)).count()
    }

    pub fn count2(&self, a: &str, b: &str) -> usize {
        self.lock()
            .requests
            .iter()
            .filter(|r| r.contains(a) && r.contains(b))
            .count()
    }

    pub fn clear_requests(&self) {
        self.lock().requests.clear();
    }
}
