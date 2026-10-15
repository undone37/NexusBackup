//! Microsoft 365 as a NexusBackup plugin (docs/m365.md): Exchange mailboxes (mail,
//! calendars, contacts), OneDrive, SharePoint document libraries and Teams (team
//! files, channel messages) through Microsoft Graph with an Entra app registration
//! (application permissions, certificate credential).
//!
//! Guests (one snapshot each): `u.<user id>` (mailbox + OneDrive), `s.<site>`
//! (document libraries of a site; the site collection and web GUIDs as base64url,
//! the ids Graph uses do not fit the guest-id rules), `t.<group id>` (team files,
//! private/shared channel files, channel messages), `g.<group id>` (Microsoft 365
//! group: conversations, calendar, and the group's files unless it is a team),
//! `e.directory` (Entra ID directory objects, export only: see `backup::entra`).
//! Incremental backups: see `backup`.

pub mod auth;
pub mod backup;
pub mod export;
pub mod format;
pub mod graph;
pub mod mail;
pub mod pst;
pub mod restore;

use auth::{Bad, Credential};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use graph::{Graph, Settings};
use plugin_sdk::{error, BackupResult, Ctx, Export, Plugin, Result, Sink, Source, TaggedGuest as SdkGuest, Validation};
use serde_json::Value;

pub const GRAPH_HOST: &str = "graph.microsoft.com";
pub const LOGIN_HOST: &str = "login.microsoftonline.com";

/// The source config (manifest `config_schema`; secrets `certificate`, `private_key`).
pub struct Config {
    pub tenant_id: String,
    pub client_id: String,
    /// PEM (checked by `parse`: a usable RSA key matching the certificate)
    certificate: String,
    private_key: String,
    /// further app registrations (client id, certificate + key PEM), used round-robin
    pub apps: Vec<(String, String)>,
    pub exchange: bool,
    pub onedrive: bool,
    pub sharepoint: bool,
    pub teams: bool,
    pub teams_messages: bool,
    /// Microsoft 365 groups (conversations, calendar; files with `sharepoint`)
    pub groups: bool,
    /// 1:1 and group chats of users (export API, metered: opt-in)
    pub chats: bool,
    /// Entra ID directory objects (users, groups + memberships, devices, app
    /// registrations, service principals; extra permissions: opt-in)
    pub entra: bool,
    /// `model` parameter of the Teams export API (`A`, `B`; None = evaluation mode)
    pub teams_model: Option<String>,
    pub sharepoint_host: Option<String>,
    pub onedrive_host: Option<String>,
    pub graph_host: String,
    pub login_host: String,
    pub port: u16,
    pub ca_cert: Option<String>,
}

fn guid_ok(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

impl Config {
    pub fn parse(v: &Value) -> std::result::Result<Config, Bad> {
        let s = |k: &'static str| -> std::result::Result<String, Bad> {
            v[k].as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or((k, "required".into()))
        };
        let opt = |k: &str| {
            v[k].as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let flag = |k: &str, def: bool| v[k].as_bool().unwrap_or(def);
        let tenant_id = s("tenant_id")?;
        if !(guid_ok(&tenant_id)
            || (tenant_id.contains('.')
                && tenant_id.len() <= 253
                && tenant_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')))
        {
            return Err((
                "tenant_id",
                "expected the tenant ID (GUID) or a verified domain (contoso.onmicrosoft.com)".into(),
            ));
        }
        let client_id = s("client_id")?;
        if !guid_ok(&client_id) {
            return Err(("client_id", "expected the application (client) ID, a GUID".into()));
        }
        let (certificate, private_key) = (s("certificate")?, s("private_key")?);
        Credential::parse(&certificate, &private_key)?;
        let mut apps: Vec<(String, String)> = Vec::new();
        for (i, a) in v["apps"].as_array().into_iter().flatten().enumerate() {
            let n = i + 2;
            let id = a["client_id"].as_str().map(str::trim).unwrap_or_default();
            if !guid_ok(id) {
                return Err(("apps", format!("app {n}: expected the application (client) ID, a GUID")));
            }
            if id.eq_ignore_ascii_case(&client_id) || apps.iter().any(|x| x.0.eq_ignore_ascii_case(id)) {
                return Err(("apps", format!("app {n}: {id} is listed twice")));
            }
            let pem = a["certificate"].as_str().unwrap_or_default();
            Credential::parse(pem, "").map_err(|(_, m)| ("apps", format!("app {n}: {m}")))?;
            apps.push((id.to_owned(), pem.to_owned()));
        }
        if apps.len() > 8 {
            return Err(("apps", "at most 8 further app registrations".into()));
        }
        let port = match &v["port"] {
            Value::Null => 443,
            x => x
                .as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .filter(|p| *p > 0)
                .ok_or(("port", "expected a port".into()))?,
        };
        let c = Config {
            tenant_id,
            client_id,
            certificate,
            private_key,
            apps,
            exchange: flag("exchange", true),
            onedrive: flag("onedrive", true),
            sharepoint: flag("sharepoint", true),
            teams: flag("teams", true),
            teams_messages: flag("teams_messages", false),
            groups: flag("groups", true),
            chats: flag("chats", false),
            entra: flag("entra", false),
            teams_model: match v["teams_export_model"].as_str().unwrap_or("B") {
                "evaluation" => None,
                m => Some(m.to_owned()),
            },
            sharepoint_host: opt("sharepoint_host").map(|h| h.to_ascii_lowercase()),
            onedrive_host: opt("onedrive_host").map(|h| h.to_ascii_lowercase()),
            graph_host: opt("graph_host").unwrap_or_else(|| GRAPH_HOST.into()),
            login_host: opt("login_host").unwrap_or_else(|| LOGIN_HOST.into()),
            port,
            ca_cert: opt("ca_cert"),
        };
        if !(c.exchange || c.onedrive || c.sharepoint || c.teams || c.teams_messages || c.groups || c.chats || c.entra)
        {
            return Err(("exchange", "select at least one workload".into()));
        }
        if c.files() && c.sharepoint_host.is_none() {
            return Err((
                "sharepoint_host",
                "required for OneDrive, SharePoint and Teams files (contoso.sharepoint.com)".into(),
            ));
        }
        if c.onedrive && c.onedrive_host.is_none() {
            return Err((
                "onedrive_host",
                "required for OneDrive (contoso-my.sharepoint.com)".into(),
            ));
        }
        Ok(c)
    }

    /// Any workload whose files live in SharePoint (downloads/uploads go to its hosts).
    pub fn files(&self) -> bool {
        self.onedrive || self.sharepoint || self.teams
    }

    fn origin(&self, host: &str) -> String {
        if self.port == 443 {
            format!("https://{host}")
        } else {
            format!("https://{host}:{}", self.port)
        }
    }

    /// Graph client with every app registration, starting with app 1.
    pub fn graph(&self) -> Result<Graph> {
        self.graph_for(None)
    }

    /// Graph client starting with the app picked for `guest` (round-robin).
    pub fn graph_for(&self, guest: Option<&str>) -> Result<Graph> {
        let bad = |(f, m): Bad| error(22, format!("config {f}: {m}"));
        let mut apps = vec![graph::App {
            client_id: self.client_id.clone(),
            cred: Credential::parse(&self.certificate, &self.private_key).map_err(bad)?,
        }];
        for (id, pem) in &self.apps {
            apps.push(graph::App {
                client_id: id.clone(),
                cred: Credential::parse(pem, "").map_err(bad)?,
            });
        }
        let start = guest.map_or(0, |g| graph::pick(g, apps.len()));
        Graph::new(
            Settings {
                graph_origin: self.origin(&self.graph_host),
                token_url: format!(
                    "{}/{}/oauth2/v2.0/token",
                    self.origin(&self.login_host),
                    graph::enc(&self.tenant_id)
                ),
                ca_pem: self.ca_cert.clone(),
            },
            apps,
            start,
        )
    }
}

/// A protected object (guest).
#[derive(Debug, Clone, PartialEq)]
pub enum Guest {
    User(String),
    /// site collection id, web id
    Site(String, String),
    Team(String),
    /// Microsoft 365 group (group id)
    Group(String),
    /// the tenant's Entra ID directory objects (one guest per source)
    Directory,
}

fn guid_bytes(g: &str) -> Option<Vec<u8>> {
    let h: String = g.chars().filter(|c| *c != '-').collect();
    (h.len() == 32)
        .then(|| {
            (0..16)
                .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok())
                .collect()
        })
        .flatten()
}

fn guid_str(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

impl Guest {
    pub fn id(&self) -> String {
        match self {
            Guest::User(u) => format!("u.{}", u.to_ascii_lowercase()),
            Guest::Team(t) => format!("t.{}", t.to_ascii_lowercase()),
            Guest::Group(g) => format!("g.{}", g.to_ascii_lowercase()),
            Guest::Directory => "e.directory".into(),
            Guest::Site(s, w) => {
                let mut b = guid_bytes(s).unwrap_or_default();
                b.extend(guid_bytes(w).unwrap_or_default());
                format!("s.{}", B64URL.encode(b))
            }
        }
    }

    pub fn parse(id: &str) -> Option<Guest> {
        let (k, v) = id.split_once('.')?;
        match k {
            "u" if guid_ok(v) => Some(Guest::User(v.into())),
            "t" if guid_ok(v) => Some(Guest::Team(v.into())),
            "g" if guid_ok(v) => Some(Guest::Group(v.into())),
            "e" if v == "directory" => Some(Guest::Directory),
            "s" => {
                let b = B64URL.decode(v).ok().filter(|b| b.len() == 32)?;
                Some(Guest::Site(guid_str(&b[..16]), guid_str(&b[16..])))
            }
            _ => None,
        }
    }

    /// Graph site id (`host,site,web`) of a site guest.
    pub fn site_id(&self, host: &str) -> Option<String> {
        match self {
            Guest::Site(s, w) => Some(format!("{host},{s},{w}")),
            _ => None,
        }
    }
}

/// Site guest of a Graph site id (`host,site-guid,web-guid`).
pub fn site_guest(id: &str) -> Option<Guest> {
    let mut p = id.split(',');
    let (_, s, w) = (p.next()?, p.next()?, p.next()?);
    (guid_ok(s) && guid_ok(w)).then(|| Guest::Site(s.to_ascii_lowercase(), w.to_ascii_lowercase()))
}

pub struct M365;

/// Microsoft 365 (unified) groups with the properties the plugin needs.
pub const UNIFIED_GROUPS: &str =
    "/groups?$filter=groupTypes%2Fany(c%3Ac%20eq%20%27Unified%27)&$select=id,displayName,resourceProvisioningOptions";

/// Does a group (Graph JSON) back a team?
pub fn is_team(g: &Value) -> bool {
    g["resourceProvisioningOptions"]
        .as_array()
        .is_some_and(|a| a.iter().any(|x| x == "Team"))
}

/// Private and shared channels keep their files in a SharePoint site of their own.
pub fn separate_channel(ch: &Value) -> bool {
    matches!(ch["membershipType"].as_str(), Some("private") | Some("shared"))
}

/// Drive (document library) holding a channel's files (`filesFolder`); None while
/// the channel's site is not provisioned yet.
pub fn channel_drive(g: &mut Graph, team: &str, channel: &str) -> Result<Option<String>> {
    match g.get(
        &format!(
            "/teams/{}/channels/{}/filesFolder",
            graph::enc(team),
            graph::enc(channel)
        ),
        &[],
    ) {
        Ok(f) => Ok(f["parentReference"]["driveId"].as_str().map(str::to_owned)),
        Err(e) if graph::status(&e) == Some(404) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Site guests a group / team guest covers: the group's site and, for teams, the
/// sites of private and shared channels (`sharepointIds` of the channel drive's
/// root). Lookup failures are logged and skipped (the site stays a plain site).
pub fn group_sites(ctx: &Ctx, g: &mut Graph, group: &str, team: bool) -> Vec<Guest> {
    let mut out = Vec::new();
    match g.get(&format!("/groups/{}/sites/root?$select=id", graph::enc(group)), &[]) {
        Ok(s) => out.extend(s["id"].as_str().and_then(site_guest)),
        Err(e) if graph::status(&e) == Some(404) => {}
        Err(e) => ctx.warn(format!("site of group {group}: {e:#}")),
    }
    if !team {
        return out;
    }
    let mut chans = Vec::new();
    let r = g.pages(
        &format!(
            "/teams/{}/channels?$select=id,displayName,membershipType",
            graph::enc(group)
        ),
        &[],
        |c| {
            if separate_channel(&c) {
                chans.push(c["id"].as_str().unwrap_or_default().to_owned());
            }
            Ok(())
        },
    );
    if let Err(e) = r {
        ctx.warn(format!("channels of team {group}: {e:#}"));
    }
    for ch in chans {
        let site = channel_drive(g, group, &ch).and_then(|d| match d {
            Some(d) => {
                let r = g.get(
                    &format!("/drives/{}/root?$select=id,sharepointIds", graph::enc(&d)),
                    &[],
                )?;
                let ids = &r["sharepointIds"];
                Ok(match (ids["siteId"].as_str(), ids["webId"].as_str()) {
                    (Some(s), Some(w)) if guid_ok(s) && guid_ok(w) => {
                        Some(Guest::Site(s.to_ascii_lowercase(), w.to_ascii_lowercase()))
                    }
                    _ => None,
                })
            }
            None => Ok(None),
        });
        match site {
            Ok(s) => out.extend(s),
            Err(e) => ctx.warn(format!("site of channel {ch}: {e:#}")),
        }
    }
    out
}

/// The parsed config of a context (plugin error code 22 = invalid config).
pub fn config(ctx: &Ctx) -> Result<Config> {
    Config::parse(&ctx.config).map_err(|(f, m)| error(22, format!("config {f}: {m}")))
}

/// Opens Graph for a context (config + credential).
pub fn connect(ctx: &Ctx) -> Result<(Config, Graph)> {
    let c = config(ctx)?;
    let g = c.graph_for(ctx.guest())?;
    Ok((c, g))
}

/// Validation answer for a failed token request (Entra error codes → config field).
fn token_problem(e: &anyhow::Error) -> Validation {
    let g = graph::graph_error(e);
    let code = g.map(|g| g.code.as_str()).unwrap_or_default();
    let field = match code {
        "AADSTS90002" | "AADSTS900023" | "AADSTS90023" => "tenant_id",
        "AADSTS700016" | "AADSTS7000229" => "client_id",
        "AADSTS700027" | "AADSTS700023" | "AADSTS70002" | "AADSTS7000274" | "AADSTS7000215" => "certificate",
        _ => "tenant_id",
    };
    let hint = match field {
        "certificate" => " — upload this certificate to the app registration (Certificates & secrets → Certificates)",
        "client_id" => " — the application (client) ID of the app registration in this tenant",
        _ => "",
    };
    Validation::Invalid {
        field: field.into(),
        message: format!(
            "sign-in failed: {}{hint}",
            g.map_or_else(|| format!("{e:#}"), |g| g.message.clone())
        ),
    }
}

/// Short reason of a permission failure (`403` → which application permission is missing).
fn missing(e: &anyhow::Error, perms: &str) -> String {
    match graph::status(e) {
        Some(401) | Some(403) => format!(
            "access denied ({}) — grant the application permission(s) {perms} with admin consent",
            graph::graph_error(e).map_or(String::new(), |g| g.code.clone())
        ),
        _ => format!("{e:#}"),
    }
}

fn invalid(field: &str, message: String) -> Validation {
    Validation::Invalid {
        field: field.into(),
        message,
    }
}

/// `contoso.sharepoint.com` → `contoso-my.sharepoint.com`.
pub fn my_host(sp: &str) -> String {
    match sp.split_once('.') {
        Some((t, rest)) => format!("{t}-my.{rest}"),
        None => format!("{sp}-my"),
    }
}

impl Plugin for M365 {
    fn validate(&mut self, ctx: &Ctx) -> Result<Validation> {
        let c = match Config::parse(&ctx.config) {
            Ok(c) => c,
            Err((f, m)) => return Ok(invalid(f, m)),
        };
        let mut g = c.graph()?;
        ctx.info(format!("certificate thumbprint (SHA-1) {}", g.thumbprint(0)));
        if let Err(e) = g.token() {
            return Ok(token_problem(&e));
        }
        let users = match g.get("/users?$select=id,userPrincipalName&$top=5", &[]) {
            Ok(v) => v["value"].as_array().cloned().unwrap_or_default(),
            Err(e) => return Ok(invalid("client_id", missing(&e, "User.Read.All"))),
        };
        // further app registrations: each signs in and reads the directory
        for i in 1..g.apps() {
            g.use_app(i);
            ctx.info(format!(
                "app {} ({}): certificate thumbprint (SHA-1) {}",
                i + 1,
                g.client_id(i),
                g.thumbprint(i)
            ));
            let r = g.token().and_then(|_| g.get("/users?$select=id&$top=1", &[]));
            if let Err(e) = r {
                let why = match token_problem(&e) {
                    _ if graph::status(&e) == Some(403) => {
                        missing(&e, "User.Read.All (and the other permissions of app 1)")
                    }
                    Validation::Invalid { message, .. } => message,
                    Validation::Valid => String::new(),
                };
                return Ok(invalid("apps", format!("app {} ({}): {why}", i + 1, g.client_id(i))));
            }
        }
        g.use_app(0);
        if c.exchange {
            if let Some(u) = users.first().and_then(|u| u["id"].as_str()) {
                if let Err(e) = g.get(&format!("/users/{}/mailFolders?$top=1", graph::enc(u)), &[]) {
                    if graph::status(&e) != Some(404) {
                        return Ok(invalid(
                            "exchange",
                            missing(&e, "Mail.ReadWrite, Calendars.ReadWrite, Contacts.ReadWrite"),
                        ));
                    }
                }
            }
        }
        if c.chats {
            if let Some(u) = users.first().and_then(|u| u["id"].as_str()) {
                if let Err(e) = g.get(&backup::chats::export_url(&c, u, None, 1), &[]) {
                    if graph::is_protected_api_denied(&e) {
                        return Ok(invalid("chats", backup::chats::CHATS_HELP.into()));
                    }
                    if graph::status(&e) != Some(404) {
                        return Ok(invalid("chats", missing(&e, "Chat.Read.All")));
                    }
                }
            }
        }
        if c.files() {
            let root = match g.get("/sites/root?$select=id,siteCollection,webUrl", &[]) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(invalid(
                        "sharepoint",
                        missing(
                            &e,
                            "Sites.Read.All (Sites.ReadWrite.All / Files.ReadWrite.All for restores)",
                        ),
                    ))
                }
            };
            let host = root["siteCollection"]["hostname"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if !host.is_empty() && c.sharepoint_host.as_deref() != Some(host.as_str()) {
                return Ok(invalid(
                    "sharepoint_host",
                    format!("this tenant's SharePoint host is {host}"),
                ));
            }
            if c.onedrive && !host.is_empty() && c.onedrive_host.as_deref() != Some(my_host(&host).as_str()) {
                return Ok(invalid(
                    "onedrive_host",
                    format!("this tenant's OneDrive host is {}", my_host(&host)),
                ));
            }
        }
        if c.teams || c.teams_messages {
            let teams = match g.get("/teams?$select=id,displayName&$top=5", &[]) {
                Ok(v) => v["value"].as_array().cloned().unwrap_or_default(),
                Err(e) => {
                    return Ok(invalid(
                        "teams",
                        missing(&e, "Team.ReadBasic.All, Channel.ReadBasic.All"),
                    ))
                }
            };
            if c.teams_messages {
                if let Some(t) = teams.first().and_then(|t| t["id"].as_str()) {
                    let url = backup::teams_export_url(&c, t, None, 1);
                    if let Err(e) = g.get(&url, &[]) {
                        if graph::is_protected_api_denied(&e) {
                            return Ok(invalid("teams_messages", backup::PROTECTED_API_HELP.into()));
                        }
                        return Ok(invalid("teams_messages", missing(&e, "ChannelMessage.Read.All")));
                    }
                } else {
                    ctx.warn("no team found: access to the Teams export API could not be checked");
                }
            }
        }
        if c.groups {
            if let Err(e) = g.get(&format!("{UNIFIED_GROUPS}&$top=1"), &[]) {
                return Ok(invalid("groups", missing(&e, "Group.Read.All")));
            }
        }
        if c.entra {
            for (url, perm) in backup::entra::CHECKS {
                if let Err(e) = g.get(url, &[]) {
                    return Ok(invalid("entra", missing(&e, perm)));
                }
            }
        }
        Ok(Validation::Valid)
    }

    /// Users, sites, teams and groups, tagged `type:user|site|team|group`
    /// (auto-protect groups); users without any license also `license:none`
    /// (`assignedLicenses` needs no permission beyond User.Read.All), sites of groups
    /// and teams (incl. private/shared channel sites) also `site:team` — they are
    /// backed up by their team / group guest, and groups of mode `all` leave them out
    /// (catalog `DEFAULT_OFF`). Entra group tags (`group:<name>`) would need
    /// GroupMember.Read.All: not done.
    fn list_tagged_guests(&mut self, ctx: &Ctx) -> Result<Vec<SdkGuest>> {
        let (c, mut g) = connect(ctx)?;
        let mut out = Vec::new();
        if c.exchange || c.onedrive || c.chats {
            g.pages(
                "/users?$select=id,displayName,userPrincipalName,userType,assignedLicenses&$top=999",
                &[],
                |u| {
                    if u["userType"].as_str().is_some_and(|t| t != "Member") {
                        return Ok(());
                    }
                    if let Some(id) = u["id"].as_str().filter(|i| guid_ok(i)) {
                        let mut tags = vec!["type:user".to_owned()];
                        if u["assignedLicenses"].as_array().is_some_and(std::vec::Vec::is_empty) {
                            tags.push("license:none".into());
                        }
                        out.push(SdkGuest {
                            tags,
                            id: Guest::User(id.into()).id(),
                            title: format!(
                                "User: {} ({})",
                                u["displayName"].as_str().unwrap_or_default(),
                                u["userPrincipalName"].as_str().unwrap_or_default()
                            ),
                            size: None,
                        });
                    }
                    Ok(())
                },
            )?;
        }
        // groups: guests of their own, and their sites are not offered as plain sites
        let mut groups = Vec::new();
        if c.groups || c.sharepoint {
            let r = g.pages(&format!("{UNIFIED_GROUPS}&$top=999"), &[], |x| {
                groups.push(x);
                Ok(())
            });
            if let Err(e) = r {
                if !matches!(graph::status(&e), Some(401) | Some(403)) {
                    return Err(e);
                }
                ctx.warn(format!(
                    "Microsoft 365 groups not listed: {} (team and group sites are offered as plain sites)",
                    missing(&e, "Group.Read.All")
                ));
                groups.clear();
            }
        }
        if c.groups {
            for x in &groups {
                if let Some(id) = x["id"].as_str().filter(|i| guid_ok(i)) {
                    out.push(SdkGuest {
                        tags: vec!["type:group".into()],
                        id: Guest::Group(id.into()).id(),
                        title: format!(
                            "Group: {}{}",
                            x["displayName"].as_str().unwrap_or_default(),
                            if is_team(x) { " (team)" } else { "" }
                        ),
                        size: None,
                    });
                }
            }
        }
        if c.sharepoint {
            let mut covered = std::collections::HashSet::new();
            for x in &groups {
                if let Some(id) = x["id"].as_str() {
                    covered.extend(group_sites(ctx, &mut g, id, is_team(x)).into_iter().map(|s| s.id()));
                }
            }
            let host = c.sharepoint_host.clone().unwrap_or_default();
            g.pages(
                "/sites/getAllSites?$select=id,displayName,webUrl,isPersonalSite&$top=999",
                &[],
                |s| {
                    let id = s["id"].as_str().unwrap_or_default();
                    if s["isPersonalSite"] == true || !id.to_ascii_lowercase().starts_with(&format!("{host},")) {
                        return Ok(());
                    }
                    if let Some(gst) = site_guest(id) {
                        let team = covered.contains(&gst.id());
                        let mut tags = vec!["type:site".to_owned()];
                        if team {
                            tags.push("site:team".into());
                        }
                        out.push(SdkGuest {
                            tags,
                            id: gst.id(),
                            title: format!(
                                "Site: {} ({}){}",
                                s["displayName"].as_str().unwrap_or_default(),
                                s["webUrl"].as_str().unwrap_or_default(),
                                if team { " - backed up with its team / group" } else { "" }
                            ),
                            size: None,
                        });
                    }
                    Ok(())
                },
            )?;
        }
        if c.teams || c.teams_messages {
            g.pages("/teams?$select=id,displayName&$top=999", &[], |t| {
                if let Some(id) = t["id"].as_str().filter(|i| guid_ok(i)) {
                    out.push(SdkGuest {
                        tags: vec!["type:team".into()],
                        id: Guest::Team(id.into()).id(),
                        title: format!("Team: {}", t["displayName"].as_str().unwrap_or_default()),
                        size: None,
                    });
                }
                Ok(())
            })?;
        }
        if c.entra {
            out.push(SdkGuest {
                tags: vec!["type:directory".into()],
                id: Guest::Directory.id(),
                title: "Entra ID directory: users, groups, devices, app registrations (export only)".into(),
                size: None,
            });
        }
        Ok(out)
    }

    fn backup(&mut self, ctx: &Ctx, sink: &mut Sink) -> Result<BackupResult> {
        let (c, g) = connect(ctx)?;
        let guest = ctx.guest().ok_or_else(|| {
            error(
                22,
                "select users, sites, teams, groups or the Entra ID directory in the group: a tenant is backed up per object",
            )
        })?;
        let guest = Guest::parse(guest).ok_or_else(|| error(22, format!("unknown guest {guest:?}")))?;
        backup::run(ctx, &c, g, &guest, sink)
    }

    fn restore(&mut self, ctx: &Ctx, src: &mut Source) -> Result<String> {
        let (c, g) = connect(ctx)?;
        restore::run(ctx, &c, g, src)
    }

    /// Download with conversion (mail as mbox / PST): no config, no network.
    fn export(&mut self, ctx: &Ctx, ex: &mut Export) -> Result<String> {
        export::run(ctx, ex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn guest_ids() {
        let u = Guest::User("0C9D1C7A-1111-2222-3333-444455556666".into());
        assert_eq!(u.id(), "u.0c9d1c7a-1111-2222-3333-444455556666");
        let s = site_guest(
            "contoso.sharepoint.com,2c712604-1370-44e7-a1f5-426573fda80a,9e7f2c0d-0000-4b6b-8f3a-0123456789ab",
        )
        .unwrap();
        let id = s.id();
        assert!(plugin_sdk::proto::valid_guest_id(&id) && id.len() <= 64, "{id}");
        assert_eq!(Guest::parse(&id), Some(s.clone()));
        assert_eq!(
            s.site_id("contoso.sharepoint.com").unwrap(),
            "contoso.sharepoint.com,2c712604-1370-44e7-a1f5-426573fda80a,9e7f2c0d-0000-4b6b-8f3a-0123456789ab"
        );
        for g in [
            u.clone(),
            Guest::Team("2c712604-1370-44e7-a1f5-426573fda80a".into()),
            Guest::Group("2c712604-1370-44e7-a1f5-426573fda80b".into()),
            Guest::Directory,
        ] {
            assert!(plugin_sdk::proto::valid_guest_id(&g.id()));
            assert_eq!(Guest::parse(&g.id()).map(|x| x.id()), Some(g.id()));
        }
        // the source name stays parseable (GUID parts may be all digits)
        let sn = plugin_sdk::proto::source_name("m365", 12, Some("u.12345678-1234-1234-1234-123456789012"));
        assert_eq!(
            plugin_sdk::proto::parse_source_name(&sn).unwrap().2.as_deref(),
            Some("u.12345678-1234-1234-1234-123456789012")
        );
        assert_eq!(Guest::parse("x.1"), None);
        assert_eq!(Guest::parse("u.not-a-guid"), None);
        assert_eq!(my_host("contoso.sharepoint.com"), "contoso-my.sharepoint.com");
    }

    #[test]
    fn config_rules() {
        let cert = include_str!("../tests/data/test-app.crt");
        let key = include_str!("../tests/data/test-app.key");
        let base = json!({"tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-2222-3333-4444-555555555555",
            "certificate": cert, "private_key": key, "sharepoint_host": "contoso.sharepoint.com",
            "onedrive_host": "contoso-my.sharepoint.com"});
        let c = Config::parse(&base).unwrap();
        assert!(c.exchange && c.onedrive && !c.teams_messages && c.port == 443 && c.graph_host == GRAPH_HOST);
        assert_eq!(c.teams_model.as_deref(), Some("B"));
        let with = |k: &str, v: Value| {
            let mut x = base.clone();
            x[k] = v;
            Config::parse(&x).err().map(|e| e.0)
        };
        assert_eq!(with("client_id", json!("nope")), Some("client_id"));
        assert_eq!(with("tenant_id", json!("a b")), Some("tenant_id"));
        assert_eq!(with("onedrive_host", Value::Null), Some("onedrive_host"));
        assert_eq!(with("sharepoint_host", Value::Null), Some("sharepoint_host"));
        assert_eq!(with("private_key", json!("x")), Some("private_key"));
        let mut mail_only = base.clone();
        for k in ["onedrive", "sharepoint", "teams"] {
            mail_only[k] = json!(false);
        }
        mail_only["sharepoint_host"] = Value::Null;
        mail_only["onedrive_host"] = Value::Null;
        assert!(Config::parse(&mail_only).is_ok());
        mail_only["exchange"] = json!(false);
        assert!(Config::parse(&mail_only).is_ok(), "groups alone");
        mail_only["groups"] = json!(false);
        assert_eq!(Config::parse(&mail_only).err().map(|e| e.0), Some("exchange"));
    }
}
