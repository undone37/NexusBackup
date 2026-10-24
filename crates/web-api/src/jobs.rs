//! Job requests, snapshots, downloads (alerts: `alerts.rs`).

use crate::auth::Ctx;
use crate::{random_hex, validate, ApiError, ApiResult, St, J, Q};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Kinds a tenant_user may request (restores only, own tenant).
const RESTORE_KINDS: &[&str] = &[
    "restore",
    "restore_ct",
    "instant_recover",
    // Phase 22b: one disk attached to an existing VM of the tenant (scheduler checks the target)
    "instant_disk",
    "files_list",
    "files_get",
    "restore_files",
    // Phase 33: newest clean version of each file (download or onto an agent)
    "synthetic_restore",
    "plugin_restore",
    "plugin_mount",
    // Phase 17d: browse the offsite copy, fetch a snapshot back for a restore
    "offsite_list",
    "offsite_restore",
];
/// Kinds only an admin may request (they change software or trust on a host);
/// tenant admins too, for their own tenant's agents (Phase 19b).
/// `chunk_repair` (Phase 21d): admin only; the provider's, like verify.
const ADMIN_KINDS: &[&str] = &["agent_update", "agent_enroll", "agent_renew", "chunk_repair"];
/// Appliance maintenance: never requested by a tenant admin (retention, GC,
/// offsite copy and verification belong to the provider).
const PROVIDER_KINDS: &[&str] = &["offsite", "retention", "gc", "verify", "chunk_repair"];
/// Start and cancel jobs of a tenant (scoped by `Ctx::sees`).
const RUNNERS: &[&str] = &["admin", "operator", "tenant_admin"];
pub const DOWNLOAD_TTL_SECS: i64 = 24 * 3600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobReq {
    kind: String,
    tenant: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupP {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vmid: Option<u32>,
    /// one Linux agent (its linux source)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    /// group_id only: back up these guests of the group (Phase 13b)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guests: Option<Vec<Value>>,
    /// group_id only: the guests that failed in the group's last run
    #[serde(default, skip_serializing)]
    failed_only: bool,
    /// Phase 23a: lock the new snapshots until then (crate::keep)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keep_until: Option<i64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreFilesP {
    /// `host-<agent_id>`, `nas-…`, `share-…`, `plugin-…`, `vm-<id>`, `ct-<id>` (Phase 15b)
    source: String,
    time: i64,
    paths: Vec<String>,
    /// absolute path on the target agent
    target: String,
    overwrite: String,
    /// the target agent's name, typed by the user
    confirm: String,
    /// target agent (same tenant; default for host snapshots: the snapshot's agent,
    /// required for every other source)
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentP {
    agent_id: String,
}

/// `agent_update`: the release to install (default: the recommended one).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentUpdateP {
    agent_id: String,
    #[serde(default)]
    version: Option<String>,
}

/// Name of an agent of `tenant`, or 400.
fn agent_name(st: &St, tenant: &str, id: &str) -> ApiResult<String> {
    validate::agent_id(id)?;
    let n = st
        .cat
        .conn()
        .query_row(
            "SELECT name FROM agents WHERE id = ?1 AND tenant = ?2",
            params![id, tenant],
            |r| r.get(0),
        )
        .optional()?;
    n.ok_or_else(|| ApiError::bad("agent_id: no such agent in this tenant"))
}

/// Full restore / instant recovery (options: Phase 15a, `crates/pve/src/restore.rs`).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestoreP {
    pub source: String,
    pub time: i64,
    pub node: String,
    pub target: u32,
    pub storage: String,
    /// name of the new guest (default `<backed-up name>-restore`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// or a prefix to the backed-up name
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    /// PVE resource pool
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// power on afterwards (instant recovery: default on)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<bool>,
    /// disconnect all NICs of the new guest
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_down: Option<bool>,
    /// replace the original guest: approval `restore.replace`, never a plain job
    #[serde(default, skip_serializing)]
    pub replace: bool,
    /// replace: leave the original's NICs connected
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_original_links: Option<bool>,
    /// Phase 30: replace by rolling the original VM back in place (changed chunks
    /// only; the full replace is the fallback); VMs, only with replace
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<bool>,
    /// the Proxmox VE source (cluster) to restore to; required for a VMware snapshot (`vmw-<uuid>`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<i64>,
    /// VMware snapshot: the bridge of the restored VM's NICs (default vmbr0)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
}

/// Instant disk recovery (Phase 22b, `nexus-pve instant-disk`): one disk of a VM
/// snapshot attached to the existing VM `target` (a VM a group of the tenant
/// protects on the same source; checked by the scheduler) as `key` (default:
/// the first free scsi slot), optionally moved to `move_to` afterwards.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InstantDiskP {
    source: String,
    time: i64,
    /// `drive-scsi1`
    device: String,
    node: String,
    target: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    move_to: Option<String>,
}

/// PVE guest / pool names (DNS-name characters, 1..=63, no leading `-` or `.`).
fn pve_name(s: &str, what: &str) -> ApiResult<()> {
    let ok = (1..=63).contains(&s.len())
        && !s.starts_with(['-', '.'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad(format!(
            "{what}: must match [A-Za-z0-9._-]{{1,63}} without a leading dot or dash"
        )))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesListP {
    source: String,
    time: i64,
    path: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FilesGetP {
    source: String,
    time: i64,
    paths: Vec<String>,
    format: String,
    /// plugin snapshots (contract v1.9): conversion parameters of the plugin's
    /// `download` restore (its `params_schema`, e.g. M365 `mail_format`); the plugin
    /// then converts the selection (`nexus-pluginhost export`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
    /// set by the web-api: the scheduler writes `<downloads>/<token>.<format>`
    #[serde(default, skip_deserializing)]
    download_token: String,
}

/// Phase 33 synthetic restore (scheduler `synthetic.rs`): a file-tree snapshot
/// of an agent, NAS or share with the newest clean version of each file.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticP {
    source: String,
    time: i64,
    /// paths inside the snapshot (default: everything)
    #[serde(default = "root_path")]
    paths: Vec<String>,
    /// older snapshots examined (1..=100, default 30)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    depth: Option<u64>,
    /// `download` (tar or zip) or `host` (onto an agent, like restore_files)
    mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    overwrite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    /// set by the web-api: the download (`mode: download`) and the CSV of substituted files
    #[serde(default, skip_deserializing, skip_serializing_if = "Option::is_none")]
    download_token: Option<String>,
    #[serde(default, skip_deserializing)]
    report_token: String,
}

fn root_path() -> Vec<String> {
    vec!["/".into()]
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PluginSourceP {
    source_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guests: Option<Vec<String>>,
    /// plugin_backup only (Phase 23a, crate::keep)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keep_until: Option<i64>,
}

/// `inventory`: refresh the guest inventory of one source (crate::inventory).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InventoryP {
    source_id: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PluginRestoreP {
    /// `plugin-<plugin>-<source id>[-<guest>]`
    source: String,
    time: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    restore: Option<String>,
    #[serde(default)]
    params: Value,
    /// plugin_mount: 1..=1440
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minutes: Option<u64>,
    /// plugin_restore into another source of the same tenant and kind (manifest
    /// `target_source`, e.g. Microsoft 365 into another M365 tenant)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_source_id: Option<i64>,
}

/// `offsite_restore`: fetch one offsite-only snapshot back into the store.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OffsiteRestoreP {
    source: String,
    time: i64,
    /// Phase 30: 2 = from the second offsite target
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<u8>,
}

/// The tenant has offsite target `n` (1: `tenants.offsite.remote`, 2: its `second`).
fn has_offsite_n(st: &St, tenant: &str, n: u8) -> ApiResult<()> {
    let o: Option<String> = st
        .cat
        .conn()
        .query_row("SELECT offsite FROM tenants WHERE name = ?1", [tenant], |r| r.get(0))
        .optional()?;
    let o: Value = o.and_then(|o| serde_json::from_str(&o).ok()).unwrap_or_default();
    let ok = match n {
        1 => o["remote"].is_object(),
        2 => o["second"]["remote"].is_object(),
        _ => return Err(ApiError::bad("target: 1 or 2")),
    };
    if ok {
        Ok(())
    } else if n == 2 {
        Err(ApiError::bad("tenant: has no second offsite target"))
    } else {
        Err(ApiError::bad("tenant: has no offsite target"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaintP {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    /// Phase 30: `offsite` / `offsite_list` on the second offsite target (2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<u8>,
}

fn parse<T: serde::de::DeserializeOwned>(v: Value) -> ApiResult<T> {
    let v = if v.is_null() { json!({}) } else { v };
    serde_json::from_value(v).map_err(|e| ApiError::bad(format!("params: {e}")))
}

/// Snapshots whose files `restore_files` can put onto an agent (Phase 15b): host,
/// TrueNAS dataset, NFS/SMB share, VM and CT snapshots, and plugin snapshots of a
/// plugin that offers the `download` restore (its `files` tree are plain files).
fn restorable_files(st: &St, tenant: &str, source: &str) -> ApiResult<()> {
    validate::source_ref(source)?;
    let Some((pid, sid, _)) = plugin_proto::parse_source_name(source).filter(|_| source.starts_with("plugin-")) else {
        return Ok(());
    };
    let (cur, spec) = crate::plugins::source_of(&st.cat.conn(), tenant, sid as i64)?;
    if cur.id != pid || !spec.restores.iter().any(|x| x.id == "download") {
        return Err(ApiError::bad(
            "source: this plugin's snapshots hold no plain files to restore (no download restore)",
        ));
    }
    Ok(())
}

fn snapshot_exists(st: &St, tenant: &str, source: &str, time: i64) -> ApiResult<()> {
    validate::source_ref(source)?;
    let found = st
        .cat
        .conn()
        .query_row(
            "SELECT 1 FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
            params![tenant, source, time],
            |_| Ok(()),
        )
        .optional()?;
    found.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()))
}

/// A point-in-time target as unix seconds: `YYYY-MM-DD HH:MM:SS` (or `T`), optional fraction, then `Z`, `+HH`,
/// `+HHMM` or `+HH:MM` (as the restore dialog writes it); `None` for other forms (the plugin's server checks those).
fn target_secs(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || !(b[10] == b' ' || b[10] == b'T') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    if b[4] != b'-'
        || b[7] != b'-'
        || b[13] != b':'
        || b[16] != b':'
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
    {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(f) = rest.strip_prefix('.') {
        rest = f.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let off = match rest {
        "Z" | "" => 0,
        _ => {
            let sign = match rest.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let digits: String = rest[1..].chars().filter(|c| *c != ':').collect();
            let (oh, om) = match digits.len() {
                2 => (digits.parse::<i64>().ok()?, 0),
                4 => (digits[..2].parse::<i64>().ok()?, digits[2..].parse::<i64>().ok()?),
                _ => return None,
            };
            sign * (oh * 3600 + om * 60)
        }
    };
    // days from the civil date (Howard Hinnant)
    let (yy, m) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se - off)
}

/// Validates and canonicalises the params of a job request.
pub(crate) fn check_params(st: &St, kind: &str, tenant: &str, p: Value) -> ApiResult<Value> {
    Ok(match kind {
        "backup" => {
            crate::replication::refuse_replicated(&st.cat.conn(), tenant)?;
            let mut b: BackupP = parse(p)?;
            crate::keep::check(b.keep_until)?;
            if b.group_id.is_none() && (b.guests.is_some() || b.failed_only) {
                return Err(ApiError::bad("params: guests and failed_only need group_id"));
            }
            match (b.group_id, b.vmid, &b.agent_id) {
                (None, None, Some(a)) => {
                    agent_name(st, tenant, a)?;
                }
                (Some(g), None, None) => {
                    let ok = st
                        .cat
                        .conn()
                        .query_row(
                            "SELECT 1 FROM groups WHERE id = ?1 AND tenant = ?2",
                            params![g, tenant],
                            |_| Ok(()),
                        )
                        .optional()?;
                    ok.ok_or_else(|| ApiError::bad("group_id: no such group in this tenant"))?;
                    b.guests = crate::runctl::backup_guests(&st.cat.conn(), g, b.guests.take(), b.failed_only)?;
                }
                (None, Some(v), None) => validate::vmid(v)?,
                _ => return Err(ApiError::bad("params: exactly one of group_id, vmid, agent_id")),
            }
            json!(b)
        }
        "restore_files" => {
            let mut r: RestoreFilesP = parse(p)?;
            restorable_files(st, tenant, &r.source)?;
            // host snapshots default to their own agent; other sources name the target
            let src_agent = match (r.source.strip_prefix("host-"), r.agent_id.as_deref()) {
                (_, Some(a)) | (Some(a), None) => a.to_owned(),
                (None, None) => return Err(ApiError::bad(
                    "agent_id: choose the agent to restore to (snapshots of NAS shares, plugins, VMs and containers)",
                )),
            };
            snapshot_exists(st, tenant, &r.source, r.time)?;
            if r.paths.is_empty() || r.paths.len() > 1000 {
                return Err(ApiError::bad("paths: 1..=1000 entries"));
            }
            for x in &mut r.paths {
                // snapshot entries of Windows agents are /C/...
                if let Some(c) = validate::windows_canonical(x) {
                    *x = c;
                }
                validate::host_path(x, "paths")?;
            }
            validate::host_path(&r.target, "target")?;
            if !["never", "if_older", "always"].contains(&r.overwrite.as_str()) {
                return Err(ApiError::bad("overwrite: never, if_older or always"));
            }
            let target_agent = r.agent_id.clone().unwrap_or(src_agent);
            let name = agent_name(st, tenant, &target_agent)?;
            if r.confirm != name {
                return Err(ApiError::bad(format!(
                    "confirm: type the target agent's name ({name}) to confirm the restore"
                )));
            }
            r.agent_id = Some(target_agent);
            json!(r)
        }
        "agent_update" => {
            let a: AgentUpdateP = parse(p)?;
            agent_name(st, tenant, &a.agent_id)?;
            match crate::agent_updates::check_update_version(st, &a.agent_id, a.version.as_deref())? {
                Some(v) => json!({"agent_id": a.agent_id, "version": v}),
                None => json!({"agent_id": a.agent_id}),
            }
        }
        "agent_enroll" | "agent_renew" => {
            let a: AgentP = parse(p)?;
            agent_name(st, tenant, &a.agent_id)?;
            json!(a)
        }
        "restore" | "restore_ct" | "instant_recover" => {
            let r: RestoreP = parse(p)?;
            let vmw = r.source.starts_with(vmware::names::SOURCE_PREFIX);
            if vmw {
                // a VMware VM as a new Proxmox VE VM (#34): full restore only, to a PVE source of the tenant
                validate::source_ref(&r.source)?;
                if kind != "restore" || r.replace || r.rollback == Some(true) {
                    return Err(ApiError::bad(
                        "source: a VMware snapshot is restored in full as a new VM (no replace, rollback or instant recovery)",
                    ));
                }
                let sid = r
                    .source_id
                    .ok_or_else(|| ApiError::bad("source_id: the Proxmox VE source to restore the VMware VM to"))?;
                let pve: Option<i64> = st
                    .cat
                    .conn()
                    .query_row(
                        "SELECT 1 FROM sources WHERE id = ?1 AND tenant = ?2 AND kind = 'pve'",
                        params![sid, tenant],
                        |r| r.get(0),
                    )
                    .optional()?;
                if pve.is_none() {
                    return Err(ApiError::bad("source_id: no Proxmox VE source of this tenant"));
                }
            } else {
                let want = if kind == "restore_ct" { "ct-" } else { "vm-" };
                if !r.source.starts_with(want) {
                    return Err(ApiError::bad(format!("source: {kind} needs a {want}<vmid> snapshot")));
                }
                if r.bridge.is_some() {
                    return Err(ApiError::bad("bridge: only for a VMware snapshot"));
                }
            }
            if let Some(b) = &r.bridge {
                validate::name(b, "bridge")?;
            }
            validate::name(&r.node, "node")?;
            validate::vmid(r.target)?;
            validate::name(&r.storage, "storage")?;
            if r.name.is_some() && r.name_prefix.is_some() {
                return Err(ApiError::bad("name, name_prefix: give at most one"));
            }
            for (v, what) in [(&r.name, "name"), (&r.name_prefix, "name_prefix"), (&r.pool, "pool")] {
                if let Some(v) = v {
                    pve_name(v, what)?;
                }
            }
            if r.replace {
                if kind == "instant_recover" {
                    return Err(ApiError::bad("replace: only a full restore can replace the original"));
                }
                if r.source[3..].parse::<u32>().ok() == Some(r.target) {
                    return Err(ApiError::bad("target: replace restores to a new VMID"));
                }
            } else if r.keep_original_links.is_some() {
                return Err(ApiError::bad("keep_original_links: only with replace"));
            }
            if r.rollback == Some(true) && (!r.replace || kind != "restore") {
                return Err(ApiError::bad("rollback: only a VM restore that replaces the original"));
            }
            snapshot_exists(st, tenant, &r.source, r.time)?;
            let mut v = json!(r);
            if r.replace {
                v["replace"] = json!(true); // taken out again by create_job (approval)
            }
            v
        }
        "instant_disk" => {
            let r: InstantDiskP = parse(p)?;
            if !r.source.starts_with("vm-") {
                return Err(ApiError::bad("source: instant_disk needs a vm-<vmid> snapshot"));
            }
            let slot_ok = |k: &str| {
                crate::selection::valid_disk_key(k) && !k.starts_with("efidisk") && !k.starts_with("tpmstate")
            };
            if !r.device.strip_prefix("drive-").is_some_and(slot_ok) {
                return Err(ApiError::bad("device: a data disk of the snapshot (drive-scsi1, …)"));
            }
            if r.key.as_deref().is_some_and(|k| !slot_ok(k) || k.starts_with("unused")) {
                return Err(ApiError::bad(
                    "key: a free disk slot of the target VM (scsi5, virtio2, …)",
                ));
            }
            validate::name(&r.node, "node")?;
            validate::vmid(r.target)?;
            if let Some(m) = &r.move_to {
                validate::name(m, "move_to")?;
            }
            snapshot_exists(st, tenant, &r.source, r.time)?;
            json!(r)
        }
        "files_list" => {
            let f: FilesListP = parse(p)?;
            validate::guest_path(&f.path)?;
            snapshot_exists(st, tenant, &f.source, f.time)?;
            json!(f)
        }
        "files_get" => {
            let mut f: FilesGetP = parse(p)?;
            if f.paths.is_empty() || f.paths.len() > 1000 {
                return Err(ApiError::bad("paths: 1..=1000 entries"));
            }
            for x in &f.paths {
                validate::guest_path(x)?;
            }
            if f.format != "tar" && f.format != "zip" {
                return Err(ApiError::bad("format: tar or zip"));
            }
            snapshot_exists(st, tenant, &f.source, f.time)?;
            if f.params
                .as_ref()
                .is_some_and(|v| v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty))
            {
                f.params = None;
            }
            if let Some(v) = &f.params {
                let schema = plugin_proto::parse_source_name(&f.source)
                    .filter(|_| f.source.starts_with("plugin-"))
                    .and_then(|(pid, sid, _)| {
                        let (cur, spec) = crate::plugins::source_of(&st.cat.conn(), tenant, sid as i64).ok()?;
                        let r = spec.restores.into_iter().find(|r| r.id == "download")?;
                        (cur.id == pid).then_some(r.params_schema).flatten()
                    })
                    .ok_or_else(|| ApiError::bad("params: this snapshot's download takes no parameters"))?;
                crate::plugins::check_schema(&schema, v, "params", &[])?;
            }
            f.download_token = random_hex();
            json!(f)
        }
        "synthetic_restore" => {
            let mut r: SyntheticP = parse(p)?;
            if !["host-", "nas-", "share-"].iter().any(|x| r.source.starts_with(x)) {
                return Err(ApiError::bad(
                    "source: synthetic restores take file-tree snapshots of agents, NAS (TrueNAS) and shares",
                ));
            }
            snapshot_exists(st, tenant, &r.source, r.time)?;
            if r.paths.is_empty() || r.paths.len() > 1000 {
                return Err(ApiError::bad("paths: 1..=1000 entries"));
            }
            for x in &mut r.paths {
                if let Some(c) = validate::windows_canonical(x) {
                    *x = c;
                }
                validate::host_path(x, "paths")?;
            }
            if r.depth.is_some_and(|d| !(1..=100).contains(&d)) {
                return Err(ApiError::bad("depth: 1..=100 older snapshots"));
            }
            match r.mode.as_str() {
                "download" => {
                    if r.target.is_some() || r.overwrite.is_some() || r.confirm.is_some() || r.agent_id.is_some() {
                        return Err(ApiError::bad(
                            "target, overwrite, confirm, agent_id: only with mode host",
                        ));
                    }
                    let f = r.format.get_or_insert_with(|| "tar".into());
                    if f != "tar" && f != "zip" {
                        return Err(ApiError::bad("format: tar or zip"));
                    }
                    r.download_token = Some(random_hex());
                }
                "host" => {
                    if r.format.is_some() {
                        return Err(ApiError::bad("format: only with mode download"));
                    }
                    let target = r
                        .target
                        .as_deref()
                        .ok_or_else(|| ApiError::bad("target: required with mode host"))?;
                    validate::host_path(target, "target")?;
                    let ow = r.overwrite.get_or_insert_with(|| "never".into());
                    if !["never", "if_older", "always"].contains(&ow.as_str()) {
                        return Err(ApiError::bad("overwrite: never, if_older or always"));
                    }
                    let agent = match (r.agent_id.clone(), r.source.strip_prefix("host-")) {
                        (Some(a), _) => a,
                        (None, Some(a)) => a.to_owned(),
                        (None, None) => {
                            return Err(ApiError::bad(
                                "agent_id: choose the agent to restore to (snapshots of NAS and shares)",
                            ))
                        }
                    };
                    let name = agent_name(st, tenant, &agent)?;
                    if r.confirm.as_deref() != Some(name.as_str()) {
                        return Err(ApiError::bad(format!(
                            "confirm: type the target agent's name ({name}) to confirm the restore"
                        )));
                    }
                    r.agent_id = Some(agent);
                }
                _ => return Err(ApiError::bad("mode: download or host")),
            }
            r.report_token = random_hex();
            json!(r)
        }
        "plugin_validate" | "plugin_guests" | "plugin_backup" => {
            let mut r: PluginSourceP = parse(p)?;
            if kind == "plugin_backup" {
                crate::replication::refuse_replicated(&st.cat.conn(), tenant)?;
            }
            let c = st.cat.conn();
            crate::keep::check(r.keep_until)?;
            let (_, spec) = crate::plugins::source_of(&c, tenant, r.source_id)?;
            if kind != "plugin_backup" {
                r.guests = None;
                if r.keep_until.is_some() {
                    return Err(ApiError::bad("keep_until: backups only"));
                }
            } else if let Some(g) = &r.guests {
                let mut v: Vec<Value> = g.iter().map(|x| json!(x)).collect();
                let k = format!("plugin:{}", spec.kind);
                crate::plugins::check_guests(&c, &k, &mut v)?;
                r.guests = Some(v.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect());
            }
            json!(r)
        }
        "plugin_restore" | "plugin_mount" => {
            let mut r: PluginRestoreP = parse(p)?;
            snapshot_exists(st, tenant, &r.source, r.time)?;
            let (pid, sid, guest) = plugin_proto::parse_source_name(&r.source)
                .ok_or_else(|| ApiError::bad("source: a plugin-<plugin>-<source-id> snapshot"))?;
            let (cur, spec) = crate::plugins::source_of(&st.cat.conn(), tenant, sid as i64)?;
            if cur.id != pid {
                return Err(ApiError::bad("source: the snapshot belongs to another plugin"));
            }
            let want = if kind == "plugin_mount" {
                r.minutes = Some(r.minutes.unwrap_or(60));
                if !(1..=1440).contains(&r.minutes.unwrap()) {
                    return Err(ApiError::bad("minutes: 1..=1440"));
                }
                r.restore = None;
                if r.target_source_id.is_some() {
                    return Err(ApiError::bad("target_source_id: restores only"));
                }
                "mount".to_owned()
            } else {
                r.minutes = None;
                r.restore.clone().ok_or_else(|| ApiError::bad("restore: required"))?
            };
            if want == "download" {
                return Err(ApiError::bad("restore: download runs as files_get"));
            }
            let action = spec
                .restores
                .iter()
                .find(|x| x.id == want)
                .ok_or_else(|| ApiError::bad(format!("restore: {want} is not offered by this plugin")))?;
            if !action.applies(guest.is_some()) {
                return Err(ApiError::bad(format!(
                    "restore: {want} applies to {} snapshots only",
                    action.applies_to.as_deref().unwrap_or("any")
                )));
            }
            if r.params.is_null() {
                r.params = json!({});
            }
            match &action.params_schema {
                Some(schema) => crate::plugins::check_schema(schema, &r.params, "params", &[])?,
                None if r.params.as_object().is_some_and(serde_json::Map::is_empty) => {}
                None => return Err(ApiError::bad("params: this restore takes no parameters")),
            }
            // #49: a point-in-time target outside the snapshot's recoverable range (plugin metadata) is refused here
            // too, not only by the dialog (the server would end recovery before reaching it)
            if let Some(ts) = r.params["target_time"].as_str().and_then(target_secs) {
                let meta: Option<String> = st
                    .cat
                    .conn()
                    .query_row(
                        "SELECT meta FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
                        params![tenant, r.source, r.time],
                        |row| row.get(0),
                    )
                    .optional()?
                    .flatten();
                let range = meta.and_then(|m| serde_json::from_str::<Value>(&m).ok());
                let (from, to) = match range.as_ref().map(|m| &m["recoverable"]) {
                    Some(rc) => (rc["from_time"].as_i64(), rc["to_time"].as_i64()),
                    None => (None, None),
                };
                if let (Some(from), Some(to)) = (from, to) {
                    if ts < from || ts > to {
                        return Err(ApiError::bad(format!(
                            "params.target_time: outside the recoverable range of this snapshot ({from} to {to}, unix seconds)"
                        )));
                    }
                }
            }
            if let Some(tid) = r.target_source_id {
                // only sources of the same appliance tenant (source_of) and plugin kind
                if !action.target_source {
                    return Err(ApiError::bad(format!(
                        "target_source_id: restore {want} cannot run into another source"
                    )));
                }
                let (tcur, tspec) = crate::plugins::source_of(&st.cat.conn(), tenant, tid)
                    .map_err(|_| ApiError::bad("target_source_id: no such plugin source in this tenant"))?;
                if tcur.id != cur.id || tspec.kind != spec.kind {
                    return Err(ApiError::bad(format!("target_source_id: not a {} source", spec.kind)));
                }
            }
            json!(r)
        }
        "inventory" => {
            let r: InventoryP = parse(p)?;
            let c = st.cat.conn();
            let kind: String = c
                .query_row(
                    "SELECT kind FROM sources WHERE id = ?1 AND tenant = ?2",
                    params![r.source_id, tenant],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or_else(|| ApiError::bad("source_id: no such source in this tenant"))?;
            if !crate::inventory::has_inventory(&c, &kind) {
                return Err(ApiError::bad("source_id: this source has no guest inventory"));
            }
            json!(r)
        }
        "offsite_list" => {
            let m: MaintP = parse(p)?;
            has_offsite_n(st, tenant, m.target.unwrap_or(1))?;
            match m.target {
                Some(2) => json!({"target": 2}),
                _ => json!({}),
            }
        }
        "offsite_restore" => {
            let r: OffsiteRestoreP = parse(p)?;
            validate::source_ref(&r.source)?;
            let n = r.target.unwrap_or(1);
            has_offsite_n(st, tenant, n)?;
            let col = if n == 2 { "offsite2" } else { "offsite" };
            let row: Option<(bool, bool)> = st
                .cat
                .conn()
                .query_row(
                    &format!("SELECT local, {col} FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3"),
                    params![tenant, r.source, r.time],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                None | Some((_, false)) => {
                    return Err(ApiError(StatusCode::NOT_FOUND, "no such offsite snapshot".into()))
                }
                Some((true, _)) => return Err(ApiError::conflict("the snapshot is in the local store already")),
                Some((false, true)) => {}
            }
            json!(r)
        }
        "chunk_repair" => {
            let _: Empty = parse(p)?;
            json!({})
        }
        "offsite" | "retention" | "gc" | "verify" => {
            let m: MaintP = parse(p)?;
            if let Some(s) = &m.source {
                validate::source_ref(s)?;
            }
            if let Some(n) = m.target {
                if kind != "offsite" {
                    return Err(ApiError::bad("target: only for offsite jobs"));
                }
                has_offsite_n(st, tenant, n)?;
            }
            json!(m)
        }
        // Phase 25: an isolated restore test (recovery.rs)
        "restore_test" => crate::recovery::check_test(st, tenant, p)?,
        _ => return Err(ApiError::bad("kind: unknown job kind")),
    })
}

/// 202 `{id}` (+ `download_token` for `files_get`, which also needs the
/// account's download privilege). Viewers and security officers request no jobs.
pub async fn create_job(State(st): State<St>, ctx: Ctx, J(r): J<JobReq>) -> ApiResult<Response> {
    let allowed = match ctx.user.role.as_str() {
        "admin" => true,
        "operator" => !ADMIN_KINDS.contains(&r.kind.as_str()),
        "tenant_user" => RESTORE_KINDS.contains(&r.kind.as_str()),
        "tenant_admin" => !PROVIDER_KINDS.contains(&r.kind.as_str()),
        "viewer" | "security_officer" => false,
        _ => false,
    };
    if !allowed || (r.kind == "files_get" && !ctx.user.can_download) {
        return Err(ApiError::forbidden());
    }
    if ctx.token.as_ref().is_some_and(|t| t.scope == "backup") && r.kind != "backup" {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "this API token may only start backups".into(),
        ));
    }
    if ctx.token.is_some() && crate::tokens::DENIED_KINDS.contains(&r.kind.as_str()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "API tokens cannot start downloads or mounts".into(),
        ));
    }
    validate::name(&r.tenant, "tenant")?;
    if !ctx.sees(&r.tenant) {
        return Err(ApiError::forbidden());
    }
    let tenant_ok = st
        .cat
        .conn()
        .query_row("SELECT 1 FROM tenants WHERE name = ?1", [&r.tenant], |_| Ok(()))
        .optional()?;
    tenant_ok.ok_or_else(|| ApiError::bad("tenant: does not exist"))?;
    crate::tenants::refuse_paused(&st.cat.conn(), &r.tenant, &r.kind)?;
    let mut raw = r.params;
    // Phase 21e: YARA scan before the restore (scheduler `scan.rs` holds the job)
    let scan_first = crate::scan::take_scan_first(&st.cat.conn(), &r.kind, &mut raw)?;
    let mut params = check_params(&st, &r.kind, &r.tenant, raw)?;
    if let Some(s) = scan_first {
        params["scan_first"] = json!(s);
    }
    // Phase 33: a synthetic download is a download (privilege, never through a token)
    if r.kind == "synthetic_restore" && params["mode"] == "download" {
        if !ctx.user.can_download {
            return Err(ApiError::forbidden());
        }
        if ctx.token.is_some() {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "API tokens cannot start downloads or mounts".into(),
            ));
        }
    }
    // Phase 28: a locked-down tenant gets no backups and no restores that overwrite
    crate::lockdown::refuse_job(&st.cat.conn(), &r.tenant, &r.kind, &params)?;
    // Phase 29: frozen restores to production; flagged snapshots to production need approval
    if let Some(res) = crate::infected::gate(&st, &ctx, &r.kind, &r.tenant, &params)? {
        return Ok(res);
    }
    if params.get("replace").is_some() {
        return request_replace(&st, &ctx, &r.kind, &r.tenant, params).map(|o| crate::quorum::accepted(o, json!({})));
    }
    // vault mode: restores and downloads only through approval (`vault.restore`)
    if let Some(res) = crate::vault::gate_jobs(&st, &ctx, &r.tenant, &[(r.kind.as_str(), &params)])? {
        return Ok(res);
    }
    // Phase 23a: a lock beyond `keep_until_max_days` needs approval
    if let Some(res) = crate::keep::gate_job(&st, &ctx, &r.kind, &r.tenant, &params)? {
        return Ok(res);
    }
    let id = {
        let c = st.cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES (?1, ?2, ?3, 'queued', ?4, ?5)",
            params![r.kind, r.tenant, params.to_string(), ctx.name(), catalog::now()],
        )?;
        c.last_insert_rowid()
    };
    st.audit(
        ctx.name(),
        "job.create",
        &format!("job/{id}"),
        json!({"kind": r.kind, "tenant": r.tenant, "params": params}),
    )?;
    let mut body = json!({"id": id});
    for k in ["download_token", "report_token"] {
        if let Some(t) = params.get(k) {
            body[k] = t.clone();
        }
    }
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

/// Replace original (Phase 15a): admins and operators only, never via a token;
/// approval `restore.replace` (executed by the scheduler as a restore job).
fn request_replace(
    st: &St,
    ctx: &Ctx,
    kind: &str,
    tenant: &str,
    mut params: Value,
) -> ApiResult<crate::quorum::Outcome> {
    ctx.require(RUNNERS)?;
    if ctx.token.is_some() {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "API tokens cannot replace guests".into(),
        ));
    }
    if let Some(o) = params.as_object_mut() {
        o.remove("replace");
    }
    let target = format!(
        "snapshot/{tenant}/{}/{}",
        params["source"].as_str().unwrap_or_default(),
        params["time"]
    );
    crate::quorum::request(
        st,
        ctx,
        "restore.replace",
        &target,
        json!({"tenant": tenant, "kind": kind, "params": params}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobFilter {
    state: Option<String>,
    kind: Option<String>,
    tenant: Option<String>,
    limit: Option<u32>,
}

fn job_json(r: &catalog::rusqlite::Row, with_log: bool) -> catalog::rusqlite::Result<Value> {
    let p: String = r.get(3)?;
    let raw = serde_json::from_str::<Value>(&p).unwrap_or_default();
    // sealed values (an `offsite_attach` recovery key until the scheduler takes it) never leave;
    // the download token stays visible here (only its requester can use it, see `download`) —
    // quorum::redact hides it from approval lists (vault mode, 17c)
    let mut params = crate::quorum::redact(raw.clone());
    if let Some(tok) = raw.get("download_token") {
        params["download_token"] = tok.clone();
    }
    let mut v = json!({
        "id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "tenant": r.get::<_, String>(2)?,
        "params": params,
        "state": r.get::<_, String>(4)?,
        "requested_by": r.get::<_, String>(5)?, "created": r.get::<_, i64>(6)?,
        "started": r.get::<_, Option<i64>>(7)?, "finished": r.get::<_, Option<i64>>(8)?,
        "result": r.get::<_, Option<String>>(10)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
        "attempt": r.get::<_, i64>(11)?, "retry_of": r.get::<_, Option<i64>>(12)?,
        "not_before": r.get::<_, Option<i64>>(13)?, "cancel_by": r.get::<_, Option<String>>(14)?,
        // live progress of a running job (scheduler, docs/control-plane.md "Live progress")
        "progress": r.get::<_, Option<String>>(15)?.and_then(|s| serde_json::from_str::<Value>(&s).ok()),
    });
    if with_log {
        // a running job: its output so far (`live_log`) after what was logged before it started
        let mut log = r.get::<_, String>(9)?;
        log.push_str(&r.get::<_, Option<String>>(16)?.unwrap_or_default());
        v["log"] = json!(log);
    }
    Ok(v)
}

const JOB_COLS: &str = "id, kind, tenant, params, state, requested_by, created, started, finished, log, result, \
                        attempt, retry_of, not_before, cancel_by, progress, live_log";

pub async fn list_jobs(State(st): State<St>, ctx: Ctx, Q(f): Q<JobFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let rows = c
        .prepare(&format!(
            "SELECT {JOB_COLS} FROM jobs WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR kind = ?2)
             AND (?3 IS NULL OR tenant = ?3) AND (?4 IS NULL OR tenant = ?4) ORDER BY id DESC LIMIT ?5"
        ))?
        .query_map(
            params![f.state, f.kind, f.tenant, ctx.scope(), f.limit.unwrap_or(100).min(1000)],
            |r| job_json(r, false),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

pub async fn get_job(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    let mut job = c
        .query_row(
            &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)"),
            params![id, ctx.scope()],
            |r| job_json(r, true),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    // the jobs it queued (params.after_job: retention, offsite, file index after a backup)
    let followups = c
        .prepare(
            "SELECT id, kind, state, created, started, finished FROM jobs
             WHERE json_extract(params, '$.after_job') = ?1 AND (?2 IS NULL OR tenant = ?2) ORDER BY id",
        )?
        .query_map(params![id, ctx.scope()], |r| {
            Ok(
                json!({"id": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "state": r.get::<_, String>(2)?,
                      "created": r.get::<_, i64>(3)?, "started": r.get::<_, Option<i64>>(4)?,
                      "finished": r.get::<_, Option<i64>>(5)?}),
            )
        })?
        .collect::<Result<Vec<_>, _>>()?;
    job["followups"] = Value::Array(followups);
    Ok(Json(job))
}

/// `GET /jobs/{id}/synthetic.csv` (Phase 33): the files a synthetic restore
/// substituted, brought back or left out (written by the scheduler next to the
/// downloads, kept as long as a download). Roles that may request restores, in
/// their scope; audited `synthetic.report`.
pub async fn synthetic_report(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    ctx.require(&["admin", "operator", "tenant_admin", "tenant_user"])?;
    let token: Option<String> = st
        .cat
        .conn()
        .query_row(
            "SELECT json_extract(params, '$.report_token') FROM jobs
             WHERE id = ?1 AND kind = 'synthetic_restore' AND (?2 IS NULL OR tenant = ?2)",
            params![id, ctx.scope()],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    let token = token
        .filter(|t| t.len() == 64 && t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .ok_or_else(ApiError::not_found)?;
    let path = st.downloads.join(format!("{token}.csv"));
    let csv = tokio::fs::read(&path).await.map_err(|_| {
        ApiError(
            StatusCode::NOT_FOUND,
            "no report (the job has not decided yet, or it expired)".into(),
        )
    })?;
    st.audit(
        ctx.name(),
        "synthetic.report",
        &format!("job/{id}"),
        json!({"bytes": csv.len()}),
    )?;
    let mut res = Body::from(csv).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"synthetic-restore-{id}.csv\""))
            .map_err(|_| ApiError::not_found())?,
    );
    Ok(res)
}

/// Queued jobs are cancelled here; running jobs get a cancel request
/// (`jobs.cancel_by`) that the scheduler carries out (Phase 13b: SIGTERM, then
/// SIGKILL after 30 s; the job ends `cancelled`). Answers the state after the
/// request: `cancelled` or `cancelling`.
pub async fn cancel_job(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    ctx.require(RUNNERS)?;
    let state = {
        let c = st.cat.conn();
        let (state, replace): (String, bool) = c
            .query_row(
                "SELECT state, COALESCE(json_extract(params, '$.replace'), 0) = 1 FROM jobs
                 WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
                params![id, ctx.scope()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(ApiError::not_found)?;
        // stopping it between stopping and restoring the original could leave the
        // original switched off and renamed (Phase 15a; its own rollback needs to run)
        if replace && state == "running" {
            return Err(ApiError::conflict(
                "a running restore that replaces the original cannot be cancelled",
            ));
        }
        let queued = c.execute(
            "UPDATE jobs SET state = 'cancelled', finished = ?2 WHERE id = ?1 AND state = 'queued'",
            params![id, catalog::now()],
        )?;
        let running = c.execute(
            "UPDATE jobs SET cancel_by = ?2 WHERE id = ?1 AND state = 'running' AND cancel_by IS NULL",
            params![id, ctx.name()],
        )?;
        match (queued, running) {
            (1, _) => "cancelled",
            (_, 1) => "cancelling",
            _ if state == "running" => return Err(ApiError::conflict("cancellation already requested")),
            _ => {
                return Err(ApiError::conflict(format!(
                    "job is {state}, only queued or running jobs can be cancelled"
                )))
            }
        }
    };
    st.audit(
        ctx.name(),
        "job.cancel",
        &format!("job/{id}"),
        json!({"running": state == "cancelling"}),
    )?;
    Ok(Json(json!({"id": id, "state": state})))
}

/// Streams `<downloads>/<token>.<format>` to the user who requested the
/// `files_get` job (everyone else gets 404). Files older than 24 h are gone
/// (the scheduler deletes them; we refuse to serve them meanwhile).
pub async fn download(State(st): State<St>, ctx: Ctx, Path(token): Path<String>) -> ApiResult<Response> {
    if !ctx.user.can_download {
        return Err(ApiError::forbidden());
    }
    if token.len() != 64 || !token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ApiError::not_found());
    }
    // agent installers (Phase 27): token from POST /agent-releases/{version}/download
    if let Some((path, name)) = crate::agent_updates::installer_file(&st, &token, ctx.name())? {
        let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::not_found())?;
        let meta = file.metadata().await.map_err(|_| ApiError::not_found())?;
        st.audit(
            ctx.name(),
            "download.get",
            &format!("agent-installer/{name}"),
            json!({"bytes": meta.len()}),
        )?;
        let mut res = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
        let h = res.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
        h.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")).map_err(|_| ApiError::not_found())?,
        );
        return Ok(res);
    }
    let job = st
        .cat
        .conn()
        .query_row(
            "SELECT id, requested_by, json_extract(params, '$.format') FROM jobs
             WHERE kind IN ('files_get', 'synthetic_restore') AND json_extract(params, '$.download_token') = ?1",
            [&token],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
        )
        .optional()?;
    let Some((job_id, by, format)) = job.filter(|(_, by, _)| by == ctx.name()) else {
        return Err(ApiError::not_found());
    };
    let ext = if format == "zip" { "zip" } else { "tar" };
    let path = st.downloads.join(format!("{token}.{ext}"));
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::not_found())?;
    let meta = file.metadata().await.map_err(|_| ApiError::not_found())?;
    let age = meta
        .modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .map_or(i64::MAX, |d| d.as_secs() as i64);
    if !meta.is_file() || age > DOWNLOAD_TTL_SECS {
        return Err(ApiError::not_found());
    }
    st.audit(
        &by,
        "download.get",
        &format!("job/{job_id}"),
        json!({"bytes": meta.len()}),
    )?;
    let mut res = Body::from_stream(tokio_util::io::ReaderStream::new(file)).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if ext == "zip" {
            "application/zip"
        } else {
            "application/x-tar"
        }),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(meta.len()));
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"restore-{job_id}.{ext}\"")).unwrap(),
    );
    Ok(res)
}

// ---------------------------------------------------------------- snapshots

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapFilter {
    tenant: Option<String>,
    source: Option<String>,
    /// only snapshots with an open (active or advisory) legal hold
    held: Option<bool>,
}

pub async fn list_snapshots(State(st): State<St>, ctx: Ctx, Q(f): Q<SnapFilter>) -> ApiResult<Json<Value>> {
    let c = st.cat.conn();
    // the open legal hold (v18) of each snapshot, if any
    let rows = c
        .prepare(&format!(
            "SELECT s.tenant, s.source, s.time, s.size, s.local, s.offsite, s.lock_until, s.verified, s.origin,
                    h.id IS NOT NULL, s.consistency, s.meta, s.anomaly, s.anomaly_at, s.anomaly_cleared_by,
                    s.anomaly_cleared_at, s.anomaly_note, {}, s.damaged AS damaged, s.damaged_at AS damaged_at,
                    (SELECT json_object('job', job_id, 'finished', finished, 'matches', matches_total,
                       'complete', json(CASE WHEN complete = 1 THEN 'true' ELSE 'false' END)) FROM snapshot_scans x
                     WHERE x.tenant = s.tenant AND x.source = s.source AND x.time = s.time
                     ORDER BY job_id DESC LIMIT 1) AS scan, s.scan_state AS scan_state,
                    s.clean_point AS clean_point, s.offsite2 AS offsite2,
                    (SELECT json_object('state', state, 'reason', reason) FROM snapshot_index y
                     WHERE y.tenant = s.tenant AND y.source = s.source AND y.time = s.time) AS file_index,
                    COALESCE((SELECT i.name FROM inventory i JOIN sources so ON so.id = i.source_id
                              WHERE so.tenant = s.tenant AND (s.source LIKE 'vm-%' OR s.source LIKE 'ct-%')
                                AND i.guest = substr(s.source, 4) AND i.name != '' LIMIT 1),
                             (SELECT a.name FROM agents a WHERE 'host-' || a.id = s.source)) AS label
             FROM snapshots s

             LEFT JOIN legal_holds h ON h.tenant = s.tenant AND h.source = s.source AND h.time = s.time
               AND h.state IN ('active','advisory')
             WHERE (?1 IS NULL OR s.tenant = ?1) AND (?2 IS NULL OR s.source = ?2) AND (?3 IS NULL OR s.tenant = ?3)
               AND (?4 IS NULL OR ?4 = 0 OR h.id IS NOT NULL)
             ORDER BY s.tenant, s.source, s.time DESC",
            crate::holds::COLUMNS
        ))?
        .query_map(params![f.tenant, f.source, ctx.scope(), f.held], |r| {
            let idx = r
                .get::<_, Option<String>>("file_index")?
                .and_then(|v| serde_json::from_str::<Value>(&v).ok());
            let hold = if r.get::<_, bool>(9)? {
                crate::holds::row(r)?
            } else {
                Value::Null
            };
            Ok(json!({
                "tenant": r.get::<_, String>(0)?, "source": r.get::<_, String>(1)?, "time": r.get::<_, i64>(2)?,
                "size": r.get::<_, i64>(3)?, "local": r.get::<_, bool>(4)?, "offsite": r.get::<_, bool>(5)?,
                // Phase 30: on the tenant's second offsite target
                "offsite2": r.get::<_, bool>("offsite2")?,
                "lock_until": r.get::<_, i64>(6)?, "verified": r.get::<_, Option<i64>>(7)?,
                "origin": r.get::<_, Option<String>>(8)?, "hold": hold,
                "consistency": r.get::<_, Option<String>>(10)?,
                // plugin snapshot metadata (v23), e.g. a recoverable range
                "meta": r.get::<_, Option<String>>(11)?.and_then(|m| serde_json::from_str::<Value>(&m).ok()),
                // Phase 21a: change-rate / file-level anomaly flag (cleared = clean again)
                "anomaly": match r.get::<_, Option<String>>(12)? {
                    Some(reason) => json!({"reason": reason, "at": r.get::<_, Option<i64>>(13)?,
                        "cleared_by": r.get::<_, Option<String>>(14)?, "cleared_at": r.get::<_, Option<i64>>(15)?,
                        "note": r.get::<_, Option<String>>(16)?}),
                    None => Value::Null,
                },
                "anomalous": r.get::<_, Option<String>>(12)?.is_some() && r.get::<_, Option<i64>>(15)?.is_none(),
                // Phase 21d: references chunks that failed verify (count of bad chunks)
                "damaged": r.get::<_, Option<i64>>("damaged")?,
                "damaged_at": r.get::<_, Option<i64>>("damaged_at")?,
                // Phase 21e: the latest YARA scan `{job, finished, matches, complete}`
                "scan": r.get::<_, Option<String>>("scan")?.and_then(|v| serde_json::from_str::<Value>(&v).ok()),
                // Phase 28: its verdict `clean` | `hit` | `incomplete`, null = unscanned
                "scan_state": r.get::<_, Option<String>>("scan_state")?,
                // Phase 29: restoring it to production needs approval `restore.infected`
                "flagged": r.get::<_, Option<i64>>(15)?.is_none()
                    && (r.get::<_, Option<String>>(12)?.is_some()
                        || r.get::<_, Option<String>>("scan_state")?.as_deref() == Some("hit")),
                // Phase 29: marked by a scan back as the source's recommended restore point
                "clean_point": r.get::<_, Option<i64>>("clean_point")?,
                // the guest's or agent's name (inventory, agents), shown next to the source
                "label": r.get::<_, Option<String>>("label")?,
                // Phase 31: file index state of VM/CT snapshots (catalog v42 snapshot_index)
                "index_state": idx.as_ref().map(|v| v["state"].clone()),
                "index_reason": idx.as_ref().map(|v| v["reason"].clone()),
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(Value::Array(rows)))
}

/// Deletes one local snapshot (admin, approval action `snapshot.delete`, executed
/// by the scheduler). Refused at once while it is locked, when only the offsite
/// copy is left (offsite retention), for replicated snapshots (the
/// replication source's retention; a deleted one would be fetched again) and
/// under a legal hold (the scheduler checks the hold again when it runs).
pub async fn delete_snapshot(
    State(st): State<St>,
    ctx: Ctx,
    Path((tenant, source, time)): Path<(String, String, i64)>,
) -> ApiResult<Response> {
    ctx.require(&["admin"])?;
    validate::name(&tenant, "tenant")?;
    validate::source_ref(&source)?;
    if !ctx.sees(&tenant) {
        return Err(ApiError::forbidden());
    }
    crate::lockdown::refuse(&st.cat.conn(), &tenant, "deletes")?;
    if catalog::incident::frozen(&st.cat.conn(), &tenant)?.deletions {
        return Err(ApiError::conflict(
            "incident mode: deletions are frozen; lifting the freeze needs a second approver",
        ));
    }
    let row: Option<(bool, i64, Option<String>)> = st
        .cat
        .conn()
        .query_row(
            "SELECT local, lock_until, origin FROM snapshots WHERE tenant = ?1 AND source = ?2 AND time = ?3",
            params![tenant, source, time],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (local, lock_until, origin) = row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no such snapshot".into()))?;
    if !local {
        return Err(ApiError::conflict(
            "only the offsite copy is left: it follows the offsite retention",
        ));
    }
    if origin.is_some() {
        return Err(ApiError::conflict(
            "replicated snapshot: it follows the replication source's retention",
        ));
    }
    if lock_until > catalog::now() {
        return Err(ApiError::conflict(format!(
            "snapshot is locked until {lock_until} (unix time)"
        )));
    }
    if catalog::holds::active(&st.cat.conn(), &tenant, &source, time)?.is_some() {
        return Err(ApiError::conflict(
            "snapshot is under a legal hold: release it first (needs approval)",
        ));
    }
    let o = crate::quorum::request(
        &st,
        &ctx,
        "snapshot.delete",
        &format!("snapshot/{tenant}/{source}/{time}"),
        json!({"tenant": tenant, "source": source, "time": time}),
    )?;
    Ok(crate::quorum::accepted(o, json!({})))
}

#[cfg(test)]
mod pitr_tests {
    use super::target_secs;

    #[test]
    fn target_time_forms() {
        // 2026-10-10 14:30:00 UTC = 1791642600
        assert_eq!(target_secs("2026-10-10 14:30:00+00"), Some(1_791_642_600));
        assert_eq!(target_secs("2026-10-10T14:30:00Z"), Some(1_791_642_600));
        assert_eq!(target_secs("2026-10-10 16:30:00.250+02:00"), Some(1_791_642_600));
        assert_eq!(target_secs("2026-10-10 09:30:00-0500"), Some(1_791_642_600));
        assert_eq!(target_secs("1970-01-01 00:00:00+00"), Some(0));
        for bad in [
            "",
            "yesterday",
            "2026-13-01 00:00:00+00",
            "2026-10-10 14:30:00 CET",
            "2026-10-10",
        ] {
            assert_eq!(target_secs(bad), None, "{bad}");
        }
    }
}
