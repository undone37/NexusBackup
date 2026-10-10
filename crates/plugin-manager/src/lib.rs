//! Plugin manager (docs/plugin-system.md "Trust and lifecycle"): verification of
//! uploaded bundles (web-api), lifecycle rows in the catalog (`plugins`,
//! `plugin_keys`, catalog v8) and the installer `nexus-plugin-install`.
//!
//! Flow: the web-api verifies an upload (signature against the project keys of the
//! image + the publisher keys added with quorum, manifest, API version, publisher
//! binding, id ownership, strictly newer version, no kind taken by another plugin),
//! stores it in the staging dir as `<sha256>.nxplugin` + `.sig`, records the row as
//! `pending` and asks for quorum. On approval the row becomes `approved` (all checks
//! repeated) and the web-api touches `<staging>/.trigger`. The installer — its own
//! uid `nexus-plugins`, not the plugin runtime uid — verifies everything again
//! against the catalog record, unpacks to `<plugins>/<id>/<version>/` (dirs 0555,
//! files 0444, `bin/plugin` 0555), marks it `installed` + `current` and removes the
//! staged files. `removing` rows are deleted from disk the same way.

use catalog::rusqlite::{params, Connection, OptionalExtension};
use catalog::Catalog;
use plugin_proto::bundle::{self, Bundle, TrustedKey};
use plugin_proto::{newer, Manifest};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const ACTOR: &str = "plugin-installer";

/// An error with an HTTP-like status for the web-api (400 bad input, 409 conflict).
#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}

fn bad(m: impl Into<String>) -> Error {
    Error {
        status: 400,
        message: m.into(),
    }
}
fn conflict(m: impl Into<String>) -> Error {
    Error {
        status: 409,
        message: m.into(),
    }
}
fn db(e: catalog::rusqlite::Error) -> Error {
    Error {
        status: 500,
        message: format!("catalog: {e}"),
    }
}

/// `sha256:<hex>` (the form shown in the UI and used in `/plugin-keys/{fp}`).
pub fn key_id(k: &TrustedKey) -> String {
    format!("sha256:{}", k.fingerprint())
}

/// Trusted keys: the image's project keys plus the catalog's publisher keys.
pub fn trusted_keys(c: &Connection, project_dir: &Path) -> Result<Vec<TrustedKey>, Error> {
    let mut keys = bundle::load_project_keys(project_dir);
    let mut st = c
        .prepare("SELECT fingerprint, publisher, public_key FROM plugin_keys ORDER BY added_at")
        .map_err(db)?;
    let rows = st
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })
        .map_err(db)?;
    for row in rows {
        let (fp, publisher, pem) = row.map_err(db)?;
        if let Ok(point) = bundle::parse_public_key(&pem) {
            keys.push(TrustedKey {
                name: format!("{publisher}/{}", &fp[..fp.len().min(23)]),
                publisher,
                point,
                builtin: false,
            });
        }
    }
    Ok(keys)
}

/// Result of a successful upload check.
#[derive(Debug, Clone)]
pub struct Verified {
    pub bundle: Bundle,
    pub sha256: String,
    pub size: usize,
    pub signer: String,
    pub upgrade_from: Option<String>,
}

struct Row {
    version: String,
    publisher: String,
    state: String,
}

fn rows_of(c: &Connection, id: &str) -> Result<Vec<Row>, Error> {
    let mut st = c
        .prepare("SELECT version, publisher, state FROM plugins WHERE id = ?1")
        .map_err(db)?;
    let rows = st
        .query_map([id], |r| {
            Ok(Row {
                version: r.get(0)?,
                publisher: r.get(1)?,
                state: r.get(2)?,
            })
        })
        .map_err(db)?;
    rows.collect::<Result<_, _>>().map_err(db)
}

/// Id ownership, version order and kind uniqueness against the catalog
/// (`pending_ok`: the row of this very version may exist as pending — approval).
fn check_lifecycle(c: &Connection, m: &Manifest, pending_ok: bool) -> Result<Option<String>, Error> {
    let rows = rows_of(c, &m.id)?;
    if let Some(o) = rows
        .iter()
        .find(|r| r.publisher != m.publisher && r.state != "removed" && r.state != "rejected")
    {
        return Err(conflict(format!(
            "plugin id {} belongs to publisher {} (refused for {})",
            m.id, o.publisher, m.publisher
        )));
    }
    let mut upgrade_from: Option<String> = None;
    for r in &rows {
        if r.version == m.version {
            let ok = match r.state.as_str() {
                "pending" => pending_ok,
                "failed" | "rejected" | "removed" => true,
                _ => false,
            };
            if !ok {
                return Err(conflict(format!("{} {} is already {}", m.id, m.version, r.state)));
            }
        } else if (r.state == "installed" || r.state == "approved") && !newer(&m.version, &r.version) {
            return Err(conflict(format!(
                "{} {} is not newer than {} (downgrades are refused)",
                m.id, m.version, r.version
            )));
        } else if r.state == "installed" && upgrade_from.as_deref().is_none_or(|u| newer(&r.version, u)) {
            upgrade_from = Some(r.version.clone());
        }
    }
    // a kind must not be provided by another plugin id (source kinds are `plugin:<kind>`)
    let mut st = c
        .prepare("SELECT id, manifest FROM plugins WHERE id != ?1 AND state IN ('pending','approved','installed','removing')")
        .map_err(db)?;
    let others = st
        .query_map([&m.id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(db)?;
    for o in others {
        let (oid, om) = o.map_err(db)?;
        let Ok(om) = serde_json::from_str::<Manifest>(&om) else {
            continue;
        };
        if let Some(k) = m.kinds.iter().find(|k| om.kinds.iter().any(|x| x.kind == k.kind)) {
            return Err(conflict(format!("kind {} is already provided by plugin {oid}", k.kind)));
        }
    }
    Ok(upgrade_from)
}

/// Verifies an uploaded bundle + detached signature.
pub fn verify_upload(c: &Connection, project_keys: &Path, bytes: &[u8], sig: &[u8]) -> Result<Verified, Error> {
    let b = bundle::read(bytes).map_err(bad)?;
    let keys = trusted_keys(c, project_keys)?;
    let k = bundle::verify(bytes, sig, &keys).map_err(bad)?;
    if k.publisher != b.manifest.publisher {
        return Err(bad(format!(
            "the bundle claims publisher {} but is signed by a key of {} ({})",
            b.manifest.publisher, k.publisher, k.name
        )));
    }
    let signer = format!("{} ({})", k.name, key_id(k));
    let upgrade_from = check_lifecycle(c, &b.manifest, false)?;
    Ok(Verified {
        sha256: bundle::sha256_hex(bytes),
        size: bytes.len(),
        signer,
        upgrade_from,
        bundle: b,
    })
}

pub fn staged_paths(staging: &Path, sha256: &str) -> (PathBuf, PathBuf) {
    (
        staging.join(format!("{sha256}.nxplugin")),
        staging.join(format!("{sha256}.sig")),
    )
}

fn write_new(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = p.with_extension("part");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))?;
    fs::rename(&tmp, p)
}

/// Web-api: stores the verified upload (group-readable for the installer).
pub fn stage(staging: &Path, v: &Verified, bytes: &[u8], sig: &[u8]) -> std::io::Result<()> {
    let (b, s) = staged_paths(staging, &v.sha256);
    write_new(&b, bytes)?;
    write_new(&s, sig)
}

/// Web-api: records the upload as `pending` with its quorum request.
pub fn record_pending(c: &Connection, v: &Verified, by: &str, quorum_id: Option<i64>) -> Result<(), Error> {
    let m = &v.bundle.manifest;
    c.execute(
        "INSERT INTO plugins (id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, current, enabled,
                              quorum_id, uploaded_by, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', 0, 1, ?10, ?11, ?12)
         ON CONFLICT (id, version) DO UPDATE SET name=?3, publisher=?4, sha256=?5, bin_sha256=?6, size=?7, manifest=?8,
           signer=?9, state='pending', current=0, quorum_id=?10, uploaded_by=?11, uploaded_at=?12, installed_at=NULL, error=NULL",
        params![
            m.id,
            m.version,
            m.name,
            m.publisher,
            v.sha256,
            v.bundle.bin_sha256(),
            v.size as i64,
            String::from_utf8_lossy(&v.bundle.manifest_raw),
            v.signer,
            quorum_id,
            by,
            catalog::now()
        ],
    )
    .map_err(db)?;
    Ok(())
}

/// Quorum execution of `plugin.install`: repeats the lifecycle checks, `pending` → `approved`.
pub fn approve_install(c: &Connection, id: &str, version: &str, sha256: &str) -> Result<(), Error> {
    let (manifest, state, sha): (String, String, String) = c
        .query_row(
            "SELECT manifest, state, sha256 FROM plugins WHERE id = ?1 AND version = ?2",
            params![id, version],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(db)?
        .ok_or_else(|| conflict("the plugin upload no longer exists"))?;
    if state != "pending" || sha != sha256 {
        return Err(conflict(format!("the upload is {state} / was replaced; upload again")));
    }
    let m: Manifest = serde_json::from_str(&manifest).map_err(|e| bad(e.to_string()))?;
    check_lifecycle(c, &m, true)?;
    c.execute(
        "UPDATE plugins SET state = 'approved' WHERE id = ?1 AND version = ?2",
        params![id, version],
    )
    .map_err(db)?;
    Ok(())
}

/// Source kinds (`plugin:<kind>`) of a plugin id (all its versions).
pub fn kinds_of(c: &Connection, id: &str) -> Result<Vec<String>, Error> {
    let mut st = c.prepare("SELECT manifest FROM plugins WHERE id = ?1").map_err(db)?;
    let rows = st.query_map([id], |r| r.get::<_, String>(0)).map_err(db)?;
    let mut out = Vec::new();
    for r in rows {
        if let Ok(m) = serde_json::from_str::<Manifest>(&r.map_err(db)?) {
            out.extend(m.kinds.iter().map(|k| Manifest::source_kind(&k.kind)));
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Sources that use any kind of the plugin (removal is refused while they exist).
pub fn sources_using(c: &Connection, id: &str) -> Result<i64, Error> {
    let mut n = 0;
    for k in kinds_of(c, id)? {
        n += c
            .query_row("SELECT COUNT(*) FROM sources WHERE kind = ?1", [&k], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(db)?;
    }
    Ok(n)
}

/// The installed, current version of a plugin that provides `kind` (scheduler, web-api).
#[derive(Debug, Clone)]
pub struct Current {
    pub id: String,
    pub version: String,
    pub bin_sha256: String,
    pub manifest_raw: String,
    pub manifest: Manifest,
    pub enabled: bool,
}

pub fn current_for_kind(c: &Connection, kind: &str) -> Result<Option<Current>, Error> {
    let mut st = c
        .prepare(
            "SELECT id, version, bin_sha256, manifest, enabled FROM plugins WHERE current = 1 AND state = 'installed'",
        )
        .map_err(db)?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)? != 0,
            ))
        })
        .map_err(db)?;
    for row in rows {
        let (id, version, bin_sha256, raw, enabled) = row.map_err(db)?;
        let Ok(m) = serde_json::from_str::<Manifest>(&raw) else {
            continue;
        };
        if m.kinds.iter().any(|k| k.kind == kind) {
            return Ok(Some(Current {
                id,
                version,
                bin_sha256,
                manifest_raw: raw,
                manifest: m,
                enabled,
            }));
        }
    }
    Ok(None)
}

// ---- installer ---------------------------------------------------------------

pub struct Paths {
    pub staging: PathBuf,
    pub plugins: PathBuf,
    pub project_keys: PathBuf,
}

fn ioe(e: std::io::Error, what: &str) -> Error {
    Error {
        status: 500,
        message: format!("{what}: {e}"),
    }
}

fn sync_dir(p: &Path) {
    if let Ok(f) = fs::File::open(p) {
        let _ = f.sync_all();
    }
}

fn unpack(b: &Bundle, dir: &Path) -> Result<(), Error> {
    let mk = |p: &Path| fs::create_dir_all(p).map_err(|e| ioe(e, &p.display().to_string()));
    let file = |p: &Path, data: &[u8], mode: u32| -> Result<(), Error> {
        // created under its final name: the SELinux name transition labels bin/plugin
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)
            .map_err(|e| ioe(e, &p.display().to_string()))?;
        f.write_all(data).map_err(|e| ioe(e, "write"))?;
        f.sync_all().map_err(|e| ioe(e, "fsync"))?;
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).map_err(|e| ioe(e, "chmod"))
    };
    mk(&dir.join("bin"))?;
    file(&dir.join("manifest.json"), &b.manifest_raw, 0o444)?;
    file(&dir.join("bin/plugin"), &b.bin, 0o555)?;
    let mut dirs = vec![dir.join("bin")];
    for (rel, data) in &b.assets {
        let p = dir.join("assets").join(rel);
        let parent = p.parent().unwrap().to_owned();
        mk(&parent)?;
        let mut d = parent.clone();
        while d != *dir {
            dirs.push(d.clone());
            d = d.parent().unwrap().to_owned();
        }
        file(&p, data, 0o444)?;
    }
    dirs.sort();
    dirs.dedup();
    for d in dirs.iter().rev().chain(std::iter::once(&dir.to_path_buf())) {
        sync_dir(d);
        fs::set_permissions(d, fs::Permissions::from_mode(0o555)).map_err(|e| ioe(e, "chmod"))?;
    }
    Ok(())
}

fn remove_tree(p: &Path) -> std::io::Result<()> {
    // read-only dirs (0555) must become writable to delete their entries
    if let Ok(m) = fs::symlink_metadata(p) {
        if m.is_dir() {
            fs::set_permissions(p, fs::Permissions::from_mode(0o755))?;
            for e in fs::read_dir(p)? {
                remove_tree(&e?.path())?;
            }
            return fs::remove_dir(p);
        }
        return fs::remove_file(p);
    }
    Ok(())
}

fn set_current_link(plugins: &Path, id: &str, version: Option<&str>) {
    let link = plugins.join(id).join("current");
    let tmp = plugins.join(id).join(".current.tmp");
    let _ = fs::remove_file(&tmp);
    match version {
        Some(v) => {
            if std::os::unix::fs::symlink(v, &tmp).is_ok() {
                let _ = fs::rename(&tmp, &link);
            }
        }
        None => {
            let _ = fs::remove_file(&link);
        }
    }
}

/// Installs one approved row (everything re-verified against the catalog record).
fn install_one(c: &Connection, p: &Paths, id: &str, version: &str) -> Result<(), Error> {
    let (sha, bin_sha, manifest, publisher): (String, String, String, String) = c
        .query_row(
            "SELECT sha256, bin_sha256, manifest, publisher FROM plugins WHERE id = ?1 AND version = ?2",
            params![id, version],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(db)?;
    if !plugin_proto::valid_plugin_id(id) || !id.bytes().all(|b| b != b'/') {
        return Err(bad("invalid plugin id"));
    }
    let (bp, sp) = staged_paths(&p.staging, &sha);
    let bytes = fs::read(&bp).map_err(|e| ioe(e, &bp.display().to_string()))?;
    let sig = fs::read(&sp).map_err(|e| ioe(e, &sp.display().to_string()))?;
    if bundle::sha256_hex(&bytes) != sha {
        return Err(bad("staged bundle does not match the approved digest"));
    }
    let keys = trusted_keys(c, &p.project_keys)?;
    let k = bundle::verify(&bytes, &sig, &keys).map_err(bad)?;
    let b = bundle::read(&bytes).map_err(bad)?;
    if k.publisher != publisher
        || b.manifest.publisher != publisher
        || b.manifest.id != id
        || b.manifest.version != version
        || b.manifest_raw != manifest.as_bytes()
        || b.bin_sha256() != bin_sha
    {
        return Err(bad("staged bundle does not match the approved catalog record"));
    }
    let base = p.plugins.join(id);
    fs::create_dir_all(&base).map_err(|e| ioe(e, &base.display().to_string()))?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).map_err(|e| ioe(e, "chmod"))?;
    let tmp = base.join(format!(".{version}.tmp"));
    let dst = base.join(version);
    remove_tree(&tmp).map_err(|e| ioe(e, "cleanup"))?;
    remove_tree(&dst).map_err(|e| ioe(e, "cleanup"))?;
    unpack(&b, &tmp)?;
    fs::rename(&tmp, &dst).map_err(|e| ioe(e, "rename"))?;
    sync_dir(&base);
    let tx = c.unchecked_transaction().map_err(db)?;
    tx.execute("UPDATE plugins SET current = 0 WHERE id = ?1", [id])
        .map_err(db)?;
    tx.execute(
        "UPDATE plugins SET state = 'installed', current = 1, installed_at = ?3, error = NULL WHERE id = ?1 AND version = ?2",
        params![id, version, catalog::now()],
    )
    .map_err(db)?;
    tx.commit().map_err(db)?;
    set_current_link(&p.plugins, id, Some(version));
    let _ = fs::remove_file(&bp);
    let _ = fs::remove_file(&sp);
    Ok(())
}

/// One installer pass: approved → installed, removing → removed, current links in sync.
/// Returns human-readable lines (also audited).
pub fn run_pending(cat: &Catalog, p: &Paths) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let approved: Vec<(String, String)> = {
        let c = cat.conn();
        let mut st = c.prepare("SELECT id, version FROM plugins WHERE state = 'approved' ORDER BY uploaded_at")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (id, version) in approved {
        let r = install_one(&cat.conn(), p, &id, &version);
        match r {
            Ok(()) => {
                cat.audit(
                    ACTOR,
                    "plugin.installed",
                    &format!("plugin/{id}"),
                    &json!({"version": version}),
                )?;
                out.push(format!("installed {id} {version}"));
            }
            Err(e) => {
                cat.conn().execute(
                    "UPDATE plugins SET state = 'failed', error = ?3 WHERE id = ?1 AND version = ?2",
                    params![id, version, e.message],
                )?;
                cat.audit(
                    ACTOR,
                    "plugin.install_failed",
                    &format!("plugin/{id}"),
                    &json!({"version": version, "error": e.message}),
                )?;
                out.push(format!("install of {id} {version} failed: {e}"));
            }
        }
    }
    let removing: Vec<String> = {
        let c = cat.conn();
        let mut st = c.prepare("SELECT DISTINCT id FROM plugins WHERE state = 'removing'")?;
        let rows = st.query_map([], |r| r.get(0))?;
        rows.collect::<Result<_, _>>()?
    };
    for id in removing {
        if !plugin_proto::valid_plugin_id(&id) {
            continue;
        }
        let dir = p.plugins.join(&id);
        match remove_tree(&dir) {
            Ok(()) => {
                cat.conn().execute(
                    "UPDATE plugins SET state = 'removed', current = 0 WHERE id = ?1 AND state IN ('removing','installed','failed')",
                    [&id],
                )?;
                cat.audit(ACTOR, "plugin.removed", &format!("plugin/{id}"), &json!({}))?;
                out.push(format!("removed {id}"));
            }
            Err(e) => out.push(format!("removing {id} failed: {e}")),
        }
    }
    // `current` links follow the catalog (activate switches the flag there)
    let current: Vec<(String, String)> = {
        let c = cat.conn();
        let mut st = c.prepare("SELECT id, version FROM plugins WHERE current = 1 AND state = 'installed'")?;
        let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_, _>>()?
    };
    for (id, v) in current {
        if p.plugins.join(&id).join(&v).is_dir()
            && fs::read_link(p.plugins.join(&id).join("current")).ok() != Some(PathBuf::from(&v))
        {
            set_current_link(&p.plugins, &id, Some(&v));
            out.push(format!("current {id} -> {v}"));
        }
    }
    // stale uploads (rejected / expired requests): older than 4 days
    if let Ok(rd) = fs::read_dir(&p.staging) {
        let live: Vec<String> = {
            let c = cat.conn();
            let mut st = c.prepare("SELECT sha256 FROM plugins WHERE state IN ('pending','approved')")?;
            let rows = st.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(sha) = name.strip_suffix(".nxplugin").or_else(|| name.strip_suffix(".sig")) else {
                continue;
            };
            let old = e
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|a| a.as_secs() > 4 * 86400);
            if old && !live.iter().any(|l| l == sha) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    Ok(out)
}

/// JSON of one `plugins` row for the API.
pub fn row_json(r: &catalog::rusqlite::Row) -> catalog::rusqlite::Result<Value> {
    let manifest: String = r.get(7)?;
    Ok(json!({
        "id": r.get::<_, String>(0)?, "version": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
        "publisher": r.get::<_, String>(3)?, "sha256": r.get::<_, String>(4)?, "bin_sha256": r.get::<_, String>(5)?,
        "size": r.get::<_, i64>(6)?, "manifest": serde_json::from_str::<Value>(&manifest).unwrap_or(Value::Null),
        "signer": r.get::<_, String>(8)?, "state": r.get::<_, String>(9)?, "current": r.get::<_, i64>(10)? != 0,
        "enabled": r.get::<_, i64>(11)? != 0, "quorum_id": r.get::<_, Option<i64>>(12)?,
        "uploaded_by": r.get::<_, String>(13)?, "uploaded_at": r.get::<_, i64>(14)?,
        "installed_at": r.get::<_, Option<i64>>(15)?, "error": r.get::<_, Option<String>>(16)?,
    }))
}

pub const ROW_COLS: &str =
    "id, version, name, publisher, sha256, bin_sha256, size, manifest, signer, state, current, enabled, \
                            quorum_id, uploaded_by, uploaded_at, installed_at, error";
