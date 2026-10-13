//! Appliance configuration backup (docs/control-plane.md "Configuration backup",
//! manual/14): what goes into the sealed bundle, the root helper
//! `nexus-config-backup` that makes it, and `nexus-setup restore-config`.
//!
//! The helper (root oneshot, `nexus-config-backup.path`) is the only process that
//! reads all the key files below; it has no network and no keyd access. It seals
//! to the public key keyd publishes ([`keyd::config_bundle`]), so it never holds a
//! secret that opens a bundle. Control dir (default [`DIR`], 2770 root:nexus-catalog):
//! ```text
//! request.json   {"id": <job id>, "appliance": <id>}   written by the scheduler (job config_backup)
//! status.json    {"id", "state": "done"|"error", "error", "created", "appliance", "bytes",
//!                 "sha256", "files": [...]}                   written by the helper
//! latest.bundle  the newest bundle (0640): the scheduler uploads it, the web-api serves it
//! latest.json    status of that bundle (the last successful run)
//! ```
//! Not in the bundle: tenant DEKs (escrowed offsite under `keys/`), the KEK (only
//! wrapped: `kek.recovery` is in the clear part), chunk data, plugin binaries
//! (plugins are uploaded again after a restore).

use crate::{mkdir, Paths, Setup, SERVICES};
use anyhow::{anyhow, bail, Context, Result};
use catalog::Catalog;
use keyd::config_bundle::{self, Entry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const DIR: &str = "/var/lib/nexus/config-backup";
pub const KEYD_RUN: &str = "/run/nexus-keyd";
pub const REQUEST: &str = "request.json";
pub const STATUS: &str = "status.json";
pub const LATEST: &str = "latest.bundle";
pub const LATEST_INFO: &str = "latest.json";
/// catalog setting (scheduler config_backup.rs): tenants whose DEKs come back from their offsite escrow
pub const REKEY_PENDING: &str = "config_restore_keys";
/// relative to `/`; the snapshot is taken with `VACUUM INTO` (consistent while in use)
pub const CATALOG: &str = "var/lib/nexus/catalog/catalog.db";
/// Files and directories (recursively) in the bundle, relative to `/`. Missing ones are skipped.
pub const INCLUDE: &[&str] = &[
    // web-api: key of the users' TOTP seeds
    "var/lib/nexus/webapi/totp.key",
    // scheduler: opens the sealed source / offsite secrets in the catalog
    "var/lib/nexus/scheduler/secrets.key",
    // agent CA (enrolled agents keep working) and replication client credentials
    "var/lib/nexus/scheduler/agent-ca",
    "var/lib/nexus/scheduler/replica",
    // nexus-replicad: replication CA + token sealing key (peers keep working)
    "var/lib/nexus/replicad",
    // the appliance's SSH keys (PVE nodes, SFTP offsite) and known hosts
    "etc/nexus/ssh",
    // web / replication TLS identity (pinned by peers), imported certificate
    "etc/nexus/tls/cert.pem",
    "etc/nexus/tls/key.pem",
    "etc/nexus/tls/web.pem",
    "etc/nexus/metrics-token",
];
/// Directories recreated with their recorded mode/owner before the files (parents of single files).
const PARENTS: &[&str] = &["var/lib/nexus/webapi", "var/lib/nexus/scheduler", "etc/nexus/tls"];
/// largest single file taken into a bundle
const MAX_FILE: u64 = 256 << 20;

fn user_name(uid: u32) -> String {
    // SAFETY: getpwuid returns NULL or static storage; the helper is single-threaded.
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return uid.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) }
        .to_string_lossy()
        .into_owned()
}

fn group_name(gid: u32) -> String {
    // SAFETY: as above.
    let gr = unsafe { libc::getgrgid(gid) };
    if gr.is_null() {
        return gid.to_string();
    }
    unsafe { std::ffi::CStr::from_ptr((*gr).gr_name) }
        .to_string_lossy()
        .into_owned()
}

fn entry(rel: &str, m: &fs::Metadata, data: Vec<u8>) -> Entry {
    Entry {
        path: rel.to_owned(),
        dir: m.is_dir(),
        mode: m.mode() & 0o7777,
        user: user_name(m.uid()),
        group: group_name(m.gid()),
        data,
    }
}

fn walk(root: &Path, rel: &str, out: &mut Vec<Entry>) -> Result<()> {
    let p = root.join(rel);
    let m = match fs::symlink_metadata(&p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    if m.is_dir() {
        out.push(entry(rel, &m, vec![]));
        let mut names: Vec<String> = fs::read_dir(&p)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect::<Result<_, _>>()?;
        names.sort();
        for n in names {
            walk(root, &format!("{rel}/{n}"), out)?;
        }
    } else if m.is_file() {
        if m.len() > MAX_FILE {
            bail!("{} is larger than {MAX_FILE} bytes", p.display());
        }
        let data = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
        out.push(entry(rel, &m, data));
    } // sockets, symlinks: not configuration
    Ok(())
}

/// Every entry of the bundle: parents, the catalog snapshot (taken into `tmp`), [`INCLUDE`].
pub fn collect(root: &Path, tmp: &Path) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    for rel in PARENTS {
        if let Ok(m) = fs::metadata(root.join(rel)) {
            out.push(entry(rel, &m, vec![]));
        }
    }
    let db = root.join(CATALOG);
    let m = fs::metadata(&db).with_context(|| format!("catalog {}", db.display()))?;
    let snap = tmp.join(format!("catalog-{}.db", std::process::id()));
    let _ = fs::remove_file(&snap);
    let res = (|| -> Result<Vec<u8>> {
        let c = catalog::rusqlite::Connection::open_with_flags(
            &db,
            catalog::rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | catalog::rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        c.busy_timeout(std::time::Duration::from_secs(30))?;
        c.execute("VACUUM INTO ?1", [snap.to_string_lossy()])?;
        Ok(fs::read(&snap)?)
    })();
    let _ = fs::remove_file(&snap);
    out.push(entry(CATALOG, &m, res.context("catalog snapshot")?));
    for rel in INCLUDE {
        walk(root, rel, &mut out)?;
    }
    Ok(out)
}

/// Makes one sealed bundle: (bytes, header).
pub fn create(root: &Path, keyd_run: &Path, tmp: &Path, appliance: &str, now: i64) -> Result<(Vec<u8>, Value)> {
    let pk: [u8; 32] = fs::read(keyd_run.join(config_bundle::PUB_FILE))
        .context("the key service has not published its configuration backup key (is nexus-keyd running?)")?
        .try_into()
        .map_err(|_| anyhow!("{} is corrupt", config_bundle::PUB_FILE))?;
    let kr = fs::read(keyd_run.join(config_bundle::KEK_RECOVERY_FILE)).context("kek.recovery")?;
    let entries = collect(root, tmp)?;
    let header = json!({
        "format": 1,
        "appliance": appliance,
        "created": now,
        "host": fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),
        "version": env!("CARGO_PKG_VERSION"),
        "files": entries.iter().filter(|e| !e.dir).map(|e| e.path.as_str()).collect::<Vec<_>>(),
    });
    let b = config_bundle::seal(&pk, &kr, header.to_string().as_bytes(), &entries)?;
    Ok((b, header))
}

/// Atomic write in the control dir; 0640 (group nexus-catalog through the setgid dir).
fn publish(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&tmp)
        .and_then(|mut f| std::io::Write::write_all(&mut f, data).and_then(|()| f.sync_all()))
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))?;
    fs::rename(&tmp, dir.join(name))?;
    Ok(())
}

/// One helper run: handles a pending request (consumed first). Returns whether there was one.
pub fn tick(dir: &Path, root: &Path, keyd_run: &Path) -> Result<bool> {
    let req = dir.join(REQUEST);
    let raw = match fs::read(&req) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    fs::remove_file(&req)?;
    let r: Value = serde_json::from_slice(&raw[..raw.len().min(4096)]).unwrap_or(Value::Null);
    let id = r["id"].as_i64().unwrap_or(0);
    let appliance = r["appliance"].as_str().unwrap_or_default().to_owned();
    let now = catalog::now();
    let res = if offsite_id_ok(&appliance) {
        create(root, keyd_run, &std::env::temp_dir(), &appliance, now)
    } else {
        Err(anyhow!("invalid appliance id {appliance:?}"))
    };
    let status = match res {
        Ok((b, header)) => {
            publish(dir, LATEST, &b)?;
            let sha: String = Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect();
            let st = json!({"id": id, "state": "done", "created": now, "appliance": appliance, "bytes": b.len(),
                            "sha256": sha, "files": header["files"]});
            publish(dir, LATEST_INFO, st.to_string().as_bytes())?;
            st
        }
        Err(e) => {
            eprintln!("<3>nexus-config-backup: {e:#}");
            json!({"id": id, "state": "error", "created": now, "appliance": appliance, "error": format!("{e:#}")})
        }
    };
    publish(dir, STATUS, status.to_string().as_bytes())?;
    Ok(true)
}

fn offsite_id_ok(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'-')
}

// ---------------------------------------------------------------- restore

pub struct Restored {
    pub appliance: String,
    pub created: i64,
    pub host: String,
    pub files: usize,
}

/// Where an entry goes: the overridable [`Paths`] first, else below the root.
fn target(paths: &Paths, rel: &str) -> PathBuf {
    match rel {
        CATALOG => paths.catalog.clone(),
        "var/lib/nexus/webapi/totp.key" => paths.totp_key.clone(),
        "etc/nexus/metrics-token" => paths.metrics_token.clone(),
        _ => match rel.strip_prefix("etc/nexus/tls/") {
            Some(f) => paths.tls_dir.join(f),
            None => paths.root.join(rel),
        },
    }
}

/// Fetches the newest bundle from an offsite target: `{"remote": {…}}` as in a
/// nexus-offsite job config (or the remote object alone). With `nft` (the real
/// appliance) the outbound firewall is opened for the target's addresses for the
/// download and closed again (like nexus-update does for the registry).
pub fn fetch(target: &Value, appliance: Option<&str>, nft: Option<&Path>) -> Result<(String, u64, Vec<u8>)> {
    let remote = target.get("remote").unwrap_or(target).clone();
    let cfg: offsite::cfg::RemoteCfg = serde_json::from_value(remote).context("offsite target")?;
    let mut opened = Vec::new();
    if let (Some(nft), Some((host, port))) = (nft, cfg.endpoint()) {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::IpAddr> = (host.as_str(), port)
            .to_socket_addrs()
            .with_context(|| format!("resolving {host}"))?
            .map(|a| a.ip())
            .collect();
        for a in addrs {
            let set = if a.is_ipv4() {
                "allowed_out_v4"
            } else {
                "allowed_out_v6"
            };
            opened.push(format!("inet nexus {set} {{ {a} . tcp . {port} }}"));
        }
        let script: String = opened.iter().map(|e| format!("add element {e}\n")).collect();
        nftsync::apply(nft, &script).context("opening the outbound firewall for the offsite target")?;
    }
    let res = offsite::cfg::remote(&cfg, 1).and_then(|r| offsite::config::latest(r.as_ref(), appliance));
    if let Some(nft) = nft.filter(|_| !opened.is_empty()) {
        let script: String = opened.iter().map(|e| format!("destroy element {e}\n")).collect();
        if let Err(e) = nftsync::apply(nft, &script) {
            eprintln!("warning: closing the outbound firewall again failed ({e:#}); nexus-nft-sync resets it at the next boot");
        }
    }
    res
}

fn ssh_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// A throwaway ed25519 key for fetching from a Storage Box during a restore:
/// (OpenSSH private key PEM, `ssh-ed25519 <b64> <comment>`). Same format as the
/// scheduler's own keys (`scheduler::sshkeys::generate`); the restored
/// `/etc/nexus/ssh` brings the lost appliance's keys back afterwards.
pub fn ssh_key(comment: &str) -> (Zeroizing<String>, String) {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let seed = Zeroizing::new(rand::random::<[u8; 32]>());
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, &pk);
    let check: [u8; 4] = rand::random();
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    ssh_string(&mut private, b"ssh-ed25519");
    ssh_string(&mut private, &pk);
    let mut both = Zeroizing::new([0u8; 64]);
    both[..32].copy_from_slice(&*seed);
    both[32..].copy_from_slice(&pk);
    ssh_string(&mut private, &*both);
    ssh_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    let mut body = Zeroizing::new(b"openssh-key-v1\0".to_vec());
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut body, &blob);
    ssh_string(&mut body, &private);
    let b64 = Zeroizing::new(STANDARD.encode(&*body));
    let mut pem = Zeroizing::new(String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    (pem, format!("ssh-ed25519 {} {comment}", STANDARD.encode(&blob)))
}

/// Header of a bundle without the key (shown before the recovery key is asked for).
pub fn header(bundle: &[u8]) -> Result<Value> {
    serde_json::from_slice(&config_bundle::header(bundle)?).context("bundle header")
}

impl Setup {
    /// `nexus-setup restore-config` on a fresh appliance (first boot not finished):
    /// opens the bundle with the recovery key of the old appliance, puts every
    /// file back with its owner and mode, installs `kek.recovery` and re-seals the
    /// KEK on this machine (the old recovery key stays valid), relabels (restorecon),
    /// sets the boot menu password, marks plugins for upload again, writes
    /// `setup-done` and starts the services. Nothing is changed if the key is wrong.
    pub fn restore_config(&mut self, bundle: &[u8], recovery_key: &str) -> Result<Restored> {
        if self.paths.setup_done.exists() {
            bail!("this appliance is already set up: a configuration backup is restored only on a new appliance, before the first boot setup is finished");
        }
        let rk = Zeroizing::new(recovery_key.trim().to_owned());
        let opened = config_bundle::open(bundle, &rk)?;
        let h: Value = serde_json::from_slice(&opened.header).unwrap_or(Value::Null);
        let keyd_dir = self.paths.keyd_dir.clone();
        if fs::read(keyd_dir.join("kek.recovery")).is_ok_and(|k| k != opened.kek_recovery) {
            // the wizard already initialised the key service: harmless before setup-done, unless tenants have keys
            if fs::read_dir(keyd_dir.join("tenants")).is_ok_and(|mut d| d.next().is_some()) {
                bail!("the key service of this appliance already holds tenant keys: refusing to replace it");
            }
            fs::remove_dir_all(&keyd_dir).with_context(|| format!("resetting {}", keyd_dir.display()))?;
        }

        // the catalog is replaced under our feet: let go of it first
        self.cat = Catalog::open_memory()?;
        self.put_entries(&opened.entries)?;
        self.cat = crate::open_catalog(&self.paths.catalog, &self.owner)?;

        mkdir(&keyd_dir, 0o700)?;
        mkdir(&keyd_dir.join("tenants"), 0o700)?;
        self.write_file(
            &keyd_dir.join("kek.recovery"),
            &opened.kek_recovery,
            0o600,
            Some("nexus-keyd"),
            Some("nexus-keyd"),
        )?;
        keyd::recover(&keyd_dir, &rk).context("re-sealing the KEK")?;
        for p in [keyd_dir.join("kek.local"), keyd_dir.join("tenants"), keyd_dir.clone()] {
            self.own(&p, Some("nexus-keyd"), Some("nexus-keyd"))?;
        }

        // plugin binaries are not in the bundle: upload them again (verified + approved as new)
        let plugins = self.cat.conn().execute(
            "UPDATE plugins SET state = 'failed',
                    error = 'restored from a configuration backup: upload the plugin bundle again'
             WHERE state IN ('pending', 'approved', 'installed', 'removing')",
            [],
        )?;
        // tenants with an offsite target get their DEKs back from its escrow (wrapped under
        // the restored KEK) before anything else runs for them: the scheduler's config_rekey
        let rekey: Vec<String> = self
            .cat
            .conn()
            .prepare(
                "SELECT name FROM tenants WHERE json_valid(offsite) AND json_type(offsite, '$.remote') = 'object'
                 ORDER BY name",
            )?
            .query_map([], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        catalog::set_setting(&self.cat.conn(), REKEY_PENDING, &json!(rekey).to_string())?;
        let r = Restored {
            appliance: h["appliance"].as_str().unwrap_or_default().to_owned(),
            created: h["created"].as_i64().unwrap_or_default(),
            host: h["host"].as_str().unwrap_or_default().to_owned(),
            files: opened.entries.iter().filter(|e| !e.dir).count(),
        };
        self.audit(
            "setup.restore_config",
            "appliance",
            json!({"appliance": r.appliance, "bundle_created": r.created, "bundle_host": r.host, "files": r.files,
                   "plugins_to_upload": plugins, "tenant_keys_from_offsite": rekey,
                   "dry_run": self.dry_run}),
        )?;
        let root = self.paths.root.clone();
        let relabel: Vec<String> = ["var/lib/nexus", "etc/nexus"]
            .iter()
            .map(|p| root.join(p).to_string_lossy().into_owned())
            .collect();
        let mut args = vec!["-R"];
        args.extend(relabel.iter().map(String::as_str));
        self.cmd("restorecon", &args)?;
        self.grub_password(&rk)?;
        self.audit(
            "setup.done",
            "appliance",
            json!({"restored": true, "dry_run": self.dry_run}),
        )?;
        self.write_file(
            &self.paths.setup_done,
            format!("restored {}\n", catalog::now()).as_bytes(),
            0o644,
            None,
            None,
        )?;
        let mut args = vec!["enable", "--now"];
        args.extend(SERVICES);
        self.cmd("systemctl", &args)
            .context("the configuration is restored, but starting the services failed; run: systemctl enable --now nexus-web-api nexus-scheduler nexus-keyd nexus-replicad")?;
        Ok(r)
    }

    /// Directories first (bundle order: parents before children), files staged
    /// next to their target (same file system: /etc and /var are separate on
    /// bootc) with their final mode/owner and renamed into place.
    fn put_entries(&self, entries: &[Entry]) -> Result<()> {
        for (i, e) in entries.iter().enumerate() {
            let t = target(&self.paths, &e.path);
            if e.dir {
                fs::create_dir_all(&t).with_context(|| format!("creating {}", t.display()))?;
            } else {
                let parent = t.parent().ok_or_else(|| anyhow!("no parent"))?;
                fs::create_dir_all(parent)?;
                let s = parent.join(format!(".nexus-restore-{i}.tmp"));
                let _ = fs::remove_file(&s);
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&s)
                    .and_then(|mut f| std::io::Write::write_all(&mut f, &e.data).and_then(|()| f.sync_all()))
                    .with_context(|| format!("staging {}", e.path))?;
                if e.path == CATALOG {
                    for x in ["-wal", "-shm"] {
                        let _ = fs::remove_file(format!("{}{x}", t.display()));
                    }
                }
                self.place(&s, &t, e)?;
                continue;
            }
            self.place(&t, &t, e)?;
        }
        Ok(())
    }

    fn place(&self, from: &Path, to: &Path, e: &Entry) -> Result<()> {
        fs::set_permissions(from, fs::Permissions::from_mode(e.mode))?;
        self.own(from, Some(&e.user), Some(&e.group))?;
        if from != to {
            fs::rename(from, to).with_context(|| format!("restoring {}", to.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DryRunRunner;

    /// An old appliance in a temp root with every kind of file.
    fn old_appliance() -> (tempfile::TempDir, Paths, String, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::under(d.path());
        fs::create_dir_all(&paths.keyd_dir).unwrap();
        let rk = keyd::init(&paths.keyd_dir).unwrap();
        let run = d.path().join("run/nexus-keyd");
        fs::create_dir_all(&run).unwrap();
        keyd::config_bundle::publish(&paths.keyd_dir, &run).unwrap();
        fs::create_dir_all(paths.catalog.parent().unwrap()).unwrap();
        let cat = Catalog::open(&paths.catalog).unwrap();
        cat.conn()
            .execute_batch(
                "INSERT INTO users (name, password_hash, totp_secret, role, created) VALUES ('alice', 'h', 'enc', 'admin', 1);
                 INSERT INTO tenants (name, offsite) VALUES ('acme', '{\"remote\":{\"type\":\"local\",\"path\":\"/b\"}}'), ('beta', '{}');
                 INSERT INTO settings (key, value) VALUES ('appliance_id', 'a1b2c3')
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
            )
            .unwrap();
        cat.audit("setup", "setup.keyd.confirmed", "keyd", &json!({})).unwrap();
        drop(cat);
        let files: &[(&str, &[u8], u32)] = &[
            ("var/lib/nexus/webapi/totp.key", b"totp", 0o600),
            ("var/lib/nexus/scheduler/secrets.key", b"secrets", 0o600),
            ("var/lib/nexus/scheduler/agent-ca/ca.key", b"agent-ca-key", 0o600),
            ("var/lib/nexus/scheduler/agent-ca/ca.pem", b"agent-ca-cert", 0o644),
            ("var/lib/nexus/scheduler/replica/3/client.key", b"replica", 0o600),
            ("var/lib/nexus/replicad/ca.key", b"repl-ca", 0o600),
            ("etc/nexus/ssh/offsite-acme", b"ssh-key", 0o600),
            ("etc/nexus/ssh/known_hosts", b"kh", 0o644),
            ("etc/nexus/tls/cert.pem", b"cert", 0o644),
            ("etc/nexus/tls/key.pem", b"key", 0o600),
            ("etc/nexus/tls/web.pem", b"web", 0o640),
            ("etc/nexus/metrics-token", b"tok", 0o640),
            // not configuration: must stay out
            ("etc/nexus/tls/pending/key.pem", b"pending", 0o600),
            ("var/lib/nexus/chunkstore/acme/x", b"chunk", 0o600),
        ];
        for (p, data, mode) in files {
            let p = d.path().join(p);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, data).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(*mode)).unwrap();
        }
        (d, paths, rk, run)
    }

    /// The restore key is a valid OpenSSH key (the SFTP client parses it).
    #[test]
    fn restore_ssh_key_parses() {
        let (pem, line) = ssh_key("nexus-restore");
        assert!(line.starts_with("ssh-ed25519 ") && line.ends_with(" nexus-restore"));
        assert!(offsite::sftp::parse_host_key(&line).is_ok());
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    }

    #[test]
    fn bundle_is_complete_and_restores_into_a_new_root() {
        let (old, _, rk, run) = old_appliance();
        let tmp = tempfile::tempdir().unwrap();
        let (b, header) = create(old.path(), &run, tmp.path(), "a1b2c3", 1_800_000_000).unwrap();
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0, "no plaintext left in tmp");
        let files: Vec<&str> = header["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for want in [
            CATALOG,
            "var/lib/nexus/webapi/totp.key",
            "var/lib/nexus/scheduler/secrets.key",
            "var/lib/nexus/scheduler/agent-ca/ca.key",
            "var/lib/nexus/scheduler/agent-ca/ca.pem",
            "var/lib/nexus/scheduler/replica/3/client.key",
            "var/lib/nexus/replicad/ca.key",
            "etc/nexus/ssh/offsite-acme",
            "etc/nexus/ssh/known_hosts",
            "etc/nexus/tls/cert.pem",
            "etc/nexus/tls/key.pem",
            "etc/nexus/tls/web.pem",
            "etc/nexus/metrics-token",
        ] {
            assert!(files.contains(&want), "{want} missing from {files:?}");
        }
        for never in ["pending", "chunkstore", "keyd"] {
            assert!(!files.iter().any(|f| f.contains(never)), "{never} in bundle");
        }
        assert!(!b.windows(7).any(|w| w == b"repl-ca"), "no file content in the clear");
        assert_eq!(super::header(&b).unwrap()["appliance"], "a1b2c3");

        // a fresh appliance: the wizard ran up to the key step (own KEK, no tenants)
        let new = tempfile::tempdir().unwrap();
        let paths = Paths::under(new.path());
        fs::create_dir_all(&paths.keyd_dir).unwrap();
        keyd::init(&paths.keyd_dir).unwrap();
        let mut s = Setup::open(paths.clone(), Box::new(DryRunRunner), true, false).unwrap();
        // wrong key: refused, nothing changed
        let wrong = keyd::format_recovery_key(&[5; 32]);
        assert!(s.restore_config(&b, &wrong).is_err());
        assert!(!paths.totp_key.exists() && !paths.setup_done.exists());

        let r = s.restore_config(&b, &rk).unwrap();
        assert_eq!((r.appliance.as_str(), r.files), ("a1b2c3", files.len()));
        for f in &files {
            if *f == CATALOG {
                continue;
            }
            let (a, b) = (old.path().join(f), target(&paths, f));
            assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap(), "{f}");
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode(&a), mode(&b), "{f}");
        }
        // the old recovery key works on the new machine; the catalog is the old one
        keyd::check_recovery_key(&paths.keyd_dir, &rk).unwrap();
        let c = s.cat.conn();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM users WHERE name = 'alice'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let a: String = c
            .query_row(
                "SELECT details FROM audit WHERE action = 'setup.restore_config'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(a.contains("a1b2c3"));
        let pending = catalog::setting(&c, REKEY_PENDING).unwrap().unwrap();
        assert_eq!(pending, r#"["acme"]"#, "only tenants with an offsite target");
        drop(c);
        assert!(paths.setup_done.exists());
        assert!(s.log.iter().any(|l| l.contains("restorecon -R")), "{:?}", s.log);
        assert!(s.log.iter().any(|l| l.contains("systemctl enable --now")));
        // once set up: refused
        assert!(s.restore_config(&b, &rk).is_err());
    }
}
