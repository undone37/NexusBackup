//! Signed self-update: signature and version checks shared by all agents (installing
//! the new binary is platform specific).
//!
//! `signature` is what `cosign sign-blob --key <release key>` prints: base64 of an
//! ASN.1/DER ECDSA P-256 signature over SHA-256 of the binary. It is verified against
//! the pinned keys in `/etc/nexus-agent/release-keys/*.pub` (PEM SPKI, as written by
//! `cosign generate-key-pair`; lab builds pin `release/testkey/TEST-cosign.pub`).
//!
//! The version the appliance claims is not covered by the signature, so the agent
//! reads the version embedded in the signed binary itself (`VERSION_MARKER`) and
//! refuses anything that is not strictly newer (no downgrade / replay of an older
//! signed build). Each agent embeds its own marker
//! (`concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0")`).

use base64::Engine;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use std::fs;
use std::path::{Path, PathBuf};

pub const MARKER_PREFIX: &[u8] = b"\0NEXUS-AGENT-VERSION=";

/// DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Parse a PEM `PUBLIC KEY` (P-256) into the uncompressed point ring expects.
pub fn parse_public_key(pem: &str) -> Result<Vec<u8>, String> {
    let b64: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN PUBLIC KEY-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("public key: {e}"))?;
    match der.strip_prefix(&P256_SPKI_PREFIX[..]) {
        Some(point) if point.len() == 65 && point[0] == 4 => Ok(point.to_vec()),
        _ => Err("public key is not an ECDSA P-256 key".into()),
    }
}

/// All pinned keys (file name, point). Unreadable / foreign keys are skipped.
pub fn load_keys(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    let Ok(rd) = fs::read_dir(dir) else { return out };
    let mut names: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect();
    names.sort();
    for p in names {
        match fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|t| parse_public_key(&t))
        {
            Ok(k) => out.push((p.file_name().unwrap_or_default().to_string_lossy().into_owned(), k)),
            Err(e) => eprintln!("nexus-agent: release key {}: {e}", p.display()),
        }
    }
    out
}

/// Verify a cosign blob signature; returns the name of the key that matched.
pub fn verify(binary: &[u8], signature: &[u8], keys: &[(String, Vec<u8>)]) -> Result<String, String> {
    if keys.is_empty() {
        return Err("no pinned release keys".into());
    }
    let text = std::str::from_utf8(signature).ok().map(|s| s.trim().to_string());
    let der = match text.and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok()) {
        Some(d) => d,
        None if signature.first() == Some(&0x30) => signature.to_vec(),
        None => return Err("signature is neither base64 nor DER".into()),
    };
    keys.iter()
        .find(|(_, k)| {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, k)
                .verify(binary, &der)
                .is_ok()
        })
        .map(|(n, _)| n.clone())
        .ok_or_else(|| "signature does not verify with any pinned release key".into())
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u64>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// The version embedded in a candidate binary (exactly one distinct marker).
pub fn embedded_version(binary: &[u8]) -> Result<String, String> {
    let mut found: Vec<String> = vec![];
    let mut i = 0;
    while let Some(pos) = binary[i..]
        .windows(MARKER_PREFIX.len())
        .position(|w| w == MARKER_PREFIX)
    {
        let start = i + pos + MARKER_PREFIX.len();
        let end = binary[start..].iter().take(32).position(|b| *b == 0).map(|e| start + e);
        if let Some(v) = end.and_then(|e| std::str::from_utf8(&binary[start..e]).ok()) {
            if parse_version(v).is_some() && !found.iter().any(|f| f == v) {
                found.push(v.to_string());
            }
        }
        i = start;
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err("binary carries no version marker".into()),
        _ => Err("binary carries several version markers".into()),
    }
}

/// All checks before installing: signature by a pinned key, the embedded version
/// equals the claimed one and is strictly newer than `current`, and `native` accepts
/// the executable format (ELF for this architecture / PE32+ x86-64). Returns
/// (key name, embedded version).
pub fn check_candidate(
    claimed: &str,
    binary: &[u8],
    signature: &[u8],
    keys: &[(String, Vec<u8>)],
    current: &str,
    native: fn(&[u8]) -> bool,
) -> Result<(String, String), String> {
    let key = verify(binary, signature, keys)?;
    let embedded = embedded_version(binary)?;
    if embedded != claimed.trim() {
        return Err(format!("claimed version {claimed} but the signed binary is {embedded}"));
    }
    let (new, cur) = (
        parse_version(&embedded).ok_or("bad version")?,
        parse_version(current).ok_or("bad current version")?,
    );
    if new <= cur {
        return Err(format!(
            "refusing downgrade/reinstall: {embedded} is not newer than {current}"
        ));
    }
    if !native(binary) {
        return Err("not an executable for this platform and architecture".into());
    }
    Ok((key, embedded))
}

/// Marker file shipped by the deb/rpm/msi packages (content: the package type). A
/// package-managed binary is updated by the package manager, not by `Update`.
pub fn package_marker() -> PathBuf {
    #[cfg(not(windows))]
    return PathBuf::from("/usr/lib/nexus-agent/package-managed");
    #[cfg(windows)]
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("package-managed")))
        .unwrap_or_default()
}

/// The package type if this agent was installed from a package. Only a missing marker means "no package": a marker
/// that cannot be read (an ACL, a file lock of a scanner) counts as an unknown package, so a package install is never
/// updated by a binary swap behind its package manager's back (#67: an MSI install reported `manual` while its
/// folder's ACL denied the service account).
pub fn packaged(marker: &Path) -> Option<String> {
    let t = match fs::read_to_string(marker) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some("package".into()),
    };
    let t = t.trim();
    Some(if t.is_empty() || t.len() > 16 {
        "package".into()
    } else {
        t.to_string()
    })
}

/// Why every update is refused before any check, if it is: `self_update = off` in
/// agent.conf always wins (the server owner keeps control). Unset (`auto`, the
/// default) and `on` allow updates with the install's own package type
/// ([`kind_allowed`]).
pub fn self_update_blocked(setting: Option<bool>, _packaged: Option<&str>) -> Option<String> {
    match setting {
        Some(false) => Some("self-update is off (self_update = off in agent.conf)".into()),
        _ => None,
    }
}

/// The single-frame `Update` (protocol before v1.8) swaps the binary: never under a
/// package manager (the package database would no longer be truthful).
pub fn binary_swap_blocked(packaged: Option<&str>) -> Option<String> {
    packaged.map(|p| {
        format!(
            "installed from a {p} package: it is updated with a {p} package (appliance with protocol v1.8), not by replacing the binary"
        )
    })
}

/// How this agent was installed: the package type of the marker, else `default`
/// (`bundle` on Linux, `manual` on Windows).
pub fn install_type(packaged: Option<&str>, default: &str) -> String {
    match packaged {
        Some(p @ ("deb" | "rpm" | "msi")) => p.to_string(),
        Some(_) => "manual".into(),
        None => default.into(),
    }
}

/// Which artifact kinds an install type takes in-band (Phase 27): every install is
/// updated with its own package type, bundles and manual installs by a binary swap.
pub fn kind_allowed(install: &str, kind: &str) -> bool {
    use agent_proto::release::*;
    matches!(
        (install, kind),
        ("bundle" | "manual", KIND_BINARY)
            | ("deb", KIND_DEB | KIND_DESKTOP_DEB)
            | ("rpm", KIND_RPM | KIND_DESKTOP_RPM)
            | ("msi", KIND_MSI)
    )
}

/// Oldest release this build may be rolled back to (an approved rollback, protocol
/// v1.8 `UpdateBegin.rollback`). Part of the signed binary: a compromised appliance
/// cannot take an agent back below it. Raise it when a release fixes a security issue.
pub const ROLLBACK_FLOOR: &str = "0.1.0";

/// Version rule of an update: strictly newer, or (with `rollback`) strictly older but
/// not below `floor`.
pub fn check_version(target: &str, current: &str, rollback: bool, floor: &str) -> Result<(), String> {
    let t = parse_version(target).ok_or_else(|| format!("bad version {target:?}"))?;
    let c = parse_version(current).ok_or("bad current version")?;
    if t == c {
        return Err(format!("refusing reinstall: {target} is already running"));
    }
    if t > c {
        return Ok(());
    }
    if !rollback {
        return Err(format!("refusing downgrade: {target} is not newer than {current}"));
    }
    match parse_version(floor) {
        Some(f) if t >= f => Ok(()),
        _ => Err(format!(
            "refusing rollback to {target}: below the oldest release this build allows ({floor})"
        )),
    }
}

/// An artifact announced by `UpdateBegin`, checked against its signed manifest
/// (everything except the data itself, see [`check_artifact_data`]).
#[derive(Debug, Clone)]
pub struct Announced {
    pub manifest: agent_proto::release::Manifest,
    pub artifact: agent_proto::release::Artifact,
    pub key: String,
}

/// All checks of an `UpdateBegin` before any data is accepted (docs/agent-update-plan.md
/// "Agent checks"); `host` = the agent's own facts.
#[allow(clippy::too_many_arguments)]
pub fn check_announced(
    keys: &[(String, Vec<u8>)],
    manifest: &[u8],
    manifest_sig: &[u8],
    kind: &str,
    name: &str,
    size: u64,
    sha256: &[u8; 32],
    host: &agent_proto::release::HostFacts,
    current: &str,
    rollback: bool,
) -> Result<Announced, String> {
    if !kind_allowed(&host.install, kind) {
        return Err(format!(
            "a {kind} artifact cannot update a {} install (updates use the install's own package type)",
            host.install
        ));
    }
    let key = verify(manifest, manifest_sig, keys).map_err(|e| format!("release manifest: {e}"))?;
    let m = agent_proto::release::Manifest::parse(manifest)?;
    let a = m
        .artifact(name)
        .ok_or_else(|| format!("{name} is not part of release {}", m.version))?
        .clone();
    if a.kind != kind {
        return Err(format!("{name} is a {} artifact, not {kind}", a.kind));
    }
    if a.os != host.os || a.arch != host.arch {
        return Err(format!(
            "{name} is for {}/{}, this host is {}/{}",
            a.os, a.arch, host.os, host.arch
        ));
    }
    if a.size != size || a.sha256 != agent_proto::release::hex(sha256) {
        return Err(format!("{name}: size or SHA-256 differ from the signed manifest"));
    }
    // the desktop UI rides along with the agent package; the agent's version decides
    if !kind.starts_with("desktop-") {
        if a.version != m.version {
            return Err(format!(
                "{name}: version {} differs from the release {}",
                a.version, m.version
            ));
        }
        check_version(&m.version, current, rollback, ROLLBACK_FLOOR)?;
    }
    Ok(Announced {
        manifest: m,
        artifact: a,
        key,
    })
}

/// The received data: its own signature, and for a binary the embedded version
/// marker and the executable format.
pub fn check_artifact_data(
    a: &Announced,
    data: &[u8],
    signature: &[u8],
    keys: &[(String, Vec<u8>)],
    native: &dyn Fn(&[u8]) -> bool,
) -> Result<(), String> {
    verify(data, signature, keys).map_err(|e| format!("{}: {e}", a.artifact.name))?;
    if a.artifact.kind == agent_proto::release::KIND_BINARY {
        let embedded = embedded_version(data)?;
        if embedded != a.artifact.version {
            return Err(format!(
                "{}: the signed binary is {embedded}, the manifest says {}",
                a.artifact.name, a.artifact.version
            ));
        }
        if !native(data) {
            return Err("not an executable for this platform and architecture".into());
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ update state

/// `<state>/update-state.json`: the outcome of the last update, reported to the
/// appliance (`UpdateStatus`).
pub fn state_file(paths: &crate::config::Paths) -> PathBuf {
    paths.state.join("update-state.json")
}

/// `<state>/update-pending.json`: an update in progress (written before installing,
/// removed when its outcome is known). Also the start watchdog's counter.
pub fn pending_file(paths: &crate::config::Paths) -> PathBuf {
    paths.state.join("update-pending.json")
}

/// Directory the artifacts are received into (emptied before each update).
pub fn staging_dir(paths: &crate::config::Paths) -> PathBuf {
    paths.state.join("update")
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct UpdateState {
    /// installing | ok | failed | rolled_back
    pub state: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub at: u64,
    #[serde(default)]
    pub error: String,
    /// last lines of the installer's output (package installs)
    #[serde(default)]
    pub log: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Pending {
    pub kind: String,
    pub from: String,
    pub to: String,
    pub started: u64,
    /// starts of the new binary that did not reach "listening" (binary swaps)
    #[serde(default)]
    pub starts: u32,
    /// transient systemd unit / installer log (package installs)
    #[serde(default)]
    pub unit: String,
    /// the starts are counted by the previous binary before each start ([`watchdog_pre`], the service's
    /// `ExecStartPre`): the new binary does not count them again
    #[serde(default)]
    pub pre: bool,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn read_pending(paths: &crate::config::Paths) -> Option<Pending> {
    serde_json::from_slice(&fs::read(pending_file(paths)).ok()?).ok()
}

pub fn write_pending(paths: &crate::config::Paths, p: &Pending) -> std::io::Result<()> {
    crate::config::write_atomic(&pending_file(paths), &serde_json::to_vec(p)?, 0o600)
}

pub fn write_state(paths: &crate::config::Paths, s: &UpdateState) -> std::io::Result<()> {
    let mut s = s.clone();
    s.error = s.error.chars().take(1000).collect();
    let skip = s.log.len().saturating_sub(40);
    s.log = s.log.split_off(skip);
    for l in &mut s.log {
        *l = l.chars().take(300).collect();
    }
    crate::config::write_atomic(&state_file(paths), &serde_json::to_vec(&s)?, 0o600)
}

/// The state document for `UpdateState` (`{}` when no update ran).
pub fn state_json(paths: &crate::config::Paths) -> String {
    fs::read(state_file(paths))
        .ok()
        .and_then(|b| serde_json::from_slice::<UpdateState>(&b).ok())
        .and_then(|s| serde_json::to_string(&s).ok())
        .filter(|j| j.len() <= agent_proto::MAX_UPDATE_STATE)
        .unwrap_or_else(|| "{}".into())
}

/// Finishes a pending update with `state` (ok / failed / rolled_back).
pub fn finish(paths: &crate::config::Paths, p: &Pending, state: &str, error: &str, log: Vec<String>) {
    let _ = write_state(
        paths,
        &UpdateState {
            state: state.into(),
            kind: p.kind.clone(),
            from: p.from.clone(),
            to: p.to.clone(),
            at: now(),
            error: error.into(),
            log,
        },
    );
    let _ = fs::remove_file(pending_file(paths));
    let _ = fs::remove_dir_all(staging_dir(paths));
}

/// What the start watchdog decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Watchdog {
    /// nothing pending (or a package install: see [`settle_package`])
    Continue,
    /// the previous binary is back in place: exit so the service manager restarts it
    Reverted,
}

/// Starts of a new binary allowed without reaching "listening" before the previous
/// one is put back.
pub const WATCHDOG_STARTS: u32 = 2;

/// At the very start of `run`: counts this start of a freshly swapped binary; the
/// third start without [`mark_listening`] puts `<exe>.prev` back (`restore` = the
/// platform's rename of `.prev` over the running executable).
pub fn watchdog_on_start(
    paths: &crate::config::Paths,
    current: &str,
    restore: &dyn Fn() -> Result<(), String>,
) -> Watchdog {
    let Some(mut p) = read_pending(paths) else {
        return Watchdog::Continue;
    };
    if p.kind != agent_proto::release::KIND_BINARY {
        return Watchdog::Continue;
    }
    if current == p.from {
        // the swap did not take (or the previous binary was put back by hand)
        finish(
            paths,
            &p,
            "rolled_back",
            "the agent runs the previous version again",
            vec![],
        );
        return Watchdog::Continue;
    }
    if current != p.to {
        finish(
            paths,
            &p,
            "failed",
            &format!("the agent runs {current}, expected {}", p.to),
            vec![],
        );
        return Watchdog::Continue;
    }
    if p.pre {
        // counted (and, on the third start, reverted) by the previous binary before this start
        return Watchdog::Continue;
    }
    if p.starts < WATCHDOG_STARTS {
        p.starts += 1;
        let _ = write_pending(paths, &p);
        return Watchdog::Continue;
    }
    revert(paths, &p, restore)
}

/// The service's `ExecStartPre`, run by the previous, already trusted binary `<exe>.prev` (#93): counts a
/// start of a freshly swapped binary before the service manager runs it, and puts the previous binary back on
/// the third start that did not reach "listening". Unlike [`watchdog_on_start`] this also covers a new binary
/// that never runs its own code (a loader or C library mismatch, a binary that exits at once).
pub fn watchdog_pre(paths: &crate::config::Paths, restore: &dyn Fn() -> Result<(), String>) -> Watchdog {
    let Some(mut p) = read_pending(paths) else {
        return Watchdog::Continue;
    };
    if p.kind != agent_proto::release::KIND_BINARY {
        return Watchdog::Continue;
    }
    if p.starts < WATCHDOG_STARTS {
        p.starts += 1;
        p.pre = true;
        let _ = write_pending(paths, &p);
        return Watchdog::Continue;
    }
    revert(paths, &p, restore)
}

/// Puts the previous binary back and finishes the pending update as rolled back (failed when that is not
/// possible).
fn revert(paths: &crate::config::Paths, p: &Pending, restore: &dyn Fn() -> Result<(), String>) -> Watchdog {
    match restore() {
        Ok(()) => {
            finish(
                paths,
                p,
                "rolled_back",
                &format!(
                    "version {} did not start {} times in a row; the previous binary {} was put back",
                    p.to,
                    WATCHDOG_STARTS + 1,
                    p.from
                ),
                vec![],
            );
            Watchdog::Reverted
        }
        Err(e) => {
            finish(
                paths,
                p,
                "failed",
                &format!("watchdog could not restore the previous binary: {e}"),
                vec![],
            );
            Watchdog::Continue
        }
    }
}

/// The agent listens: a pending binary swap or package install that brought this
/// version is done.
pub fn mark_listening(paths: &crate::config::Paths, current: &str) {
    if let Some(p) = read_pending(paths) {
        if p.to == current {
            finish(paths, &p, "ok", "", vec![]);
        }
    }
}

/// Outcome of a package install as the platform sees it.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallResult {
    /// still running
    Running,
    /// the installer finished successfully
    Succeeded,
    /// the installer failed (error, last log lines)
    Failed(String, Vec<String>),
    /// nothing known about it (unit gone, no log)
    Unknown,
}

/// Longest a package install may take before it counts as failed.
pub const INSTALL_TIMEOUT_SECS: u64 = 30 * 60;
/// After the installer ended successfully, how long the old agent waits to be
/// restarted into the new version before it reports the update as failed.
pub const RESTART_GRACE_SECS: u64 = 120;

/// Settles a pending package install of a running agent (called at start and every
/// 30 s): this version is the target: ok; else the installer's result decides.
/// Returns true while it is still pending.
pub fn settle_package(paths: &crate::config::Paths, current: &str, result: &dyn Fn(&Pending) -> InstallResult) -> bool {
    settle_package_at(paths, current, result, now())
}

pub fn settle_package_at(
    paths: &crate::config::Paths,
    current: &str,
    result: &dyn Fn(&Pending) -> InstallResult,
    now: u64,
) -> bool {
    let Some(p) = read_pending(paths) else {
        return false;
    };
    if p.kind == agent_proto::release::KIND_BINARY {
        return false;
    }
    if p.to == current {
        finish(paths, &p, "ok", "", vec![]);
        return false;
    }
    match result(&p) {
        InstallResult::Running if now < p.started + INSTALL_TIMEOUT_SECS => true,
        InstallResult::Running => {
            finish(
                paths,
                &p,
                "failed",
                "the package install did not finish within 30 minutes",
                vec![],
            );
            false
        }
        InstallResult::Failed(e, log) => {
            finish(paths, &p, "failed", &e, log);
            false
        }
        InstallResult::Succeeded | InstallResult::Unknown if now < p.started + RESTART_GRACE_SECS => true,
        InstallResult::Succeeded | InstallResult::Unknown => {
            finish(
                paths,
                &p,
                "failed",
                &format!(
                    "the package install ended but the agent still runs {current}, not {}",
                    p.to
                ),
                vec![],
            );
            false
        }
    }
}

/// Splits installer output into its last `n` non-empty lines (progress lines rewritten
/// with `\r` keep only their last state).
pub fn tail_lines(text: &str, n: usize) -> Vec<String> {
    let lines: Vec<String> = text
        .lines()
        .map(|l| l.trim_end().rsplit('\r').next().unwrap_or_default().trim_end())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let skip = lines.len().saturating_sub(n);
    lines[skip..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const TEST_PUB: &str = include_str!("../../../release/testkey/TEST-cosign.pub");
    const BLOB: &[u8] = include_bytes!("../tests/fixtures/cosign-blob.bin");
    const BLOB_SIG: &[u8] = include_bytes!("../tests/fixtures/cosign-blob.bin.sig");

    fn keypair() -> (EcdsaKeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let point = kp.public_key().as_ref().to_vec();
        (kp, point)
    }

    fn sign(kp: &EcdsaKeyPair, data: &[u8]) -> Vec<u8> {
        let sig = kp.sign(&SystemRandom::new(), data).unwrap();
        base64::engine::general_purpose::STANDARD
            .encode(sig.as_ref())
            .into_bytes()
    }

    fn fake_binary(version: &str) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[18..20].copy_from_slice(&62u16.to_le_bytes());
        b.extend_from_slice(format!("\0NEXUS-AGENT-VERSION={version}\0").as_bytes());
        b.extend_from_slice(MARKER_PREFIX); // a bare needle elsewhere must not confuse the parser
        b.extend_from_slice(b"junk");
        b
    }

    #[test]
    fn verifies_real_cosign_sign_blob_output_with_the_test_key() {
        // fixture made with: cosign sign-blob --key release/testkey/TEST-cosign.key blob
        let keys = vec![("TEST-cosign.pub".to_string(), parse_public_key(TEST_PUB).unwrap())];
        assert_eq!(verify(BLOB, BLOB_SIG, &keys).unwrap(), "TEST-cosign.pub");
        let mut tampered = BLOB.to_vec();
        tampered[0] ^= 1;
        assert!(verify(&tampered, BLOB_SIG, &keys).is_err());
        let (_, other) = keypair();
        assert!(verify(BLOB, BLOB_SIG, &[("other".into(), other)]).is_err());
        assert!(verify(BLOB, BLOB_SIG, &[]).is_err());
    }

    #[test]
    fn package_installs_leave_updates_to_the_package_manager() {
        let t = tempfile::tempdir().unwrap();
        let m = t.path().join("package-managed");
        assert_eq!(packaged(&m), None);
        fs::write(&m, "deb\n").unwrap();
        assert_eq!(packaged(&m).as_deref(), Some("deb"));
        fs::write(&m, "").unwrap();
        assert_eq!(packaged(&m).as_deref(), Some("package"));
        // unreadable (here: a directory in its place): an unknown package, no binary swap
        let d = t.path().join("unreadable");
        fs::create_dir(&d).unwrap();
        assert_eq!(packaged(&d).as_deref(), Some("package"));
        assert!(binary_swap_blocked(packaged(&d).as_deref()).is_some());
        // auto (unset) and on: allowed with the own package type; off always wins
        assert_eq!(self_update_blocked(None, None), None);
        assert_eq!(self_update_blocked(None, Some("rpm")), None);
        assert_eq!(self_update_blocked(Some(true), Some("msi")), None);
        assert!(self_update_blocked(Some(false), None)
            .unwrap()
            .contains("self_update = off"));
        assert!(self_update_blocked(Some(false), Some("deb")).is_some());
        // never a binary swap under a package manager
        assert!(binary_swap_blocked(Some("deb")).unwrap().contains("deb package"));
        assert_eq!(binary_swap_blocked(None), None);
        assert_eq!(install_type(Some("deb"), "bundle"), "deb");
        assert_eq!(install_type(Some("package"), "bundle"), "manual");
        assert_eq!(install_type(None, "manual"), "manual");
        for (install, kind, ok) in [
            ("bundle", "binary", true),
            ("manual", "binary", true),
            ("deb", "deb", true),
            ("deb", "desktop-deb", true),
            ("deb", "binary", false),
            ("deb", "rpm", false),
            ("rpm", "rpm", true),
            ("rpm", "desktop-rpm", true),
            ("msi", "msi", true),
            ("msi", "binary", false),
            ("bundle", "deb", false),
            ("bundle", "exe", false),
        ] {
            assert_eq!(kind_allowed(install, kind), ok, "{install} {kind}");
        }
    }

    fn native(b: &[u8]) -> bool {
        b.starts_with(b"\x7fELF")
    }

    #[test]
    fn candidate_checks_signature_version_and_format() {
        let (kp, point) = keypair();
        let keys = vec![("k.pub".to_string(), point)];
        let new = fake_binary("0.2.0");
        let sig = sign(&kp, &new);
        assert!(check_candidate("0.2.0", &new, &sign(&kp, b"x"), &keys, "0.1.0", native).is_err());
        assert!(check_candidate("0.3.0", &new, &sig, &keys, "0.1.0", native)
            .unwrap_err()
            .contains("claimed"));
        assert!(check_candidate("0.2.0", &new, &sig, &keys, "0.2.0", native)
            .unwrap_err()
            .contains("downgrade"));
        assert!(check_candidate("0.2.0", &new, &sig, &keys, "0.10.0", native)
            .unwrap_err()
            .contains("downgrade"));
        let mut other = new.clone();
        other[0] = b'#';
        assert!(check_candidate("0.2.0", &other, &sign(&kp, &other), &keys, "0.1.0", native).is_err());
        assert_eq!(
            check_candidate("0.2.0", &new, &sig, &keys, "0.1.0", native).unwrap(),
            ("k.pub".to_string(), "0.2.0".to_string())
        );
    }

    #[test]
    fn version_rules_with_rollback_floor() {
        assert!(check_version("0.2.0", "0.1.0", false, "0.1.0").is_ok());
        assert!(check_version("0.1.0", "0.1.0", true, "0.1.0")
            .unwrap_err()
            .contains("already"));
        assert!(check_version("0.1.0", "0.2.0", false, "0.1.0")
            .unwrap_err()
            .contains("downgrade"));
        assert!(check_version("0.1.0", "0.2.0", true, "0.1.0").is_ok());
        assert!(check_version("0.1.5", "0.3.0", true, "0.2.0")
            .unwrap_err()
            .contains("oldest"));
        assert!(check_version("0.2.0", "0.3.0", true, "0.2.0").is_ok());
        assert!(check_version("x", "0.1.0", false, "0.1.0").is_err());
        assert!(parse_version(ROLLBACK_FLOOR).is_some());
    }

    fn release(kp: &EcdsaKeyPair, data: &[(&str, &str, &str, &[u8])]) -> (Vec<u8>, Vec<u8>) {
        use sha2::Digest;
        let m = agent_proto::release::Manifest {
            format: 1,
            version: "0.2.0".into(),
            protocol: "1.8".into(),
            min_appliance: String::new(),
            released: String::new(),
            notes: String::new(),
            artifacts: data
                .iter()
                .map(|(name, kind, arch, d)| agent_proto::release::Artifact {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    os: "linux".into(),
                    arch: arch.to_string(),
                    version: "0.2.0".into(),
                    size: d.len() as u64,
                    sha256: agent_proto::release::hex(&sha2::Sha256::digest(d)),
                })
                .collect(),
        };
        let json = serde_json::to_vec(&m).unwrap();
        let sig = sign(kp, &json);
        (json, sig)
    }

    fn sha(d: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(d).into()
    }

    #[test]
    fn announced_artifacts_are_checked_against_the_signed_manifest() {
        let (kp, point) = keypair();
        let keys = vec![("k.pub".to_string(), point)];
        let bin = fake_binary("0.2.0");
        let deb = b"!<arch>\ndebian-binary".to_vec();
        let (m, msig) = release(
            &kp,
            &[
                ("linux-x86_64/nexus-agent", "binary", "x86_64", &bin),
                ("linux-x86_64/nexus-agent_0.2.0_amd64.deb", "deb", "x86_64", &deb),
            ],
        );
        let host = |install: &str| agent_proto::release::HostFacts {
            os: "linux".into(),
            arch: "x86_64".into(),
            install: install.into(),
            gui_version: None,
        };
        let check = |m: &[u8], msig: &[u8], kind: &str, name: &str, d: &[u8], install: &str, cur: &str, rb: bool| {
            check_announced(
                &keys,
                m,
                msig,
                kind,
                name,
                d.len() as u64,
                &sha(d),
                &host(install),
                cur,
                rb,
            )
        };
        let a = check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "deb",
            "0.1.0",
            false,
        )
        .unwrap();
        assert_eq!(a.manifest.version, "0.2.0");
        assert_eq!(a.key, "k.pub");
        // the data itself: its own signature
        check_artifact_data(&a, &deb, &sign(&kp, &deb), &keys, &|_| false).unwrap();
        assert!(check_artifact_data(&a, &deb, &sign(&kp, b"other"), &keys, &|_| false).is_err());
        // binary: version marker and format
        let b = check(
            &m,
            &msig,
            "binary",
            "linux-x86_64/nexus-agent",
            &bin,
            "bundle",
            "0.1.0",
            false,
        )
        .unwrap();
        check_artifact_data(&b, &bin, &sign(&kp, &bin), &keys, &|x| x.starts_with(b"\x7fELF")).unwrap();
        assert!(check_artifact_data(&b, &bin, &sign(&kp, &bin), &keys, &|_| false)
            .unwrap_err()
            .contains("platform"));
        // install type decides the kind: no binary swap under dpkg, no deb on a bundle
        assert!(check(
            &m,
            &msig,
            "binary",
            "linux-x86_64/nexus-agent",
            &bin,
            "deb",
            "0.1.0",
            false
        )
        .unwrap_err()
        .contains("own package type"));
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "bundle",
            "0.1.0",
            false
        )
        .is_err());
        // unsigned / foreign-key manifest
        let (other, _) = keypair();
        assert!(check(
            &m,
            &sign(&other, &m),
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "deb",
            "0.1.0",
            false
        )
        .unwrap_err()
        .contains("manifest"));
        // not listed, wrong kind, wrong data
        assert!(check(&m, &msig, "deb", "linux-x86_64/other.deb", &deb, "deb", "0.1.0", false).is_err());
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent",
            &bin,
            "deb",
            "0.1.0",
            false
        )
        .is_err());
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            b"x",
            "deb",
            "0.1.0",
            false
        )
        .unwrap_err()
        .contains("SHA-256"));
        // wrong architecture
        let mut aarch = host("deb");
        aarch.arch = "aarch64".into();
        assert!(check_announced(
            &keys,
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            deb.len() as u64,
            &sha(&deb),
            &aarch,
            "0.1.0",
            false
        )
        .unwrap_err()
        .contains("aarch64"));
        // downgrade only as a rollback, never below the floor
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "deb",
            "0.3.0",
            false
        )
        .unwrap_err()
        .contains("downgrade"));
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "deb",
            "0.3.0",
            true
        )
        .is_ok());
        assert!(check(
            &m,
            &msig,
            "deb",
            "linux-x86_64/nexus-agent_0.2.0_amd64.deb",
            &deb,
            "deb",
            "0.2.0",
            true
        )
        .is_err());
    }

    fn paths() -> (tempfile::TempDir, crate::config::Paths) {
        let t = tempfile::tempdir().unwrap();
        let p = crate::config::Paths {
            config: t.path().join("etc"),
            state: t.path().join("state"),
            run: t.path().join("run"),
        };
        fs::create_dir_all(&p.state).unwrap();
        (t, p)
    }

    fn pending(kind: &str) -> Pending {
        Pending {
            kind: kind.into(),
            from: "0.1.0".into(),
            to: "0.2.0".into(),
            started: 1000,
            starts: 0,
            unit: String::new(),
            pre: false,
        }
    }

    fn state(p: &crate::config::Paths) -> UpdateState {
        serde_json::from_str(&state_json(p)).unwrap()
    }

    #[test]
    fn unit_watchdog_reverts_a_binary_that_never_runs() {
        // #93: the new binary exits before its own watchdog (lab: an ELF that is /bin/false); the previous one
        // counts in ExecStartPre and puts itself back on the third start
        let (_t, p) = paths();
        let restored = std::cell::Cell::new(0);
        let restore = || {
            restored.set(restored.get() + 1);
            Ok(())
        };
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue, "nothing pending");
        write_pending(&p, &pending("binary")).unwrap();
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue);
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue);
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Reverted);
        assert_eq!(restored.get(), 1);
        assert_eq!(state(&p).state, "rolled_back");
        // a new binary that does run: counted once per start, by the unit only
        write_pending(&p, &pending("binary")).unwrap();
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue);
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue);
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        assert_eq!(read_pending(&p).unwrap().starts, 2, "not counted twice per start");
        mark_listening(&p, "0.2.0");
        assert_eq!(state(&p).state, "ok");
        // package installs are not binary swaps
        write_pending(&p, &pending("deb")).unwrap();
        assert_eq!(watchdog_pre(&p, &restore), Watchdog::Continue);
        assert_eq!(read_pending(&p).unwrap().starts, 0);
    }

    #[test]
    fn start_watchdog_reverts_after_three_failed_starts() {
        let (_t, p) = paths();
        let restored = std::cell::Cell::new(0);
        let restore = || {
            restored.set(restored.get() + 1);
            Ok(())
        };
        assert_eq!(watchdog_on_start(&p, "0.1.0", &restore), Watchdog::Continue);
        write_pending(&p, &pending("binary")).unwrap();
        // two starts of the new version that never listened
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        assert_eq!(read_pending(&p).unwrap().starts, 2);
        // the third one puts the previous binary back
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Reverted);
        assert_eq!(restored.get(), 1);
        assert!(read_pending(&p).is_none());
        let s = state(&p);
        assert_eq!(
            (s.state.as_str(), s.from.as_str(), s.to.as_str()),
            ("rolled_back", "0.1.0", "0.2.0")
        );
        // a new version that listens is done
        write_pending(&p, &pending("binary")).unwrap();
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        mark_listening(&p, "0.2.0");
        assert!(read_pending(&p).is_none());
        assert_eq!(state(&p).state, "ok");
        // the old version came back (swap failed or reverted by hand)
        write_pending(&p, &pending("binary")).unwrap();
        assert_eq!(watchdog_on_start(&p, "0.1.0", &restore), Watchdog::Continue);
        assert_eq!(state(&p).state, "rolled_back");
        // a restore that fails is reported, the agent keeps running
        write_pending(
            &p,
            &Pending {
                starts: 2,
                ..pending("binary")
            },
        )
        .unwrap();
        assert_eq!(
            watchdog_on_start(&p, "0.2.0", &|| Err("gone".into())),
            Watchdog::Continue
        );
        assert!(state(&p).error.contains("gone"));
        // package installs are not the watchdog's business
        write_pending(
            &p,
            &Pending {
                starts: 9,
                ..pending("deb")
            },
        )
        .unwrap();
        assert_eq!(watchdog_on_start(&p, "0.2.0", &restore), Watchdog::Continue);
        assert_eq!(read_pending(&p).unwrap().starts, 9);
    }

    #[test]
    fn package_installs_settle_by_version_or_installer_result() {
        let (_t, p) = paths();
        let run = |_: &Pending| InstallResult::Running;
        assert!(!settle_package_at(&p, "0.1.0", &run, 1000), "nothing pending");
        write_pending(&p, &pending("deb")).unwrap();
        assert!(settle_package_at(&p, "0.1.0", &run, 1100));
        assert!(!settle_package_at(&p, "0.1.0", &run, 1000 + INSTALL_TIMEOUT_SECS));
        assert!(state(&p).error.contains("30 minutes"));
        // the new version runs: ok
        write_pending(&p, &pending("rpm")).unwrap();
        assert!(!settle_package_at(&p, "0.2.0", &run, 1100));
        assert_eq!(state(&p).state, "ok");
        // installer failed: error + log
        write_pending(&p, &pending("deb")).unwrap();
        let failed = |_: &Pending| InstallResult::Failed("exit status 100".into(), vec!["E: broken".into()]);
        assert!(!settle_package_at(&p, "0.1.0", &failed, 1100));
        let s = state(&p);
        assert_eq!(
            (s.state.as_str(), s.log.as_slice()),
            ("failed", &["E: broken".to_string()][..])
        );
        // succeeded but the agent was not restarted into the new version
        write_pending(&p, &pending("deb")).unwrap();
        let ok = |_: &Pending| InstallResult::Succeeded;
        assert!(settle_package_at(&p, "0.1.0", &ok, 1000 + RESTART_GRACE_SECS - 1));
        assert!(!settle_package_at(&p, "0.1.0", &ok, 1000 + RESTART_GRACE_SECS));
        assert!(state(&p).error.contains("still runs 0.1.0"));
        // binary swaps are left to the watchdog
        write_pending(&p, &pending("binary")).unwrap();
        assert!(!settle_package_at(&p, "0.1.0", &failed, 1100));
        assert!(read_pending(&p).is_some());
        assert_eq!(tail_lines("a\n\nb\nc\n", 2), ["b", "c"]);
        assert_eq!(
            tail_lines("(Reading 5%\r(Reading 100%\r\nok", 5),
            ["(Reading 100%", "ok"]
        );
    }

    #[test]
    fn key_parsing_and_versions() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("a.pub"), TEST_PUB).unwrap();
        fs::write(
            t.path().join("bad.pub"),
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
        )
        .unwrap();
        fs::write(t.path().join("ignored.txt"), TEST_PUB).unwrap();
        assert_eq!(load_keys(t.path()).len(), 1);
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3-rc1"), None);
        assert!(parse_version("0.10.0") > parse_version("0.9.9"));
        assert_eq!(embedded_version(&fake_binary("1.2.3")).unwrap(), "1.2.3");
        assert!(embedded_version(b"no marker").is_err());
        let mut two = fake_binary("1.0.0");
        two.extend(fake_binary("2.0.0"));
        assert!(embedded_version(&two).is_err());
    }
}
