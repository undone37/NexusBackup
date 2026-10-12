//! The appliance's web certificate (docs/control-plane.md "Web certificate").
//!
//! `/etc/nexus/tls` holds two certificates:
//! - `cert.pem` / `key.pem`: the self-signed **identity** nexus-setup creates.
//!   Replication secondaries pin its SHA-256, so connections with a replication
//!   ALPN always get it; browsers get it until a certificate is imported.
//! - `web.pem`: an **imported** chain plus its private key in one file (a rename
//!   swaps both at once), served to browsers and API clients.
//!
//! `nexus-tls` (root oneshot, started by nexus-tls.path) answers the request the
//! web-api writes to `/var/lib/nexus/tls/request.json`:
//! - `csr {cn, sans}`: a new ECDSA P-256 key into `pending/key.pem` (it never
//!   leaves `/etc/nexus/tls`), the CSR is returned and kept as `csr.pem`;
//! - `install {chain_pem}`: the chain is validated against the pending key and
//!   the requested names ([`validate`]), then `web.pem` is replaced atomically and
//!   the previous one kept as `web.pem.prev`;
//! - `revert`: swaps `web.pem` and `web.pem.prev` (no previous one: back to the
//!   self-signed identity).
//!
//! The answer is written to `result.json` with the request's `id`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

pub const TLS_DIR: &str = "/etc/nexus/tls";
pub const REQ_DIR: &str = "/var/lib/nexus/tls";
/// Largest accepted chain (PEM bytes) and request file.
pub const MAX_CHAIN: usize = 64 * 1024;
pub const MAX_CERTS: usize = 8;
pub const MAX_SANS: usize = 32;

#[derive(Clone, Debug)]
pub struct Paths {
    pub tls: PathBuf,
    pub req: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Paths {
            tls: TLS_DIR.into(),
            req: REQ_DIR.into(),
        }
    }
}

impl Paths {
    /// self-signed identity certificate (nexus-setup)
    pub fn identity(&self) -> PathBuf {
        self.tls.join("cert.pem")
    }
    /// imported chain + key
    pub fn web(&self) -> PathBuf {
        self.tls.join("web.pem")
    }
    pub fn prev(&self) -> PathBuf {
        self.tls.join("web.pem.prev")
    }
    fn pending(&self) -> PathBuf {
        self.tls.join("pending")
    }
    pub fn request(&self) -> PathBuf {
        self.req.join("request.json")
    }
    pub fn result(&self) -> PathBuf {
        self.req.join("result.json")
    }
    /// public copies of the pending CSR and its names (for the UI)
    pub fn csr(&self) -> PathBuf {
        self.req.join("csr.pem")
    }
    pub fn pending_info(&self) -> PathBuf {
        self.req.join("pending.json")
    }
}

// ---------------------------------------------------------------- parsing

/// What the UI shows per certificate.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// DNS names (lower case) and IP addresses
    pub sans: Vec<String>,
    pub not_before: i64,
    pub not_after: i64,
    /// SHA-256 of the DER, upper case and colon separated (what browsers show)
    pub sha256: String,
    pub self_signed: bool,
    pub ca: bool,
}

pub fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// DER of every CERTIFICATE block, in file order (other blocks are skipped).
pub fn pem_certs(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = vec![];
    for p in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let p = p.map_err(|e| anyhow::anyhow!("PEM: {e}"))?;
        if p.label == "CERTIFICATE" {
            out.push(p.contents);
        }
    }
    Ok(out)
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>> {
    let (rest, c) = X509Certificate::from_der(der).map_err(|e| anyhow::anyhow!("certificate: {e}"))?;
    if !rest.is_empty() {
        bail!("certificate: trailing data");
    }
    Ok(c)
}

fn sans_of(c: &X509Certificate) -> Vec<String> {
    let Ok(Some(ext)) = c.subject_alternative_name() else {
        return vec![];
    };
    ext.value
        .general_names
        .iter()
        .filter_map(|g| match g {
            GeneralName::DNSName(s) => Some(s.to_ascii_lowercase()),
            GeneralName::IPAddress(b) => match b.len() {
                4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

fn issued(child: &X509Certificate, parent: &X509Certificate) -> bool {
    child.issuer().as_raw() == parent.subject().as_raw() && child.verify_signature(Some(parent.public_key())).is_ok()
}

fn info_of(der: &[u8], c: &X509Certificate) -> CertInfo {
    CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        sans: sans_of(c),
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        sha256: fingerprint(der),
        self_signed: c.subject().as_raw() == c.issuer().as_raw() && c.verify_signature(None).is_ok(),
        ca: c.is_ca(),
    }
}

pub fn info(der: &[u8]) -> Result<CertInfo> {
    Ok(info_of(der, &parse(der)?))
}

/// Every certificate of a PEM file (leaf first).
pub fn chain_info(pem: &[u8]) -> Result<Vec<CertInfo>> {
    pem_certs(pem)?.iter().map(|d| info(d)).collect()
}

// ---------------------------------------------------------------- names

/// A DNS name (labels of letters, digits and `-`, optionally `*.` first) or an IP.
pub fn check_name(s: &str) -> Result<String> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let n = s.trim_end_matches('.').to_ascii_lowercase();
    let host = n.strip_prefix("*.").unwrap_or(&n);
    let ok = (1..=253).contains(&n.len())
        && host.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    if !ok {
        bail!("{s:?} is neither a DNS name nor an IP address");
    }
    Ok(n)
}

/// Whether a certificate SAN covers `name` (wildcards: exactly one left-most label).
pub fn covers(san: &str, name: &str) -> bool {
    if let (Ok(a), Ok(b)) = (san.parse::<IpAddr>(), name.parse::<IpAddr>()) {
        return a == b;
    }
    let (san, name) = (san.to_ascii_lowercase(), name.to_ascii_lowercase());
    match san.strip_prefix("*.") {
        Some(rest) => name
            .split_once('.')
            .is_some_and(|(first, tail)| !first.is_empty() && first != "*" && tail == rest),
        None => san == name,
    }
}

// ---------------------------------------------------------------- CSR

/// What a CSR asked for (kept until the matching chain is installed).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Pending {
    pub cn: String,
    pub sans: Vec<String>,
    pub created: i64,
}

fn check_request(cn: &str, sans: &[String]) -> Result<(String, Vec<String>)> {
    let cn = check_name(cn.trim()).context("cn")?;
    if sans.len() > MAX_SANS {
        bail!("sans: at most {MAX_SANS} names");
    }
    let mut out: Vec<String> = vec![];
    for s in std::iter::once(&cn).chain(sans) {
        let n = check_name(s.trim()).context("sans")?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok((cn, out))
}

/// A new P-256 key (PEM) and a CSR for `cn` with SANs `sans` (the CN is always one of them).
pub fn make_csr(cn: &str, sans: &[String]) -> Result<(String, String, Pending)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    let (cn, sans) = check_request(cn, sans)?;
    let mut p = CertificateParams::default();
    for s in &sans {
        p.subject_alt_names.push(match s.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(s.clone().try_into()?),
        });
    }
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn.as_str());
    p.distinguished_name = dn;
    let key = KeyPair::generate()?;
    let csr = p.serialize_request(&key)?.pem()?;
    let pending = Pending {
        cn,
        sans,
        created: now(),
    };
    Ok((key.serialize_pem(), csr, pending))
}

// ---------------------------------------------------------------- validation

/// A chain that passed [`validate`].
#[derive(Debug)]
pub struct Valid {
    pub chain: Vec<CertInfo>,
    /// the certificates, re-encoded (leaf first)
    pub pem: String,
    pub warnings: Vec<String>,
}

/// Checks an imported chain before it replaces the web certificate:
/// - leaf first, then each issuer (every certificate signed by the next one,
///   intermediates are CAs); the root may be left out;
/// - the leaf's public key is the pending key's (`key_pem`);
/// - every certificate is valid at `now`;
/// - the leaf is no CA, allows serverAuth and digitalSignature (if it restricts
///   them) and its SANs cover every name of the CSR (`names`).
pub fn validate(chain_pem: &str, key_pem: &str, names: &[String], now: i64) -> Result<Valid> {
    if chain_pem.len() > MAX_CHAIN {
        bail!("certificate chain larger than {MAX_CHAIN} bytes");
    }
    let ders = pem_certs(chain_pem.as_bytes())?;
    if ders.is_empty() {
        bail!("no certificate found (paste PEM: -----BEGIN CERTIFICATE-----)");
    }
    if ders.len() > MAX_CERTS {
        bail!("more than {MAX_CERTS} certificates");
    }
    let certs = ders.iter().map(|d| parse(d)).collect::<Result<Vec<_>>>()?;
    let infos: Vec<CertInfo> = ders.iter().zip(&certs).map(|(d, c)| info_of(d, c)).collect();
    let leaf = &certs[0];

    let key = rcgen::KeyPair::from_pem(key_pem).context("pending key")?;
    if leaf.public_key().raw != key.public_key_der().as_slice() {
        let other = certs[1..]
            .iter()
            .any(|c| c.public_key().raw == key.public_key_der().as_slice());
        bail!(if other {
            "wrong order: the certificate for this appliance's key must come first (leaf, then intermediates)"
        } else {
            "the certificate does not belong to the pending key: was it issued for the CSR generated here last?"
        });
    }
    for (i, w) in certs.windows(2).enumerate() {
        if !issued(&w[0], &w[1]) {
            let elsewhere = certs
                .iter()
                .enumerate()
                .any(|(j, c)| j != i + 1 && j != i && issued(&w[0], c));
            bail!(
                "{}: certificate {} ({}) was not issued by certificate {} ({})",
                if elsewhere { "wrong order" } else { "not a chain" },
                i + 1,
                infos[i].subject,
                i + 2,
                infos[i + 1].subject
            );
        }
        if !w[1].is_ca() {
            bail!("certificate {} ({}) is not a CA", i + 2, infos[i + 1].subject);
        }
    }
    for (i, c) in infos.iter().enumerate() {
        if now < c.not_before {
            bail!("certificate {} ({}) is not valid yet", i + 1, c.subject);
        }
        if now > c.not_after {
            bail!("certificate {} ({}) has expired", i + 1, c.subject);
        }
    }
    if leaf.is_ca() {
        bail!("the leaf certificate is a CA certificate");
    }
    if let Ok(Some(eku)) = leaf.extended_key_usage() {
        if !eku.value.server_auth && !eku.value.any {
            bail!("the leaf certificate does not allow TLS server authentication (EKU serverAuth)");
        }
    }
    if let Ok(Some(ku)) = leaf.key_usage() {
        if !ku.value.digital_signature() {
            bail!("the leaf certificate's key usage lacks digitalSignature");
        }
    }
    let sans = &infos[0].sans;
    if sans.is_empty() {
        bail!("the leaf certificate has no subject alternative names");
    }
    let missing: Vec<&String> = names.iter().filter(|n| !sans.iter().any(|s| covers(s, n))).collect();
    if !missing.is_empty() {
        bail!(
            "the certificate does not cover {} (it has: {})",
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            sans.join(", ")
        );
    }
    let mut warnings = vec![];
    let last = infos.last().unwrap();
    if !last.self_signed {
        warnings.push(format!(
            "the issuer {} is not included: clients must trust it (or the root above it) already",
            last.issuer
        ));
    }
    if infos[0].not_after - now < 30 * 86400 {
        warnings.push("the certificate expires within 30 days".into());
    }
    let pem = ders
        .iter()
        .map(|d| pem_block("CERTIFICATE", d))
        .collect::<Vec<_>>()
        .concat();
    Ok(Valid {
        chain: infos,
        pem,
        warnings,
    })
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let cfg = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    pem::encode_config(&pem::Pem::new(label, der), cfg)
}

// ---------------------------------------------------------------- operations

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Write to `<path>.tmp`, fsync, rename (readers see the old or the new file).
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("{}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path).with_context(|| format!("{}", path.display()))?;
    Ok(())
}

/// Reads a regular file (no symlink) of at most `max` bytes; `None` if absent.
pub fn read_small(path: &Path, max: usize) -> Result<Option<Vec<u8>>> {
    let f = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("{}", path.display())),
    };
    if !f.metadata()?.is_file() {
        bail!("{}: not a regular file", path.display());
    }
    let mut v = vec![];
    f.take(max as u64 + 1).read_to_end(&mut v)?;
    if v.len() > max {
        bail!("{}: larger than {max} bytes", path.display());
    }
    Ok(Some(v))
}

fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e).with_context(|| format!("{}", path.display())),
        _ => Ok(()),
    }
}

/// `csr`: new pending key + CSR (replaces an earlier pending one).
pub fn csr(p: &Paths, cn: &str, sans: &[String]) -> Result<Value> {
    let (key, csr, pending) = make_csr(cn, sans)?;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p.pending())?;
    write_atomic(&p.pending().join("key.pem"), key.as_bytes(), 0o600)?;
    let info = serde_json::to_vec(&pending)?;
    write_atomic(&p.pending().join("request.json"), &info, 0o600)?;
    write_atomic(&p.csr(), csr.as_bytes(), 0o644)?;
    write_atomic(&p.pending_info(), &info, 0o644)?;
    Ok(json!({"csr_pem": csr, "pending": pending}))
}

/// `install`: validated chain + pending key become `web.pem`.
pub fn install(p: &Paths, chain_pem: &str, now: i64) -> Result<Value> {
    let key = read_small(&p.pending().join("key.pem"), 16 * 1024)?.context("no pending key: generate a CSR first")?;
    let key = String::from_utf8(key).context("pending key")?;
    let pending: Pending = serde_json::from_slice(
        &read_small(&p.pending().join("request.json"), 64 * 1024)?.context("pending request missing")?,
    )?;
    let v = validate(chain_pem, &key, &pending.sans, now)?;
    if let Some(cur) = read_small(&p.web(), MAX_CHAIN + 16 * 1024)? {
        write_atomic(&p.prev(), &cur, 0o640)?;
    }
    write_atomic(&p.web(), format!("{}{key}", v.pem).as_bytes(), 0o640)?;
    fs::remove_dir_all(p.pending()).context("remove pending key")?;
    remove(&p.csr())?;
    remove(&p.pending_info())?;
    Ok(json!({"chain": v.chain, "warnings": v.warnings}))
}

/// `revert`: the previous imported certificate, or the self-signed one.
pub fn revert(p: &Paths) -> Result<Value> {
    let max = MAX_CHAIN + 16 * 1024;
    let (cur, prev) = (read_small(&p.web(), max)?, read_small(&p.prev(), max)?);
    if cur.is_none() && prev.is_none() {
        bail!("nothing to revert: the self-signed certificate is in use and there is no previous one");
    }
    // the current one first to a side file, so a crash in between loses nothing
    let side = p.tls.join("web.pem.prev.new");
    if let Some(c) = &cur {
        write_atomic(&side, c, 0o640)?;
    }
    match &prev {
        Some(x) => write_atomic(&p.web(), x, 0o640)?,
        None => remove(&p.web())?,
    }
    match &cur {
        Some(_) => fs::rename(&side, p.prev())?,
        None => remove(&p.prev())?,
    }
    Ok(json!({"active": if prev.is_some() { "imported" } else { "self_signed" }}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub op: String,
    #[serde(default)]
    pub cn: String,
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default)]
    pub chain_pem: String,
}

/// Handles `request.json` if there is one: removes it and writes `result.json`
/// (`{id, ok, error?, ...}`). Returns whether a request was handled.
pub fn process(p: &Paths) -> Result<bool> {
    let Some(raw) = read_small(&p.request(), MAX_CHAIN + 4096)? else {
        return Ok(false);
    };
    remove(&p.request())?;
    let req: Request = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("<4>nexus-tls: bad request: {e}");
            return Ok(true);
        }
    };
    if req.id.is_empty() || req.id.len() > 64 || !req.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!("<4>nexus-tls: bad request id");
        return Ok(true);
    }
    let out = match req.op.as_str() {
        "csr" => csr(p, &req.cn, &req.sans),
        "install" => install(p, &req.chain_pem, now()),
        "revert" => revert(p),
        o => Err(anyhow::anyhow!("unknown operation {o:?}")),
    };
    let mut v = match out {
        Ok(mut v) => {
            v["ok"] = json!(true);
            eprintln!("<5>nexus-tls: {} done", req.op);
            v
        }
        Err(e) => {
            eprintln!("<4>nexus-tls: {}: {e:#}", req.op);
            json!({"ok": false, "error": format!("{e:#}")})
        }
    };
    v["id"] = json!(req.id);
    write_atomic(&p.result(), &serde_json::to_vec(&v)?, 0o644)?;
    Ok(true)
}

/// What the web-api shows on Settings → Certificate.
pub fn status(p: &Paths) -> Result<Value> {
    let max = MAX_CHAIN + 16 * 1024;
    let identity = read_small(&p.identity(), max)?
        .map(|b| chain_info(&b))
        .transpose()?
        .and_then(|c| c.into_iter().next());
    let web = read_small(&p.web(), max)?.map(|b| chain_info(&b)).transpose()?;
    let pending: Option<Pending> =
        read_small(&p.pending_info(), 64 * 1024)?.and_then(|b| serde_json::from_slice(&b).ok());
    let csr = read_small(&p.csr(), 64 * 1024)?.map(|b| String::from_utf8_lossy(&b).into_owned());
    let has_prev = p.prev().exists();
    Ok(json!({
        "active": if web.is_some() { "imported" } else { "self_signed" },
        "chain": web.clone().unwrap_or_else(|| identity.clone().into_iter().collect()),
        "identity": identity,
        "pending": pending.map(|x| json!({"cn": x.cn, "sans": x.sans, "created": x.created, "csr_pem": csr})),
        "can_revert": web.is_some() || has_prev,
        "previous": has_prev,
    }))
}

#[cfg(test)]
mod tests;
