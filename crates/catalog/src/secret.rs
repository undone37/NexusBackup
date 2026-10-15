//! Secrets at rest in the catalog (security review H-2). One module so web-api,
//! scheduler and setup use the same formats.
//!
//! **Source / offsite credentials** (`sources.config`, `tenants.offsite`: every
//! string field named in [`SECRET_FIELDS`]) are sealed to the scheduler with an
//! anonymous public-key box (libsodium `crypto_box_seal`: X25519 +
//! XSalsa20-Poly1305, crate `crypto_box`). Stored as `sealed:v1:<base64>`. The
//! scheduler owns the private key ([`SchedulerKey`], 0600 in its state dir) and
//! publishes the public key ([`SealKey`]) for the web-api, which can seal but
//! never open. The sealed plaintext is `location NUL secret`; [`SchedulerKey::open`]
//! checks the location, so a blob cannot be moved to another source / tenant /
//! field, nor follow an endpoint change: the location includes a digest of the
//! endpoint fields next to the secret ([`BINDING_FIELDS`]), so redirecting a
//! source to another host in the catalog makes its token unusable.
//!
//! **TOTP seeds** (`users.totp_secret`, and the `totp_secret` of pending
//! `user.update` quorum params) are encrypted with a web-api-only symmetric key
//! ([`TotpKey`], XChaCha20-Poly1305, AAD = user name; names never change).
//! Stored as `enc:v1:<base64(nonce || ciphertext)>`. Values without the prefix
//! are legacy plaintext (base32) and still accepted until re-encrypted.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub const SEALED_PREFIX: &str = "sealed:v1:";
pub const TOTP_PREFIX: &str = "enc:v1:";

/// JSON keys whose string values are credentials (sealed to the scheduler).
/// `password` / `keytab`: SMB shares (docs/nas-connector.md); `secret_key`: S3 secret access key of an offsite remote.
pub const SECRET_FIELDS: &[&str] = &["token_secret", "key_pem", "password", "keytab", "secret_key"];

/// Sibling fields that define where a secret is sent; part of its location.
pub const BINDING_FIELDS: &[&str] = &["host", "port", "connect_addr", "ca_pem", "token_id", "user", "host_key"];

/// More binding fields (S3 offsite remotes). They join the digest only when
/// present, so the locations of secrets sealed before they existed stay the same.
pub const EXTRA_BINDING_FIELDS: &[&str] = &["endpoint", "bucket", "access_key", "path_style", "region"];

pub fn is_sealed(v: &str) -> bool {
    v.starts_with(SEALED_PREFIX)
}

pub fn is_encrypted_totp(v: &str) -> bool {
    v.starts_with(TOTP_PREFIX)
}

/// Location owner of a source config.
pub fn source_owner(id: i64) -> String {
    format!("source/{id}")
}

/// Location of an agent's sealed enrollment token digest (`agents.token_hash`):
/// bound to the agent and its endpoint, so a changed host/port makes it unusable.
pub fn agent_token_location(id: &str, host: &str, port: u16) -> String {
    format!("agent/{id}/token@{host}:{port}")
}

/// Location of an edge proxy's sealed enrollment token digest (`edges.token_hash`,
/// docs/edge.md), bound to the edge id and its control address.
pub fn edge_token_location(id: &str, host: &str, port: u16) -> String {
    format!("edge/{id}/token@{host}:{port}")
}

/// Location of a rescue session's sealed recovery token digest
/// (`rescue_sessions.token_hash`, docs/bmr.md), bound to the session's original agent.
pub fn rescue_token_location(id: &str, agent: &str) -> String {
    format!("rescue/{id}/token@agent/{agent}")
}

/// Location of the plaintext recovery token of a P2V session (written onto the
/// config disk of the new VM by the scheduler; `rescue_sessions.p2v` `token`).
pub fn rescue_p2v_token_location(id: &str, agent: &str) -> String {
    format!("rescue/{id}/p2v-token@agent/{agent}")
}

/// Location of a replication peer's enrollment token digest on the primary
/// (`replication_peers.token_hash`, sealed to nexus-replicad, docs/replication.md).
pub fn replication_peer_token_location(id: &str) -> String {
    format!("replication-peer/{id}/token")
}

/// Location of a replication source's enrollment token digest on the secondary
/// (`replication_sources.token_hash`, sealed to the scheduler): bound to the
/// primary's address, peer id and certificate pin.
pub fn replication_source_token_location(id: i64, url: &str, peer_id: &str, pin: &str) -> String {
    format!("replication-source/{id}/token@{url}/{peer_id}/{pin}")
}

/// Location owner of a tenant's offsite config.
pub fn tenant_owner(name: &str) -> String {
    format!("tenant/{name}/offsite")
}

/// Location of the recovery key the requester of an approved
/// `tenant.attach_offsite` (quorum `id`) submits once: sealed into the
/// `offsite_attach` job's params by the web-api, opened and removed from the
/// row by the scheduler when the job starts (docs/control-plane.md "Attach an offsite copy").
pub fn attach_key_location(quorum_id: i64, tenant: &str) -> String {
    format!("attach/{quorum_id}/{tenant}/recovery-key")
}

fn binding(o: &Map<String, Value>) -> String {
    let mut v: Vec<Value> = BINDING_FIELDS
        .iter()
        .map(|k| o.get(*k).cloned().unwrap_or(Value::Null))
        .collect();
    for k in EXTRA_BINDING_FIELDS {
        if let Some(x) = o.get(*k) {
            v.push(Value::String((*k).to_owned()));
            v.push(x.clone());
        }
    }
    let d = Sha256::digest(serde_json::to_string(&v).unwrap_or_default().as_bytes());
    d[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Calls `f(pointer, location, value)` for every secret field (string value
/// under a key in [`SECRET_FIELDS`]) in `v`. `pointer` is the JSON pointer
/// (`/api/token_secret`), `location` = `<owner><pointer>@<endpoint digest>`.
pub fn for_each_secret(
    owner: &str,
    v: &mut Value,
    f: &mut dyn FnMut(&str, &str, &mut String) -> Result<()>,
) -> Result<()> {
    for_each_secret_with(owner, v, &[], f)
}

/// Like [`for_each_secret`], with more secret field names (a plugin's
/// `secret_fields`, docs/plugin-system.md). Locations are computed the same way,
/// so a field that is also in [`SECRET_FIELDS`] gets the same location either way.
pub fn for_each_secret_with(
    owner: &str,
    v: &mut Value,
    extra: &[&str],
    f: &mut dyn FnMut(&str, &str, &mut String) -> Result<()>,
) -> Result<()> {
    fn walk(
        owner: &str,
        ptr: &mut String,
        v: &mut Value,
        extra: &[&str],
        f: &mut dyn FnMut(&str, &str, &mut String) -> Result<()>,
    ) -> Result<()> {
        match v {
            Value::Object(o) => {
                let b = binding(o);
                for (k, x) in o.iter_mut() {
                    let len = ptr.len();
                    ptr.push('/');
                    ptr.push_str(&k.replace('~', "~0").replace('/', "~1"));
                    match x {
                        Value::String(s) if SECRET_FIELDS.contains(&k.as_str()) || extra.contains(&k.as_str()) => {
                            f(ptr, &format!("{owner}{ptr}@{b}"), s)?;
                        }
                        _ => walk(owner, ptr, x, extra, f)?,
                    }
                    ptr.truncate(len);
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter_mut().enumerate() {
                    let len = ptr.len();
                    ptr.push_str(&format!("/{i}"));
                    walk(owner, ptr, x, extra, f)?;
                    ptr.truncate(len);
                }
            }
            _ => {}
        }
        Ok(())
    }
    walk(owner, &mut String::new(), v, extra, f)
}

// ---------------------------------------------------------------- key files

/// Reads a 32-byte key file; refuses files readable by group or others.
pub fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let meta = fs::metadata(path).with_context(|| format!("{}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{}: key file must not be accessible by group or others (chmod 0600)",
            path.display()
        );
    }
    let b = Zeroizing::new(fs::read(path).with_context(|| format!("{}", path.display()))?);
    let mut k = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        bail!("{}: expected a 32-byte key", path.display());
    }
    k.copy_from_slice(&b);
    Ok(k)
}

/// Creates a new random 32-byte key file (0600, never overwrites). Returns
/// `Ok(None)` if the file already exists.
pub fn create_key(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let dir = path.parent().ok_or_else(|| anyhow!("{}: no parent", path.display()))?;
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let mut f = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
    };
    let k = Zeroizing::new(rand::random::<[u8; 32]>());
    f.write_all(&k[..])?;
    f.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(Some(k))
}

/// The key at `path`, created if missing; `true` if it was created.
pub fn load_or_create_key(path: &Path) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    match create_key(path)? {
        Some(k) => Ok((k, true)),
        None => Ok((read_key(path)?, false)),
    }
}

// ---------------------------------------------------------------- sealed box (scheduler)

/// Public half: seals secrets for the scheduler (web-api side).
pub struct SealKey(crypto_box::PublicKey);

impl SealKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        SealKey(crypto_box::PublicKey::from_bytes(b))
    }

    /// Reads the published public key (`base64\n`).
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path).with_context(|| format!("{}", path.display()))?;
        let b = B64
            .decode(s.trim())
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| anyhow!("{}: not a base64 X25519 public key", path.display()))?;
        Ok(Self::from_bytes(b))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }

    /// `sealed:v1:<base64>` of `location NUL secret`.
    pub fn seal(&self, location: &str, secret: &str) -> Result<String> {
        if location.contains('\0') {
            bail!("invalid secret location");
        }
        let mut pt = Zeroizing::new(Vec::with_capacity(location.len() + 1 + secret.len()));
        pt.extend_from_slice(location.as_bytes());
        pt.push(0);
        pt.extend_from_slice(secret.as_bytes());
        let ct = self
            .0
            .seal(&mut rand::rngs::OsRng, &pt)
            .map_err(|_| anyhow!("sealing failed"))?;
        Ok(format!("{SEALED_PREFIX}{}", B64.encode(ct)))
    }

    /// Seals every plaintext secret field in `v` (already sealed values are kept).
    /// Returns the JSON pointers of the fields it sealed.
    pub fn seal_all(&self, owner: &str, v: &mut Value) -> Result<Vec<String>> {
        self.seal_all_with(owner, v, &[])
    }

    /// [`Self::seal_all`] with more secret field names (plugin `secret_fields`).
    pub fn seal_all_with(&self, owner: &str, v: &mut Value, extra: &[&str]) -> Result<Vec<String>> {
        let mut done = Vec::new();
        for_each_secret_with(owner, v, extra, &mut |ptr, loc, s| {
            if !is_sealed(s) {
                *s = self.seal(loc, s)?;
                done.push(ptr.to_owned());
            }
            Ok(())
        })?;
        Ok(done)
    }
}

/// Private half, held only by the scheduler.
#[derive(Clone)]
pub struct SchedulerKey(crypto_box::SecretKey);

impl SchedulerKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        SchedulerKey(crypto_box::SecretKey::from_bytes(b))
    }

    pub fn generate() -> Self {
        SchedulerKey(crypto_box::SecretKey::generate(&mut rand::rngs::OsRng))
    }

    /// Loads the key (0600), generating it on first use. `true` = created.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        let (k, created) = load_or_create_key(path)?;
        Ok((Self::from_bytes(*k), created))
    }

    pub fn public(&self) -> SealKey {
        SealKey(self.0.public_key())
    }

    /// Writes the public key atomically, mode 0640, group `gid` if given.
    pub fn write_public(&self, path: &Path, gid: Option<u32>) -> Result<()> {
        let dir = path.parent().ok_or_else(|| anyhow!("{}: no parent", path.display()))?;
        fs::create_dir_all(dir)?;
        let tmp = dir.join(format!(
            ".{}.tmp",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o640).open(&tmp)?;
        f.write_all(format!("{}\n", self.public().to_base64()).as_bytes())?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))?;
        if gid.is_some() {
            std::os::unix::fs::chown(&tmp, None, gid).with_context(|| format!("chgrp {}", tmp.display()))?;
        }
        fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// Opens a `sealed:v1:` value written for `location`.
    pub fn open(&self, location: &str, sealed: &str) -> Result<Zeroizing<String>> {
        let b = sealed
            .strip_prefix(SEALED_PREFIX)
            .and_then(|b| B64.decode(b).ok())
            .ok_or_else(|| anyhow!("{location}: not a sealed:v1 value"))?;
        let pt = Zeroizing::new(
            self.0
                .unseal(&b)
                .map_err(|_| anyhow!("{location}: cannot open sealed secret (wrong key or tampered)"))?,
        );
        let nul = pt
            .iter()
            .position(|&c| c == 0)
            .ok_or_else(|| anyhow!("{location}: malformed sealed secret"))?;
        if &pt[..nul] != location.as_bytes() {
            bail!("{location}: sealed secret belongs to another location (moved or endpoint changed)");
        }
        Ok(Zeroizing::new(
            String::from_utf8(pt[nul + 1..].to_vec()).map_err(|_| anyhow!("{location}: secret is not UTF-8"))?,
        ))
    }

    /// Opens every sealed secret field in `v` in place (memory only). Legacy
    /// plaintext values are left as they are.
    pub fn open_all(&self, owner: &str, v: &mut Value) -> Result<()> {
        self.open_all_with(owner, v, &[])
    }

    /// [`Self::open_all`] with more secret field names (plugin `secret_fields`).
    pub fn open_all_with(&self, owner: &str, v: &mut Value, extra: &[&str]) -> Result<()> {
        for_each_secret_with(owner, v, extra, &mut |_, loc, s| {
            if is_sealed(s) {
                *s = self.open(loc, s)?.to_string();
            }
            Ok(())
        })
    }
}

// ---------------------------------------------------------------- TOTP seeds (web-api)

/// Symmetric key for TOTP seeds, held only by the web-api (and setup, root).
pub struct TotpKey(Zeroizing<[u8; 32]>);

fn totp_aad(user: &str) -> Vec<u8> {
    [b"nexus totp v1\0user/".as_slice(), user.as_bytes()].concat()
}

fn labeled_aad(label: &str) -> Vec<u8> {
    [b"nexus webapi v1\0".as_slice(), label.as_bytes()].concat()
}

impl TotpKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        TotpKey(Zeroizing::new(b))
    }

    pub fn generate() -> Self {
        Self::from_bytes(rand::random())
    }

    pub fn load(path: &Path) -> Result<Self> {
        Ok(TotpKey(read_key(path)?))
    }

    /// Loads the key; creates it (0600, parent dir 0700) when missing, unless
    /// seeds encrypted with a previous key exist (a new key would lock every
    /// such user out). `true` = created.
    pub fn open_or_create(path: &Path, cat: &crate::Catalog) -> Result<(Self, bool)> {
        if path.exists() {
            return Ok((Self::load(path)?, false));
        }
        let encrypted: i64 = cat.conn().query_row(
            "SELECT COUNT(*) FROM users WHERE totp_secret LIKE 'enc:v1:%'",
            [],
            |r| r.get(0),
        )?;
        if encrypted > 0 {
            bail!(
                "{} is missing but {encrypted} TOTP seed(s) are encrypted with it: restore the key file",
                path.display()
            );
        }
        let (k, created) = load_or_create_key(path)?;
        Ok((TotpKey(k), created))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.0).into())
    }

    /// `enc:v1:<base64(nonce || ciphertext)>`, bound to the user name.
    pub fn encrypt(&self, user: &str, secret_b32: &str) -> Result<String> {
        let nonce: [u8; 24] = rand::random();
        let ct = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret_b32.as_bytes(),
                    aad: &totp_aad(user),
                },
            )
            .map_err(|_| anyhow!("encrypting TOTP seed failed"))?;
        Ok(format!("{TOTP_PREFIX}{}", B64.encode([&nonce[..], &ct].concat())))
    }

    /// Another web-api-only secret (the OIDC client secret): `enc:v1:`, bound to
    /// `label` (AAD distinct from every TOTP seed's).
    pub fn encrypt_labeled(&self, label: &str, secret: &str) -> Result<String> {
        let nonce: [u8; 24] = rand::random();
        let ct = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret.as_bytes(),
                    aad: &labeled_aad(label),
                },
            )
            .map_err(|_| anyhow!("encrypting {label} failed"))?;
        Ok(format!("{TOTP_PREFIX}{}", B64.encode([&nonce[..], &ct].concat())))
    }

    pub fn decrypt_labeled(&self, label: &str, stored: &str) -> Result<Zeroizing<String>> {
        let b = stored
            .strip_prefix(TOTP_PREFIX)
            .and_then(|b| B64.decode(b).ok())
            .filter(|b| b.len() >= 24 + 16)
            .ok_or_else(|| anyhow!("{label}: malformed"))?;
        let pt = Zeroizing::new(
            self.cipher()
                .decrypt(
                    XNonce::from_slice(&b[..24]),
                    Payload {
                        msg: &b[24..],
                        aad: &labeled_aad(label),
                    },
                )
                .map_err(|_| anyhow!("{label}: cannot decrypt (wrong key or tampered)"))?,
        );
        Ok(Zeroizing::new(
            String::from_utf8(pt.to_vec()).map_err(|_| anyhow!("{label}: not UTF-8"))?,
        ))
    }

    /// The base32 seed of `user`. Legacy plaintext values are returned as they are.
    pub fn decrypt(&self, user: &str, stored: &str) -> Result<Zeroizing<String>> {
        let Some(b) = stored.strip_prefix(TOTP_PREFIX) else {
            return Ok(Zeroizing::new(stored.to_owned()));
        };
        let b = B64.decode(b).map_err(|_| anyhow!("user {user}: malformed TOTP seed"))?;
        if b.len() < 24 + 16 {
            bail!("user {user}: malformed TOTP seed");
        }
        let pt = Zeroizing::new(
            self.cipher()
                .decrypt(
                    XNonce::from_slice(&b[..24]),
                    Payload {
                        msg: &b[24..],
                        aad: &totp_aad(user),
                    },
                )
                .map_err(|_| anyhow!("user {user}: cannot decrypt TOTP seed (wrong key, other user or tampered)"))?,
        );
        Ok(Zeroizing::new(
            String::from_utf8(pt.to_vec()).map_err(|_| anyhow!("user {user}: TOTP seed is not UTF-8"))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn flip(s: &str, at: usize) -> String {
        let pfx = if is_sealed(s) { SEALED_PREFIX } else { TOTP_PREFIX };
        let mut b = B64.decode(&s[pfx.len()..]).unwrap();
        let i = at % b.len();
        b[i] ^= 1;
        format!("{pfx}{}", B64.encode(b))
    }

    #[test]
    fn sealed_roundtrip_wrong_key_location_tamper() {
        let k = SchedulerKey::generate();
        let pk = k.public();
        let s = pk.seal("source/1/token_secret@x", "s3cr3t").unwrap();
        assert!(s.starts_with(SEALED_PREFIX) && !s.contains("s3cr3t"));
        assert_eq!(*k.open("source/1/token_secret@x", &s).unwrap(), "s3cr3t");
        // fresh ephemeral key per seal: same input, different output
        assert_ne!(s, pk.seal("source/1/token_secret@x", "s3cr3t").unwrap());
        assert!(SchedulerKey::generate().open("source/1/token_secret@x", &s).is_err());
        let e = k.open("source/2/token_secret@x", &s).unwrap_err().to_string();
        assert!(e.contains("another location"), "{e}");
        // a location that is a prefix of the real one does not match either
        assert!(k.open("source/1/token_secre", &s).is_err());
        for at in [0, 5, 40, 1000] {
            assert!(k.open("source/1/token_secret@x", &flip(&s, at)).is_err());
        }
        assert!(k.open("l", "s3cr3t").is_err());
        assert!(k.open("l", "sealed:v1:!!").is_err());
    }

    #[test]
    fn walker_binds_owner_field_and_endpoint() {
        let k = SchedulerKey::generate();
        let pk = k.public();
        let mut cfg = json!({"host": "pve1", "port": 8006, "ca_pem": "CA", "token_id": "a@pve!b", "token_secret": "tok",
                             "nodes": {"n1": {"host": "10.0.0.1", "key_pem": "KEY", "known_hosts_text": "kh"}}});
        let sealed = pk.seal_all(&source_owner(1), &mut cfg).unwrap();
        assert_eq!(sealed, ["/nodes/n1/key_pem", "/token_secret"]);
        assert!(
            is_sealed(cfg["token_secret"].as_str().unwrap())
                && is_sealed(cfg["nodes"]["n1"]["key_pem"].as_str().unwrap())
        );
        assert_eq!(cfg["nodes"]["n1"]["known_hosts_text"], "kh");
        // sealing again is a no-op
        assert!(pk.seal_all(&source_owner(1), &mut cfg).unwrap().is_empty());

        let mut open = cfg.clone();
        k.open_all(&source_owner(1), &mut open).unwrap();
        assert_eq!(open["token_secret"], "tok");
        assert_eq!(open["nodes"]["n1"]["key_pem"], "KEY");
        // moved to another source
        assert!(k.open_all(&source_owner(2), &mut cfg.clone()).is_err());
        // endpoint changed in the catalog: the token no longer opens
        let mut moved = cfg.clone();
        moved["host"] = json!("attacker.example");
        assert!(k.open_all(&source_owner(1), &mut moved).is_err());
        // moved to another field
        let mut swapped = cfg.clone();
        swapped["nodes"]["n1"]["key_pem"] = cfg["token_secret"].clone();
        assert!(k.open_all(&source_owner(1), &mut swapped).is_err());
        // legacy plaintext passes through untouched
        let mut legacy = json!({"remote": {"host": "box", "key_pem": "PLAIN"}});
        k.open_all(&tenant_owner("t"), &mut legacy).unwrap();
        assert_eq!(legacy["remote"]["key_pem"], "PLAIN");
    }

    #[test]
    fn binding_digest_is_stable_and_covers_s3() {
        // digest of a config without the extra fields: unchanged since v1
        let o = json!({"host": "pve1", "port": 8006, "token_id": "a@pve!b"});
        assert_eq!(binding(o.as_object().unwrap()), "7d546a9cc175d59904a518f280092a17");
        // sha256(["pve1",8006,null,null,"a@pve!b",null,null])
    }

    #[test]
    fn s3_secret_follows_neither_endpoint_nor_bucket() {
        let k = SchedulerKey::generate();
        let pk = k.public();
        let mut cfg = json!({"remote": {"type": "s3", "endpoint": "https://s3.example", "region": "eu", "bucket": "b",
                                         "access_key": "AK", "secret_key": "SK", "path_style": false}});
        assert_eq!(
            pk.seal_all(&tenant_owner("t"), &mut cfg).unwrap(),
            ["/remote/secret_key"]
        );
        let mut open = cfg.clone();
        k.open_all(&tenant_owner("t"), &mut open).unwrap();
        assert_eq!(open["remote"]["secret_key"], "SK");
        for (f, v) in [
            ("endpoint", json!("https://attacker.example")),
            ("bucket", json!("other")),
            ("access_key", json!("AK2")),
            ("path_style", json!(true)),
            ("region", json!("us-east-1")),
        ] {
            let mut moved = cfg.clone();
            moved["remote"][f] = v;
            assert!(k.open_all(&tenant_owner("t"), &mut moved).is_err(), "{f}");
        }
        // prefix / storage classes / lock may change without re-entering the key
        let mut same = cfg.clone();
        same["remote"]["prefix"] = json!("x");
        same["remote"]["lock"] = json!(true);
        k.open_all(&tenant_owner("t"), &mut same).unwrap();
    }

    #[test]
    fn totp_roundtrip_wrong_key_user_tamper() {
        let k = TotpKey::generate();
        let e = k.encrypt("alice", "JBSWY3DPEHPK3PXP").unwrap();
        assert!(is_encrypted_totp(&e) && !e.contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(*k.decrypt("alice", &e).unwrap(), "JBSWY3DPEHPK3PXP");
        assert!(TotpKey::generate().decrypt("alice", &e).is_err());
        assert!(k.decrypt("bob", &e).is_err());
        for at in [0, 23, 24, 50] {
            assert!(k.decrypt("alice", &flip(&e, at)).is_err());
        }
        assert!(k.decrypt("alice", "enc:v1:AAAA").is_err());
        // legacy plaintext
        assert_eq!(*k.decrypt("alice", "JBSWY3DPEHPK3PXP").unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn labeled_roundtrip_is_bound_to_label_and_key() {
        let k = TotpKey::generate();
        let e = k.encrypt_labeled("oidc/client_secret", "s3cret").unwrap();
        assert_eq!(&*k.decrypt_labeled("oidc/client_secret", &e).unwrap(), "s3cret");
        assert!(k.decrypt_labeled("other", &e).is_err());
        assert!(TotpKey::generate().decrypt_labeled("oidc/client_secret", &e).is_err());
        // never readable as a TOTP seed of a user named like the label
        assert!(k.decrypt("oidc/client_secret", &e).is_err());
        assert!(k.decrypt_labeled("x", "plain").is_err());
    }

    #[test]
    fn key_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/totp.key");
        let (k1, created) = load_or_create_key(&p).unwrap();
        assert!(created);
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(p.parent().unwrap()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let (k2, created) = load_or_create_key(&p).unwrap();
        assert!(!created && *k1 == *k2);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_key(&p).unwrap_err().to_string().contains("0600"));

        let (sk, _) = SchedulerKey::load_or_create(&d.path().join("secrets.key")).unwrap();
        let pubf = d.path().join("cat/secrets.pub");
        sk.write_public(&pubf, None).unwrap();
        assert_eq!(fs::metadata(&pubf).unwrap().permissions().mode() & 0o777, 0o640);
        let pk = SealKey::load(&pubf).unwrap();
        assert_eq!(*sk.open("x", &pk.seal("x", "y").unwrap()).unwrap(), "y");
        let (again, created) = SchedulerKey::load_or_create(&d.path().join("secrets.key")).unwrap();
        assert!(!created);
        assert_eq!(*again.open("x", &pk.seal("x", "y").unwrap()).unwrap(), "y");
    }
}
