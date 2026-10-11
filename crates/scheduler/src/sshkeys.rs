//! The appliance's own SSH key pairs under `/etc/nexus/ssh` (docs/phase12-contract.md
//! §4, security review L-10): generated here (ed25519, OpenSSH format), public
//! halves published to the catalog (setting `ssh_keys`) for `GET /ssh-keys`.
//!
//! Rotation keeps the old key in use: `rotate` writes `<name>.next` (+ `.pub`);
//! the admin adds its public key to the sources, then `retire` renames it over
//! `<name>` (the path the source configs name), which deletes the old key.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Catalog setting with the published public halves.
pub const SETTING: &str = "ssh_keys";

/// What uses a key file: Proxmox VE node access.
pub const PURPOSE_PVE: &str = "Proxmox VE nodes (forced command)";
/// What uses a key file: an SFTP offsite target.
pub const PURPOSE_OFFSITE: &str = "Storage Box offsite (SFTP)";

fn ssh_string(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

/// New ed25519 key: (OpenSSH private key PEM, `ssh-ed25519 <b64> <comment>` line).
pub fn generate(comment: &str) -> (zeroize::Zeroizing<String>, String) {
    let seed = zeroize::Zeroizing::new(rand::random::<[u8; 32]>());
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pk = sk.verifying_key().to_bytes();
    let mut blob = Vec::new();
    ssh_string(&mut blob, b"ssh-ed25519");
    ssh_string(&mut blob, &pk);
    // private section (unencrypted): check ints, key, comment, padding 1, 2, 3 …
    let check: [u8; 4] = rand::random();
    let mut private = zeroize::Zeroizing::new(Vec::new());
    private.extend_from_slice(&check);
    private.extend_from_slice(&check);
    ssh_string(&mut private, b"ssh-ed25519");
    ssh_string(&mut private, &pk);
    let mut both = zeroize::Zeroizing::new([0u8; 64]);
    both[..32].copy_from_slice(&*seed);
    both[32..].copy_from_slice(&pk);
    ssh_string(&mut private, &*both);
    ssh_string(&mut private, comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    let mut body = zeroize::Zeroizing::new(b"openssh-key-v1\0".to_vec());
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"none");
    ssh_string(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    ssh_string(&mut body, &blob);
    ssh_string(&mut body, &private);
    let b64 = zeroize::Zeroizing::new(STANDARD.encode(&*body));
    let mut pem = zeroize::Zeroizing::new(String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    for chunk in b64.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    (pem, format!("ssh-ed25519 {} {comment}", STANDARD.encode(&blob)))
}

/// `SHA256:<base64>` of the key blob of a public key line.
pub fn fingerprint(line: &str) -> Option<String> {
    let blob = STANDARD.decode(line.split_whitespace().nth(1)?).ok()?;
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))))
}

/// The public key line of an OpenSSH private key file (the public blob is
/// stored unencrypted, for any key type).
pub fn public_from_private(pem: &str, comment: &str) -> Option<String> {
    fn take<'a>(rest: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (a, b) = rest.split_at_checked(n)?;
        *rest = b;
        Some(a)
    }
    fn string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
        let n = u32::from_be_bytes(take(rest, 4)?.try_into().ok()?) as usize;
        take(rest, n)
    }
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let body = STANDARD.decode(b64.trim()).ok()?;
    let mut rest = body.strip_prefix(b"openssh-key-v1\0".as_slice())?;
    // cipher, kdf, kdf options, key count, first public key blob
    for _ in 0..3 {
        string(&mut rest)?;
    }
    if take(&mut rest, 4)? != 1u32.to_be_bytes() {
        return None;
    }
    let blob = string(&mut rest)?;
    let kty = std::str::from_utf8(string(&mut &blob[..])?).ok()?;
    if kty.is_empty() || !kty.bytes().all(|b| b.is_ascii_alphanumeric() || b"@.-".contains(&b)) {
        return None;
    }
    Some(format!("{kty} {} {comment}", STANDARD.encode(blob)))
}

/// Writes a file atomically (tmp + rename) with `mode`.
fn write(dir: &Path, name: &str, data: &[u8], mode: u32) -> Result<()> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .with_context(|| format!("{}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(name)).with_context(|| format!("{}/{name}", dir.display()))?;
    Ok(())
}

fn new_pair(dir: &Path, base: &str, comment: &str) -> Result<String> {
    let (pem, line) = generate(comment);
    write(dir, base, pem.as_bytes(), 0o600)?;
    write(dir, &format!("{base}.pub"), format!("{line}\n").as_bytes(), 0o644)?;
    Ok(line)
}

fn comment(name: &str) -> String {
    format!("nexusbackup-{name}@{}", crate::alerts::hostname())
}

/// (Re)writes a `.pub` that is missing or does not match its private key
/// (hand-placed keys, an interrupted retire) for the keys in use.
pub fn ensure(dir: &Path, names: &[String]) -> Result<()> {
    for name in names {
        for base in [name.to_string(), format!("{name}.next")] {
            let Ok(pem) = fs::read_to_string(dir.join(&base)) else {
                continue;
            };
            let Some(line) = public_from_private(&pem, &comment(name)) else {
                continue;
            };
            let current = fs::read_to_string(dir.join(format!("{base}.pub"))).unwrap_or_default();
            if fingerprint(&current) != fingerprint(&line) {
                write(dir, &format!("{base}.pub"), format!("{line}\n").as_bytes(), 0o644)?;
            }
        }
    }
    Ok(())
}

/// A key file name directly in the key dir (not a public half, a rotated key
/// or known_hosts) that exists.
fn known(dir: &Path, name: &str) -> Result<()> {
    let plain = (1..=64).contains(&name.len())
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !name.ends_with(".pub")
        && !name.ends_with(".next")
        && name != "known_hosts";
    if !plain || !dir.join(name).is_file() {
        bail!("unknown appliance key {name:?}");
    }
    Ok(())
}

/// New key `<name>.next`; the current one stays in use. Returns its fingerprint.
pub fn rotate(dir: &Path, name: &str) -> Result<String> {
    known(dir, name)?;
    if dir.join(format!("{name}.next")).exists() {
        bail!("{name}: a rotated key is waiting already (retire the old one first)");
    }
    let line = new_pair(dir, &format!("{name}.next"), &comment(name))?;
    fingerprint(&line).context("fingerprint")
}

/// The rotated key replaces the current one (same path): (old, new) fingerprints.
pub fn retire(dir: &Path, name: &str) -> Result<(Option<String>, String)> {
    known(dir, name)?;
    let next = dir.join(format!("{name}.next"));
    if !next.exists() {
        bail!("{name}: nothing to retire (no rotated key)");
    }
    let fp = |p: &Path| fs::read_to_string(p).ok().as_deref().and_then(fingerprint);
    let old = fp(&dir.join(format!("{name}.pub")));
    let new = fp(&dir.join(format!("{name}.next.pub"))).context("rotated key has no public half")?;
    // private first: an interrupted retire is repaired by `ensure` (public from private)
    fs::rename(&next, dir.join(name))?;
    fs::rename(dir.join(format!("{name}.next.pub")), dir.join(format!("{name}.pub")))?;
    fs::File::open(dir)?.sync_all()?;
    Ok((old, new))
}

fn entry(dir: &Path, base: &str) -> Option<Value> {
    let p = dir.join(format!("{base}.pub"));
    let line = fs::read_to_string(&p).ok()?;
    let line = line.trim();
    Some(json!({
        "public_key": line,
        "fingerprint": fingerprint(line)?,
        "created": fs::metadata(&p).ok()?.mtime(),
    }))
}

/// What `GET /ssh-keys` shows: the keys the configuration uses (`used`: file
/// name below the key dir, purpose) that exist, one entry each. After a rotation
/// the entry shows the new key (the one to install on the sources) and the old one
/// as `previous` (still in use until retired).
pub fn list(dir: &Path, used: &[(String, String)]) -> Value {
    let keys: Vec<Value> = used
        .iter()
        .filter_map(|(name, purpose)| {
            let current = entry(dir, name)?;
            let (mut e, previous) = match entry(dir, &format!("{name}.next")) {
                Some(next) => (next, current),
                None => (current, Value::Null),
            };
            e["name"] = json!(name);
            e["purpose"] = json!(purpose);
            e["previous"] = previous;
            Some(e)
        })
        .collect();
    json!(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_parse_and_rotate() {
        let (pem, line) = generate("t@x");
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert_eq!(public_from_private(&pem, "t@x").as_deref(), Some(line.as_str()));
        assert!(fingerprint(&line).unwrap().starts_with("SHA256:"));
        assert_eq!(fingerprint(&line).unwrap().len(), 7 + 43);

        let d = tempfile::tempdir().unwrap();
        let used = vec![
            ("pve".to_owned(), PURPOSE_PVE.to_owned()),
            ("box".to_owned(), PURPOSE_OFFSITE.to_owned()),
        ];
        let names: Vec<String> = used.iter().map(|u| u.0.clone()).collect();
        // a hand-placed private key without .pub gets its public half; missing ones are not listed
        let (pem, line) = generate("hand@placed");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(d.path().join("pve"))
            .unwrap()
            .write_all(pem.as_bytes())
            .unwrap();
        ensure(d.path(), &names).unwrap();
        let before = list(d.path(), &used);
        assert_eq!(before.as_array().unwrap().len(), 1, "box does not exist");
        assert_eq!(before[0]["name"], "pve");
        assert_eq!(before[0]["purpose"], PURPOSE_PVE);
        assert_eq!(before[0]["fingerprint"].as_str(), fingerprint(&line).as_deref());
        assert!(before[0]["previous"].is_null());
        let fp = rotate(d.path(), "pve").unwrap();
        assert!(rotate(d.path(), "pve").is_err(), "one rotation at a time");
        let mode = fs::metadata(d.path().join("pve.next")).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mid = list(d.path(), &used);
        assert_eq!(
            mid[0]["previous"]["fingerprint"], before[0]["fingerprint"],
            "old key still in use"
        );
        assert_eq!(mid[0]["fingerprint"], fp);
        let (old, new) = retire(d.path(), "pve").unwrap();
        assert_eq!(
            (old, new.clone()),
            (before[0]["fingerprint"].as_str().map(str::to_owned), fp)
        );
        let after = list(d.path(), &used);
        assert_eq!(after[0]["fingerprint"], new);
        assert!(after[0]["previous"].is_null());
        assert!(retire(d.path(), "pve").is_err());
        for bad in ["../etc", "box", "pve.pub", "known_hosts", ".x"] {
            assert!(rotate(d.path(), bad).is_err(), "{bad}");
        }
    }

    /// ssh-keygen accepts the private key and derives the same public key.
    #[test]
    fn ssh_keygen_reads_generated_key() {
        let Ok(out) = std::process::Command::new("ssh-keygen").arg("-?").output() else {
            eprintln!("SKIP: no ssh-keygen");
            return;
        };
        let _ = out;
        let d = tempfile::tempdir().unwrap();
        let (pem, line) = generate("t@x");
        let p = d.path().join("k");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&p)
            .unwrap()
            .write_all(pem.as_bytes())
            .unwrap();
        let o = std::process::Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&p)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let derived = String::from_utf8(o.stdout).unwrap();
        assert_eq!(fingerprint(&derived), fingerprint(&line));
    }
}
