//! The appliance's agent release store (Phase 27, docs/agent-update-plan.md "Release
//! store"): `/usr/share/nexus/agent/<version>/` from the image and
//! `/var/lib/nexus/agent-releases/<version>/` for signed uploads. Each version holds
//! `manifest.json` + `manifest.json.sig` and the artifacts with their `.sig`. Used by
//! the web-api (list, upload, downloads), the scheduler (recommended version,
//! automatic rollouts) and `nexus-agentctl update` (what to send).

use crate::update::verify;
use agent_proto::release::{parse_version, Artifact, Manifest};
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const IMAGE_DIR: &str = "/usr/share/nexus/agent";
pub const UPLOAD_DIR: &str = "/var/lib/nexus/agent-releases";
/// Keys the appliance pins for its own image updates; agent releases are signed with
/// the same offline release key.
pub const KEYS_DIR: &str = "/etc/pki/nexus/cosign";

/// One release directory as found.
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub dir: PathBuf,
    /// `image` or `upload`
    pub source: &'static str,
    pub manifest: Option<Manifest>,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sig: Vec<u8>,
    /// name of the pinned key that signed the manifest
    pub key: Option<String>,
    /// why it cannot be used (unsigned, foreign key, files missing, ...)
    pub error: Option<String>,
}

impl Release {
    /// Signed by a pinned key and complete: may be offered and sent.
    pub fn usable(&self) -> bool {
        self.error.is_none() && self.key.is_some() && self.manifest.is_some()
    }

    pub fn path_of(&self, a: &Artifact) -> PathBuf {
        self.dir.join(&a.name)
    }

    pub fn signature_of(&self, a: &Artifact) -> std::io::Result<Vec<u8>> {
        fs::read(self.dir.join(format!("{}.sig", a.name)))
    }

    /// What the API shows (`GET /agent-releases`).
    pub fn to_json(&self) -> Value {
        let m = self.manifest.as_ref();
        json!({
            "version": self.version,
            "source": self.source,
            "signed": self.key.is_some(),
            "key": self.key,
            "error": self.error,
            "protocol": m.map(|m| m.protocol.clone()),
            "min_appliance": m.map(|m| m.min_appliance.clone()),
            "released": m.map(|m| m.released.clone()),
            "notes": m.map(|m| m.notes.clone()),
            "artifacts": m.map(|m| m.artifacts.clone()).unwrap_or_default(),
        })
    }
}

/// Reads one release directory: manifest signature by a pinned key, manifest
/// structure, version = directory name, every artifact and signature present with
/// the listed size. `full` also checks every artifact's SHA-256 and own signature
/// (uploads; the image's tree is read-only and was checked at build time).
pub fn load(dir: &Path, source: &'static str, keys: &[(String, Vec<u8>)], full: bool) -> Release {
    let version = dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut r = Release {
        version,
        dir: dir.to_owned(),
        source,
        manifest: None,
        manifest_bytes: Vec::new(),
        manifest_sig: Vec::new(),
        key: None,
        error: None,
    };
    if let Err(e) = load_into(&mut r, keys, full) {
        r.error = Some(e);
    }
    r
}

fn load_into(r: &mut Release, keys: &[(String, Vec<u8>)], full: bool) -> Result<(), String> {
    r.manifest_bytes = read_limited(&r.dir.join("manifest.json"), agent_proto::MAX_MANIFEST as u64)?;
    r.manifest_sig = read_limited(&r.dir.join("manifest.json.sig"), agent_proto::MAX_SIGNATURE as u64)
        .map_err(|_| "manifest.json.sig missing: the release is not signed".to_string())?;
    let m = Manifest::parse(&r.manifest_bytes)?;
    let version_ok = m.version == r.version;
    r.manifest = Some(m.clone());
    if !version_ok {
        return Err(format!(
            "the manifest names version {}, the directory {}",
            m.version, r.version
        ));
    }
    r.key = Some(verify(&r.manifest_bytes, &r.manifest_sig, keys).map_err(|e| format!("manifest: {e}"))?);
    for a in &m.artifacts {
        let p = r.dir.join(&a.name);
        let meta = fs::symlink_metadata(&p).map_err(|_| format!("{} missing", a.name))?;
        if !meta.is_file() || meta.len() != a.size {
            return Err(format!("{}: not a regular file of {} bytes", a.name, a.size));
        }
        let sig = r.dir.join(format!("{}.sig", a.name));
        let sig =
            read_limited(&sig, agent_proto::MAX_SIGNATURE as u64).map_err(|_| format!("{}.sig missing", a.name))?;
        if full {
            let data = fs::read(&p).map_err(|e| format!("{}: {e}", a.name))?;
            use sha2::Digest;
            if agent_proto::release::hex(&sha2::Sha256::digest(&data)) != a.sha256 {
                return Err(format!("{}: SHA-256 differs from the manifest", a.name));
            }
            verify(&data, &sig, keys).map_err(|e| format!("{}: {e}", a.name))?;
        }
    }
    Ok(())
}

fn read_limited(p: &Path, max: u64) -> Result<Vec<u8>, String> {
    let f = fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    if b.len() as u64 > max {
        return Err(format!("{} is too large", p.display()));
    }
    Ok(b)
}

/// All releases below `dirs` (`(path, source)`), newest first; a version present in
/// several directories is listed once (the image wins).
pub fn scan(dirs: &[(PathBuf, &'static str)], keys: &[(String, Vec<u8>)]) -> Vec<Release> {
    let mut out: Vec<Release> = Vec::new();
    for (d, source) in dirs {
        let Ok(rd) = fs::read_dir(d) else { continue };
        let mut names: Vec<PathBuf> = rd
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).and_then(parse_version).is_some())
            .collect();
        names.sort();
        for p in names {
            let r = load(&p, source, keys, false);
            if !out.iter().any(|x| x.version == r.version) {
                out.push(r);
            }
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(parse_version(&a.version)));
    out
}

/// The newest usable release: what "outdated" is measured against and what
/// automatic rollouts install.
pub fn recommended(releases: &[Release]) -> Option<&Release> {
    releases.iter().find(|r| r.usable())
}

pub fn find<'a>(releases: &'a [Release], version: &str) -> Option<&'a Release> {
    releases.iter().find(|r| r.version == version)
}

/// `a < b` for X.Y.Z versions (unparsable counts as oldest).
pub fn older(a: &str, b: &str) -> bool {
    parse_version(a) < parse_version(b)
}

/// Signed test releases for the tests of this and other crates (agent-conn, web-api,
/// scheduler): a throw-away P-256 key, cosign-style base64 DER signatures.
#[doc(hidden)]
pub mod testing {
    use super::*;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use sha2::Digest;

    pub struct Signer {
        pub kp: EcdsaKeyPair,
        pub point: Vec<u8>,
    }

    impl Signer {
        pub fn new() -> Signer {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            let point = kp.public_key().as_ref().to_vec();
            Signer { kp, point }
        }

        pub fn sign(&self, data: &[u8]) -> Vec<u8> {
            let sig = self.kp.sign(&SystemRandom::new(), data).unwrap();
            base64::engine::general_purpose::STANDARD
                .encode(sig.as_ref())
                .into_bytes()
        }

        /// PEM `PUBLIC KEY` as `cosign generate-key-pair` writes it.
        pub fn public_pem(&self) -> String {
            let mut der = vec![
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            der.extend(&self.point);
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                base64::engine::general_purpose::STANDARD.encode(der)
            )
        }

        pub fn keys(&self) -> Vec<(String, Vec<u8>)> {
            vec![("release.pub".to_string(), self.point.clone())]
        }

        /// `<root>/<version>/` with `manifest.json(.sig)` and the files
        /// `(name, kind, os, arch, data)`, each with its `.sig`.
        pub fn write_release(&self, root: &Path, version: &str, files: &[(&str, &str, &str, &str, &[u8])]) -> PathBuf {
            let dir = root.join(version);
            let mut arts = Vec::new();
            for (name, kind, os, arch, data) in files {
                let p = dir.join(name);
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(&p, data).unwrap();
                fs::write(dir.join(format!("{name}.sig")), self.sign(data)).unwrap();
                arts.push(Artifact {
                    name: name.to_string(),
                    kind: kind.to_string(),
                    os: os.to_string(),
                    arch: arch.to_string(),
                    version: version.into(),
                    size: data.len() as u64,
                    sha256: agent_proto::release::hex(&sha2::Sha256::digest(data)),
                });
            }
            let m = Manifest {
                format: 1,
                version: version.into(),
                protocol: "1.8".into(),
                min_appliance: String::new(),
                released: "2026-10-14T00:00:00Z".into(),
                notes: format!("release {version}"),
                artifacts: arts,
            };
            let j = serde_json::to_vec_pretty(&m).unwrap();
            fs::write(dir.join("manifest.json"), &j).unwrap();
            fs::write(dir.join("manifest.json.sig"), self.sign(&j)).unwrap();
            dir
        }
    }

    impl Default for Signer {
        fn default() -> Self {
            Signer::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Signer;
    use super::*;

    #[test]
    fn store_lists_verified_releases_newest_first() {
        let t = tempfile::tempdir().unwrap();
        let (img, up) = (t.path().join("img"), t.path().join("up"));
        let s = Signer::new();
        let keys = s.keys();
        let bin = |d: &'static [u8]| [("linux-x86_64/nexus-agent", "binary", "linux", "x86_64", d)];
        s.write_release(&img, "0.1.0", &bin(b"one"));
        s.write_release(&up, "0.10.0", &bin(b"ten"));
        Signer::new().write_release(&up, "0.11.0", &bin(b"x"));
        let d = s.write_release(&up, "0.12.0", &bin(b"y"));
        fs::write(d.join("linux-x86_64/nexus-agent"), b"yy").unwrap();
        fs::create_dir_all(up.join("not-a-version")).unwrap();
        let dirs = vec![(img.clone(), "image"), (up.clone(), "upload")];
        let rs = scan(&dirs, &keys);
        let v: Vec<(&str, bool)> = rs.iter().map(|r| (r.version.as_str(), r.usable())).collect();
        assert_eq!(
            v,
            [("0.12.0", false), ("0.11.0", false), ("0.10.0", true), ("0.1.0", true)]
        );
        assert!(rs[0].error.as_deref().unwrap().contains("bytes"));
        assert!(rs[1].error.as_deref().unwrap().contains("manifest"));
        assert_eq!(recommended(&rs).unwrap().version, "0.10.0");
        assert_eq!(find(&rs, "0.1.0").unwrap().source, "image");
        let j = rs[2].to_json();
        assert_eq!(j["signed"], true);
        assert_eq!(j["artifacts"][0]["kind"], "binary");
        // full check catches a tampered artifact with the right size
        let d = s.write_release(&up, "0.13.0", &bin(b"abc"));
        assert!(load(&d, "upload", &keys, true).usable());
        fs::write(d.join("linux-x86_64/nexus-agent"), b"abd").unwrap();
        assert!(
            load(&d, "upload", &keys, false).usable(),
            "quick scan checks sizes only"
        );
        assert!(load(&d, "upload", &keys, true).error.unwrap().contains("SHA-256"));
        // a manifest whose version differs from the directory
        let d = s.write_release(&up, "0.14.0", &bin(b"a"));
        fs::rename(&d, up.join("0.15.0")).unwrap();
        assert!(load(&up.join("0.15.0"), "upload", &keys, false)
            .error
            .unwrap()
            .contains("directory"));
        assert!(older("0.9.0", "0.10.0") && !older("1.0.0", "0.10.0"));
        // the PEM parses like a cosign key
        assert_eq!(crate::update::parse_public_key(&s.public_pem()).unwrap(), s.point);
    }
}
