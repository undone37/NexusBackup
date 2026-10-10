//! `nexus-plugin` — packaging tool for plugin bundles (docs/plugin-sdk.md "Packaging").
//!
//! ```text
//! nexus-plugin pack <manifest.json> <binary> <out.nxplugin> [<assets-dir>]
//! nexus-plugin keygen <name>                   # <name>.key (PKCS#8, keep secret) + <name>.pub
//! nexus-plugin sign <bundle> <key.pem> [<out.sig>]   # default <bundle>.sig
//! nexus-plugin verify <bundle> <bundle.sig> <key.pub | keys-dir>...
//! nexus-plugin inspect <bundle>
//! ```
//! Signatures are what `cosign sign-blob` / `release/sign.sh sign-blob` print (base64
//! DER ECDSA P-256 over SHA-256 of the bundle), so project bundles are signed with
//! the release tooling and third-party publishers can use this tool or cosign.

use plugin_proto::bundle::{self, TrustedKey};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;

fn die(m: impl std::fmt::Display) -> ExitCode {
    eprintln!("nexus-plugin: {m}");
    ExitCode::from(1)
}

fn assets(dir: &Path, base: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        let p = e.path();
        let t = e.file_type().map_err(|e| e.to_string())?;
        if t.is_dir() {
            assets(&p, base, out)?;
        } else if t.is_file() {
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            out.insert(rel, fs::read(&p).map_err(|e| e.to_string())?);
        } else {
            return Err(format!("{}: only regular files are allowed in assets", p.display()));
        }
    }
    Ok(())
}

fn keys_from(args: &[String]) -> Result<Vec<TrustedKey>, String> {
    let mut keys = Vec::new();
    for a in args {
        let p = Path::new(a);
        if p.is_dir() {
            keys.extend(bundle::load_project_keys(p));
        } else {
            let pem = fs::read_to_string(p).map_err(|e| format!("{a}: {e}"))?;
            keys.push(TrustedKey {
                name: a.clone(),
                publisher: String::new(),
                point: bundle::parse_public_key(&pem).map_err(|e| format!("{a}: {e}"))?,
                builtin: false,
            });
        }
    }
    Ok(keys)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["pack", manifest, bin, out, rest @ ..] if rest.len() <= 1 => {
            let m = match fs::read(manifest) {
                Ok(m) => m,
                Err(e) => return die(format!("{manifest}: {e}")),
            };
            let b = match fs::read(bin) {
                Ok(b) => b,
                Err(e) => return die(format!("{bin}: {e}")),
            };
            let mut ass = BTreeMap::new();
            if let Some(d) = rest.first() {
                if let Err(e) = assets(Path::new(d), Path::new(d), &mut ass) {
                    return die(e);
                }
            }
            match bundle::pack(&m, &b, &ass) {
                Ok(bytes) => {
                    if let Err(e) = fs::write(out, &bytes) {
                        return die(format!("{out}: {e}"));
                    }
                    println!("{out}: {} bytes, sha256 {}", bytes.len(), bundle::sha256_hex(&bytes));
                }
                Err(e) => return die(e),
            }
        }
        ["keygen", name] => {
            let (sk, pk) = match bundle::generate_key() {
                Ok(k) => k,
                Err(e) => return die(e),
            };
            let key = format!("{name}.key");
            let w = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key)
                .and_then(|mut f| std::io::Write::write_all(&mut f, sk.as_bytes()));
            if let Err(e) = w.and_then(|_| fs::write(format!("{name}.pub"), &pk)) {
                return die(e);
            }
            println!(
                "{name}.key (secret) and {name}.pub written; fingerprint sha256:{}",
                bundle::fingerprint(&bundle::parse_public_key(&pk).unwrap())
            );
        }
        ["sign", b, key, rest @ ..] if rest.len() <= 1 => {
            let (bytes, pem) = match (fs::read(b), fs::read_to_string(key)) {
                (Ok(x), Ok(y)) => (x, y),
                (Err(e), _) | (_, Err(e)) => return die(e),
            };
            if let Err(e) = bundle::read(&bytes) {
                return die(e);
            }
            let sig = match bundle::sign(&bytes, &pem) {
                Ok(s) => s,
                Err(e) => return die(e),
            };
            let out = rest.first().map_or_else(|| format!("{b}.sig"), |s| s.to_string());
            if let Err(e) = fs::write(&out, format!("{sig}\n")) {
                return die(e);
            }
            println!("signature written to {out}");
        }
        ["verify", b, sig, keys @ ..] if !keys.is_empty() => {
            let (bytes, s) = match (fs::read(b), fs::read(sig)) {
                (Ok(x), Ok(y)) => (x, y),
                (Err(e), _) | (_, Err(e)) => return die(e),
            };
            let keys = match keys_from(&keys.iter().map(|s| s.to_string()).collect::<Vec<_>>()) {
                Ok(k) => k,
                Err(e) => return die(e),
            };
            let bun = match bundle::read(&bytes) {
                Ok(x) => x,
                Err(e) => return die(e),
            };
            match bundle::verify(&bytes, &s, &keys) {
                Ok(k) => println!(
                    "OK: {} {} by {} signed with {} (sha256:{})",
                    bun.manifest.id,
                    bun.manifest.version,
                    bun.manifest.publisher,
                    k.name,
                    k.fingerprint()
                ),
                Err(e) => return die(e),
            }
        }
        ["inspect", b] => {
            let bytes = match fs::read(b) {
                Ok(x) => x,
                Err(e) => return die(e),
            };
            match bundle::read(&bytes) {
                Ok(bun) => {
                    let m = &bun.manifest;
                    println!(
                        "id        {}\nname      {}\nversion   {}\npublisher {}\napi       {}",
                        m.id, m.name, m.version, m.publisher, m.api
                    );
                    println!(
                        "sha256    {}\nbinary    {} bytes, sha256 {}",
                        bundle::sha256_hex(&bytes),
                        bun.bin.len(),
                        bun.bin_sha256()
                    );
                    for k in &m.kinds {
                        let r: Vec<&str> = k.restores.iter().map(|r| r.id.as_str()).collect();
                        println!("kind      plugin:{} ({}) restores: {}", k.kind, k.title, r.join(", "));
                    }
                    if let Some(s) = &m.sandbox {
                        println!("sandbox   {s}");
                    }
                    for a in bun.assets.keys() {
                        println!("asset     {a}");
                    }
                }
                Err(e) => return die(e),
            }
        }
        _ => {
            eprintln!("usage:\n  nexus-plugin pack <manifest.json> <binary> <out.nxplugin> [<assets-dir>]\n  nexus-plugin keygen <name>\n  nexus-plugin sign <bundle> <key.pem> [<out.sig>]\n  nexus-plugin verify <bundle> <sig> <key.pub|keys-dir>...\n  nexus-plugin inspect <bundle>");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}
