//! Signed self-update (signature/version checks: `agent_core::update`).
//!
//! `signature` is what `cosign sign-blob --key <release key>` prints: base64 of an
//! ASN.1/DER ECDSA P-256 signature over SHA-256 of the binary. It is verified against
//! the pinned keys in `/etc/nexus-agent/release-keys/*.pub` (PEM SPKI, as written by
//! `cosign generate-key-pair`; lab builds pin `release/testkey/TEST-cosign.pub`).
//!
//! The version the appliance claims is not covered by the signature, so the agent
//! reads the version embedded in the signed binary itself ([`VERSION_MARKER`]) and
//! refuses anything that is not strictly newer (no downgrade / replay of an older
//! signed build). The binary is written next to the running one, fsynced and renamed
//! over it atomically (the previous binary is kept as `<exe>.prev`); the service then
//! exits with [`RESTART_EXIT_CODE`] and systemd restarts it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Embedded in every build; found in update candidates to learn their real version.
#[used]
pub static VERSION_MARKER: &[u8] = concat!("\0NEXUS-AGENT-VERSION=", env!("CARGO_PKG_VERSION"), "\0").as_bytes();
pub const RESTART_EXIT_CODE: i32 = 75;

pub use agent_core::update::{embedded_version, load_keys, parse_public_key, parse_version, verify, MARKER_PREFIX};

fn is_native_elf(b: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    const MACHINE: u16 = 62;
    #[cfg(target_arch = "aarch64")]
    const MACHINE: u16 = 183;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const MACHINE: u16 = 0;
    b.len() > 64 && b[..4] == *b"\x7fELF" && b[4] == 2 && u16::from_le_bytes([b[18], b[19]]) == MACHINE
}

/// Check everything; on success atomically replace `exe` ([`swap`] with `probe`). Returns a summary.
pub fn apply(
    claimed: &str,
    binary: &[u8],
    signature: &[u8],
    keys: &[(String, Vec<u8>)],
    current: &str,
    exe: &Path,
    probe: &dyn Fn(&Path, &str) -> Result<(), String>,
) -> Result<String, String> {
    let (key, embedded) =
        agent_core::update::check_candidate(claimed, binary, signature, keys, current, is_native_elf)?;
    swap(exe, binary, &|p| probe(p, &embedded))?;
    Ok(format!("updated {current} -> {embedded} (signed by {key})"))
}

// ------------------------------------------------------------- Phase 27 (protocol v1.8)

/// `arch=` capability of this build.
pub fn arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

/// ELF executable for this architecture (`binary` updates).
pub fn native(b: &[u8]) -> bool {
    is_native_elf(b)
}

/// Writes `binary` next to `exe`, checks it with `probe` (`agent_core::update::probe`: it starts and answers
/// `version`, #120), and renames it over `exe` atomically; the previous binary stays as `<exe>.prev` (start
/// watchdog, manual rollback).
pub fn swap(exe: &Path, binary: &[u8], probe: &dyn Fn(&Path) -> Result<(), String>) -> Result<(), String> {
    let dir = exe.parent().ok_or("executable has no directory")?;
    let name = exe
        .file_name()
        .ok_or("executable has no name")?
        .to_string_lossy()
        .into_owned();
    let tmp = dir.join(format!(".{name}.update"));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    let res = f
        .write_all(binary)
        .and_then(|_| f.set_permissions(fs::Permissions::from_mode(0o755)))
        .and_then(|_| f.sync_all());
    // closed before it runs (a file open for writing cannot be executed: ETXTBSY)
    drop(f);
    if let Err(e) = res.as_ref().map_err(ToString::to_string).and_then(|_| probe(&tmp)) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("installing update: {e}"));
    }
    let res = Ok(())
        .and_then(|_| {
            let prev = dir.join(format!("{name}.prev"));
            let _ = fs::remove_file(&prev);
            let _ = fs::hard_link(exe, &prev);
            fs::rename(&tmp, exe)
        })
        .and_then(|_| fs::File::open(dir)?.sync_all());
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("installing update: {e}"));
    }
    Ok(())
}

/// Start watchdog: put `<exe>.prev` back over `exe` (the previous binary stays
/// available as `.prev` of the failed one is not kept: it did not start).
pub fn restore_prev(exe: &Path) -> Result<(), String> {
    let name = exe.file_name().ok_or("executable has no name")?.to_string_lossy();
    let prev = exe.with_file_name(format!("{name}.prev"));
    if !prev.is_file() {
        return Err(format!("{} not found", prev.display()));
    }
    fs::rename(&prev, exe).map_err(|e| format!("{} -> {}: {e}", prev.display(), exe.display()))?;
    if let Some(d) = exe.parent() {
        let _ = fs::File::open(d).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Name of the transient unit that installs a package update.
pub const UPDATE_UNIT: &str = "nexus-agent-update.service";

/// Which programs exist on this host (absolute paths), for [`package_command`].
pub struct Tools {
    pub systemd_run: Option<PathBuf>,
    pub apt_get: Option<PathBuf>,
    pub dnf: Option<PathBuf>,
    pub rpm: Option<PathBuf>,
}

impl Tools {
    pub fn probe() -> Tools {
        let find = |n: &str| crate::volumes::tool(n);
        Tools {
            systemd_run: find("systemd-run"),
            apt_get: find("apt-get"),
            dnf: find("dnf").or_else(|| find("dnf5")),
            rpm: find("rpm"),
        }
    }
}

/// The command line that installs staged packages of `kind` (`deb` / `rpm`) in a
/// transient systemd unit, so the upgrade survives the agent's own restart by the
/// package's maintainer script. No shell and no appliance-supplied arguments: the
/// program is fixed, the only variable parts are the absolute paths of the verified
/// files below `staging` (desktop package first, in the same transaction).
pub fn package_command(
    kind: &str,
    files: &[PathBuf],
    staging: &Path,
    rollback: bool,
    tools: &Tools,
) -> Result<Vec<String>, String> {
    if files.is_empty() {
        return Err("nothing to install".into());
    }
    let mut paths = Vec::new();
    for f in files {
        let s = f.to_str().ok_or("staged file name is not UTF-8")?;
        if !f.is_absolute() || f.parent() != Some(staging) || s.contains(['\n', '\0']) {
            return Err(format!("{s}: not a staged update file"));
        }
        let ext = if kind == "deb" { ".deb" } else { ".rpm" };
        if !s.ends_with(ext) {
            return Err(format!("{s}: not a {kind} package"));
        }
        paths.push(s.to_owned());
    }
    let run = tools
        .systemd_run
        .as_ref()
        .ok_or("systemd-run not found (package updates need systemd)")?;
    let mut argv: Vec<String> = vec![
        run.to_string_lossy().into_owned(),
        format!("--unit={UPDATE_UNIT}"),
        "--description=NexusBackup agent update".into(),
        "--property=TimeoutStartSec=30min".into(),
        "--setenv=DEBIAN_FRONTEND=noninteractive".into(),
        "--setenv=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "--".into(),
    ];
    match kind {
        "deb" => {
            let apt = tools.apt_get.as_ref().ok_or("apt-get not found")?;
            argv.push(apt.to_string_lossy().into_owned());
            argv.extend(["install", "-y", "-o", "Dpkg::Options::=--force-confold"].map(String::from));
            if rollback {
                argv.push("--allow-downgrades".into());
            }
        }
        "rpm" => match (&tools.dnf, &tools.rpm) {
            (Some(dnf), _) => {
                argv.push(dnf.to_string_lossy().into_owned());
                argv.push(if rollback { "downgrade" } else { "install" }.into());
                argv.extend(["-y", "--disablerepo=*"].map(String::from));
            }
            (None, Some(rpm)) => {
                argv.push(rpm.to_string_lossy().into_owned());
                argv.push("-U".into());
                if rollback {
                    argv.push("--oldpackage".into());
                }
            }
            (None, None) => return Err("neither dnf nor rpm found".into()),
        },
        _ => return Err(format!("{kind} is not a Linux package kind")),
    }
    argv.extend(paths);
    Ok(argv)
}

/// State of the transient unit from `systemctl show --property=LoadState,ActiveState,Result,ExecMainStatus`.
pub fn parse_unit_show(text: &str) -> agent_core::update::InstallResult {
    use agent_core::update::InstallResult;
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .unwrap_or("")
            .trim()
    };
    match (get("LoadState"), get("ActiveState"), get("Result")) {
        ("not-found", _, _) | ("", "", _) => InstallResult::Unknown,
        (_, "active" | "activating" | "deactivating" | "reloading", _) => InstallResult::Running,
        (_, "failed", r) | (_, "inactive", r) if r != "success" && !r.is_empty() => InstallResult::Failed(
            format!(
                "package install failed ({r}, exit status {})",
                if get("ExecMainStatus").is_empty() {
                    "?"
                } else {
                    get("ExecMainStatus")
                }
            ),
            vec![],
        ),
        (_, "inactive", "success") => InstallResult::Succeeded,
        _ => InstallResult::Unknown,
    }
}

/// `dpkg-query` / `rpm -q` version of the desktop package (`0.1.0-1` → `0.1.0`).
pub fn desktop_version(install: &str) -> Option<String> {
    let (tool, args): (&str, &[&str]) = match install {
        "deb" => ("dpkg-query", &["-W", "-f=${Version}", "nexus-agent-desktop"]),
        "rpm" => ("rpm", &["-q", "--qf", "%{VERSION}", "nexus-agent-desktop"]),
        _ => return None,
    };
    let out = crate::volumes::run_tool(tool, args).ok()?;
    let v = out.trim().split(['-', '~', '+']).next()?.to_owned();
    agent_proto::release::parse_version(&v).map(|_| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    const TEST_PUB: &str = include_str!("../../../release/testkey/TEST-cosign.pub");
    const BLOB: &[u8] = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin");
    const BLOB_SIG: &[u8] = include_bytes!("../../agent-core/tests/fixtures/cosign-blob.bin.sig");

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
    fn apply_checks_signature_version_and_replaces_atomically() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("nexus-agent");
        fs::write(&exe, b"old").unwrap();
        let (kp, point) = keypair();
        let keys = vec![("k.pub".to_string(), point)];
        let new = fake_binary("0.2.0");
        let sig = sign(&kp, &new);
        let unreached = |_: &Path, _: &str| -> Result<(), String> { panic!("refused before the probe") };
        // unsigned / wrong signature
        assert!(apply("0.2.0", &new, &sign(&kp, b"x"), &keys, "0.1.0", &exe, &unreached).is_err());
        // claimed version differs from the embedded one
        assert!(apply("0.3.0", &new, &sig, &keys, "0.1.0", &exe, &unreached)
            .unwrap_err()
            .contains("claimed"));
        // downgrade and reinstall
        assert!(apply("0.2.0", &new, &sig, &keys, "0.2.0", &exe, &unreached)
            .unwrap_err()
            .contains("downgrade"));
        assert!(apply("0.2.0", &new, &sig, &keys, "0.10.0", &exe, &unreached)
            .unwrap_err()
            .contains("downgrade"));
        // not an ELF
        let mut notelf = new.clone();
        notelf[0] = b'#';
        assert!(apply("0.2.0", &notelf, &sign(&kp, &notelf), &keys, "0.1.0", &exe, &unreached).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        // the probe sees the staged file and the embedded version
        let probed = |p: &Path, v: &str| {
            assert_eq!((fs::read(p).unwrap(), v), (new.clone(), "0.2.0"));
            Ok(())
        };
        let msg = apply("0.2.0", &new, &sig, &keys, "0.1.0", &exe, &probed).unwrap();
        assert!(msg.contains("0.2.0"), "{msg}");
        assert_eq!(fs::read(&exe).unwrap(), new);
        assert_eq!(fs::read(t.path().join("nexus-agent.prev")).unwrap(), b"old");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 2, "no temp files left");
    }

    #[test]
    fn package_commands_are_fixed_argv_without_a_shell() {
        let staging = Path::new("/var/lib/nexus-agent/update");
        let tools = Tools {
            systemd_run: Some("/usr/bin/systemd-run".into()),
            apt_get: Some("/usr/bin/apt-get".into()),
            dnf: Some("/usr/bin/dnf".into()),
            rpm: Some("/usr/bin/rpm".into()),
        };
        let deb = vec![
            staging.join("nexus-agent-desktop_0.2.0-1_amd64.deb"),
            staging.join("nexus-agent_0.2.0_amd64.deb"),
        ];
        let a = package_command("deb", &deb, staging, false, &tools).unwrap();
        assert_eq!(a[0], "/usr/bin/systemd-run");
        assert!(a.contains(&format!("--unit={UPDATE_UNIT}")));
        let tail: Vec<&str> = a
            .iter()
            .skip_while(|x| *x != "--")
            .skip(1)
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "/usr/bin/apt-get",
                "install",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confold",
                "/var/lib/nexus-agent/update/nexus-agent-desktop_0.2.0-1_amd64.deb",
                "/var/lib/nexus-agent/update/nexus-agent_0.2.0_amd64.deb"
            ]
        );
        assert!(!a.iter().any(|x| x.contains("sh -c") || x == "/bin/sh"));
        let a = package_command("deb", &deb[1..], staging, true, &tools).unwrap();
        assert!(a.contains(&"--allow-downgrades".to_string()));
        let rpm = vec![staging.join("nexus-agent-0.2.0-1.x86_64.rpm")];
        let a = package_command("rpm", &rpm, staging, false, &tools).unwrap();
        let tail: Vec<&str> = a
            .iter()
            .skip_while(|x| *x != "--")
            .skip(1)
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            [
                "/usr/bin/dnf",
                "install",
                "-y",
                "--disablerepo=*",
                "/var/lib/nexus-agent/update/nexus-agent-0.2.0-1.x86_64.rpm"
            ]
        );
        let a = package_command("rpm", &rpm, staging, true, &tools).unwrap();
        assert!(a.contains(&"downgrade".to_string()));
        let no_dnf = Tools { dnf: None, ..tools };
        let a = package_command("rpm", &rpm, staging, true, &no_dnf).unwrap();
        assert!(a.ends_with(&[
            "/usr/bin/rpm".to_string(),
            "-U".into(),
            "--oldpackage".into(),
            "/var/lib/nexus-agent/update/nexus-agent-0.2.0-1.x86_64.rpm".into()
        ]));
        // only staged package files
        for bad in [
            vec![PathBuf::from("/tmp/nexus-agent_0.2.0_amd64.deb")],
            vec![PathBuf::from("nexus-agent_0.2.0_amd64.deb")],
            vec![staging.join("evil.sh")],
            vec![staging.join("x/../../y.deb")],
            vec![],
        ] {
            assert!(
                package_command("deb", &bad, staging, false, &no_dnf).is_err(),
                "{bad:?}"
            );
        }
        assert!(package_command("msi", &deb, staging, false, &no_dnf).is_err());
        let none = Tools {
            systemd_run: None,
            apt_get: None,
            dnf: None,
            rpm: None,
        };
        assert!(package_command("deb", &deb, staging, false, &none)
            .unwrap_err()
            .contains("systemd-run"));
    }

    #[test]
    fn transient_unit_states() {
        use agent_core::update::InstallResult;
        let show = |l: &str, a: &str, r: &str, c: &str| {
            format!("LoadState={l}\nActiveState={a}\nResult={r}\nExecMainStatus={c}\n")
        };
        assert_eq!(
            parse_unit_show(&show("loaded", "active", "success", "0")),
            InstallResult::Running
        );
        assert_eq!(
            parse_unit_show(&show("loaded", "inactive", "success", "0")),
            InstallResult::Succeeded
        );
        match parse_unit_show(&show("loaded", "failed", "exit-code", "100")) {
            InstallResult::Failed(e, _) => assert!(e.contains("exit-code") && e.contains("100"), "{e}"),
            r => panic!("{r:?}"),
        }
        assert_eq!(
            parse_unit_show(&show("not-found", "inactive", "success", "0")),
            InstallResult::Unknown
        );
        assert_eq!(parse_unit_show(""), InstallResult::Unknown);
    }

    #[test]
    fn swap_keeps_prev_and_watchdog_restores_it() {
        let t = tempfile::tempdir().unwrap();
        let exe = t.path().join("nexus-agent");
        fs::write(&exe, b"old").unwrap();
        assert!(restore_prev(&exe).is_err(), "nothing to restore yet");
        // #120: the new binary must start and answer `version`; one that does not is refused before the swap
        let broken = b"#!/bin/sh\nexit 1\n";
        let probe = |v: &'static str| move |p: &Path| agent_core::update::probe(p, v);
        let e = swap(&exe, broken, &probe("0.2.0")).unwrap_err();
        assert!(e.contains("does not start"), "{e}");
        let wrong = b"#!/bin/sh\necho nexus-agent 0.1.9\n";
        assert!(swap(&exe, wrong, &probe("0.2.0")).unwrap_err().contains("0.1.9"));
        assert_eq!(fs::read(&exe).unwrap(), b"old", "the running binary stays");
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1, "no temp files left");
        let new = b"#!/bin/sh\necho nexus-agent 0.2.0\n";
        swap(&exe, new, &probe("0.2.0")).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), new);
        assert_eq!(fs::read(t.path().join("nexus-agent.prev")).unwrap(), b"old");
        restore_prev(&exe).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"old");
        assert!(!t.path().join("nexus-agent.prev").exists());
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1, "no temp files left");
        assert!(native(&fake_binary("0.2.0")) == cfg!(target_arch = "x86_64"));
        assert!(["x86_64", "aarch64"].contains(&arch()));
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
        assert_eq!(embedded_version(VERSION_MARKER).unwrap(), env!("CARGO_PKG_VERSION"));
        // a real build (this test binary) carries exactly one parsable marker
        let me = fs::read(std::env::current_exe().unwrap()).unwrap();
        assert_eq!(embedded_version(&me).unwrap(), env!("CARGO_PKG_VERSION"));
        let mut two = fake_binary("1.0.0");
        two.extend(fake_binary("2.0.0"));
        assert!(embedded_version(&two).is_err());
    }
}
