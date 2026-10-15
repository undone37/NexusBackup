//! Agent releases (Phase 27, docs/agent-update-plan.md "Implementation"): the signed
//! release manifest, the host facts an agent reports in `HelloReply.caps`, and which
//! artifacts of a release fit a host. Shared by the agents (they check what they
//! receive against the manifest) and the appliance (it picks what to send).

use serde::{Deserialize, Serialize};

// Artifact kinds an agent can install in-band.
/// Agent executable alone (bundle and manual installs replace the binary).
pub const KIND_BINARY: &str = "binary";
/// Agent Debian package.
pub const KIND_DEB: &str = "deb";
/// Agent RPM package.
pub const KIND_RPM: &str = "rpm";
/// Agent Windows installer (MSI, with the desktop UI).
pub const KIND_MSI: &str = "msi";
/// `nexus-agent-desktop` Debian package (desktop UI), sent before the agent package.
pub const KIND_DESKTOP_DEB: &str = "desktop-deb";
/// `nexus-agent-desktop` RPM package (desktop UI), sent before the agent package.
pub const KIND_DESKTOP_RPM: &str = "desktop-rpm";
// Download-only kinds (installer downloads on the appliance).
/// Linux install bundle (download only).
pub const KIND_BUNDLE: &str = "bundle";
/// Windows setup executable (download only).
pub const KIND_EXE: &str = "exe";
/// Every artifact kind a manifest may list.
pub const KINDS: &[&str] = &[
    KIND_BINARY,
    KIND_DEB,
    KIND_RPM,
    KIND_MSI,
    KIND_DESKTOP_DEB,
    KIND_DESKTOP_RPM,
    KIND_BUNDLE,
    KIND_EXE,
];

/// How an agent was installed (`install=` capability).
pub const INSTALLS: &[&str] = &["bundle", "deb", "rpm", "msi", "manual"];
/// Architectures of artifacts and of the `arch=` capability.
pub const ARCHES: &[&str] = &["x86_64", "aarch64"];
/// Operating systems of artifacts.
pub const OSES: &[&str] = &["linux", "windows"];

/// `manifest.json` of a release (signed as a whole: `manifest.json.sig`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// manifest format, always 1
    pub format: u32,
    /// release version, `X.Y.Z`
    pub version: String,
    /// highest agent protocol of this release, e.g. "1.8"
    #[serde(default)]
    pub protocol: String,
    /// oldest appliance version that can drive this release ("" = any)
    #[serde(default)]
    pub min_appliance: String,
    /// RFC 3339 build time
    #[serde(default)]
    pub released: String,
    /// release notes, plain text (at most 4096 bytes; absent: "")
    #[serde(default)]
    pub notes: String,
    /// the files of the release (at most 64, names unique)
    pub artifacts: Vec<Artifact>,
}

/// One file of a release, as listed in [`Manifest::artifacts`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// relative path below the release directory (`linux-x86_64/nexus-agent`)
    pub name: String,
    /// one of [`KINDS`]
    pub kind: String,
    /// one of [`OSES`]
    pub os: String,
    /// one of [`ARCHES`]
    pub arch: String,
    /// version of the program inside (the desktop UI has its own)
    pub version: String,
    /// file size in bytes (1..=[`crate::MAX_UPDATE`])
    pub size: u64,
    /// SHA-256 of the file, lowercase hex
    pub sha256: String,
}

impl Manifest {
    /// Parses and checks the structure (names, kinds, versions, hashes).
    pub fn parse(bytes: &[u8]) -> Result<Manifest, String> {
        let m: Manifest = serde_json::from_slice(bytes).map_err(|e| format!("manifest.json: {e}"))?;
        m.check()?;
        Ok(m)
    }

    /// Checks the structure of an already decoded manifest (see [`Manifest::parse`]).
    pub fn check(&self) -> Result<(), String> {
        if self.format != 1 {
            return Err(format!("manifest format {} is not supported", self.format));
        }
        if parse_version(&self.version).is_none() {
            return Err(format!("manifest version {:?} is not X.Y.Z", self.version));
        }
        if self.notes.len() > 4096 || self.artifacts.len() > 64 {
            return Err("manifest exceeds limits".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for a in &self.artifacts {
            if !valid_name(&a.name) {
                return Err(format!("artifact name {:?} is not a plain relative path", a.name));
            }
            if !names.insert(a.name.as_str()) {
                return Err(format!("artifact {} listed twice", a.name));
            }
            if !KINDS.contains(&a.kind.as_str()) || !OSES.contains(&a.os.as_str()) || !ARCHES.contains(&a.arch.as_str())
            {
                return Err(format!("artifact {}: unknown kind, OS or architecture", a.name));
            }
            if parse_version(&a.version).is_none() {
                return Err(format!("artifact {}: version {:?} is not X.Y.Z", a.name, a.version));
            }
            if a.sha256.len() != 64 || !a.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(format!("artifact {}: sha256 is not 64 lowercase hex digits", a.name));
            }
            if a.size == 0 || a.size > crate::MAX_UPDATE {
                return Err(format!("artifact {}: size out of range", a.name));
            }
        }
        Ok(())
    }

    /// The artifact listed under `name`.
    pub fn artifact(&self, name: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.name == name)
    }

    /// What to send to a host to update it with its own install type (in order; the
    /// last one is committed with `apply`). Empty: nothing in this release fits.
    pub fn select(&self, host: &HostFacts) -> Vec<&Artifact> {
        let want: &[&str] = match (host.os.as_str(), host.install.as_str()) {
            (_, "bundle" | "manual") => &[KIND_BINARY],
            ("linux", "deb") => &[KIND_DESKTOP_DEB, KIND_DEB],
            ("linux", "rpm") => &[KIND_DESKTOP_RPM, KIND_RPM],
            ("windows", "msi") => &[KIND_MSI],
            _ => &[],
        };
        let mut out: Vec<&Artifact> = Vec::new();
        for k in want {
            let is_gui = k.starts_with("desktop-");
            if is_gui && host.gui_version.is_none() {
                continue;
            }
            if let Some(a) = self
                .artifacts
                .iter()
                .find(|a| a.kind == *k && a.os == host.os && a.arch == host.arch)
            {
                out.push(a);
            }
        }
        // the agent itself must be part of it (a desktop package alone is no update)
        if !out.iter().any(|a| !a.kind.starts_with("desktop-")) {
            return Vec::new();
        }
        out
    }
}

/// Relative path of plain components (`[A-Za-z0-9._+-]`, no `.`/`..`, at most 200 bytes).
pub fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= crate::MAX_ARTIFACT_NAME
        && n.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
        })
}

/// `X.Y.Z` with numeric parts.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().split('.').map(|p| p.parse::<u64>().ok());
    let r = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(r)
}

/// Host facts of an agent (v1.8 capabilities `os` is `HelloReply.os` reduced to
/// `linux` / `windows`).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize)]
pub struct HostFacts {
    /// `linux` or `windows`
    pub os: String,
    /// one of [`ARCHES`] (`arch=`; default `x86_64`)
    pub arch: String,
    /// one of [`INSTALLS`] (`install=`)
    pub install: String,
    /// version of the installed desktop UI package (`gui=`); `None`: not installed
    pub gui_version: Option<String>,
}

impl HostFacts {
    /// `arch=` / `install=` / `gui=` capabilities. Agents before v1.8 report none:
    /// Linux agents were bundles on x86_64, Windows agents manual installs on x64.
    pub fn from_caps(os_text: &str, caps: &[String]) -> HostFacts {
        let os = if os_text.to_ascii_lowercase().contains("windows") {
            "windows"
        } else {
            "linux"
        };
        let get = |k: &str| {
            caps.iter()
                .find_map(|c| c.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .map(str::to_owned)
        };
        let legacy = !caps.iter().any(|c| c == crate::CAP_UPDATE2);
        HostFacts {
            os: os.into(),
            arch: get("arch")
                .filter(|a| ARCHES.contains(&a.as_str()))
                .unwrap_or_else(|| "x86_64".into()),
            install: get("install")
                .filter(|i| INSTALLS.contains(&i.as_str()))
                .unwrap_or_else(|| {
                    if legacy && os == "windows" {
                        "manual".into()
                    } else if legacy {
                        "bundle".into()
                    } else {
                        "manual".into()
                    }
                }),
            gui_version: get("gui").filter(|v| parse_version(v).is_some()),
        }
    }

    /// The `arch=` / `install=` / `gui=` capabilities an agent announces.
    pub fn to_caps(&self) -> Vec<String> {
        let mut c = vec![format!("arch={}", self.arch), format!("install={}", self.install)];
        if let Some(g) = &self.gui_version {
            c.push(format!("gui={g}"));
        }
        c
    }
}

/// Protocol label of an agent for the UI: "1.8" with chunked updates, else "1.7"
/// (or older: all earlier versions share the update path).
pub fn protocol_of(caps: &[String]) -> &'static str {
    if caps.iter().any(|c| c == crate::CAP_UPDATE2) {
        "1.8"
    } else {
        "1.7"
    }
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn art(name: &str, kind: &str, os: &str, arch: &str) -> Artifact {
        Artifact {
            name: name.into(),
            kind: kind.into(),
            os: os.into(),
            arch: arch.into(),
            version: "0.2.0".into(),
            size: 10,
            sha256: "ab".repeat(32),
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            format: 1,
            version: "0.2.0".into(),
            protocol: "1.8".into(),
            min_appliance: String::new(),
            released: String::new(),
            notes: String::new(),
            artifacts: vec![
                art("linux-x86_64/nexus-agent", KIND_BINARY, "linux", "x86_64"),
                art("linux-aarch64/nexus-agent", KIND_BINARY, "linux", "aarch64"),
                art("linux-x86_64/nexus-agent_0.2.0_amd64.deb", KIND_DEB, "linux", "x86_64"),
                art(
                    "linux-x86_64/nexus-agent-desktop_0.2.0-1_amd64.deb",
                    KIND_DESKTOP_DEB,
                    "linux",
                    "x86_64",
                ),
                art(
                    "linux-aarch64/nexus-agent-0.2.0-1.aarch64.rpm",
                    KIND_RPM,
                    "linux",
                    "aarch64",
                ),
                art("windows-x64/nexus-agent-0.2.0-x64.msi", KIND_MSI, "windows", "x86_64"),
                art("windows-x64/nexus-agent.exe", KIND_BINARY, "windows", "x86_64"),
                art(
                    "linux-x86_64/nexus-agent-0.2.0-x86_64.tar.gz",
                    KIND_BUNDLE,
                    "linux",
                    "x86_64",
                ),
            ],
        }
    }

    fn host(os: &str, arch: &str, install: &str, gui: Option<&str>) -> HostFacts {
        HostFacts {
            os: os.into(),
            arch: arch.into(),
            install: install.into(),
            gui_version: gui.map(str::to_owned),
        }
    }

    fn names(v: Vec<&Artifact>) -> Vec<String> {
        v.into_iter().map(|a| a.name.clone()).collect()
    }

    #[test]
    fn artifact_selection_per_os_arch_and_install() {
        let m = manifest();
        m.check().unwrap();
        assert_eq!(
            names(m.select(&host("linux", "x86_64", "bundle", None))),
            ["linux-x86_64/nexus-agent"]
        );
        assert_eq!(
            names(m.select(&host("linux", "aarch64", "bundle", None))),
            ["linux-aarch64/nexus-agent"]
        );
        // deb: never the bare binary; the desktop package rides along only when installed
        assert_eq!(
            names(m.select(&host("linux", "x86_64", "deb", None))),
            ["linux-x86_64/nexus-agent_0.2.0_amd64.deb"]
        );
        assert_eq!(
            names(m.select(&host("linux", "x86_64", "deb", Some("0.1.0")))),
            [
                "linux-x86_64/nexus-agent-desktop_0.2.0-1_amd64.deb",
                "linux-x86_64/nexus-agent_0.2.0_amd64.deb"
            ]
        );
        assert_eq!(
            names(m.select(&host("linux", "aarch64", "rpm", Some("0.1.0")))),
            ["linux-aarch64/nexus-agent-0.2.0-1.aarch64.rpm"]
        );
        // no x86_64 rpm in this release: nothing (not the binary)
        assert!(m.select(&host("linux", "x86_64", "rpm", None)).is_empty());
        assert_eq!(
            names(m.select(&host("windows", "x86_64", "msi", Some("0.1.0")))),
            ["windows-x64/nexus-agent-0.2.0-x64.msi"]
        );
        assert_eq!(
            names(m.select(&host("windows", "x86_64", "manual", None))),
            ["windows-x64/nexus-agent.exe"]
        );
        assert!(m.select(&host("windows", "x86_64", "deb", None)).is_empty());
    }

    #[test]
    fn manifest_checks() {
        let mut m = manifest();
        m.artifacts[0].name = "../etc/passwd".into();
        assert!(m.check().is_err());
        let mut m = manifest();
        m.artifacts[1].name = m.artifacts[0].name.clone();
        assert!(m.check().unwrap_err().contains("twice"));
        let mut m = manifest();
        m.artifacts[0].sha256 = "AB".repeat(32);
        assert!(m.check().is_err());
        let mut m = manifest();
        m.version = "0.2".into();
        assert!(m.check().is_err());
        let mut m = manifest();
        m.artifacts[0].kind = "script".into();
        assert!(m.check().is_err());
        let json = serde_json::to_vec(&manifest()).unwrap();
        assert_eq!(Manifest::parse(&json).unwrap(), manifest());
        assert!(Manifest::parse(br#"{"format":1,"version":"1.0.0","artifacts":[],"extra":1}"#).is_err());
        assert!(valid_name("a/b-1.2_3+x.deb"));
        assert!(!valid_name("a//b"));
        assert!(!valid_name("/abs"));
        assert!(!valid_name("a/./b"));
        assert!(!valid_name("a b"));
    }

    #[test]
    fn host_facts_from_caps() {
        let caps: Vec<String> = ["lz4", "update2", "arch=aarch64", "install=rpm", "gui=0.1.0"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        let h = HostFacts::from_caps("AlmaLinux 10", &caps);
        assert_eq!(h, host("linux", "aarch64", "rpm", Some("0.1.0")));
        assert_eq!(HostFacts::from_caps("AlmaLinux 10", &h.to_caps()).install, "rpm");
        // a v1.7 agent: bundle on x86_64 / manual Windows install
        let old: Vec<String> = vec!["lz4".into(), "update".into()];
        assert_eq!(
            HostFacts::from_caps("Debian GNU/Linux 13", &old),
            host("linux", "x86_64", "bundle", None)
        );
        assert_eq!(
            HostFacts::from_caps("Windows Server 2022 Standard", &old),
            host("windows", "x86_64", "manual", None)
        );
        let bad: Vec<String> = vec![
            "update2".into(),
            "arch=sparc".into(),
            "install=zip".into(),
            "gui=x".into(),
        ];
        assert_eq!(
            HostFacts::from_caps("Linux", &bad),
            host("linux", "x86_64", "manual", None)
        );
        assert_eq!(protocol_of(&caps), "1.8");
        assert_eq!(protocol_of(&old), "1.7");
    }
}
