//! nexus-setup: first-boot wizard (docs/control-plane.md "First boot", plan §12.5, §6.2).
//!
//! All step logic lives here, free of terminal I/O, so the console TUI (`tui`)
//! and the scripted driver (`script`) share it and tests can drive it directly.
//! Progress is derived from facts on disk plus the audit log (actor `setup`),
//! so an interrupted run resumes where it stopped:
//!
//! | Step | done when |
//! |---|---|
//! | network | audit `setup.network` exists (always redoable) |
//! | admin | a user with that role exists (replace needs explicit confirmation) |
//! | second person (security officer) | a security officer exists, or audit `setup.second_person_later` |
//! | recovery key | audit `setup.keyd.confirmed` (keyd is never re-initialised) |
//! | TLS | audit `setup.tls` + cert/key files exist |
//! | metrics token | token file exists + audit `setup.metrics_token` |
//! | finish | `setup-done` exists |
//!
//! The second person is optional (plan §2 "Approval system", user decision
//! 2026-10-10): with two people the appliance starts with approvals enabled;
//! with a single administrator they start disabled (written at `finish`).

use anyhow::{anyhow, bail, Context, Result};
use catalog::secret::TotpKey;
use catalog::{auth, Catalog};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub mod script;
pub mod tui;

pub const ACTOR: &str = "setup";
/// NetworkManager connection profile owned by the appliance.
pub const NM_CONNECTION: &str = "nexus-mgmt";
/// `[0]` is restarted after a network reconfiguration (new TLS SAN). keyd is
/// needed by the scheduler (tenant keys); it requires `keyd init` (done in setup).
/// nexus-replicad serves replication peers through the web-api (docs/replication.md).
pub const SERVICES: [&str; 4] = [
    "nexus-web-api.service",
    "nexus-scheduler.service",
    "nexus-keyd.service",
    "nexus-replicad.service",
];
pub const WEB_PORT: u16 = 8443;

// ---------------------------------------------------------------- paths

#[derive(Clone, Debug)]
pub struct Paths {
    pub catalog: PathBuf,
    pub keyd_dir: PathBuf,
    pub tls_dir: PathBuf,
    pub metrics_token: PathBuf,
    /// web-api-only key for TOTP seeds (0600 nexus-webapi)
    pub totp_key: PathBuf,
    pub setup_done: PathBuf,
    pub lock: PathBuf,
    /// Read-only NIC enumeration; not prefixed by `--root`.
    pub sys_class_net: PathBuf,
}

impl Paths {
    pub fn under(root: &Path) -> Paths {
        let p = |rel: &str| root.join(rel);
        Paths {
            catalog: p("var/lib/nexus/catalog/catalog.db"),
            keyd_dir: p("var/lib/nexus/keyd"),
            tls_dir: p("etc/nexus/tls"),
            metrics_token: p("etc/nexus/metrics-token"),
            totp_key: p("var/lib/nexus/webapi/totp.key"),
            setup_done: p("var/lib/nexus/setup-done"),
            lock: p("var/lib/nexus/.setup.lock"),
            sys_class_net: PathBuf::from("/sys/class/net"),
        }
    }
    pub fn cert(&self) -> PathBuf {
        self.tls_dir.join("cert.pem")
    }
    pub fn key(&self) -> PathBuf {
        self.tls_dir.join("key.pem")
    }
}

// ---------------------------------------------------------------- command runner

/// Runs external commands (`nmcli`, `hostnamectl`, `systemctl`). Injectable so
/// tests and dev machines never touch the host network or units.
pub trait Runner {
    fn run(&mut self, prog: &str, args: &[&str]) -> Result<String>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, prog: &str, args: &[&str]) -> Result<String> {
        let out = Command::new(prog)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("starting {prog}"))?;
        if !out.status.success() {
            bail!(
                "{prog} {} failed ({}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Prints nothing itself: the command line lands in `Setup::log` like every
/// other command, and the driver shows it.
pub struct DryRunRunner;

impl Runner for DryRunRunner {
    fn run(&mut self, _prog: &str, _args: &[&str]) -> Result<String> {
        Ok(String::new())
    }
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./:,=@".contains(&b)) {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

// ---------------------------------------------------------------- ownership

fn lookup_uid(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns NULL or a pointer to static storage; single-threaded use.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    (!pw.is_null()).then(|| unsafe { (*pw).pw_uid })
}

fn lookup_gid(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: as above.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    (!gr.is_null()).then(|| unsafe { (*gr).gr_gid })
}

// ---------------------------------------------------------------- steps

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Network,
    Admin,
    SecurityOfficer,
    RecoveryKey,
    Tls,
    MetricsToken,
    Finish,
}

impl Step {
    pub const ALL: [Step; 7] = [
        Step::Network,
        Step::Admin,
        Step::SecurityOfficer,
        Step::RecoveryKey,
        Step::Tls,
        Step::MetricsToken,
        Step::Finish,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Step::Network => "Management network",
            Step::Admin => "Administrator account + TOTP",
            Step::SecurityOfficer => "Second person: security officer (recommended)",
            Step::RecoveryKey => "Key service + recovery key",
            Step::Tls => "TLS certificate",
            Step::MetricsToken => "Metrics token",
            Step::Finish => "Finish and start services",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    SecurityOfficer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::SecurityOfficer => "security_officer",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Role::Admin => "Administrator",
            Role::SecurityOfficer => "Security officer",
        }
    }
    pub fn step(self) -> Step {
        match self {
            Role::Admin => Step::Admin,
            Role::SecurityOfficer => Step::SecurityOfficer,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    Uninitialized,
    /// keyd initialised, but the recovery key was never confirmed (interrupted run).
    /// It cannot be shown again; the operator must type it in full or re-image.
    Unconfirmed,
    Confirmed,
}

/// Refuses a completed appliance unless the operator explicitly reconfigures the network.
pub fn check_start(paths: &Paths, force_reconfigure_network: bool) -> Result<()> {
    if paths.setup_done.exists() && !force_reconfigure_network {
        bail!(
            "setup already completed ({} exists); use --force-reconfigure-network to change the management network",
            paths.setup_done.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- network

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "lowercase", deny_unknown_fields)]
pub enum Ipv4Config {
    Dhcp,
    Static {
        address: Ipv4Addr,
        prefix: u8,
        #[serde(default)]
        gateway: Option<Ipv4Addr>,
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetConfig {
    pub nic: String,
    #[serde(flatten)]
    pub ipv4: Ipv4Config,
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Nic {
    pub name: String,
    pub mac: String,
    pub up: bool,
}

/// NICs from sysfs: physical ones (with a `device` link) first; if there are
/// none (containers, odd dev boxes) every interface except `lo`.
pub fn list_nics(sys_class_net: &Path) -> Result<Vec<Nic>> {
    let mut all = vec![];
    for e in fs::read_dir(sys_class_net).with_context(|| format!("reading {}", sys_class_net.display()))? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "lo" || name == "bonding_masters" {
            continue;
        }
        let rd = |f: &str| {
            fs::read_to_string(e.path().join(f))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        let physical = e.path().join("device").exists();
        all.push((
            physical,
            Nic {
                up: rd("operstate") == "up",
                mac: rd("address"),
                name,
            },
        ));
    }
    all.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    let physical: Vec<Nic> = all.iter().filter(|(p, _)| *p).map(|(_, n)| n.clone()).collect();
    Ok(if physical.is_empty() {
        all.into_iter().map(|(_, n)| n).collect()
    } else {
        physical
    })
}

pub fn validate_hostname(h: &str) -> Result<()> {
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !ok {
        bail!("invalid hostname {h:?} (letters, digits, '-', dot-separated labels)");
    }
    Ok(())
}

fn in_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    u32::from(a) & mask == u32::from(b) & mask
}

/// Parses the TUI's text fields. `address` may carry the prefix (`192.0.2.10/24`).
pub fn parse_static(address: &str, gateway: &str, dns: &str) -> Result<Ipv4Config> {
    let (addr, prefix) = address
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow!("address needs a prefix length, e.g. 192.0.2.10/24"))?;
    let address: Ipv4Addr = addr
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid IPv4 address {addr:?}"))?;
    let prefix: u8 = prefix
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid prefix length {prefix:?}"))?;
    let gateway = match gateway.trim() {
        "" => None,
        g => Some(g.parse().map_err(|_| anyhow!("invalid gateway {g:?}"))?),
    };
    let dns = dns
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| anyhow!("invalid DNS server {s:?}")))
        .collect::<Result<_>>()?;
    Ok(Ipv4Config::Static {
        address,
        prefix,
        gateway,
        dns,
    })
}

impl NetConfig {
    pub fn validate(&self) -> Result<()> {
        if self.nic.is_empty()
            || self.nic.len() > 15
            || !self
                .nic
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            bail!("invalid interface name {:?}", self.nic);
        }
        if let Some(h) = &self.hostname {
            validate_hostname(h)?;
        }
        if let Ipv4Config::Static {
            address,
            prefix,
            gateway,
            dns,
        } = &self.ipv4
        {
            if !(1..=32).contains(prefix) {
                bail!("prefix length must be 1..32");
            }
            let bad = |a: &Ipv4Addr| a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast();
            if bad(address) {
                bail!("{address} is not a usable host address");
            }
            if let Some(g) = gateway {
                if bad(g) || g == address || !in_subnet(*g, *address, *prefix) {
                    bail!("gateway {g} must be another host in {address}/{prefix}");
                }
            }
            if let Some(d) = dns.iter().find(|d| bad(d)) {
                bail!("{d} is not a usable DNS server");
            }
        }
        Ok(())
    }

    /// `nmcli connection add …` arguments (pure, for tests and display).
    pub fn nmcli_add_args(&self) -> Vec<String> {
        let mut a: Vec<String> = [
            "connection",
            "add",
            "type",
            "ethernet",
            "con-name",
            NM_CONNECTION,
            "ifname",
            &self.nic,
            "connection.autoconnect",
            "yes",
            "connection.autoconnect-priority",
            "100",
            // ponytail: IPv4 management only; IPv6 management once nftables sets carry v6 peers
            "ipv6.method",
            "disabled",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        match &self.ipv4 {
            Ipv4Config::Dhcp => a.extend(["ipv4.method".into(), "auto".into()]),
            Ipv4Config::Static {
                address,
                prefix,
                gateway,
                dns,
            } => {
                a.extend(["ipv4.method".into(), "manual".into()]);
                a.extend(["ipv4.addresses".into(), format!("{address}/{prefix}")]);
                if let Some(g) = gateway {
                    a.extend(["ipv4.gateway".into(), g.to_string()]);
                }
                if !dns.is_empty() {
                    let d: Vec<String> = dns.iter().map(|d| d.to_string()).collect();
                    a.extend([
                        "ipv4.dns".into(),
                        d.join(","),
                        "ipv4.ignore-auto-dns".into(),
                        "yes".into(),
                    ]);
                }
            }
        }
        a
    }
}

/// Parses `nmcli -g IP4.ADDRESS device show` (`a.b.c.d/nn | e.f.g.h/mm`).
pub fn parse_nmcli_addresses(out: &str) -> Vec<IpAddr> {
    out.split(['|', '\n'])
        .filter_map(|s| s.trim().split('/').next()?.parse().ok())
        .collect()
}

// ---------------------------------------------------------------- recovery key

/// The recovery key while it is on screen. Never Debug/Display/Clone, zeroed on drop.
pub struct RecoveryKey(Zeroizing<String>);

pub const KEY_GROUPS: usize = 16;

impl RecoveryKey {
    pub fn from_string(s: String) -> Self {
        RecoveryKey(Zeroizing::new(s))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// 16 groups of 4 hex digits, upper-case for legibility (0/D, 6/b).
    pub fn groups(&self) -> Vec<Zeroizing<String>> {
        self.0
            .split('-')
            .map(|g| Zeroizing::new(g.to_ascii_uppercase()))
            .collect()
    }
    /// `idx` are 0-based group numbers; answers are compared case-insensitively.
    pub fn check_groups(&self, idx: &[usize], answers: &[&str]) -> bool {
        let groups = self.groups();
        idx.len() == answers.len()
            && !idx.is_empty()
            && idx.iter().zip(answers).fold(true, |ok, (&i, a)| {
                let a: String = a.chars().filter(|c| !c.is_whitespace()).collect();
                // no early exit: every group is compared
                ok & groups.get(i).is_some_and(|g| g.eq_ignore_ascii_case(&a))
            })
    }
}

/// Three distinct random group indices (0-based, sorted).
pub fn challenge() -> [usize; 3] {
    let mut v = rand::seq::index::sample(&mut rand::thread_rng(), KEY_GROUPS, 3).into_vec();
    v.sort();
    [v[0], v[1], v[2]]
}

// ---------------------------------------------------------------- TLS

pub struct Cert {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
    pub fingerprint: String,
    pub sans: Vec<String>,
}

/// Uppercase, colon-separated SHA-256 (what browsers show).
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Self-signed ECDSA P-256 certificate, SAN = hostname + management IPs, 10 years.
pub fn generate_cert(hostname: &str, ips: &[IpAddr]) -> Result<Cert> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    let mut params = CertificateParams::new(vec![hostname.to_owned()])?;
    params
        .subject_alt_names
        .extend(ips.iter().map(|ip| SanType::IpAddress(*ip)));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, hostname);
    dn.push(DnType::OrganizationName, "NexusBackup appliance");
    params.distinguished_name = dn;
    let year = 1970 + (catalog::now() / 31_556_952) as i32;
    params.not_before = rcgen::date_time_ymd(year - 1, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + 10, 1, 1);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    let mut sans = vec![hostname.to_owned()];
    sans.extend(ips.iter().map(|i| i.to_string()));
    Ok(Cert {
        fingerprint: fingerprint(cert.der()),
        cert_pem: cert.pem(),
        key_pem: Zeroizing::new(key.serialize_pem()),
        sans,
    })
}

#[derive(Clone, Debug)]
pub struct TlsInfo {
    pub fingerprint: String,
    pub sans: Vec<String>,
}

/// Unicode half-block QR code (two modules per character cell), drawn light on
/// the console's dark background. A 2-module quiet zone (instead of the usual 4)
/// keeps a TOTP URI at 21 rows, so it fits an 80x25 console; phone scanners cope.
pub fn qr_lines(data: &str) -> Result<Vec<String>> {
    const QUIET: usize = 2;
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::L)?;
    let (w, colors) = (code.width(), code.to_colors());
    let n = w + 2 * QUIET;
    // light = drawn; the quiet zone is light, the half row below the last one dark
    let light = |x: usize, y: usize| {
        if y >= n {
            return false;
        }
        let inside = (QUIET..QUIET + w).contains(&x) && (QUIET..QUIET + w).contains(&y);
        !inside || colors[(y - QUIET) * w + (x - QUIET)] == qrcode::Color::Light
    };
    Ok((0..n.div_ceil(2))
        .map(|r| {
            (0..n)
                .map(|x| match (light(x, 2 * r), light(x, 2 * r + 1)) {
                    (true, true) => '\u{2588}',
                    (true, false) => '\u{2580}',
                    (false, true) => '\u{2584}',
                    (false, false) => ' ',
                })
                .collect()
        })
        .collect())
}

pub fn validate_username(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !name.starts_with(['.', '-']);
    if !ok {
        bail!("user name: 1-64 characters a-z 0-9 . _ - (not starting with . or -)");
    }
    Ok(())
}

pub fn check_password_pair(pw: &str, repeat: &str) -> Result<()> {
    if pw != repeat {
        bail!("passwords do not match");
    }
    if pw.chars().count() < 12 {
        bail!("password must have at least 12 characters");
    }
    Ok(())
}

// ---------------------------------------------------------------- the wizard backend

pub struct Setup {
    pub paths: Paths,
    runner: Box<dyn Runner>,
    pub dry_run: bool,
    owner: Owner,
    pub cat: Catalog,
    /// Every external command, shell-quoted, for display (`$ nmcli …`).
    pub log: Vec<String>,
    _lock: File,
}

impl Setup {
    /// Takes the setup lock (one wizard at a time: tty1 unit vs. a manual run) and opens the catalog.
    pub fn open(paths: Paths, runner: Box<dyn Runner>, dry_run: bool, strict_owners: bool) -> Result<Setup> {
        // chown to the service users only as root; missing users are fatal on the real appliance
        let owner = Owner {
            chown: unsafe { libc::geteuid() } == 0,
            strict: strict_owners,
        };
        let nexus = paths.setup_done.parent().unwrap_or(Path::new("/"));
        mkdir(nexus, 0o755)?;
        let lock = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&paths.lock)?;
        // SAFETY: plain flock on an owned fd.
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another nexus-setup is running (lock {})", paths.lock.display());
        }
        Ok(Setup {
            cat: open_catalog(&paths.catalog, &owner)?,
            paths,
            runner,
            dry_run,
            owner,
            log: vec![],
            _lock: lock,
        })
    }

    fn own(&self, path: &Path, user: Option<&str>, group: Option<&str>) -> Result<()> {
        self.owner.own(path, user, group)
    }

    /// Atomic write with the final mode/owner set before the rename.
    fn write_file(&self, path: &Path, data: &[u8], mode: u32, user: Option<&str>, group: Option<&str>) -> Result<()> {
        let dir = path.parent().ok_or_else(|| anyhow!("no parent"))?;
        let tmp = dir.join(format!(".{}.tmp", path.file_name().unwrap().to_string_lossy()));
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        self.own(&tmp, user, group)?;
        fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn cmd(&mut self, prog: &str, args: &[&str]) -> Result<String> {
        let line: Vec<String> = std::iter::once(prog)
            .chain(args.iter().copied())
            .map(shell_quote)
            .collect();
        self.log.push(format!(
            "{}{}",
            if self.dry_run { "(dry-run) " } else { "" },
            line.join(" ")
        ));
        self.runner.run(prog, args)
    }

    fn audit(&self, action: &str, target: &str, details: Value) -> Result<()> {
        self.cat.audit(ACTOR, action, target, &details)?;
        Ok(())
    }

    fn last_audit(&self, action: &str) -> Result<Option<Value>> {
        use catalog::rusqlite::OptionalExtension;
        let d: Option<String> = self
            .cat
            .conn()
            .query_row(
                "SELECT details FROM audit WHERE actor = ?1 AND action = ?2 ORDER BY seq DESC LIMIT 1",
                [ACTOR, action],
                |r| r.get(0),
            )
            .optional()?;
        Ok(d.map(|d| serde_json::from_str(&d)).transpose()?)
    }

    // ---- progress

    pub fn is_done(&self, step: Step) -> Result<bool> {
        Ok(match step {
            Step::Network => self.last_audit("setup.network")?.is_some(),
            Step::Admin => self.user_with_role(Role::Admin)?.is_some(),
            Step::SecurityOfficer => {
                self.user_with_role(Role::SecurityOfficer)?.is_some()
                    || self.last_audit("setup.second_person_later")?.is_some()
            }
            Step::RecoveryKey => self.key_state()? == KeyState::Confirmed,
            Step::Tls => self.tls_info()?.is_some(),
            Step::MetricsToken => {
                self.paths.metrics_token.exists() && self.last_audit("setup.metrics_token")?.is_some()
            }
            Step::Finish => self.paths.setup_done.exists(),
        })
    }

    pub fn next_step(&self) -> Result<Option<Step>> {
        for s in Step::ALL {
            if !self.is_done(s)? {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    // ---- 1. network

    pub fn hostname(&self) -> String {
        fs::read_to_string("/proc/sys/kernel/hostname")
            .map(|h| h.trim().to_owned())
            .ok()
            .filter(|h| validate_hostname(h).is_ok())
            .unwrap_or_else(|| "nexus".into())
    }

    /// Applies the management network through NetworkManager; returns the management IPs.
    pub fn apply_network(&mut self, cfg: &NetConfig) -> Result<Vec<IpAddr>> {
        cfg.validate()?;
        if let Some(h) = &cfg.hostname {
            self.cmd("hostnamectl", &["set-hostname", h])?;
        }
        // absent on first run; anything else surfaces in the `add` below
        let _ = self.cmd("nmcli", &["connection", "delete", NM_CONNECTION]);
        let add = cfg.nmcli_add_args();
        self.cmd("nmcli", &add.iter().map(String::as_str).collect::<Vec<_>>())?;
        self.cmd("nmcli", &["--wait", "30", "connection", "up", NM_CONNECTION])?;
        let ips = match &cfg.ipv4 {
            Ipv4Config::Static { address, .. } => vec![IpAddr::V4(*address)],
            Ipv4Config::Dhcp => {
                parse_nmcli_addresses(&self.cmd("nmcli", &["-g", "IP4.ADDRESS", "device", "show", &cfg.nic])?)
            }
        };
        let hostname = cfg.hostname.clone().unwrap_or_else(|| self.hostname());
        let (method, gateway, dns) = match &cfg.ipv4 {
            Ipv4Config::Dhcp => ("dhcp", None, vec![]),
            Ipv4Config::Static { gateway, dns, .. } => ("static", *gateway, dns.clone()),
        };
        self.audit(
            "setup.network",
            &format!("nic/{}", cfg.nic),
            json!({"nic": cfg.nic, "method": method, "addresses": ips, "gateway": gateway, "dns": dns,
                   "hostname": hostname, "dry_run": self.dry_run}),
        )?;
        Ok(ips)
    }

    /// Hostname and management IPs as recorded by the last network step.
    pub fn management(&self) -> Result<(String, Vec<IpAddr>)> {
        let d = self.last_audit("setup.network")?.unwrap_or(Value::Null);
        let hostname = d["hostname"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| self.hostname());
        let ips = serde_json::from_value(d["addresses"].clone()).unwrap_or_default();
        Ok((hostname, ips))
    }

    // ---- 2./3. accounts

    pub fn user_with_role(&self, role: Role) -> Result<Option<String>> {
        use catalog::rusqlite::OptionalExtension;
        Ok(self
            .cat
            .conn()
            .query_row(
                "SELECT name FROM users WHERE role = ?1 AND disabled = 0 ORDER BY id LIMIT 1",
                [role.as_str()],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Creates the account after the TOTP code proved the authenticator works.
    /// An existing account of that role is only replaced with `replace = true`
    /// (explicit operator confirmation); its row keeps its id.
    pub fn create_user(
        &mut self,
        role: Role,
        name: &str,
        password: &str,
        totp_secret: &str,
        code: &str,
        replace: bool,
    ) -> Result<()> {
        use catalog::rusqlite::OptionalExtension;
        validate_username(name)?;
        if !auth::totp_check(totp_secret, code) {
            bail!("TOTP code is not valid (check the authenticator app and the appliance clock)");
        }
        let hash = Zeroizing::new(auth::hash_password(password)?);
        // stored encrypted with the web-api's key, bound to the account name
        let seed = self.totp_key()?.encrypt(name, totp_secret)?;
        let other: Option<String> = self
            .cat
            .conn()
            .query_row("SELECT role FROM users WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        if other.as_deref().is_some_and(|r| r != role.as_str()) {
            bail!(
                "name {name:?} already belongs to the {} account; the four-eyes principle needs two different accounts",
                other.unwrap()
            );
        }
        let existing: Option<(i64, String)> = self
            .cat
            .conn()
            .query_row(
                "SELECT id, name FROM users WHERE role = ?1 ORDER BY id LIMIT 1",
                [role.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((_, old)) if !replace => {
                bail!(
                    "a {} account ({old}) already exists; replacing it needs explicit confirmation",
                    role.as_str()
                )
            }
            Some((id, old)) => {
                self.cat.conn().execute(
                    "UPDATE users SET name = ?1, password_hash = ?2, totp_secret = ?3, disabled = 0 WHERE id = ?4",
                    catalog::rusqlite::params![name, *hash, seed, id],
                )?;
                self.audit(
                    "setup.user.replace",
                    &format!("user/{name}"),
                    json!({"role": role.as_str(), "previous_name": old}),
                )
            }
            None => {
                self.cat.conn().execute(
                    "INSERT INTO users (name, password_hash, totp_secret, role, tenant, disabled, created)
                     VALUES (?1, ?2, ?3, ?4, NULL, 0, ?5)",
                    catalog::rusqlite::params![name, *hash, seed, role.as_str(), catalog::now()],
                )?;
                self.audit(
                    "setup.user.create",
                    &format!("user/{name}"),
                    json!({"role": role.as_str()}),
                )
            }
        }
    }

    /// The operator chose to add the second person later (in the web UI):
    /// approvals then start disabled.
    pub fn second_person_later(&mut self) -> Result<()> {
        self.audit(
            "setup.second_person_later",
            "appliance",
            json!({"approvals": "disabled"}),
        )
    }

    /// Whether approvals will start enabled: at least two people (enabled
    /// admins / security officers) could approve requests.
    pub fn approvals_start_enabled(&self) -> Result<bool> {
        Ok(catalog::possible_approvers(&self.cat.conn())?.len() >= 2)
    }

    /// The web-api's TOTP key, created if missing (0600, owner nexus-webapi,
    /// parent dir 0700). Only setup (root) and the web-api can read it.
    fn totp_key(&self) -> Result<TotpKey> {
        let p = &self.paths.totp_key;
        let (k, created) = TotpKey::open_or_create(p, &self.cat)?;
        if created {
            if let Some(dir) = p.parent() {
                self.own(dir, Some("nexus-webapi"), Some("nexus-webapi"))?;
            }
            self.own(p, Some("nexus-webapi"), Some("nexus-webapi"))?;
            self.audit("setup.totp_key", "webapi/totp.key", json!({"created": true}))?;
        }
        Ok(k)
    }

    // ---- 4. keyd + recovery key

    pub fn key_state(&self) -> Result<KeyState> {
        Ok(if !self.paths.keyd_dir.join("kek.recovery").exists() {
            KeyState::Uninitialized
        } else if self.last_audit("setup.keyd.confirmed")?.is_some() {
            KeyState::Confirmed
        } else {
            KeyState::Unconfirmed
        })
    }

    /// `keyd init`. Refuses if keyd was already initialised (never re-init).
    /// The returned key is never written anywhere by this crate.
    pub fn keyd_init(&mut self) -> Result<RecoveryKey> {
        if self.key_state()? != KeyState::Uninitialized {
            bail!("keyd is already initialised; it is never re-initialised by setup");
        }
        let dir = self.paths.keyd_dir.clone();
        mkdir(&dir, 0o700)?;
        let rk = RecoveryKey::from_string(keyd::init(&dir)?);
        for p in [
            dir.join("tenants"),
            dir.join("kek.recovery"),
            dir.join("kek.local"),
            dir.clone(),
        ] {
            let mode = if p.is_dir() { 0o700 } else { 0o600 };
            fs::set_permissions(&p, fs::Permissions::from_mode(mode))?;
            self.own(&p, Some("nexus-keyd"), Some("nexus-keyd"))?;
        }
        self.audit("setup.keyd.init", "keyd", json!({"dir": dir}))?;
        Ok(rk)
    }

    /// Re-entry of the challenged groups. On success the key is also checked
    /// against the KEK on disk and the confirmation is recorded.
    pub fn confirm_recovery_groups(&mut self, key: &RecoveryKey, idx: &[usize], answers: &[&str]) -> Result<bool> {
        let groups: Vec<usize> = idx.iter().map(|i| i + 1).collect();
        if !key.check_groups(idx, answers) {
            self.audit("setup.keyd.challenge_failed", "keyd", json!({"groups": groups}))?;
            return Ok(false);
        }
        keyd::check_recovery_key(&self.paths.keyd_dir, key.expose())?;
        self.audit(
            "setup.keyd.confirmed",
            "keyd",
            json!({"method": "groups", "groups": groups}),
        )?;
        Ok(true)
    }

    /// Resume after an interrupted run: the key cannot be shown again, so the
    /// operator proves possession by typing it in full.
    pub fn confirm_recovery_full(&mut self, entered: &str) -> Result<()> {
        let entered = Zeroizing::new(entered.to_owned());
        if let Err(e) = keyd::check_recovery_key(&self.paths.keyd_dir, &entered) {
            self.audit("setup.keyd.challenge_failed", "keyd", json!({"method": "full"}))?;
            bail!("recovery key rejected: {e}");
        }
        self.audit("setup.keyd.confirmed", "keyd", json!({"method": "full"}))
    }

    // ---- 5. TLS

    pub fn tls_info(&self) -> Result<Option<TlsInfo>> {
        if !(self.paths.cert().exists() && self.paths.key().exists()) {
            return Ok(None);
        }
        Ok(self.last_audit("setup.tls")?.map(|d| TlsInfo {
            fingerprint: d["fingerprint_sha256"].as_str().unwrap_or_default().to_owned(),
            sans: serde_json::from_value(d["san"].clone()).unwrap_or_default(),
        }))
    }

    /// Generates cert + key unless already done (or `regenerate`, after a network change).
    pub fn tls(&mut self, regenerate: bool) -> Result<TlsInfo> {
        if !regenerate {
            if let Some(i) = self.tls_info()? {
                return Ok(i);
            }
        }
        let (hostname, ips) = self.management()?;
        let c = generate_cert(&hostname, &ips)?;
        mkdir(&self.paths.tls_dir, 0o755)?;
        // web-api reads the key as its own user; nobody else can
        self.write_file(
            &self.paths.key(),
            c.key_pem.as_bytes(),
            0o600,
            Some("nexus-webapi"),
            Some("nexus-webapi"),
        )?;
        self.write_file(&self.paths.cert(), c.cert_pem.as_bytes(), 0o644, None, None)?;
        self.audit(
            "setup.tls",
            "tls",
            json!({"fingerprint_sha256": c.fingerprint, "san": c.sans, "regenerated": regenerate}),
        )?;
        Ok(TlsInfo {
            fingerprint: c.fingerprint,
            sans: c.sans,
        })
    }

    // ---- 6. metrics token

    /// Creates `/etc/nexus/metrics-token` (0640, group nexus-webapi); an existing token is kept.
    pub fn metrics_token(&mut self) -> Result<()> {
        let p = self.paths.metrics_token.clone();
        let created = !p.exists();
        if created {
            mkdir(p.parent().unwrap(), 0o755)?;
            let tok = Zeroizing::new(
                rand::random::<[u8; 32]>()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    + "\n",
            );
            self.write_file(&p, tok.as_bytes(), 0o640, None, Some("nexus-webapi"))?;
        }
        self.audit("setup.metrics_token", "metrics-token", json!({"created": created}))
    }

    // ---- 7. finish

    /// Writes `setup-done` and enables the control-plane services.
    pub fn finish(&mut self) -> Result<()> {
        for s in &Step::ALL[..Step::ALL.len() - 1] {
            if !self.is_done(*s)? {
                bail!("cannot finish: step {:?} is not complete", s.title());
            }
        }
        let approvals = self.approvals_start_enabled()?;
        catalog::set_setting(
            &self.cat.conn(),
            "approvals_enabled",
            if approvals { "true" } else { "false" },
        )?;
        self.audit(
            "setup.approvals",
            "settings/approvals_enabled",
            json!({"enabled": approvals}),
        )?;
        self.audit("setup.done", "appliance", json!({"dry_run": self.dry_run}))?;
        self.write_file(
            &self.paths.setup_done,
            format!("completed {}\n", catalog::now()).as_bytes(),
            0o644,
            None,
            None,
        )?;
        let mut args = vec!["enable", "--now"];
        args.extend(SERVICES);
        self.cmd("systemctl", &args)
            .context("setup is complete, but starting the services failed; run: systemctl enable --now nexus-web-api nexus-scheduler nexus-keyd nexus-replicad")?;
        Ok(())
    }

    /// `--force-reconfigure-network` on a finished appliance: new network,
    /// new certificate (the SAN changes), web-api restarted.
    pub fn reconfigure_network(&mut self, cfg: &NetConfig) -> Result<TlsInfo> {
        self.apply_network(cfg)?;
        let tls = self.tls(true)?;
        if self.paths.setup_done.exists() {
            self.cmd("systemctl", &["try-restart", SERVICES[0]])?;
        }
        Ok(tls)
    }
}

struct Owner {
    chown: bool,
    strict: bool,
}

impl Owner {
    fn own(&self, path: &Path, user: Option<&str>, group: Option<&str>) -> Result<()> {
        if !self.chown {
            return Ok(());
        }
        let resolve = |name: Option<&str>, f: fn(&str) -> Option<u32>| -> Result<Option<u32>> {
            match name {
                None => Ok(None),
                Some(n) => match f(n) {
                    Some(id) => Ok(Some(id)),
                    None if self.strict => bail!("unknown user/group {n} (systemd-sysusers not run?)"),
                    None => Ok(None),
                },
            }
        };
        let (uid, gid) = (resolve(user, lookup_uid)?, resolve(group, lookup_gid)?);
        if uid.is_some() || gid.is_some() {
            std::os::unix::fs::chown(path, uid, gid).with_context(|| format!("chown {}", path.display()))?;
        }
        Ok(())
    }
}

fn open_catalog(db: &Path, owner: &Owner) -> Result<Catalog> {
    let dir = db.parent().ok_or_else(|| anyhow!("catalog path has no parent"))?;
    // setgid dir: -wal/-shm (created with the db file's mode by SQLite) keep group nexus-catalog
    mkdir(dir, 0o2770)?;
    owner.own(dir, None, Some("nexus-catalog"))?;
    if !db.exists() {
        OpenOptions::new().create(true).append(true).mode(0o660).open(db)?;
    }
    fs::set_permissions(db, fs::Permissions::from_mode(0o660))?;
    owner.own(db, None, Some("nexus-catalog"))?;
    Catalog::open(db).with_context(|| format!("opening catalog {}", db.display()))
}

fn mkdir(dir: &Path, mode: u32) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(a: &str, p: u8, g: Option<&str>) -> NetConfig {
        NetConfig {
            nic: "eth0".into(),
            ipv4: Ipv4Config::Static {
                address: a.parse().unwrap(),
                prefix: p,
                gateway: g.map(|g| g.parse().unwrap()),
                dns: vec!["192.0.2.53".parse().unwrap()],
            },
            hostname: Some("nexus01".into()),
        }
    }

    #[test]
    fn network_validation_and_nmcli() {
        assert!(stat("192.0.2.10", 24, Some("192.0.2.1")).validate().is_ok());
        assert!(
            stat("192.0.2.10", 24, Some("198.51.100.1")).validate().is_err(),
            "gateway off-subnet"
        );
        assert!(stat("192.0.2.10", 24, Some("192.0.2.10")).validate().is_err());
        assert!(stat("127.0.0.1", 8, None).validate().is_err());
        assert!(stat("192.0.2.10", 33, None).validate().is_err());
        let mut bad = stat("192.0.2.10", 24, None);
        bad.nic = "eth0; rm -rf /".into();
        assert!(bad.validate().is_err());
        bad.nic = "eth0".into();
        bad.hostname = Some("-bad".into());
        assert!(bad.validate().is_err());

        let a = stat("192.0.2.10", 24, Some("192.0.2.1")).nmcli_add_args().join(" ");
        assert!(a.contains("ifname eth0"));
        assert!(
            a.contains("ipv4.method manual ipv4.addresses 192.0.2.10/24 ipv4.gateway 192.0.2.1 ipv4.dns 192.0.2.53")
        );
        let d = NetConfig {
            nic: "eno1".into(),
            ipv4: Ipv4Config::Dhcp,
            hostname: None,
        };
        assert!(d.nmcli_add_args().join(" ").ends_with("ipv4.method auto"));

        assert_eq!(
            parse_static("10.0.0.5/16", "10.0.0.1", "10.0.0.2, 10.0.0.3").unwrap(),
            Ipv4Config::Static {
                address: "10.0.0.5".parse().unwrap(),
                prefix: 16,
                gateway: Some("10.0.0.1".parse().unwrap()),
                dns: vec!["10.0.0.2".parse().unwrap(), "10.0.0.3".parse().unwrap()],
            }
        );
        assert!(parse_static("10.0.0.5", "", "").is_err(), "prefix required");
        assert_eq!(
            parse_nmcli_addresses("192.0.2.7/24 | 10.1.1.1/8\n"),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap(), "10.1.1.1".parse().unwrap()]
        );
        let j: NetConfig = serde_json::from_str(r#"{"nic":"eth1","method":"dhcp"}"#).unwrap();
        assert_eq!(j.ipv4, Ipv4Config::Dhcp);
    }

    #[test]
    fn recovery_key_groups() {
        let k = RecoveryKey::from_string(keyd::format_recovery_key(&[0xab; 32]));
        assert_eq!(k.groups().len(), KEY_GROUPS);
        assert_eq!(k.groups()[0].as_str(), "ABAB");
        assert!(k.check_groups(&[0, 5, 15], &["abab", "ABAB", " ab ab "]));
        assert!(!k.check_groups(&[0, 5, 15], &["abab", "ABAB", "abac"]));
        assert!(!k.check_groups(&[0, 5, 16], &["abab", "abab", "abab"]), "out of range");
        assert!(!k.check_groups(&[], &[]));
        for _ in 0..50 {
            let c = challenge();
            assert!(c[0] < c[1] && c[1] < c[2] && c[2] < KEY_GROUPS);
        }
    }

    #[test]
    fn cert_and_qr() {
        let c = generate_cert("nexus01", &["192.0.2.10".parse().unwrap()]).unwrap();
        assert!(c.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(c.key_pem.contains("PRIVATE KEY"));
        assert_eq!(c.fingerprint.len(), 32 * 3 - 1);
        assert_eq!(c.sans, ["nexus01", "192.0.2.10"]);
        let q = qr_lines("otpauth://totp/NexusBackup:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=NexusBackup")
            .unwrap();
        assert_eq!(q.len(), 21, "fits an 80x25 console");
        assert_eq!(q[0].chars().count(), 41);
        assert!(q[0].chars().all(|c| c == '\u{2588}'), "quiet zone on top");
        // decode the half blocks back into modules and compare with the symbol
        let uri = "otpauth://totp/NexusBackup:x?secret=AAAA";
        let code = qrcode::QrCode::with_error_correction_level(uri, qrcode::EcLevel::L).unwrap();
        let (w, colors) = (code.width(), code.to_colors());
        let rows: Vec<Vec<char>> = qr_lines(uri).unwrap().iter().map(|l| l.chars().collect()).collect();
        for y in 0..w {
            for x in 0..w {
                let (gy, gx) = (y + 2, x + 2);
                let c = rows[gy / 2][gx];
                let light = if gy % 2 == 0 {
                    matches!(c, '\u{2588}' | '\u{2580}')
                } else {
                    matches!(c, '\u{2588}' | '\u{2584}')
                };
                assert_eq!(light, colors[y * w + x] == qrcode::Color::Light, "module {x},{y}");
            }
        }
        assert!(q.iter().all(|l| l.chars().count() == q[0].chars().count()));
    }

    #[test]
    fn names_and_passwords() {
        assert!(validate_username("admin").is_ok() && validate_username("so.jane-doe_2").is_ok());
        for bad in ["", "Admin", "a b", "-x", ".x", &"x".repeat(65)] {
            assert!(validate_username(bad).is_err(), "{bad}");
        }
        assert!(check_password_pair("correct horse battery", "correct horse battery").is_ok());
        assert!(check_password_pair("correct horse battery", "correct horse batterY").is_err());
        assert!(check_password_pair("short", "short").is_err());
    }

    #[test]
    fn nics_from_sysfs() {
        let d = tempfile::tempdir().unwrap();
        for (n, phys) in [("lo", false), ("eth0", true), ("docker0", false), ("eno1", true)] {
            let p = d.path().join(n);
            fs::create_dir(&p).unwrap();
            fs::write(p.join("address"), "52:54:00:00:00:01\n").unwrap();
            fs::write(p.join("operstate"), "up\n").unwrap();
            if phys {
                fs::create_dir(p.join("device")).unwrap();
            }
        }
        let n: Vec<String> = list_nics(d.path()).unwrap().into_iter().map(|n| n.name).collect();
        assert_eq!(n, ["eno1", "eth0"]);
    }
}
