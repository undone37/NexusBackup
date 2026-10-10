//! Protocol between the connector (`nexus-nas`, unprivileged) and the mount
//! helper (`nexus-nasmount`, root with `CAP_SYS_ADMIN` only). One connection
//! = one mount request:
//!
//! ```text
//! connector -> helper   nexus-nasmount 1\n  (key value\n)*  end\n
//! helper -> connector   ok\n  + the mount fd as SCM_RIGHTS   |   error <message>\n
//! ```
//!
//! Every key at most once, unknown keys refused, values without control
//! characters; secrets (`password`, `keytab`) are hex encoded. The helper treats
//! the request as untrusted: [`Request::parse`] is strict and bounded and
//! [`Request::check`] validates every field before anything reaches the kernel
//! ([`crate::opts`] then only emits fixed option names). The fuzz target
//! `nas:helper_request` runs on [`Request::parse`] + [`crate::opts::build`].

use crate::{valid_export, valid_host, valid_principal, valid_share, valid_smb_user, NFS_VERSIONS, SMB_VERSIONS};
use anyhow::{bail, Context, Result};
use std::fmt::Write as _;
use std::net::IpAddr;

pub const MAGIC: &str = "nexus-nasmount 1";
/// Upper bound of a request (a keytab is a few KiB; hex doubles it).
pub const MAX_REQUEST: usize = 256 << 10;
/// Upper bound of a keytab.
pub const MAX_KEYTAB: usize = 64 << 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fs {
    Nfs,
    Smb,
}

impl Fs {
    pub fn as_str(self) -> &'static str {
        match self {
            Fs::Nfs => "nfs",
            Fs::Smb => "smb",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sec {
    /// NFS: AUTH_SYS (the only NFS flavour in v1)
    Sys,
    /// SMB: NTLMv2 in NTLMSSP with user + password
    Ntlmssp,
    /// SMB: Kerberos (keytab + principal; the helper runs kinit)
    Krb5,
}

impl Sec {
    pub fn as_str(self) -> &'static str {
        match self {
            Sec::Sys => "sys",
            Sec::Ntlmssp => "ntlmssp",
            Sec::Krb5 => "krb5",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    pub fs: Fs,
    /// server name (NFS source string, SMB UNC and Kerberos service name)
    pub host: String,
    /// resolved address of `host` (the helper never resolves names)
    pub addr: IpAddr,
    pub port: u16,
    /// NFS: 3 | 4.0 | 4.1 | 4.2; SMB: 2.1 | 3 | 3.0 | 3.02 | 3.1.1
    pub version: String,
    /// NFS export path
    pub export: String,
    /// NFS v3: mountd port (no rpcbind/portmapper lookup)
    pub mount_port: u16,
    /// SMB share name
    pub share: String,
    /// SMB user
    pub user: String,
    /// SMB domain (empty = none)
    pub domain: String,
    pub sec: Sec,
    /// SMB: require signing
    pub sign: bool,
    /// SMB 3: require encryption
    pub seal: bool,
    /// per-request timeout of the kernel client (seconds)
    pub timeout_secs: u32,
    pub password: Option<String>,
    pub keytab: Option<Vec<u8>>,
    pub principal: Option<String>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("fs", &self.fs)
            .field("host", &self.host)
            .field("addr", &self.addr)
            .field("port", &self.port)
            .field("version", &self.version)
            .field("export", &self.export)
            .field("share", &self.share)
            .field("user", &self.user)
            .field("sec", &self.sec)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("keytab", &self.keytab.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

impl Request {
    /// An NFS request with the defaults (version 4.2, port 2049, mountd 20048, timeout 60 s).
    pub fn nfs(host: &str, addr: IpAddr, export: &str) -> Request {
        Request {
            fs: Fs::Nfs,
            host: host.into(),
            addr,
            port: 2049,
            version: "4.2".into(),
            export: export.into(),
            mount_port: 20048,
            share: String::new(),
            user: String::new(),
            domain: String::new(),
            sec: Sec::Sys,
            sign: false,
            seal: false,
            timeout_secs: 60,
            password: None,
            keytab: None,
            principal: None,
        }
    }

    /// An SMB request with the defaults (dialect 3.x, port 445, NTLMSSP, signing, timeout 60 s).
    pub fn smb(host: &str, addr: IpAddr, share: &str, user: &str, password: &str) -> Request {
        Request {
            fs: Fs::Smb,
            host: host.into(),
            addr,
            port: 445,
            version: "3".into(),
            export: String::new(),
            mount_port: 0,
            share: share.into(),
            user: user.into(),
            domain: String::new(),
            sec: Sec::Ntlmssp,
            sign: true,
            seal: false,
            timeout_secs: 60,
            password: Some(password.into()),
            keytab: None,
            principal: None,
        }
    }

    /// Field validation (both sides; the helper relies on it).
    pub fn check(&self) -> Result<()> {
        if !valid_host(&self.host) {
            bail!("invalid host");
        }
        if self.addr.is_unspecified() || self.addr.is_multicast() {
            bail!("invalid address");
        }
        if self.port == 0 {
            bail!("invalid port");
        }
        if !(1..=600).contains(&self.timeout_secs) {
            bail!("timeout must be 1..=600 s");
        }
        match self.fs {
            Fs::Nfs => {
                if !NFS_VERSIONS.contains(&self.version.as_str()) {
                    bail!("NFS version must be one of {NFS_VERSIONS:?}");
                }
                if !valid_export(&self.export) {
                    bail!("invalid export path");
                }
                if self.version == "3" && self.mount_port == 0 {
                    bail!("NFSv3 needs the mountd port");
                }
                if self.sec != Sec::Sys {
                    bail!("NFS supports sec=sys only");
                }
                if !self.share.is_empty() || !self.user.is_empty() || !self.domain.is_empty() {
                    bail!("NFS takes no share, user or domain");
                }
                if self.password.is_some()
                    || self.keytab.is_some()
                    || self.principal.is_some()
                    || self.sign
                    || self.seal
                {
                    bail!("NFS takes no credentials, sign or seal");
                }
            }
            Fs::Smb => {
                if !SMB_VERSIONS.contains(&self.version.as_str()) {
                    bail!("SMB version must be one of {SMB_VERSIONS:?}");
                }
                if self.seal && self.version == "2.1" {
                    bail!("encryption (seal) needs SMB 3");
                }
                if !valid_share(&self.share) {
                    bail!("invalid share name");
                }
                if !self.export.is_empty() || self.mount_port != 0 {
                    bail!("SMB takes no export or mount port");
                }
                if !self.domain.is_empty() && !crate::valid_domain(&self.domain) {
                    bail!("invalid domain");
                }
                match self.sec {
                    Sec::Ntlmssp => {
                        if !valid_smb_user(&self.user) {
                            bail!("invalid user");
                        }
                        if !self.password.as_deref().is_some_and(crate::valid_password) {
                            bail!("password missing or invalid");
                        }
                        if self.keytab.is_some() || self.principal.is_some() {
                            bail!("keytab/principal only with sec=krb5");
                        }
                    }
                    Sec::Krb5 => {
                        if self.password.is_some() {
                            bail!("no password with sec=krb5");
                        }
                        if !self
                            .keytab
                            .as_ref()
                            .is_some_and(|k| !k.is_empty() && k.len() <= MAX_KEYTAB)
                        {
                            bail!("keytab missing or too large");
                        }
                        if !self.principal.as_deref().is_some_and(valid_principal) {
                            bail!("principal missing or invalid (user@REALM)");
                        }
                        if !self.user.is_empty() && !valid_smb_user(&self.user) {
                            bail!("invalid user");
                        }
                    }
                    Sec::Sys => bail!("SMB needs sec=ntlmssp or sec=krb5"),
                }
            }
        }
        Ok(())
    }

    /// Wire form (see the module docs). Fails if the request is invalid.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut s = format!("{MAGIC}\n");
        let mut kv = |k: &str, v: &str| {
            let _ = writeln!(s, "{k} {v}");
        };
        kv("fs", self.fs.as_str());
        kv("host", &self.host);
        kv("addr", &self.addr.to_string());
        kv("port", &self.port.to_string());
        kv("version", &self.version);
        kv("sec", self.sec.as_str());
        kv("timeout", &self.timeout_secs.to_string());
        match self.fs {
            Fs::Nfs => {
                kv("export", &self.export);
                if self.mount_port != 0 {
                    kv("mount_port", &self.mount_port.to_string());
                }
            }
            Fs::Smb => {
                kv("share", &self.share);
                if !self.user.is_empty() {
                    kv("user", &self.user);
                }
                if !self.domain.is_empty() {
                    kv("domain", &self.domain);
                }
                kv("sign", if self.sign { "1" } else { "0" });
                kv("seal", if self.seal { "1" } else { "0" });
                if let Some(p) = &self.password {
                    kv("password", &hex(p.as_bytes()));
                }
                if let Some(k) = &self.keytab {
                    kv("keytab", &hex(k));
                }
                if let Some(p) = &self.principal {
                    kv("principal", p);
                }
            }
        }
        s.push_str("end\n");
        Ok(s.into_bytes())
    }

    /// Strict parser of the wire form; the result is [`Request::check`]ed.
    pub fn parse(b: &[u8]) -> Result<Request> {
        if b.len() > MAX_REQUEST {
            bail!("request too large");
        }
        let text = std::str::from_utf8(b).context("request is not UTF-8")?;
        let body = text.strip_suffix("end\n").context("request does not end with `end`")?;
        let mut lines = body.split('\n');
        if lines.next() != Some(MAGIC) {
            bail!("not a {MAGIC} request");
        }
        let mut seen: Vec<&str> = Vec::new();
        let mut r = Request {
            fs: Fs::Nfs,
            host: String::new(),
            addr: IpAddr::from([0, 0, 0, 0]),
            port: 0,
            version: String::new(),
            export: String::new(),
            mount_port: 0,
            share: String::new(),
            user: String::new(),
            domain: String::new(),
            sec: Sec::Sys,
            sign: false,
            seal: false,
            timeout_secs: 0,
            password: None,
            keytab: None,
            principal: None,
        };
        let body_lines: Vec<&str> = lines.collect();
        // `split` yields one empty string after the last `\n` of the body
        let (last, kvs) = body_lines.split_last().context("empty request")?;
        if !last.is_empty() {
            bail!("malformed request");
        }
        for l in kvs {
            let (k, v) = l
                .split_once(' ')
                .with_context(|| format!("malformed line {:?}", trunc(l)))?;
            if v.is_empty() || v.chars().any(char::is_control) {
                bail!("{k}: empty value or control characters");
            }
            if seen.contains(&k) {
                bail!("{k} given twice");
            }
            let num = |v: &str| -> Result<u32> {
                if v.len() > 10 || !v.bytes().all(|c| c.is_ascii_digit()) || (v.len() > 1 && v.starts_with('0')) {
                    bail!("{k}: not a number");
                }
                Ok(v.parse()?)
            };
            let flag = |v: &str| -> Result<bool> {
                match v {
                    "0" => Ok(false),
                    "1" => Ok(true),
                    _ => bail!("{k}: expected 0 or 1"),
                }
            };
            match k {
                "fs" => {
                    r.fs = match v {
                        "nfs" => Fs::Nfs,
                        "smb" => Fs::Smb,
                        _ => bail!("fs: nfs or smb"),
                    }
                }
                "host" => r.host = v.into(),
                "addr" => r.addr = v.parse().context("addr: not an IP address")?,
                "port" => r.port = u16::try_from(num(v)?).context("port")?,
                "version" => r.version = v.into(),
                "sec" => {
                    r.sec = match v {
                        "sys" => Sec::Sys,
                        "ntlmssp" => Sec::Ntlmssp,
                        "krb5" => Sec::Krb5,
                        _ => bail!("sec: sys, ntlmssp or krb5"),
                    }
                }
                "timeout" => r.timeout_secs = num(v)?,
                "export" => r.export = v.into(),
                "mount_port" => r.mount_port = u16::try_from(num(v)?).context("mount_port")?,
                "share" => r.share = v.into(),
                "user" => r.user = v.into(),
                "domain" => r.domain = v.into(),
                "sign" => r.sign = flag(v)?,
                "seal" => r.seal = flag(v)?,
                "password" => {
                    r.password = Some(String::from_utf8(unhex(v).context("password")?).context("password: not UTF-8")?)
                }
                "keytab" => r.keytab = Some(unhex(v).context("keytab")?),
                "principal" => r.principal = Some(v.into()),
                _ => bail!("unknown key {:?}", trunc(k)),
            }
            seen.push(k);
        }
        for k in ["fs", "host", "addr", "port", "version", "sec", "timeout"] {
            if !seen.contains(&k) {
                bail!("{k} missing");
            }
        }
        r.check()?;
        Ok(r)
    }
}

fn trunc(s: &str) -> String {
    s.chars().take(32).collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        bail!("not lowercase hex");
    }
    Ok((0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect())
}

/// Helper answer: `ok` (the fd travels with it) or `error <message>`.
pub fn parse_response(line: &[u8]) -> Result<()> {
    let s = String::from_utf8_lossy(line);
    let s = s.trim_end_matches('\n');
    if s == "ok" {
        return Ok(());
    }
    match s.strip_prefix("error ") {
        Some(m) => bail!(
            "mount helper: {}",
            m.chars().filter(|c| !c.is_control()).take(2000).collect::<String>()
        ),
        None => bail!("mount helper: unexpected answer {:?}", trunc(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nfs() -> Request {
        Request::nfs("nas.lab", "10.0.2.2".parse().unwrap(), "/srv/share")
    }
    fn smb() -> Request {
        Request::smb(
            "nas.lab",
            "10.0.2.2".parse().unwrap(),
            "Data Files",
            "backup",
            "p,w=d\\\"x y",
        )
    }

    #[test]
    fn round_trip() {
        for r in [
            nfs(),
            smb(),
            {
                let mut r = nfs();
                r.version = "3".into();
                r.port = 12049;
                r.mount_port = 12048;
                r
            },
            {
                let mut r = smb();
                r.sec = Sec::Krb5;
                r.password = None;
                r.keytab = Some(vec![5, 2, 0, 0, 0, 1]);
                r.principal = Some("backup@LAB.EXAMPLE".into());
                r.domain = "LAB".into();
                r.seal = true;
                r.version = "3.1.1".into();
                r
            },
        ] {
            let w = r.encode().unwrap();
            assert_eq!(Request::parse(&w).unwrap(), r);
            // the password never appears in clear on the wire
            if let Some(p) = &r.password {
                assert!(!String::from_utf8_lossy(&w).contains(p.as_str()));
            }
            assert!(!format!("{r:?}").contains("p,w=d"));
        }
    }

    #[test]
    fn refuses_bad_requests() {
        let good = String::from_utf8(nfs().encode().unwrap()).unwrap();
        let cases = [
            good.replace("nexus-nasmount 1", "nexus-nasmount 2"),
            good.replace("end\n", ""),
            format!("{good}x"),
            good.replace("fs nfs\n", ""),
            good.replace("fs nfs\n", "fs nfs\nfs nfs\n"),
            good.replace("fs nfs\n", "fs ext4\n"),
            good.replace("export /srv/share", "export /srv/share,rw"),
            good.replace("export /srv/share", "export /srv/../etc"),
            good.replace("version 4.2", "version 2"),
            good.replace("addr 10.0.2.2", "addr nas.lab"),
            good.replace("addr 10.0.2.2", "addr 0.0.0.0"),
            good.replace("port 2049", "port 0"),
            good.replace("port 2049", "port 02049"),
            good.replace("port 2049", "port 99999"),
            good.replace("timeout 60", "timeout 0"),
            good.replace("sec sys", "sec krb5"),
            good.replace("host nas.lab", "host nas,lab"),
            good.replace("end\n", "rw 1\nend\n"),
            good.replace("end\n", "password 6161\nend\n"),
            good.replace("end\n", "share x\nend\n"),
            good.replace("\n", "\r\n"),
            good.replace("host nas.lab", "host nas\u{1}lab"),
        ];
        for (i, c) in cases.iter().enumerate() {
            assert!(Request::parse(c.as_bytes()).is_err(), "case {i}: {c:?}");
        }
        let good = String::from_utf8(smb().encode().unwrap()).unwrap();
        for c in [
            good.replace("sec ntlmssp", "sec sys"),
            good.replace("share Data Files", "share a/b"),
            good.replace("user backup\n", ""),
            good.replace("password ", "password X"),
            good.replace("password ", "password 0"),
            good.replace("sign 1", "sign yes"),
            good.replace("version 3\n", "version 1.0\n"),
            good.replace("end\n", "export /x\nend\n"),
        ] {
            assert!(Request::parse(c.as_bytes()).is_err(), "{c:?}");
        }
        let mut r = smb();
        r.version = "2.1".into();
        r.seal = true;
        assert!(r.encode().is_err());
        assert!(Request::parse(&vec![b'a'; MAX_REQUEST + 1]).is_err());
    }

    #[test]
    fn responses() {
        assert!(parse_response(b"ok\n").is_ok());
        let e = parse_response(b"error nfs: access denied\n").unwrap_err().to_string();
        assert!(e.contains("access denied"));
        assert!(parse_response(b"okay\n").is_err());
    }
}
