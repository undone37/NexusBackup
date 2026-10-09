//! Mount option builder: a validated [`Request`] becomes the `fsconfig` calls
//! of the new mount API. Each option is a separate key/value handed to the
//! kernel (no comma-joined option string, so no option injection through a
//! value), keys are fixed names, values come from validated fields only.
//!
//! Always: superblock `ro`, mount attributes `MOUNT_ATTR_RDONLY | NOSUID |
//! NODEV | NOEXEC | NOSYMFOLLOW` (set by `fsmount`, not negotiable by the
//! request), `soft` with a timeout, no shared superblock/session with other mounts.
//!
//! NFS: `addr=` (no DNS in the kernel), `proto=tcp|tcp6`, `sec=sys`; v3 adds
//! `mountvers=3,mountproto=tcp,mountport=<n>` (no rpcbind lookup, so the
//! firewall needs exactly 2049 + mountd) and `nolock` (no NLM/statd: a reader
//! needs no locks). v4.x uses only the NFS port.
//! SMB: `ip=` (no DNS upcall), `vers=`, `sec=ntlmssp|krb5`, optional `sign`
//! (required signing) and `seal` (SMB3 encryption), `noperm` (the server
//! decides with the SMB user's rights, not the faked client modes),
//! `backupuid=<connector uid>` (opens carry the backup intent flag: a user with
//! SeBackupPrivilege reads everything on Windows servers), `nobrl`, `nosharesock`,
//! `nolease` (leases are keyed per inode: concurrent opens of two names of a hard-linked
//! file are refused by the server otherwise).

use crate::proto::{Fs, Request, Sec};
use anyhow::Result;

pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

/// The attributes every share mount gets.
pub const ATTRS: u64 =
    MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSYMFOLLOW;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    /// `FSCONFIG_SET_FLAG`
    Flag(&'static str),
    /// `FSCONFIG_SET_STRING`
    Str(&'static str, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpec {
    /// `fsopen` file system type
    pub fstype: &'static str,
    pub params: Vec<Param>,
    /// `fsmount` attribute flags
    pub attrs: u64,
}

impl MountSpec {
    /// Human-readable option list (secrets redacted) for logs and tests.
    pub fn describe(&self) -> String {
        let p: Vec<String> = self
            .params
            .iter()
            .map(|p| match p {
                Param::Flag(k) => k.to_string(),
                Param::Str("password", _) => "password=<redacted>".into(),
                Param::Str(k, v) => format!("{k}={v}"),
            })
            .collect();
        format!("{} {}", self.fstype, p.join(","))
    }
}

/// `peer_uid`: uid of the connector (from SO_PEERCRED), for `backupuid=`.
pub fn build(r: &Request, peer_uid: u32) -> Result<MountSpec> {
    r.check()?;
    let v6 = r.addr.is_ipv6();
    let tcp = if v6 { "tcp6" } else { "tcp" };
    let mut p = vec![Param::Flag("ro")];
    let fstype = match r.fs {
        Fs::Nfs => {
            p.push(Param::Str("source", format!("{}:{}", r.host, r.export)));
            p.push(Param::Str("vers", r.version.clone()));
            p.push(Param::Str("addr", r.addr.to_string()));
            p.push(Param::Str("proto", tcp.into()));
            p.push(Param::Str("port", r.port.to_string()));
            if r.version == "3" {
                p.push(Param::Str("mountvers", "3".into()));
                p.push(Param::Str("mountproto", tcp.into()));
                p.push(Param::Str("mountport", r.mount_port.to_string()));
                p.push(Param::Flag("nolock"));
            }
            p.push(Param::Str("sec", "sys".into()));
            p.push(Param::Flag("soft"));
            // deciseconds; the kernel retries `retrans` times before a soft error
            p.push(Param::Str("timeo", (r.timeout_secs.min(600) * 10).to_string()));
            p.push(Param::Str("retrans", "2".into()));
            p.push(Param::Flag("nosharecache"));
            if r.version == "3" {
                "nfs"
            } else {
                "nfs4"
            }
        }
        Fs::Smb => {
            if r.host.contains(':') {
                anyhow::bail!("SMB needs a host name or IPv4 address in the UNC path");
            }
            p.push(Param::Str("source", format!("//{}/{}", r.host, r.share)));
            p.push(Param::Str("ip", r.addr.to_string()));
            p.push(Param::Str("port", r.port.to_string()));
            p.push(Param::Str("vers", r.version.clone()));
            p.push(Param::Str("sec", r.sec.as_str().into()));
            if r.sign {
                p.push(Param::Flag("sign"));
            }
            if r.seal {
                p.push(Param::Flag("seal"));
            }
            if !r.user.is_empty() {
                p.push(Param::Str("username", r.user.clone()));
            }
            if !r.domain.is_empty() {
                p.push(Param::Str("domain", r.domain.clone()));
            }
            match r.sec {
                Sec::Ntlmssp => p.push(Param::Str("password", r.password.clone().unwrap_or_default())),
                // the upcall (cifs.upcall) finds the helper's ticket cache via
                // KRB5CCNAME in the helper's environment; tickets of uid 0
                Sec::Krb5 => p.push(Param::Str("cruid", "0".into())),
                Sec::Sys => unreachable!("checked"),
            }
            p.push(Param::Flag("noperm"));
            p.push(Param::Str("backupuid", peer_uid.to_string()));
            p.push(Param::Flag("soft"));
            p.push(Param::Str("echo_interval", r.timeout_secs.clamp(1, 600).to_string()));
            p.push(Param::Flag("nobrl"));
            p.push(Param::Flag("nosharesock"));
            // no leases: the client keys leases per inode, and opening another name of a
            // hard-linked file under the same lease key is refused (EINVAL) while one is open
            p.push(Param::Flag("nolease"));
            "cifs"
        }
    };
    Ok(MountSpec {
        fstype,
        params: p,
        attrs: ATTRS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs_options() {
        let mut r = Request::nfs("nas.lab", "10.0.2.2".parse().unwrap(), "/srv/share");
        let m = build(&r, 990).unwrap();
        assert_eq!(m.fstype, "nfs4");
        assert_eq!(
            m.describe(),
            "nfs4 ro,source=nas.lab:/srv/share,vers=4.2,addr=10.0.2.2,proto=tcp,port=2049,sec=sys,soft,timeo=600,retrans=2,nosharecache"
        );
        assert_eq!(m.attrs, 0x20000f);
        r.version = "3".into();
        r.port = 12049;
        r.mount_port = 12048;
        r.addr = "fd00::5".parse().unwrap();
        r.timeout_secs = 900; // refused by check
        assert!(build(&r, 990).is_err());
        r.timeout_secs = 30;
        let m = build(&r, 990).unwrap();
        assert_eq!(m.fstype, "nfs");
        assert_eq!(
            m.describe(),
            "nfs ro,source=nas.lab:/srv/share,vers=3,addr=fd00::5,proto=tcp6,port=12049,mountvers=3,mountproto=tcp6,mountport=12048,nolock,sec=sys,soft,timeo=300,retrans=2,nosharecache"
        );
    }

    #[test]
    fn smb_options() {
        let mut r = Request::smb("nas", "10.0.2.2".parse().unwrap(), "Data", "backup", "s3cr,et=x");
        let m = build(&r, 990).unwrap();
        assert_eq!(m.fstype, "cifs");
        assert_eq!(
            m.describe(),
            "cifs ro,source=//nas/Data,ip=10.0.2.2,port=445,vers=3,sec=ntlmssp,sign,username=backup,password=<redacted>,noperm,backupuid=990,soft,echo_interval=60,nobrl,nosharesock,nolease"
        );
        // the password is one fsconfig value: commas and `=` cannot inject options
        assert!(m.params.contains(&Param::Str("password", "s3cr,et=x".into())));
        r.sign = false;
        r.seal = true;
        r.version = "3.1.1".into();
        r.domain = "LAB".into();
        let d = build(&r, 990).unwrap().describe();
        assert!(d.contains(",seal,") && !d.contains(",sign,") && d.contains("domain=LAB") && d.contains("vers=3.1.1"));
        r.sec = Sec::Krb5;
        r.password = None;
        r.keytab = Some(vec![5, 2]);
        r.principal = Some("backup@LAB.EXAMPLE".into());
        let d = build(&r, 990).unwrap().describe();
        assert!(d.contains("sec=krb5") && d.contains("cruid=0") && !d.contains("password"));
        let mut v6 = Request::smb("fd00::5", "fd00::5".parse().unwrap(), "Data", "backup", "x");
        v6.port = 445;
        assert!(build(&v6, 1).is_err());
    }
}
