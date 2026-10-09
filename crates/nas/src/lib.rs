//! NAS connector (docs/nas-connector.md): NFS (v3/v4.x) and SMB (2.1/3.x)
//! shares, file level. Decision (plan.md §2): kernel NFS/CIFS mounts,
//! read-only, in a private mount namespace, done by a small privileged helper
//! with its own SELinux domain.
//!
//! - [`nexus-nasmount`](../nexus_nasmount/index.html) (root, `CAP_SYS_ADMIN`
//!   only, socket-activated per connection): validates a [`proto::Request`],
//!   builds the mount with the new mount API (`fsopen`/`fsconfig`/`fsmount`,
//!   [`opts`]) as a **detached** mount (an anonymous mount namespace that no
//!   process lives in) with `ro,nosuid,nodev,noexec,nosymfollow`, and hands the
//!   mount fd to the connector over the socket (`SCM_RIGHTS`). The mount exists
//!   exactly as long as the connector holds the fd: the kernel unmounts it when
//!   the connector exits, however it exits.
//! - `nexus-nas` (unprivileged, spawned by the scheduler, SELinux `nexus_nas_t`):
//!   walks the share relative to that fd (`openat2` `RESOLVE_BENEATH |
//!   RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV`, never into nested mounts or
//!   automount points) with a parallel scan, reuses unchanged files from the
//!   previous snapshot (metadata cache), chunks the rest into the store and
//!   commits an `Index::Tree` snapshot `share-<source>`.
//!
//! Without the `connector` feature only names/validation, the option builder
//! and the helper protocol are built (web-api, scheduler, nexus-nasmount).

pub mod cred;
pub mod fdpass;
pub mod kmount;
pub mod opts;
pub mod proto;

#[cfg(feature = "connector")]
pub mod backup;
#[cfg(feature = "connector")]
pub mod mount;
#[cfg(feature = "connector")]
pub mod scan;
#[cfg(feature = "connector")]
pub mod sys;

/// Index name inside a share snapshot (same as agent and TrueNAS snapshots).
pub const TREE_INDEX: &str = "tree";

/// Default socket of the mount helper (systemd `nexus-nasmount.socket`).
pub const MOUNT_SOCKET: &str = "/run/nexus-nasmount/mount.sock";

/// Upper bound for paths and symlink targets (Linux PATH_MAX).
pub const MAX_PATH: usize = 4096;

/// Snapshot directory names that are never backed up as data (they would
/// multiply the share): NetApp/Isilon `.snapshot`, Windows/Samba `~snapshot`, ZFS `.zfs`.
pub const DEFAULT_EXCLUDES: &[&str] = &[".snapshot", "~snapshot", ".zfs"];

/// Store source of a share: `share-<source-id>`.
pub fn source_name(source_id: u64) -> String {
    format!("share-{source_id}")
}

/// Inverse of [`source_name`].
pub fn parse_source_name(s: &str) -> Option<u64> {
    let id = s.strip_prefix("share-")?;
    if id.is_empty() || id.len() > 19 || id.starts_with('0') || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    id.parse().ok()
}

/// Host name or IP literal (no brackets): `[A-Za-z0-9.-]` labels, or an IPv4/IPv6 address.
pub fn valid_host(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// NFS export path: absolute, at most 1024 bytes, no control characters, no
/// `,` `"` `'` `\`, no empty / `.` / `..` components (`/` alone is allowed).
pub fn valid_export(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 1024
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, ',' | '"' | '\'' | '\\'))
        && (s == "/" || s[1..].split('/').all(|c| !c.is_empty() && c != "." && c != ".."))
}

/// SMB share name: 1..=80 characters, none of `\ / : * ? " < > | , =` or control characters.
pub fn valid_share(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= 80
        && !s.starts_with(' ')
        && !s.chars().any(|c| c.is_control() || "\\/:*?\"<>|,=".contains(c))
}

/// SMB user name: 1..=104 characters, none of `\ / : * ? " < > | , = @ [ ] ; +` or control characters.
pub fn valid_smb_user(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 104 && !s.chars().any(|c| c.is_control() || "\\/:*?\"<>|,=@[];+".contains(c))
}

/// SMB/AD domain (NetBIOS or DNS form): `[A-Za-z0-9.-]`, at most 255 bytes.
pub fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && !s.starts_with(['.', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// Kerberos principal `user@REALM` (printable ASCII, no space, `,` or `\`).
pub fn valid_principal(s: &str) -> bool {
    s.len() <= 256
        && s.split_once('@').is_some_and(|(u, r)| !u.is_empty() && valid_domain(r))
        && s.bytes().all(|b| b.is_ascii_graphic() && !b",\\'\"".contains(&b))
}

/// Password for SMB: 1..=256 bytes, no NUL (handed to the kernel as a C string).
pub fn valid_password(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.contains('\0')
}

/// Relative directory below the share root (snapshot directory such as
/// `.zfs/snapshot`, `.snapshot`, `~snapshot`): `/`-separated, no empty, `.`
/// or `..` component, no control characters, at most 256 bytes.
pub fn valid_rel_dir(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && !s.starts_with('/')
        && !s.chars().any(char::is_control)
        && s.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// NFS versions the connector mounts.
pub const NFS_VERSIONS: &[&str] = &["3", "4.0", "4.1", "4.2"];
/// SMB dialects (`vers=` of the kernel client; `3` = negotiate the highest 3.x).
pub const SMB_VERSIONS: &[&str] = &["2.1", "3", "3.0", "3.02", "3.1.1"];

/// Relative path of a scanned entry: raw bytes, `/`-separated, no empty, `.`
/// or `..` component, no NUL, at most [`MAX_PATH`] bytes.
pub fn valid_rel_path(p: &[u8]) -> bool {
    !p.is_empty()
        && p.len() <= MAX_PATH
        && !p.contains(&0)
        && p.split(|b| *b == b'/')
            .all(|c| !c.is_empty() && c != b"." && c != b"..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(source_name(7), "share-7");
        assert_eq!(parse_source_name("share-7"), Some(7));
        for bad in [
            "share-",
            "share-07",
            "share-7a",
            "nas-7-x",
            "share--1",
            "share-99999999999999999999",
        ] {
            assert_eq!(parse_source_name(bad), None, "{bad}");
        }
        for ok in ["nas1", "nas.lab.local", "10.0.2.2", "fd00::1", "a-b.c"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in ["", "-a", "a..b", "a b", "a,b", "[fd00::1]", "a_b", "a:b"] {
            assert!(!valid_host(bad), "{bad}");
        }
        for ok in ["/", "/srv/share", "/mnt/tank/data set", "/export/ä"] {
            assert!(valid_export(ok), "{ok}");
        }
        for bad in [
            "",
            "srv",
            "/srv/",
            "//srv",
            "/srv/../etc",
            "/a,b",
            "/a\nb",
            "/a\\b",
            "/a/./b",
        ] {
            assert!(!valid_export(bad), "{bad:?}");
        }
        for ok in ["share", "Data Files", "C$", "projekte-ä"] {
            assert!(valid_share(ok), "{ok}");
        }
        for bad in ["", " x", "a/b", "a\\b", "a,b", "a=b", "a\0", &"x".repeat(81)] {
            assert!(!valid_share(bad), "{bad:?}");
        }
        assert!(valid_smb_user("nexusbackup") && valid_smb_user("Backup Operator"));
        assert!(!valid_smb_user("a,b") && !valid_smb_user("dom\\user") && !valid_smb_user("u@r"));
        assert!(valid_domain("LAB") && valid_domain("lab.example.com") && !valid_domain("a b"));
        assert!(valid_principal("nexus@LAB.EXAMPLE.COM") && !valid_principal("nexus") && !valid_principal("a,b@R"));
        assert!(valid_password("p,a=s s\\w\"rd") && !valid_password("") && !valid_password("a\0b"));
        for ok in [".zfs/snapshot", ".snapshot", "~snapshot"] {
            assert!(valid_rel_dir(ok), "{ok}");
        }
        for bad in ["", "/x", "a/../b", "a//b", "a/\n"] {
            assert!(!valid_rel_dir(bad), "{bad:?}");
        }
    }
}
