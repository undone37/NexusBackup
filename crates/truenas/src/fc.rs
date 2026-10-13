//! The forced command of the appliance's SSH key on TrueNAS (nothing is
//! installed there: the script lives in the `authorized_keys` line, which
//! TrueNAS stores verbatim from the user's "SSH public key" field).
//!
//! `restrict,command="exec /usr/bin/bash -c '<script>' nexus-fc" ssh-ed25519 …`
//!
//! The script runs as the restricted user and only understands
//! (`SSH_ORIGINAL_COMMAND`):
//! - `hello` → `nexus-fc 1`
//! - `diff <ds> <from> <to>` → `zfs diff -FH ds@from ds@to` (needs `zfs allow -u <user> diff <ds>`,
//!   or `sudo` for zfs when `zfs_sudo`)
//! - `walk <ds> <snap>` → GNU find metadata records of `.zfs/snapshot/<snap>` (see [`crate::walk`])
//! - `read <ds> <snap>` + NUL-separated relative paths on stdin → POSIX tar with xattrs
//!   of exactly those paths (see [`crate::stream`])
//!
//! Datasets must be one of the configured roots (or below one, if recursive),
//! snapshot names must be `nexus-<id>-<time>`. `read` refuses any path whose
//! canonical form differs from its literal form under the snapshot directory:
//! no `.`/`..`/empty components and no symlink in any component, so a
//! compromised appliance cannot make the privileged tar read outside the
//! snapshot (e.g. through a user's symlink to `/`). Reading needs root for
//! files the user cannot read: `find`, `tar` and `realpath` run via
//! `sudo -n` (TrueNAS user field "Allowed sudo commands with no password").

use anyhow::{bail, Result};

#[derive(Clone, Debug)]
pub struct Fc {
    /// configured dataset roots
    pub datasets: Vec<String>,
    /// children of the roots are allowed too
    pub recursive: bool,
    /// run find/tar/realpath through `sudo -n`
    pub sudo: bool,
    /// run `zfs diff` through `sudo -n` instead of relying on `zfs allow … diff`
    pub zfs_sudo: bool,
    /// "use existing snapshots" (Phase 22b): snapshots named `<prefix>…` are allowed too
    pub existing_prefix: Option<String>,
}

/// Absolute tool paths (TrueNAS defaults; tests point them elsewhere).
#[derive(Clone, Debug)]
pub struct Tools {
    pub bash: String,
    pub zfs: String,
    pub find: String,
    pub tar: String,
    pub realpath: String,
    pub xargs: String,
    pub sudo: String,
}

impl Default for Tools {
    fn default() -> Self {
        Tools {
            bash: "/usr/bin/bash".into(),
            zfs: "/usr/sbin/zfs".into(),
            find: "/usr/bin/find".into(),
            tar: "/usr/bin/tar".into(),
            realpath: "/usr/bin/realpath".into(),
            xargs: "/usr/bin/xargs".into(),
            sudo: "/usr/bin/sudo".into(),
        }
    }
}

fn tool_ok(p: &str) -> bool {
    p.starts_with('/') && p.len() <= 256 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

/// The script (one line, no `'`, so it fits `bash -c '…'` inside `command="…"`).
pub fn script(fc: &Fc, t: &Tools) -> Result<String> {
    if fc.datasets.is_empty() || fc.datasets.len() > 64 || !fc.datasets.iter().all(|d| crate::valid_dataset(d)) {
        bail!("forced command: 1..=64 valid datasets required");
    }
    for p in [&t.bash, &t.zfs, &t.find, &t.tar, &t.realpath, &t.xargs, &t.sudo] {
        if !tool_ok(p) {
            bail!("forced command: invalid tool path {p:?}");
        }
    }
    let s = if fc.sudo {
        format!("{} -n", t.sudo)
    } else {
        String::new()
    };
    let z = if fc.zfs_sudo {
        format!("{} -n", t.sudo)
    } else {
        String::new()
    };
    if fc
        .existing_prefix
        .as_deref()
        .is_some_and(|p| !crate::valid_snap_prefix(p))
    {
        bail!("forced command: invalid existing snapshot prefix");
    }
    let comp = "[A-Za-z0-9_][A-Za-z0-9_-]*";
    let stmts = [
        "set -f -o pipefail".to_owned(),
        "export LC_ALL=C".to_owned(),
        format!("S=\"{s}\""),
        format!("Z=\"{z}\""),
        format!("A=\"{}\"", fc.datasets.join(" ")),
        format!("R={}", u8::from(fc.recursive)),
        "f(){ echo \"nexus-fc: $*\" >&2; exit 2; }".to_owned(),
        "c=$SSH_ORIGINAL_COMMAND".to_owned(),
        "[[ $c =~ ^[a-z]+(\\ [A-Za-z0-9_/-]+){0,3}$ ]] || f refused".to_owned(),
        "read -r o d a b x <<< \"$c\"".to_owned(),
        format!(
            "ok(){{ [[ $1 =~ ^{comp}(/{comp})*$ ]] || return 1; for r in $A; do [[ $1 == \"$r\" ]] && return 0; [[ $R == 1 && $1 == \"$r\"/* ]] && return 0; done; return 1; }}"
        ),
        format!("E=\"{}\"", fc.existing_prefix.as_deref().unwrap_or("")),
        "sn(){ [[ $1 =~ ^nexus-[1-9][0-9]{0,9}-[1-9][0-9]{0,19}$ ]] || [[ -n $E && $1 == \"$E\"* && $1 =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$ ]]; }".to_owned(),
        "if [[ $o == hello && -z $d ]]; then echo \"nexus-fc 1\"; exit 0; fi".to_owned(),
        format!(
            "if [[ $o == diff ]]; then ok \"$d\" && sn \"$a\" && sn \"$b\" && [[ -z $x ]] || f usage; exec $Z {} diff -FH \"$d@$a\" \"$d@$b\"; fi",
            t.zfs
        ),
        "[[ $o == walk || $o == read ]] && ok \"$d\" && sn \"$a\" && [[ -z $b ]] || f usage".to_owned(),
        format!("m=$({} get -Hp -o value mountpoint \"$d\") || f \"no dataset\"", t.zfs),
        format!(
            "[[ $m == /* && $({} get -Hp -o value mounted \"$d\") == yes ]] || f \"not mounted\"",
            t.zfs
        ),
        format!("p=$($S {} -e \"$m/.zfs/snapshot/$a\") || f \"no snapshot\"", t.realpath),
        format!(
            "if [[ $o == walk ]]; then exec $S {} \"$p/\" -mindepth 1 -printf \"%y %m %U %G %s %T@ %C@ %i %n\\0%P\\0%l\\0\"; fi",
            t.find
        ),
        "mapfile -d \"\" -t P".to_owned(),
        "((${#P[@]})) || f \"nothing to read\"".to_owned(),
        format!(
            "mapfile -d \"\" -t Q < <(printf \"%s\\0\" \"${{P[@]/#/\"$p/\"}}\" | {} -0 -r $S {} -z -e --)",
            t.xargs, t.realpath
        ),
        "((${#Q[@]} == ${#P[@]})) || f \"path check failed\"".to_owned(),
        "for i in \"${!P[@]}\"; do [[ ${Q[i]} == \"$p/${P[i]}\" ]] || f \"refused path\"; done".to_owned(),
        format!(
            "printf \"%s\\0\" \"${{P[@]}}\" | $S {} -C \"$p\" -cf - --format=posix --numeric-owner --no-recursion --xattrs \"--xattrs-include=*\" --null --verbatim-files-from -T -",
            t.tar
        ),
    ];
    let out = stmts.join("; ");
    debug_assert!(!out.contains('\'') && !out.contains('\n'));
    Ok(out)
}

/// Value of `command="…"` (before quoting): runs the script with bash whatever the login shell is.
pub fn command(fc: &Fc, t: &Tools) -> Result<String> {
    Ok(format!("exec {} -c '{}' nexus-fc", t.bash, script(fc, t)?))
}

/// `ssh-ed25519 AAAA… comment` → type, base64 blob, comment (validated).
fn parse_pubkey(line: &str) -> Result<(String, String, String)> {
    let mut it = line.split_whitespace();
    let (Some(ty), Some(blob)) = (it.next(), it.next()) else {
        bail!("public key: expected `<type> <base64> [comment]`");
    };
    if !matches!(
        ty,
        "ssh-ed25519" | "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" | "ssh-rsa"
    ) {
        bail!("public key: unsupported type {ty:?}");
    }
    if blob.len() > 4096 || !blob.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
        bail!("public key: invalid base64");
    }
    let comment: Vec<&str> = it.collect();
    let comment = comment.join(" ");
    if comment.len() > 128 || !comment.bytes().all(|b| b.is_ascii_graphic() || b == b' ') || comment.contains('"') {
        bail!("public key: invalid comment");
    }
    Ok((ty.into(), blob.into(), comment))
}

/// The complete `authorized_keys` line for the TrueNAS user's "SSH public key" field.
/// `from`: optional `from="…"` pattern list (appliance address).
pub fn authorized_keys(fc: &Fc, t: &Tools, pubkey: &str, from: Option<&str>) -> Result<String> {
    let (ty, blob, comment) = parse_pubkey(pubkey)?;
    let mut opts = String::from("restrict");
    if let Some(f) = from {
        if f.is_empty()
            || f.len() > 256
            || !f
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".:/*?,-[]".contains(&b))
        {
            bail!("from: expected a comma-separated list of addresses/patterns");
        }
        opts.push_str(&format!(",from=\"{f}\""));
    }
    // OpenSSH option values: only `\"` is an escape inside quotes
    let cmd = command(fc, t)?.replace('"', "\\\"");
    let comment = if comment.is_empty() {
        "nexus-appliance".to_owned()
    } else {
        comment
    };
    Ok(format!("{opts},command=\"{cmd}\" {ty} {blob} {comment}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fc() -> Fc {
        Fc {
            datasets: vec!["tank/data".into(), "tank/smb".into()],
            recursive: true,
            sudo: true,
            zfs_sudo: false,
            existing_prefix: None,
        }
    }

    #[test]
    fn builds_one_line_without_single_quotes() {
        let s = script(&fc(), &Tools::default()).unwrap();
        assert!(!s.contains('\'') && !s.contains('\n'));
        assert!(s.contains("A=\"tank/data tank/smb\"") && s.contains("S=\"/usr/bin/sudo -n\"") && s.contains("Z=\"\""));
        let line = authorized_keys(
            &fc(),
            &Tools::default(),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample appliance@nexus",
            Some("192.0.2.10"),
        )
        .unwrap();
        assert!(line.starts_with("restrict,from=\"192.0.2.10\",command=\"exec /usr/bin/bash -c '"));
        assert!(line.ends_with("' nexus-fc\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample appliance@nexus"));
        // every quote inside the option value is escaped
        let inner = &line[line.find("command=\"").unwrap() + 9..line.rfind("\" ssh-ed25519").unwrap()];
        assert!(inner.match_indices('"').all(|(i, _)| inner.as_bytes()[i - 1] == b'\\'));
    }

    #[test]
    fn existing_prefix_in_the_script() {
        let t = Tools::default();
        assert!(
            script(&fc(), &t).unwrap().contains("E=\"\""),
            "no prefix: only nexus- snapshots"
        );
        let s = script(
            &Fc {
                existing_prefix: Some("auto-".into()),
                ..fc()
            },
            &t,
        )
        .unwrap();
        assert!(s.contains("E=\"auto-\"") && !s.contains('\''));
        for bad in ["", "-x", "a b", "a\"b", "a/b", &"a".repeat(33)] {
            let f = Fc {
                existing_prefix: Some(bad.into()),
                ..fc()
            };
            assert!(script(&f, &t).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn refuses_bad_input() {
        let t = Tools::default();
        assert!(script(
            &Fc {
                datasets: vec![],
                ..fc()
            },
            &t
        )
        .is_err());
        assert!(script(
            &Fc {
                datasets: vec!["tank/a b".into()],
                ..fc()
            },
            &t
        )
        .is_err());
        assert!(script(
            &fc(),
            &Tools {
                tar: "tar;rm".into(),
                ..t.clone()
            }
        )
        .is_err());
        for k in [
            "",
            "ssh-dss AAAA",
            "ssh-ed25519 AA\"AA",
            "ssh-ed25519 AAAA bad\"comment",
            "ssh-ed25519",
        ] {
            assert!(authorized_keys(&fc(), &t, k, None).is_err(), "{k}");
        }
        assert!(authorized_keys(&fc(), &t, "ssh-ed25519 AAAA", Some("1.2.3.4\" x")).is_err());
    }
}
