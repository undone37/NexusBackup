//! Point-in-time restore of a cluster snapshot (physical.rs) over SSH: unpacks
//! `data/` as a new data directory on the restore host, the WAL into
//! `<dir>/nexus_wal/`, each tablespace into its new directory (`tablespaces`:
//! `<oid or old path>=<new path>`, rewritten in `tablespace_map`; PostgreSQL
//! creates the `pg_tblspc` links from it), and configures recovery: to a time, an
//! LSN, a named restore point or the end of the WAL, then promote. With `start`
//! the plugin starts PostgreSQL on it (`pg_ctl start`, same major version).

use crate::ssh::{sh_quote, Ssh};
use anyhow::{anyhow, bail, Context, Result};
use plugin_sdk::{Ctx, Kind, Source};
use serde_json::Value;
use std::io;

pub fn valid_dir(d: &str) -> bool {
    d.len() > 1
        && d.len() <= 1024
        && d.starts_with('/')
        && d.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && d.split('/').all(|c| c != ".." && c != ".")
}

fn valid_lsn(s: &str) -> bool {
    s.split_once('/').is_some_and(|(a, b)| {
        [a, b]
            .iter()
            .all(|x| (1..=8).contains(&x.len()) && x.bytes().all(|c| c.is_ascii_hexdigit()))
    })
}

/// Recovery settings appended to `postgresql.auto.conf`, and what they recover to.
pub fn recovery_conf(p: &Value) -> Result<(String, String)> {
    let get = |k: &str| p[k].as_str().map(str::trim).filter(|v| !v.is_empty());
    let (time, lsn, name) = (get("target_time"), get("target_lsn"), get("target_name"));
    let mut conf = String::from("\n# NexusBackup point-in-time restore\nrestore_command = 'cp nexus_wal/%f \"%p\"'\n");
    let until = match (time, lsn, name) {
        (None, None, None) => "the end of the WAL".to_owned(),
        (Some(t), None, None) => {
            // the manifest pattern allows digits, `-: .+Z` and `T` only: safe inside quotes
            if !t.bytes().all(|b| b.is_ascii_digit() || b" -:.+TZ".contains(&b)) {
                bail!("target_time: e.g. 2026-10-10 14:30:00+00");
            }
            conf += &format!("recovery_target_time = '{t}'\n");
            format!("time {t}")
        }
        (None, Some(l), None) => {
            if !valid_lsn(l) {
                bail!("target_lsn: an LSN like 0/3000060");
            }
            conf += &format!("recovery_target_lsn = '{l}'\n");
            format!("LSN {l}")
        }
        (None, None, Some(n)) => {
            if n.len() > 63 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)) {
                bail!("target_name: the restore point name ([A-Za-z0-9_.:-], up to 63 characters)");
            }
            conf += &format!("recovery_target_name = '{n}'\n");
            format!("restore point {n}")
        }
        _ => bail!("give at most one recovery target (time, LSN or restore point name)"),
    };
    conf += "recovery_target_action = 'promote'\narchive_mode = 'off'\n";
    if let Some(port) = p["port"].as_u64() {
        if !(1..=65535).contains(&port) {
            bail!("port: 1..65535");
        }
        conf += &format!("port = {port}\n");
    }
    Ok((conf, until))
}

/// A tablespace of the snapshot and where it goes.
#[derive(Debug, PartialEq)]
pub struct Tablespace {
    pub oid: String,
    pub old: String,
    pub new: String,
}

/// `tablespace_map` (`<oid> <path>` per line) + rules `<oid or old path>=<new path>`
/// → the tablespaces and the rewritten map. Every tablespace needs a rule: its
/// old path may be in use on the restore host (the source itself).
pub fn remap(map: &str, rules: &[String]) -> Result<(Vec<Tablespace>, String)> {
    let mut out: Vec<Tablespace> = Vec::new();
    for l in map.lines().filter(|l| !l.trim().is_empty()) {
        let (oid, old) = l
            .split_once(' ')
            .with_context(|| format!("tablespace_map: bad line {l:?}"))?;
        if oid.is_empty() || !oid.bytes().all(|b| b.is_ascii_digit()) {
            bail!("tablespace_map: bad line {l:?}");
        }
        out.push(Tablespace {
            oid: oid.into(),
            old: old.into(),
            new: String::new(),
        });
    }
    for r in rules {
        let (k, new) = r
            .split_once('=')
            .with_context(|| format!("tablespaces: {r:?} is not <oid or old path>=<new path>"))?;
        let (k, new) = (k.trim(), new.trim());
        if !valid_dir(new) {
            bail!("tablespaces: {new:?} is not an absolute path of [A-Za-z0-9._/-]");
        }
        let t = out
            .iter_mut()
            .find(|t| t.oid == k || t.old == k)
            .with_context(|| format!("tablespaces: the snapshot has no tablespace {k:?}"))?;
        t.new = new.into();
    }
    let missing: Vec<String> = out
        .iter()
        .filter(|t| t.new.is_empty())
        .map(|t| format!("{} ({})", t.oid, t.old))
        .collect();
    if !missing.is_empty() {
        bail!(
            "the snapshot has tablespaces: give each a new directory (tablespaces: <oid or old path>=<new path>): {}",
            missing.join(", ")
        );
    }
    let mut news: Vec<&str> = out.iter().map(|t| t.new.as_str()).collect();
    news.sort_unstable();
    if news.windows(2).any(|w| w[0] == w[1]) {
        bail!("tablespaces: two tablespaces in one directory");
    }
    let rewritten = out.iter().map(|t| format!("{} {}\n", t.oid, t.new)).collect();
    Ok((out, rewritten))
}

/// Files whose content the restore edits or adds when missing.
const WATCH: &[&str] = &[
    "postgresql.auto.conf",
    "postgresql.conf",
    "pg_hba.conf",
    "pg_ident.conf",
    "tablespace_map",
];

#[derive(Default)]
struct Unpacked {
    files: u64,
    bytes: u64,
    wal: u64,
    seen: Vec<String>,
}

/// Streams the snapshot files at `paths` as a tar into `tar -x` in `dir` on the
/// restore host. `name`: archive name of a snapshot path (None = skip); `edit`:
/// new content of a `WATCH`ed file; `extra`: files appended at the end (given
/// the `WATCH`ed names seen).
fn unpack(
    ctx: &Ctx,
    src: &mut Source,
    ssh: &Ssh,
    dir: &str,
    paths: &[String],
    name: &dyn Fn(&str) -> Option<String>,
    edit: &dyn Fn(&str, Vec<u8>) -> Vec<u8>,
    extra: &dyn Fn(&[String]) -> Vec<(&'static str, Vec<u8>)>,
) -> Result<Unpacked> {
    let exec = ssh.exec(&format!("exec tar -x -f - -C {}", sh_quote(dir)))?;
    let mut tar = tar::Builder::new(io::BufWriter::with_capacity(1 << 18, exec));
    let mut u = Unpacked::default();
    let req: Vec<Vec<u8>> = paths.iter().map(|p| p.as_bytes().to_vec()).collect();
    src.files(&req, |item, data| {
        let path = String::from_utf8_lossy(&item.path).into_owned();
        let Some(rel) = name(&path) else { return Ok(()) };
        let m = &item.meta;
        let mut h = tar::Header::new_gnu();
        h.set_mode(m.mode & 0o7777);
        h.set_mtime(m.mtime_ns.max(0) as u64 / 1_000_000_000);
        match m.kind.unwrap_or(Kind::File) {
            Kind::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_size(0);
                tar.append_data(&mut h, &rel, io::empty())?;
            }
            Kind::File if WATCH.contains(&rel.as_str()) => {
                let mut c = Vec::new();
                data.read_to_end(&mut c)?;
                let c = edit(&rel, c);
                h.set_size(c.len() as u64);
                tar.append_data(&mut h, &rel, &c[..])?;
                u.seen.push(rel);
            }
            Kind::File => {
                h.set_size(m.size);
                tar.append_data(&mut h, &rel, data)?;
                if rel.starts_with("nexus_wal/") {
                    u.wal += 1;
                } else {
                    u.files += 1;
                    u.bytes += m.size;
                }
            }
            k => ctx.warn(format!("{path}: {k:?} skipped")),
        }
        Ok(())
    })?;
    for (n, c) in extra(&u.seen) {
        let mut h = tar::Header::new_gnu();
        h.set_mode(0o600);
        h.set_mtime(crate::physical::now());
        h.set_size(c.len() as u64);
        tar.append_data(&mut h, n, &c[..])?;
    }
    let exec = tar
        .into_inner()?
        .into_inner()
        .map_err(|e| anyhow!("ssh: {}", e.error()))?;
    exec.finish()
        .with_context(|| format!("unpacking into {dir} on the restore host"))?;
    Ok(u)
}

/// Starts PostgreSQL on `dir`: `pg_ctl` from `pg_ctl` (config `ssh_pg_ctl`), else
/// of the data directory's major version (Debian/Ubuntu and PGDG RPM paths), else
/// from PATH. Waits up to 10 minutes; the log is `<dir>/nexus_restore.log`.
pub fn start_cmd(dir: &str, pg_ctl: Option<&str>) -> String {
    let d = sh_quote(dir);
    let first = pg_ctl.map(sh_quote).unwrap_or_default();
    format!(
        "d={d}; v=$(cat \"$d/PG_VERSION\") || exit 1; c=; \
         for x in {first} \"/usr/lib/postgresql/$v/bin/pg_ctl\" \"/usr/pgsql-$v/bin/pg_ctl\" \"$(command -v pg_ctl)\"; do \
         [ -n \"$x\" ] && [ -x \"$x\" ] && {{ c=$x; break; }}; done; \
         [ -n \"$c\" ] || {{ echo \"pg_ctl of PostgreSQL $v not found on the restore host (set ssh_pg_ctl)\" >&2; exit 127; }}; \
         \"$c\" -D \"$d\" -l \"$d/nexus_restore.log\" -w -t 600 start </dev/null >/dev/null 2>&1 || \
         {{ echo \"pg_ctl start failed; end of $d/nexus_restore.log:\" >&2; tail -n 15 \"$d/nexus_restore.log\" >&2; exit 1; }}"
    )
}

pub fn pitr(ctx: &Ctx, src: &mut Source, ssh: &Ssh) -> Result<String> {
    let p = &ctx.params["params"];
    let dir = p["directory"].as_str().unwrap_or_default();
    if !valid_dir(dir) {
        bail!("directory: an absolute path of [A-Za-z0-9._/-], without `..`");
    }
    let top: Vec<&str> = ctx.params["top"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    if !top.contains(&"data") {
        bail!("this snapshot holds no base backup (point-in-time restore needs a cluster snapshot)");
    }
    let (conf, until) = recovery_conf(p)?;
    let start = p["start"].as_bool().unwrap_or(false);
    let rules: Vec<String> = p["tablespaces"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    let (spaces, new_map) = if top.contains(&"tablespaces") {
        let mut map = None;
        src.files(&[b"data/tablespace_map".to_vec()], |_, r| {
            let mut s = String::new();
            r.read_to_string(&mut s)?;
            map = Some(s);
            Ok(())
        })?;
        remap(
            &map.context("the snapshot has tablespaces but no data/tablespace_map")?,
            &rules,
        )?
    } else if !rules.is_empty() {
        bail!("tablespaces: this snapshot has no tablespaces besides the data directory");
    } else {
        (Vec::new(), String::new())
    };
    if spaces
        .iter()
        .any(|t| t.new == dir || t.new.starts_with(&format!("{dir}/")))
    {
        bail!("tablespaces: a tablespace directory may not lie inside the data directory");
    }

    let mut mk = format!("umask 077 && mkdir -- {}", sh_quote(dir));
    for t in &spaces {
        mk += &format!(" && mkdir -- {}", sh_quote(&t.new));
    }
    ssh.run(&format!("{mk} && command -v tar >/dev/null"))
        .context("creating the target directories (they must not exist; their parents must)")?;
    let none = |_: &str, c: Vec<u8>| c;
    let nothing = |_: &[String]| Vec::new();
    for t in &spaces {
        let pre = format!("tablespaces/{}", t.oid);
        let strip = format!("{pre}/");
        unpack(
            ctx,
            src,
            ssh,
            &t.new,
            std::slice::from_ref(&pre),
            &|path| path.strip_prefix(&strip).map(str::to_owned),
            &none,
            &nothing,
        )?;
    }
    let edit = |name: &str, mut c: Vec<u8>| match name {
        "postgresql.auto.conf" => {
            c.extend_from_slice(conf.as_bytes());
            c
        }
        "tablespace_map" if !new_map.is_empty() => new_map.clone().into_bytes(),
        _ => c,
    };
    let extra = |seen: &[String]| {
        let has = |n: &str| seen.iter().any(|s| s == n);
        let mut x = vec![("recovery.signal", Vec::new())];
        if !has("postgresql.auto.conf") {
            x.push(("postgresql.auto.conf", conf.clone().into_bytes()));
        }
        // the source keeps its configuration outside the data directory (Debian): a
        // minimal one, local connections only
        if !has("postgresql.conf") {
            x.push((
                "postgresql.conf",
                b"# NexusBackup: the source kept its configuration outside the data directory\n".to_vec(),
            ));
        }
        if !has("pg_hba.conf") {
            x.push(("pg_hba.conf", b"local all all peer\n".to_vec()));
        }
        if !has("pg_ident.conf") {
            x.push(("pg_ident.conf", Vec::new()));
        }
        x
    };
    let u = unpack(
        ctx,
        src,
        ssh,
        dir,
        &["data".to_owned(), "wal".to_owned()],
        &|path| match path.split_once('/') {
            Some(("data", r)) => Some(r.to_owned()),
            Some(("wal", r)) => Some(format!("nexus_wal/{r}")),
            None if path == "wal" => Some("nexus_wal".into()),
            _ => None,
        },
        &edit,
        &extra,
    )?;
    let ts = if spaces.is_empty() {
        String::new()
    } else {
        format!(
            ", tablespaces {}",
            spaces
                .iter()
                .map(|t| format!("{} → {}", t.oid, t.new))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let head = format!(
        "{} files ({} bytes) + {} WAL segments restored to {dir}{ts}; recovery to {until}, then promote",
        u.files, u.bytes, u.wal
    );
    if !start {
        return Ok(format!(
            "{head}: start PostgreSQL of the same major version on it (pg_ctl -D {dir} start)"
        ));
    }
    ctx.info(format!("{head}; starting PostgreSQL"));
    let pg_ctl = ctx.config["ssh_pg_ctl"].as_str().filter(|s| !s.is_empty());
    if pg_ctl.is_some_and(|c| !valid_dir(c)) {
        bail!("ssh_pg_ctl: an absolute path of [A-Za-z0-9._/-]");
    }
    ssh.run(&start_cmd(dir, pg_ctl))
        .context("the data directory is restored, but PostgreSQL did not start")?;
    Ok(format!(
        "{head}; PostgreSQL started on it (log {dir}/nexus_restore.log)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn restore_dirs() {
        assert!(valid_dir("/var/lib/postgresql/17/restore"));
        for bad in ["/", "rel/dir", "/a/../etc", "/a b", "/a/'x'", "/a/./b"] {
            assert!(!valid_dir(bad), "{bad}");
        }
    }

    #[test]
    fn recovery_targets() {
        let (c, u) = recovery_conf(&json!({})).unwrap();
        assert_eq!(u, "the end of the WAL");
        assert!(!c.contains("recovery_target_time") && c.contains("recovery_target_action = 'promote'"));
        let (c, u) = recovery_conf(&json!({"target_time": "2026-10-10 14:30:00+00", "port": 5499})).unwrap();
        assert!(c.contains("recovery_target_time = '2026-10-10 14:30:00+00'\n") && c.contains("port = 5499\n"));
        assert_eq!(u, "time 2026-10-10 14:30:00+00");
        let (c, _) = recovery_conf(&json!({"target_lsn": "0/3000060", "target_time": ""})).unwrap();
        assert!(c.contains("recovery_target_lsn = '0/3000060'\n"));
        let (c, u) = recovery_conf(&json!({"target_name": "before_upgrade"})).unwrap();
        assert!(c.contains("recovery_target_name = 'before_upgrade'\n"));
        assert_eq!(u, "restore point before_upgrade");
        for bad in [
            json!({"target_lsn": "0/3000060", "target_name": "x"}),
            json!({"target_lsn": "3000060"}),
            json!({"target_lsn": "0/123456789"}),
            json!({"target_name": "a'b"}),
            json!({"target_name": "a\\b"}),
            json!({"target_time": "2026-10-10'; x"}),
            json!({"port": 70000}),
        ] {
            assert!(recovery_conf(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tablespace_remap() {
        let map = "16390 /srv/ts1\n16391 /srv/fast disk\n";
        let (t, m) = remap(map, &["16390=/new/ts1".into(), "/srv/fast disk=/new/fast".into()]).unwrap();
        assert_eq!(m, "16390 /new/ts1\n16391 /new/fast\n");
        assert_eq!(
            t[1],
            Tablespace {
                oid: "16391".into(),
                old: "/srv/fast disk".into(),
                new: "/new/fast".into()
            }
        );
        let e = remap(map, &["16390=/new/ts1".into()]).unwrap_err().to_string();
        assert!(e.contains("16391 (/srv/fast disk)"), "{e}");
        for bad in [
            vec!["99=/x".to_owned(), "16390=/a".into(), "16391=/b".into()],
            vec!["16390=rel".into(), "16391=/b".into()],
            vec!["16390=/a".into(), "16391=/a".into()],
            vec!["16390".into()],
        ] {
            assert!(remap(map, &bad).is_err(), "{bad:?}");
        }
        assert_eq!(remap("", &[]).unwrap(), (vec![], String::new()));
    }

    #[test]
    fn start_command_quotes() {
        let c = start_cmd("/var/lib/pg/r1", Some("/opt/pg/bin/pg_ctl"));
        assert!(c.starts_with("d='/var/lib/pg/r1'; "), "{c}");
        assert!(
            c.contains("for x in '/opt/pg/bin/pg_ctl' \"/usr/lib/postgresql/$v/bin/pg_ctl\""),
            "{c}"
        );
        assert!(c.contains("-w -t 600 start"));
    }
}
