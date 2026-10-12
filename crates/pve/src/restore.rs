//! Restore options and "replace original" (docs/pve-connector.md "Restore options").
//!
//! Every full restore (VM or container) creates a *new* guest `target`; PVE
//! refuses an existing VMID (no `force`). Options: the new guest's name (`name`,
//! or `name_prefix` + the backed-up name, default `<backed-up name>-restore`), a
//! resource `pool`, `link_down` (all NICs disconnected, set after the restore and
//! before any start) and `start`.
//!
//! **Replace original** (approval `restore.replace`) swaps the restored guest in
//! for the original (the guest with the snapshot's VMID). The VMID changes: the
//! restored guest keeps `target`. Order, chosen so that any failure leaves the
//! original as it was (configuration restored, running again if it ran):
//! 1. restore to `target` (keeps the MAC addresses: the original is stopped
//!    before the new guest first starts), onboot 0, links as requested;
//! 2. stop the original (shutdown, then hard stop after the timeout);
//! 3. rename the original `<name>-replaced-<YYYYmmddHHMM>`, onboot 0 and (default)
//!    all its NICs `link_down=1`, in one configuration update;
//! 4. give the restored guest the original's name and onboot;
//! 5. start the restored guest (if requested).
//!
//! A failure in 2–5 rolls back (best effort, each step reported): the restored
//! guest gets its restore name and onboot 0 again, the original its previous
//! name / onboot / NICs and is started again if it was running. The original
//! is never deleted; removing it later is the operator's decision.

use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};

/// Options of a full restore (CLI flags of `nexus-pve restore` / `restore-ct`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RestoreOpts {
    pub name: Option<String>,
    pub name_prefix: Option<String>,
    pub start: bool,
    pub pool: Option<String>,
    pub link_down: bool,
    pub replace: bool,
    /// replace: leave the original's NICs connected (default: link_down on all)
    pub keep_original_links: bool,
}

impl RestoreOpts {
    /// `--name <n> --name-prefix <p> --pool <p> --start --link-down --replace --keep-original-links`
    pub fn parse(args: &[String]) -> Result<Self> {
        let mut o = RestoreOpts::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut val = |what: &str| -> Result<String> {
                let v = it.next().with_context(|| format!("{what} needs a value"))?;
                if !valid_name(v) {
                    bail!("{what}: invalid value {v:?}");
                }
                Ok(v.clone())
            };
            match a.as_str() {
                "--name" => o.name = Some(val("--name")?),
                "--name-prefix" => o.name_prefix = Some(val("--name-prefix")?),
                "--pool" => o.pool = Some(val("--pool")?),
                "--start" => o.start = true,
                "--link-down" => o.link_down = true,
                "--replace" => o.replace = true,
                "--keep-original-links" => o.keep_original_links = true,
                _ => bail!("unknown restore option {a:?}"),
            }
        }
        Ok(o)
    }

    /// Name of the restored guest: `name`, else `name_prefix` + the backed-up
    /// name, else `<backed-up name>-restore` (`<fallback>` if the backup has none).
    pub fn name_for(&self, backed_up: Option<&str>, fallback: &str) -> String {
        let orig = backed_up.filter(|n| !n.is_empty()).unwrap_or(fallback);
        match (&self.name, &self.name_prefix) {
            (Some(n), _) => n.clone(),
            (None, Some(p)) => format!("{p}{orig}"),
            (None, None) => format!("{orig}-restore"),
        }
    }
}

/// PVE names (VM `name`, CT `hostname`, pool ids): DNS-name characters only, 1..=63.
pub fn valid_name(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && !s.starts_with(['-', '.'])
}

/// The config key holding a guest's name.
pub fn name_key(kind: &str) -> &'static str {
    if kind == "lxc" {
        "hostname"
    } else {
        "name"
    }
}

/// `key: value` of a backed-up config (`qemu-server.conf` / `pct.conf`), main section only.
pub fn conf_value(conf: &str, key: &str) -> Option<String> {
    conf.lines()
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| Some(l.strip_prefix(key)?.strip_prefix(':')?.trim().to_owned()))
}

/// Creation parameters of the restore (`POST /nodes/{node}/qemu` resp. `/lxc`).
/// `start` is only passed to PVE when nothing has to change before the first
/// boot (no `link_down`, no replace); otherwise [`run`] starts the guest itself.
pub fn restore_params(
    kind: &str,
    target: u32,
    archive: &str,
    storage: &str,
    name: &str,
    o: &RestoreOpts,
) -> Vec<(String, String)> {
    let mut p: Vec<(String, String)> = vec![("vmid".into(), target.to_string())];
    if kind == "lxc" {
        p.push(("ostemplate".into(), archive.into()));
        p.push(("restore".into(), "1".into()));
        // PVE refuses privileged restores from backup providers
        p.push(("unprivileged".into(), "1".into()));
    } else {
        p.push(("archive".into(), archive.into()));
    }
    p.push(("storage".into(), storage.into()));
    // replace keeps the MAC addresses (and VM identity): the original is stopped first
    p.push(("unique".into(), if o.replace { "0" } else { "1" }.into()));
    p.push((name_key(kind).into(), name.into()));
    if o.replace {
        p.push(("onboot".into(), "0".into()));
    }
    if let Some(pool) = &o.pool {
        p.push(("pool".into(), pool.clone()));
    }
    if o.start && !o.link_down && !o.replace {
        p.push(("start".into(), "1".into()));
    }
    p
}

fn is_net_key(k: &str) -> bool {
    k.strip_prefix("net")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `netN` values of a live config with `link_down=1` (works for VM and CT NICs).
pub fn link_down_changes(cfg: &Map<String, Value>) -> Vec<(String, Option<String>)> {
    let mut v: Vec<(String, Option<String>)> = cfg
        .iter()
        .filter(|(k, _)| is_net_key(k))
        .filter_map(|(k, v)| {
            let opts: Vec<&str> = v
                .as_str()?
                .split(',')
                .filter(|o| !o.starts_with("link_down="))
                .collect();
            Some((k.clone(), Some(format!("{},link_down=1", opts.join(",")))))
        })
        .collect();
    v.sort();
    v
}

/// What [`run`] needs from PVE (implemented by `Cluster`; tests use a fake).
pub trait GuestOps {
    /// (node, kind) of an existing guest, `None` if there is none
    fn locate(&self, vmid: u32) -> Result<Option<(String, String)>>;
    fn config(&self, node: &str, kind: &str, vmid: u32) -> Result<Map<String, Value>>;
    /// `Some(v)` sets, `None` deletes the key
    fn set_config(&self, node: &str, kind: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()>;
    fn running(&self, node: &str, kind: &str, vmid: u32) -> Result<bool>;
    /// clean shutdown, hard stop after the timeout
    fn stop(&self, node: &str, kind: &str, vmid: u32) -> Result<()>;
    fn start(&self, node: &str, kind: &str, vmid: u32) -> Result<()>;
}

/// Outcome of [`run`], printed as `restored {json}` for the job result.
#[derive(Debug, PartialEq, serde::Serialize)]
pub struct Restored {
    pub target: u32,
    pub name: String,
    pub started: bool,
    pub link_down: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_renamed_to: Option<String>,
}

fn cfg_str(cfg: &Map<String, Value>, k: &str) -> Option<String> {
    match cfg.get(k)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Restores `orig`'s snapshot as `target` (the `restore` closure runs the PVE
/// restore task with the given parameters), then applies the options; see the
/// module doc for the replace order. `stamp` = `YYYYmmddHHMM` (UTC) for the rename.
#[allow(clippy::too_many_arguments)]
pub fn run(
    ops: &impl GuestOps,
    kind: &str,
    node: &str,
    target: u32,
    orig: u32,
    archive: &str,
    storage: &str,
    backed_up_name: Option<&str>,
    o: &RestoreOpts,
    stamp: &str,
    restore: impl FnOnce(&[(String, String)]) -> Result<()>,
) -> Result<Restored> {
    let fallback = format!("{}-{orig}", if kind == "lxc" { "ct" } else { "vm" });
    if ops.locate(target)?.is_some() {
        bail!("guest {target} already exists: choose a free VMID");
    }
    // replace: the original as it is now (nothing is changed before the restore succeeded)
    let original = if o.replace {
        if target == orig {
            bail!("replace: the restore needs a new VMID");
        }
        let (onode, okind) = ops
            .locate(orig)?
            .with_context(|| format!("replace: the original guest {orig} no longer exists; restore without replace"))?;
        if okind != kind {
            bail!("replace: guest {orig} is a {okind}, the snapshot a {kind}");
        }
        let cfg = ops.config(&onode, kind, orig)?;
        Some((onode, cfg))
    } else {
        None
    };
    let name = match &original {
        // the restored guest takes over the name at the end; until then `<name>-restore`
        Some((_, cfg)) => o.name_for(cfg_str(cfg, name_key(kind)).as_deref(), &fallback),
        None => o.name_for(backed_up_name, &fallback),
    };
    restore(&restore_params(kind, target, archive, storage, &name, o)).context("restore")?;
    eprintln!("restored {kind} {target} ({name})");
    if o.link_down {
        let cfg = ops.config(node, kind, target)?;
        ops.set_config(node, kind, target, &link_down_changes(&cfg))
            .context("link_down on the restored guest")?;
    }
    let mut out = Restored {
        target,
        name,
        started: o.start && !o.link_down && !o.replace,
        link_down: o.link_down,
        replaced: None,
        original_renamed_to: None,
    };
    let Some((onode, ocfg)) = original else {
        if o.start && !out.started {
            ops.start(node, kind, target).context("start the restored guest")?;
            out.started = true;
        }
        return Ok(out);
    };

    // ---- replace: from here on every failure rolls back
    let nk = name_key(kind);
    let oname = cfg_str(&ocfg, nk).unwrap_or(fallback);
    let renamed = format!("{oname}-replaced-{stamp}");
    let was_running = ops.running(&onode, kind, orig)?;
    let mut orig_changes = vec![
        (nk.to_owned(), Some(renamed.clone())),
        ("onboot".into(), Some("0".into())),
    ];
    if !o.keep_original_links {
        orig_changes.extend(link_down_changes(&ocfg));
    }
    // the previous values of exactly the keys we change (absent keys are deleted again)
    let orig_revert: Vec<(String, Option<String>)> = orig_changes
        .iter()
        .map(|(k, _)| (k.clone(), cfg_str(&ocfg, k)))
        .collect();
    let new_changes = vec![
        (nk.to_owned(), Some(oname.clone())),
        (
            "onboot".into(),
            Some(cfg_str(&ocfg, "onboot").unwrap_or_else(|| "0".into())),
        ),
    ];
    let new_revert = vec![
        (nk.to_owned(), Some(out.name.clone())),
        ("onboot".into(), Some("0".into())),
    ];

    let mut stage = 0;
    let res = (|| -> Result<()> {
        if was_running {
            ops.stop(&onode, kind, orig).context("stop the original")?;
        }
        stage = 1;
        ops.set_config(&onode, kind, orig, &orig_changes)
            .context("rename / isolate the original")?;
        stage = 2;
        ops.set_config(node, kind, target, &new_changes)
            .context("rename the restored guest")?;
        stage = 3;
        if o.start {
            ops.start(node, kind, target).context("start the restored guest")?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        let mut notes = Vec::new();
        if stage >= 3 {
            if let Ok(true) = ops.running(node, kind, target) {
                if let Err(x) = ops.stop(node, kind, target) {
                    notes.push(format!("stopping the restored guest {target} failed: {x:#}"));
                }
            }
        }
        if stage >= 2 {
            if let Err(x) = ops.set_config(node, kind, target, &new_revert) {
                notes.push(format!("renaming the restored guest {target} back failed: {x:#}"));
            }
        }
        if stage >= 1 {
            if let Err(x) = ops.set_config(&onode, kind, orig, &orig_revert) {
                notes.push(format!("restoring the original's configuration failed: {x:#}"));
            }
        }
        if was_running && !matches!(ops.running(&onode, kind, orig), Ok(true)) {
            if let Err(x) = ops.start(&onode, kind, orig) {
                notes.push(format!("starting the original {orig} again failed: {x:#}"));
            }
        }
        let rolled = if notes.is_empty() {
            format!(
                "rolled back: original {orig} unchanged{}",
                if was_running { " and running" } else { "" }
            )
        } else {
            format!("ROLLBACK INCOMPLETE: {}", notes.join("; "))
        };
        bail!("replace failed ({e:#}); {rolled}; the restored guest {target} is kept");
    }
    eprintln!(
        "original {kind} {orig} stopped, renamed {renamed}, onboot 0{}; {target} is now {oname}",
        if o.keep_original_links { "" } else { ", NICs link_down" }
    );
    out.name = oname;
    out.started = o.start;
    out.replaced = Some(orig);
    out.original_renamed_to = Some(renamed);
    Ok(out)
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl GuestOps for crate::backup::Cluster {
    fn locate(&self, vmid: u32) -> Result<Option<(String, String)>> {
        let res = self.api.get("/cluster/resources?type=vm")?;
        Ok(res
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["vmid"].as_u64() == Some(vmid as u64))
            .and_then(|r| Some((r["node"].as_str()?.to_owned(), r["type"].as_str()?.to_owned()))))
    }
    fn config(&self, node: &str, kind: &str, vmid: u32) -> Result<Map<String, Value>> {
        self.api.guest_config(node, kind, vmid)
    }
    fn set_config(&self, node: &str, kind: &str, vmid: u32, changes: &[(String, Option<String>)]) -> Result<()> {
        self.api.set_config(node, kind, vmid, changes)
    }
    fn running(&self, node: &str, kind: &str, vmid: u32) -> Result<bool> {
        self.api.guest_running(node, kind, vmid)
    }
    fn stop(&self, node: &str, kind: &str, vmid: u32) -> Result<()> {
        self.api
            .guest_power(node, kind, vmid, "shutdown", &[("forceStop", "1"), ("timeout", "180")])
    }
    fn start(&self, node: &str, kind: &str, vmid: u32) -> Result<()> {
        self.api.guest_power(node, kind, vmid, "start", &[])
    }
}

/// `YYYYmmddHHMM` (UTC) of a unix time.
pub fn stamp(unix: u64) -> String {
    let days = (unix / 86400) as i64;
    let secs = unix % 86400;
    // civil from days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}{:02}{:02}", secs / 3600, secs % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn parses_options() {
        let o = RestoreOpts::parse(&s(&["--name", "web1-dr", "--start", "--pool", "dr", "--link-down"])).unwrap();
        assert_eq!(o.name.as_deref(), Some("web1-dr"));
        assert!(o.start && o.link_down && !o.replace);
        assert_eq!(o.pool.as_deref(), Some("dr"));
        assert!(RestoreOpts::parse(&s(&["--name"])).is_err());
        assert!(RestoreOpts::parse(&s(&["--name", "a b"])).is_err());
        assert!(RestoreOpts::parse(&s(&["--force"])).is_err());
        assert_eq!(RestoreOpts::parse(&[]).unwrap(), RestoreOpts::default());
    }

    #[test]
    fn names() {
        let mut o = RestoreOpts::default();
        assert_eq!(o.name_for(Some("web1"), "vm-100"), "web1-restore");
        assert_eq!(o.name_for(None, "vm-100"), "vm-100-restore");
        o.name_prefix = Some("dr-".into());
        assert_eq!(o.name_for(Some("web1"), "vm-100"), "dr-web1");
        o.name = Some("x".into());
        assert_eq!(o.name_for(Some("web1"), "vm-100"), "x");
        assert_eq!(
            conf_value("cores: 1\nname: web1\n[snap]\nname: old\n", "name").as_deref(),
            Some("web1")
        );
        assert_eq!(conf_value("hostname: ct1\n", "name"), None);
        assert_eq!(stamp(0), "197001010000");
        assert_eq!(stamp(1_791_840_600), "202610122130");
    }

    fn get<'a>(p: &'a [(String, String)], k: &str) -> Option<&'a str> {
        p.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn builds_pve_params() {
        let mut o = RestoreOpts {
            start: true,
            pool: Some("dr".into()),
            ..Default::default()
        };
        let p = restore_params(
            "qemu",
            105,
            "nexus:backup/nexus-100-17",
            "local-lvm",
            "web1-restore",
            &o,
        );
        assert_eq!(get(&p, "archive"), Some("nexus:backup/nexus-100-17"));
        assert_eq!(get(&p, "name"), Some("web1-restore"));
        assert_eq!(get(&p, "pool"), Some("dr"));
        assert_eq!(get(&p, "start"), Some("1"));
        assert_eq!(get(&p, "unique"), Some("1"));
        assert_eq!(get(&p, "onboot"), None);
        // link_down must be set before the first boot: we start ourselves
        o.link_down = true;
        let p = restore_params("qemu", 105, "a", "s", "n", &o);
        assert_eq!(get(&p, "start"), None);
        o.link_down = false;
        o.replace = true;
        let p = restore_params("qemu", 105, "a", "s", "n", &o);
        assert_eq!(get(&p, "start"), None);
        assert_eq!(get(&p, "unique"), Some("0"));
        assert_eq!(get(&p, "onboot"), Some("0"));
        let p = restore_params("lxc", 205, "a", "s", "ct1-restore", &RestoreOpts::default());
        assert_eq!(get(&p, "hostname"), Some("ct1-restore"));
        assert_eq!(get(&p, "ostemplate"), Some("a"));
        assert_eq!(get(&p, "restore"), Some("1"));
        assert_eq!(get(&p, "unprivileged"), Some("1"));
        assert_eq!(get(&p, "name"), None);
        assert_eq!(get(&p, "pool"), None);
    }

    #[test]
    fn link_down_of_all_nics() {
        let cfg: Map<String, Value> = serde_json::from_str(
            r#"{"net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0","net1":"name=eth1,bridge=vmbr1,link_down=0",
                "network":"x","memory":1024}"#,
        )
        .unwrap();
        assert_eq!(
            link_down_changes(&cfg),
            vec![
                (
                    "net0".into(),
                    Some("virtio=BC:24:11:00:00:01,bridge=vmbr0,link_down=1".into())
                ),
                ("net1".into(), Some("name=eth1,bridge=vmbr1,link_down=1".into())),
            ]
        );
    }

    /// In-memory PVE: guests with config + power state; `fail` names the
    /// operation (e.g. "stop:100", "set:105") that fails once.
    #[derive(Default)]
    struct Fake {
        guests: RefCell<BTreeMap<u32, (Map<String, Value>, bool)>>,
        fail: RefCell<Option<String>>,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn with_original() -> Self {
            let f = Fake::default();
            let cfg: Map<String, Value> = serde_json::from_str(
                r#"{"name":"web1","onboot":"1","net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0","memory":2048}"#,
            )
            .unwrap();
            f.guests.borrow_mut().insert(100, (cfg, true));
            f
        }
        fn check(&self, op: String) -> Result<()> {
            self.calls.borrow_mut().push(op.clone());
            if self.fail.borrow().as_deref() == Some(op.as_str()) {
                *self.fail.borrow_mut() = None;
                bail!("injected failure at {op}");
            }
            Ok(())
        }
        fn restore(&self, p: &[(String, String)]) -> Result<()> {
            self.check("restore".into())?;
            let id: u32 = get(p, "vmid").unwrap().parse().unwrap();
            let mut cfg = Map::new();
            cfg.insert("name".into(), get(p, "name").unwrap().into());
            cfg.insert("net0".into(), "virtio=BC:24:11:00:00:01,bridge=vmbr0".into());
            if let Some(b) = get(p, "onboot") {
                cfg.insert("onboot".into(), b.into());
            }
            self.guests.borrow_mut().insert(id, (cfg, get(p, "start") == Some("1")));
            Ok(())
        }
    }

    impl GuestOps for Fake {
        fn locate(&self, vmid: u32) -> Result<Option<(String, String)>> {
            Ok(self
                .guests
                .borrow()
                .contains_key(&vmid)
                .then(|| ("pve1".into(), "qemu".into())))
        }
        fn config(&self, _: &str, _: &str, vmid: u32) -> Result<Map<String, Value>> {
            Ok(self.guests.borrow()[&vmid].0.clone())
        }
        fn set_config(&self, _: &str, _: &str, vmid: u32, ch: &[(String, Option<String>)]) -> Result<()> {
            self.check(format!("set:{vmid}"))?;
            let mut g = self.guests.borrow_mut();
            let cfg = &mut g.get_mut(&vmid).unwrap().0;
            for (k, v) in ch {
                match v {
                    Some(v) => cfg.insert(k.clone(), v.clone().into()),
                    None => cfg.remove(k),
                };
            }
            Ok(())
        }
        fn running(&self, _: &str, _: &str, vmid: u32) -> Result<bool> {
            Ok(self.guests.borrow()[&vmid].1)
        }
        fn stop(&self, _: &str, _: &str, vmid: u32) -> Result<()> {
            self.check(format!("stop:{vmid}"))?;
            self.guests.borrow_mut().get_mut(&vmid).unwrap().1 = false;
            Ok(())
        }
        fn start(&self, _: &str, _: &str, vmid: u32) -> Result<()> {
            self.check(format!("start:{vmid}"))?;
            self.guests.borrow_mut().get_mut(&vmid).unwrap().1 = true;
            Ok(())
        }
    }

    fn replace_opts() -> RestoreOpts {
        RestoreOpts {
            replace: true,
            start: true,
            ..Default::default()
        }
    }

    fn go(f: &Fake, o: &RestoreOpts) -> Result<Restored> {
        run(
            f,
            "qemu",
            "pve1",
            105,
            100,
            "nexus:backup/nexus-100-17",
            "local-lvm",
            Some("web1"),
            o,
            "202610122130",
            |p| f.restore(p),
        )
    }

    #[test]
    fn plain_restore_with_link_down_starts_after_isolating() {
        let f = Fake::with_original();
        let o = RestoreOpts {
            link_down: true,
            start: true,
            name_prefix: Some("dr-".into()),
            ..Default::default()
        };
        let r = go(&f, &o).unwrap();
        assert_eq!(r.name, "dr-web1");
        assert!(r.started);
        assert_eq!(*f.calls.borrow(), ["restore", "set:105", "start:105"]);
        let g = f.guests.borrow();
        assert!(g[&105].0["net0"].as_str().unwrap().ends_with("link_down=1"));
        assert!(g[&100].1, "original untouched");
        assert!(go(&f, &o).is_err(), "existing target refused");
    }

    #[test]
    fn replace_swaps_names_and_keeps_the_original() {
        let f = Fake::with_original();
        let r = go(&f, &replace_opts()).unwrap();
        assert_eq!(r.replaced, Some(100));
        assert_eq!(r.original_renamed_to.as_deref(), Some("web1-replaced-202610122130"));
        assert_eq!(
            *f.calls.borrow(),
            ["restore", "stop:100", "set:100", "set:105", "start:105"]
        );
        let g = f.guests.borrow();
        let (o, orun) = &g[&100];
        assert!(!orun);
        assert_eq!(o["name"], "web1-replaced-202610122130");
        assert_eq!(o["onboot"], "0");
        assert!(o["net0"].as_str().unwrap().ends_with("link_down=1"));
        let (n, nrun) = &g[&105];
        assert!(nrun);
        assert_eq!(n["name"], "web1");
        assert_eq!(n["onboot"], "1");
        assert!(!n["net0"].as_str().unwrap().contains("link_down"));
    }

    /// Failure injection at every step after the restore: the original ends up
    /// with its old configuration and running again.
    #[test]
    fn replace_failures_leave_the_original_untouched() {
        for step in ["restore", "stop:100", "set:100", "set:105", "start:105"] {
            let f = Fake::with_original();
            let before = f.guests.borrow()[&100].clone();
            *f.fail.borrow_mut() = Some(step.into());
            let e = go(&f, &replace_opts()).unwrap_err();
            let msg = format!("{e:#}");
            assert!(msg.contains("injected failure"), "{step}: {msg}");
            assert_eq!(f.guests.borrow()[&100], before, "{step}: original changed ({msg})");
            if step != "restore" {
                assert!(msg.contains("rolled back"), "{step}: {msg}");
                let g = f.guests.borrow();
                assert_eq!(g[&105].0["name"], "web1-restore", "{step}");
                assert!(!g[&105].1, "{step}: restored guest must not run next to the original");
            }
        }
    }

    #[test]
    fn replace_refusals() {
        let f = Fake::default();
        let e = go(&f, &replace_opts()).unwrap_err();
        assert!(e.to_string().contains("no longer exists"), "{e}");
        assert!(f.calls.borrow().is_empty(), "nothing restored");
        let f = Fake::with_original();
        let e = run(
            &f,
            "qemu",
            "pve1",
            100,
            100,
            "a",
            "s",
            None,
            &replace_opts(),
            "x",
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
    }
}
