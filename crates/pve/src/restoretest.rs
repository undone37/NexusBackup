//! Restore tests and recovery plans (docs/control-plane.md "Restore tests and
//! recovery plans"): `nexus-pve <cfg> restore-test <spec.json>`.
//!
//! - **test** (`restore_test`, recovery plan test run): every guest boots
//!   isolated on the chosen node / storage under the name `nxtest-<name>`: a VM
//!   from instant-recovery overlays that are never moved, a container from a full
//!   restore (PVE has no overlay for containers). NICs are link down, or on an
//!   admin-chosen isolated bridge / VNet (then the plan's guests reach each other).
//!   After the checks all guests of the run stay up until the last wave is
//!   checked, then each is destroyed, always: also when a check or the start
//!   failed and when the job is cancelled (SIGTERM, [`CANCEL`]).
//! - **execute** (approved recovery plan): full restores under the original
//!   VMIDs and names (or a plan's target VMID), bridges renamed by the network
//!   map, started, checked, kept. A wave with a failed guest stops the run.
//!
//! Guests start wave by wave (a wave waits for its largest `delay`, then all of
//! its guests start together); checks per guest ([`Checks`]): VM running, the
//! QEMU guest agent answers, TCP ports listening inside the guest (the network
//! is isolated, so the probe runs through the agent: `ss`/`netstat`), a custom
//! command's exit code; containers: the init process keeps running. Every guest
//! ends with one `restore-test {json}` line ([`GuestResult`]) on stdout.

use crate::backup::Cluster;
use anyhow::{bail, Context, Result};
use chunkstore::Store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Set by SIGTERM (job cancelled): checks stop, test guests are destroyed.
pub static CANCEL: AtomicBool = AtomicBool::new(false);

pub const PREFIX: &str = "nxtest-";
/// Test VMIDs: the first free ones from `vmid_base` (the scheduler spreads jobs).
pub const VMID_BASE: u32 = 990_000;
/// How long the init process must keep running (containers).
const CT_SETTLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });
/// Ports may come up after the agent: they are probed at least this long.
const PORT_GRACE: Duration = Duration::from_secs(60);

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Checks {
    /// seconds until the guest must run and its agent answer
    pub boot_timeout: u64,
    /// QEMU guest agent ping (implied by ports and command; VMs only)
    pub agent: bool,
    /// TCP ports that must be listening inside the guest (VMs only)
    pub ports: Vec<u16>,
    /// run through the guest agent (VMs only): argv, empty = none
    pub command: Vec<String>,
    pub expect_exit: i64,
    pub command_timeout: u64,
}

impl Default for Checks {
    fn default() -> Self {
        Checks {
            boot_timeout: 600,
            agent: true,
            ports: Vec::new(),
            command: Vec::new(),
            expect_exit: 0,
            command_timeout: 60,
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Guest {
    /// `vm-<vmid>` or `ct-<vmid>`
    pub source: String,
    pub time: u64,
    #[serde(default)]
    pub wave: u32,
    /// seconds before the wave starts (the wave waits for its largest delay)
    #[serde(default)]
    pub delay: u64,
    #[serde(default)]
    pub checks: Checks,
    /// execute only: VMID of the restored guest (default: the original)
    #[serde(default)]
    pub target: Option<u32>,
}

impl Guest {
    /// (container, vmid)
    pub fn parse(&self) -> Result<(bool, u32)> {
        let (ct, id) = match (self.source.strip_prefix("vm-"), self.source.strip_prefix("ct-")) {
            (Some(v), _) => (false, v),
            (_, Some(c)) => (true, c),
            _ => bail!("{}: expected vm-<vmid> or ct-<vmid>", self.source),
        };
        Ok((ct, id.parse().with_context(|| format!("{}: bad vmid", self.source))?))
    }
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Test,
    Execute,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub mode: Mode,
    pub node: String,
    pub storage: String,
    /// test: isolated bridge / VNet (else link down)
    #[serde(default)]
    pub bridge: Option<String>,
    /// execute: source bridge -> target bridge
    #[serde(default)]
    pub network_map: BTreeMap<String, String>,
    #[serde(default = "vmid_base")]
    pub vmid_base: u32,
    pub guests: Vec<Guest>,
}

fn vmid_base() -> u32 {
    VMID_BASE
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct GuestResult {
    pub source: String,
    pub time: u64,
    pub wave: u32,
    pub target: Option<u32>,
    pub name: String,
    /// passed, failed, cancelled, skipped
    pub state: &'static str,
    pub started: u64,
    pub finished: u64,
    /// seconds until the guest ran and answered (agent / init)
    pub boot_secs: Option<u64>,
    pub checks: Vec<Check>,
    pub error: Option<String>,
    /// test: the guest is gone again (false: destroying failed, clean up by hand)
    pub destroyed: Option<bool>,
}

/// What the run needs from PVE (implemented for [`PveLab`]; tests use a fake).
pub trait Lab: Sync {
    fn exists(&self, vmid: u32) -> Result<bool>;
    /// the backed-up guest name, if the snapshot has one
    fn backed_up_name(&self, g: &Guest) -> Result<Option<String>>;
    /// Creates and starts guest `target` (test: isolated, execute: for real),
    /// calls `inside` once it was started, then (test) destroys it, also on
    /// errors. Errors: create / start / destroy.
    fn session(&self, g: &Guest, target: u32, name: &str, inside: &mut dyn FnMut()) -> Result<()>;
    /// (running, pid)
    fn status(&self, ct: bool, target: u32) -> Result<(bool, Option<u64>)>;
    fn agent_ping(&self, target: u32) -> Result<()>;
    /// guest agent `get-osinfo` id (`mswindows`, `debian`, …)
    fn agent_os(&self, target: u32) -> Result<String>;
    /// (exit code, stdout + stderr)
    fn agent_exec(&self, target: u32, cmd: &[String], timeout: Duration) -> Result<(i64, String)>;
}

fn now() -> u64 {
    crate::restore::unix_now()
}

/// Sleeps `d` unless cancelled first; false when cancelled.
fn pause(d: Duration) -> bool {
    let end = Instant::now() + d;
    while Instant::now() < end {
        if CANCEL.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep((end - Instant::now()).min(Duration::from_millis(200)));
    }
    !CANCEL.load(Ordering::SeqCst)
}

/// Whether `port` is listening in `ss -ltn` / `netstat -ltn` / Windows
/// `netstat -an -p TCP` output.
pub fn listening(out: &str, port: u16) -> bool {
    let suffix = format!(":{port}");
    out.lines()
        .filter(|l| l.contains("LISTEN"))
        .any(|l| l.split_whitespace().any(|t| t.ends_with(&suffix)))
}

/// argv listing the listening TCP sockets in a guest of `os`.
pub fn port_probe(os: &str) -> Vec<String> {
    let v: &[&str] = if os == "mswindows" {
        &["netstat", "-an", "-p", "TCP"]
    } else {
        &["sh", "-c", "ss -ltn 2>/dev/null || netstat -ltn"]
    };
    v.iter().map(std::string::ToString::to_string).collect()
}

/// The checks of one started guest; returns (checks, boot seconds).
pub fn check_guest(lab: &impl Lab, ct: bool, target: u32, c: &Checks) -> (Vec<Check>, Option<u64>) {
    let start = Instant::now();
    let limit = Duration::from_secs(c.boot_timeout.max(1));
    let mut out = Vec::new();
    let check = |name: &str, ok: bool, detail: String| Check {
        name: name.into(),
        ok,
        detail,
    };
    let cancelled = |out: &mut Vec<Check>| out.push(check("cancelled", false, "the job was cancelled".into()));
    // 1. running
    let pid = loop {
        match lab.status(ct, target) {
            Ok((true, pid)) => break pid,
            Ok(_) => {}
            Err(e) => eprintln!("status of {target}: {e:#}"),
        }
        if start.elapsed() > limit {
            out.push(check(
                "running",
                false,
                format!("not running after {} s", limit.as_secs()),
            ));
            return (out, None);
        }
        if !pause(Duration::from_secs(2)) {
            cancelled(&mut out);
            return (out, None);
        }
    };
    if ct {
        // the init process must survive the first seconds (no immediate crash / stop)
        if !pause(CT_SETTLE) {
            cancelled(&mut out);
            return (out, None);
        }
        let ok = match (pid, lab.status(ct, target)) {
            (Some(p), Ok((true, Some(q)))) if p == q => Ok(p),
            (_, Ok((true, q))) => Err(format!("init PID changed or unknown ({pid:?} -> {q:?})")),
            (_, Ok(_)) => Err(format!("container stopped within {} s", CT_SETTLE.as_secs())),
            (_, Err(e)) => Err(format!("status: {e:#}")),
        };
        let boot = start.elapsed().as_secs();
        match ok {
            Ok(p) => out.push(check("init", true, format!("init PID {p} running after {boot} s"))),
            Err(e) => out.push(check("init", false, e)),
        }
        return (out, Some(boot));
    }
    out.push(check(
        "running",
        true,
        format!("running after {} s", start.elapsed().as_secs()),
    ));
    if !(c.agent || !c.ports.is_empty() || !c.command.is_empty()) {
        return (out, Some(start.elapsed().as_secs()));
    }
    // 2. guest agent
    loop {
        match lab.agent_ping(target) {
            Ok(()) => break,
            Err(_) if start.elapsed() > limit => {
                out.push(check(
                    "guest_agent",
                    false,
                    format!("the QEMU guest agent did not answer within {} s", limit.as_secs()),
                ));
                return (out, None);
            }
            Err(_) => {}
        }
        if !pause(Duration::from_secs(5)) {
            cancelled(&mut out);
            return (out, None);
        }
    }
    let boot = start.elapsed().as_secs();
    out.push(check("guest_agent", true, format!("answered after {boot} s")));
    // 3. ports, probed from inside the guest until all listen (boot timeout, at least the grace)
    if !c.ports.is_empty() {
        let probe = port_probe(&lab.agent_os(target).unwrap_or_default());
        let deadline = (start + limit).max(Instant::now() + PORT_GRACE);
        let mut last = String::new();
        let mut error;
        loop {
            error = match lab.agent_exec(target, &probe, Duration::from_secs(30)) {
                Ok((_, o)) => {
                    last = o;
                    None
                }
                Err(e) => Some(format!("{e:#}")),
            };
            if c.ports.iter().all(|p| listening(&last, *p)) || Instant::now() > deadline {
                break;
            }
            if !pause(Duration::from_secs(5)) {
                cancelled(&mut out);
                return (out, Some(boot));
            }
        }
        for p in &c.ports {
            let ok = listening(&last, *p);
            let detail = match (&error, ok) {
                (_, true) => "listening".to_owned(),
                (Some(e), false) => format!("probe failed: {e}"),
                (None, false) => "not listening".to_owned(),
            };
            out.push(check(&format!("tcp/{p}"), ok, detail));
        }
    }
    // 4. custom command
    if !c.command.is_empty() {
        match lab.agent_exec(target, &c.command, Duration::from_secs(c.command_timeout.max(1))) {
            Ok((code, o)) => {
                let o: String = o.trim().chars().take(300).collect();
                out.push(check(
                    "command",
                    code == c.expect_exit,
                    format!(
                        "exit {code} (expected {}){}",
                        c.expect_exit,
                        if o.is_empty() { String::new() } else { format!(": {o}") }
                    ),
                ));
            }
            Err(e) => out.push(check("command", false, format!("{e:#}"))),
        }
    }
    (out, Some(boot))
}

/// Name of a test guest: `nxtest-<name>`, at most 63 characters.
pub fn test_name(backed_up: Option<&str>, source: &str) -> String {
    let n = format!("{PREFIX}{}", backed_up.filter(|n| !n.is_empty()).unwrap_or(source));
    n.chars().take(63).collect()
}

/// Runs the spec wave by wave; `emit` gets every result when its guest is done.
pub fn run(lab: &impl Lab, spec: &Spec, emit: &(dyn Fn(&GuestResult) + Sync)) -> Vec<GuestResult> {
    let test = spec.mode == Mode::Test;
    let mut waves: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    for (i, g) in spec.guests.iter().enumerate() {
        waves.entry(g.wave).or_default().push(i);
    }
    let results: Mutex<Vec<Option<GuestResult>>> = Mutex::new(vec![None; spec.guests.len()]);
    let release = (Mutex::new(false), Condvar::new());
    let mut next_id = spec.vmid_base;
    let done = |i: usize, r: GuestResult| {
        emit(&r);
        results.lock().unwrap()[i] = Some(r);
    };
    std::thread::scope(|s| {
        let mut stop: Option<&'static str> = None;
        for (wave, idx) in &waves {
            let delay = idx.iter().map(|i| spec.guests[*i].delay).max().unwrap_or(0);
            if stop.is_none() && delay > 0 {
                eprintln!("wave {wave}: waiting {delay} s");
                if !pause(Duration::from_secs(delay)) {
                    stop = Some("cancelled");
                }
            }
            if CANCEL.load(Ordering::SeqCst) {
                stop = Some("cancelled");
            }
            let (tx, rx) = mpsc::channel::<bool>();
            for &i in idx {
                let g = &spec.guests[i];
                let skip = |state: &'static str, error: String| GuestResult {
                    source: g.source.clone(),
                    time: g.time,
                    wave: g.wave,
                    target: None,
                    name: String::new(),
                    state,
                    started: now(),
                    finished: now(),
                    boot_secs: None,
                    checks: Vec::new(),
                    error: Some(error),
                    destroyed: None,
                };
                if let Some(why) = stop {
                    let msg = if why == "cancelled" {
                        "the job was cancelled"
                    } else {
                        "an earlier wave failed"
                    };
                    done(i, skip(why, msg.into()));
                    continue;
                }
                let prep = (|| -> Result<(bool, u32, u32, String)> {
                    let (ct, vmid) = g.parse()?;
                    let name = lab.backed_up_name(g)?;
                    if !test {
                        let fallback = format!("{}-{vmid}", if ct { "ct" } else { "vm" });
                        return Ok((ct, vmid, g.target.unwrap_or(vmid), name.unwrap_or(fallback)));
                    }
                    while lab.exists(next_id)? {
                        next_id += 1;
                    }
                    next_id += 1;
                    Ok((ct, vmid, next_id - 1, test_name(name.as_deref(), &g.source)))
                })();
                let (ct, _, target, name) = match prep {
                    Ok(p) => p,
                    Err(e) => {
                        done(i, skip("failed", format!("{e:#}")));
                        let _ = tx.send(false);
                        continue;
                    }
                };
                let (tx, release, done) = (tx.clone(), &release, &done);
                s.spawn(move || {
                    let started = now();
                    eprintln!("wave {}: {} ({}) as {target} {name}", g.wave, g.source, g.time);
                    let mut tx = Some(tx);
                    let mut outcome: Option<(Vec<Check>, Option<u64>)> = None;
                    let res = lab.session(g, target, &name, &mut || {
                        let (checks, boot) = check_guest(lab, ct, target, &g.checks);
                        let ok = !checks.is_empty() && checks.iter().all(|c| c.ok);
                        outcome = Some((checks, boot));
                        if let Some(t) = tx.take() {
                            let _ = t.send(ok);
                        }
                        if test {
                            // the plan's other guests may need this one until the last wave is checked
                            let mut r = release.0.lock().unwrap();
                            while !*r && !CANCEL.load(Ordering::SeqCst) {
                                r = release.1.wait_timeout(r, Duration::from_millis(500)).unwrap().0;
                            }
                        }
                    });
                    if let Some(t) = tx.take() {
                        let _ = t.send(false);
                    }
                    let (checks, boot_secs) = outcome.unwrap_or_default();
                    let passed = !checks.is_empty() && checks.iter().all(|c| c.ok) && res.is_ok();
                    let state = if CANCEL.load(Ordering::SeqCst) {
                        "cancelled"
                    } else if passed {
                        "passed"
                    } else {
                        "failed"
                    };
                    done(
                        i,
                        GuestResult {
                            source: g.source.clone(),
                            time: g.time,
                            wave: g.wave,
                            target: Some(target),
                            name,
                            state,
                            started,
                            finished: now(),
                            boot_secs,
                            checks,
                            error: res.as_ref().err().map(|e| format!("{e:#}")),
                            // a destroy error is the session's last error; only test guests are destroyed
                            destroyed: test.then(|| {
                                res.as_ref()
                                    .err()
                                    .is_none_or(|e| !format!("{e:#}").contains("destroy "))
                            }),
                        },
                    );
                });
            }
            drop(tx);
            let failed = rx.iter().filter(|ok| !ok).count();
            if failed > 0 && !test && stop.is_none() {
                stop = Some("skipped");
            }
        }
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
    });
    results.into_inner().unwrap().into_iter().flatten().collect()
}

/// [`Lab`] on a PVE cluster, serving from the store.
pub struct PveLab<'a> {
    pub cluster: &'a Cluster,
    pub store: &'a Store,
    pub spec: &'a Spec,
}

impl PveLab<'_> {
    fn agent(&self, target: u32, cmd: &str) -> String {
        format!("/nodes/{}/qemu/{target}/agent/{cmd}", self.spec.node)
    }

    /// Execute: full restore under the original identity, bridges mapped, started.
    fn restore(&self, g: &Guest, ct: bool, vmid: u32, target: u32, name: &str) -> Result<()> {
        let (api, node, kind) = (
            &self.cluster.api,
            self.spec.node.as_str(),
            if ct { "lxc" } else { "qemu" },
        );
        let opts = crate::restore::RestoreOpts {
            name: Some(name.to_owned()),
            ..Default::default()
        };
        if ct {
            self.cluster
                .restore_ct(self.store, vmid, g.time, node, target, &self.spec.storage, &opts)?;
        } else {
            self.cluster
                .restore_vm(self.store, vmid, g.time, node, target, &self.spec.storage, &opts)?;
        }
        if !self.spec.network_map.is_empty() {
            let cfg = api.guest_config(node, kind, target)?;
            let changes: Vec<(String, Option<String>)> = cfg
                .iter()
                .filter(|(k, _)| crate::ir::is_net_key(k))
                .filter_map(|(k, v)| {
                    let v = v.as_str()?;
                    let m = crate::ir::map_net(v, &self.spec.network_map);
                    (m != v).then(|| (k.clone(), Some(m)))
                })
                .collect();
            if !changes.is_empty() {
                api.set_config(node, kind, target, &changes)
                    .context("network mapping")?;
            }
        }
        api.guest_power(node, kind, target, "start", &[]).context("start")
    }
}

impl Lab for PveLab<'_> {
    fn exists(&self, vmid: u32) -> Result<bool> {
        Ok(crate::restore::GuestOps::locate(self.cluster, vmid)?.is_some())
    }

    fn backed_up_name(&self, g: &Guest) -> Result<Option<String>> {
        let (ct, _) = g.parse()?;
        let m = self.store.load_manifest(&g.source, g.time)?;
        let (file, key) = if ct {
            (crate::ct::CONFIG_FILE, "hostname")
        } else {
            ("qemu-server.conf", "name")
        };
        let conf = crate::backup::read_config(self.store, &m, file)?.unwrap_or_default();
        Ok(crate::restore::conf_value(&conf, key))
    }

    fn session(&self, g: &Guest, target: u32, name: &str, inside: &mut dyn FnMut()) -> Result<()> {
        let (ct, vmid) = g.parse()?;
        let (node, storage, bridge) = (&self.spec.node, &self.spec.storage, self.spec.bridge.as_deref());
        if self.spec.mode == Mode::Execute {
            self.restore(g, ct, vmid, target, name)?;
            inside();
            return Ok(());
        }
        if !ct {
            return self
                .cluster
                .ir_session(self.store, vmid, g.time, node, target, storage, name, bridge, inside);
        }
        // containers: full restore with the links down, then isolate / start / check / destroy
        let api = &self.cluster.api;
        let opts = crate::restore::RestoreOpts {
            name: Some(name.to_owned()),
            link_down: true,
            ..Default::default()
        };
        let restored = self
            .cluster
            .restore_ct(self.store, vmid, g.time, node, target, storage, &opts);
        if let Err(e) = restored {
            if self.exists(target).unwrap_or(false) {
                let _ = crate::ir::destroy_guest(api, node, "lxc", target);
            }
            return Err(e.context("restore container"));
        }
        let started = (|| -> Result<()> {
            let cfg = api.guest_config(node, "lxc", target)?;
            let mut changes: Vec<(String, Option<String>)> = cfg
                .iter()
                .filter(|(k, _)| crate::ir::is_net_key(k))
                .filter_map(|(k, v)| Some((k.clone(), Some(crate::ir::isolate_net(v.as_str()?, bridge)))))
                .collect();
            changes.push(("onboot".into(), Some("0".into())));
            api.set_config(node, "lxc", target, &changes)?;
            api.guest_power(node, "lxc", target, "start", &[])
        })()
        .context("start container");
        if started.is_ok() {
            inside();
        }
        let destroyed = crate::ir::destroy_guest(api, node, "lxc", target);
        started?;
        destroyed
    }

    fn status(&self, ct: bool, target: u32) -> Result<(bool, Option<u64>)> {
        let kind = if ct { "lxc" } else { "qemu" };
        self.cluster.api.guest_status(&self.spec.node, kind, target)
    }

    fn agent_ping(&self, target: u32) -> Result<()> {
        self.cluster.api.post(&self.agent(target, "ping"), &[]).map(drop)
    }

    fn agent_os(&self, target: u32) -> Result<String> {
        let v = self.cluster.api.get(&self.agent(target, "get-osinfo"))?;
        Ok(v["result"]["id"].as_str().unwrap_or_default().to_owned())
    }

    fn agent_exec(&self, target: u32, cmd: &[String], timeout: Duration) -> Result<(i64, String)> {
        let api = &self.cluster.api;
        let form: Vec<(&str, &str)> = cmd.iter().map(|a| ("command", a.as_str())).collect();
        let v = api.post(&self.agent(target, "exec"), &form)?;
        let pid = v["pid"].as_u64().context("guest agent exec returned no pid")?;
        let start = Instant::now();
        loop {
            let st = api.get(&format!("{}?pid={pid}", self.agent(target, "exec-status")))?;
            if st["exited"].as_u64() == Some(1) || st["exited"].as_bool() == Some(true) {
                let text = |k: &str| st[k].as_str().unwrap_or_default().to_owned();
                return Ok((
                    st["exitcode"].as_i64().unwrap_or(-1),
                    text("out-data") + &text("err-data"),
                ));
            }
            if start.elapsed() > timeout {
                bail!("command still running after {} s", timeout.as_secs());
            }
            if !pause(Duration::from_secs(1)) {
                bail!("cancelled");
            }
        }
    }
}

/// Readiness of a recovery plan's target (`nexus-pve <cfg> lab-check <spec.json>`):
/// node online, target storage and the IR storage active with free space,
/// bridges (test bridge, network map targets) present. One JSON object.
pub fn lab_check(c: &Cluster, spec: &Spec) -> serde_json::Value {
    use serde_json::json;
    let node = &spec.node;
    let online = c
        .api
        .get("/nodes")
        .map(|v| {
            v.as_array()
                .into_iter()
                .flatten()
                .any(|n| n["node"].as_str() == Some(node) && n["status"].as_str() == Some("online"))
        })
        .map_err(|e| format!("{e:#}"));
    let storage = |id: &str| match c.api.get(&format!("/nodes/{node}/storage/{id}/status")) {
        Ok(v) => json!({"id": id, "active": v["active"].as_u64() == Some(1) || v["active"] == true,
                         "avail": v["avail"].as_u64(), "total": v["total"].as_u64()}),
        Err(e) => json!({"id": id, "error": format!("{e:#}")}),
    };
    let mut bridges: Vec<&str> = spec.network_map.values().map(String::as_str).collect();
    bridges.extend(spec.bridge.as_deref());
    bridges.sort();
    bridges.dedup();
    let known: Vec<String> = c
        .api
        .get(&format!("/nodes/{node}/network"))
        .map(|v| {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i["iface"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    // SDN VNets are bridges on the node too, but only listed by the SDN API
    let vnets: Vec<String> = c
        .api
        .get("/cluster/sdn/vnets")
        .map(|v| {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i["vnet"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let missing: Vec<&str> = bridges
        .into_iter()
        .filter(|b| !known.iter().chain(&vnets).any(|k| k == b))
        .collect();
    json!({
        "node": node,
        "online": online.as_ref().ok(),
        "error": online.as_ref().err(),
        "storage": storage(&spec.storage),
        "ir_storage": storage(&c.storage),
        "missing_bridges": missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    /// Fake PVE: guests "boot" at once; behaviour per target VMID.
    #[derive(Default)]
    struct Fake {
        taken: Vec<u32>,
        /// source -> name in the snapshot
        names: HashMap<String, String>,
        /// sources whose session fails at start
        broken: Vec<String>,
        /// sources whose agent never answers
        no_agent: Vec<String>,
        listening: String,
        exit: i64,
        log: Mutex<Vec<String>>,
        running: Mutex<HashMap<u32, String>>,
        sessions: AtomicUsize,
    }

    impl Fake {
        fn source(&self, target: u32) -> String {
            self.running.lock().unwrap().get(&target).cloned().unwrap_or_default()
        }
    }

    impl Lab for Fake {
        fn exists(&self, vmid: u32) -> Result<bool> {
            Ok(self.taken.contains(&vmid) || self.running.lock().unwrap().contains_key(&vmid))
        }
        fn backed_up_name(&self, g: &Guest) -> Result<Option<String>> {
            Ok(self.names.get(&g.source).cloned())
        }
        fn session(&self, g: &Guest, target: u32, name: &str, inside: &mut dyn FnMut()) -> Result<()> {
            self.sessions.fetch_add(1, Ordering::SeqCst);
            self.log.lock().unwrap().push(format!("create {target} {name}"));
            if self.broken.contains(&g.source) {
                self.log.lock().unwrap().push(format!("destroy {target}"));
                bail!("start VM: boom");
            }
            self.running.lock().unwrap().insert(target, g.source.clone());
            inside();
            self.running.lock().unwrap().remove(&target);
            self.log.lock().unwrap().push(format!("destroy {target}"));
            Ok(())
        }
        fn status(&self, _ct: bool, target: u32) -> Result<(bool, Option<u64>)> {
            Ok((true, Some(u64::from(target))))
        }
        fn agent_ping(&self, target: u32) -> Result<()> {
            if self.no_agent.contains(&self.source(target)) {
                bail!("QEMU guest agent is not running");
            }
            Ok(())
        }
        fn agent_os(&self, _: u32) -> Result<String> {
            Ok("debian".into())
        }
        fn agent_exec(&self, _: u32, cmd: &[String], _: Duration) -> Result<(i64, String)> {
            if cmd[0] == "sh" {
                return Ok((0, self.listening.clone()));
            }
            Ok((self.exit, "degraded\n".into()))
        }
    }

    fn guest(source: &str, wave: u32, checks: Checks) -> Guest {
        Guest {
            source: source.into(),
            time: 1000,
            wave,
            delay: 0,
            checks,
            target: None,
        }
    }

    fn spec(mode: Mode, guests: Vec<Guest>) -> Spec {
        Spec {
            mode,
            node: "pve1".into(),
            storage: "local-lvm".into(),
            bridge: None,
            network_map: BTreeMap::new(),
            vmid_base: 990_000,
            guests,
        }
    }

    #[test]
    fn port_listing_parsers() {
        let ss = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
                  LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\n\
                  LISTEN 0      511             [::]:443          [::]:*\n";
        assert!(listening(ss, 22) && listening(ss, 443));
        assert!(!listening(ss, 80) && !listening(ss, 2));
        let win = "  TCP    0.0.0.0:3389    0.0.0.0:0    LISTENING\n  TCP  10.0.0.5:50000  10.0.0.9:22  ESTABLISHED\n";
        assert!(listening(win, 3389));
        assert!(!listening(win, 22), "established connections do not count");
        assert_eq!(port_probe("mswindows")[0], "netstat");
        assert_eq!(port_probe("debian")[0], "sh");
        assert_eq!(test_name(Some("web1"), "vm-101"), "nxtest-web1");
        assert_eq!(test_name(None, "vm-101"), "nxtest-vm-101");
        assert_eq!(test_name(Some(&"x".repeat(80)), "vm-1").len(), 63);
    }

    /// Two waves: all guests stay up until the last wave was checked, then all
    /// are destroyed; free test VMIDs from the base; failures per guest.
    #[test]
    fn test_run_waves_checks_and_cleanup() {
        let fake = Fake {
            taken: vec![990_000, 990_002],
            names: [("vm-101".to_owned(), "db1".to_owned())].into(),
            broken: vec!["vm-103".into()],
            no_agent: vec!["vm-104".into()],
            listening: "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\n".into(),
            exit: 0,
            ..Default::default()
        };
        let ports = Checks {
            ports: vec![5432],
            command: vec!["systemctl".into(), "is-system-running".into()],
            ..Default::default()
        };
        let quick = Checks {
            boot_timeout: 1,
            ..Default::default()
        };
        let s = spec(
            Mode::Test,
            vec![
                guest("vm-101", 1, ports),
                guest("ct-102", 1, Checks::default()),
                guest("vm-103", 2, Checks::default()),
                guest("vm-104", 2, quick),
            ],
        );
        let emitted = Mutex::new(Vec::new());
        // ct-102's settle time: 10 s
        let r = run(&fake, &s, &|g| emitted.lock().unwrap().push(g.source.clone()));
        assert_eq!(emitted.lock().unwrap().len(), 4);
        let by: HashMap<&str, &GuestResult> = r.iter().map(|g| (g.source.as_str(), g)).collect();
        let db = by["vm-101"];
        assert_eq!(
            (db.state, db.target, db.name.as_str()),
            ("passed", Some(990_001), "nxtest-db1")
        );
        let names: Vec<&str> = db.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["running", "guest_agent", "tcp/5432", "command"]);
        assert_eq!(db.destroyed, Some(true));
        let ct = by["ct-102"];
        assert_eq!((ct.state, ct.target), ("passed", Some(990_003)));
        assert_eq!(ct.checks[0].name, "init");
        assert_eq!(ct.name, "nxtest-ct-102");
        let broken = by["vm-103"];
        assert_eq!(broken.state, "failed");
        assert!(broken.error.as_deref().unwrap().contains("boom"));
        assert!(broken.checks.is_empty());
        let noagent = by["vm-104"];
        assert_eq!(noagent.state, "failed");
        assert!(noagent.checks.iter().any(|c| c.name == "guest_agent" && !c.ok));
        // wave 1 was still up while wave 2 started; everything destroyed at the end
        let log = fake.log.lock().unwrap().clone();
        let pos = |x: &str| {
            log.iter()
                .position(|l| l == x)
                .unwrap_or_else(|| panic!("{x} in {log:?}"))
        };
        assert!(pos("destroy 990001") > pos("create 990005 nxtest-vm-104"), "{log:?}");
        for t in [990_001, 990_003, 990_004, 990_005] {
            pos(&format!("destroy {t}"));
        }
        assert!(fake.running.lock().unwrap().is_empty());
    }

    /// Execute: original VMIDs and names, a failed wave stops the run.
    #[test]
    fn execute_stops_after_a_failed_wave() {
        let fake = Fake {
            names: [("vm-101".to_owned(), "db1".to_owned())].into(),
            broken: vec!["vm-101".into()],
            ..Default::default()
        };
        let mut g2 = guest("vm-105", 2, Checks::default());
        g2.target = Some(205);
        let s = spec(Mode::Execute, vec![guest("vm-101", 1, Checks::default()), g2]);
        let r = run(&fake, &s, &|_| {});
        assert_eq!(
            (r[0].state, r[0].target, r[0].name.as_str()),
            ("failed", Some(101), "db1")
        );
        assert_eq!(r[0].destroyed, None);
        assert_eq!(r[1].state, "skipped");
        assert_eq!(fake.sessions.load(Ordering::SeqCst), 1);
        // a command with the wrong exit code fails the check
        let fake = Fake {
            exit: 3,
            ..Default::default()
        };
        let c = Checks {
            command: vec!["true".into()],
            expect_exit: 0,
            ..Default::default()
        };
        let (checks, _) = check_guest(&fake, false, 1, &c);
        let cmd = checks.iter().find(|c| c.name == "command").unwrap();
        assert!(!cmd.ok && cmd.detail.starts_with("exit 3 (expected 0): degraded"));
    }

    #[test]
    fn spec_defaults() {
        let s: Spec = serde_json::from_str(
            r#"{"mode":"test","node":"pve1","storage":"local-lvm","guests":[{"source":"vm-100","time":5}]}"#,
        )
        .unwrap();
        assert_eq!(s.vmid_base, VMID_BASE);
        assert_eq!(s.guests[0].checks, Checks::default());
        assert!(s.guests[0].checks.agent);
        assert!(serde_json::from_str::<Spec>(r#"{"mode":"x","node":"n","storage":"s","guests":[]}"#).is_err());
        assert!(guest("host-1", 0, Checks::default()).parse().is_err());
        assert_eq!(guest("ct-7", 0, Checks::default()).parse().unwrap(), (true, 7));
    }
}
