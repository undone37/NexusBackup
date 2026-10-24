use anyhow::{bail, Context, Result};
use setup::{check_start, script, tui, DryRunRunner, Paths, Runner, Setup, SystemRunner};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: nexus-setup [options]
       nexus-setup recover-admin [--user NAME] [--force-solo] [--root DIR] [--catalog FILE] [--keyd-dir DIR]
                                break-glass: reset a local admin account to pending activation with a new
                                one-time code; asks for the recovery key (stdin)
       nexus-setup disable-approvals [--root DIR] [--catalog FILE] [--keyd-dir DIR]
                                break-glass: switch approvals off when nobody else can approve any more;
                                asks for the recovery key (stdin)
       nexus-setup grub-password [--install [--dry-run] [--root DIR] [--catalog FILE] [--keyd-dir DIR]]
                                print the boot menu (GRUB) password derived from the recovery key (stdin);
                                needs nothing else, so it also works on another Linux machine. --install
                                (appliance, root): check the key against keyd and set the password (audited)
       nexus-setup vault-disable [--root DIR] [--catalog FILE] [--keyd-dir DIR]
                                switch vault mode off after an approved vault.disable request;
                                asks for the recovery key (stdin)
       nexus-setup restore-config (BUNDLE | --offsite TARGET.json [--appliance ID]) [--dry-run] [--root DIR] [path options]
                                new appliance, before first boot setup is finished: restore the configuration
                                of a lost appliance from a configuration backup (a downloaded bundle, or the
                                newest one on an offsite target: a JSON file {\"remote\": ...} as in a nexus-offsite job);
                                asks for the recovery key of the lost appliance (stdin)
       nexus-setup import-update BUNDLE [--root DIR] [--catalog FILE]
                                offline update bundle from a USB stick (mount it first, e.g.
                                mount -o ro /dev/sdb1 /mnt): the same checks as Settings -> Updates;
                                waits for the verification; installing stays in the web UI (approval)
       nexus-setup reset-firewall [--root DIR] [--catalog FILE]
                                clear every inbound firewall restriction (web UI reachable from any
                                address again); reset-mgmt-allow is the old name
  --root DIR                    prefix for every written path (dev/tests)    env NEXUS_SETUP_ROOT
  --dry-run                     print nmcli/hostnamectl/systemctl, run none   env NEXUS_SETUP_DRY_RUN=1
  --script FILE                 non-interactive, answers from JSON (see crate docs)
  --force-reconfigure-network   redo the network step (also on a finished appliance)
  --catalog FILE  --keyd-dir DIR  --tls-dir DIR  --metrics-token FILE
  --setup-done FILE  --sys-class-net DIR
                                override single paths                         env NEXUS_SETUP_<NAME>
                                (e.g. NEXUS_SETUP_KEYD_DIR)
exit codes: 0 done, 1 error, 2 usage, 3 wizard quit before completion";

struct Opts {
    root: PathBuf,
    dry_run: bool,
    script: Option<PathBuf>,
    force_network: bool,
    paths: Paths,
}

fn parse(args: &[String]) -> Result<Opts> {
    let env = |k: &str| std::env::var_os(format!("NEXUS_SETUP_{k}")).map(PathBuf::from);
    let mut root = env("ROOT").unwrap_or_else(|| "/".into());
    let mut dry_run = std::env::var("NEXUS_SETUP_DRY_RUN").is_ok_and(|v| v == "1");
    let (mut script, mut force_network) = (None, false);
    let mut overrides: Vec<(&str, PathBuf)> = vec![];
    for k in [
        "CATALOG",
        "KEYD_DIR",
        "TLS_DIR",
        "METRICS_TOKEN",
        "SETUP_DONE",
        "SYS_CLASS_NET",
    ] {
        if let Some(v) = env(k) {
            overrides.push((k, v));
        }
    }
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .map(PathBuf::from)
                .with_context(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "--root" => root = val()?,
            "--dry-run" => dry_run = true,
            "--script" => script = Some(val()?),
            "--force-reconfigure-network" => force_network = true,
            "--catalog" => overrides.push(("CATALOG", val()?)),
            "--keyd-dir" => overrides.push(("KEYD_DIR", val()?)),
            "--tls-dir" => overrides.push(("TLS_DIR", val()?)),
            "--metrics-token" => overrides.push(("METRICS_TOKEN", val()?)),
            "--setup-done" => overrides.push(("SETUP_DONE", val()?)),
            "--sys-class-net" => overrides.push(("SYS_CLASS_NET", val()?)),
            _ => bail!("unknown argument {a}"),
        }
    }
    let mut paths = Paths::under(&root);
    for (k, v) in overrides {
        *match k {
            "CATALOG" => &mut paths.catalog,
            "KEYD_DIR" => &mut paths.keyd_dir,
            "TLS_DIR" => &mut paths.tls_dir,
            "METRICS_TOKEN" => &mut paths.metrics_token,
            "SETUP_DONE" => &mut paths.setup_done,
            _ => &mut paths.sys_class_net,
        } = v;
    }
    if let Some(dir) = paths.setup_done.parent() {
        paths.lock = dir.join(".setup.lock");
    }
    Ok(Opts {
        root,
        dry_run,
        script,
        force_network,
        paths,
    })
}

fn run(o: Opts) -> Result<ExitCode> {
    let real = o.root == std::path::Path::new("/");
    // SAFETY: geteuid has no preconditions and cannot fail.
    if real && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root (use --root DIR --dry-run on a development machine)");
    }
    check_start(&o.paths, o.force_network)?;
    let runner: Box<dyn Runner> = if o.dry_run {
        Box::new(DryRunRunner)
    } else {
        Box::new(SystemRunner)
    };
    let mut s = Setup::open(o.paths, runner, o.dry_run, real)?;
    s.cat.audit(
        setup::ACTOR,
        "setup.run",
        "appliance",
        &serde_json::json!({"mode": if o.script.is_some() { "script" } else { "tui" },
                            "dry_run": o.dry_run, "force_reconfigure_network": o.force_network}),
    )?;
    match o.script {
        Some(f) => {
            let answers: script::Answers = serde_json::from_slice(&zeroize::Zeroizing::new(
                std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?,
            ))
            .with_context(|| format!("parsing {}", f.display()))?;
            script::run(&mut s, &answers, o.force_network, &mut std::io::stdout().lock())?;
            Ok(ExitCode::SUCCESS)
        }
        None => Ok(match tui::run(&mut s, o.force_network)? {
            tui::Outcome::Completed => ExitCode::SUCCESS,
            tui::Outcome::Quit => ExitCode::from(3),
        }),
    }
}

/// `recover-admin` (docs/phase12-contract.md §7): break-glass on the console.
fn recover_admin(args: &[String]) -> Result<ExitCode> {
    let (mut user, mut force_solo, mut rest) = (None, false, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--user" => user = Some(it.next().context("--user needs a value")?.clone()),
            "--force-solo" => force_solo = true,
            _ => rest.push(a.clone()),
        }
    }
    let o = parse(&rest)?;
    if o.dry_run || o.script.is_some() || o.force_network {
        bail!("recover-admin takes only --user, --force-solo and path options");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if o.root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    eprint!("Recovery key (as printed at first boot): ");
    let mut key = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut key)?;
    let r = setup::recover::recover_admin(&o.paths, user.as_deref(), force_solo, &key)?;
    println!("Account {} was reset and waits for activation.", r.user);
    println!();
    println!("One-time activation code (valid 72 h, shown only now):");
    println!("  {}", r.code);
    println!();
    println!(
        "Open https://<appliance>:{}/#/activate?name={} → enter the code, set a new password and enroll an authenticator.",
        setup::WEB_PORT,
        r.user
    );
    if r.forced_solo {
        println!("Recorded as --force-solo: approvals are enabled and other approvers exist.");
    }
    println!("This was audited (user.break_glass) and raised a critical alert; the web UI shows a banner until it is acknowledged.");
    Ok(ExitCode::SUCCESS)
}

/// `disable-approvals`: break-glass when approvals can no longer be granted.
fn disable_approvals(args: &[String]) -> Result<ExitCode> {
    let o = parse(args)?;
    if o.dry_run || o.script.is_some() || o.force_network {
        bail!("disable-approvals takes only path options");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if o.root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    eprint!("Recovery key (as printed at first boot): ");
    let mut key = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut key)?;
    setup::recover::disable_approvals(&o.paths, &key)?;
    println!("Approvals are disabled. Add administrators or security officers (Users), then enable approvals again");
    println!("in Settings -> Approvals. This was audited (approvals.break_glass) and raised a critical alert.");
    Ok(ExitCode::SUCCESS)
}

/// `grub-password`: the boot menu password of a recovery key; `--install` sets it.
fn grub_password(args: &[String]) -> Result<ExitCode> {
    let install = args.iter().any(|a| a == "--install");
    let rest: Vec<String> = args.iter().filter(|a| *a != "--install").cloned().collect();
    let o = parse(&rest)?;
    if o.script.is_some() || o.force_network || (!install && rest.iter().any(|a| a.starts_with("--"))) {
        bail!("grub-password takes only --install and, with it, --dry-run and path options");
    }
    let real = o.root == std::path::Path::new("/");
    // SAFETY: geteuid has no preconditions and cannot fail.
    if install && real && !o.dry_run && unsafe { libc::geteuid() } != 0 {
        bail!("--install must run as root on the appliance console");
    }
    eprint!("Recovery key (as printed at first boot): ");
    let mut key = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut key)?;
    let pw = setup::grub::password(key.trim())?;
    if install {
        keyd::check_recovery_key(&o.paths.keyd_dir, key.trim())
            .map_err(|e| anyhow::anyhow!("recovery key rejected: {e}"))?;
        let runner: Box<dyn Runner> = if o.dry_run {
            Box::new(DryRunRunner)
        } else {
            Box::new(SystemRunner)
        };
        let mut s = Setup::open(o.paths, runner, o.dry_run, real)?;
        s.grub_password(key.trim())?;
        for l in &s.log {
            eprintln!("+ {l}");
        }
        println!("The boot menu password is set (audited as setup.grub_password).");
    }
    println!("Boot menu (GRUB) user: root");
    println!("Password: {}   (type it without the spaces)", setup::grub::grouped(&pw));
    Ok(ExitCode::SUCCESS)
}

/// `vault-disable`: the console half of switching vault mode off (Phase 17c).
fn vault_disable(args: &[String]) -> Result<ExitCode> {
    let o = parse(args)?;
    if o.dry_run || o.script.is_some() || o.force_network {
        bail!("vault-disable takes only path options");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if o.root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    eprint!("Recovery key (as printed at first boot): ");
    let mut key = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut key)?;
    let id = setup::recover::vault_disable(&o.paths, &key)?;
    println!("Vault mode is off (approved request {id}). Restores and downloads no longer need approval;");
    println!("approvals stay enabled. This was audited (vault.disable) and raised a warning alert.");
    Ok(ExitCode::SUCCESS)
}

/// `restore-config`: a new appliance takes over the configuration of a lost one.
fn restore_config(args: &[String]) -> Result<ExitCode> {
    let (mut bundle, mut offsite, mut appliance, mut rest) = (None, None, None, Vec::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--offsite" => offsite = Some(PathBuf::from(it.next().context("--offsite needs a file")?)),
            "--appliance" => appliance = Some(it.next().context("--appliance needs an id")?.clone()),
            x if !x.starts_with("--") && bundle.is_none() && rest.is_empty() => bundle = Some(PathBuf::from(x)),
            _ => rest.push(a.clone()),
        }
    }
    let o = parse(&rest)?;
    if o.script.is_some() || o.force_network {
        bail!("restore-config takes a bundle or --offsite, --appliance, --dry-run and path options");
    }
    let real = o.root == std::path::Path::new("/");
    // SAFETY: geteuid has no preconditions and cannot fail.
    if real && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    let bytes = match (bundle, offsite) {
        (Some(b), None) => std::fs::read(&b).with_context(|| format!("reading {}", b.display()))?,
        (None, Some(t)) => {
            let target: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&t).with_context(|| format!("reading {}", t.display()))?)
                    .context("offsite target file")?;
            let nft = (real && !o.dry_run).then(|| std::path::Path::new("/usr/sbin/nft"));
            let (id, time, b) = setup::cfgbackup::fetch(&target, appliance.as_deref(), nft)?;
            println!(
                "Fetched the newest configuration backup of appliance {id} ({time}, {} bytes).",
                b.len()
            );
            b
        }
        _ => bail!("give either a bundle file or --offsite TARGET.json"),
    };
    let h = setup::cfgbackup::header(&bytes)?;
    println!(
        "Bundle of appliance {} (host {}), created {} (unix time), {} files.",
        h["appliance"].as_str().unwrap_or("?"),
        h["host"].as_str().unwrap_or("?"),
        h["created"],
        h["files"].as_array().map_or(0, Vec::len)
    );
    check_start(&o.paths, false)?;
    let runner: Box<dyn Runner> = if o.dry_run {
        Box::new(DryRunRunner)
    } else {
        Box::new(SystemRunner)
    };
    let mut s = Setup::open(o.paths, runner, o.dry_run, real)?;
    eprint!("Recovery key of the lost appliance: ");
    let mut key = zeroize::Zeroizing::new(String::new());
    std::io::stdin().read_line(&mut key)?;
    let r = s.restore_config(&bytes, &key)?;
    for l in &s.log {
        eprintln!("+ {l}");
    }
    println!(
        "Configuration of appliance {} restored ({} files). The services are started; the recovery key stays the same.",
        r.appliance, r.files
    );
    println!("Next: sign in to the web UI, upload the plugins again (if any), then recover the tenants' data:");
    println!(
        "Tenants -> Attach offsite copy, or nexus-offsite ... dr (manual chapter 14). Audited as setup.restore_config."
    );
    Ok(ExitCode::SUCCESS)
}

/// `reset-firewall` (old name `reset-mgmt-allow`): console recovery from an
/// inbound firewall lockout.
fn reset_firewall(args: &[String]) -> Result<ExitCode> {
    let o = parse(args)?;
    if o.dry_run || o.script.is_some() || o.force_network {
        bail!("reset-firewall takes only path options");
    }
    let real = o.root == std::path::Path::new("/");
    // SAFETY: geteuid has no preconditions and cannot fail.
    if real && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    let old = setup::recover::reset_firewall(&o.paths)?;
    if real {
        if let Err(e) = setup::recover::open_firewall(&o.paths, std::path::Path::new("/usr/sbin/nft")) {
            eprintln!("warning: could not open the firewall at once ({e:#}); the scheduler applies it within a minute");
        }
    }
    let was: Vec<String> = old.iter().map(|(s, l)| format!("{s}: {}", l.join(", "))).collect();
    println!(
        "Inbound firewall restrictions cleared (were: {}). The web UI on port {} is reachable from any address again.",
        if was.is_empty() { "none".into() } else { was.join("; ") },
        setup::WEB_PORT
    );
    println!("This was audited (firewall.reset) and raised a warning alert. Set correct source lists in Settings -> Firewall.");
    Ok(ExitCode::SUCCESS)
}

fn import_update(args: &[String]) -> Result<ExitCode> {
    let (bundle, rest) = match args.split_first() {
        Some((b, rest)) if !b.starts_with("--") => (PathBuf::from(b), rest),
        _ => bail!("usage: nexus-setup import-update BUNDLE [--root DIR] [--catalog FILE]"),
    };
    let o = parse(rest)?;
    if o.dry_run || o.script.is_some() || o.force_network {
        bail!("import-update takes only path options");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if o.root == std::path::Path::new("/") && unsafe { libc::geteuid() } != 0 {
        bail!("must run as root on the appliance console");
    }
    println!(
        "Copying {} and waiting for the verification (signature, version, checksums) ...",
        bundle.display()
    );
    let s = setup::recover::import_update(&o.paths, &bundle, std::time::Duration::from_secs(1800))?;
    let result = s["last_result"]["result"].as_str().unwrap_or("?");
    println!("{result}");
    if !result.starts_with("staged") {
        return Ok(ExitCode::FAILURE);
    }
    println!(
        "Install it under Settings -> Updates (Install now; approved by a security officer when approvals are on)."
    );
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "import-update") {
        return match import_update(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup import-update: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.first().is_some_and(|a| a == "disable-approvals") {
        keyd::harden_process();
        return match disable_approvals(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup disable-approvals: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.first().is_some_and(|a| a == "vault-disable") {
        keyd::harden_process();
        return match vault_disable(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup vault-disable: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args
        .first()
        .is_some_and(|a| a == "reset-firewall" || a == "reset-mgmt-allow")
    {
        return match reset_firewall(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup reset-firewall: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.first().is_some_and(|a| a == "restore-config") {
        keyd::harden_process();
        return match restore_config(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup restore-config: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.first().is_some_and(|a| a == "grub-password") {
        keyd::harden_process();
        return match grub_password(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup grub-password: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.first().is_some_and(|a| a == "recover-admin") {
        keyd::harden_process();
        return match recover_admin(&args[1..]) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("nexus-setup recover-admin: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let opts = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("nexus-setup: {e:#}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    // umask 077, not dumpable, memory locked: the recovery key and passwords pass through here
    keyd::harden_process();
    match run(opts) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nexus-setup: {e:#}");
            ExitCode::FAILURE
        }
    }
}
