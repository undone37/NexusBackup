use anyhow::{bail, Context, Result};
use setup::{check_start, script, tui, DryRunRunner, Paths, Runner, Setup, SystemRunner};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: nexus-setup [options]
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
