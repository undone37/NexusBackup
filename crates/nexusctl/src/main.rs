use anyhow::{Context, Result};
use nexusctl::{parse_global, run, Client, Conn, USAGE};

fn main() {
    if let Err(e) = real_main() {
        eprintln!("nexusctl: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cli = parse_global(&args)?;
    if cli.cmd.is_empty() || matches!(cli.cmd[0].as_str(), "help" | "--help" | "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    // Phase 33: several appliances, each with its own token from the fleet configuration
    if cli.cmd[0] == "fleet" {
        let (out, code) = nexusctl::fleet::cli(&cli.cmd[1..], cli.json)?;
        print!("{out}");
        std::process::exit(code);
    }
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let ca = cli.ca.or_else(|| env("NEXUS_CA"));
    // #28: an administrator's session, not a token
    if cli.cmd[0] == "update" {
        let url = cli
            .url
            .or_else(|| env("NEXUS_URL"))
            .context("--url or NEXUS_URL is required")?;
        let ca_pem = ca
            .map(|p| std::fs::read_to_string(&p).with_context(|| format!("reading {p}")))
            .transpose()?;
        return update(&url, ca_pem.as_deref(), &cli.cmd[1..], cli.json);
    }
    let conn = Conn {
        url: cli
            .url
            .or_else(|| env("NEXUS_URL"))
            .context("--url or NEXUS_URL is required")?,
        token: cli
            .token
            .or_else(|| env("NEXUS_TOKEN"))
            .context("--token or NEXUS_TOKEN is required")?,
        ca_pem: ca
            .map(|p| std::fs::read_to_string(&p).with_context(|| format!("reading {p}")))
            .transpose()?,
    };
    let client = Client::new(conn)?;
    print!("{}", run(&client, &cli.cmd, cli.json)?);
    Ok(())
}

/// `update upload <bundle> --user NAME [--wait S]`
fn update(url: &str, ca_pem: Option<&str>, args: &[String], as_json: bool) -> Result<()> {
    let (mut file, mut user, mut wait) = (None, None, 1800u64);
    let mut it = args.iter();
    match it.next().map(String::as_str) {
        Some("upload") => {}
        _ => anyhow::bail!("usage: nexusctl update upload <bundle.tar> --user NAME [--wait SECONDS]"),
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--user" => user = it.next().cloned(),
            "--wait" => {
                wait = it
                    .next()
                    .context("--wait: seconds")?
                    .parse()
                    .context("--wait: seconds")?;
            }
            f if file.is_none() && !f.starts_with("--") => file = Some(std::path::PathBuf::from(f)),
            other => anyhow::bail!("unexpected argument {other:?}"),
        }
    }
    let file = file.context("the bundle file is required")?;
    let user = user.context("--user NAME (an administrator) is required")?;
    let password = prompt(&format!("password of {user}: "), false)?;
    let mut totp = || prompt("TOTP code: ", true);
    let mut login = nexusctl::update::Login {
        user,
        password,
        totp: &mut totp,
    };
    let v = nexusctl::update::upload(
        url,
        ca_pem,
        &mut login,
        &file,
        std::time::Duration::from_secs(wait),
        &mut |m| eprintln!("{m}"),
    )?;
    if as_json {
        println!("{v:#}");
    } else {
        println!(
            "{}: {}",
            v["status"].as_str().unwrap_or("?"),
            v["last_result"]["result"].as_str().unwrap_or("?")
        );
    }
    let staged = v["last_result"]["result"]
        .as_str()
        .is_some_and(|r| r.starts_with("staged"));
    std::process::exit(if staged { 0 } else { 1 })
}

/// One line from the terminal, without echo for the password (stty on /dev/tty); without a terminal (scripts)
/// the next line of stdin.
fn prompt(label: &str, echo: bool) -> Result<String> {
    use std::io::{BufRead, Write};
    let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            anyhow::bail!(
                "{}: no terminal and nothing on stdin",
                label.trim_end_matches([':', ' '])
            );
        }
        return Ok(line.trim_end_matches(['\r', '\n']).to_owned());
    };
    let stty = |arg: &str| {
        std::process::Command::new("stty")
            .arg(arg)
            .stdin(tty.try_clone()?)
            .status()
            .map(drop)
    };
    write!(&tty, "{label}")?;
    if !echo {
        stty("-echo")?;
    }
    let mut line = String::new();
    let r = std::io::BufReader::new(&tty).read_line(&mut line);
    if !echo {
        stty("echo")?;
        writeln!(&tty)?;
    }
    r?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
