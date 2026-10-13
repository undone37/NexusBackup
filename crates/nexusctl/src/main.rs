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
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let ca = cli.ca.or_else(|| env("NEXUS_CA"));
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
