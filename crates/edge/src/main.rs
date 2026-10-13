//! `nexus-edge init --token <T|-> | serve [--public ADDR] [--control ADDR] | status`
//! Common options: `--state DIR` (default /var/lib/nexus-edge), `--release-keys DIR`
//! (default /usr/share/nexus-edge/release-keys). docs/edge.md.

use nexus_edge::{Edge, Files, DEFAULT_RELEASE_KEYS, DEFAULT_STATE};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!(
        "usage: nexus-edge [--state DIR] [--release-keys DIR] init --token <T|-> | serve [--public ADDR] [--control ADDR] | status"
    );
    std::process::exit(2)
}

fn main() {
    std::hint::black_box(nexus_edge::VERSION_MARKER);
    std::hint::black_box(nexus_edge::EDGE_MARKER);
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut opt = |name: &str, default: &str| -> String {
        match args.iter().position(|a| a == name) {
            Some(i) if i + 1 < args.len() => {
                let v = args.remove(i + 1);
                args.remove(i);
                v
            }
            Some(_) => usage(),
            None => default.to_string(),
        }
    };
    let files = Files {
        dir: PathBuf::from(opt("--state", DEFAULT_STATE)),
    };
    let keys = PathBuf::from(opt("--release-keys", DEFAULT_RELEASE_KEYS));
    let token = opt("--token", "");
    let public = opt("--public", &format!("[::]:{}", agent_proto::edge::DEFAULT_PUBLIC_PORT));
    let control = opt(
        "--control",
        &format!("[::]:{}", agent_proto::edge::DEFAULT_CONTROL_PORT),
    );
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init"] => {
            let mut token = token;
            if token == "-" {
                token.clear();
                let _ = std::io::stdin().read_to_string(&mut token);
            }
            nexus_edge::init(&files, &token).map(|fp| {
                println!("edge initialised; the appliance enrolls it with this token");
                println!("edge certificate sha256: {fp}");
            })
        }
        ["status"] => {
            print!("{}", nexus_edge::status(&files));
            Ok(())
        }
        ["serve"] => serve(files, keys, &public, &control),
        _ => usage(),
    };
    if let Err(e) = r {
        eprintln!("nexus-edge: {e}");
        std::process::exit(1);
    }
}

fn serve(files: Files, keys: PathBuf, public: &str, control: &str) -> Result<(), String> {
    nexus_edge::exec_update(&files, &keys);
    let edge = Arc::new(Edge::open(files, keys)?);
    eprintln!(
        "nexus-edge {}: public {public}, control {control}, certificate sha256 {}",
        nexus_edge::VERSION,
        edge.cert_sha256
    );
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let p = tokio::net::TcpListener::bind(public)
            .await
            .map_err(|e| format!("{public}: {e}"))?;
        let c = tokio::net::TcpListener::bind(control)
            .await
            .map_err(|e| format!("{control}: {e}"))?;
        edge.run(p, c).await;
        Ok(())
    })
}
