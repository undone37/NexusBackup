//! The plugin binary in the real sandbox against the TrueNAS lab VM
//! (lab/truenas/, skipped unless configured; same inputs as crate truenas's lab test):
//!
//! ```sh
//! NEXUS_TRUENAS_LAB=/home/ah/nexus-lab/truenas/lab-cli.json \
//! NEXUS_TRUENAS_SUMS=<output of `sh.py data.sh sums`> \
//!   cargo test -p truenas-plugin --test lab -- --nocapture
//! ```
//! validate, guests, then per guest (dataset) a full and an incremental backup
//! into the harness's temp store with the real API client and `ssh` inside the
//! sandbox; every regular file must match the sums taken on TrueNAS, and at most
//! two `nexus-<sid>-*` snapshots (reference + last) stay per dataset. Source id
//! `NEXUS_TRUENAS_PLUGIN_SID` (default 900, not the built-in source's).

#[path = "../../../crates/truenas/tests/support/mod.rs"]
mod support;

use chunkstore::TreeKind;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

#[test]
fn lab_plugin_rounds() {
    let Ok(p) = std::env::var("NEXUS_TRUENAS_LAB") else {
        eprintln!("NEXUS_TRUENAS_LAB not set: skipped");
        return;
    };
    let c: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    let rd = |v: &Value| std::fs::read_to_string(v.as_str().unwrap()).unwrap();
    let (a, s) = (&c["api"], &c["ssh"]);
    // the plugin connects to the address itself (no connect_addr): the certificate is pinned
    let (host, port) = match a["connect_addr"].as_str() {
        Some(x) => {
            let sa: std::net::SocketAddr = x.parse().unwrap();
            (sa.ip().to_string(), sa.port())
        }
        None => (
            a["host"].as_str().unwrap().to_owned(),
            a["port"].as_u64().unwrap() as u16,
        ),
    };
    let host_key: Vec<String> = rd(&s["known_hosts_file"])
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .unwrap()
        .split_whitespace()
        .skip(1)
        .take(2)
        .map(str::to_owned)
        .collect();
    let cfg = json!({
        "host": host, "port": port, "ca_pem": rd(&a["ca_file"]), "user": a["user"],
        "api_key": rd(&a["key_file"]).trim(),
        "ssh_host": s["host"], "ssh_port": s["port"], "ssh_user": s["user"],
        "ssh_host_key": host_key.join(" "), "ssh_private_key": rd(&s["key_file"]),
        "datasets": c["datasets"], "recursive": c["recursive"],
    });
    let mut h = Host::binary(
        concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json").as_ref(),
        env!("CARGO_BIN_EXE_truenas-plugin").as_ref(),
        "truenas",
    )
    .unwrap();
    h.source_id = std::env::var("NEXUS_TRUENAS_PLUGIN_SID").map_or(900, |v| v.parse().unwrap());
    h.timeout = std::time::Duration::from_secs(3600);
    h.idle = std::time::Duration::from_secs(900);
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v} {:#?}", h.log());
    let g = h.guests(&cfg).unwrap();
    println!("guests {g}");
    let want = std::env::var("NEXUS_TRUENAS_SUMS")
        .ok()
        .map(|f| support::sums(&std::fs::read_to_string(f).unwrap()));
    for guest in g["guests"].as_array().unwrap() {
        let guest = guest["id"].as_str().unwrap();
        let ds = guest.replace('.', "/");
        for round in ["full", "incremental"] {
            let t = std::time::Instant::now();
            let r = h.backup(&cfg, Some(guest)).unwrap();
            println!("{round} {guest} in {:.1?}: {r:?}", t.elapsed());
            assert_eq!(r.base.is_some(), round == "incremental");
            let Some(want) = &want else { continue };
            let entries = support::tree(h.store(), &r.source, r.time, "files");
            let mut got = BTreeMap::new();
            for e in entries.iter().filter(|e| e.kind == TreeKind::File) {
                let mut hs = Sha256::new();
                let mut rd = h.store().chunk_reader(&e.chunks);
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = rd.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    hs.update(&buf[..n]);
                }
                got.insert(e.path.clone(), format!("{:x}", hs.finalize()));
            }
            for e in entries.iter().filter(|e| e.kind == TreeKind::Hardlink) {
                let v = got[e.link_target.as_ref().unwrap()].clone();
                got.insert(e.path.clone(), v);
            }
            let exp = want.get(&ds).cloned().unwrap_or_default();
            assert_eq!(got.len(), exp.len(), "{ds}: file count");
            for (p, hsum) in &exp {
                assert_eq!(got.get(p), Some(hsum), "{ds}: {}", String::from_utf8_lossy(p));
            }
            println!("verified {} files of {ds}", exp.len());
        }
    }
    let mut api = truenas::api::Api::connect(&truenas::api::ApiConfig {
        host: host.clone(),
        port,
        connect_addr: None,
        ca_pem: rd(&a["ca_file"]).into_bytes(),
        user: a["user"].as_str().unwrap().to_owned(),
        api_key: rd(&a["key_file"]).trim().to_owned(),
        timeout: std::time::Duration::from_secs(120),
    })
    .unwrap();
    for guest in g["guests"].as_array().unwrap() {
        let ds = guest["id"].as_str().unwrap().replace('.', "/");
        let ours: Vec<String> = truenas::api::Nas::snapshots(&mut api, &ds)
            .unwrap()
            .into_iter()
            .filter(|n| truenas::parse_snap_name(h.source_id, n).is_some())
            .collect();
        println!("{ds}: {ours:?}");
        assert_eq!(ours.len(), 2, "{ds}: reference + last");
    }
    api.close();
    for l in h.log() {
        println!("{l}");
    }
}
