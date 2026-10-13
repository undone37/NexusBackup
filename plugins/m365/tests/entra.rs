//! Phase 21e: Entra ID directory objects as the guest `e.directory` behind the
//! `entra` source option (export only) — against the Graph mock.

mod mock;

use chunkstore::TreeKind;
use m365_plugin::{Guest, M365};
use mock::*;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const SID: u64 = 5;

fn host() -> Host {
    let mut h = Host::in_process(MANIFEST.as_ref(), "m365", || M365).unwrap();
    h.source_id = SID;
    h
}

fn src() -> String {
    format!("plugin-m365-{SID}-{}", Guest::Directory.id())
}

fn snapshot(h: &Host, time: u64) -> BTreeMap<String, Option<Vec<u8>>> {
    let s = h.snapshot(&src(), time).unwrap();
    s.files
        .iter()
        .map(|e| {
            let content = (e.kind == TreeKind::File).then(|| {
                let mut b = Vec::new();
                h.store().chunk_reader(&e.chunks).read_to_end(&mut b).unwrap();
                b
            });
            (String::from_utf8(e.path.clone()).unwrap(), content)
        })
        .collect()
}

fn json_at(s: &BTreeMap<String, Option<Vec<u8>>>, prefix: &str) -> Value {
    let (_, b) = s
        .iter()
        .find(|(p, c)| p.starts_with(prefix) && c.is_some())
        .unwrap_or_else(|| panic!("{prefix} not in {:?}", s.keys().collect::<Vec<_>>()));
    serde_json::from_slice(b.as_ref().unwrap()).unwrap()
}

#[test]
fn entra_option_guest_validation() {
    let m = Mock::start();
    m.lock().add_user("Alice", true, false);
    let h = host();
    let mut cfg = m.config();
    // off by default: no directory guest, and a backup of it is refused
    let g = h.guests(&cfg).unwrap();
    assert!(!g["guests"].as_array().unwrap().iter().any(|x| x["id"] == "e.directory"));
    assert!(h.backup(&cfg, Some("e.directory")).is_err());

    cfg["entra"] = json!(true);
    let g = h.guests(&cfg).unwrap();
    let d = g["guests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "e.directory")
        .cloned()
        .unwrap();
    assert_eq!(d["tags"], json!(["type:directory"]));
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v}");
    // a missing permission names the option and the permission
    m.lock().deny.insert("/devices".into());
    let v = h.validate(&cfg).unwrap();
    assert_eq!(
        (v["valid"].as_bool(), v["field"].as_str()),
        (Some(false), Some("entra")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("Device.Read.All"), "{v}");

    // the option alone is a valid workload selection
    let mut only = m.config();
    for k in [
        "exchange",
        "onedrive",
        "sharepoint",
        "teams",
        "teams_messages",
        "groups",
    ] {
        only[k] = json!(false);
    }
    only["entra"] = json!(true);
    assert!(m365_plugin::Config::parse(&only).is_ok());
    let man: Value = serde_json::from_str(&std::fs::read_to_string(MANIFEST).unwrap()).unwrap();
    assert_eq!(
        man["kinds"][0]["config_schema"]["properties"]["entra"]["default"],
        false
    );
}

#[test]
fn directory_backup_incremental_export_only() {
    let m = Mock::start();
    let (alice, sales, laptop, app) = {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, false);
        let bob = t.add_user("Bob", false, false);
        let sales = t.add_group("Sales");
        t.add_member(&sales, &alice, false);
        t.add_member(&sales, &bob, false);
        t.add_member(&sales, &alice, true);
        let laptop = t.add_device("ALICE-LAPTOP");
        let app = t.add_application("Payroll");
        (alice, sales, laptop, app)
    };
    let h = host();
    let mut cfg = m.config();
    cfg["entra"] = json!(true);

    let b1 = h.backup(&cfg, Some("e.directory")).unwrap();
    assert!(
        b1.summary
            .contains("Entra ID: 2 users, 1 groups, 1 devices, 1 applications, 1 service-principals"),
        "{}",
        b1.summary
    );
    let s1 = snapshot(&h, b1.time);
    for d in ["users", "groups", "devices", "applications", "service-principals"] {
        assert_eq!(s1.get(d), Some(&None), "directory {d}");
    }
    let u = json_at(&s1, "users/alice@contoso.test ~");
    assert_eq!(u["id"], alice.as_str());
    let g = json_at(&s1, "groups/Sales ~");
    assert_eq!(g["id"], sales.as_str());
    assert_eq!(g["members"].as_array().unwrap().len(), 2);
    assert_eq!(g["owners"][0]["id"], alice.as_str());
    assert_eq!(json_at(&s1, "devices/ALICE-LAPTOP ~")["id"], laptop.as_str());
    let a = json_at(&s1, "applications/Payroll ~");
    assert_eq!(a["id"], app.as_str());
    assert!(a["passwordCredentials"][0].get("secretText").is_none());
    assert!(json_at(&s1, "service-principals/Payroll ~")["appId"].is_string());

    // unchanged objects are taken over; a new member changes only the group file
    let carol = m.lock().add_user("Carol", false, false);
    m.lock().add_member(&sales, &carol, false);
    let b2 = h.backup(&cfg, Some("e.directory")).unwrap();
    assert!(b2.summary.contains("(5 unchanged)"), "{}", b2.summary);
    let s2 = snapshot(&h, b2.time);
    assert_eq!(json_at(&s2, "groups/Sales ~")["members"].as_array().unwrap().len(), 3);
    assert!(s2.keys().any(|k| k.starts_with("users/carol@contoso.test ~")));

    // a type the app may not read: warning, its base files stay
    m.lock().deny.insert("/applications".into());
    let b3 = h.backup(&cfg, Some("e.directory")).unwrap();
    assert!(b3.summary.contains("could not be read"), "{}", b3.summary);
    assert!(
        h.log().iter().any(|l| l.contains("Application.Read.All")),
        "{:#?}",
        h.log()
    );
    let s3 = snapshot(&h, b3.time);
    assert_eq!(json_at(&s3, "applications/Payroll ~")["id"], app.as_str());

    // export only: the plugin refuses restores into Entra; the download works
    for (action, params) in [("to_original", json!({})), ("to_other", json!({"target": "x"}))] {
        let e = h.restore(&cfg, &src(), b2.time, action, params).unwrap_err();
        assert!(format!("{e:#}").contains("export only"), "{e:#}");
    }
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("entra.tar");
    h.export(&src(), b2.time, &["/".to_owned()], json!({}), &out).unwrap();
    let mut names = Vec::new();
    let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
    for e in ar.entries().unwrap() {
        names.push(e.unwrap().path().unwrap().to_string_lossy().into_owned());
    }
    assert!(names.iter().any(|n| n.starts_with("groups/Sales ~")), "{names:?}");
}
