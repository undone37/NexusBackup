//! Phase 18a: several app registrations (round-robin, failover on throttling),
//! 1:1 and group chats behind the `chats` flag, and restores into another
//! Microsoft 365 tenant (another source of the kind) — against the Graph mock.

mod mock;

use chunkstore::TreeKind;
use m365_plugin::{Guest, M365};
use mock::*;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::{Duration, Instant};

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const SID: u64 = 5;

fn host() -> Host {
    let mut h = Host::in_process(MANIFEST.as_ref(), "m365", || M365).unwrap();
    h.source_id = SID;
    h
}

fn src(guest: &str) -> String {
    format!("plugin-m365-{SID}-{guest}")
}

fn snapshot(h: &Host, source: &str, time: u64) -> BTreeMap<String, Option<Vec<u8>>> {
    let s = h.snapshot(source, time).unwrap();
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

/// Config with the second app registered at the mock and listed in `apps`.
fn two_apps(m: &Mock) -> Value {
    m.lock().add_app(CLIENT_ID2, CERT2, KEY2);
    let mut c = m.config();
    c["apps"] = json!([{"client_id": CLIENT_ID2, "certificate": format!("{CERT2}{KEY2}")}]);
    c
}

#[test]
fn apps_config_rules() {
    let m = Mock::start();
    let base = m.config();
    let parse = |apps: Value| {
        let mut c = base.clone();
        c["apps"] = apps;
        m365_plugin::Config::parse(&c).err().map(|e| (e.0, e.1))
    };
    let pem2 = format!("{CERT2}{KEY2}");
    assert_eq!(parse(json!([{"client_id": CLIENT_ID2, "certificate": pem2}])), None);
    let e = parse(json!([{"client_id": CLIENT_ID, "certificate": pem2}])).unwrap();
    assert!(e.0 == "apps" && e.1.contains("twice"), "{e:?}");
    let e = parse(json!([{"client_id": "x", "certificate": pem2}])).unwrap();
    assert!(e.0 == "apps" && e.1.contains("app 2"), "{e:?}");
    let e = parse(json!([{"client_id": CLIENT_ID2, "certificate": CERT2}])).unwrap();
    assert!(e.0 == "apps" && e.1.contains("private key"), "{e:?}");
    // a certificate with another app's key
    let e = parse(json!([{"client_id": CLIENT_ID2, "certificate": format!("{CERT2}{KEY}")}])).unwrap();
    assert!(e.1.contains("does not belong"), "{e:?}");

    // the manifest's schema has the list (the web form renders it)
    let man: Value = serde_json::from_str(&std::fs::read_to_string(MANIFEST).unwrap()).unwrap();
    let apps = &man["kinds"][0]["config_schema"]["properties"]["apps"];
    assert_eq!(apps["items"]["type"], "object");
    assert!(man["kinds"][0]["secret_fields"]
        .as_array()
        .unwrap()
        .contains(&json!("certificate")));
}

#[test]
fn validation_signs_in_with_every_app() {
    let m = Mock::start();
    m.lock().add_user("Alice", true, true);
    let h = host();
    let cfg = two_apps(&m);
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v}\n{:#?}", h.log());
    assert!(m.lock().per_app.get(CLIENT_ID2).is_some_and(|n| *n >= 1));
    assert!(h.log().iter().any(|l| l.contains("app 2")));
    // the second app's certificate is not registered at Entra
    m.lock().apps.get_mut(CLIENT_ID2).unwrap().0 = "c29tZXRoaW5nIGVsc2U".into();
    let v = h.validate(&cfg).unwrap();
    assert_eq!(
        (v["valid"].as_bool(), v["field"].as_str()),
        (Some(false), Some("apps")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("AADSTS700027"), "{v}");
}

#[test]
fn round_robin_and_failover_on_throttling() {
    let m = Mock::start();
    let users: Vec<String> = {
        let mut t = m.lock();
        (0..6)
            .map(|i| {
                let u = t.add_user(&format!("User{i}"), true, false);
                let f = t.add_folder(&u, None, "Inbox");
                t.add_message(&u, &f, "Hi", "x");
                u
            })
            .collect()
    };
    let h = host();
    let mut cfg = two_apps(&m);
    cfg["onedrive"] = json!(false);
    cfg["sharepoint"] = json!(false);
    cfg["teams"] = json!(false);
    cfg["teams_messages"] = json!(false);

    // round-robin: the guests spread over both apps (stable per guest)
    let starts: Vec<usize> = users
        .iter()
        .map(|u| m365_plugin::graph::pick(&Guest::User(u.clone()).id(), 2))
        .collect();
    assert!(starts.contains(&0) && starts.contains(&1), "{starts:?}");
    for u in &users {
        h.backup(&cfg, Some(&Guest::User(u.clone()).id())).unwrap();
    }
    {
        let t = m.lock();
        let (a1, a2) = (t.per_app[CLIENT_ID], t.per_app[CLIENT_ID2]);
        assert!(a1 > 0 && a2 > 0, "{a1} {a2}");
    }

    // app 1 throttled (Retry-After 30 s): the requests move to app 2 at once
    let guest = Guest::User(users[starts.iter().position(|s| *s == 0).unwrap()].clone()).id();
    m.lock().per_app.clear();
    m.lock().throttle_app.insert(CLIENT_ID.into(), 3);
    let t0 = Instant::now();
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(20),
        "no 30 s wait: {:?}",
        t0.elapsed()
    );
    assert!(b.summary.contains("1 app switches"), "{}", b.summary);
    let t = m.lock();
    assert_eq!(t.per_app[CLIENT_ID], 1, "parked after its 429");
    assert!(t.per_app[CLIENT_ID2] >= 3);
    let s = snapshot(&h, &src(&guest), b.time);
    assert_eq!(s.keys().filter(|k| k.ends_with(".eml")).count(), 1);
}

#[test]
fn chats_behind_the_flag() {
    let m = Mock::start();
    let (alice, chat1, chat2) = {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, false);
        let bob = t.add_user("Bob", true, false);
        let carol = t.add_user("Carol", true, false);
        let c1 = t.add_chat_thread("", &[&alice, &bob]);
        let c2 = t.add_chat_thread("Lunch crew", &[&alice, &bob, &carol]);
        let c3 = t.add_chat_thread("", &[&bob, &carol]);
        t.add_chat_msg(&c1, &alice, "hi Bob", None);
        t.add_chat_msg(&c1, &bob, "hi <b>Alice</b>", None);
        t.add_chat_msg(&c2, &carol, "noon?", None);
        t.add_chat_msg(&c3, &bob, "not Alice's business", None);
        (alice, c1, c2)
    };
    let h = host();
    let mut cfg = m.config();
    for k in ["onedrive", "sharepoint", "teams", "teams_messages"] {
        cfg[k] = json!(false);
    }
    let guest = Guest::User(alice.clone()).id();

    // off by default: the metered API is never called
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    assert!(!snapshot(&h, &src(&guest), b.time)
        .keys()
        .any(|k| k.starts_with("chats")));
    assert_eq!(m.count("getAllMessages"), 0);

    cfg["chats"] = json!(true);
    assert_eq!(h.validate(&cfg).unwrap()["valid"], true);
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    let s = snapshot(&h, &src(&guest), b.time);
    let files: Vec<&String> = s.keys().filter(|k| k.starts_with("chats/")).collect();
    assert_eq!(files.len(), 4, "{files:?}");
    let json_of = |s: &BTreeMap<String, Option<Vec<u8>>>, name: &str| -> Value {
        let (_, c) = s
            .iter()
            .find(|(k, _)| k.starts_with("chats/") && k.contains(name) && k.ends_with(".json"))
            .unwrap_or_else(|| panic!("{name} in {:?}", s.keys()));
        serde_json::from_slice(c.as_ref().unwrap()).unwrap()
    };
    let one = json_of(&s, "Alice, Bob");
    assert_eq!(one["chat"]["id"], chat1.as_str());
    assert_eq!(one["messages"].as_array().unwrap().len(), 2);
    let html = s
        .iter()
        .find(|(k, _)| k.contains("Lunch crew") && k.ends_with(".html"))
        .and_then(|(_, c)| c.clone())
        .unwrap();
    let html = String::from_utf8(html).unwrap();
    assert!(html.contains("noon?") && html.contains("Carol"), "{html}");

    // incremental: only the changed chat is read again
    let late = now() + 5;
    m.lock().add_chat_msg(&chat2, &alice, "12:30", Some(late));
    m.clear_requests();
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!(m.count(&format!("/chats/{}/messages", chat1.replace(':', "%3A"))), 0);
    assert_eq!(m.count2("/chats/", "/messages"), 1, "{:#?}", m.lock().requests);
    let s2 = snapshot(&h, &src(&guest), b2.time);
    assert_eq!(json_of(&s2, "Lunch crew")["messages"].as_array().unwrap().len(), 2);
    assert_eq!(json_of(&s2, "Alice, Bob"), one, "taken over from the base");

    // download only: a restore skips the chats
    let r = h
        .restore(&cfg, &src(&guest), b2.time, "to_original", json!({"paths": ["chats"]}))
        .unwrap();
    assert!(
        r.summary.contains("4 chat files (download only, skipped)"),
        "{}",
        r.summary
    );

    // protected API not granted: validation names the flag
    m.lock().protected_api = false;
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["field"], "chats", "{v}");
}

#[test]
fn restore_into_another_tenant() {
    let (m, m2) = (Mock::start(), Mock::start());
    let alice = {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, true);
        let f = t.add_folder(&alice, None, "Inbox");
        t.add_message(&alice, &f, "Contract", "signed");
        let d = t.user_drive(&alice);
        let root = t.drive_root(&d);
        t.add_item(&d, &root, "plan.txt", Some(b"the plan".to_vec()));
        alice
    };
    let zed = m2.lock().add_user("Zed", true, true);
    let h = host();
    let guest = Guest::User(alice).id();
    let b = h.backup(&m.config(), Some(&guest)).unwrap();

    // the host runs the plugin with the target source's config (other tenant, other app)
    m.clear_requests();
    let r = h
        .restore_into(
            &m2.config(),
            Some(9),
            &src(&guest),
            b.time,
            "to_other",
            json!({"target": "zed@contoso.test", "folder": "From old tenant"}),
        )
        .unwrap();
    assert!(
        r.summary.contains("1 messages") && r.summary.contains("1 files"),
        "{}",
        r.summary
    );
    let t2 = m2.lock();
    assert!(t2.folder_by_name(&zed, "From old tenant").is_some());
    assert!(t2.messages.iter().any(|x| x.user == zed && x.subject == "Contract"));
    let d = t2.user_drive(&zed);
    assert!(t2
        .tree(&d)
        .contains(&("From old tenant/plan.txt".into(), Some(b"the plan".to_vec()))));
    drop(t2);
    assert_eq!(m.lock().requests.len(), 0, "the original tenant is not contacted");

    // into another source only the to_other restore
    let e = h
        .restore_into(&m2.config(), Some(9), &src(&guest), b.time, "to_original", json!({}))
        .unwrap_err();
    assert!(format!("{e:#}").contains("another source"), "{e:#}");
}
