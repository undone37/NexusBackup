//! The M365 plugin against the in-repo Graph mock (tests/mock) and the real host
//! code (plugin_sdk::testing): token flow with the certificate assertion,
//! validation, guests, full + incremental (delta) backups per workload, throttling,
//! paging, token refresh, ranged downloads, restores to the original and to another
//! user / site / team, the Teams protected-API path, and the real binary in the
//! real sandbox.

mod mock;

use chunkstore::TreeKind;
use m365_plugin::M365;
use mock::*;
use plugin_sdk::testing::Host;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");
const SID: u64 = 5;
const BIG: usize = (32 << 20) + 777;

fn host() -> Host {
    let mut h = Host::in_process(MANIFEST.as_ref(), "m365", || M365).unwrap();
    h.source_id = SID;
    h
}

fn src(guest: &str) -> String {
    format!("plugin-m365-{SID}-{guest}")
}

/// path → (is dir, content) of a snapshot.
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

fn find<'a>(
    s: &'a BTreeMap<String, Option<Vec<u8>>>,
    prefix: &str,
    contains: &str,
) -> Option<(&'a String, &'a Vec<u8>)> {
    s.iter()
        .filter_map(|(p, c)| Some((p, c.as_ref()?)))
        .find(|(p, _)| p.starts_with(prefix) && p.contains(contains))
}

fn big() -> Vec<u8> {
    (0..BIG).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

struct Ids {
    alice: String,
    bob: String,
    carol: String,
    bob_inbox: String,
    inbox: String,
    projects: String,
    sent: String,
    msgs: Vec<String>,
    docs: String,
    deep: String,
    report: String,
    pct: String,
    marketing: String,
    archive: String,
    team: String,
    general: String,
    design: String,
    t1: String,
    t2: String,
}

fn seed(m: &Mock) -> Ids {
    let mut t = m.lock();
    let alice = t.add_user("Alice", true, true);
    let bob = t.add_user("Bob", true, true);
    let carol = t.add_user("Carol", false, false);
    let ext = t.add_user("Guesty", false, false);
    t.users.iter_mut().find(|u| u.id == ext).unwrap().member = false;
    let inbox = t.add_folder(&alice, None, "Inbox");
    let projects = t.add_folder(&alice, Some(&inbox), "Projects/2026");
    let sent = t.add_folder(&alice, None, "Sent Items");
    let msgs = vec![
        t.add_message(&alice, &inbox, "Hello", "first"),
        t.add_message(&alice, &inbox, "Invoice 42", "pay"),
        t.add_message(&alice, &inbox, "Lunch?", "noon"),
        t.add_message(&alice, &projects, "Plan", "q4"),
        t.add_message(&alice, &projects, "Budget", "money"),
        t.add_message(&alice, &sent, "Re: Hello", "hi back"),
    ];
    t.add_event(&alice, "Planning");
    t.add_event(&alice, "Review");
    t.add_contact(&alice, None, "Bob Builder");
    t.add_contact(&alice, None, "Dora Explorer");
    let sup = t.add_contact_folder(&alice, None, "Suppliers");
    t.add_contact(&alice, Some(&sup), "Sam Supplier");
    let eu = t.add_contact_folder(&alice, Some(&sup), "EU");
    t.add_contact(&alice, Some(&eu), "Eve Euro");
    let d = t.user_drive(&alice);
    let root = t.drive_root(&d);
    let docs = t.add_item(&d, &root, "Documents", None);
    let report = t.add_item(&d, &docs, "report.docx", Some(b"report v1".to_vec()));
    let deep = t.add_item(&d, &docs, "Deep", None);
    t.add_item(&d, &deep, "notes.txt", Some(b"deep notes".to_vec()));
    t.add_item(&d, &root, "big.bin", Some(big()));
    let pct = t.add_item(&d, &root, "100% done.txt", Some(b"done".to_vec()));
    let bd = t.user_drive(&bob);
    let broot = t.drive_root(&bd);
    t.add_item(&bd, &broot, "bob.txt", Some(b"bob's file".to_vec()));
    let bob_inbox = t.add_folder(&bob, None, "Inbox");
    t.add_message(&bob, &bob_inbox, "Welcome Bob", "hi");
    let marketing = t.add_site("Marketing", &["Documents", "Assets"]);
    let archive = t.add_site("Archive", &["Documents"]);
    let (md, ma) = (
        t.site(&marketing).drives[0].clone(),
        t.site(&marketing).drives[1].clone(),
    );
    let (mdr, mar) = (t.drive_root(&md), t.drive_root(&ma));
    let camp = t.add_item(&md, &mdr, "Campaign", None);
    t.add_item(&md, &camp, "plan.pptx", Some(b"slides".to_vec()));
    t.add_item(&ma, &mar, "logo.svg", Some(b"<svg/>".to_vec()));
    let team = t.add_team("Project X", &["General", "Design"]);
    let (general, design) = {
        let tm = t.team(&team);
        (tm.channels[0].0.clone(), tm.channels[1].0.clone())
    };
    let td = t.team(&team).drive.clone();
    let tdr = t.drive_root(&td);
    let gen = t.add_item(&td, &tdr, "General", None);
    t.add_item(&td, &gen, "minutes.md", Some(b"# minutes".to_vec()));
    let t1 = t.add_chat(&team, &general, &alice, "kickoff", None, None);
    t.add_chat(&team, &general, &bob, "sounds good", Some(&t1), None);
    let t2 = t.add_chat(&team, &design, &alice, "colors", None, None);
    Ids {
        alice,
        bob,
        carol,
        bob_inbox,
        inbox,
        projects,
        sent,
        msgs,
        docs,
        deep,
        report,
        pct,
        marketing,
        archive,
        team,
        general,
        design,
        t1,
        t2,
    }
}

fn guest_of(kind: &str, id: &str) -> String {
    match kind {
        "u" => m365_plugin::Guest::User(id.into()).id(),
        "t" => m365_plugin::Guest::Team(id.into()).id(),
        "g" => m365_plugin::Guest::Group(id.into()).id(),
        _ => m365_plugin::site_guest(id).unwrap().id(),
    }
}

#[test]
fn token_flow_validation_and_guests() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v}\n{:#?}", h.log());
    assert!(
        m.lock().assertions_ok >= 1,
        "the mock verified a signed client assertion"
    );
    assert!(h.log().iter().any(|l| l.contains("certificate thumbprint")));

    let invalid = |cfg: &Value| {
        let v = h.validate(cfg).unwrap();
        assert_eq!(v["valid"], false, "{v}");
        (
            v["field"].as_str().unwrap().to_owned(),
            v["message"].as_str().unwrap().to_owned(),
        )
    };
    let mut c = cfg.clone();
    c["tenant_id"] = json!("fabrikam.onmicrosoft.com");
    assert_eq!(invalid(&c).0, "tenant_id");
    let mut c = cfg.clone();
    c["client_id"] = json!("99999999-2222-3333-4444-555555555555");
    let (f, msg) = invalid(&c);
    assert!(f == "client_id" && msg.contains("AADSTS700016"), "{f}: {msg}");
    let mut c = cfg.clone();
    c["sharepoint_host"] = json!("fabrikam.sharepoint.com");
    let (f, msg) = invalid(&c);
    assert!(
        f == "sharepoint_host" && msg.contains("contoso.sharepoint.com"),
        "{msg}"
    );
    let mut c = cfg.clone();
    c["onedrive_host"] = json!("contoso.sharepoint.com");
    assert_eq!(invalid(&c).0, "onedrive_host");
    let mut c = cfg.clone();
    c["private_key"] = json!("-----BEGIN PRIVATE KEY-----\nMA==\n-----END PRIVATE KEY-----");
    assert_eq!(invalid(&c).0, "private_key");

    // a missing application permission
    m.lock().deny.insert("/v1.0/users".into());
    let (f, msg) = invalid(&cfg);
    assert!(f == "client_id" && msg.contains("User.Read.All"), "{f}: {msg}");
    m.lock().deny.clear();

    // protected Teams APIs not (yet) granted by Microsoft
    m.lock().protected_api = false;
    let (f, msg) = invalid(&cfg);
    assert!(
        f == "teams_messages" && msg.contains("protected Teams APIs"),
        "{f}: {msg}"
    );
    let mut c = cfg.clone();
    c["teams_messages"] = json!(false);
    assert_eq!(
        h.validate(&c).unwrap()["valid"],
        true,
        "without messages the source is valid"
    );
    m.lock().protected_api = true;

    // another certificate registered on the app: Entra refuses the assertion
    let reg = m.lock().registered.clone();
    m.lock().registered = "c29tZXRoaW5nIGVsc2U".into();
    let (f, msg) = invalid(&cfg);
    assert!(f == "certificate" && msg.contains("AADSTS700027"), "{f}: {msg}");
    m.lock().registered = reg;

    let g = h.guests(&cfg).unwrap();
    let list = g["guests"].as_array().unwrap();
    let has = |id: &str| list.iter().any(|x| x["id"] == id);
    assert!(has(&guest_of("u", &ids.alice)) && has(&guest_of("u", &ids.carol)));
    assert!(has(&guest_of("s", &ids.marketing)) && has(&guest_of("t", &ids.team)));
    // 3 users, 3 sites (incl. the team's), 1 team, 1 group (the team's)
    assert_eq!(list.len(), 3 + 3 + 1 + 1, "no guest users, no personal sites: {g}");
    // v1.5 tags (auto-protect): type per object, unlicensed users
    let tags = |id: &str| list.iter().find(|x| x["id"] == id).unwrap()["tags"].clone();
    assert_eq!(tags(&guest_of("u", &ids.alice)), serde_json::json!(["type:user"]));
    assert_eq!(
        tags(&guest_of("u", &ids.carol)),
        serde_json::json!(["type:user", "license:none"])
    );
    assert_eq!(tags(&guest_of("s", &ids.marketing)), serde_json::json!(["type:site"]));
    assert_eq!(tags(&guest_of("t", &ids.team)), serde_json::json!(["type:team"]));
    assert!(list
        .iter()
        .all(|x| plugin_sdk::proto::valid_guest_id(x["id"].as_str().unwrap())));
}

#[test]
fn mailbox_and_onedrive_full_incremental_and_formats() {
    let m = Mock::start();
    let ids = seed(&m);
    m.lock().break_downloads = 1; // the first range breaks off half-way: resumed
    let h = host();
    let cfg = m.config();
    let guest = guest_of("u", &ids.alice);
    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    let s1 = snapshot(&h, &src(&guest), b1.time);
    // mail as .eml (MIME as Graph returned it), folder names with `/` encoded
    let (p, eml) = find(&s1, "mail/Inbox/", "Hello ~").unwrap();
    assert!(p.ends_with(".eml"), "{p}");
    assert_eq!(eml, &m.lock().msg(&ids.msgs[0]).mime);
    assert!(s1.contains_key("mail/Inbox/Projects%2F2026"), "{:#?}", s1.keys());
    assert!(find(&s1, "mail/Inbox/Projects%2F2026/", "Budget").is_some());
    assert!(find(&s1, "mail/Sent Items/", "Re: Hello").is_some());
    // calendar as .ics with the Graph JSON embedded; contacts as .vcf
    let (p, ics) = find(&s1, "calendar/Calendar/", "Planning").unwrap();
    let ics = String::from_utf8(ics.clone()).unwrap();
    assert!(
        p.starts_with("calendar/Calendar/2026-10-12 Planning ~") && p.ends_with(".ics"),
        "{p}"
    );
    assert!(
        ics.starts_with("BEGIN:VCALENDAR\r\n") && ics.contains("ATTENDEE;CN=\"Bob\""),
        "{ics}"
    );
    assert!(m365_plugin::format::embedded_graph(&ics).is_some());
    let (_, vcf) = find(&s1, "contacts/Contacts/", "Bob Builder").unwrap();
    assert!(String::from_utf8_lossy(vcf).contains("FN:Bob Builder"));
    assert!(find(&s1, "contacts/Suppliers/EU/", "Eve Euro").is_some());
    // OneDrive files as they are (big one in ranges, resumed after the break)
    assert_eq!(s1["onedrive/Documents/report.docx"].as_deref(), Some(&b"report v1"[..]));
    assert_eq!(
        s1["onedrive/Documents/Deep/notes.txt"].as_deref(),
        Some(&b"deep notes"[..])
    );
    assert_eq!(s1["onedrive/100%25 done.txt"].as_deref(), Some(&b"done"[..]));
    assert!(s1["onedrive/big.bin"].as_deref() == Some(&big()[..]), "big file intact");
    assert!(m.count("/_dl/") >= 3, "two ranges + one resumed: {}", m.count("/_dl/"));

    // changes: new, updated, deleted and moved mail; new event; file update, folder rename, delete, add
    {
        let mut t = m.lock();
        t.add_message(&ids.alice, &ids.inbox, "Brand new", "new");
        t.update_message(&ids.msgs[3], "Plan v2", "q4 again");
        t.delete_message(&ids.msgs[1]);
        t.move_message(&ids.msgs[5], &ids.inbox);
        t.add_event(&ids.alice, "Retro");
        t.update_item(&ids.report, b"report v2".to_vec());
        t.rename_item(&ids.deep, "Deeper");
        t.delete_item(&ids.pct);
        let d = t.user_drive(&ids.alice);
        t.add_item(&d, &ids.docs, "new.txt", Some(b"fresh".to_vec()));
    }
    m.clear_requests();
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    let s2 = snapshot(&h, &src(&guest), b2.time);
    assert_eq!(
        m.count("/$value"),
        3,
        "only new, changed and moved messages are downloaded"
    );
    assert_eq!(
        m.count2("/messages/delta?", "token="),
        4,
        "every folder (3 + Recoverable Items Deletions) continued from its delta link"
    );
    assert_eq!(m.count2("/root/delta?", "token="), 1);
    assert_eq!(
        m.count("/_dl/"),
        3,
        "report, new.txt, renamed notes.txt — big.bin is not downloaded again"
    );
    assert!(find(&s2, "mail/Inbox/", "Brand new").is_some());
    // Phase 39 C4: sender and recipients of every mail, sealed with the snapshot; unchanged mails keep theirs
    let meta = |t| -> BTreeMap<String, serde_json::Value> {
        let b = h
            .store()
            .read_snap_file(&src(&guest), t, plugin_sdk::proto::ITEM_META_FILE)
            .unwrap()
            .unwrap();
        serde_json::from_slice(&b).unwrap()
    };
    let (m1, m2) = (meta(b1.time), meta(b2.time));
    let (hello, rec) = m1.iter().find(|(p, _)| p.contains("Hello ~")).unwrap();
    assert_eq!(rec["from"], "alice@contoso.test");
    assert_eq!(rec["to"], serde_json::json!(["bob@contoso.test"]));
    assert_eq!(rec["subject"], "Hello");
    assert_eq!(m2[hello], *rec, "carried over for the unchanged mail");
    assert!(m2.keys().any(|p| p.contains("Brand new")), "the new mail has one");
    assert_eq!(
        m2.len(),
        s2.keys()
            .filter(|p| p.starts_with("mail/") && p.ends_with(".eml"))
            .count(),
        "one per mail"
    );
    assert!(find(&s2, "mail/", "Invoice 42").is_none(), "deleted");
    assert!(find(&s2, "mail/Inbox/", "Re: Hello").is_some() && find(&s2, "mail/Sent Items/", "Re: Hello").is_none());
    assert!(find(&s2, "mail/Inbox/Projects%2F2026/", "Plan v2").is_some());
    assert!(find(&s2, "calendar/", "Retro").is_some());
    assert_eq!(s2["onedrive/Documents/report.docx"].as_deref(), Some(&b"report v2"[..]));
    assert_eq!(
        s2["onedrive/Documents/Deeper/notes.txt"].as_deref(),
        Some(&b"deep notes"[..])
    );
    assert!(!s2.contains_key("onedrive/Documents/Deep") && !s2.contains_key("onedrive/100%25 done.txt"));
    assert_eq!(s2["onedrive/Documents/new.txt"].as_deref(), Some(&b"fresh"[..]));
    assert!(s2["onedrive/big.bin"].as_deref() == Some(&big()[..]));
    // unchanged: 3 old mails, 2 events, 4 contacts, big.bin
    assert!(b2.unchanged >= 10, "{b2:?}");
    assert!(b2.transferred < 64 << 10, "{b2:?}");

    // nothing changed: everything is Unchanged, nothing transferred
    m.clear_requests();
    let b3 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!((b3.transferred, b3.files), (0, b3.unchanged), "{b3:?}");
    assert_eq!(snapshot(&h, &src(&guest), b3.time), s2);
    assert_eq!(m.count("/$value") + m.count("/_dl/"), 0);
}

#[test]
fn throttling_paging_token_refresh() {
    let m = Mock::start();
    let ids = seed(&m);
    {
        let mut t = m.lock();
        t.page_size = 2;
        t.faults = vec![
            Fault {
                path: "/messages/delta".into(),
                status: 429,
                count: 2,
            },
            Fault {
                path: "/root/delta".into(),
                status: 503,
                count: 1,
            },
            Fault {
                path: "/content".into(),
                status: 429,
                count: 1,
            },
        ];
        t.revoke_after = Some(6);
    }
    let h = host();
    let guest = guest_of("u", &ids.alice);
    let b = h.backup(&m.config(), Some(&guest)).unwrap();
    assert!(b.summary.contains("(4 throttled"), "{}", b.summary);
    assert!(m.lock().assertions_ok >= 2, "token refreshed after the 401");
    assert!(m.count("skip=") >= 3, "pages followed");
    let s = snapshot(&h, &src(&guest), b.time);
    assert_eq!(s.keys().filter(|k| k.ends_with(".eml")).count(), 6);
    assert_eq!(s.keys().filter(|k| k.ends_with(".vcf")).count(), 4);

    // short-lived tokens are renewed before they expire
    m.lock().token_lifetime = 120;
    let before = m.lock().assertions_ok;
    h.backup(&m.config(), Some(&guest)).unwrap();
    assert!(
        m.lock().assertions_ok - before >= 3,
        "a new token per request when < 5 min are left"
    );
}

#[test]
fn restore_mailbox_and_onedrive_to_original_and_other_user() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let guest = guest_of("u", &ids.alice);
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    let source = src(&guest);

    // to the original mailbox, only one folder subtree, into a named new folder
    let r = h
        .restore(
            &cfg,
            &source,
            b.time,
            "to_original",
            json!({"paths": ["mail/Inbox"], "folder": "Recovered"}),
        )
        .unwrap();
    assert!(r.summary.contains("5 messages"), "{}", r.summary);
    {
        let t = m.lock();
        let rec = t.folder_by_name(&ids.alice, "Recovered").unwrap().id.clone();
        let inbox2 = t
            .folders
            .iter()
            .find(|f| f.parent.as_deref() == Some(&rec) && f.name == "Inbox")
            .unwrap();
        let proj2 = t
            .folders
            .iter()
            .find(|f| f.parent.as_deref() == Some(&inbox2.id))
            .unwrap();
        assert_eq!(proj2.name, "Projects/2026");
        let orig = t.messages.iter().find(|x| x.id == ids.msgs[0]).unwrap();
        assert!(
            t.messages.iter().any(|x| x.folder == inbox2.id && x.mime == orig.mime),
            "MIME imported as is"
        );
        assert_eq!(t.messages.iter().filter(|x| x.folder == proj2.id).count(), 2);
        assert_eq!(
            t.messages
                .iter()
                .filter(|x| x.folder == ids.inbox && !x.deleted)
                .count(),
            3,
            "originals untouched"
        );
    }
    // never overwrite: the same folder again fails, nothing is merged into it
    let e = h
        .restore(
            &cfg,
            &source,
            b.time,
            "to_original",
            json!({"paths": ["mail/Inbox"], "folder": "Recovered"}),
        )
        .unwrap_err();
    assert!(format!("{e:#}").contains("ErrorFolderExists"), "{e:#}");

    // OneDrive to the original drive: new folder, small files by PUT, the big one by upload session
    let r = h
        .restore(&cfg, &source, b.time, "to_original", json!({"paths": ["onedrive"]}))
        .unwrap();
    assert!(r.summary.contains("4 files"), "{}", r.summary);
    let folder = r.summary.split('"').nth(1).unwrap().to_owned();
    assert!(folder.starts_with("Restored "), "{}", r.summary);
    {
        let t = m.lock();
        let tree = t.tree(&t.user_drive(&ids.alice));
        let get = |p: &str| tree.iter().find(|x| x.0 == p).and_then(|x| x.1.clone());
        assert_eq!(
            get(&format!("{folder}/Documents/report.docx")).as_deref(),
            Some(&b"report v1"[..])
        );
        assert_eq!(
            get(&format!("{folder}/Documents/Deep/notes.txt")).as_deref(),
            Some(&b"deep notes"[..])
        );
        assert_eq!(
            get(&format!("{folder}/100% done.txt")).as_deref(),
            Some(&b"done"[..]),
            "names decoded"
        );
        assert!(get(&format!("{folder}/big.bin")).as_deref() == Some(&big()[..]));
        assert_eq!(
            get("Documents/report.docx").as_deref(),
            Some(&b"report v1"[..]),
            "original kept"
        );
    }
    assert!(
        m.count("/createUploadSession") == 1 && m.count("PUT /_up/") == 4,
        "33 MiB in 10 MiB fragments"
    );
    let e = h
        .restore(
            &cfg,
            &source,
            b.time,
            "to_original",
            json!({"paths": ["onedrive"], "folder": folder}),
        )
        .unwrap_err();
    assert!(format!("{e:#}").contains("exists already"), "{e:#}");

    // everything to another user (leaver scenario), by UPN
    let r = h
        .restore(
            &cfg,
            &source,
            b.time,
            "to_other",
            json!({"target": "bob@contoso.test", "folder": "From Alice"}),
        )
        .unwrap();
    assert!(
        r.summary.contains("6 messages") && r.summary.contains("2 events") && r.summary.contains("4 contacts"),
        "{}",
        r.summary
    );
    let t = m.lock();
    assert!(t.folder_by_name(&ids.bob, "From Alice").is_some());
    let cal = t
        .calendars
        .iter()
        .find(|c| c.1 == ids.bob && c.2 == "From Alice – Calendar")
        .unwrap();
    let evs: Vec<&Value> = t.events.iter().filter(|e| e.0 == cal.0).map(|e| &e.1).collect();
    assert_eq!(evs.len(), 2);
    assert!(
        evs.iter()
            .all(|e| e.get("attendees").is_none() && e["subject"].is_string()),
        "no invitations"
    );
    let cf = t
        .contact_folders
        .iter()
        .find(|f| f.1 == ids.bob && f.3 == "From Alice")
        .unwrap()
        .0
        .clone();
    let subs: Vec<&String> = t
        .contact_folders
        .iter()
        .filter(|f| f.2.as_deref() == Some(&cf))
        .map(|f| &f.3)
        .collect();
    assert!(
        subs.contains(&&"Suppliers – EU".to_owned()) && subs.contains(&&"Contacts".to_owned()),
        "{subs:?}"
    );
    let tree = t.tree(&t.user_drive(&ids.bob));
    assert!(tree.iter().any(|x| x.0 == "From Alice/Documents/report.docx"));
    drop(t);
    let e = h
        .restore(
            &cfg,
            &source,
            b.time,
            "to_other",
            json!({"target": "nobody@contoso.test"}),
        )
        .unwrap_err();
    assert!(format!("{e:#}").contains("not found"), "{e:#}");
}

#[test]
fn sharepoint_site_backup_and_restores() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let guest = guest_of("s", &ids.marketing);
    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    let s1 = snapshot(&h, &src(&guest), b1.time);
    assert_eq!(
        s1["libraries/Documents/Campaign/plan.pptx"].as_deref(),
        Some(&b"slides"[..])
    );
    assert_eq!(s1["libraries/Assets/logo.svg"].as_deref(), Some(&b"<svg/>"[..]));
    let ma = m.lock().site(&ids.marketing).drives[1].clone();
    {
        let mut t = m.lock();
        let r = t.drive_root(&ma);
        t.add_item(&ma, &r, "banner.png", Some(b"png".to_vec()));
    }
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!((b2.unchanged, b2.transferred), (2, 3), "{b2:?}");

    // to the original site: library with the same name, new folder
    h.restore(&cfg, &src(&guest), b2.time, "to_original", json!({"folder": "Back"}))
        .unwrap();
    {
        let t = m.lock();
        let s = t.site(&ids.marketing).clone();
        assert!(t.tree(&s.drives[0]).iter().any(|x| x.0 == "Back/Campaign/plan.pptx"));
        assert!(t.tree(&s.drives[1]).iter().any(|x| x.0 == "Back/banner.png"));
    }
    // to another site by URL: no "Assets" library there → default library, Back/Assets/…
    h.restore(
        &cfg,
        &src(&guest),
        b2.time,
        "to_other",
        json!({"target": "https://contoso.sharepoint.com/sites/archive", "folder": "Back"}),
    )
    .unwrap();
    let t = m.lock();
    let ad = t.site(&ids.archive).drives[0].clone();
    let tree = t.tree(&ad);
    assert!(tree.iter().any(|x| x.0 == "Back/Campaign/plan.pptx"), "{tree:?}");
    assert!(tree.iter().any(|x| x.0 == "Back/Assets/logo.svg"), "{tree:?}");
}

#[test]
fn teams_files_messages_protected_api_and_restore() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let guest = guest_of("t", &ids.team);

    m.lock().protected_api = false;
    let e = h.backup(&cfg, Some(&guest)).unwrap_err();
    assert!(format!("{e:#}").contains("protected Teams APIs"), "{e:#}");
    assert!(h.store().list_snapshots().unwrap().is_empty(), "nothing committed");
    m.lock().protected_api = true;

    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    let s1 = snapshot(&h, &src(&guest), b1.time);
    assert_eq!(s1["files/General/minutes.md"].as_deref(), Some(&b"# minutes"[..]));
    let (p, thread) = find(&s1, "channels/General/", "Topic kickoff").unwrap();
    assert!(p.ends_with(".json"), "{p}");
    let doc: Value = serde_json::from_slice(thread).unwrap();
    assert_eq!(doc["root"]["id"], ids.t1.as_str());
    assert_eq!(doc["replies"].as_array().unwrap().len(), 1);
    assert!(find(&s1, "channels/Design/", "Topic colors").is_some());
    assert!(m.count("model=B") >= 1, "export API with the payment model");

    // a new reply in thread 1 and a new thread: only those are fetched again
    {
        let mut t = m.lock();
        t.add_chat(
            &ids.team,
            &ids.general,
            &ids.bob,
            "one more thing",
            Some(&ids.t1),
            Some(now()),
        );
        t.add_chat(&ids.team, &ids.design, &ids.bob, "fonts", None, Some(now()));
    }
    m.clear_requests();
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert!(
        m.count("$filter=lastModifiedDateTime") == 1,
        "export since the last backup"
    );
    assert_eq!(m.count("/replies"), 2, "changed threads only");
    assert_eq!(
        m.count(&format!("/messages/{}", ids.t2)),
        0,
        "unchanged thread not fetched"
    );
    let s2 = snapshot(&h, &src(&guest), b2.time);
    let (_, thread) = find(&s2, "channels/General/", "Topic kickoff").unwrap();
    let doc: Value = serde_json::from_slice(thread).unwrap();
    assert_eq!(doc["replies"].as_array().unwrap().len(), 2);
    assert!(find(&s2, "channels/Design/", "Topic fonts").is_some());
    assert!(find(&s2, "channels/Design/", "Topic colors").is_some());
    assert!(b2.unchanged >= 2, "{b2:?}");

    // restore to the original team: migration channels with the original authors and times
    let r = h
        .restore(&cfg, &src(&guest), b2.time, "to_original", json!({}))
        .unwrap();
    assert!(
        r.summary.contains("5 channel messages") && r.summary.contains("1 files"),
        "{}",
        r.summary
    );
    let t = m.lock();
    let team = t.team(&ids.team);
    let restored: Vec<_> = team.channels.iter().filter(|c| c.2).collect();
    assert_eq!(restored.len(), 2, "{:?}", team.channels);
    assert!(
        restored.iter().all(|c| c.3 && c.1.contains("(restored ")),
        "migration completed"
    );
    let gen2 = restored.iter().find(|c| c.1.starts_with("General")).unwrap().0.clone();
    let imported: Vec<&Value> = t
        .chat
        .iter()
        .filter(|(_, m)| m["channelIdentity"]["channelId"] == gen2.as_str())
        .map(|(_, m)| m)
        .collect();
    assert_eq!(imported.len(), 3);
    let orig = t.chat.iter().find(|(_, m)| m["id"] == ids.t1.as_str()).unwrap();
    assert!(imported
        .iter()
        .any(|m| m["createdDateTime"] == orig.1["createdDateTime"] && m["replyToId"].is_null()));
    assert!(t
        .tree(&team.drive)
        .iter()
        .any(|x| x.0.ends_with("/General/minutes.md") && x.0.starts_with("Restored ")));
    let _ = (&ids.design, &ids.projects, &ids.sent, &ids.carol);
}

#[test]
fn guests_without_data_and_bad_requests() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    // a user without mailbox and OneDrive: an empty but valid snapshot
    let b = h.backup(&cfg, Some(&guest_of("u", &ids.carol))).unwrap();
    assert!(
        b.summary.contains("no Exchange Online mailbox") && b.summary.contains("no OneDrive"),
        "{}",
        b.summary
    );
    // no guest selected / unknown guests
    let e = h.backup(&cfg, None).unwrap_err();
    assert!(format!("{e:#}").contains("per object"), "{e:#}");
    assert!(h.backup(&cfg, Some("x.1")).is_err());
    // a workload switched off
    let mut c = cfg.clone();
    c["sharepoint"] = json!(false);
    assert!(h.backup(&c, Some(&guest_of("s", &ids.marketing))).is_err());
}

/// The real binary in the real sandbox (Landlock: TCP only to the configured endpoint
/// port, here the mock's) against the mock over TLS with its own CA.
#[test]
fn sandboxed_binary() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = Host::binary(MANIFEST.as_ref(), env!("CARGO_BIN_EXE_m365-plugin").as_ref(), "m365").unwrap();
    let mut cfg = m.config();
    cfg["teams_messages"] = json!(false);
    let v = h.validate(&cfg).unwrap();
    assert_eq!(v["valid"], true, "{v}\n{:#?}", h.log());
    assert!(h.log().iter().any(|l| l.contains("landlock")), "{:?}", h.log());
    let guest = guest_of("u", &ids.bob);
    let source = format!("plugin-m365-1-{guest}");
    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    m.lock().add_message(&ids.bob, &ids.bob_inbox, "late", "x");
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert!(b2.unchanged >= 2, "{b2:?}");
    let s = snapshot(&h, &source, b2.time);
    assert_eq!(s["onedrive/bob.txt"].as_deref(), Some(&b"bob's file"[..]));
    let _ = b1;
}

/// Items that keep failing after Graph's retries are skipped and reported (contract
/// v1.7 `Warnings`): the snapshot commits, the failed items are asked for again next
/// time; a folder whose listing fails keeps its base items.
#[test]
fn failed_items_are_skipped_and_reported() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let guest = guest_of("u", &ids.alice);
    {
        let mut t = m.lock();
        t.broken.insert(ids.msgs[2].clone());
        t.broken.insert(ids.report.clone());
    }
    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!(b1.warnings, 2, "{b1:?}");
    assert!(
        b1.warning_samples.iter().any(|s| s.starts_with("mail/Inbox/Lunch? ~"))
            && b1
                .warning_samples
                .iter()
                .any(|s| s.starts_with("onedrive/Documents/report.docx: ")),
        "{:?}",
        b1.warning_samples
    );
    assert!(b1.summary.contains("2 items could not be read"), "{}", b1.summary);
    assert!(h
        .log()
        .iter()
        .any(|l| l.starts_with(&format!("warnings {}/{}: 2 items", src(&guest), b1.time))));
    let s1 = snapshot(&h, &src(&guest), b1.time);
    assert!(find(&s1, "mail/Inbox/", "Lunch?").is_none() && find(&s1, "mail/Inbox/", "Hello ~").is_some());
    assert!(!s1.contains_key("onedrive/Documents/report.docx") && s1.contains_key("onedrive/Documents/Deep/notes.txt"));

    // fixed: the next (incremental) backup fetches exactly the skipped items again
    m.lock().broken.clear();
    // and the calendar listing fails now: its events of the base are kept
    m.lock().deny.insert("/calendars/cal-".into());
    m.clear_requests();
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!(b2.warnings, 1, "{b2:?}");
    assert!(
        b2.warning_samples[0].starts_with("calendar/Calendar: "),
        "{:?}",
        b2.warning_samples
    );
    let s2 = snapshot(&h, &src(&guest), b2.time);
    assert!(find(&s2, "mail/Inbox/", "Lunch?").is_some());
    assert_eq!(s2["onedrive/Documents/report.docx"].as_deref(), Some(&b"report v1"[..]));
    assert!(
        find(&s2, "calendar/Calendar/", "Planning").is_some(),
        "base events kept"
    );
    assert_eq!(m.count("/$value"), 1, "only the skipped message");
    assert_eq!(m.count("/_dl/"), 1, "only the skipped file");
    m.lock().deny.clear();
    let b3 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!((b3.warnings, b3.transferred), (0, 0), "{b3:?}");
}

#[test]
fn recoverable_items_backup_and_restore() {
    let m = Mock::start();
    let ids = seed(&m);
    let h = host();
    let cfg = m.config();
    let guest = guest_of("u", &ids.alice);
    let rec = m.lock().recoverable(&ids.alice);
    m.lock().add_message(&ids.alice, &rec, "Purged contract", "gone?");
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    let s = snapshot(&h, &src(&guest), b.time);
    let (p, _) = find(&s, "recoverable/Deletions/", "Purged contract").unwrap();
    assert!(p.ends_with(".eml"), "{p}");
    assert!(find(&s, "mail/", "Purged contract").is_none(), "not under mail/");
    let r = h
        .restore(
            &cfg,
            &src(&guest),
            b.time,
            "to_original",
            json!({"paths": ["recoverable"], "folder": "Back"}),
        )
        .unwrap();
    assert!(r.summary.contains("1 deleted messages"), "{}", r.summary);
    let t = m.lock();
    let back = t.folder_by_name(&ids.alice, "Back").unwrap().id.clone();
    let f = t
        .folders
        .iter()
        .find(|f| f.parent.as_deref() == Some(&back) && f.name == "Restored deleted items")
        .unwrap();
    assert!(t
        .messages
        .iter()
        .any(|x| x.folder == f.id && x.subject == "Purged contract"));
}

#[test]
fn groups_guests_backup_and_restore() {
    let m = Mock::start();
    let ids = seed(&m);
    let (sales, conv) = {
        let mut t = m.lock();
        let sales = t.add_group("Sales");
        let conv = t.add_conversation(&sales, "Q4 pipeline", &["numbers?", "attached"]);
        t.add_conversation(&sales, "Offsite", &["where"]);
        t.add_group_event(&sales, "Kickoff");
        let d = t.group(&sales).drive.clone();
        let r = t.drive_root(&d);
        t.add_item(&d, &r, "deals.xlsx", Some(b"deals".to_vec()));
        (sales, conv)
    };
    let h = host();
    let cfg = m.config();
    // guests: groups (team-backed too) and their sites tagged site:team
    let g = h.guests(&cfg).unwrap();
    let list = g["guests"].as_array().unwrap();
    let tags = |id: &str| list.iter().find(|x| x["id"] == id).map(|x| x["tags"].clone());
    assert_eq!(tags(&guest_of("g", &sales)), Some(json!(["type:group"])));
    assert_eq!(tags(&guest_of("g", &ids.team)), Some(json!(["type:group"])));
    let site_of = |gid: &str| guest_of("s", &m.lock().group(gid).site);
    assert_eq!(tags(&site_of(&sales)), Some(json!(["type:site", "site:team"])));
    assert_eq!(tags(&site_of(&ids.team)), Some(json!(["type:site", "site:team"])));
    assert_eq!(tags(&guest_of("s", &ids.marketing)), Some(json!(["type:site"])));

    let guest = guest_of("g", &sales);
    let b1 = h.backup(&cfg, Some(&guest)).unwrap();
    assert!(b1.summary.contains("group calendar not readable"), "{}", b1.summary);
    let s1 = snapshot(&h, &src(&guest), b1.time);
    let (p, doc) = find(&s1, "conversations/", "Q4 pipeline ~").unwrap();
    assert!(p.ends_with(".json"), "{p}");
    let doc: Value = serde_json::from_slice(doc).unwrap();
    assert_eq!(doc["conversation"]["id"], conv.as_str());
    assert_eq!(doc["threads"][0]["posts"].as_array().unwrap().len(), 2);
    assert_eq!(s1["files/deals.xlsx"].as_deref(), Some(&b"deals"[..]));
    assert!(!s1.keys().any(|k| k.starts_with("calendar/")));

    // a new post: only that conversation is read again; the calendar once Graph allows it
    m.lock().add_post(&conv, "closed!");
    m.lock().group_calendar = true;
    m.clear_requests();
    let b2 = h.backup(&cfg, Some(&guest)).unwrap();
    assert_eq!(m.count("/posts"), 1, "unchanged conversation not re-read");
    let s2 = snapshot(&h, &src(&guest), b2.time);
    let (_, doc) = find(&s2, "conversations/", "Q4 pipeline ~").unwrap();
    let doc: Value = serde_json::from_slice(doc).unwrap();
    assert_eq!(doc["threads"][0]["posts"].as_array().unwrap().len(), 3);
    assert!(find(&s2, "calendar/", "2026-11-02 Kickoff").is_some());

    // restore: files into a new folder of the group's drive; conversations are download-only
    let r = h
        .restore(&cfg, &src(&guest), b2.time, "to_original", json!({"folder": "Back"}))
        .unwrap();
    assert!(
        r.summary.contains("1 files") && r.summary.contains("download only"),
        "{}",
        r.summary
    );
    let d = m.lock().group(&sales).drive.clone();
    assert!(m.lock().tree(&d).iter().any(|x| x.0 == "Back/deals.xlsx"));

    // a team's group guest: mailbox only, the files belong to the team guest
    let tg = guest_of("g", &ids.team);
    let b = h.backup(&cfg, Some(&tg)).unwrap();
    assert!(b.summary.contains("files are backed up with the team"), "{}", b.summary);
    assert!(!snapshot(&h, &src(&tg), b.time).keys().any(|k| k.starts_with("files")));
    let mut c = cfg.clone();
    c["groups"] = json!(false);
    assert!(h.backup(&c, Some(&guest)).is_err());
}

#[test]
fn private_channel_sites_under_the_team() {
    let m = Mock::start();
    let ids = seed(&m);
    let (_, d) = m.lock().add_channel(&ids.team, "Secret", "private");
    {
        let mut t = m.lock();
        let r = t.drive_root(&d);
        t.add_item(&d, &r, "salaries.csv", Some(b"a,b".to_vec()));
    }
    let h = host();
    let mut cfg = m.config();
    cfg["teams_messages"] = json!(false);
    let g = h.guests(&cfg).unwrap();
    let site = {
        let t = m.lock();
        t.sites.iter().find(|s| s.drives.contains(&d)).unwrap().id.clone()
    };
    let entry = g["guests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == guest_of("s", &site))
        .cloned()
        .unwrap();
    assert_eq!(entry["tags"], json!(["type:site", "site:team"]), "{entry}");

    let guest = guest_of("t", &ids.team);
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    let s = snapshot(&h, &src(&guest), b.time);
    assert_eq!(s["channel-files/Secret/salaries.csv"].as_deref(), Some(&b"a,b"[..]));
    assert_eq!(s["files/General/minutes.md"].as_deref(), Some(&b"# minutes"[..]));
    // restore into the private channel's own site, never into the team's library
    let r = h
        .restore(
            &cfg,
            &src(&guest),
            b.time,
            "to_original",
            json!({"paths": ["channel-files"], "folder": "Back"}),
        )
        .unwrap();
    assert!(r.summary.contains("1 files"), "{}", r.summary);
    let t = m.lock();
    assert!(t.tree(&d).iter().any(|x| x.0 == "Back/salaries.csv"));
    assert!(!t.tree(&t.team(&ids.team).drive).iter().any(|x| x.0.starts_with("Back")));
}
