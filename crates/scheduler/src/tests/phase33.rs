//! Phase 33 (Commvault Tier 2): PSA ticketing against mock HaloPSA,
//! ConnectWise and Autotask servers; new tenant approvers; synthetic restores
//! (the decision from a real store, the connector faked).

use super::*;
use crate::psa::{Ticketing, ALERT_AFTER_SECS, NOTE_EVERY_SECS};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

/// One request the mock received.
#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    /// lower-case names
    headers: Vec<(String, String)>,
    body: String,
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// A PSA on loopback: records every request, answers like the vendor (ticket
/// IDs from 100 up), or 500 while `fail` is set.
struct Mock {
    port: u16,
    got: Arc<Mutex<Vec<Req>>>,
    fail: Arc<AtomicBool>,
    /// token requests answered
    tokens: Arc<std::sync::atomic::AtomicUsize>,
}

impl Mock {
    fn start(vendor: &'static str) -> Mock {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let got = Arc::new(Mutex::new(Vec::<Req>::new()));
        let fail = Arc::new(AtomicBool::new(false));
        let tokens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (g, f, n) = (got.clone(), fail.clone(), tokens.clone());
        std::thread::spawn(move || {
            let mut next = 100;
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut first = String::new();
                if r.read_line(&mut first).is_err() || first.is_empty() {
                    continue;
                }
                let mut it = first.split_whitespace();
                let (method, path) = (it.next().unwrap().to_owned(), it.next().unwrap().to_owned());
                let (mut headers, mut len) = (Vec::new(), 0usize);
                loop {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    let line = line.trim_end();
                    if line.is_empty() {
                        break;
                    }
                    let (k, v) = line.split_once(':').unwrap();
                    let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_owned());
                    if k == "content-length" {
                        len = v.parse().unwrap();
                    }
                    headers.push((k, v));
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let req = Req {
                    method: method.clone(),
                    path: path.clone(),
                    headers,
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                g.lock().unwrap().push(req);
                let (status, answer) = if f.load(Ordering::SeqCst) {
                    (500, json!({"error": "down"}))
                } else if path.ends_with("/auth/token") || path.contains("/auth/token?") {
                    n.fetch_add(1, Ordering::SeqCst);
                    (
                        200,
                        json!({"access_token": "tok-1", "token_type": "Bearer", "expires_in": 3600}),
                    )
                } else if method == "POST"
                    && (path == "/api/Tickets" || path == "/cw/service/tickets" || path == "/at/Tickets")
                {
                    let created = String::from_utf8_lossy(&body).contains("summary")
                        || String::from_utf8_lossy(&body).contains("title");
                    if created && !String::from_utf8_lossy(&body).contains("status_id") {
                        next += 1;
                        match vendor {
                            "halopsa" => (201, json!({"id": next, "summary": "x"})),
                            "connectwise" => (201, json!({"id": next})),
                            _ => (200, json!({"itemId": next})),
                        }
                    } else {
                        (200, json!([{"id": 1}]))
                    }
                } else {
                    (200, json!({"ok": true}))
                };
                let text = answer.to_string();
                let _ = write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        Mock {
            port,
            got,
            fail,
            tokens,
        }
    }

    fn take(&self) -> Vec<Req> {
        std::mem::take(&mut *self.got.lock().unwrap())
    }
}

fn psa_rule(s: &Scheduler, vendor: &str, port: u16) -> Value {
    let base = format!("http://127.0.0.1:{port}");
    let mut p = match vendor {
        "halopsa" => json!({"vendor": vendor, "url": format!("{base}/api"), "token_url": format!("{base}/auth/token"),
                            "client_id": "nexus", "secret": "halo-secret", "account": "12", "board": "3"}),
        "connectwise" => json!({"vendor": vendor, "url": format!("{base}/cw"), "client_id": "cid-1", "company": "msp",
                                "username": "pub", "secret": "priv", "account": "ACME", "board": "Alerts"}),
        _ => json!({"vendor": vendor, "url": format!("{base}/at"), "username": "api@msp", "secret": "at-secret",
                    "integration_code": "CODE", "account": "77", "board": "9"}),
    };
    let typed: catalog::alerting::Psa = serde_json::from_value(p.clone()).unwrap();
    let loc = catalog::alerting::psa_location("acme-psa", &typed);
    p["secret"] = json!(s.secrets.public().seal(&loc, typed.secret.as_str()).unwrap());
    json!([{"name": "acme-psa", "min_severity": "warning", "tenants": ["acme"], "channels": {"psa": p}}])
}

fn tickets(s: &Scheduler) -> Vec<(String, String, Option<i64>)> {
    s.db.conn()
        .prepare("SELECT key, ticket, closed FROM psa_tickets ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap()
}

/// The full ticket lifecycle per vendor: one ticket per alert key (other
/// tenants and lower severities none), a note on a repeat only after an hour
/// and at once on an escalation, closed (note + status) when resolved, a new
/// ticket when raised again; vendor authentication and the egress allow-list.
#[test]
fn psa_ticket_lifecycle() {
    for vendor in ["halopsa", "connectwise", "autotask"] {
        let mut e = env(1);
        e.cfg.psa_poll_secs = 0;
        let s = sched(&e);
        let m = Mock::start(vendor);
        catalog::set_setting(&s.db.conn(), "alert_rules", &psa_rule(&s, vendor, m.port).to_string()).unwrap();
        let mut t = Ticketing::new(
            s.db.clone(),
            s.secrets.clone(),
            "nexus".into(),
            e.cfg.alerts_config.clone(),
        )
        .unwrap();
        let now = catalog::now();
        s.raise(
            "warning",
            "job_failed",
            "job_failed:acme/x",
            "backup failed: no route",
            Some("acme"),
        )
        .unwrap();
        s.raise(
            "critical",
            "job_failed",
            "job_failed:globex/x",
            "other tenant",
            Some("globex"),
        )
        .unwrap();
        s.raise(
            "info",
            "job_failed",
            "job_failed:acme/y",
            "below the rule",
            Some("acme"),
        )
        .unwrap();
        t.step(now);
        let reqs = m.take();
        let creates: Vec<&Req> = reqs
            .iter()
            .filter(|r| r.method == "POST" && !r.path.contains("token"))
            .collect();
        assert_eq!(creates.len(), 1, "{vendor}: {reqs:?}");
        let c = creates[0];
        match vendor {
            "halopsa" => {
                let tok = reqs
                    .iter()
                    .find(|r| r.path.contains("/auth/token"))
                    .expect("token request");
                assert!(
                    tok.body.contains("grant_type=client_credentials")
                        && tok.body.contains("client_secret=halo-secret")
                );
                assert_eq!(c.header("authorization"), Some("Bearer tok-1"));
                let b = c.json();
                assert_eq!(
                    (b[0]["client_id"].clone(), b[0]["tickettype_id"].clone()),
                    (json!(12), json!(3))
                );
                assert!(b[0]["summary"]
                    .as_str()
                    .unwrap()
                    .starts_with("[NexusBackup nexus] warning job_failed: backup failed"));
            }
            "connectwise" => {
                use base64::Engine;
                let basic = base64::engine::general_purpose::STANDARD.encode("msp+pub:priv");
                assert_eq!(c.header("authorization"), Some(format!("Basic {basic}").as_str()));
                assert_eq!(c.header("clientid"), Some("cid-1"));
                let b = c.json();
                assert_eq!(
                    (b["company"]["identifier"].clone(), b["board"]["name"].clone()),
                    (json!("ACME"), json!("Alerts"))
                );
            }
            _ => {
                assert_eq!(
                    (c.header("username"), c.header("secret"), c.header("apiintegrationcode")),
                    (Some("api@msp"), Some("at-secret"), Some("CODE"))
                );
                let b = c.json();
                assert_eq!(
                    (b["companyID"].clone(), b["queueID"].clone(), b["priority"].clone()),
                    (json!(77), json!(9), json!(2))
                );
            }
        }
        assert_eq!(tickets(&s), vec![("job_failed:acme/x".into(), "101".into(), None)]);
        // a repeat within the hour: nothing; after it: one note
        s.raise(
            "warning",
            "job_failed",
            "job_failed:acme/x",
            "backup failed again",
            Some("acme"),
        )
        .unwrap();
        t.step(now + 60);
        assert!(
            m.take().iter().all(|r| r.path.contains("token")),
            "{vendor}: no note within the hour"
        );
        t.step(now + NOTE_EVERY_SECS + 1);
        let reqs = m.take();
        let notes: Vec<&Req> = reqs.iter().filter(|r| !r.path.contains("token")).collect();
        assert_eq!(notes.len(), 1, "{vendor}: {reqs:?}");
        assert!(notes[0].body.contains("2 times"), "{}", notes[0].body);
        match vendor {
            "halopsa" => assert_eq!(notes[0].path, "/api/Actions"),
            "connectwise" => assert_eq!(notes[0].path, "/cw/service/tickets/101/notes"),
            _ => assert_eq!(notes[0].path, "/at/Tickets/101/Notes"),
        }
        // an escalation: a note at once
        s.raise(
            "critical",
            "job_failed",
            "job_failed:acme/x",
            "still failing",
            Some("acme"),
        )
        .unwrap();
        t.step(now + NOTE_EVERY_SECS + 2);
        let reqs: Vec<Req> = m.take().into_iter().filter(|r| !r.path.contains("token")).collect();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].body.contains("Escalated to critical"));
        // resolved: a note and the closed status
        s.resolve("job_failed:acme/x").unwrap();
        t.step(now + NOTE_EVERY_SECS + 3);
        let reqs: Vec<Req> = m.take().into_iter().filter(|r| !r.path.contains("token")).collect();
        assert_eq!(reqs.len(), 2, "{vendor}: {reqs:?}");
        assert!(reqs[0].body.contains("problem went away"));
        let close = &reqs[1];
        match vendor {
            "halopsa" => assert_eq!(
                (close.method.as_str(), close.json()[0]["status_id"].clone()),
                ("POST", json!(9))
            ),
            "connectwise" => {
                assert_eq!(
                    (close.method.as_str(), close.path.as_str()),
                    ("PATCH", "/cw/service/tickets/101")
                );
                assert_eq!(close.json()[0]["value"], json!({"name": "Closed"}));
            }
            _ => assert_eq!(
                (close.method.as_str(), close.json()["status"].clone()),
                ("PATCH", json!(5))
            ),
        }
        assert!(tickets(&s)[0].2.is_some(), "closed");
        // raised again later: a new ticket
        s.raise(
            "warning",
            "job_failed",
            "job_failed:acme/x",
            "failed once more",
            Some("acme"),
        )
        .unwrap();
        t.step(now + NOTE_EVERY_SECS + 4);
        assert_eq!(tickets(&s).len(), 2);
        assert_eq!(tickets(&s)[1].1, "102");
        if vendor == "halopsa" {
            // cached across rounds, fetched again once it expired (1 h - 1 min after the first)
            assert_eq!(m.tokens.load(Ordering::SeqCst), 2);
        }
        // the PSA hosts are egress targets
        let targets = firewall::alert_targets(&s.alerts_config().unwrap());
        assert!(targets.contains(&("127.0.0.1".into(), m.port)), "{targets:?}");
    }
}

/// A failing PSA: the rule's state records it, `psa` is raised after 15
/// minutes (and never sent to a PSA itself), resolved by the next good round;
/// removing the PSA channel drops the rule's tickets and state.
#[test]
fn psa_failures_raise_and_resolve() {
    let mut e = env(1);
    e.cfg.psa_poll_secs = 0;
    let mut s = sched(&e);
    let m = Mock::start("autotask");
    catalog::set_setting(
        &s.db.conn(),
        "alert_rules",
        &psa_rule(&s, "autotask", m.port).to_string(),
    )
    .unwrap();
    let mut t = Ticketing::new(
        s.db.clone(),
        s.secrets.clone(),
        "nexus".into(),
        e.cfg.alerts_config.clone(),
    )
    .unwrap();
    let now = catalog::now();
    m.fail.store(true, Ordering::SeqCst);
    s.raise(
        "critical",
        "job_failed",
        "job_failed:acme/x",
        "backup failed",
        Some("acme"),
    )
    .unwrap();
    t.step(now);
    assert!(tickets(&s).is_empty());
    s.check_psa(now + 60).unwrap();
    let open = |s: &Scheduler| -> i64 {
        s.db.conn()
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE kind = 'psa' AND resolved_at IS NULL",
                [],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(open(&s), 0, "not yet");
    s.check_psa(now + ALERT_AFTER_SECS).unwrap();
    assert_eq!(open(&s), 1);
    let msg: String =
        s.db.conn()
            .query_row("SELECT message FROM alerts WHERE kind = 'psa'", [], |r| r.get(0))
            .unwrap();
    assert!(msg.contains("acme-psa") && msg.contains("500"), "{msg}");
    m.fail.store(false, Ordering::SeqCst);
    m.take();
    t.step(now + ALERT_AFTER_SECS + 1);
    let creates = m.take();
    assert_eq!(creates.len(), 1, "only the job alert, not the psa alert: {creates:?}");
    s.check_psa(now + ALERT_AFTER_SECS + 2).unwrap();
    assert_eq!(open(&s), 0, "resolved after a good round");
    // the PSA channel removed: its tickets and state go
    catalog::set_setting(&s.db.conn(), "alert_rules", "[]").unwrap();
    t.step(now + ALERT_AFTER_SECS + 3);
    let n: i64 =
        s.db.conn()
            .query_row(
                "SELECT (SELECT COUNT(*) FROM psa_tickets) + (SELECT COUNT(*) FROM psa_state)",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(n, 0);
}

/// Settings → Alert delivery → Test opens a ticket and closes it again; a
/// secret sealed for another URL does not open (the setting is refused).
#[test]
fn psa_test_and_sealing() {
    let mut e = env(1);
    e.cfg.psa_poll_secs = 0;
    let mut s = sched(&e);
    let m = Mock::start("connectwise");
    let rules = psa_rule(&s, "connectwise", m.port);
    catalog::set_setting(&s.db.conn(), "alert_rules", &rules.to_string()).unwrap();
    let id = manual(&s, "alert_test", "-", json!({"rule": "acme-psa"}));
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let r: Value = serde_json::from_str(
        &s.db
            .conn()
            .query_row("SELECT result FROM jobs WHERE id=?1", [id], |r| r.get::<_, String>(0))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(r["psa"], "ok (ticket 101 opened and closed)", "{r}");
    let reqs = m.take();
    assert_eq!(reqs.len(), 3, "create, note, close: {reqs:?}");
    // the sealed secret moved to another URL: refused
    let mut moved = rules.clone();
    moved[0]["channels"]["psa"]["url"] = json!("https://evil.example/cw");
    catalog::set_setting(&s.db.conn(), "alert_rules", &moved.to_string()).unwrap();
    assert!(s.alerts_config().is_err());
}

/// Tenant-side approvers: an account that becomes an approver of an opted-in
/// tenant after the opt-in raises `tenant_approver` once (tenant set); the
/// approvers at opt-in time, other tenants and other roles do not.
#[test]
fn new_tenant_approver_alert() {
    let mut e = env(1);
    e.cfg.psa_poll_secs = 0;
    let s = sched(&e);
    let now = catalog::now();
    s.db.conn()
        .execute_batch(&format!(
            "INSERT INTO tenant_approvals (tenant, enabled_at, enabled_by) VALUES ('t1', {t}, 'alice');
             INSERT INTO users (name, password_hash, totp_secret, role, tenant, created, approver_since) VALUES
               ('old', 'x', 'y', 'tenant_admin', 't1', 1, NULL),
               ('new', 'x', 'y', 'tenant_admin', 't1', 1, {n}),
               ('other', 'x', 'y', 'tenant_admin', 't2', 1, {n}),
               ('user', 'x', 'y', 'tenant_user', 't1', 1, {n});",
            t = now - 3600,
            n = now - 60
        ))
        .unwrap();
    s.check_tenant_approvers(now).unwrap();
    s.check_tenant_approvers(now + 30).unwrap();
    let rows: Vec<(String, String, Option<String>, i64)> =
        s.db.conn()
            .prepare("SELECT severity, message, tenant, count FROM alerts WHERE kind = 'tenant_approver'")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].0.as_str(), rows[0].2.as_deref(), rows[0].3),
        ("warning", Some("t1"), 1)
    );
    assert!(
        rows[0]
            .1
            .contains("account new becomes a tenant-side approver of tenant t1"),
        "{}",
        rows[0].1
    );
    // resolved by hand: not raised again for the same change
    s.db.conn()
        .execute("UPDATE alerts SET resolved_at = 1 WHERE kind = 'tenant_approver'", [])
        .unwrap();
    s.check_tenant_approvers(now + 60).unwrap();
    let n: i64 =
        s.db.conn()
            .query_row("SELECT COUNT(*) FROM alerts WHERE kind = 'tenant_approver'", [], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(n, 1);
}

// ---------------------------------------------------------------- synthetic restore

fn tree_file(path: &str, size: u64, mtime: i64) -> chunkstore::TreeEntry {
    chunkstore::TreeEntry {
        path: path.as_bytes().to_vec(),
        kind: chunkstore::TreeKind::File,
        mode: 0o644,
        uid: 0,
        gid: 0,
        size,
        mtime_ns: mtime * 1_000_000_000,
        ctime_ns: 0,
        inode: 0,
        rdev: 0,
        link_target: None,
        xattrs: Vec::new(),
        chunks: Vec::new(),
        inconsistent: false,
    }
}

/// A share snapshot hit by ransomware (60 files renamed to `.lockbit`, a ransom
/// note) whose other file a YARA rule matched: the scheduler decides from the
/// name indexes and the catalog, writes the plan and the CSV, and hands the
/// download to the connector; the job result carries its counts and the download.
#[test]
fn synthetic_restore_plan_csv_and_download() {
    let mut e = env(1);
    e.cfg.psa_poll_secs = 0;
    let d = e.d.path().to_path_buf();
    e.cfg.agentctl_bin = d.join("agentctl");
    script(
        &e.cfg.agentctl_bin,
        &format!(
            "cp \"$1\" {0}/syn-cfg.json\ncp \"$(dirname \"$1\")/synthetic.json\" {0}/syn-plan.json\necho reading >&2\necho '{{\"files\": 62, \"entries\": 64}}'",
            d.display()
        ),
    );
    fs::create_dir_all(&e.cfg.downloads).unwrap();
    let store = chunkstore::Store::open(
        e.cfg.store_base.join("t1"),
        Keyring::new("t1", &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap();
    let docs: Vec<String> = (0..60).map(|i| format!("docs/f{i:02}.docx")).collect();
    let mut day1: Vec<chunkstore::TreeEntry> = docs.iter().map(|p| tree_file(p, 10, 1)).collect();
    day1.push(tree_file("docs/tool.exe", 5, 1));
    day1.push(tree_file("docs/keep.txt", 3, 1));
    let mut day2 = day1.clone();
    day2[60] = tree_file("docs/tool.exe", 6, 2);
    let mut day3: Vec<chunkstore::TreeEntry> = docs.iter().map(|p| tree_file(&format!("{p}.lockbit"), 12, 3)).collect();
    day3.push(tree_file("docs/tool.exe", 6, 2));
    day3.push(tree_file("docs/keep.txt", 3, 1));
    day3.push(tree_file("docs/HOW_TO_DECRYPT.txt", 1, 3));
    for (t, v) in [(1u64, day1), (2, day2), (3, day3)] {
        store
            .commit_snapshot("share-5", t, &[("tree", chunkstore::Index::Tree { entries: v })])
            .unwrap();
        s_snap(&e, t);
    }
    e.db.conn()
        .execute(
            "INSERT INTO snapshot_scans (job_id, tenant, source, time, finished, rules, files, skipped, errors, complete,
               matches_total, matches) VALUES (900, 't1', 'share-5', 3, 3, 'r', 63, 0, 0, 1, 1, ?1)",
            [json!([{"rule": "Dropper", "path": "/docs/tool.exe"}]).to_string()],
        )
        .unwrap();
    let mut s = sched(&e);
    let (dl, rep) = ("a".repeat(64), "b".repeat(64));
    let id = manual(
        &s,
        "synthetic_restore",
        "t1",
        json!({"source": "share-5", "time": 3, "mode": "download", "format": "tar",
               "download_token": dl, "report_token": rep}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    let log: String =
        s.db.conn()
            .query_row("SELECT log FROM jobs WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
    assert_eq!(state(&s, id), "ok", "{log}");
    let plan: Value = serde_json::from_slice(&fs::read(d.join("syn-plan.json")).unwrap()).unwrap();
    // tool.exe: version 2 has the flagged content, version 1 is clean; the renamed
    // documents come back from 2, just before the rename
    assert_eq!(plan["take"]["1"], json!(["docs/tool.exe"]), "{plan}");
    assert_eq!(plan["take"]["2"].as_array().unwrap().len(), 60);
    assert_eq!(
        plan["drop"].as_array().unwrap().len(),
        61,
        "60 renamed outputs and the note"
    );
    assert_eq!(plan["paths"], json!(["/"]));
    assert_eq!(
        (
            plan["stats"]["substituted"].clone(),
            plan["stats"]["restored"].clone(),
            plan["stats"]["left_out"].clone()
        ),
        (json!(1), json!(60), json!(61))
    );
    let cfg: Value = serde_json::from_slice(&fs::read(d.join("syn-cfg.json")).unwrap()).unwrap();
    assert_eq!(
        cfg["synthetic"]["out"],
        json!(e.cfg.downloads.join(format!("{dl}.tar")))
    );
    assert!(cfg["agent"].is_null(), "a download needs no agent");
    let csv = fs::read_to_string(e.cfg.downloads.join(format!("{rep}.csv"))).unwrap();
    assert!(csv.starts_with("path,action,version,reason\r\n"), "{csv}");
    assert!(
        csv.contains("/docs/tool.exe,substituted,1,YARA rule Dropper matched in snapshot 3"),
        "{csv}"
    );
    assert!(
        csv.contains("/docs/f00.docx,restored,2,\"deleted by a mass rename in snapshot 3 (mass rename: 60 of 62"),
        "{csv}"
    );
    assert!(
        csv.contains("/docs/HOW_TO_DECRYPT.txt,left_out,,ransom-note file name"),
        "{csv}"
    );
    let r = result_of(&s, id);
    assert_eq!(
        (
            r["files"].clone(),
            r["download_token"].clone(),
            r["report_token"].clone()
        ),
        (json!(62), json!(dl), json!(rep))
    );
    // to a host: the agent of the tenant, restore options in the connector's config
    s.db.conn()
        .execute(
            "INSERT INTO agents (id, tenant, name, host, port, cert_sha256) VALUES ('0123456789abcdef','t1','srv','10.0.0.9',7444,'ab')",
            [],
        )
        .unwrap();
    let id = manual(
        &s,
        "synthetic_restore",
        "t1",
        json!({"source": "share-5", "time": 3, "mode": "host", "agent_id": "0123456789abcdef", "target": "/srv/clean",
               "overwrite": "never", "confirm": "srv", "paths": ["/docs/keep.txt"], "depth": 5, "report_token": rep}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let cfg: Value = serde_json::from_slice(&fs::read(d.join("syn-cfg.json")).unwrap()).unwrap();
    assert_eq!(cfg["agent"]["id"], "0123456789abcdef");
    assert_eq!(
        cfg["synthetic"]["restore"],
        json!({"target": "/srv/clean", "overwrite": "never", "confirm": "srv"})
    );
    let plan: Value = serde_json::from_slice(&fs::read(d.join("syn-plan.json")).unwrap()).unwrap();
    assert_eq!(plan["stats"]["files"], 1, "only the selected path");
    assert!(plan["take"].as_object().unwrap().is_empty() && plan["drop"].as_array().unwrap().is_empty());
    // not a file tree: refused
    let id = manual(
        &s,
        "synthetic_restore",
        "t1",
        json!({"source": "vm-100", "time": 3, "mode": "download", "download_token": dl, "report_token": rep}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(state(&s, id), "failed");
}

/// The catalog row of a share snapshot (the scheduler lists local snapshots).
fn s_snap(e: &Env, t: u64) {
    e.db.conn()
        .execute(
            "INSERT INTO snapshots (tenant, source, time, size, local, offsite) VALUES ('t1', 'share-5', ?1, 1, 1, 0)",
            [t as i64],
        )
        .unwrap();
}

// ---------------------------------------------------------------- cases

/// A case's search is a file_search job with `case_id`: only the sources with
/// the prefix are searched, the matched snapshots (items per snapshot) replace
/// the case's list; rows with a hold of the case stay (with 0 items).
#[test]
fn case_search_records_matched_snapshots() {
    let mut e = env(1);
    e.cfg.psa_poll_secs = 0;
    let store = chunkstore::Store::open(
        e.cfg.store_base.join("t1"),
        Keyring::new("t1", &[(1, [7; 32])]),
        test_opts(),
    )
    .unwrap();
    let mail = |p: &str| tree_file(p, 10, 1);
    for (src, t, files) in [
        (
            "plugin-m365-1-u.ann",
            100u64,
            vec![mail("mail/Inbox/Invoice 4711 ~a.eml"), mail("mail/Inbox/Lunch ~b.eml")],
        ),
        (
            "plugin-m365-1-u.ann",
            200,
            vec![
                mail("mail/Inbox/Invoice 4711 ~a.eml"),
                mail("mail/Sent/Invoice 4711 reminder ~c.eml"),
            ],
        ),
        ("share-9", 200, vec![mail("Invoice 4711.pdf")]),
    ] {
        store
            .commit_snapshot(src, t, &[("files", chunkstore::Index::Tree { entries: files })])
            .unwrap();
    }
    let s = sched(&e);
    s.db.conn()
        .execute_batch(
            "INSERT INTO cases (id, tenant, name, criteria, state, created_by, created_at) VALUES (7, 't1', 'm', '{}', 'open', 'a', 1);
             INSERT INTO case_snapshots (case_id, source, time, items, hold_id) VALUES
               (7, 'plugin-m365-1-u.old', 50, 4, 99), (7, 'plugin-m365-1-u.gone', 60, 1, NULL);",
        )
        .unwrap();
    let mut s = s;
    let id = manual(
        &s,
        "file_search",
        "t1",
        json!({"query": "invoice 4711", "source_prefix": "plugin-m365-", "limit": 2000, "case_id": 7}),
    );
    s.start_jobs().unwrap();
    s.wait_idle(Duration::from_secs(30)).unwrap();
    assert_eq!(state(&s, id), "ok");
    let rows: Vec<(String, i64, i64, Option<i64>)> =
        s.db.conn()
            .prepare("SELECT source, time, items, hold_id FROM case_snapshots WHERE case_id = 7 ORDER BY source, time")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
    assert_eq!(
        rows,
        vec![
            ("plugin-m365-1-u.ann".into(), 100, 1, None),
            ("plugin-m365-1-u.ann".into(), 200, 2, None),
            ("plugin-m365-1-u.old".into(), 50, 0, Some(99)),
        ],
        "the share is not searched, the stale unheld row is gone"
    );
    let (last, at): (i64, Option<i64>) =
        s.db.conn()
            .query_row("SELECT last_job, searched_at FROM cases WHERE id = 7", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!(last, id);
    assert!(at.is_some());
}
