//! Forwarding (Phase 14a): syslog over TLS and the HTTPS sink against local
//! rustls listeners with a test certificate; resume after restart, no skipped
//! entries after failures, the daily anchor and the `forwarding:<sink>` alert.

use super::*;
use crate::forward::{self, Forwarder};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::Digest;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

const DAY: i64 = 86400;

/// syslog: raw bytes per connection; https: (headers, JSON body) per request
type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Server {
    port: u16,
    pem: String,
    der: Vec<u8>,
    got: Received,
    /// refuse the TLS handshake (syslog) / answer 500 (https)
    fail: Arc<AtomicBool>,
}

fn tls_server(https: bool) -> Server {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = ck.cert.der().to_vec();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(der.clone())],
                PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into()),
            )
            .unwrap(),
    );
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let got = Arc::new(Mutex::new(Vec::new()));
    let fail = Arc::new(AtomicBool::new(false));
    let (g, f) = (got.clone(), fail.clone());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { continue };
            if !https && f.load(Ordering::SeqCst) {
                drop(s); // no handshake
                continue;
            }
            let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, s);
            if !https {
                let mut buf = Vec::new();
                if tls.read_to_end(&mut buf).is_ok() {
                    g.lock().unwrap().push((String::new(), buf));
                }
                continue;
            }
            let mut r = BufReader::new(&mut tls);
            let (mut head, mut len) = (String::new(), 0);
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).is_err() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push_str(&line);
            }
            let mut body = vec![0; len];
            if r.read_exact(&mut body).is_err() {
                continue;
            }
            let failing = f.load(Ordering::SeqCst);
            let status = if failing { "500 Internal Server Error" } else { "200 OK" };
            let _ = write!(
                tls,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.conn.complete_io(&mut tls.sock);
            if !failing {
                g.lock().unwrap().push((head, body));
            }
        }
    });
    Server {
        port,
        pem: ck.cert.pem(),
        der,
        got,
        fail,
    }
}

/// Splits an RFC 5425 octet-counted stream into messages (length checked).
fn frames(mut b: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let sp = b.iter().position(|c| *c == b' ').unwrap();
        let n: usize = std::str::from_utf8(&b[..sp]).unwrap().parse().unwrap();
        out.push(String::from_utf8(b[sp + 1..sp + 1 + n].to_vec()).unwrap());
        b = &b[sp + 1 + n..];
    }
    out
}

fn syslog_msgs(s: &Server) -> Vec<String> {
    s.got.lock().unwrap().iter().flat_map(|(_, b)| frames(b)).collect()
}

fn set(db: &Catalog, v: Value) {
    catalog::set_setting(&db.conn(), catalog::forwarding::SETTING, &v.to_string()).unwrap();
}

fn cursor(db: &Catalog, sink: &str) -> (i64, i64, Option<i64>, Option<String>) {
    db.conn()
        .query_row(
            "SELECT audit_seq, event_seq, failing_since, last_error FROM forward_state WHERE sink = ?1",
            [sink],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

fn audit_n(db: &Catalog, n: usize) {
    for i in 0..n {
        db.audit("alice", "test.entry", &format!("x/{i}"), &json!({"i": i}))
            .unwrap();
    }
}

fn sd(m: &str, k: &str) -> String {
    let p = format!(" {k}=\"");
    let i = m.find(&p).unwrap() + p.len();
    m[i..i + m[i..].find('"').unwrap()].to_owned()
}

/// Syslog: every audit entry once with seq + hash, in order; a refused
/// connection keeps the cursor (records the error); a restarted forwarder
/// resumes after the last delivered entry; outbox events follow.
#[test]
fn syslog_resumes_after_restart_and_never_skips() {
    let srv = tls_server(false);
    let db = Arc::new(Catalog::open_memory().unwrap());
    audit_n(&db, 3);
    set(
        &db,
        json!({"syslog": {"host": "127.0.0.1", "port": srv.port, "ca_pem": srv.pem}}),
    );
    let key = SchedulerKey::generate();
    let mut f = Forwarder::new(db.clone(), key.clone(), "nexus1".into());
    f.step(1000);
    let m = syslog_msgs(&srv);
    assert_eq!(m.len(), 3, "{m:?}");
    let hashes: Vec<String> = db
        .conn()
        .prepare("SELECT hash FROM audit ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for (i, msg) in m.iter().enumerate() {
        assert!(msg.starts_with("<109>1 "), "{msg}");
        assert!(msg.contains(" nexus1 nexus - audit [nexus@32473 "), "{msg}");
        assert_eq!(sd(msg, "seq"), (i + 1).to_string());
        assert_eq!(sd(msg, "hash"), hashes[i]);
        assert_eq!(sd(msg, "action"), "test.entry");
    }
    assert_eq!(cursor(&db, "syslog").0, 3);
    // nothing new: no connection at all
    f.step(1001);
    assert_eq!(srv.got.lock().unwrap().len(), 1);

    // failing receiver: cursor stays, error and failing_since recorded, backoff
    srv.fail.store(true, Ordering::SeqCst);
    audit_n(&db, 2);
    f.step(1010);
    let (a, _, since, err) = cursor(&db, "syslog");
    assert_eq!((a, since), (3, Some(1010)));
    assert!(err.is_some());
    srv.fail.store(false, Ordering::SeqCst);
    f.step(1011); // backing off (10 s)
    assert_eq!(syslog_msgs(&srv).len(), 3);

    // "restart": a new forwarder resumes at seq 4; an alert event follows
    drop(f);
    db.conn()
        .execute(
            "INSERT INTO alerts (ts, last_ts, severity, kind, key, message) VALUES (5, 5, 'critical', 'verify', 'verify:t', 'bad \"chunk\"]')",
            [],
        )
        .unwrap();
    let mut f = Forwarder::new(db.clone(), key, "nexus1".into());
    f.step(1012);
    let m = syslog_msgs(&srv);
    assert_eq!(m.len(), 6, "{m:?}");
    assert_eq!((sd(&m[3], "seq"), sd(&m[4], "seq")), ("4".into(), "5".into()));
    assert!(m[5].contains(" alert [nexus@32473 outbox_seq=\"1\""), "{}", m[5]);
    assert!(m[5].starts_with("<106>1 "), "critical = 2: {}", m[5]);
    let (a, e, since, err) = cursor(&db, "syslog");
    assert_eq!((a, e, since, err), (5, 1, None, None));

    // a new destination starts from the beginning
    set(
        &db,
        json!({"syslog": {"host": "localhost", "port": srv.port, "ca_pem": srv.pem}}),
    );
    f.step(1013);
    assert_eq!(syslog_msgs(&srv).len(), 12);
}

/// Pin by SHA-256; a wrong pin or an unknown CA fails the handshake.
#[test]
fn syslog_pin_and_untrusted_certificate() {
    let srv = tls_server(false);
    let other = tls_server(false);
    let pin: String = sha2::Sha256::digest(&srv.der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let s = |v: Value| -> catalog::forwarding::Syslog { serde_json::from_value(v).unwrap() };
    let rec = [forward::Record::Test { ts: 0 }];
    assert!(forward::send_syslog(
        &s(json!({"host": "127.0.0.1", "port": srv.port, "pin_sha256": pin})),
        "h",
        &rec
    )
    .is_ok());
    assert!(frames(&srv.got.lock().unwrap()[0].1)[0].contains(" test [nexus@32473]"));
    let e = forward::send_syslog(
        &s(json!({"host": "127.0.0.1", "port": srv.port, "ca_pem": other.pem})),
        "h",
        &rec,
    )
    .unwrap_err();
    assert!(format!("{e:#}").contains("certificate"), "{e:#}");
    // public roots only (no CA / pin): a self-signed server is refused
    assert!(forward::send_syslog(&s(json!({"host": "127.0.0.1", "port": srv.port})), "h", &rec).is_err());
}

/// HTTPS: batches of `batch_max`, sealed header opened, a 500 keeps the cursor.
#[test]
fn https_batches_headers_and_retry() {
    let srv = tls_server(true);
    let db = Arc::new(Catalog::open_memory().unwrap());
    audit_n(&db, 5);
    let key = SchedulerKey::generate();
    let url = format!("https://127.0.0.1:{}/ingest", srv.port);
    let sealed = key
        .public()
        .seal(
            &catalog::forwarding::header_location("Authorization", &url),
            "Bearer s3cret",
        )
        .unwrap();
    set(
        &db,
        json!({"https": {"url": url, "headers": {"Authorization": sealed}, "batch_max": 2, "ca_pem": srv.pem}}),
    );
    let mut f = Forwarder::new(db.clone(), key.clone(), "nexus1".into());
    f.step(100);
    {
        let got = srv.got.lock().unwrap();
        assert_eq!(got.len(), 3, "5 entries in batches of 2");
        assert!(got[0].0.to_ascii_lowercase().contains("authorization: bearer s3cret"));
        let seqs: Vec<i64> = got
            .iter()
            .flat_map(|(_, b)| serde_json::from_slice::<Vec<Value>>(b).unwrap())
            .map(|v| {
                assert_eq!(
                    (v["type"].as_str(), v["host"].as_str()),
                    (Some("audit"), Some("nexus1"))
                );
                assert_eq!(v["hash"].as_str().unwrap().len(), 64);
                v["seq"].as_i64().unwrap()
            })
            .collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
    }
    srv.fail.store(true, Ordering::SeqCst);
    db.conn()
        .execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created) VALUES ('gc','t','{}','running','s',1)",
            [],
        )
        .unwrap();
    db.conn()
        .execute("UPDATE jobs SET state = 'failed', finished = 2", [])
        .unwrap();
    f.step(200);
    let (a, e, since, _) = cursor(&db, "https");
    assert_eq!((a, e, since), (5, 0, Some(200)));
    srv.fail.store(false, Ordering::SeqCst);
    f.step(211); // after the 10 s backoff
    let got = srv.got.lock().unwrap();
    let last: Vec<Value> = serde_json::from_slice(&got[3].1).unwrap();
    assert_eq!(
        (last[0]["type"].as_str(), last[0]["state"].as_str()),
        (Some("job"), Some("failed"))
    );
    assert_eq!(cursor(&db, "https"), (5, 1, None, None));
    // "Send test message"
    let cfg = catalog::forwarding::Forwarding::load(&db.conn()).unwrap();
    assert_eq!(forward::test(&cfg, &key, "nexus1"), json!({"https": "ok"}));
}

/// Daily `audit.anchor` with the head before it; the `forwarding:<sink>` alert
/// after 15 minutes of failure, resolved when the sink delivers again.
#[test]
fn daily_anchor_and_failure_alert() {
    let mut e = env(1);
    e.cfg.forward_poll_secs = 0;
    let mut s = sched(&e);
    let day0 = 20_000 * DAY + 3600;
    let anchors = |s: &Scheduler| -> Vec<Value> {
        s.db.conn()
            .prepare("SELECT details FROM audit WHERE action = 'audit.anchor' ORDER BY seq")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|d| serde_json::from_str(&d.unwrap()).unwrap())
            .collect()
    };
    let head = |s: &Scheduler| -> (i64, String) {
        s.db.conn()
            .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap()
    };
    s.db.audit("alice", "x", "y", &json!({})).unwrap();
    let (seq, hash) = head(&s);
    s.check_forwarding(day0).unwrap();
    s.check_forwarding(day0 + 3600).unwrap();
    let a = anchors(&s);
    assert_eq!(a, vec![json!({"head_seq": seq, "head_hash": hash})]);
    s.check_forwarding(day0 + DAY).unwrap();
    assert_eq!(anchors(&s).len(), 2);
    // a restarted scheduler knows today's anchor from the audit log (entries
    // carry the real clock): none again today, one tomorrow
    let mut s2 = sched(&e);
    s2.check_forwarding(catalog::now()).unwrap();
    assert_eq!(anchors(&s2).len(), 2);
    s2.check_forwarding(catalog::now() + DAY).unwrap();
    assert_eq!(anchors(&s2).len(), 3);

    set(&s.db, json!({"syslog": {"host": "log.example"}}));
    let open = |s: &Scheduler| -> Vec<(String, Option<i64>)> {
        s.db.conn()
            .prepare("SELECT key, resolved_at FROM alerts WHERE kind = 'forwarding'")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let now = day0 + DAY;
    s.db.conn()
        .execute(
            "INSERT INTO forward_state (sink, dest, failing_since, last_error) VALUES ('syslog', 'log.example:6514', ?1, 'refused')",
            [now - 600],
        )
        .unwrap();
    s.check_forwarding(now).unwrap();
    assert!(open(&s).is_empty(), "10 minutes: no alert yet");
    s.check_forwarding(now + 300).unwrap();
    let a = open(&s);
    assert_eq!((a.len(), a[0].0.as_str(), a[0].1), (1, "forwarding:syslog", None));
    s.db.conn()
        .execute("UPDATE forward_state SET failing_since = NULL", [])
        .unwrap();
    s.check_forwarding(now + 360).unwrap();
    assert!(open(&s)[0].1.is_some(), "resolved after recovery");
}
