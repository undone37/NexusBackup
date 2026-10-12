//! Audit and alert forwarding (Phase 14a, docs/control-plane.md "Forwarding").
//! A thread of its own follows the audit chain by `seq` and the outbox
//! `forward_events` (alert raised / escalated / acknowledged / resolved, job
//! finished; catalog v15 triggers) and delivers both, in order and at least
//! once, to the sinks of the setting `forwarding` (`catalog::forwarding`):
//!
//! - **syslog**: RFC 5424 messages with RFC 5425 octet-counting framing over
//!   TLS (rustls), MSGID `audit` / `alert` / `job`, structured data
//!   `[nexus@32473 seq=".." hash=".." actor=".." action=".." target=".."]`.
//!   Syslog has no acknowledgement: a batch counts as delivered when the
//!   connection closed cleanly after it (close_notify, then the receiver's EOF).
//! - **https**: POST of a JSON array `[{type: "audit"|"alert"|"job", …}]`, any
//!   2xx = delivered.
//!
//! Cursors (`forward_state`) advance only after a delivered batch, so a crash
//! or a failing sink repeats rather than skips. A sink whose destination
//! changes starts again from the beginning. Failures back off (10 s doubling up
//! to 5 min); after 15 minutes the tick raises the alert `forwarding:<sink>`,
//! resolved after the next delivered batch. The tick also writes the daily
//! `audit.anchor` entry (head seq + hash), so the chain head leaves the box at
//! least once a day.

use crate::{Scheduler, ACTOR};
use anyhow::{bail, Context, Result};
use catalog::forwarding::{self, Forwarding, Https, Syslog, PEN};
use catalog::rusqlite::{params, OptionalExtension};
use catalog::secret::SchedulerKey;
use catalog::Catalog;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme, StreamOwned,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// A sink failing this long raises `forwarding:<sink>`.
pub const ALERT_AFTER_SECS: i64 = 15 * 60;
/// Messages per syslog connection.
const SYSLOG_BATCH: usize = 200;
/// Batches per sink and round (the rest follows in the next round).
const ROUNDS: usize = 20;
/// Delivered outbox events are kept this long (also when no sink is enabled, so
/// a sink enabled later still gets the last day).
const OUTBOX_KEEP_SECS: i64 = 86400;

/// One forwarded record.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    Audit {
        seq: i64,
        ts: i64,
        actor: String,
        action: String,
        target: String,
        details: String,
        prev_hash: String,
        hash: String,
    },
    /// outbox event (`kind`: alert or job)
    Event {
        seq: i64,
        ts: i64,
        kind: String,
        payload: Value,
    },
    /// "Send test message" (Settings → Forwarding)
    Test { ts: i64 },
}

// ---------------------------------------------------------------- RFC 5424

/// SD-PARAM value: `"`, `\` and `]` escaped (RFC 5424 §6.3.3).
pub fn sd_escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        if matches!(c, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// HOSTNAME / APP-NAME / MSGID: printable US-ASCII without space, at most
/// `max` characters, `-` when empty.
fn header_field(s: &str, max: usize) -> String {
    let f: String = s
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(max)
        .collect();
    if f.is_empty() {
        "-".into()
    } else {
        f
    }
}

/// RFC 3339 UTC (`2026-10-12T08:30:00Z`) from unix seconds.
pub fn rfc3339(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86400), ts.rem_euclid(86400));
    // civil_from_days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

fn sev_of_alert(s: &str) -> u8 {
    match s {
        "critical" => 2,
        "warning" => 4,
        _ => 6,
    }
}

fn str_of(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

/// One RFC 5424 message (without framing). MSG is plain UTF-8 text with
/// control characters replaced by spaces.
pub fn rfc5424(r: &Record, host: &str, app: &str, facility: u8) -> String {
    let (sev, ts, msgid, sd, msg): (u8, i64, &str, Vec<(&str, String)>, String) = match r {
        Record::Audit {
            seq,
            ts,
            actor,
            action,
            target,
            details,
            hash,
            ..
        } => (
            5,
            *ts,
            "audit",
            vec![
                ("seq", seq.to_string()),
                ("hash", hash.clone()),
                ("actor", actor.clone()),
                ("action", action.clone()),
                ("target", target.clone()),
            ],
            format!("{action} {target} by {actor}: {details}"),
        ),
        Record::Event {
            seq,
            ts,
            kind,
            payload: p,
        } if kind == "alert" => {
            let event = str_of(&p["event"]);
            let sev = if event == "resolved" {
                5
            } else {
                sev_of_alert(p["severity"].as_str().unwrap_or_default())
            };
            (
                sev,
                *ts,
                "alert",
                vec![
                    ("outbox_seq", seq.to_string()),
                    ("id", str_of(&p["id"])),
                    ("event", event.clone()),
                    ("severity", str_of(&p["severity"])),
                    ("kind", str_of(&p["kind"])),
                    ("key", str_of(&p["key"])),
                    ("tenant", str_of(&p["tenant"])),
                ],
                format!(
                    "alert {} {event} {} {}: {}",
                    str_of(&p["id"]),
                    str_of(&p["severity"]),
                    str_of(&p["kind"]),
                    str_of(&p["message"])
                ),
            )
        }
        Record::Event {
            seq, ts, payload: p, ..
        } => {
            let state = str_of(&p["state"]);
            let sev = match state.as_str() {
                "failed" => 4,
                "cancelled" => 5,
                _ => 6,
            };
            (
                sev,
                *ts,
                "job",
                vec![
                    ("outbox_seq", seq.to_string()),
                    ("id", str_of(&p["id"])),
                    ("kind", str_of(&p["kind"])),
                    ("tenant", str_of(&p["tenant"])),
                    ("state", state.clone()),
                    ("requested_by", str_of(&p["requested_by"])),
                ],
                format!(
                    "job {} {} {state} (tenant {})",
                    str_of(&p["id"]),
                    str_of(&p["kind"]),
                    str_of(&p["tenant"])
                ),
            )
        }
        Record::Test { ts } => (
            6,
            *ts,
            "test",
            Vec::new(),
            "Test message from the NexusBackup appliance (Settings → Forwarding).".into(),
        ),
    };
    let mut sd_text = format!("[nexus@{PEN}");
    for (k, v) in sd {
        sd_text.push_str(&format!(" {k}=\"{}\"", sd_escape(&v)));
    }
    sd_text.push(']');
    let msg: String = msg.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!(
        "<{}>1 {} {} {} - {msgid} {sd_text} {msg}",
        u16::from(facility.min(23)) * 8 + u16::from(sev),
        rfc3339(ts),
        header_field(host, 255),
        header_field(app, 48),
    )
}

/// RFC 5425 octet counting: `MSG-LEN SP SYSLOG-MSG`.
pub fn frame(msg: &str) -> Vec<u8> {
    format!("{} {msg}", msg.len()).into_bytes()
}

/// The JSON object of a record (HTTPS sink).
pub fn json_record(r: &Record, host: &str) -> Value {
    match r {
        Record::Audit {
            seq,
            ts,
            actor,
            action,
            target,
            details,
            prev_hash,
            hash,
        } => json!({
            "type": "audit", "host": host, "seq": seq, "ts": ts, "actor": actor, "action": action,
            "target": target, "details": serde_json::from_str::<Value>(details).unwrap_or_else(|_| json!(details)),
            "prev_hash": prev_hash, "hash": hash,
        }),
        Record::Event { seq, ts, kind, payload } => {
            let mut v = payload.clone();
            if let Some(o) = v.as_object_mut() {
                o.insert("type".into(), json!(kind));
                o.insert("host".into(), json!(host));
                o.insert("outbox_seq".into(), json!(seq));
                o.insert("event_ts".into(), json!(ts));
                if kind == "alert" {
                    if let Some(id) = payload["id"].as_i64() {
                        o.insert("alert_url".into(), json!(crate::alerts::Alert::url(host, id)));
                    }
                }
            }
            v
        }
        Record::Test { ts } => json!({
            "type": "test", "host": host, "ts": ts,
            "message": "Test message from the NexusBackup appliance (Settings → Forwarding).",
        }),
    }
}

// ---------------------------------------------------------------- TLS

/// Accepts a server certificate whose SHA-256 is pinned (`pin_sha256`, or a
/// certificate of `ca_pem` itself), else verifies the chain (host name
/// included) against the configured CA certificates or the web PKI roots.
#[derive(Debug)]
struct Verifier {
    provider: Arc<CryptoProvider>,
    pins: Vec<[u8; 32]>,
    webpki: Option<Arc<WebPkiServerVerifier>>,
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let digest: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&digest) {
            return Ok(ServerCertVerified::assertion());
        }
        match &self.webpki {
            Some(w) => w.verify_server_cert(end_entity, intermediates, name, ocsp, now),
            None => Err(Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)),
        }
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(msg, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(msg, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// `ab:cd:…` or `abcd…` (64 hex digits) → 32 bytes.
pub fn parse_pin(s: &str) -> Result<[u8; 32]> {
    let hex: String = s.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("pin_sha256: 64 hex digits");
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}

pub fn tls_config(ca_pem: Option<&str>, pin_sha256: Option<&str>) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut pins = Vec::new();
    if let Some(p) = pin_sha256 {
        pins.push(parse_pin(p)?);
    }
    let mut roots = RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("ca_pem: {e}"))?;
            if certs.is_empty() {
                bail!("ca_pem: no certificate");
            }
            for c in certs {
                pins.push(Sha256::digest(c.as_ref()).into());
                let _ = roots.add(c); // a leaf that is no valid anchor stays a pin
            }
        }
        None if pins.is_empty() => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        None => {}
    }
    let webpki = if roots.is_empty() {
        None
    } else {
        Some(WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?)
    };
    let v = Verifier {
        provider: provider.clone(),
        pins,
        webpki,
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(v))
        .with_no_client_auth())
}

// ---------------------------------------------------------------- sinks

/// One connection per batch: handshake, all frames, close_notify, then wait
/// for the receiver to close (a reset or a TLS error = not delivered).
pub fn send_syslog(s: &Syslog, host: &str, records: &[Record]) -> Result<()> {
    let cfg = Arc::new(tls_config(s.ca_pem.as_deref(), s.pin_sha256.as_deref())?);
    let name = s.host.trim_matches(['[', ']']);
    let mut last = anyhow::anyhow!("{name}: no address");
    let mut tcp = None;
    for addr in (name, s.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {name}"))?
    {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(t) => {
                tcp = Some(t);
                break;
            }
            Err(e) => last = anyhow::Error::new(e).context(format!("connecting {addr}")),
        }
    }
    let tcp = tcp.ok_or(last)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(30)))?;
    let conn = ClientConnection::new(cfg, ServerName::try_from(name.to_owned())?)?;
    let mut tls = StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    for r in records {
        buf.extend(frame(&rfc5424(r, host, &s.app_name, s.facility)));
    }
    tls.write_all(&buf).context("TLS")?;
    tls.flush()?;
    tls.conn.send_close_notify();
    while tls.conn.wants_write() {
        tls.conn.write_tls(&mut tls.sock)?;
    }
    tls.sock.shutdown(Shutdown::Write)?;
    let mut sink = [0u8; 1024];
    loop {
        match tls.read(&mut sink) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            // closed without close_notify, or no answer in time: the data was sent
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::WouldBlock | ErrorKind::TimedOut
                ) =>
            {
                return Ok(())
            }
            Err(e) => return Err(e).context("syslog receiver closed the connection abnormally"),
        }
    }
}

/// Header values of the HTTPS sink, opened (sealed at the URL).
pub fn open_headers(h: &Https, key: &SchedulerKey) -> Result<BTreeMap<String, String>> {
    h.headers
        .iter()
        .map(|(k, v)| {
            let open = if catalog::secret::is_sealed(v) {
                key.open(&forwarding::header_location(k, &h.url), v)
                    .with_context(|| format!("https header {k}"))?
                    .to_string()
            } else {
                v.clone()
            };
            Ok((k.clone(), open))
        })
        .collect()
}

pub fn send_https(h: &Https, headers: &BTreeMap<String, String>, host: &str, records: &[Record]) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .use_preconfigured_tls(tls_config(h.ca_pem.as_deref(), h.pin_sha256.as_deref())?)
        .timeout(Duration::from_secs(30))
        .build()?;
    let body: Vec<Value> = records.iter().map(|r| json_record(r, host)).collect();
    let mut req = client.post(&h.url).json(&body);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    req.send()?.error_for_status()?;
    Ok(())
}

/// "Send test message": one test record to every configured sink (enabled or
/// not), `"ok"` / `"error: …"` per sink.
pub fn test(cfg: &Forwarding, key: &SchedulerKey, host: &str) -> Value {
    let rec = [Record::Test { ts: catalog::now() }];
    let res = |r: Result<()>| match r {
        Ok(()) => json!("ok"),
        Err(e) => json!(format!("error: {e:#}")),
    };
    let mut out = serde_json::Map::new();
    if let Some(s) = &cfg.syslog {
        out.insert("syslog".into(), res(send_syslog(s, host, &rec)));
    }
    if let Some(h) = &cfg.https {
        out.insert(
            "https".into(),
            res(open_headers(h, key).and_then(|hd| send_https(h, &hd, host, &rec))),
        );
    }
    if out.is_empty() {
        out.insert("forwarding".into(), json!("error: no sink configured"));
    }
    Value::Object(out)
}

// ---------------------------------------------------------------- forwarder

pub struct Forwarder {
    db: Arc<Catalog>,
    key: SchedulerKey,
    host: String,
    /// per sink: consecutive failures, next attempt (unix seconds)
    retry: HashMap<&'static str, (u32, i64)>,
}

impl Forwarder {
    pub fn new(db: Arc<Catalog>, key: SchedulerKey, host: String) -> Self {
        Forwarder {
            db,
            key,
            host,
            retry: HashMap::new(),
        }
    }

    /// One round: every enabled sink that is not backing off delivers what is pending.
    pub fn step(&mut self, now: i64) {
        let cfg = match Forwarding::load(&self.db.conn()) {
            Ok(c) => c,
            Err(e) => return eprintln!("<3>forward: setting: {e:#}"),
        };
        for (sink, dest) in cfg.enabled() {
            if self.retry.get(sink).is_some_and(|(_, at)| now < *at) {
                continue;
            }
            match self.deliver(&cfg, sink, &dest, now) {
                Ok(()) => {
                    self.retry.remove(sink);
                }
                Err(e) => {
                    let n = self.retry.get(sink).map_or(0, |r| r.0) + 1;
                    let delay = (10i64 << (n - 1).min(5)).min(300);
                    self.retry.insert(sink, (n, now + delay));
                    let msg = format!("{e:#}");
                    eprintln!("<4>forward: {sink} ({dest}) failed (attempt {n}, next in {delay} s): {msg}");
                    if let Err(e) = self.db.conn().execute(
                        "UPDATE forward_state SET last_error = ?2, last_error_ts = ?3,
                           failing_since = COALESCE(failing_since, ?3) WHERE sink = ?1",
                        params![sink, msg, now],
                    ) {
                        eprintln!("<3>forward: state: {e:#}");
                    }
                }
            }
        }
    }

    /// The sink's cursors (audit seq, event seq); restarted at 0 for a new destination.
    fn cursor(&self, sink: &str, dest: &str) -> Result<(i64, i64)> {
        let c = self.db.conn();
        let row: Option<(String, i64, i64)> = c
            .query_row(
                "SELECT dest, audit_seq, event_seq FROM forward_state WHERE sink = ?1",
                [sink],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match row {
            Some((d, a, e)) if d == dest => Ok((a, e)),
            _ => {
                c.execute(
                    "INSERT OR REPLACE INTO forward_state (sink, dest, audit_seq, event_seq) VALUES (?1, ?2, 0, 0)",
                    params![sink, dest],
                )?;
                Ok((0, 0))
            }
        }
    }

    /// Up to `max` records after the cursors: audit entries first, then events.
    pub fn pending(&self, audit_seq: i64, event_seq: i64, max: usize) -> Result<Vec<Record>> {
        let c = self.db.conn();
        let mut out: Vec<Record> = c
            .prepare(
                "SELECT seq, ts, actor, action, target, details, prev_hash, hash FROM audit
                 WHERE seq > ?1 ORDER BY seq LIMIT ?2",
            )?
            .query_map(params![audit_seq, max as i64], |r| {
                Ok(Record::Audit {
                    seq: r.get(0)?,
                    ts: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    details: r.get(5)?,
                    prev_hash: r.get(6)?,
                    hash: r.get(7)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        let left = max - out.len();
        if left > 0 {
            let ev = c
                .prepare("SELECT seq, ts, type, payload FROM forward_events WHERE seq > ?1 ORDER BY seq LIMIT ?2")?
                .query_map(params![event_seq, left as i64], |r| {
                    let p: String = r.get(3)?;
                    Ok(Record::Event {
                        seq: r.get(0)?,
                        ts: r.get(1)?,
                        kind: r.get(2)?,
                        payload: serde_json::from_str(&p).unwrap_or(Value::Null),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            out.extend(ev);
        }
        Ok(out)
    }

    fn deliver(&self, cfg: &Forwarding, sink: &'static str, dest: &str, now: i64) -> Result<()> {
        let (mut a, mut e) = self.cursor(sink, dest)?;
        let (send, batch): (Box<dyn Fn(&[Record]) -> Result<()>>, usize) = match sink {
            "syslog" => {
                let s = cfg.syslog.clone().context("syslog")?;
                let host = self.host.clone();
                (Box::new(move |r| send_syslog(&s, &host, r)), SYSLOG_BATCH)
            }
            _ => {
                let h = cfg.https.clone().context("https")?;
                let headers = open_headers(&h, &self.key)?;
                let host = self.host.clone();
                let batch = h.batch_max.clamp(1, 1000) as usize;
                (Box::new(move |r| send_https(&h, &headers, &host, r)), batch)
            }
        };
        for _ in 0..ROUNDS {
            let recs = self.pending(a, e, batch)?;
            if recs.is_empty() {
                break;
            }
            send(&recs)?;
            for r in &recs {
                match r {
                    Record::Audit { seq, .. } => a = a.max(*seq),
                    Record::Event { seq, .. } => e = e.max(*seq),
                    Record::Test { .. } => {}
                }
            }
            self.db.conn().execute(
                "UPDATE forward_state SET audit_seq = ?2, event_seq = ?3, last_ok = ?4, last_error = NULL,
                   last_error_ts = NULL, failing_since = NULL WHERE sink = ?1 AND dest = ?5",
                params![sink, a, e, now, dest],
            )?;
        }
        Ok(())
    }
}

/// The forwarder thread (one round every `poll`).
pub fn spawn(db: Arc<Catalog>, key: SchedulerKey, host: String, poll: Duration) {
    std::thread::spawn(move || {
        let mut f = Forwarder::new(db, key, host);
        loop {
            f.step(catalog::now());
            std::thread::sleep(poll);
        }
    });
}

/// Deletes outbox events every enabled sink has (older than a day).
pub fn prune_outbox(db: &Catalog, now: i64) -> Result<()> {
    let c = db.conn();
    let cfg = Forwarding::load(&c)?;
    let mut upto = i64::MAX;
    for (sink, dest) in cfg.enabled() {
        let seq: i64 = c
            .query_row(
                "SELECT event_seq FROM forward_state WHERE sink = ?1 AND dest = ?2",
                params![sink, dest],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        upto = upto.min(seq);
    }
    c.execute(
        "DELETE FROM forward_events WHERE seq <= ?1 AND ts < ?2",
        params![upto, now - OUTBOX_KEEP_SECS],
    )?;
    Ok(())
}

impl Scheduler {
    /// Each tick: the daily `audit.anchor`, and the `forwarding:<sink>` alert of
    /// a sink failing for [`ALERT_AFTER_SECS`] (resolved when it delivers again,
    /// or is disabled / removed).
    pub(crate) fn check_forwarding(&mut self, now: i64) -> Result<()> {
        self.anchor_audit(now)?;
        let (cfg, states) = {
            let c = self.db.conn();
            let cfg = Forwarding::load(&c)?;
            let states: Vec<(String, String, Option<i64>, Option<String>)> = c
                .prepare("SELECT sink, dest, failing_since, last_error FROM forward_state")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<_, _>>()?;
            (cfg, states)
        };
        let enabled = cfg.enabled();
        for sink in ["syslog", "https"] {
            let key = forwarding::alert_key(sink);
            let dest = enabled.iter().find(|(s, _)| *s == sink).map(|(_, d)| d);
            let failing = states
                .iter()
                .find(|(s, d, ..)| s == sink && Some(d) == dest)
                .and_then(|(_, d, since, err)| since.map(|t| (d, t, err.clone().unwrap_or_default())));
            match failing {
                Some((d, since, err)) if now - since >= ALERT_AFTER_SECS => self.raise(
                    "warning",
                    "forwarding",
                    &key,
                    &format!(
                        "forwarding to the {sink} sink {d} has failed for {} minutes: {err}",
                        (now - since) / 60
                    ),
                    None,
                )?,
                Some(_) => {}
                None => self.resolve(&key)?,
            }
        }
        Ok(())
    }

    /// Writes `audit.anchor` {head_seq, head_hash} once per UTC day.
    fn anchor_audit(&mut self, now: i64) -> Result<()> {
        let day = now.div_euclid(86400);
        if self.anchor_day.is_none() {
            let last: Option<i64> = self
                .db
                .conn()
                .query_row(
                    "SELECT ts FROM audit WHERE action = 'audit.anchor' ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            self.anchor_day = Some(last.map_or(i64::MIN, |t| t.div_euclid(86400)));
        }
        if self.anchor_day >= Some(day) {
            return Ok(());
        }
        let head: Option<(i64, String)> = self
            .db
            .conn()
            .query_row("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((seq, hash)) = head {
            self.db.audit(
                ACTOR,
                "audit.anchor",
                "audit/chain",
                &json!({"head_seq": seq, "head_hash": hash}),
            )?;
        }
        self.anchor_day = Some(day);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(seq: i64, details: &str) -> Record {
        Record::Audit {
            seq,
            ts: 1_760_257_800,
            actor: "alice".into(),
            action: "user.create".into(),
            target: "user/b\"o]b\\".into(),
            details: details.into(),
            prev_hash: "0".repeat(64),
            hash: "ab".repeat(32),
        }
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_760_257_800), "2025-10-12T08:30:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    /// RFC 5424 header, SD escaping (`"`, `\`, `]`), MSG without control
    /// characters, octet-counting frame = byte length (UTF-8).
    #[test]
    fn rfc5424_format_and_framing() {
        assert_eq!(sd_escape(r#"a"b\c]d"#), r#"a\"b\\c\]d"#);
        let m = rfc5424(&audit(7, "{\"x\":\"é\\n\"}"), "nexus 1", "nexus", 13);
        assert_eq!(
            m,
            format!(
                "<109>1 2025-10-12T08:30:00Z nexus_1 nexus - audit [nexus@32473 seq=\"7\" hash=\"{}\" actor=\"alice\" \
                 action=\"user.create\" target=\"user/b\\\"o\\]b\\\\\"] user.create user/b\"o]b\\ by alice: {{\"x\":\"é\\n\"}}",
                "ab".repeat(32)
            )
        );
        let f = frame(&m);
        let (len, rest) = std::str::from_utf8(&f).unwrap().split_once(' ').unwrap();
        assert_eq!(len.parse::<usize>().unwrap(), rest.len());
        assert!(
            rest.len() > rest.chars().count(),
            "length counts octets, not characters"
        );
        let ev = Record::Event {
            seq: 3,
            ts: 0,
            kind: "alert".into(),
            payload: json!({"event": "raised", "id": 9, "severity": "critical", "kind": "verify", "key": "verify:acme",
                            "message": "line1\nline2", "tenant": "acme"}),
        };
        let m = rfc5424(&ev, "h", "", 16);
        assert!(
            m.starts_with("<130>1 1970-01-01T00:00:00Z h - - alert [nexus@32473 outbox_seq=\"3\" id=\"9\""),
            "{m}"
        );
        assert!(m.ends_with("alert 9 raised critical verify: line1 line2"), "{m}");
        let job = Record::Event {
            seq: 4,
            ts: 0,
            kind: "job".into(),
            payload: json!({"id": 5, "kind": "backup", "tenant": "acme", "state": "failed", "requested_by": "scheduler"}),
        };
        assert!(rfc5424(&job, "h", "nexus", 13).starts_with("<108>1 "));
        let j = json_record(&audit(7, "{\"a\":1}"), "h");
        assert_eq!(
            (j["type"].as_str(), j["details"]["a"].as_i64()),
            (Some("audit"), Some(1))
        );
        assert_eq!(json_record(&ev, "h")["alert_url"], "https://h/#/alerts?id=9");
    }

    #[test]
    fn pins() {
        assert!(parse_pin("zz").is_err());
        let p = "ab:".repeat(31) + "ab";
        assert_eq!(parse_pin(&p).unwrap(), [0xab; 32]);
        assert!(tls_config(Some("not pem"), None).is_err());
        assert!(tls_config(None, None).is_ok());
    }
}
