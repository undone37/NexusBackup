//! S3 offsite backend (plan §9.3): a minimal own client, AWS Signature V4 in
//! the `Authorization` header, HTTPS only (rustls), no AWS SDK.
//!
//! - **Addressing**: virtual-hosted style (`https://<bucket>.<endpoint>/<key>`)
//!   or path style (`https://<endpoint>/<bucket>/<key>`, needed for MinIO and
//!   buckets with dots). All keys live under `prefix/`.
//! - **TLS**: the public web PKI (compiled-in Mozilla roots), or exactly the
//!   certificates in `ca_pem` (a CA, or the endpoint's own certificate = pin)
//!   for on-prem endpoints.
//! - **Payload**: every request signs the SHA-256 of its body
//!   (`x-amz-content-sha256`, no `UNSIGNED-PAYLOAD`); bodies also carry
//!   `Content-MD5`, which Object Lock requires for writes.
//! - **put never overwrites**: HEAD first (`AlreadyExists` without uploading),
//!   then `PUT` with `If-None-Match: *`, so a concurrent writer loses with 412.
//!   Providers that ignore `If-None-Match` leave a race between HEAD and PUT
//!   (two writers of the same new key); with versioning + Object Lock the
//!   older version still exists. The appliance is the only writer of a
//!   tenant prefix, and pack ids are random, so the race needs a second
//!   appliance writing the same prefix.
//! - **Multipart** above `multipart_threshold` (64 MiB): parts of `part_size`,
//!   each with Content-MD5 and signed SHA-256; `If-None-Match: *` on complete;
//!   aborted on failure (plus a bucket lifecycle rule for leftovers).
//! - **Object Lock** (`lock = true`): `put_locked` sets compliance mode and
//!   retain-until; `extend_lock` uses PutObjectRetention (only ever later);
//!   `lock_of` reads it back with HEAD.
//! - **Storage class**: `storage_class_packs` for `packs/…`,
//!   `storage_class_meta` for everything else (indexes, manifests, keys).
//! - **Retries**: transport errors, 5xx, 429 and S3 throttling codes, with
//!   exponential backoff (doubling up to 30 s, with jitter). 4xx answers are
//!   final and mapped to `io::ErrorKind`s (404 NotFound, 403 PermissionDenied,
//!   412 AlreadyExists for puts).
//!
//! The client is blocking (reqwest's blocking client runs its own runtime
//! thread): don't call it from inside a tokio runtime.

use crate::remote::{check, Remote};
use crate::xml;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use md5::Md5;
use reqwest::blocking::Client;
use reqwest::Method;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Upper bound for a whole-object GET (`len = None`) and for XML answers.
const MAX_GET: u64 = 1 << 30;
const MAX_XML: u64 = 16 << 20;
/// Locks ending sooner than this are not set (S3 refuses dates in the past;
/// a lock of a few seconds protects nothing).
const LOCK_MIN_SECS: u64 = 60;

#[derive(Clone)]
pub struct S3Config {
    /// `https://host[:port]` (no path)
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// key prefix (tenant root), without leading/trailing `/`; may be empty
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
    pub path_style: bool,
    /// PEM certificates to trust instead of the web PKI (CA or pinned leaf)
    pub ca_pem: Option<Vec<u8>>,
    pub storage_class_packs: Option<String>,
    pub storage_class_meta: Option<String>,
    /// bucket has Object Lock: set compliance retention on writes
    pub lock: bool,
    /// send `If-None-Match: *` on puts (S3 since 2024, MinIO, Ceph RGW)
    pub conditional_put: bool,
    pub multipart_threshold: usize,
    pub part_size: usize,
    pub connect_timeout: Duration,
    /// per request, plus 1 s per 256 KiB of body
    pub request_timeout: Duration,
    pub retries: u32,
    pub backoff: Duration,
}

impl S3Config {
    pub fn new(endpoint: &str, region: &str, bucket: &str, access_key: &str, secret_key: &str) -> Self {
        S3Config {
            endpoint: endpoint.into(),
            region: region.into(),
            bucket: bucket.into(),
            prefix: String::new(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            path_style: false,
            ca_pem: None,
            storage_class_packs: None,
            storage_class_meta: None,
            lock: false,
            conditional_put: true,
            multipart_threshold: 64 << 20,
            part_size: 16 << 20,
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(60),
            retries: 4,
            backoff: Duration::from_millis(500),
        }
    }
}

// ------------------------------------------------------------------ SigV4

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac takes any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// RFC 3986 encoding as SigV4 wants it: everything but `A-Za-z0-9-_.~`
/// (and `/` when `keep_slash`) as `%XX`.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Canonical query string: encoded pairs sorted by key, then value.
pub fn canonical_query(q: &[(&str, &str)]) -> String {
    let mut v: Vec<(String, String)> = q
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    v.sort();
    v.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// SigV4 inputs for one request.
pub struct SignInput<'a> {
    pub method: &'a str,
    /// already URI-encoded path (`/bucket/key` or `/key`)
    pub uri: &'a str,
    /// canonical query string ([`canonical_query`])
    pub query: &'a str,
    /// headers to sign: (name, value); names are lower-cased here
    pub headers: &'a [(String, String)],
    pub payload_hash: &'a str,
    /// `YYYYMMDDTHHMMSSZ`
    pub amz_date: &'a str,
    pub region: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
}

/// Returns (canonical request, string to sign, signature, Authorization header).
pub fn sign(i: &SignInput) -> (String, String, String, String) {
    let mut h: Vec<(String, String)> = i
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.split_ascii_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    h.sort();
    let signed: Vec<&str> = h.iter().map(|(k, _)| k.as_str()).collect();
    let signed = signed.join(";");
    let mut canon = format!("{}\n{}\n{}\n", i.method, i.uri, i.query);
    for (k, v) in &h {
        canon.push_str(&format!("{k}:{v}\n"));
    }
    canon.push_str(&format!("\n{signed}\n{}", i.payload_hash));
    let date = &i.amz_date[..8];
    let scope = format!("{date}/{}/s3/aws4_request", i.region);
    let sts = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        i.amz_date,
        sha256_hex(canon.as_bytes())
    );
    let mut k = hmac(format!("AWS4{}", i.secret_key).as_bytes(), date.as_bytes());
    for part in [i.region, "s3", "aws4_request"] {
        k = hmac(&k, part.as_bytes());
    }
    let sig = hex(&hmac(&k, sts.as_bytes()));
    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed},Signature={sig}",
        i.access_key
    );
    (canon, sts, sig, auth)
}

// ------------------------------------------------------------------ time

fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn split_time(secs: u64) -> (i64, u32, u32, u64, u64, u64) {
    let (y, m, d) = civil((secs / 86400) as i64);
    let s = secs % 86400;
    (y, m, d, s / 3600, s / 60 % 60, s % 60)
}

/// `YYYYMMDDTHHMMSSZ` (x-amz-date).
pub fn amz_date(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = split_time(secs);
    format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z")
}

/// `YYYY-MM-DDTHH:MM:SSZ` (Object Lock dates).
pub fn iso_date(secs: u64) -> String {
    let (y, m, d, hh, mm, ss) = split_time(secs);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff]Z` (fractions are dropped).
pub fn parse_iso(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| -> Option<u32> {
        let t = s.get(r)?;
        t.bytes().all(|c| c.is_ascii_digit()).then(|| t.parse().ok())?
    };
    let rest = &s[19..];
    let rest = match rest.strip_prefix('.') {
        Some(f) => f.trim_start_matches(|c: char| c.is_ascii_digit()),
        None => rest,
    };
    if rest != "Z" {
        return None;
    }
    let (y, mo, d, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(y as i64, mo, d);
    u64::try_from(days * 86400 + (h * 3600 + mi * 60 + se) as i64).ok()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

// ------------------------------------------------------------------ errors

/// An S3 error answer: HTTP status + `<Error><Code>`/`<Message>`.
#[derive(Debug, Clone, PartialEq)]
pub struct S3Error {
    pub status: u16,
    pub code: String,
    pub message: String,
}

fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// Parses an `<Error>` document (also the 200-with-error answer of CompleteMultipartUpload).
pub fn parse_error(status: u16, body: &[u8]) -> S3Error {
    let (code, message) = match xml::parse(body) {
        Ok(e) if e.name == "Error" => (
            clean(e.text_of("Code").unwrap_or_default()),
            clean(e.text_of("Message").unwrap_or_default()),
        ),
        _ => (String::new(), String::new()),
    };
    S3Error { status, code, message }
}

impl S3Error {
    fn retryable(&self) -> bool {
        self.status >= 500
            || self.status == 429
            || matches!(
                self.code.as_str(),
                "SlowDown" | "RequestTimeout" | "InternalError" | "ServiceUnavailable" | "ConditionalRequestConflict"
            )
    }

    pub fn into_io(self) -> io::Error {
        let kind = match (self.status, self.code.as_str()) {
            (_, "NoSuchKey") | (404, "") => io::ErrorKind::NotFound,
            (_, "AccessDenied" | "ObjectLocked") | (403, _) => io::ErrorKind::PermissionDenied,
            // MinIO: "Object is WORM protected and cannot be overwritten"
            (400, "InvalidRequest") if self.message.contains("WORM") => io::ErrorKind::PermissionDenied,
            (412, _) | (_, "PreconditionFailed") => io::ErrorKind::AlreadyExists,
            (416, _) => io::ErrorKind::UnexpectedEof,
            (400, "InvalidArgument" | "InvalidRequest") => io::ErrorKind::InvalidInput,
            _ => io::ErrorKind::Other,
        };
        let hint = if self.code == "RequestTimeTooSkewed" {
            " (check the appliance clock / NTS)"
        } else {
            ""
        };
        io::Error::new(
            kind,
            format!("S3 {} {}: {}{hint}", self.status, self.code, self.message),
        )
    }
}

/// A ListObjectsV2 page: (files `(name, size)`, dirs, next continuation token).
pub type ListPage = (Vec<(String, u64)>, Vec<String>, Option<String>);

/// Parses a ListObjectsV2 answer; names are relative to `prefix`. Names that
/// are empty or contain `/` (a server ignoring the delimiter) are dropped.
pub fn parse_list(body: &[u8], prefix: &str) -> io::Result<ListPage> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("ListObjectsV2: {m}"));
    let r = xml::parse(body).map_err(|e| bad(&e.to_string()))?;
    if r.name != "ListBucketResult" {
        return Err(bad("unexpected document"));
    }
    let rel = |k: &str| k.strip_prefix(prefix).filter(|n| !n.is_empty()).map(str::to_owned);
    let mut files = Vec::new();
    for c in r.children("Contents") {
        let Some(name) = c.text_of("Key").and_then(rel) else {
            continue;
        };
        if name.contains('/') {
            continue;
        }
        let size = c
            .text_of("Size")
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| bad("bad Size"))?;
        files.push((name, size));
    }
    let mut dirs = Vec::new();
    for c in r.children("CommonPrefixes") {
        let Some(p) = c.text_of("Prefix").and_then(rel) else {
            continue;
        };
        let Some(d) = p.strip_suffix('/') else { continue };
        if !d.is_empty() && !d.contains('/') {
            dirs.push(d.to_owned());
        }
    }
    let next = if r.text_of("IsTruncated").map(str::trim) == Some("true") {
        Some(
            r.text_of("NextContinuationToken")
                .filter(|t| !t.is_empty())
                .ok_or_else(|| bad("truncated without NextContinuationToken"))?
                .to_owned(),
        )
    } else {
        None
    };
    Ok((files, dirs, next))
}

// ------------------------------------------------------------------ TLS

mod tls {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::client::WebPkiServerVerifier;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
    use std::io;
    use std::sync::Arc;

    /// Accepts a certificate that is byte-identical to a configured one (pin),
    /// else verifies the chain against the configured certificates as roots.
    #[derive(Debug)]
    struct Verifier {
        provider: Arc<CryptoProvider>,
        pins: Vec<Vec<u8>>,
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
            if self.pins.iter().any(|p| p.as_slice() == end_entity.as_ref()) {
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

    /// TLS config trusting exactly the certificates in `pem`.
    pub fn config(pem: &[u8]) -> io::Result<ClientConfig> {
        let bad = |m: String| io::Error::new(io::ErrorKind::InvalidInput, format!("ca_pem: {m}"));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let pins: Vec<Vec<u8>> = CertificateDer::pem_slice_iter(pem)
            .map(|c| c.map(|c| c.as_ref().to_vec()))
            .collect::<Result<_, _>>()
            .map_err(|e| bad(e.to_string()))?;
        if pins.is_empty() {
            return Err(bad("no certificate".into()));
        }
        let mut roots = RootCertStore::empty();
        for p in &pins {
            let _ = roots.add(CertificateDer::from(p.clone())); // a leaf that is no valid anchor stays a pin
        }
        let webpki = if roots.is_empty() {
            None
        } else {
            Some(
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                    .build()
                    .map_err(|e| bad(e.to_string()))?,
            )
        };
        let v = Verifier {
            provider: provider.clone(),
            pins,
            webpki,
        };
        let mut c = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| bad(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(v))
            .with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(c)
    }
}

// ------------------------------------------------------------------ client

pub struct S3Remote {
    cfg: S3Config,
    http: Client,
    /// `https://authority`
    base: String,
    /// Host header value (authority)
    host: String,
    /// `/bucket` (path style) or empty
    bucket_path: String,
    root: String,
}

/// HEAD answer of an object.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectInfo {
    pub size: u64,
    pub etag: String,
    pub version_id: Option<String>,
    pub retain_until: Option<u64>,
    pub lock_mode: Option<String>,
}

struct Resp {
    status: u16,
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Valid bucket names (S3 rules, without the legacy uppercase ones).
pub fn valid_bucket(b: &str) -> bool {
    (3..=63).contains(&b.len())
        && b.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
        && b.as_bytes()[0].is_ascii_alphanumeric()
        && b.as_bytes()[b.len() - 1].is_ascii_alphanumeric()
        && !b.contains("..")
}

/// `https://host[:port]` → (host, port); refuses anything else (paths, userinfo, http).
pub fn parse_endpoint(e: &str) -> io::Result<(String, Option<u16>)> {
    let bad = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("endpoint {e:?}: expected https://host[:port]"),
        )
    };
    let rest = e.strip_prefix("https://").ok_or_else(bad)?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ', '\\']) {
        return Err(bad());
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, p) = v6.split_once(']').ok_or_else(bad)?;
        (format!("[{h}]"), p)
    } else {
        match rest.rsplit_once(':') {
            Some((h, _)) => (h.to_owned(), &rest[h.len()..]),
            None => (rest.to_owned(), ""),
        }
    };
    let port = match port.strip_prefix(':') {
        Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0).ok_or_else(bad)?),
        None if port.is_empty() => None,
        None => return Err(bad()),
    };
    let ok = host.starts_with('[')
        || (!host.is_empty()
            && host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-'));
    if !ok {
        return Err(bad());
    }
    Ok((host.to_ascii_lowercase(), port))
}

fn md5_b64(b: &[u8]) -> String {
    B64.encode(Md5::digest(b))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

impl S3Remote {
    pub fn new(cfg: S3Config) -> io::Result<Self> {
        let inval = |m: String| io::Error::new(io::ErrorKind::InvalidInput, m);
        let (host, port) = parse_endpoint(&cfg.endpoint)?;
        if !valid_bucket(&cfg.bucket) {
            return Err(inval(format!("bucket {:?}: invalid name", cfg.bucket)));
        }
        if !cfg.path_style && (cfg.bucket.contains('.') || host.starts_with('[')) {
            return Err(inval("bucket names with dots and IP endpoints need path_style".into()));
        }
        let root = cfg.prefix.trim_matches('/').to_owned();
        if !root.is_empty() {
            check(&root)?;
        }
        if cfg.region.is_empty() || cfg.access_key.is_empty() || cfg.secret_key.is_empty() {
            return Err(inval("region, access_key and secret_key are required".into()));
        }
        if cfg.part_size < (5 << 20) || cfg.multipart_threshold < cfg.part_size {
            return Err(inval("part_size >= 5 MiB and multipart_threshold >= part_size".into()));
        }
        let host = if cfg.path_style {
            host
        } else {
            format!("{}.{host}", cfg.bucket)
        };
        let authority = match port {
            Some(p) if p != 443 => format!("{host}:{p}"),
            _ => host,
        };
        let mut b = Client::builder()
            .connect_timeout(cfg.connect_timeout)
            .timeout(None)
            .http1_only()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(16)
            .user_agent(concat!("nexus-offsite/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = &cfg.ca_pem {
            b = b.use_preconfigured_tls(tls::config(pem)?);
        }
        let http = b.build().map_err(io::Error::other)?;
        Ok(S3Remote {
            bucket_path: if cfg.path_style {
                format!("/{}", cfg.bucket)
            } else {
                String::new()
            },
            base: format!("https://{authority}"),
            host: authority,
            root,
            cfg,
            http,
        })
    }

    fn key(&self, path: &str) -> String {
        if self.root.is_empty() {
            path.to_owned()
        } else {
            format!("{}/{path}", self.root)
        }
    }

    fn storage_class(&self, path: &str) -> Option<&str> {
        if path.starts_with("packs/") {
            self.cfg.storage_class_packs.as_deref()
        } else {
            self.cfg.storage_class_meta.as_deref()
        }
    }

    /// One signed request with retries. `key = None` addresses the bucket.
    /// Returns every answer that is not retryable (callers map statuses).
    fn request(
        &self,
        method: Method,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(String, String)],
        body: &[u8],
        max_body: u64,
    ) -> io::Result<Resp> {
        let uri = match key {
            Some(k) => format!("{}/{}", self.bucket_path, uri_encode(k, true)),
            None => format!("{}/", self.bucket_path),
        };
        let q = canonical_query(query);
        let url = if q.is_empty() {
            format!("{}{uri}", self.base)
        } else {
            format!("{}{uri}?{q}", self.base)
        };
        let payload_hash = if body.is_empty() {
            EMPTY_SHA256.to_owned()
        } else {
            sha256_hex(body)
        };
        let timeout = self.cfg.request_timeout + Duration::from_secs(body.len() as u64 / (256 << 10));
        let mut delay = self.cfg.backoff;
        let mut attempt = 0;
        loop {
            let date = amz_date(now_secs());
            let mut headers = vec![
                ("host".to_owned(), self.host.clone()),
                ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
                ("x-amz-date".to_owned(), date.clone()),
            ];
            headers.extend(extra.iter().cloned());
            let (_, _, _, auth) = sign(&SignInput {
                method: method.as_str(),
                uri: &uri,
                query: &q,
                headers: &headers,
                payload_hash: &payload_hash,
                amz_date: &date,
                region: &self.cfg.region,
                access_key: &self.cfg.access_key,
                secret_key: &self.cfg.secret_key,
            });
            let mut rb = self.http.request(method.clone(), &url).timeout(timeout);
            for (k, v) in &headers {
                rb = rb.header(k.as_str(), v.as_str());
            }
            rb = rb.header("authorization", auth);
            if !body.is_empty() || method == Method::PUT || method == Method::POST {
                rb = rb.body(body.to_vec());
            }
            let r: io::Result<Resp> = match rb.send() {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let headers = resp.headers().clone();
                    let limit = if (200..300).contains(&status) {
                        max_body
                    } else {
                        MAX_XML
                    };
                    let mut body = Vec::new();
                    // a body cut off mid-transfer is a transport error (retried)
                    match resp.take(limit + 1).read_to_end(&mut body) {
                        Ok(_) if body.len() as u64 > limit => {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "S3 answer too large"));
                        }
                        Ok(_) => Ok(Resp { status, headers, body }),
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(io::Error::other(e)),
            };
            let retry_err: io::Error = match r {
                Ok(resp) if resp.status < 300 => return Ok(resp),
                Ok(resp) => {
                    let e = parse_error(resp.status, &resp.body);
                    if !e.retryable() {
                        return Ok(resp);
                    }
                    e.into_io()
                }
                Err(e) => e,
            };
            if attempt >= self.cfg.retries {
                return Err(retry_err);
            }
            attempt += 1;
            let jitter = rand::random::<f64>() * 0.5 + 0.75;
            std::thread::sleep(delay.mul_f64(jitter));
            delay = (delay * 2).min(Duration::from_secs(30));
        }
    }

    fn fail(resp: Resp) -> io::Error {
        parse_error(resp.status, &resp.body).into_io()
    }

    /// HEAD of an object (`None` if it does not exist).
    pub fn head(&self, path: &str) -> io::Result<Option<ObjectInfo>> {
        check(path)?;
        let r = self.request(Method::HEAD, Some(&self.key(path)), &[], &[], &[], 0)?;
        if r.status == 404 {
            return Ok(None);
        }
        if r.status >= 300 {
            return Err(Self::fail(r));
        }
        Ok(Some(ObjectInfo {
            size: r
                .header("content-length")
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HEAD without Content-Length"))?,
            etag: r.header("etag").unwrap_or_default().trim_matches('"').to_owned(),
            version_id: r.header("x-amz-version-id").map(str::to_owned),
            retain_until: r.header("x-amz-object-lock-retain-until-date").and_then(parse_iso),
            lock_mode: r.header("x-amz-object-lock-mode").map(str::to_owned),
        }))
    }

    /// Deletes one object version (admin/test tool: the appliance's own
    /// credentials should not be allowed to, and Object Lock refuses it for
    /// locked versions anyway).
    pub fn delete_version(&self, path: &str, version_id: &str) -> io::Result<()> {
        check(path)?;
        let r = self.request(
            Method::DELETE,
            Some(&self.key(path)),
            &[("versionId", version_id)],
            &[],
            &[],
            0,
        )?;
        if r.status >= 300 {
            return Err(Self::fail(r));
        }
        Ok(())
    }

    fn lock_headers(&self, until: Option<u64>) -> Vec<(String, String)> {
        match until {
            Some(t) if self.cfg.lock && t > now_secs() + LOCK_MIN_SECS => vec![
                ("x-amz-object-lock-mode".into(), "COMPLIANCE".into()),
                ("x-amz-object-lock-retain-until-date".into(), iso_date(t)),
            ],
            _ => vec![],
        }
    }

    /// After a 412 or a failed complete: was it our own earlier attempt that landed?
    fn landed(&self, path: &str, size: u64, etag: &str) -> io::Result<()> {
        match self.head(path)? {
            Some(i) if i.size == size && i.etag == etag => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{path} exists"))),
        }
    }

    fn put_impl(&self, path: &str, data: &[u8], until: Option<u64>) -> io::Result<()> {
        check(path)?;
        if self.head(path)?.is_some() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{path} exists")));
        }
        let mut h = self.lock_headers(until);
        if let Some(c) = self.storage_class(path) {
            h.push(("x-amz-storage-class".into(), c.into()));
        }
        if data.len() > self.cfg.multipart_threshold {
            return self.multipart(path, data, h);
        }
        h.push(("content-md5".into(), md5_b64(data)));
        if self.cfg.conditional_put {
            h.push(("if-none-match".into(), "*".into()));
        }
        let r = self.request(Method::PUT, Some(&self.key(path)), &[], &h, data, MAX_XML)?;
        match r.status {
            200..=299 => Ok(()),
            412 => self.landed(path, data.len() as u64, &hex(&Md5::digest(data))),
            _ => Err(Self::fail(r)),
        }
    }

    fn multipart(&self, path: &str, data: &[u8], mut h: Vec<(String, String)>) -> io::Result<()> {
        let key = self.key(path);
        let r = self.request(Method::POST, Some(&key), &[("uploads", "")], &h, &[], MAX_XML)?;
        if r.status >= 300 {
            return Err(Self::fail(r));
        }
        let doc = xml::parse(&r.body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let id = doc
            .text_of("UploadId")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "CreateMultipartUpload: no UploadId"))?
            .to_owned();
        let res = (|| {
            let mut parts = Vec::new();
            let mut md5s = Vec::new();
            for (i, part) in data.chunks(self.cfg.part_size).enumerate() {
                let n = (i + 1).to_string();
                let md5 = Md5::digest(part);
                let ph = [("content-md5".to_owned(), B64.encode(md5))];
                let r = self.request(
                    Method::PUT,
                    Some(&key),
                    &[("partNumber", &n), ("uploadId", &id)],
                    &ph,
                    part,
                    MAX_XML,
                )?;
                if r.status >= 300 {
                    return Err(Self::fail(r));
                }
                let etag = r
                    .header("etag")
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "UploadPart: no ETag"))?
                    .to_owned();
                parts.push((n, etag));
                md5s.extend_from_slice(&md5);
            }
            let mut body = String::from("<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
            for (n, etag) in &parts {
                body.push_str(&format!(
                    "<Part><PartNumber>{n}</PartNumber><ETag>{}</ETag></Part>",
                    esc(etag)
                ));
            }
            body.push_str("</CompleteMultipartUpload>");
            let want_etag = format!("{}-{}", hex(&Md5::digest(&md5s)), parts.len());
            h.clear(); // storage class and lock went with CreateMultipartUpload
            h.push(("content-md5".into(), md5_b64(body.as_bytes())));
            if self.cfg.conditional_put {
                h.push(("if-none-match".into(), "*".into()));
            }
            let r = self.request(
                Method::POST,
                Some(&key),
                &[("uploadId", &id)],
                &h,
                body.as_bytes(),
                MAX_XML,
            );
            match r {
                Ok(r) if r.status < 300 => {
                    // 200 can still carry an <Error> (failure after the headers were sent)
                    match xml::parse(&r.body) {
                        Ok(d) if d.name == "Error" => {
                            let e = parse_error(500, &r.body);
                            self.landed(path, data.len() as u64, &want_etag)
                                .map_err(|_| e.into_io())
                        }
                        _ => Ok(()),
                    }
                }
                // 412, or NoSuchUpload because an earlier (retried) complete succeeded
                Ok(r) => {
                    let e = Self::fail(r);
                    self.landed(path, data.len() as u64, &want_etag).map_err(|x| {
                        if x.kind() == io::ErrorKind::AlreadyExists {
                            x
                        } else {
                            e
                        }
                    })
                }
                Err(e) => self.landed(path, data.len() as u64, &want_etag).map_err(|_| e),
            }
        })();
        if res.is_err() {
            let _ = self.request(Method::DELETE, Some(&key), &[("uploadId", &id)], &[], &[], MAX_XML);
        }
        res
    }

    fn retention_body(until: u64) -> String {
        format!(
            "<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>COMPLIANCE</Mode><RetainUntilDate>{}</RetainUntilDate></Retention>",
            iso_date(until)
        )
    }
}

impl Remote for S3Remote {
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()> {
        self.put_impl(path, data, None)
    }

    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>> {
        check(path)?;
        if len == Some(0) {
            return Ok(Vec::new());
        }
        let mut h = Vec::new();
        match len {
            Some(n) => h.push((
                "range".to_owned(),
                format!(
                    "bytes={offset}-{}",
                    offset
                        .checked_add(n - 1)
                        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
                ),
            )),
            None if offset > 0 => h.push(("range".to_owned(), format!("bytes={offset}-"))),
            None => {}
        }
        let max = len.unwrap_or(MAX_GET).min(MAX_GET);
        // a server ignoring Range answers 200 with the whole object
        let r = self.request(Method::GET, Some(&self.key(path)), &[], &h, &[], max + offset)?;
        let mut body = match r.status {
            206 => r.body,
            200 => r.body.get(offset as usize..).map(<[u8]>::to_vec).unwrap_or_default(),
            416 if len.is_none() => Vec::new(),
            _ => return Err(Self::fail(r)),
        };
        match len {
            Some(n) if (body.len() as u64) < n => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{path}: short read ({} of {n} bytes)", body.len()),
            )),
            Some(n) => {
                body.truncate(n as usize);
                Ok(body)
            }
            None if body.len() as u64 > MAX_GET => Err(io::Error::new(io::ErrorKind::InvalidData, "object too large")),
            None => Ok(body),
        }
    }

    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>> {
        let prefix = if dir.is_empty() {
            if self.root.is_empty() {
                String::new()
            } else {
                format!("{}/", self.root)
            }
        } else {
            check(dir)?;
            format!("{}/", self.key(dir))
        };
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..1_000_000 {
            let mut q = vec![("list-type", "2"), ("prefix", prefix.as_str()), ("delimiter", "/")];
            if let Some(t) = &token {
                q.push(("continuation-token", t.as_str()));
            }
            let r = self.request(Method::GET, None, &q, &[], &[], MAX_XML)?;
            if r.status >= 300 {
                return Err(Self::fail(r));
            }
            let (files, dirs, next) = parse_list(&r.body, &prefix)?;
            out.extend(files.into_iter().map(|(n, s)| (n, s, false)));
            out.extend(dirs.into_iter().map(|d| (d, 0, true)));
            match next {
                Some(n) if Some(&n) != token.as_ref() => token = Some(n),
                Some(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ListObjectsV2: token repeats",
                    ));
                }
                None => {
                    out.sort();
                    out.dedup();
                    return Ok(out);
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ListObjectsV2: too many pages",
        ))
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        check(path)?;
        let r = self.request(Method::DELETE, Some(&self.key(path)), &[], &[], &[], MAX_XML)?;
        if r.status >= 300 {
            return Err(Self::fail(r));
        }
        Ok(())
    }

    fn supports_locks(&self) -> bool {
        self.cfg.lock
    }

    fn put_locked(&self, path: &str, data: &[u8], retain_until: u64) -> io::Result<()> {
        self.put_impl(path, data, Some(retain_until))
    }

    fn extend_lock(&self, path: &str, until: u64) -> io::Result<()> {
        check(path)?;
        if !self.cfg.lock || until <= now_secs() + LOCK_MIN_SECS {
            return Ok(());
        }
        let body = Self::retention_body(until);
        let h = [("content-md5".to_owned(), md5_b64(body.as_bytes()))];
        let r = self.request(
            Method::PUT,
            Some(&self.key(path)),
            &[("retention", "")],
            &h,
            body.as_bytes(),
            MAX_XML,
        )?;
        if r.status < 300 {
            return Ok(());
        }
        // compliance mode refuses shortening: fine if it already lasts long enough
        let e = Self::fail(r);
        match self.lock_of(path) {
            Ok(Some(t)) if t >= until => Ok(()),
            _ => Err(e),
        }
    }

    fn lock_of(&self, path: &str) -> io::Result<Option<u64>> {
        match self.head(path)? {
            Some(i) => Ok(i.retain_until),
            None => Err(io::Error::new(io::ErrorKind::NotFound, format!("{path} not found"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AK: &str = "AKIAIOSFODNN7EXAMPLE";
    const SK: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const DATE: &str = "20130524T000000Z";

    fn h(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    fn sig(method: &str, uri: &str, query: &str, headers: &[(&str, &str)], payload: &str) -> String {
        sign(&SignInput {
            method,
            uri,
            query,
            headers: &h(headers),
            payload_hash: payload,
            amz_date: DATE,
            region: "us-east-1",
            access_key: AK,
            secret_key: SK,
        })
        .2
    }

    /// Known answers from the AWS documentation ("Signature Calculations for
    /// the Authorization Header: Transferring Payload in a Single Chunk").
    #[test]
    fn sigv4_aws_examples() {
        // GET Object with a range
        assert_eq!(
            sig(
                "GET",
                "/test.txt",
                "",
                &[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("Range", "bytes=0-9"),
                    ("x-amz-content-sha256", EMPTY_SHA256),
                    ("x-amz-date", DATE)
                ],
                EMPTY_SHA256
            ),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        // PUT Object
        let payload = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        assert_eq!(
            sig(
                "PUT",
                &format!("/{}", uri_encode("test$file.text", true)),
                "",
                &[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                    ("x-amz-date", DATE),
                    ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
                    ("x-amz-content-sha256", &payload)
                ],
                &payload
            ),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
        // GET Bucket Lifecycle (sub-resource without a value)
        assert_eq!(
            sig(
                "GET",
                "/",
                &canonical_query(&[("lifecycle", "")]),
                &[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", DATE),
                    ("x-amz-content-sha256", EMPTY_SHA256)
                ],
                EMPTY_SHA256
            ),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
        // GET Bucket (list objects), query sorted
        assert_eq!(
            sig(
                "GET",
                "/",
                &canonical_query(&[("prefix", "J"), ("max-keys", "2")]),
                &[
                    ("Host", "examplebucket.s3.amazonaws.com"),
                    ("x-amz-date", DATE),
                    ("x-amz-content-sha256", EMPTY_SHA256)
                ],
                EMPTY_SHA256
            ),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn canonical_request_shape() {
        let (canon, sts, _, auth) = sign(&SignInput {
            method: "GET",
            uri: "/test.txt",
            query: "",
            headers: &h(&[
                ("Host", "examplebucket.s3.amazonaws.com"),
                ("Range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", DATE),
            ]),
            payload_hash: EMPTY_SHA256,
            amz_date: DATE,
            region: "us-east-1",
            access_key: AK,
            secret_key: SK,
        });
        assert_eq!(
            canon,
            format!("GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:{DATE}\n\nhost;range;x-amz-content-sha256;x-amz-date\n{EMPTY_SHA256}")
        );
        assert_eq!(
            sts,
            "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
        );
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8"));
    }

    #[test]
    fn encoding_and_dates() {
        assert_eq!(uri_encode("a b/c~d$é", true), "a%20b/c~d%24%C3%A9");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(
            canonical_query(&[("uploadId", "x y"), ("partNumber", "2"), ("a", "")]),
            "a=&partNumber=2&uploadId=x%20y"
        );
        assert_eq!(amz_date(1_369_353_600), DATE);
        assert_eq!(iso_date(1_369_353_600), "2013-05-24T00:00:00Z");
        for t in [0, 951_782_400, 1_369_353_600, 4_102_444_799, 1_791_590_461] {
            assert_eq!(parse_iso(&iso_date(t)), Some(t));
        }
        assert_eq!(parse_iso("2013-05-24T00:00:00.123Z"), Some(1_369_353_600));
        for bad in [
            "",
            "2013-05-24",
            "2013-13-24T00:00:00Z",
            "2013-05-24T00:00:00",
            "2013-05-24T00:00:00+01:00",
            "+013-05-24T00:00:00Z",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn endpoints_and_buckets() {
        assert_eq!(
            parse_endpoint("https://s3.example.com").unwrap(),
            ("s3.example.com".into(), None)
        );
        assert_eq!(
            parse_endpoint("https://S3.example.com:9000/").unwrap(),
            ("s3.example.com".into(), Some(9000))
        );
        assert_eq!(
            parse_endpoint("https://[::1]:9000").unwrap(),
            ("[::1]".into(), Some(9000))
        );
        for bad in [
            "http://x",
            "https://",
            "https://a/b",
            "https://u@h",
            "https://h:0",
            "https://h:x",
            "x",
            "https://h:1:2",
            "https://[::1]x",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad}");
        }
        assert!(valid_bucket("nexus-offsite.t1") && valid_bucket("abc"));
        for bad in ["ab", "Abc", "-ab", "ab-", "a..b", "a_b", &"a".repeat(64)] {
            assert!(!valid_bucket(bad), "{bad}");
        }
    }

    #[test]
    fn list_and_error_parsing() {
        let body = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>t/a/</Prefix>
<KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys><Delimiter>/</Delimiter><IsTruncated>true</IsTruncated>
<NextContinuationToken>tok</NextContinuationToken>
<Contents><Key>t/a/c.bin</Key><LastModified>2026-10-09T00:00:00.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>10</Size></Contents>
<Contents><Key>other/x</Key><Size>1</Size></Contents><Contents><Key>t/a/</Key><Size>0</Size></Contents>
<Contents><Key>t/a/deep/x</Key><Size>1</Size></Contents>
<CommonPrefixes><Prefix>t/a/b/</Prefix></CommonPrefixes><CommonPrefixes><Prefix>t/a/b</Prefix></CommonPrefixes>
</ListBucketResult>"#;
        let (f, d, n) = parse_list(body, "t/a/").unwrap();
        assert_eq!(f, vec![("c.bin".to_string(), 10)]);
        assert_eq!(d, vec!["b".to_string()]);
        assert_eq!(n.as_deref(), Some("tok"));
        assert!(parse_list(
            b"<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            ""
        )
        .is_err());
        assert!(parse_list(b"<Error/>", "").is_err());
        assert!(parse_list(
            b"<ListBucketResult><Contents><Key>a</Key><Size>-1</Size></Contents></ListBucketResult>",
            ""
        )
        .is_err());

        let e = parse_error(
            403,
            b"<Error><Code>AccessDenied</Code><Message>Access Denied.\x01</Message></Error>",
        );
        assert_eq!(
            (e.code.as_str(), e.message.as_str()),
            ("AccessDenied", "Access Denied.")
        );
        assert_eq!(e.clone().into_io().kind(), io::ErrorKind::PermissionDenied);
        assert!(!e.retryable());
        assert_eq!(parse_error(404, b"").into_io().kind(), io::ErrorKind::NotFound);
        assert_eq!(
            parse_error(404, b"<Error><Code>NoSuchBucket</Code></Error>")
                .into_io()
                .kind(),
            io::ErrorKind::Other
        );
        assert_eq!(parse_error(412, b"").into_io().kind(), io::ErrorKind::AlreadyExists);
        assert!(parse_error(503, b"<Error><Code>SlowDown</Code></Error>").retryable());
        assert!(parse_error(400, b"<Error><Code>RequestTimeout</Code></Error>").retryable());
        assert!(parse_error(403, b"<Error><Code>RequestTimeTooSkewed</Code></Error>")
            .into_io()
            .to_string()
            .contains("clock"));
    }

    #[test]
    fn config_checks() {
        let c = |f: &dyn Fn(&mut S3Config)| {
            let mut c = S3Config::new("https://s3.example.com", "eu-central-1", "bucket", "ak", "sk");
            f(&mut c);
            S3Remote::new(c)
        };
        assert!(c(&|_| {}).is_ok());
        assert!(c(&|c| c.bucket = "a.b.c".into()).is_err(), "dots need path style");
        assert!(c(&|c| {
            c.bucket = "a.b.c".into();
            c.path_style = true
        })
        .is_ok());
        assert!(c(&|c| c.prefix = "../x".into()).is_err());
        assert!(c(&|c| c.secret_key.clear()).is_err());
        assert!(c(&|c| c.part_size = 1 << 20).is_err());
        assert!(c(&|c| c.ca_pem = Some(b"nope".to_vec())).is_err());
        let r = c(&|c| c.prefix = "/t1/".into()).unwrap();
        assert_eq!(r.key("packs/x"), "t1/packs/x");
        assert_eq!(r.host, "bucket.s3.example.com");
        assert_eq!(r.storage_class("packs/ab/x.pack"), None);
    }
}
