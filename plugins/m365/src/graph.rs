//! Microsoft Graph over HTTPS (blocking reqwest + rustls, public web PKI plus an
//! optional extra CA): app-only token with the certificate credential, refreshed
//! before expiry and once on 401; throttling (429/503/504 with `Retry-After`, else
//! exponential backoff) and transient errors retried; `@odata.nextLink` paging;
//! delta links; ranged downloads that resume after broken connections; small and
//! session uploads. Bearer tokens only ever go to the configured Graph origin.

use crate::auth::Credential;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use reqwest::Method;
use serde_json::{json, Value};
use std::io::{self, Read};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_ATTEMPTS: u32 = 8;
/// Range size of downloads (one request per range; a broken range is re-requested).
pub const RANGE: u64 = 32 << 20;
/// Files up to this size are uploaded in one PUT, larger ones through an upload session.
pub const SIMPLE_UPLOAD: u64 = 4 << 20;
/// Upload session fragment (a multiple of 320 KiB, as Graph requires).
pub const FRAGMENT: usize = 32 * 320 * 1024;

/// A Graph (or token endpoint) error answer.
#[derive(Debug)]
pub struct GraphError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub what: String,
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} → HTTP {} {}: {}",
            self.what, self.status, self.code, self.message
        )
    }
}
impl std::error::Error for GraphError {}

/// HTTP status of a Graph error in an error chain.
pub fn status(e: &anyhow::Error) -> Option<u16> {
    e.chain().find_map(|c| c.downcast_ref::<GraphError>()).map(|g| g.status)
}

pub fn graph_error(e: &anyhow::Error) -> Option<&GraphError> {
    e.chain().find_map(|c| c.downcast_ref::<GraphError>())
}

/// Microsoft's answer when the protected Teams APIs are not enabled for the app.
pub fn is_protected_api_denied(e: &anyhow::Error) -> bool {
    graph_error(e).is_some_and(|g| {
        g.status == 403 && {
            let m = g.message.to_ascii_lowercase();
            m.contains("protected api") || m.contains("protected-api") || m.contains("teams-protected-apis")
        }
    })
}

pub enum Body {
    None,
    Json(Value),
    Bytes(Vec<u8>, &'static str),
}

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub requests: u64,
    pub throttled: u64,
    pub retries: u64,
    pub tokens: u64,
}

pub struct Settings {
    /// `https://graph.microsoft.com` (or the configured host[:port])
    pub graph_origin: String,
    /// token endpoint `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`
    pub token_url: String,
    pub client_id: String,
    /// extra trusted CA certificates (PEM)
    pub ca_pem: Option<String>,
}

pub struct Graph {
    http: Client,
    origin: String,
    pub base: String,
    token_url: String,
    scope: String,
    client_id: String,
    cred: Credential,
    token: Option<(String, Instant)>,
    pub stats: Stats,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((1u64 << attempt.min(6)).min(60))
}

fn retry_after(r: &Response) -> Option<Duration> {
    let v = r.headers().get("retry-after")?.to_str().ok()?;
    v.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Percent-encoding for one path segment or query value.
pub fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// URL without its query (for messages: delta tokens and pre-authenticated download
/// URLs are credentials of a kind).
fn shown(url: &str) -> String {
    url.split('?').next().unwrap_or_default().to_owned()
}

fn error_of(r: Response, what: String) -> anyhow::Error {
    let status = r.status().as_u16();
    let text = r.text().unwrap_or_default();
    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let (code, message) = if v["error"].is_object() {
        (
            v["error"]["code"].as_str().unwrap_or_default().to_owned(),
            v["error"]["message"].as_str().unwrap_or_default().to_owned(),
        )
    } else if let Some(d) = v["error_description"].as_str() {
        // token endpoint: {"error": "invalid_client", "error_description": "AADSTS700027: …"}
        let code = d
            .split(':')
            .next()
            .filter(|c| c.starts_with("AADSTS"))
            .unwrap_or(v["error"].as_str().unwrap_or_default());
        (code.to_owned(), d.lines().next().unwrap_or(d).to_owned())
    } else {
        (String::new(), text.chars().take(300).collect())
    };
    GraphError {
        status,
        code,
        message,
        what,
    }
    .into()
}

impl Graph {
    pub fn new(s: Settings, cred: Credential) -> Result<Graph> {
        let mut b = Client::builder()
            .user_agent(concat!("ISV|NexusBackup|NexusBackup-M365/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(900))
            .pool_max_idle_per_host(4);
        if let Some(ca) = s.ca_pem.as_deref().filter(|c| !c.trim().is_empty()) {
            for p in pem::parse_many(crate::auth::normalize_pem(ca)).context("ca_cert: not PEM")? {
                if p.tag() == "CERTIFICATE" {
                    b = b.add_root_certificate(reqwest::Certificate::from_der(p.contents())?);
                }
            }
        }
        let origin = s.graph_origin.trim_end_matches('/').to_owned();
        let scope = format!("{}/.default", origin.split(':').take(2).collect::<Vec<_>>().join(":"));
        Ok(Graph {
            http: b.build()?,
            base: format!("{origin}/v1.0"),
            origin,
            token_url: s.token_url,
            scope,
            client_id: s.client_id,
            cred,
            token: None,
            stats: Stats::default(),
        })
    }

    pub fn thumbprint(&self) -> String {
        self.cred.thumbprint()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn ensure_ours(&self, url: &str) -> Result<()> {
        if !url.starts_with(&format!("{}/", self.origin)) {
            bail!("Graph returned a link to another host ({}); refused", shown(url));
        }
        Ok(())
    }

    /// A valid access token (new one if none or less than 5 minutes left).
    pub fn token(&mut self) -> Result<String> {
        if let Some((t, exp)) = &self.token {
            if Instant::now() + Duration::from_secs(300) < *exp {
                return Ok(t.clone());
            }
        }
        let assertion = self.cred.assertion(&self.client_id, &self.token_url, now())?;
        let form = [
            ("client_id", self.client_id.as_str()),
            ("scope", self.scope.as_str()),
            ("grant_type", "client_credentials"),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", assertion.as_str()),
        ];
        let body = form
            .iter()
            .map(|(k, v)| format!("{k}={}", enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let url = self.token_url.clone();
        let r = self.exec(
            Method::POST,
            &url,
            &Body::Bytes(body.into_bytes(), "application/x-www-form-urlencoded"),
            &[],
            false,
        )?;
        if !r.status().is_success() {
            return Err(error_of(r, "token request".into()));
        }
        let v: Value = r.json().context("token response")?;
        let t = v["access_token"]
            .as_str()
            .context("token response without access_token")?;
        let secs = v["expires_in"].as_u64().unwrap_or(3599);
        self.stats.tokens += 1;
        self.token = Some((t.to_owned(), Instant::now() + Duration::from_secs(secs)));
        Ok(t.to_owned())
    }

    /// One request with retries (throttling, transient errors, one token refresh on 401).
    pub fn exec(
        &mut self,
        method: Method,
        url: &str,
        body: &Body,
        headers: &[(&str, String)],
        auth: bool,
    ) -> Result<Response> {
        let mut attempt = 0;
        let mut refreshed = false;
        loop {
            attempt += 1;
            let mut rb = self.http.request(method.clone(), url);
            if auth {
                rb = rb.bearer_auth(self.token()?);
            }
            for (k, v) in headers {
                rb = rb.header(*k, v);
            }
            rb = match body {
                Body::None => rb,
                Body::Json(v) => rb.header("content-type", "application/json").body(v.to_string()),
                Body::Bytes(b, ct) => rb.header("content-type", *ct).body(b.clone()),
            };
            self.stats.requests += 1;
            let r = match rb.send() {
                Ok(r) => r,
                Err(e) if attempt < MAX_ATTEMPTS => {
                    self.stats.retries += 1;
                    let _ = e;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                Err(e) => return Err(anyhow!("{method} {}: {e}", shown(url))),
            };
            let st = r.status().as_u16();
            if st == 401 && auth && !refreshed {
                refreshed = true;
                self.token = None;
                continue;
            }
            if matches!(st, 429 | 503 | 504) && attempt < MAX_ATTEMPTS {
                self.stats.throttled += 1;
                let wait = retry_after(&r).unwrap_or_else(|| backoff(attempt));
                std::thread::sleep(wait.min(Duration::from_secs(300)));
                continue;
            }
            if matches!(st, 500 | 502) && attempt < 4 {
                self.stats.retries += 1;
                std::thread::sleep(backoff(attempt));
                continue;
            }
            return Ok(r);
        }
    }

    /// Authenticated request against Graph; non-2xx answers become [`GraphError`].
    pub fn call(&mut self, method: Method, url: &str, body: Body, headers: &[(&str, String)]) -> Result<Response> {
        self.ensure_ours(url)?;
        let r = self.exec(method.clone(), url, &body, headers, true)?;
        if !r.status().is_success() {
            return Err(error_of(r, format!("{method} {}", shown(url))));
        }
        Ok(r)
    }

    pub fn get(&mut self, path: &str, headers: &[(&str, String)]) -> Result<Value> {
        let url = self.url(path);
        let r = self.call(Method::GET, &url, Body::None, headers)?;
        r.json().with_context(|| format!("GET {}: invalid JSON", shown(&url)))
    }

    pub fn post(&mut self, path: &str, v: Value) -> Result<Value> {
        let url = self.url(path);
        let r = self.call(Method::POST, &url, Body::Json(v), &[])?;
        Ok(r.json().unwrap_or(Value::Null))
    }

    /// All pages of a collection (`url`: a path below `/v1.0` or a full next/delta link);
    /// returns the delta link of the last page, if any.
    pub fn pages(
        &mut self,
        url: &str,
        headers: &[(&str, String)],
        mut f: impl FnMut(Value) -> Result<()>,
    ) -> Result<Option<String>> {
        let mut next = if url.starts_with("https://") {
            url.to_owned()
        } else {
            self.url(url)
        };
        loop {
            let r = self.call(Method::GET, &next, Body::None, headers)?;
            let mut v: Value = r
                .json()
                .with_context(|| format!("GET {}: invalid JSON", shown(&next)))?;
            if let Value::Array(items) = v["value"].take() {
                for it in items {
                    f(it)?;
                }
            }
            if let Some(n) = v["@odata.nextLink"].as_str() {
                next = n.to_owned();
                continue;
            }
            return Ok(v["@odata.deltaLink"].as_str().map(str::to_owned));
        }
    }

    /// Whole body of a GET (small items: MIME messages).
    pub fn get_bytes(&mut self, path: &str, headers: &[(&str, String)]) -> Result<Vec<u8>> {
        let url = self.url(path);
        let mut r = self.call(Method::GET, &url, Body::None, headers)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)
            .with_context(|| format!("GET {}", shown(&url)))?;
        Ok(out)
    }

    /// Ranged download of `size` bytes (follows Graph's redirect to the file host).
    pub fn download(&mut self, path: &str, size: u64) -> Download<'_> {
        Download {
            url: self.url(path),
            g: self,
            size,
            pos: 0,
            end: 0,
            cur: None,
            fails: 0,
        }
    }

    /// Uploads `size` bytes to `item` (`/drives/{d}/items/{parent}:/{name}:`), never
    /// replacing an existing item (`conflictBehavior=fail`). Returns the new driveItem.
    pub fn upload(&mut self, item: &str, size: u64, data: &mut dyn Read) -> Result<Value> {
        if size <= SIMPLE_UPLOAD {
            let mut buf = Vec::with_capacity(size as usize);
            data.take(size).read_to_end(&mut buf)?;
            buf.resize(size as usize, 0);
            let url = self.url(&format!("{item}/content?@microsoft.graph.conflictBehavior=fail"));
            let r = self.call(Method::PUT, &url, Body::Bytes(buf, "application/octet-stream"), &[])?;
            return Ok(r.json().unwrap_or(Value::Null));
        }
        let s = self.post(
            &format!("{item}/createUploadSession"),
            json!({"item": {"@microsoft.graph.conflictBehavior": "fail"}}),
        )?;
        let up = s["uploadUrl"]
            .as_str()
            .context("upload session without uploadUrl")?
            .to_owned();
        if !up.starts_with("https://") {
            bail!("upload session URL is not https");
        }
        let mut pos = 0u64;
        let mut buf = vec![0u8; FRAGMENT];
        loop {
            let want = ((size - pos) as usize).min(FRAGMENT);
            let mut got = 0;
            while got < want {
                let n = data.read(&mut buf[got..want])?;
                if n == 0 {
                    buf[got..want].fill(0);
                    break;
                }
                got += n;
            }
            let range = format!("bytes {pos}-{}/{size}", pos + want as u64 - 1);
            // the session URL is pre-authenticated: no bearer token
            let r = self.exec(
                Method::PUT,
                &up,
                &Body::Bytes(buf[..want].to_vec(), "application/octet-stream"),
                &[("content-range", range)],
                false,
            )?;
            if !r.status().is_success() {
                return Err(error_of(r, format!("upload {}", shown(&up))));
            }
            pos += want as u64;
            if pos >= size {
                return Ok(r.json().unwrap_or(Value::Null));
            }
        }
    }
}

/// Reader over a ranged download: one GET per [`RANGE`] bytes; a range that breaks
/// off is requested again from the current position (up to 5 times).
pub struct Download<'a> {
    g: &'a mut Graph,
    url: String,
    size: u64,
    pos: u64,
    end: u64,
    cur: Option<Response>,
    fails: u32,
}

impl Download<'_> {
    /// Opens the first range (errors such as 404 surface before any byte is sent).
    pub fn start(&mut self) -> Result<()> {
        if self.size > 0 && self.cur.is_none() {
            self.open()?;
        }
        Ok(())
    }

    fn open(&mut self) -> Result<()> {
        let end = (self.pos + RANGE).min(self.size);
        let range = format!("bytes={}-{}", self.pos, end - 1);
        let url = self.url.clone();
        let r = self.g.call(Method::GET, &url, Body::None, &[("range", range)])?;
        match r.status().as_u16() {
            206 => self.end = end,
            200 if self.pos == 0 => self.end = self.size,
            s => bail!("GET {}: unexpected status {s} for a range", shown(&url)),
        }
        self.cur = Some(r);
        Ok(())
    }
}

impl Read for Download<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos >= self.size || buf.is_empty() {
                return Ok(0);
            }
            if self.cur.is_none() {
                if let Err(e) = self.open() {
                    self.fails += 1;
                    if self.fails > 5 || crate::graph::status(&e).is_some() {
                        return Err(io::Error::other(format!("{e:#}")));
                    }
                    continue;
                }
            }
            let want = buf.len().min((self.end - self.pos) as usize);
            match self.cur.as_mut().map(|r| r.read(&mut buf[..want])) {
                Some(Ok(0)) => {
                    if self.pos < self.end {
                        // connection ended early: ask again from here
                        self.fails += 1;
                        if self.fails > 5 {
                            return Err(io::Error::other("download broke off repeatedly"));
                        }
                    }
                    self.cur = None;
                }
                Some(Ok(n)) => {
                    self.pos += n as u64;
                    if self.pos >= self.end {
                        self.cur = None;
                    }
                    return Ok(n);
                }
                Some(Err(e)) => {
                    self.fails += 1;
                    self.cur = None;
                    if self.fails > 5 {
                        return Err(e);
                    }
                }
                None => unreachable!(),
            }
        }
    }
}
