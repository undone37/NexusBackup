//! `nexusctl update upload` (#28): an offline update bundle uploaded for sites without a browser path to the
//! appliance, with the same checks as Settings -> Updates (nexus-update verifies the signature, the version and
//! the checksums). Uploading is an administrator action and API tokens never act as administrators
//! (crates/web-api/src/tokens.rs), so this signs in with the administrator's password and TOTP code like the
//! web UI does, uploads, waits for the verification and signs out. Installing stays in the UI (approval).

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// An administrator's sign-in; `totp` is asked again for a step-up (a code is accepted only once).
pub struct Login<'a> {
    pub user: String,
    pub password: String,
    pub totp: &'a mut dyn FnMut() -> Result<String>,
}

struct Session {
    http: Client,
    base: String,
    cookie: String,
    csrf: String,
}

fn check(r: Response, what: &str) -> Result<Response> {
    let status = r.status();
    if status.is_success() {
        return Ok(r);
    }
    let text = r.text().unwrap_or_default();
    let msg = serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or(text);
    bail!("{what}: HTTP {status}: {msg}")
}

impl Session {
    fn req(&self, r: RequestBuilder) -> RequestBuilder {
        r.header(COOKIE, format!("nx_session={}", self.cookie))
            .header("X-CSRF-Token", &self.csrf)
    }
    fn get(&self, path: &str) -> Result<Value> {
        let r = self.req(self.http.get(format!("{}{path}", self.base))).send()?;
        Ok(check(r, path)?.json()?)
    }
    fn post(&self, path: &str, body: &Value) -> Result<Response> {
        check(
            self.req(self.http.post(format!("{}{path}", self.base)))
                .json(body)
                .send()?,
            path,
        )
    }
}

fn sign_in(http: Client, base: String, l: &mut Login) -> Result<Session> {
    let body = json!({"name": l.user, "password": l.password, "totp": (l.totp)()?});
    let r = check(http.post(format!("{base}/auth/login")).json(&body).send()?, "sign-in")?;
    let cookie = r
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok()?.strip_prefix("nx_session=")?.split(';').next())
        .next()
        .context("sign-in: no session cookie in the answer")?
        .to_owned();
    let csrf = r.json::<Value>()?["csrf"]
        .as_str()
        .context("sign-in: no CSRF token")?
        .to_owned();
    let s = Session {
        http,
        base,
        cookie,
        csrf,
    };
    let me = s.get("/auth/me")?;
    if me["user"]["role"] != "admin" {
        bail!(
            "{} is not an administrator: only administrators upload update bundles",
            l.user
        );
    }
    // a risk mark on the sign-in (an unusual hour or network) asks for the password and a new code once more
    if me["step_up"].is_object() && me["step_up"]["done"] != true {
        let code = (l.totp)()?;
        s.post(
            "/auth/step-up",
            &json!({"current_password": l.password, "current_totp": code}),
        )?;
    }
    Ok(s)
}

/// Uploads `file` and waits up to `wait` for nexus-update's verdict; the update status afterwards. `say` gets
/// progress lines.
pub fn upload(
    url: &str,
    ca_pem: Option<&str>,
    login: &mut Login,
    file: &std::path::Path,
    wait: Duration,
    say: &mut dyn FnMut(&str),
) -> Result<Value> {
    let parsed = reqwest::Url::parse(url).context("--url / NEXUS_URL: not a URL")?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && loopback) {
        bail!("--url / NEXUS_URL: https:// (http:// only for localhost)");
    }
    let f = std::fs::File::open(file).with_context(|| format!("{}", file.display()))?;
    let size = f.metadata()?.len();
    // no overall timeout: a bundle is about a gigabyte
    let mut b = Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(None)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("nexusctl/", env!("CARGO_PKG_VERSION")));
    if let Some(pem) = ca_pem {
        for c in reqwest::Certificate::from_pem_bundle(pem.as_bytes()).context("--ca: PEM certificates")? {
            b = b.add_root_certificate(c);
        }
    }
    let base = format!("{}/api/v1", url.trim_end_matches('/'));
    let s = sign_in(b.build()?, base, login)?;
    let res = (|| {
        let before = s.get("/updates")?["last_result"]["time"].as_i64();
        say(&format!("uploading {} ({size} bytes)", file.display()));
        let r = s
            .req(s.http.post(format!("{}/updates/bundle", s.base)))
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(reqwest::blocking::Body::sized(f, size))
            .send()?;
        check(r, "upload")?;
        say("uploaded; the appliance verifies the bundle");
        let end = Instant::now() + wait;
        loop {
            let v = s.get("/updates")?;
            let done = v["status"] != "checking" && v["last_result"]["time"].as_i64() > before;
            if done {
                return Ok(v);
            }
            if Instant::now() >= end {
                bail!("no result after {} s; see Settings -> Updates", wait.as_secs());
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    })();
    // best effort: the session ends at its idle timeout anyway
    let _ = s.post("/auth/logout", &json!({}));
    res
}
