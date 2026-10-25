//! XAPI over HTTPS (JSON-RPC 2.0 at `/jsonrpc` of the pool master), the host's certificate pinned.
//! The session stays open for the whole job: the NBD export names carry its id (docs/xcpng-design.md "Lab results").

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

pub struct Xapi {
    http: reqwest::blocking::Client,
    url: String,
    session: String,
    id: std::cell::Cell<u64>,
    /// the pool master and its pinned TLS config, for the HTTP handlers next to the API (`import_raw_vdi`)
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) tls: std::sync::Arc<rustls::ClientConfig>,
}

impl Xapi {
    /// `login_with_password` as `user` on `host:port`; `ca_pem`: the host's certificate (or its CA), pinned.
    pub fn login(host: &str, port: u16, ca_pem: &[u8], user: &str, password: &str) -> Result<Xapi> {
        let tls = truenas::api::tls_config(ca_pem).context("the XCP-ng certificate (ca_pem)")?;
        let http = reqwest::blocking::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .timeout(Duration::from_secs(300))
            .build()?;
        let mut x = Xapi {
            http,
            url: format!("https://{host}:{port}/jsonrpc"),
            session: String::new(),
            id: std::cell::Cell::new(0),
            host: host.to_owned(),
            port,
            tls: std::sync::Arc::new(tls),
        };
        let s = x.raw(
            "session.login_with_password",
            json!([user, password, "1.0", "nexusbackup"]),
        )?;
        x.session = s.as_str().context("login: no session")?.to_owned();
        Ok(x)
    }

    fn raw(&self, method: &str, params: Value) -> Result<Value> {
        self.id.set(self.id.get() + 1);
        let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": self.id.get()});
        let r: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("XAPI {method}"))?
            .error_for_status()?
            .json()
            .with_context(|| format!("XAPI {method}: answer"))?;
        if let Some(e) = r.get("error") {
            // XAPI errors: {"code", "message", "data": [error name, args...]}
            bail!("XAPI {method}: {}", e.get("data").unwrap_or(e));
        }
        Ok(r.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `method(session, params...)`.
    pub fn call(&self, method: &str, params: &[Value]) -> Result<Value> {
        let mut p = vec![json!(self.session)];
        p.extend_from_slice(params);
        self.raw(method, Value::Array(p))
    }

    pub(crate) fn session(&self) -> &str {
        &self.session
    }

    pub fn logout(&self) {
        let _ = self.call("session.logout", &[]);
    }
}

impl Drop for Xapi {
    fn drop(&mut self) {
        if !self.session.is_empty() {
            self.logout();
        }
    }
}
