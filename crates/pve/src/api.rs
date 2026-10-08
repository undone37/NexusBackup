//! PVE REST API client (port 8006), API-token auth, TLS verified against the
//! cluster CA (`/etc/pve/pve-root-ca.pem`) instead of public roots.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct ApiConfig {
    /// Host name or IP as present in the node certificate (e.g. `pve1.lab.local`).
    pub host: String,
    pub port: u16,
    /// Connect here instead of resolving `host` (NAT / lab port forwards).
    pub connect_addr: Option<SocketAddr>,
    pub ca_pem: Vec<u8>,
    /// `user@realm!tokenid`
    pub token_id: String,
    pub token_secret: String,
}

pub struct Api {
    http: reqwest::blocking::Client,
    base: String,
    auth: String,
}

impl Api {
    pub fn new(cfg: &ApiConfig) -> Result<Self> {
        let mut b = reqwest::blocking::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&cfg.ca_pem).context("cluster CA")?)
            .timeout(Duration::from_secs(60));
        if let Some(addr) = cfg.connect_addr {
            b = b.resolve(&cfg.host, addr);
        }
        Ok(Api {
            http: b.build()?,
            base: format!("https://{}:{}/api2/json", cfg.host, cfg.port),
            auth: format!("PVEAPIToken={}={}", cfg.token_id, cfg.token_secret),
        })
    }

    fn send(&self, req: reqwest::blocking::RequestBuilder) -> Result<Value> {
        let resp = req.header("Authorization", &self.auth).send()?;
        let status = resp.status();
        let body: Value = resp.json().unwrap_or(Value::Null);
        if !status.is_success() {
            bail!(
                "PVE API {status}: {}",
                body.get("errors").or(body.get("message")).unwrap_or(&body)
            );
        }
        Ok(body.get("data").cloned().unwrap_or(Value::Null))
    }

    pub fn get(&self, path: &str) -> Result<Value> {
        self.send(self.http.get(format!("{}{path}", self.base)))
    }

    pub fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<Value> {
        self.send(self.http.post(format!("{}{path}", self.base)).form(form))
    }

    pub fn version(&self) -> Result<String> {
        Ok(self.get("/version")?["version"].as_str().unwrap_or_default().to_owned())
    }

    /// Starts `vzdump` for one guest to the provider storage; returns the task UPID.
    pub fn start_backup(&self, node: &str, vmid: u32, storage: &str) -> Result<String> {
        let id = vmid.to_string();
        let upid = self.post(
            &format!("/nodes/{node}/vzdump"),
            &[("vmid", id.as_str()), ("storage", storage), ("mode", "snapshot")],
        )?;
        upid.as_str().map(str::to_owned).context("vzdump returned no UPID")
    }

    /// `None` while running, `Some(exitstatus)` when stopped ("OK" = success).
    pub fn task_status(&self, node: &str, upid: &str) -> Result<Option<String>> {
        let st = self.get(&format!("/nodes/{node}/tasks/{upid}/status"))?;
        Ok(match st["status"].as_str() {
            Some("stopped") => Some(st["exitstatus"].as_str().unwrap_or("unknown").to_owned()),
            _ => None,
        })
    }

    pub fn wait_task(&self, node: &str, upid: &str, timeout: Duration) -> Result<String> {
        let start = Instant::now();
        loop {
            if let Some(exit) = self.task_status(node, upid)? {
                return Ok(exit);
            }
            if start.elapsed() > timeout {
                bail!("task {upid} still running after {timeout:?}");
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    pub fn task_log(&self, node: &str, upid: &str) -> Result<Vec<String>> {
        let lines = self.get(&format!("/nodes/{node}/tasks/{upid}/log?limit=5000"))?;
        Ok(lines
            .as_array()
            .map(|a| a.iter().filter_map(|l| l["t"].as_str().map(str::to_owned)).collect())
            .unwrap_or_default())
    }
}
