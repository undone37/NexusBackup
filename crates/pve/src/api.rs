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
    /// Connect to this IP instead of resolving `host`. Only the IP is used: reqwest's
    /// `resolve()` ignores the port, so `port` must already be the reachable port.
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
    /// `fleecing` e.g. `enabled=1,storage=local-lvm` (mandatory for provider VM backups,
    /// `None` for containers, where vzdump has no fleecing).
    pub fn start_backup(&self, node: &str, vmid: u32, storage: &str, fleecing: Option<&str>) -> Result<String> {
        let id = vmid.to_string();
        let mut form = vec![("vmid", id.as_str()), ("storage", storage), ("mode", "snapshot")];
        if let Some(f) = fleecing {
            form.push(("fleecing", f));
        }
        let upid = self.post(&format!("/nodes/{node}/vzdump"), &form)?;
        upid.as_str().map(str::to_owned).context("vzdump returned no UPID")
    }

    /// Restores a provider archive (`<storeid>:backup/<name>`) as VM `vmid`; returns the UPID.
    pub fn start_restore(&self, node: &str, vmid: u32, archive: &str, storage: &str) -> Result<String> {
        let id = vmid.to_string();
        let upid = self.post(
            &format!("/nodes/{node}/qemu"),
            &[
                ("vmid", id.as_str()),
                ("archive", archive),
                ("storage", storage),
                ("unique", "1"),
            ],
        )?;
        upid.as_str().map(str::to_owned).context("restore returned no UPID")
    }

    /// Restores a provider container archive as CT `vmid` (unprivileged; PVE refuses
    /// privileged restores from providers); returns the UPID.
    pub fn start_ct_restore(&self, node: &str, vmid: u32, archive: &str, storage: &str) -> Result<String> {
        let id = vmid.to_string();
        let upid = self.post(
            &format!("/nodes/{node}/lxc"),
            &[
                ("vmid", id.as_str()),
                ("ostemplate", archive),
                ("restore", "1"),
                ("unprivileged", "1"),
                ("storage", storage),
                ("unique", "1"),
            ],
        )?;
        upid.as_str().map(str::to_owned).context("restore returned no UPID")
    }

    /// POST returning a task UPID.
    pub fn post_task(&self, path: &str, form: &[(&str, &str)]) -> Result<String> {
        let upid = self.post(path, form)?;
        upid.as_str()
            .map(str::to_owned)
            .with_context(|| format!("POST {path} returned no UPID"))
    }

    /// Runs a task to completion; fails with the task log unless it ended "OK".
    pub fn run_task(&self, node: &str, upid: &str, timeout: Duration) -> Result<()> {
        let exit = self.wait_task(node, upid, timeout)?;
        if exit != "OK" {
            let log = self.task_log(node, upid).unwrap_or_default();
            bail!("task ended with {exit}: {}", log.join("\n"));
        }
        Ok(())
    }

    /// Current (non-pending) VM configuration.
    pub fn vm_config(&self, node: &str, vmid: u32) -> Result<serde_json::Map<String, Value>> {
        match self.get(&format!("/nodes/{node}/qemu/{vmid}/config"))? {
            Value::Object(m) => Ok(m),
            v => bail!("unexpected VM config: {v}"),
        }
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
