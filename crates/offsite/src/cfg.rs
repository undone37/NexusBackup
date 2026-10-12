//! The target part of a nexus-offsite job config (`"remote": {"type": "local" | "sftp" | "s3", …}`),
//! shared by `nexus-offsite` and `nexus-setup restore-config`.

use crate::remote::{LocalDir, Remote};
use crate::s3::{S3Config, S3Remote};
use crate::sftp::{SftpConfig, SftpRemote};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RemoteCfg {
    Local {
        path: PathBuf,
    },
    Sftp {
        host: String,
        port: Option<u16>,
        user: String,
        key_file: PathBuf,
        host_key: String,
        base_dir: Option<String>,
    },
    /// S3 with optional Object Lock (docs/s3-offsite.md). The secret key and
    /// the trusted certificate(s) are files in the 0600 job dir.
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        access_key: String,
        secret_key_file: PathBuf,
        #[serde(default)]
        path_style: bool,
        ca_file: Option<PathBuf>,
        storage_class_packs: Option<String>,
        storage_class_meta: Option<String>,
        #[serde(default)]
        lock: bool,
        conditional_put: Option<bool>,
    },
}

pub fn remote(cfg: &RemoteCfg, connections: usize) -> Result<Box<dyn Remote>> {
    Ok(match cfg {
        RemoteCfg::Local { path } => Box::new(LocalDir(path.clone())),
        RemoteCfg::Sftp {
            host,
            port,
            user,
            key_file,
            host_key,
            base_dir,
        } => {
            let mut c = SftpConfig::new(host, user, key_file, host_key);
            c.port = port.unwrap_or(c.port);
            c.base_dir = base_dir.clone().unwrap_or_default();
            c.max_connections = connections;
            Box::new(SftpRemote::new(c)?)
        }
        RemoteCfg::S3 {
            endpoint,
            region,
            bucket,
            prefix,
            access_key,
            secret_key_file,
            path_style,
            ca_file,
            storage_class_packs,
            storage_class_meta,
            lock,
            conditional_put,
        } => {
            let secret = fs::read_to_string(secret_key_file).context("secret_key_file")?;
            let mut c = S3Config::new(
                endpoint,
                region,
                bucket,
                access_key,
                secret.trim_end_matches(['\r', '\n']),
            );
            c.prefix = prefix.clone();
            c.path_style = *path_style;
            c.ca_pem = ca_file.as_ref().map(fs::read).transpose().context("ca_file")?;
            c.storage_class_packs = storage_class_packs.clone();
            c.storage_class_meta = storage_class_meta.clone();
            c.lock = *lock;
            c.conditional_put = conditional_put.unwrap_or(true);
            Box::new(S3Remote::new(c)?)
        }
    })
}

impl RemoteCfg {
    /// `(host, port)` the target is reached at (outbound firewall), `None` for a local dir.
    pub fn endpoint(&self) -> Option<(String, u16)> {
        match self {
            RemoteCfg::Local { .. } => None,
            RemoteCfg::Sftp { host, port, .. } => Some((host.clone(), port.unwrap_or(crate::sftp::DEFAULT_PORT))),
            RemoteCfg::S3 { endpoint, .. } => {
                let rest = endpoint.split_once("://").map_or(endpoint.as_str(), |(_, r)| r);
                let hostport = rest.split('/').next().unwrap_or_default();
                let https = !endpoint.starts_with("http://");
                // [v6]:port, host:port, host
                let (host, port) = match hostport.rsplit_once(':') {
                    Some((h, p)) if !p.contains(']') && p.parse::<u16>().is_ok() => (h, p.parse().unwrap()),
                    _ => (hostport, if https { 443 } else { 80 }),
                };
                Some((host.trim_start_matches('[').trim_end_matches(']').to_owned(), port))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        let ep = |v: serde_json::Value| serde_json::from_value::<RemoteCfg>(v).unwrap().endpoint();
        assert_eq!(
            ep(serde_json::json!({"type": "s3", "endpoint": "https://minio.lan:9000", "region": "r", "bucket": "b",
                "access_key": "a", "secret_key_file": "/x"})),
            Some(("minio.lan".into(), 9000))
        );
        assert_eq!(
            ep(serde_json::json!({"type": "s3", "endpoint": "https://s3.example.com/", "region": "r", "bucket": "b",
                "access_key": "a", "secret_key_file": "/x"})),
            Some(("s3.example.com".into(), 443))
        );
        assert_eq!(
            ep(serde_json::json!({"type": "sftp", "host": "u1.your-storagebox.de", "user": "u1", "key_file": "/k",
                "host_key": "ssh-ed25519 AAAA"})),
            Some(("u1.your-storagebox.de".into(), 23))
        );
    }
}
