//! TrueNAS API client: JSON-RPC 2.0 over WebSocket (`wss://<host>/api/current`;
//! the REST API is deprecated since 25.04). TLS is verified against the
//! configured certificate(s) only (`ca_pem`): the exact TrueNAS certificate
//! (pinned, the usual self-signed `truenas_default`) or a CA that signed it
//! (then the host name must match). Auth: `auth.login_ex` with
//! `API_KEY_PLAIN` (key of a user whose privilege has only `SNAPSHOT_WRITE`,
//! `SNAPSHOT_DELETE` and `DATASET_READ`).

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error, RootCertStore, SignatureScheme, StreamOwned,
};
use serde_json::{json, Value};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

/// What the connector needs from TrueNAS (fake in tests).
pub trait Nas {
    /// `root` and (if `recursive`) every dataset below it.
    fn datasets(&mut self, root: &str, recursive: bool) -> Result<Vec<Dataset>>;
    /// Snapshot names (part after `@`) of one dataset.
    fn snapshots(&mut self, ds: &str) -> Result<Vec<String>>;
    fn create_snapshot(&mut self, ds: &str, name: &str, recursive: bool) -> Result<()>;
    fn delete_snapshot(&mut self, ds: &str, name: &str) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dataset {
    pub name: String,
    /// None: not mounted (or no file system)
    pub mountpoint: Option<String>,
    pub filesystem: bool,
}

pub struct ApiConfig {
    /// host name or address (SNI and, for CA-signed certificates, the name checked)
    pub host: String,
    pub port: u16,
    /// connect here instead of resolving `host`
    pub connect_addr: Option<SocketAddr>,
    /// PEM: the TrueNAS certificate itself (pin) and/or the CA that signed it
    pub ca_pem: Vec<u8>,
    pub user: String,
    pub api_key: String,
    pub timeout: Duration,
}

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

/// TLS client config trusting exactly the certificates in `ca_pem`.
pub fn tls_config(ca_pem: &[u8]) -> Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = pem::parse_many(ca_pem).context("ca_pem")?;
    let pins: Vec<Vec<u8>> = certs
        .iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| p.contents().to_vec())
        .collect();
    if pins.is_empty() {
        bail!("ca_pem: no certificate");
    }
    let mut roots = RootCertStore::empty();
    for p in &pins {
        let _ = roots.add(CertificateDer::from(p.clone())); // a leaf that is no valid anchor stays a pin
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

type Ws = WebSocket<StreamOwned<ClientConnection, TcpStream>>;

pub struct Api {
    ws: Ws,
    next_id: u64,
}

/// JSON-RPC answers larger than this are refused.
const MAX_MESSAGE: usize = 64 << 20;

impl Api {
    pub fn connect(cfg: &ApiConfig) -> Result<Api> {
        let addrs: Vec<SocketAddr> = match cfg.connect_addr {
            Some(a) => vec![a],
            None => (cfg.host.as_str(), cfg.port).to_socket_addrs()?.collect(),
        };
        let tcp = addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, cfg.timeout).ok())
            .with_context(|| format!("cannot connect to {}:{}", cfg.host, cfg.port))?;
        tcp.set_read_timeout(Some(cfg.timeout))?;
        tcp.set_write_timeout(Some(cfg.timeout))?;
        tcp.set_nodelay(true)?;
        let name = ServerName::try_from(cfg.host.clone()).context("host")?;
        let conn = ClientConnection::new(Arc::new(tls_config(&cfg.ca_pem)?), name)?;
        let tls = StreamOwned::new(conn, tcp);
        let url = format!("wss://{}:{}/api/current", cfg.host, cfg.port);
        let mut wcfg = WebSocketConfig::default();
        wcfg.max_message_size = Some(MAX_MESSAGE);
        wcfg.max_frame_size = Some(MAX_MESSAGE);
        let (ws, _) = tungstenite::client::client_with_config(url.as_str(), tls, Some(wcfg))
            .map_err(|e| anyhow::anyhow!("TrueNAS API handshake: {e}"))?;
        let mut api = Api { ws, next_id: 0 };
        let r = api.call(
            "auth.login_ex",
            json!([{"mechanism": "API_KEY_PLAIN", "username": cfg.user, "api_key": cfg.api_key,
                    "login_options": {"user_info": false}}]),
        )?;
        if r["response_type"] != "SUCCESS" {
            bail!(
                "TrueNAS API login as {:?} failed: {}",
                cfg.user,
                r["response_type"].as_str().unwrap_or("unexpected answer")
            );
        }
        Ok(api)
    }

    /// One call; notifications in between are skipped.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        self.next_id += 1;
        let id = self.next_id;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.ws
            .send(Message::text(req.to_string()))
            .with_context(|| format!("{method}: send"))?;
        loop {
            let m = self.ws.read().with_context(|| format!("{method}: receive"))?;
            let text = match m {
                Message::Text(t) => t,
                Message::Binary(b) => String::from_utf8(b.to_vec()).context("binary message")?.into(),
                Message::Close(_) => bail!("{method}: connection closed by TrueNAS"),
                _ => continue,
            };
            let v: Value = serde_json::from_str(text.as_str()).context("invalid JSON from TrueNAS")?;
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(e) = v.get("error") {
                let msg = e["data"]["reason"]
                    .as_str()
                    .or(e["message"].as_str())
                    .unwrap_or("unknown error");
                bail!(
                    "TrueNAS {method}: {}",
                    msg.chars().take(500).collect::<String>().escape_debug()
                );
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    pub fn close(mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}

fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k)
        .and_then(Value::as_str)
        .with_context(|| format!("TrueNAS answer without {k}"))
}

impl Nas for Api {
    fn datasets(&mut self, root: &str, recursive: bool) -> Result<Vec<Dataset>> {
        let filter = if recursive {
            json!([["OR", [["id", "=", root], ["id", "^", format!("{root}/")]]]])
        } else {
            json!([["id", "=", root]])
        };
        let r = self.call(
            "pool.dataset.query",
            json!([filter, {"extra": {"flat": true, "retrieve_children": false, "properties": ["mountpoint", "mounted"]}}]),
        )?;
        let mut out = Vec::new();
        for d in r.as_array().context("pool.dataset.query: expected an array")? {
            let name = str_field(d, "id")?.to_owned();
            if !crate::under(&name, root) {
                bail!("pool.dataset.query returned {name:?} outside {root:?}");
            }
            let filesystem = str_field(d, "type")? == "FILESYSTEM";
            let mounted = d["mounted"]["parsed"].as_bool().unwrap_or(false)
                || d["mounted"]["value"].as_str() == Some("yes")
                || d["mounted"].as_bool() == Some(true);
            let mp = d["mountpoint"]
                .as_str()
                .or(d["mountpoint"]["value"].as_str())
                .filter(|m| m.starts_with('/'));
            out.push(Dataset {
                name,
                mountpoint: if mounted && filesystem {
                    mp.map(str::to_owned)
                } else {
                    None
                },
                filesystem,
            });
        }
        Ok(out)
    }

    fn snapshots(&mut self, ds: &str) -> Result<Vec<String>> {
        let r = self.call(
            "pool.snapshot.query",
            json!([[["dataset", "=", ds]], {"select": ["id", "dataset", "snapshot_name"]}]),
        )?;
        let mut out = Vec::new();
        for s in r.as_array().context("pool.snapshot.query: expected an array")? {
            if str_field(s, "dataset")? != ds {
                bail!("pool.snapshot.query returned a snapshot of another dataset");
            }
            out.push(str_field(s, "snapshot_name")?.to_owned());
        }
        Ok(out)
    }

    fn create_snapshot(&mut self, ds: &str, name: &str, recursive: bool) -> Result<()> {
        self.call(
            "pool.snapshot.create",
            json!([{"dataset": ds, "name": name, "recursive": recursive}]),
        )?;
        Ok(())
    }

    fn delete_snapshot(&mut self, ds: &str, name: &str) -> Result<()> {
        self.call(
            "pool.snapshot.delete",
            json!([format!("{ds}@{name}"), {"defer": false, "recursive": false}]),
        )?;
        Ok(())
    }
}
