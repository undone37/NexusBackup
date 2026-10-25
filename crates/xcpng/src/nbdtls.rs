//! NBD over TLS to xapi-nbd (TCP 10809): greeting, `NBD_OPT_STARTTLS`, TLS with the host's certificate from
//! `VDI.get_nbd_info` pinned, then the export by name (xapi-nbd has no `NBD_OPT_GO`; `nbd::Client::negotiate` falls
//! back to `NBD_OPT_EXPORT_NAME` without the `NBD_OPT_LIST` it denies).

use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

type Tls = Rc<RefCell<StreamOwned<ClientConnection, TcpStream>>>;

/// One TLS stream used as the client's reader and writer (one request at a time: no concurrent use).
pub struct Half(Tls);

impl Read for Half {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.borrow_mut().read(b)
    }
}

impl Write for Half {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

pub type Client = nbd::Client<Half, Half>;

/// What `VDI.get_nbd_info` answered for one host.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NbdInfo {
    pub address: String,
    /// a number over JSON-RPC, a string over XML-RPC
    pub port: serde_json::Value,
    pub exportname: String,
    pub cert: String,
    pub subject: String,
}

pub fn connect(info: &NbdInfo, timeout: Duration) -> Result<Client> {
    let port: u16 = match &info.port {
        serde_json::Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
    .context("NBD port")?;
    let addr = (info.address.as_str(), port)
        .to_socket_addrs()?
        .next()
        .context("NBD address")?;
    let mut tcp = TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("NBD connect {addr}"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    tcp.set_nodelay(true)?;
    let mut r = tcp.try_clone()?;
    let no_zeroes = nbd::greet(&mut r, &mut tcp).context("NBD greeting")?;
    nbd::starttls(&mut r, &mut tcp).context("NBD STARTTLS")?;
    let cfg = truenas::api::tls_config(info.cert.as_bytes()).context("the host's NBD certificate")?;
    let name = ServerName::try_from(info.subject.clone())
        .or_else(|_| ServerName::try_from(info.address.clone()))
        .context("NBD server name")?;
    let conn = ClientConnection::new(Arc::new(cfg), name)?;
    let tls: Tls = Rc::new(RefCell::new(StreamOwned::new(conn, tcp)));
    nbd::Client::negotiate(Half(tls.clone()), Half(tls), &info.exportname, &[], &[], no_zeroes).context("NBD export")
}
