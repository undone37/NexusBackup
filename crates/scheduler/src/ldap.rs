//! A minimal LDAP client for the tenant directory (#52): names for the Windows domain accounts that own files in VM
//! snapshots. LDAPS only (the certificate pinned like the forwarding sinks), simple bind, one paged subtree search for
//! users and groups with `objectSid` and `sAMAccountName`. Enough for Active Directory and Samba AD; no referrals.
//!
//! BER by hand: the few message types of RFC 4511 this needs. Every length is checked against what is left of the
//! message, and a message is at most 16 MiB.

use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const MAX_MESSAGE: usize = 16 << 20;
/// at most this many accounts from one directory
pub const MAX_ACCOUNTS: usize = 500_000;
const PAGE: i64 = 500;
const PAGED_OID: &[u8] = b"1.2.840.113556.1.4.319";

/// Where and how to read the directory (the tenant's `directory` setting, password unsealed).
pub struct Directory<'a> {
    pub host: &'a str,
    pub port: u16,
    pub ca_pem: &'a str,
    pub bind_dn: &'a str,
    pub password: &'a str,
    pub base_dn: &'a str,
}

/// SID (`S-1-5-21-…`) -> account name, for every user and group under the base DN.
pub fn accounts(d: &Directory, timeout: Duration) -> Result<BTreeMap<String, String>> {
    let addr = (d.host, d.port)
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("{}: no address", d.host))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("connect {addr}"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let tls = crate::forward::tls_config(Some(d.ca_pem), None).context("ca_pem")?;
    let name = ServerName::try_from(d.host.to_owned()).context("host")?;
    let mut s = StreamOwned::new(ClientConnection::new(Arc::new(tls), name)?, tcp);
    search(&mut s, d)
}

/// Bind, the paged search, unbind on an open stream.
fn search<S: Read + Write>(s: &mut S, d: &Directory) -> Result<BTreeMap<String, String>> {
    if d.password.is_empty() {
        bail!("password: an empty password would be an unauthenticated bind");
    }
    let bind = tlv(
        0x60,
        &[
            int(0x02, 3),
            octets(d.bind_dn.as_bytes()),
            tlv(0x80, d.password.as_bytes()),
        ]
        .concat(),
    );
    s.write_all(&message(1, &bind, None))?;
    let (op, body, _) = read_message(s, 1)?;
    if op != 0x61 {
        bail!("bind: unexpected answer (tag {op:#x})");
    }
    check_result(body, "bind")?;
    let mut out = BTreeMap::new();
    let mut cookie = Vec::new();
    let mut id = 2;
    loop {
        s.write_all(&message(id, &search_request(d.base_dn), Some(&paged(&cookie))))?;
        loop {
            let (op, body, controls) = read_message(s, id)?;
            match op {
                0x64 => {
                    if let Some((sid, name)) = entry(body)? {
                        out.insert(sid, name);
                        if out.len() > MAX_ACCOUNTS {
                            bail!("more than {MAX_ACCOUNTS} accounts under {}", d.base_dn);
                        }
                    }
                }
                0x73 => {} // a referral to another directory: not followed
                0x65 => {
                    check_result(body, "search")?;
                    cookie = controls.map(page_cookie).transpose()?.unwrap_or_default();
                    break;
                }
                _ => bail!("search: unexpected answer (tag {op:#x})"),
            }
        }
        if cookie.is_empty() {
            break;
        }
        id += 1;
    }
    let _ = s.write_all(&message(id + 1, &[0x42, 0x00], None)); // unbind
    Ok(out)
}

// ---------------------------------------------------------------- encoding

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let b = (n as u32).to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        v.push(0x80 | (4 - skip) as u8);
        v.extend_from_slice(&b[skip..]);
    }
    v.extend_from_slice(content);
    v
}

fn int(tag: u8, n: i64) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut i = 0;
    // minimal two's complement
    while i < 7 && ((b[i] == 0 && b[i + 1] & 0x80 == 0) || (b[i] == 0xff && b[i + 1] & 0x80 != 0)) {
        i += 1;
    }
    tlv(tag, &b[i..])
}

fn octets(b: &[u8]) -> Vec<u8> {
    tlv(0x04, b)
}

fn message(id: i64, op: &[u8], controls: Option<&[u8]>) -> Vec<u8> {
    let mut c = int(0x02, id);
    c.extend_from_slice(op);
    if let Some(ctl) = controls {
        c.extend(tlv(0xa0, ctl));
    }
    tlv(0x30, &c)
}

/// `(|(objectClass=user)(objectClass=group))`, subtree, the two attributes.
fn search_request(base: &str) -> Vec<u8> {
    let eq = |v: &[u8]| tlv(0xa3, &[octets(b"objectClass"), octets(v)].concat());
    let filter = tlv(0xa1, &[eq(b"user"), eq(b"group")].concat());
    let attrs = tlv(0x30, &[octets(b"objectSid"), octets(b"sAMAccountName")].concat());
    let body = [
        octets(base.as_bytes()),
        int(0x0a, 2), // wholeSubtree
        int(0x0a, 0), // neverDerefAliases
        int(0x02, 0), // no size limit (the server's own applies per page)
        int(0x02, 0),
        vec![0x01, 0x01, 0x00], // typesOnly FALSE
        filter,
        attrs,
    ]
    .concat();
    tlv(0x63, &body)
}

/// The paged results control (RFC 2696) with `cookie` (empty: the first page).
fn paged(cookie: &[u8]) -> Vec<u8> {
    let value = tlv(0x30, &[int(0x02, PAGE), octets(cookie)].concat());
    tlv(0x30, &[octets(PAGED_OID), octets(&value)].concat())
}

// ---------------------------------------------------------------- decoding

/// A cursor over BER elements.
struct Ber<'a>(&'a [u8]);

impl<'a> Ber<'a> {
    fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let b = self.0;
        if b.len() < 2 {
            bail!("BER: truncated");
        }
        let (n, hdr) = if b[1] < 0x80 {
            (b[1] as usize, 2)
        } else {
            let k = (b[1] & 0x7f) as usize;
            if k == 0 || k > 4 || b.len() < 2 + k {
                bail!("BER: bad length");
            }
            (b[2..2 + k].iter().fold(0usize, |a, x| a << 8 | *x as usize), 2 + k)
        };
        if b.len() - hdr < n {
            bail!("BER: element longer than its message");
        }
        self.0 = &b[hdr + n..];
        Ok((b[0], &b[hdr..hdr + n]))
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<&'a [u8]> {
        let (t, v) = self.next()?;
        if t != tag {
            bail!("{what}: tag {t:#x}, expected {tag:#x}");
        }
        Ok(v)
    }
}

fn uint(v: &[u8]) -> i64 {
    v.iter().fold(0i64, |a, x| a.wrapping_shl(8) | *x as i64)
}

/// One LDAPMessage from the stream: (operation tag, its content, the controls' content); the message id must be
/// `id`.
fn read_message<S: Read>(s: &mut S, id: i64) -> Result<(u8, Vec<u8>, Option<Vec<u8>>)> {
    let mut h = [0u8; 2];
    s.read_exact(&mut h).context("LDAP: connection closed")?;
    if h[0] != 0x30 {
        bail!("LDAP: not a message (tag {:#x})", h[0]);
    }
    let n = if h[1] < 0x80 {
        h[1] as usize
    } else {
        let k = (h[1] & 0x7f) as usize;
        if k == 0 || k > 4 {
            bail!("LDAP: bad message length");
        }
        let mut l = [0u8; 4];
        s.read_exact(&mut l[4 - k..])?;
        u32::from_be_bytes(l) as usize
    };
    if n > MAX_MESSAGE {
        bail!("LDAP: message of {n} bytes");
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    let mut m = Ber(&buf);
    let got = uint(m.expect(0x02, "messageID")?);
    if got != id {
        bail!("LDAP: answer to message {got}, expected {id}");
    }
    let (op, body) = m.next()?;
    let controls = match m.next() {
        Ok((0xa0, c)) => Some(c.to_vec()),
        _ => None,
    };
    Ok((op, body.to_vec(), controls))
}

/// An LDAPResult: success, or the server's code and message.
fn check_result(body: Vec<u8>, what: &str) -> Result<()> {
    let mut r = Ber(&body);
    let code = uint(r.expect(0x0a, "resultCode")?);
    let _dn = r.expect(0x04, "matchedDN")?;
    let msg = r.expect(0x04, "diagnosticMessage").unwrap_or_default();
    if code != 0 {
        bail!(
            "{what}: LDAP result {code}: {}",
            String::from_utf8_lossy(msg).trim_end_matches('\0')
        );
    }
    Ok(())
}

/// The cookie of the paged results control among a message's controls (empty: last page).
fn page_cookie(controls: Vec<u8>) -> Result<Vec<u8>> {
    let mut cs = Ber(&controls);
    while !cs.0.is_empty() {
        let mut c = Ber(cs.expect(0x30, "control")?);
        if c.expect(0x04, "controlType")? != PAGED_OID {
            continue;
        }
        let (mut t, mut v) = c.next()?;
        if t == 0x01 {
            (t, v) = c.next()?; // criticality
        }
        if t != 0x04 {
            bail!("paged results control without a value");
        }
        let mut val = Ber(v);
        let mut inner = Ber(val.expect(0x30, "paged value")?);
        inner.expect(0x02, "size")?;
        return Ok(inner.expect(0x04, "cookie")?.to_vec());
    }
    Ok(Vec::new())
}

/// (SID, name) of a SearchResultEntry with both attributes; `None` for entries without them.
fn entry(body: Vec<u8>) -> Result<Option<(String, String)>> {
    let mut e = Ber(&body);
    e.expect(0x04, "objectName")?;
    let mut attrs = Ber(e.expect(0x30, "attributes")?);
    let (mut sid, mut name) = (None, None);
    while !attrs.0.is_empty() {
        let mut a = Ber(attrs.expect(0x30, "attribute")?);
        let ty = a.expect(0x04, "type")?;
        let mut vals = Ber(a.expect(0x31, "vals")?);
        let Ok(v) = vals.expect(0x04, "value") else {
            continue;
        };
        if ty.eq_ignore_ascii_case(b"objectSid") {
            sid = sid_string(v);
        } else if ty.eq_ignore_ascii_case(b"sAMAccountName") {
            name = std::str::from_utf8(v)
                .ok()
                .filter(|n| !n.is_empty() && n.len() <= 256 && !n.chars().any(char::is_control))
                .map(str::to_owned);
        }
    }
    Ok(sid.zip(name))
}

/// The binary `objectSid` as `S-1-5-21-…`.
fn sid_string(b: &[u8]) -> Option<String> {
    let n = *b.get(1)? as usize;
    if b.len() != 8 + 4 * n || b[0] != 1 {
        return None;
    }
    let auth = b[2..8].iter().fold(0u64, |a, x| a << 8 | *x as u64);
    let mut s = format!("S-1-{auth}");
    for i in 0..n {
        let o = 8 + 4 * i;
        s.push_str(&format!("-{}", u32::from_le_bytes(b[o..o + 4].try_into().ok()?)));
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_bytes(subs: &[u32]) -> Vec<u8> {
        let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, 5];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn result(op: u8, code: i64) -> Vec<u8> {
        tlv(op, &[int(0x0a, code), octets(b""), octets(b"")].concat())
    }

    fn entry_msg(id: i64, sid: &[u32], name: &str) -> Vec<u8> {
        let attr = |t: &[u8], v: &[u8]| tlv(0x30, &[octets(t), tlv(0x31, &octets(v))].concat());
        let attrs = tlv(
            0x30,
            &[
                attr(b"objectSid", &sid_bytes(sid)),
                attr(b"sAMAccountName", name.as_bytes()),
            ]
            .concat(),
        );
        message(id, &tlv(0x64, &[octets(b"CN=x,DC=lab"), attrs].concat()), None)
    }

    /// A scripted server: what it answers, what the client wrote.
    struct Fake {
        input: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl Read for Fake {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Fake {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn dir() -> Directory<'static> {
        Directory {
            host: "dc.lab",
            port: 636,
            ca_pem: "",
            bind_dn: "nexus@lab.example",
            password: "pw",
            base_dn: "DC=lab,DC=example",
        }
    }

    #[test]
    fn encoding() {
        assert_eq!(int(0x02, 0), [2, 1, 0]);
        assert_eq!(int(0x02, 128), [2, 2, 0, 128]);
        assert_eq!(int(0x02, 500), [2, 2, 1, 0xf4]);
        assert_eq!(int(0x02, -1), [2, 1, 0xff]);
        let long = tlv(0x04, &[7; 300]);
        assert_eq!(&long[..4], [0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(Ber(&long).next().unwrap().1.len(), 300);
        assert_eq!(
            sid_string(&sid_bytes(&[21, 1, 2, 3, 1104])).as_deref(),
            Some("S-1-5-21-1-2-3-1104")
        );
        assert_eq!(sid_string(&[1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]), None, "short");
    }

    #[test]
    fn hostile_lengths_are_refused() {
        for bad in [
            &[0x04, 0x05, 1][..],
            &[0x04, 0x85, 1, 1, 1, 1, 1],
            &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert!(Ber(bad).next().is_err(), "{bad:?}");
        }
        // an entry whose attribute set claims more than the message holds
        let body = [octets(b"cn"), vec![0x30, 0x10, 0x30, 0x0e]].concat();
        assert!(entry(body).is_err());
        let mut f = Fake {
            input: std::io::Cursor::new(vec![0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            written: Vec::new(),
        };
        assert!(read_message(&mut f, 1).is_err(), "a 2 GiB message");
    }

    #[test]
    fn bind_and_two_pages() {
        let cookie = b"next";
        let ctl = |c: &[u8]| {
            let v = tlv(0x30, &[int(0x02, 0), octets(c)].concat());
            tlv(0x30, &[octets(PAGED_OID), octets(&v)].concat())
        };
        let done = |id: i64, c: &[u8]| message(id, &result(0x65, 0), Some(&ctl(c)));
        let input = [
            message(1, &result(0x61, 0), None),
            entry_msg(2, &[21, 7, 8, 9, 1104], "jdoe"),
            message(2, &tlv(0x73, &octets(b"ldap://other/")), None),
            done(2, cookie),
            entry_msg(3, &[21, 7, 8, 9, 513], "Domain Users"),
            message(3, &tlv(0x64, &[octets(b"CN=no sid"), tlv(0x30, &[])].concat()), None),
            done(3, b""),
        ]
        .concat();
        let mut f = Fake {
            input: std::io::Cursor::new(input),
            written: Vec::new(),
        };
        let got = search(&mut f, &dir()).unwrap();
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            [
                ("S-1-5-21-7-8-9-1104".to_owned(), "jdoe".to_owned()),
                ("S-1-5-21-7-8-9-513".to_owned(), "Domain Users".to_owned())
            ]
        );
        // the second search carries the server's cookie
        let w = f.written;
        assert!(w.windows(cookie.len()).any(|x| x == cookie));
        assert!(w.windows(b"nexus@lab.example".len()).any(|x| x == b"nexus@lab.example"));
    }

    #[test]
    fn errors() {
        let mut f = Fake {
            input: std::io::Cursor::new(message(1, &result(0x61, 49), None)),
            written: Vec::new(),
        };
        let e = search(&mut f, &dir()).unwrap_err();
        assert!(format!("{e:#}").contains("result 49"), "{e:#}");
        let mut d = dir();
        d.password = "";
        let mut f = Fake {
            input: std::io::Cursor::new(Vec::new()),
            written: Vec::new(),
        };
        assert!(search(&mut f, &d).is_err(), "no unauthenticated bind");
        assert!(f.written.is_empty());
    }
}
