//! Everything a hostile primary sends to a secondary (docs/replication.md):
//! HTTP/1.1 response heads, Content-Length and chunked bodies on one keep-alive
//! connection, the JSON answers (snapshot listing, key export, enrollment), and
//! the chunk frames of `POST …/chunks`. Invariants: no panic, bodies and frames
//! stay within the client's limits, frames only return the requested chunk id.
#![no_main]

use libfuzzer_sys::fuzz_target;
use replication::client::read_chunk_frame;
use replication::http::Conn;
use replication::{EnrollResponse, KeyExport, SnapshotInfo, MAX_CHUNK};
use std::io::{self, Read, Write};

/// The primary's side of the connection: the fuzz input; what we send is dropped.
struct Peer<'a>(&'a [u8]);

impl Read for Peer<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // small, uneven reads exercise the line/chunk boundaries
        let n = buf.len().min(self.0.len()).min(1 + self.0.first().copied().unwrap_or(0) as usize % 97);
        buf[..n].copy_from_slice(&self.0[..n]);
        self.0 = &self.0[n..];
        Ok(n)
    }
}

impl Write for Peer<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const LIMIT: u64 = 1 << 16;

fuzz_target!(|data: &[u8]| {
    let mut c = Conn::over(Peer(data));
    // 1: a JSON answer (listing / keys / enrollment)
    let Ok(r) = c.request("GET", "/replication/v1/tenants/acme/snapshots", None, b"") else {
        return;
    };
    assert!((100..600).contains(&r.status));
    let Ok(body) = r.bytes(LIMIT) else { return };
    assert!(body.len() as u64 <= LIMIT);
    let _ = serde_json::from_slice::<Vec<SnapshotInfo>>(&body);
    let _ = serde_json::from_slice::<KeyExport>(&body);
    let _ = serde_json::from_slice::<EnrollResponse>(&body);
    // 2: chunk frames on the same keep-alive connection
    let Ok(mut r) = c.request("POST", "/replication/v1/tenants/acme/chunks", Some("application/octet-stream"), &[7; 96])
    else {
        return;
    };
    for i in 0..3u8 {
        let want = [i; 32];
        match read_chunk_frame(&mut r, &want) {
            Ok(d) => assert!(d.len() as u64 <= MAX_CHUNK),
            Err(_) => return,
        }
    }
    let mut rest = Vec::new();
    let _ = (&mut r).take(LIMIT).read_to_end(&mut rest);
});
