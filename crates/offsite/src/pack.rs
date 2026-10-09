//! Pack files (plan §9.2): `NXP1 | sealed chunk blobs… | sealed index | u32 LE index_len | NXPI`.
//! Chunk blobs are byte-identical to the local chunk files. The index is sealed
//! with the tenant key (context `pack:<id>`), so a pack is self-describing.

use anyhow::{bail, ensure, Context, Result};
use chunkstore::crypto::hex;
use chunkstore::{ChunkId, Keyring};
use serde::{Deserialize, Serialize};

pub const TARGET_SIZE: usize = 32 << 20;
const MAGIC: &[u8; 4] = b"NXP1";
const TAIL: &[u8; 4] = b"NXPI";
pub const FOOTER: u64 = 8;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: ChunkId,
    pub offset: u64,
    pub len: u32,
}

pub fn remote_path(pack: &str) -> String {
    format!("packs/{}/{pack}.pack", &pack[..2])
}

pub struct Builder {
    pub id: String,
    buf: Vec<u8>,
    entries: Vec<Entry>,
}

impl Default for Builder {
    fn default() -> Self {
        let mut buf = Vec::with_capacity(TARGET_SIZE + (4 << 20));
        buf.extend_from_slice(MAGIC);
        Builder {
            id: hex(&rand::random::<[u8; 32]>())[..32].to_owned(),
            buf,
            entries: vec![],
        }
    }
}

impl Builder {
    pub fn add(&mut self, id: ChunkId, sealed: &[u8]) {
        self.entries.push(Entry {
            id,
            offset: self.buf.len() as u64,
            len: sealed.len() as u32,
        });
        self.buf.extend_from_slice(sealed);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns (pack bytes, sealed index, entries).
    pub fn finish(mut self, keys: &Keyring) -> (String, Vec<u8>, Vec<u8>, Vec<Entry>) {
        let idx = seal_index(keys, &self.id, &self.entries);
        self.buf.extend_from_slice(&idx);
        self.buf.extend_from_slice(&(idx.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(TAIL);
        (self.id, self.buf, idx, self.entries)
    }
}

pub fn seal_index(keys: &Keyring, pack: &str, entries: &[Entry]) -> Vec<u8> {
    keys.seal(
        format!("pack:{pack}").as_bytes(),
        &postcard::to_stdvec(entries).expect("serialize"),
    )
}

pub fn open_index(keys: &Keyring, pack: &str, sealed: &[u8]) -> Result<Vec<Entry>> {
    let (_, plain) = keys
        .open(format!("pack:{pack}").as_bytes(), sealed)
        .with_context(|| format!("pack {pack} index"))?;
    Ok(postcard::from_bytes(&plain)?)
}

/// Index length from the 8-byte footer.
pub fn footer_index_len(footer: &[u8]) -> Result<u64> {
    ensure!(
        footer.len() == FOOTER as usize && &footer[4..] == TAIL,
        "bad pack footer"
    );
    Ok(u32::from_le_bytes(footer[..4].try_into().unwrap()) as u64)
}

/// Parses a whole downloaded pack and checks that every entry lies inside it.
pub fn parse(keys: &Keyring, pack: &str, bytes: &[u8]) -> Result<Vec<Entry>> {
    if bytes.len() < 12 || &bytes[..4] != MAGIC {
        bail!("pack {pack}: bad header");
    }
    let n = bytes.len() as u64;
    let ilen = footer_index_len(&bytes[(n - FOOTER) as usize..])?;
    ensure!(ilen + FOOTER + 4 <= n, "pack {pack}: index length out of range");
    let istart = n - FOOTER - ilen;
    let entries = open_index(keys, pack, &bytes[istart as usize..(n - FOOTER) as usize])?;
    ensure!(
        entries
            .iter()
            .all(|e| e.offset >= 4 && e.offset + e.len as u64 <= istart),
        "pack {pack}: entry out of range"
    );
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse() {
        let k = Keyring::new("t", &[(1, [3; 32])]);
        let mut b = Builder::default();
        let chunks: Vec<(ChunkId, Vec<u8>)> = (0..5u8)
            .map(|i| {
                let data = vec![i; 1000 + i as usize];
                let id = k.chunk_id(&data);
                (id, k.seal_chunk(&id, &data))
            })
            .collect();
        chunks.iter().for_each(|(id, s)| b.add(*id, s));
        let (pid, bytes, _, entries) = b.finish(&k);
        assert_eq!(parse(&k, &pid, &bytes).unwrap(), entries);
        for (e, (id, sealed)) in entries.iter().zip(&chunks) {
            let raw = &bytes[e.offset as usize..e.offset as usize + e.len as usize];
            assert_eq!(raw, &sealed[..]);
            assert!(k.open_chunk(id, raw).is_ok());
        }
        assert!(parse(&k, "other", &bytes).is_err(), "index bound to pack id");
        assert!(parse(&Keyring::new("t2", &[(1, [3; 32])]), &pid, &bytes).is_err());
        assert!(remote_path(&pid).starts_with(&format!("packs/{}/", &pid[..2])));
    }
}
