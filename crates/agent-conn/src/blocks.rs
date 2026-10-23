//! Appliance side of the block reads (agent protocol v1.9, `CAP_BLOCK_READ`): one disk hot-added to a
//! proxy agent becomes a fixed index of [`BLOCK_SIZE`] chunks. The proxy hashes the changed blocks, only
//! blocks the store does not have cross the network, unchanged blocks come from the previous index.

use crate::map::MapDb;
use crate::tls::Session;
use crate::{hex, name};
use agent_proto::{Hash, Message, BLOCK_SIZE, CAP_BLOCK_READ, CAP_LZ4, MAX_BATCH};
use anyhow::{bail, Context, Result};
use chunkstore::{ChunkId, Index, Store};
use std::collections::{HashMap, HashSet};

/// What one disk read cost.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BlockReport {
    /// blocks the proxy read and hashed
    pub blocks: u64,
    /// bytes the proxy read
    pub bytes: u64,
    /// blocks fetched (not in the store)
    pub wanted: u64,
    /// bytes on the wire for them
    pub wire_bytes: u64,
}

/// `(first block, count)` ranges covering the byte extents `changed` (sorted, as CBT reports them) on a
/// disk of `size` bytes, plus every block beyond `prev_size` (a grown disk). At most [`MAX_BATCH`]
/// ranges: the nearest ranges are merged (a few unchanged blocks more are read) when there are more.
pub fn block_ranges(changed: &[(u64, u64)], size: u64, prev_size: u64) -> Vec<(u64, u64)> {
    let blocks = size.div_ceil(BLOCK_SIZE);
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut add = |a: u64, b: u64| {
        // blocks a..b
        let b = b.min(blocks);
        if a >= b {
            return;
        }
        match out.last_mut() {
            Some((f, n)) if *f + *n >= a => *n = (*n).max(b - *f),
            _ => out.push((a, b - a)),
        }
    };
    for &(off, len) in changed {
        if len > 0 {
            add(off / BLOCK_SIZE, (off + len).div_ceil(BLOCK_SIZE));
        }
    }
    // a grown disk: its new blocks, and the previous partial last block (its tail is new)
    if size > prev_size {
        add(prev_size / BLOCK_SIZE, blocks);
    }
    out.sort_unstable();
    let mut gap = 1;
    while out.len() > MAX_BATCH {
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(out.len());
        for (f, n) in out {
            match merged.last_mut() {
                Some((mf, mn)) if f - (*mf + *mn) <= gap => *mn = f + n - *mf,
                _ => merged.push((f, n)),
            }
        }
        out = merged;
        gap *= 2;
    }
    out
}

/// Reads the disk at SCSI target `0:target` of the proxy behind `s` into a fixed index: the blocks of
/// `ranges` (see [`block_ranges`]) from the proxy, every other block from `prev` (None: `ranges` must
/// cover the whole disk). `job` is a job id unique on that proxy; the job is released at the end.
#[allow(clippy::too_many_arguments)]
pub fn read_disk(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    job: u64,
    target: u32,
    size: u64,
    ranges: &[(u64, u64)],
    prev: Option<&Index>,
    log: &mut dyn FnMut(&str),
) -> Result<(Index, BlockReport)> {
    if !s.has_cap(CAP_BLOCK_READ) {
        bail!("the proxy does not offer block reads (proxy = on in its agent.conf, agent 1.9 or newer)");
    }
    let blocks = size.div_ceil(BLOCK_SIZE) as usize;
    let mut chunks: Vec<Option<ChunkId>> = vec![None; blocks];
    if let Some(p) = prev {
        let Index::Fixed {
            chunk_size,
            size: psize,
            chunks: pc,
        } = p
        else {
            bail!("the previous disk index is not a fixed index");
        };
        if u64::from(*chunk_size) != BLOCK_SIZE {
            bail!("the previous disk index has {chunk_size} byte chunks, not {BLOCK_SIZE}");
        }
        // a block of the same length in both sizes (a grown disk's old partial last block is not)
        for (n, id) in pc.iter().enumerate().take(blocks) {
            let end = (n as u64 + 1) * BLOCK_SIZE;
            if end.min(*psize) == end.min(size) {
                chunks[n] = Some(*id);
            }
        }
    }
    let len_of = |n: u64| (BLOCK_SIZE.min(size - n * BLOCK_SIZE)) as u32;
    s.send(&Message::BlockScan {
        job,
        target,
        size,
        ranges: ranges.to_vec(),
    })?;
    let r = scan_and_fetch(store, map, s, job, ranges, &mut chunks, &len_of, log);
    let released = s.send(&Message::Release {
        job,
        success: r.is_ok(),
    });
    let report = r?;
    released?;
    match s.recv()? {
        Message::Released { job: j, .. } if j == job => {}
        m => bail!("unexpected answer to Release: {}", name(&m)),
    }
    let missing = chunks.iter().filter(|c| c.is_none()).count();
    if missing > 0 {
        bail!("{missing} blocks neither read nor in the previous index");
    }
    Ok((
        Index::Fixed {
            chunk_size: BLOCK_SIZE as u32,
            size,
            chunks: chunks.into_iter().flatten().collect(),
        },
        report,
    ))
}

#[allow(clippy::too_many_arguments)]
fn scan_and_fetch(
    store: &Store,
    map: &mut MapDb,
    s: &mut Session,
    job: u64,
    ranges: &[(u64, u64)],
    chunks: &mut [Option<ChunkId>],
    len_of: &dyn Fn(u64) -> u32,
    log: &mut dyn FnMut(&str),
) -> Result<BlockReport> {
    let mut rep = BlockReport::default();
    let wanted_blocks: HashSet<u64> = ranges.iter().flat_map(|&(f, n)| f..f + n).collect();
    // plain hash of each read block
    let mut hashes: Vec<(u64, Hash)> = Vec::with_capacity(wanted_blocks.len());
    loop {
        match s.recv()? {
            Message::BlockHashes {
                job: j,
                first,
                hashes: h,
            } if j == job => {
                for (i, h) in h.into_iter().enumerate() {
                    let n = first + i as u64;
                    if !wanted_blocks.contains(&n) {
                        bail!("proxy sent a hash for block {n}, which was not asked for");
                    }
                    hashes.push((n, h));
                }
            }
            Message::BlockScanDone { job: j, blocks, bytes } if j == job => {
                rep.blocks = blocks;
                rep.bytes = bytes;
                break;
            }
            m => bail!("unexpected message during the block scan: {}", name(&m)),
        }
    }
    if hashes.len() != wanted_blocks.len() {
        bail!(
            "proxy hashed {} blocks, {} were asked for",
            hashes.len(),
            wanted_blocks.len()
        );
    }
    // known chunks (mapped and present, touched against GC), the rest is fetched once per distinct hash
    let mut keyed: HashMap<Hash, ChunkId> = HashMap::new();
    let mut want: Vec<(Hash, u32)> = Vec::new();
    let mut seen = HashSet::new();
    for &(n, h) in &hashes {
        if !seen.insert(h) {
            continue;
        }
        match map.get(&h)? {
            Some(id) if store.touch_chunk(&id)? => {
                keyed.insert(h, id);
            }
            _ => want.push((h, len_of(n))),
        }
    }
    log(&format!(
        "blocks: {} read, {} distinct, {} already in the store, {} to fetch",
        hashes.len(),
        seen.len(),
        keyed.len(),
        want.len()
    ));
    let lz4 = s.has_cap(CAP_LZ4);
    for batch in want.chunks(MAX_BATCH) {
        let lens: HashMap<Hash, u32> = batch.iter().copied().collect();
        let hs: Vec<Hash> = batch.iter().map(|(h, _)| *h).collect();
        s.send(&if lz4 {
            Message::WantLz4 { job, hashes: hs }
        } else {
            Message::Want { job, hashes: hs }
        })?;
        let mut pending: HashSet<Hash> = lens.keys().copied().collect();
        let mut got = Vec::with_capacity(batch.len());
        let ids = store.insert_chunks_parallel::<anyhow::Error>(|sink| loop {
            let (hash, data, wire) = match s.recv()? {
                Message::Chunk { hash, data } => {
                    let n = data.len();
                    (hash, data, n)
                }
                Message::ChunkLz4 { hash, raw_len, data } if lz4 => {
                    let raw = agent_proto::lz4_unpack(&data, raw_len)
                        .with_context(|| format!("block {}: bad LZ4 data", hex(&hash)))?;
                    (hash, raw, data.len())
                }
                Message::WantDone => return Ok(()),
                m => bail!("unexpected message during the block transfer: {}", name(&m)),
            };
            if !pending.remove(&hash) {
                bail!("proxy sent block {} that was not requested (or twice)", hex(&hash));
            }
            if data.len() != lens[&hash] as usize || blake3::hash(&data).as_bytes() != &hash {
                bail!(
                    "block {}: data does not match its length or BLAKE3 hash; rejected",
                    hex(&hash)
                );
            }
            rep.wanted += 1;
            rep.wire_bytes += wire as u64;
            got.push(hash);
            sink.push(data)?;
        })?;
        if !pending.is_empty() {
            bail!("proxy did not deliver {} of the requested blocks", pending.len());
        }
        let mut learned = Vec::with_capacity(got.len());
        for (h, (id, _)) in got.into_iter().zip(ids) {
            keyed.insert(h, id);
            learned.push((h, id, lens[&h]));
        }
        map.put_all(&learned).context("mapping index")?;
    }
    for (n, h) in hashes {
        chunks[n as usize] = Some(keyed[&h]);
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    const B: u64 = BLOCK_SIZE;

    #[test]
    fn ranges_from_changed_extents() {
        // two extents in block 0, one across blocks 2-3, a 10-block disk
        let r = block_ranges(&[(0, 10), (100, 5), (2 * B + 1, B)], 10 * B, 10 * B);
        assert_eq!(r, [(0, 1), (2, 2)]);
        // adjacent blocks merge; a grown disk adds its new blocks, the old partial last one included
        let r = block_ranges(&[(B, B), (2 * B, 1)], 10 * B, 5 * B + 7);
        assert_eq!(r, [(1, 2), (5, 5)]);
        // full read
        assert_eq!(block_ranges(&[], 3 * B + 1, 0), [(0, 4)]);
        // nothing changed
        assert!(block_ranges(&[], 3 * B, 3 * B).is_empty());
        assert!(block_ranges(&[], 3 * B + 7, 3 * B + 7).is_empty());
        // extents beyond the disk are cut
        assert_eq!(block_ranges(&[(9 * B, 5 * B)], 10 * B, 10 * B), [(9, 1)]);
    }

    #[test]
    fn too_many_ranges_are_merged() {
        // every other block changed: MAX_BATCH + 5 ranges
        let n = MAX_BATCH as u64 + 5;
        let changed: Vec<(u64, u64)> = (0..n).map(|i| (2 * i * B, 1)).collect();
        let r = block_ranges(&changed, 2 * n * B, 2 * n * B);
        assert!(r.len() <= MAX_BATCH, "{}", r.len());
        // still covers every changed block
        for i in 0..n {
            assert!(r.iter().any(|&(f, c)| f <= 2 * i && 2 * i < f + c), "block {}", 2 * i);
        }
    }
}
