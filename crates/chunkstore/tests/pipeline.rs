//! Parallel insert pipeline (pipeline.rs): same result for any worker count,
//! errors of the reader or a worker end it without hanging.

use chunkstore::{Index, Keyring, Options, Store};
use std::io;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const CS: usize = 64 << 10;

fn open(dir: &Path, workers: usize) -> Store {
    Store::open(
        dir,
        Keyring::new("tenant1", &[(1, [9; 32])]),
        Options {
            min_lock_secs: 0,
            chunk_workers: workers,
            ..Default::default()
        },
    )
    .unwrap()
}

fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Runs `f` on a thread; fails the test instead of hanging.
fn within<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    let t = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Disconnected) => std::panic::resume_unwind(t.join().unwrap_err()),
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("pipeline hung"),
    }
}

fn restore(s: &Store, idx: &Index) -> Vec<u8> {
    let mut out = vec![0; idx.size() as usize];
    s.image_reader(idx).unwrap().read_at(0, &mut out).unwrap();
    out
}

#[test]
fn same_index_for_one_and_many_workers() {
    // base image of 40 chunks + a ragged tail; the new image grows by 5 chunks,
    // has dirty extents inside, across and at the edges of chunks, and a zero run
    let size0 = 40 * CS as u64 + 1234;
    let size1 = 45 * CS as u64 + 77;
    let old = random(size0 as usize, 1);
    let mut new = random(size1 as usize, 2);
    new[..size0 as usize].copy_from_slice(&old);
    let dirty: Vec<(u64, u64)> = vec![
        (0, 100),
        (CS as u64 - 10, 20),
        (3 * CS as u64, CS as u64),
        (7 * CS as u64 + 500, 3 * CS as u64),
        (20 * CS as u64, 4 * CS as u64), // zeroed below: identical chunks
        (size0 - 50, 50),
    ];
    let fresh = random(size1 as usize, 3);
    for &(o, l) in &dirty {
        new[o as usize..(o + l) as usize].copy_from_slice(&fresh[o as usize..(o + l) as usize]);
    }
    new[20 * CS..24 * CS].fill(0);

    let mut results = vec![];
    for workers in [1, 2, 8] {
        let d = tempfile::tempdir().unwrap();
        let s = open(d.path(), workers);
        assert_eq!(s.chunk_workers(), workers);
        let base = s
            .store_image_extents(None, CS, size0, &[], |off, buf| {
                buf.copy_from_slice(&old[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
        assert_eq!(base, s.store_image(&old[..], CS).unwrap());
        let mut calls = vec![];
        let idx = s
            .store_image_extents(Some(&base), CS, size1, &dirty, |off, buf| {
                calls.push((off, buf.len()));
                buf.copy_from_slice(&new[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
        assert!(calls.windows(2).all(|w| w[0].0 < w[1].0), "reads stay in offset order");
        assert_eq!(restore(&s, &idx), new, "{workers} workers");
        let file = s.store_file_stats(&new[..]).unwrap();
        results.push((base, idx, calls, file.chunks, s.written()));
    }
    for r in &results[1..] {
        assert_eq!(r.0, results[0].0);
        assert_eq!(r.1, results[0].1);
        assert_eq!(r.2, results[0].2, "same read requests");
        assert_eq!(r.3, results[0].3);
        assert_eq!(r.4.chunks, results[0].4.chunks, "same new-chunk accounting");
        assert_eq!(r.4.plain, results[0].4.plain);
    }
}

#[test]
fn reader_error_midway_is_returned() {
    within(60, || {
        let d = tempfile::tempdir().unwrap();
        let s = open(d.path(), 4);
        let data = random(64 * CS, 5);
        let mut n = 0;
        let r = s.store_image_extents(None, CS, data.len() as u64, &[], |off, buf| {
            n += 1;
            if n == 30 {
                return Err(io::Error::other("nbd: connection reset"));
            }
            buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
            Ok(())
        });
        assert_eq!(r.unwrap_err().to_string(), "nbd: connection reset");
        assert_eq!(n, 30, "no read after the error");
        // the first read fails before any worker exists
        let r = s.store_image_extents(None, CS, data.len() as u64, &[], |_, _| Err(io::Error::other("first")));
        assert_eq!(r.unwrap_err().to_string(), "first");
        // a failing stream in store_file / store_image
        struct Failing(usize);
        impl io::Read for Failing {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::other("stream broke"));
                }
                let k = b.len().min(self.0).min(100_000);
                b[..k].fill(self.0 as u8);
                self.0 -= k;
                Ok(k)
            }
        }
        let e = s.store_file_stats(Failing(20 << 20)).unwrap_err();
        assert!(e.to_string().contains("stream broke"), "{e}");
        let e = s.store_image(Failing(20 << 20), CS).unwrap_err();
        assert_eq!(e.to_string(), "stream broke");
    });
}

#[test]
fn worker_error_stops_the_reader() {
    within(60, || {
        let d = tempfile::tempdir().unwrap();
        let s = open(d.path(), 4);
        let size = 64 * CS as u64;
        let data = random(size as usize, 6);
        let base = s.store_image(&data[..], CS).unwrap();
        let Index::Fixed { chunks, .. } = &base else { panic!() };
        // the base of chunk 10 vanished: merging it fails in a worker
        let h: String = chunks[10].iter().map(|b| format!("{b:02x}")).collect();
        std::fs::remove_file(d.path().join("chunks").join(&h[..4]).join(&h)).unwrap();
        let dirty: Vec<(u64, u64)> = (0..64).map(|n| (n * CS as u64, 100)).collect();
        let mut reads = 0;
        let r = s.store_image_extents(Some(&base), CS, size, &dirty, |off, buf| {
            reads += 1;
            std::thread::sleep(Duration::from_millis(5)); // workers outpace the reader
            buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
            Ok(())
        });
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert!(reads < 30, "reader stopped soon after the failure ({reads} reads)");
    });
}

#[test]
fn concurrent_identical_chunks() {
    within(120, || {
        let d = tempfile::tempdir().unwrap();
        let s = std::sync::Arc::new(open(d.path(), 8));
        // all chunks identical: the workers race on one chunk id
        let idx = s.store_image(&vec![0u8; 64 * CS][..], CS).unwrap();
        let Index::Fixed { chunks, .. } = &idx else { panic!() };
        assert!(chunks.iter().all(|c| *c == chunks[0]));
        assert_eq!(s.written().chunks, 1, "stored once");
        // direct concurrent inserts of the same few chunks
        let data: Vec<Vec<u8>> = (0..4).map(|i| random(CS, 1000 * (i + 1))).collect();
        let data = std::sync::Arc::new(data);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (s, data) = (s.clone(), data.clone());
                std::thread::spawn(move || {
                    for _ in 0..20 {
                        for c in data.iter() {
                            s.insert_chunk(c).unwrap();
                        }
                    }
                })
            })
            .collect();
        threads.into_iter().for_each(|t| t.join().unwrap());
        let w = s.written();
        assert_eq!(w.chunks, 5, "each distinct chunk counted once: {w:?}");
        assert_eq!(w.plain, CS as u64 * 5);
        for c in data.iter() {
            assert_eq!(&s.read_chunk(&s.keys().chunk_id(c)).unwrap(), c);
        }
        let leftovers = walk(&d.path().join("chunks"))
            .into_iter()
            .filter(|p| p.file_name().unwrap().to_string_lossy().contains(".tmp"))
            .count();
        assert_eq!(leftovers, 0, "no temp files left");
    });
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// `cargo test -p chunkstore --release --test pipeline -- --ignored --nocapture throughput`
/// (NEXUS_BENCH_MB sets the image size, default 512; TMPDIR the store's file system)
#[test]
#[ignore]
fn throughput() {
    let mb: usize = std::env::var("NEXUS_BENCH_MB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    let cs = chunkstore::store::IMAGE_CHUNK_SIZE;
    let size = mb << 20;
    let incompressible = random(size, 9);
    // text-like: compresses ~3-4x with zstd -3, every chunk distinct
    let mut compressible = Vec::with_capacity(size);
    let words = ["backup ", "chunk ", "store ", "NexusBackup ", "dedup ", "seal ", "\n"];
    let mut x = 7u64;
    while compressible.len() < size {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        compressible.extend_from_slice(words[(x % 7) as usize].as_bytes());
        compressible.extend_from_slice(format!("{} ", x % 100_000).as_bytes());
    }
    compressible.truncate(size);
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    for (name, data) in [("incompressible", &incompressible), ("compressible", &compressible)] {
        let mut base = 0.0;
        for workers in [1, 2, 4, 8, cpus.min(16)] {
            let d = tempfile::tempdir().unwrap();
            let s = open(d.path(), workers);
            let t = Instant::now();
            s.store_image_extents(None, cs, size as u64, &[], |off, buf| {
                buf.copy_from_slice(&data[off as usize..off as usize + buf.len()]);
                Ok(())
            })
            .unwrap();
            let rate = size as f64 / t.elapsed().as_secs_f64() / 1e6;
            if workers == 1 {
                base = rate;
            }
            println!("{name:>15}: {workers:>2} workers {rate:7.0} MB/s ({:.1}x)", rate / base);
        }
    }
}
