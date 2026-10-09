//! Shared helpers for the offsite fuzz targets: an in-memory "Storage Box"
//! whose whole content comes from the fuzz input.
//!
//! Input format: repeated `[u8 path len][path][u8 flags][u16 LE data len][data]`;
//! flag bit 0 = report a wrong (doubled + 1) size in listings.

use chunkstore::Keyring;
use offsite::remote::Remote;
use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

pub fn keys() -> Keyring {
    Keyring::new("tenant1", &[(1, [5; 32])])
}

#[derive(Default)]
pub struct MemBox {
    /// path -> (data, lie about the size)
    pub files: Mutex<BTreeMap<String, (Vec<u8>, bool)>>,
}

impl MemBox {
    pub fn decode(mut d: &[u8]) -> MemBox {
        let b = MemBox::default();
        let mut f = b.files.lock().unwrap();
        while let Some((&pl, rest)) = d.split_first() {
            let Some(path) = rest.get(..pl as usize) else { break };
            let rest = &rest[pl as usize..];
            let Some(&[flags, l0, l1]) = rest.get(..3).map(|s| <&[u8; 3]>::try_from(s).unwrap()) else {
                break;
            };
            let dl = u16::from_le_bytes([l0, l1]) as usize;
            let data = rest.get(3..3 + dl).unwrap_or(&rest[3..]);
            f.insert(
                String::from_utf8_lossy(path).into_owned(),
                (data.to_vec(), flags & 1 != 0),
            );
            d = &rest[(3 + dl).min(rest.len())..];
        }
        drop(f);
        b
    }

    pub fn encode(files: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (p, data) in files {
            out.push(p.len() as u8);
            out.extend_from_slice(p.as_bytes());
            out.push(0);
            out.extend_from_slice(&(data.len() as u16).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }
}

/// Same path rule as the real backends (`remote::check`): relative, no empty, `.` or `..` components.
fn check(path: &str) -> io::Result<()> {
    let ok = !path.starts_with('/') && path.split('/').all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidInput.into())
    }
}

impl Remote for MemBox {
    fn put(&self, path: &str, data: &[u8]) -> io::Result<()> {
        check(path)?;
        let mut f = self.files.lock().unwrap();
        if f.contains_key(path) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        f.insert(path.to_owned(), (data.to_vec(), false));
        Ok(())
    }

    fn get(&self, path: &str, offset: u64, len: Option<u64>) -> io::Result<Vec<u8>> {
        check(path)?;
        let f = self.files.lock().unwrap();
        let (d, _) = f.get(path).ok_or(io::ErrorKind::NotFound)?;
        let start = usize::try_from(offset)
            .ok()
            .filter(|o| *o <= d.len())
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        let end = match len {
            Some(n) => start
                .checked_add(n as usize)
                .filter(|e| *e <= d.len())
                .ok_or(io::ErrorKind::UnexpectedEof)?,
            None => d.len(),
        };
        Ok(d[start..end].to_vec())
    }

    fn list(&self, dir: &str) -> io::Result<Vec<(String, u64, bool)>> {
        let f = self.files.lock().unwrap();
        if !dir.is_empty() {
            check(dir)?;
        }
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut out: BTreeMap<String, (u64, bool)> = BTreeMap::new();
        for (p, (d, lie)) in f.iter() {
            let Some(rest) = p.strip_prefix(&prefix) else { continue };
            match rest.split_once('/') {
                Some((sub, _)) => {
                    out.insert(sub.to_owned(), (0, true));
                }
                None => {
                    let size = if *lie { d.len() as u64 * 2 + 1 } else { d.len() as u64 };
                    out.insert(rest.to_owned(), (size, false));
                }
            }
        }
        Ok(out.into_iter().map(|(n, (s, d))| (n, s, d)).collect())
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        check(path)?;
        self.files
            .lock()
            .unwrap()
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}
