//! USN change journal: record parsing, journal continuity and the "unchanged" decision
//! (pure, tested on Linux with byte fixtures laid out per the documented structures).
//!
//! Per volume the committed metadata cache stores a [`JournalMark`] (journal id + the
//! USN the journal was at *before* that backup's snapshot). The next backup reads the
//! journal from that USN to its current end (a superset of everything that changed
//! between the two snapshots) and collects the changed file ids. A file is
//! `unchanged` only if its metadata matches the cache **and** its id is not in that
//! set. Journal recreated (id differs), wrapped (the mark is older than the first
//! retained USN) or unavailable → that volume is read in full (`Reset`).
//! Volumes without a journal (FAT/exFAT) fall back to the metadata comparison alone.

use agent_core::cache::JournalMark;
use std::collections::HashSet;

/// `USN_JOURNAL_DATA_V0/V1/V2` fields we use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalData {
    pub journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
}

impl JournalData {
    /// Parse the FSCTL_QUERY_USN_JOURNAL output (UsnJournalID u64, FirstUsn i64,
    /// NextUsn i64, LowestValidUsn i64, MaxUsn i64, ...).
    pub fn parse(b: &[u8]) -> Option<JournalData> {
        if b.len() < 40 {
            return None;
        }
        let q = |i: usize| i64::from_le_bytes(b[i..i + 8].try_into().expect("8"));
        Some(JournalData {
            journal_id: q(0) as u64,
            first_usn: q(8),
            next_usn: q(16),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub file_id: u128,
    pub parent_id: u128,
    pub usn: i64,
    pub reason: u32,
    pub attributes: u32,
    pub name: Vec<u16>,
}

/// Parse the output buffer of FSCTL_READ_USN_JOURNAL: the next USN to read (i64),
/// then USN_RECORD_V2 / V3 records (V4 range records and unknown versions are skipped
/// by their length). Malformed lengths end the parse with an error.
pub fn parse_records(buf: &[u8]) -> Result<(i64, Vec<Record>), String> {
    if buf.len() < 8 {
        return Err("USN buffer shorter than 8 bytes".into());
    }
    let next = i64::from_le_bytes(buf[..8].try_into().expect("8"));
    let mut out = vec![];
    let mut o = 8;
    while o + 8 <= buf.len() {
        let rec_len = u32::from_le_bytes(buf[o..o + 4].try_into().expect("4")) as usize;
        if rec_len == 0 {
            break;
        }
        if rec_len < 8 || o + rec_len > buf.len() {
            return Err(format!("USN record at {o}: length {rec_len} out of range"));
        }
        let r = &buf[o..o + rec_len];
        let major = u16::from_le_bytes([r[4], r[5]]);
        let u32_at = |i: usize| u32::from_le_bytes(r[i..i + 4].try_into().expect("4"));
        let u64_at = |i: usize| u64::from_le_bytes(r[i..i + 8].try_into().expect("8"));
        let u128_at = |i: usize| u128::from_le_bytes(r[i..i + 16].try_into().expect("16"));
        // (file id, parent id, offset of Usn)
        let fields = match major {
            2 if rec_len >= 60 => Some((u64_at(8) as u128, u64_at(16) as u128, 24)),
            3 if rec_len >= 76 => Some((u128_at(8), u128_at(24), 40)),
            2 | 3 => return Err(format!("USN record at {o}: too short for version {major}")),
            _ => None,
        };
        if let Some((file_id, parent_id, u)) = fields {
            // Usn, TimeStamp, Reason, SourceInfo, SecurityId, FileAttributes,
            // FileNameLength, FileNameOffset
            let usn = u64_at(u) as i64;
            let reason = u32_at(u + 16);
            let attributes = u32_at(u + 28);
            let name_len = u16::from_le_bytes([r[u + 32], r[u + 33]]) as usize;
            let name_off = u16::from_le_bytes([r[u + 34], r[u + 35]]) as usize;
            let name = r
                .get(name_off..name_off + name_len)
                .ok_or_else(|| format!("USN record at {o}: name out of range"))?
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            out.push(Record {
                file_id,
                parent_id,
                usn,
                reason,
                attributes,
                name,
            });
        }
        // records are 8-byte aligned
        o += (rec_len + 7) & !7;
    }
    Ok((next, out))
}

/// How a volume's previous journal position relates to the journal now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Continuity {
    /// read records from this USN on
    From(i64),
    /// no usable history: read the volume in full
    Reset(String),
}

pub fn continuity(stored: Option<&JournalMark>, now: &JournalData) -> Continuity {
    let Some(m) = stored else {
        return Continuity::Reset("no journal position from a previous backup".into());
    };
    if m.journal_id != now.journal_id {
        return Continuity::Reset("USN journal was recreated".into());
    }
    if m.next_usn < now.first_usn {
        return Continuity::Reset("USN journal wrapped (records since the last backup are gone)".into());
    }
    if m.next_usn > now.next_usn {
        return Continuity::Reset("stored USN is ahead of the journal".into());
    }
    Continuity::From(m.next_usn)
}

/// Per-volume change knowledge used while scanning.
#[derive(Clone, Debug)]
pub enum Changes {
    /// ids of every file with a journal record since the last backup
    Since(HashSet<u128>),
    /// journal unusable this time: nothing may be taken from the cache
    Reset(String),
    /// file system without a journal: metadata comparison only
    Unsupported,
}

impl Changes {
    pub fn from_records(records: impl IntoIterator<Item = Record>) -> Changes {
        Changes::Since(records.into_iter().map(|r| r.file_id).collect())
    }

    /// The cache decision: may a file whose metadata matches the cache (`cache_hit`)
    /// be reported `unchanged` without reading it?
    pub fn unchanged(&self, cache_hit: bool, file_id: u128) -> bool {
        cache_hit
            && match self {
                Changes::Since(set) => !set.contains(&file_id),
                Changes::Reset(_) => false,
                Changes::Unsupported => true,
            }
    }
}

#[cfg(test)]
pub mod fixtures {
    //! Records built byte by byte after the documented USN_RECORD_V2 / V3 layouts
    //! (winioctl.h); no Windows host was available to capture real buffers.

    pub fn v2(file: u64, parent: u64, usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = (60 + name.len() + 7) & !7;
        let mut r = Vec::with_capacity(len);
        r.extend((len as u32).to_le_bytes());
        r.extend(2u16.to_le_bytes());
        r.extend(0u16.to_le_bytes());
        r.extend(file.to_le_bytes());
        r.extend(parent.to_le_bytes());
        r.extend(usn.to_le_bytes());
        r.extend(132_539_328_000_000_000i64.to_le_bytes()); // TimeStamp
        r.extend(reason.to_le_bytes());
        r.extend(0u32.to_le_bytes()); // SourceInfo
        r.extend(0u32.to_le_bytes()); // SecurityId
        r.extend(0x20u32.to_le_bytes()); // FileAttributes
        r.extend((name.len() as u16).to_le_bytes());
        r.extend(60u16.to_le_bytes());
        r.extend(&name);
        r.resize(len, 0);
        r
    }

    pub fn v3(file: u128, parent: u128, usn: i64, reason: u32, name: &str) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let len = (76 + name.len() + 7) & !7;
        let mut r = Vec::with_capacity(len);
        r.extend((len as u32).to_le_bytes());
        r.extend(3u16.to_le_bytes());
        r.extend(0u16.to_le_bytes());
        r.extend(file.to_le_bytes());
        r.extend(parent.to_le_bytes());
        r.extend(usn.to_le_bytes());
        r.extend(0i64.to_le_bytes());
        r.extend(reason.to_le_bytes());
        r.extend(0u32.to_le_bytes());
        r.extend(0u32.to_le_bytes());
        r.extend(0x10u32.to_le_bytes());
        r.extend((name.len() as u16).to_le_bytes());
        r.extend(76u16.to_le_bytes());
        r.extend(&name);
        r.resize(len, 0);
        r
    }

    pub fn buffer(next: i64, records: &[Vec<u8>]) -> Vec<u8> {
        let mut b = next.to_le_bytes().to_vec();
        for r in records {
            b.extend(r);
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    const USN_REASON_DATA_EXTEND: u32 = 0x2;
    const USN_REASON_CLOSE: u32 = 0x8000_0000;

    #[test]
    fn parses_v2_v3_and_skips_unknown_versions() {
        // a V4 range-tracking record (skipped by length)
        let mut v4 = vec![0u8; 80];
        v4[0..4].copy_from_slice(&80u32.to_le_bytes());
        v4[4..6].copy_from_slice(&4u16.to_le_bytes());
        let buf = buffer(
            4096,
            &[
                v2(0x0001_0000_0000_0042, 5, 1000, USN_REASON_DATA_EXTEND, "report.docx"),
                v4,
                v3(0xAB_0000_0000_0000_0000_0007, 9, 1100, USN_REASON_CLOSE, "Grüße"),
            ],
        );
        let (next, recs) = parse_records(&buf).unwrap();
        assert_eq!(next, 4096);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].file_id, 0x0001_0000_0000_0042);
        assert_eq!(recs[0].parent_id, 5);
        assert_eq!(recs[0].usn, 1000);
        assert_eq!(recs[0].reason, USN_REASON_DATA_EXTEND);
        assert_eq!(recs[0].attributes, 0x20);
        assert_eq!(String::from_utf16(&recs[0].name).unwrap(), "report.docx");
        assert_eq!(recs[1].file_id, 0xAB_0000_0000_0000_0000_0007);
        assert_eq!(String::from_utf16(&recs[1].name).unwrap(), "Grüße");
        // empty read: only the next USN
        assert_eq!(parse_records(&4096i64.to_le_bytes()).unwrap(), (4096, vec![]));
    }

    #[test]
    fn rejects_malformed_buffers() {
        assert!(parse_records(&[0; 4]).is_err());
        let good = buffer(1, &[v2(1, 2, 3, 4, "x")]);
        let mut long = good.clone();
        long[8..12].copy_from_slice(&5000u32.to_le_bytes());
        assert!(parse_records(&long).is_err());
        let mut short = good.clone();
        short[8..12].copy_from_slice(&40u32.to_le_bytes());
        assert!(parse_records(&short).is_err(), "V2 shorter than its fixed part");
        let mut name = good.clone();
        name[8 + 56..8 + 58].copy_from_slice(&200u16.to_le_bytes());
        assert!(parse_records(&name).is_err(), "name outside the record");
    }

    #[test]
    fn journal_data_and_continuity() {
        let mut q = vec![];
        for v in [77i64, 1000, 5000, 1000, i64::MAX] {
            q.extend(v.to_le_bytes());
        }
        let now = JournalData::parse(&q).unwrap();
        assert_eq!(
            now,
            JournalData {
                journal_id: 77,
                first_usn: 1000,
                next_usn: 5000
            }
        );
        assert!(JournalData::parse(&q[..39]).is_none());
        let mark = |id, usn| JournalMark {
            volume: "v".into(),
            journal_id: id,
            next_usn: usn,
        };
        assert_eq!(continuity(Some(&mark(77, 2000)), &now), Continuity::From(2000));
        assert_eq!(continuity(Some(&mark(77, 1000)), &now), Continuity::From(1000));
        assert_eq!(continuity(Some(&mark(77, 5000)), &now), Continuity::From(5000));
        assert!(matches!(continuity(None, &now), Continuity::Reset(_)));
        assert!(matches!(continuity(Some(&mark(78, 2000)), &now), Continuity::Reset(r) if r.contains("recreated")));
        assert!(matches!(continuity(Some(&mark(77, 999)), &now), Continuity::Reset(r) if r.contains("wrapped")));
        assert!(matches!(continuity(Some(&mark(77, 5001)), &now), Continuity::Reset(_)));
    }

    #[test]
    fn unchanged_decision() {
        let (_, recs) = parse_records(&buffer(0, &[v2(42, 5, 1, 2, "a"), v3(1 << 70, 5, 2, 2, "b")])).unwrap();
        let c = Changes::from_records(recs);
        assert!(c.unchanged(true, 43), "metadata matches, no journal record");
        assert!(
            !c.unchanged(true, 42),
            "journal record = re-read even if metadata matches"
        );
        assert!(!c.unchanged(true, 1 << 70));
        assert!(!c.unchanged(false, 43), "metadata differs = re-read");
        let r = Changes::Reset("wrapped".into());
        assert!(!r.unchanged(true, 43), "journal reset = full read");
        assert!(Changes::Unsupported.unchanged(true, 43));
        assert!(!Changes::Unsupported.unchanged(false, 43));
    }
}
