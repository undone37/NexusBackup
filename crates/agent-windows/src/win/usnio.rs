//! USN journal I/O (FSCTL_QUERY / CREATE / READ_USN_JOURNAL); parsing and the
//! decisions are in `crate::usn`.

use super::sys::{self, Handle};
use crate::usn::{parse_records, Changes, JournalData};
use std::collections::HashSet;
use std::io;
use std::path::Path;

/// Distinct changed files kept in memory per volume; beyond that the volume is read in
/// full (bounded memory, ~50 bytes per id).
const MAX_CHANGED: usize = 4_000_000;

/// Volume handle for journal control codes: `\\?\Volume{...}` without the trailing `\`.
pub fn open_volume(volume_guid_path: &str) -> io::Result<Handle> {
    let p = volume_guid_path.trim_end_matches('\\');
    sys::open(
        Path::new(p),
        sys::GENERIC_READ | sys::GENERIC_WRITE,
        sys::SHARE_ALL,
        sys::OPEN_EXISTING,
        0,
    )
}

/// Current journal state; `Ok(None)` if the file system has no journal support.
/// An NTFS/ReFS volume without an active journal gets one (256 MiB, 32 MiB delta).
pub fn query(volume_guid_path: &str, create: bool) -> io::Result<Option<(JournalData, bool)>> {
    let h = open_volume(volume_guid_path)?;
    match sys::ioctl(&h, sys::FSCTL_QUERY_USN_JOURNAL, &[], 80) {
        Ok(b) => Ok(JournalData::parse(&b).map(|d| (d, false))),
        Err(e) if e.raw_os_error() == Some(sys::ERROR_INVALID_FUNCTION) => Ok(None),
        Err(e) if create && e.raw_os_error() == Some(sys::ERROR_JOURNAL_NOT_ACTIVE) => {
            let mut c = Vec::with_capacity(16);
            c.extend((256u64 << 20).to_le_bytes()); // MaximumSize
            c.extend((32u64 << 20).to_le_bytes()); // AllocationDelta
            sys::ioctl(&h, sys::FSCTL_CREATE_USN_JOURNAL, &c, 0)?;
            let b = sys::ioctl(&h, sys::FSCTL_QUERY_USN_JOURNAL, &[], 80)?;
            Ok(JournalData::parse(&b).map(|d| (d, true)))
        }
        Err(e) => Err(e),
    }
}

/// All file ids with a record from `start` to the current end of the journal.
pub fn changes_since(volume_guid_path: &str, journal_id: u64, start: i64) -> io::Result<Changes> {
    let h = open_volume(volume_guid_path)?;
    let mut ids = HashSet::new();
    let mut usn = start;
    loop {
        // READ_USN_JOURNAL_DATA_V1
        let mut q = Vec::with_capacity(48);
        q.extend(usn.to_le_bytes()); // StartUsn
        q.extend(u32::MAX.to_le_bytes()); // ReasonMask: everything
        q.extend(0u32.to_le_bytes()); // ReturnOnlyOnClose
        q.extend(0u64.to_le_bytes()); // Timeout
        q.extend(0u64.to_le_bytes()); // BytesToWaitFor
        q.extend(journal_id.to_le_bytes()); // UsnJournalID
        q.extend(2u16.to_le_bytes()); // MinMajorVersion
        q.extend(3u16.to_le_bytes()); // MaxMajorVersion
        q.resize(48, 0);
        let buf = match sys::ioctl(&h, sys::FSCTL_READ_USN_JOURNAL, &q, 1 << 20) {
            Ok(b) => b,
            Err(e) if e.raw_os_error() == Some(sys::ERROR_JOURNAL_ENTRY_DELETED) => {
                return Ok(Changes::Reset("USN journal records were deleted while reading".into()))
            }
            Err(e) => return Err(e),
        };
        let (next, recs) = parse_records(&buf).map_err(io::Error::other)?;
        if recs.is_empty() || next <= usn {
            break;
        }
        ids.extend(recs.into_iter().map(|r| r.file_id));
        if ids.len() > MAX_CHANGED {
            return Ok(Changes::Reset(format!("more than {MAX_CHANGED} changed files")));
        }
        usn = next;
    }
    Ok(Changes::Since(ids))
}
