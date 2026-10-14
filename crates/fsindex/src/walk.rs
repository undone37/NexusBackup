//! Finds the volumes of a snapshot's disks and walks them.

use crate::disk::{Io, Segment, Vol};
use crate::part::{PType, Table};
use crate::probe::Kind;
use crate::{disk_name, dm_name, lvm, Limits, Volume};
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

/// Where the entries of a walk go (the helper sends them to the parent).
pub trait Driver {
    /// A volume starts. `false`: do not parse it (the parent reuses the
    /// listing of the previous snapshot, or a parser crashed on it before).
    fn begin(&mut self, v: &Volume) -> io::Result<bool>;
    fn entry(&mut self, path: &str, size: u64, mtime: i64, kind: u8) -> io::Result<()>;
    /// The volume is done (`state` set); also called for volumes that are
    /// not parsed (unsupported, skipped, reused).
    fn end(&mut self, v: &Volume) -> io::Result<()>;
    /// Estimated entries of the volume being walked (live progress only; may be off).
    fn expect(&mut self, _entries: u64) -> io::Result<()> {
        Ok(())
    }
}

/// Limits and bookkeeping of one walk, handed to the file system walkers.
pub struct Out<'a> {
    driver: &'a mut dyn Driver,
    total: u64,
    limits: Limits,
    deadline: Instant,
    /// why the walk stopped early (entry limit, time budget)
    pub stopped: Option<String>,
    fatal: Option<io::Error>,
    notes: u64,
    first_note: Option<String>,
}

impl Out<'_> {
    /// Emits one entry. `Ok(false)`: a limit was hit, stop walking.
    pub fn emit(&mut self, info: &mut Volume, path: &str, size: u64, mtime: i64, kind: u8) -> Result<bool, String> {
        if self.total >= self.limits.max_entries {
            self.stopped = Some(format!("entry limit ({}) reached", self.limits.max_entries));
            return Ok(false);
        }
        if Instant::now() > self.deadline {
            self.stopped = Some(format!("time budget ({} s) spent", self.limits.budget_secs));
            return Ok(false);
        }
        if let Err(e) = self.driver.entry(path, size, mtime, kind) {
            self.fatal = Some(e);
            return Err("output closed".into());
        }
        self.total += 1;
        info.entries += 1;
        Ok(true)
    }

    /// The walker's estimate of the volume's entries (live progress only).
    pub fn expect(&mut self, entries: u64) {
        if let Err(e) = self.driver.expect(entries) {
            self.fatal = Some(e);
        }
    }

    /// A directory that could not be read (the volume becomes `partial`).
    pub fn note(&mut self, _info: &mut Volume, msg: String) {
        self.notes += 1;
        self.first_note.get_or_insert(msg);
    }
}

type Walker = fn(&Vol, &mut Out, &mut Volume) -> Result<(), String>;

struct Cand {
    vol: Vol,
    info: Volume,
    ptype: PType,
}

/// Lists every volume of the disks. `names`: the snapshot's disk index names
/// (`drive-scsi0`, …) in the order the micro-VM attaches them.
pub fn run(io: Io, names: &[String], limits: Limits, driver: &mut dyn Driver) -> io::Result<()> {
    let mut out = Out {
        driver,
        total: 0,
        limits,
        deadline: Instant::now() + Duration::from_secs(limits.budget_secs),
        stopped: None,
        fatal: None,
        notes: 0,
        first_note: None,
    };
    let disks = io.borrow().disks().min(names.len());
    let mut cands = Vec::new();
    let mut texts = Vec::new();
    let mut pvs = lvm::PvMap::new();
    let mut reports = Vec::new();
    for (i, name) in names.iter().enumerate().take(disks) {
        let size = io.borrow().disk_size(i);
        let whole = Vol::region(io.clone(), i, 0, size);
        let base = Volume {
            browse: disk_name(i),
            device: name.clone(),
            size,
            key: format!("{name}@0+{size}"),
            ..Default::default()
        };
        match crate::part::parse(&whole)? {
            Table::None => cands.push(Cand {
                vol: whole,
                info: base,
                ptype: PType::Data,
            }),
            Table::Corrupt(why) => reports.push(Volume {
                state: "failed".into(),
                reason: Some(format!("corrupted partition table: {why}")),
                ..base
            }),
            Table::Mbr(parts) | Table::Gpt(parts) => {
                for p in parts {
                    cands.push(Cand {
                        vol: Vol::region(io.clone(), i, p.start, p.len),
                        info: Volume {
                            browse: format!("{}{}", disk_name(i), p.number),
                            device: name.clone(),
                            size: p.len,
                            key: format!("{name}@{}+{}", p.start, p.len),
                            partuuid: p.guid.clone(),
                            ..Default::default()
                        },
                        ptype: p.ptype,
                    });
                }
            }
        }
    }
    // classify; PVs feed the LVM pass
    let mut todo: Vec<(Vol, Volume, Walker)> = Vec::new();
    let classify = |vol: &Vol,
                    mut info: Volume,
                    ptype: &PType,
                    texts: &mut Vec<String>,
                    pvs: &mut lvm::PvMap,
                    todo: &mut Vec<(Vol, Volume, Walker)>,
                    reports: &mut Vec<Volume>,
                    at: Option<(usize, u64)>| {
        let unsupported = |mut info: Volume, fs: &str, why: &str| {
            info.fs = fs.into();
            info.state = "unsupported".into();
            info.reason = Some(why.into());
            info
        };
        match ptype {
            PType::Reserved => return,
            PType::Ldm => {
                return reports.push(unsupported(
                    info,
                    "ldm",
                    "Windows dynamic disk (LDM) is not indexed yet",
                ))
            }
            PType::StorageSpaces => {
                return reports.push(unsupported(info, "storage_spaces", "Storage Spaces are not indexed"))
            }
            PType::LinuxRaid => {
                return reports.push(unsupported(
                    info,
                    "linux_raid_member",
                    "Linux software RAID (md) is not indexed yet",
                ))
            }
            PType::Zfs => return reports.push(unsupported(info, "zfs_member", "ZFS inside the guest is not indexed")),
            _ => {}
        }
        let walker: Walker = match crate::probe::probe(vol) {
            Kind::Ext => {
                info.fs = "ext4".into();
                crate::fs_ext::walk
            }
            Kind::Ntfs => {
                info.fs = "ntfs".into();
                crate::fs_ntfs::walk
            }
            Kind::Fat => {
                info.fs = "vfat".into();
                crate::fat::walk
            }
            Kind::Exfat => {
                info.fs = "exfat".into();
                crate::exfat::walk
            }
            Kind::LvmPv => {
                match (lvm::read_pv(vol), at) {
                    (Ok(pv), Some(at)) => {
                        texts.extend(pv.text);
                        pvs.insert(pv.uuid, at);
                    }
                    (Ok(_), None) => reports.push(unsupported(
                        info,
                        "LVM2_member",
                        "LVM physical volume inside a logical volume",
                    )),
                    (Err(e), _) => {
                        info.fs = "LVM2_member".into();
                        info.state = "failed".into();
                        info.reason = Some(format!("LVM physical volume: {e}"));
                        reports.push(info);
                    }
                }
                return;
            }
            Kind::Swap => {
                info.fs = "swap".into();
                info.state = "skipped".into();
                info.reason = Some("swap space".into());
                return reports.push(info);
            }
            Kind::Unsupported(fs, why) => return reports.push(unsupported(info, fs, why)),
            Kind::Unknown => {
                info.state = "skipped".into();
                info.reason = Some("no known file system".into());
                return reports.push(info);
            }
        };
        todo.push((vol.clone(), info, walker));
    };
    for c in cands {
        let at = c.vol_disk_offset();
        classify(
            &c.vol,
            c.info,
            &c.ptype,
            &mut texts,
            &mut pvs,
            &mut todo,
            &mut reports,
            Some(at),
        );
    }
    for lv in lvm::volumes(&texts, &pvs) {
        let info = Volume {
            browse: format!("lvm/{}", dm_name(&lv.vg, &lv.name)),
            device: format!("{}/{}", lv.vg, lv.name),
            ..Default::default()
        };
        match lv.map {
            Err(why) => reports.push(Volume {
                key: format!("lvm:{}", lv.id),
                state: "unsupported".into(),
                reason: Some(why),
                ..info
            }),
            Ok(segs) => {
                let vol = Vol::new(io.clone(), segs.clone());
                let info = Volume {
                    key: format!("lvm:{}:{}", lv.id, seg_key(&segs)),
                    size: vol.size(),
                    ..info
                };
                classify(
                    &vol,
                    info,
                    &PType::Data,
                    &mut texts,
                    &mut pvs,
                    &mut todo,
                    &mut reports,
                    None,
                );
            }
        }
    }
    for r in reports {
        out.driver.begin(&r)?;
        out.driver.end(&r)?;
    }
    for (vol, mut info, walker) in todo {
        if let Some(why) = &out.stopped {
            info.state = "partial".into();
            info.reason = Some(format!("not listed: {why}"));
            out.driver.begin(&info)?;
            out.driver.end(&info)?;
            continue;
        }
        if !out.driver.begin(&info)? {
            continue;
        }
        io.borrow_mut().forget();
        out.notes = 0;
        out.first_note = None;
        let res = catch_unwind(AssertUnwindSafe(|| walker(&vol, &mut out, &mut info)));
        if let Some(e) = out.fatal.take() {
            return Err(e);
        }
        match res {
            Ok(Ok(())) => {
                if let Some(why) = &out.stopped {
                    info.state = "partial".into();
                    info.reason = Some(why.clone());
                } else if out.notes > 0 {
                    info.state = "partial".into();
                    info.reason = Some(format!(
                        "{} director{} not readable (first: {})",
                        out.notes,
                        if out.notes == 1 { "y" } else { "ies" },
                        out.first_note.take().unwrap_or_default()
                    ));
                } else {
                    info.state = "indexed".into();
                }
            }
            Ok(Err(e)) => {
                info.state = "failed".into();
                info.reason = Some(e);
            }
            Err(_) => {
                info.state = "failed".into();
                info.reason = Some(format!("{} parser failed on this volume", info.fs));
            }
        }
        if info.dirty && info.state == "indexed" && info.fs != "ext4" {
            // ext4-view applies the journal; NTFS $LogFile / FAT are not replayed
            info.reason = Some("crash-consistent snapshot: changes of the last seconds may be missing".into());
        }
        out.driver.end(&info)?;
    }
    Ok(())
}

impl Cand {
    /// (disk, offset) of a partition or whole disk (single linear segment).
    fn vol_disk_offset(&self) -> (usize, u64) {
        self.vol.first_leg()
    }
}

impl Vol {
    pub(crate) fn first_leg(&self) -> (usize, u64) {
        self.segments().first().map_or((0, 0), |s| s.legs[0])
    }
}

/// Short stable text of an LV mapping (part of the volume's cache key).
fn seg_key(segs: &[Segment]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for s in segs {
        for x in [s.start, s.len, s.stripe]
            .into_iter()
            .chain(s.legs.iter().flat_map(|(d, o)| [*d as u64, *o]))
        {
            for b in x.to_le_bytes() {
                h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
            }
        }
    }
    format!("{h:016x}")
}

/// Discards entries (fuzzing, [`walk_one`]).
struct Count(u64);

impl Driver for Count {
    fn begin(&mut self, _: &Volume) -> io::Result<bool> {
        Ok(true)
    }
    fn entry(&mut self, _: &str, _: u64, _: i64, _: u8) -> io::Result<()> {
        self.0 += 1;
        Ok(())
    }
    fn end(&mut self, _: &Volume) -> io::Result<()> {
        Ok(())
    }
}

/// Walks one volume with one parser (`ext4`, `ntfs`, `vfat`, `exfat`) and
/// returns the number of entries (fuzz targets). Panics propagate.
pub fn walk_one(vol: &Vol, fs: &str, limits: Limits) -> Result<u64, String> {
    let walker: Walker = match fs {
        "ext4" => crate::fs_ext::walk,
        "ntfs" => crate::fs_ntfs::walk,
        "vfat" => crate::fat::walk,
        "exfat" => crate::exfat::walk,
        _ => return Err(format!("unknown parser {fs}")),
    };
    let mut c = Count(0);
    let mut out = Out {
        driver: &mut c,
        total: 0,
        limits,
        deadline: Instant::now() + Duration::from_secs(limits.budget_secs),
        stopped: None,
        fatal: None,
        notes: 0,
        first_note: None,
    };
    let mut info = Volume::default();
    walker(vol, &mut out, &mut info)?;
    Ok(c.0)
}
