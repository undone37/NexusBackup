//! LVM2 (read-only): PV label and metadata area, the text metadata of the
//! volume group, and the mapping of logical volumes to disk bytes. Linear,
//! striped, mirror and raid1 (first leg) LVs; thin, cache, VDO, raid4/5/6/10
//! and snapshots are reported, not mapped. A volume group with a missing PV is
//! skipped as a whole (Cohesity does the same).

use crate::disk::{le32, le64, Segment, Vol};
use std::collections::BTreeMap;

const MDA_MAGIC: &[u8] = b" LVM2 x[5A%r0N*>";
const MAX_TEXT: u64 = 4 << 20;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 200_000;

/// A physical volume found on a disk or partition.
#[derive(Clone, Debug, PartialEq)]
pub struct Pv {
    /// 32 characters, without dashes
    pub uuid: String,
    /// newest metadata text of the metadata areas (`None`: no metadata area)
    pub text: Option<String>,
}

/// Reads the PV label (sectors 0-3) and the first usable metadata area.
pub fn read_pv(v: &Vol) -> Result<Pv, String> {
    let head = v.read_vec(0, 2048).map_err(|e| e.to_string())?;
    let sector = (0..4)
        .find(|s| head.get(s * 512..s * 512 + 8) == Some(b"LABELONE") && head.get(s * 512 + 24..s * 512 + 32) == Some(b"LVM2 001"))
        .ok_or("no LVM label")?;
    let lab = &head[sector * 512..sector * 512 + 512];
    if le64(lab, 8) != sector as u64 {
        return Err("LVM label: wrong sector".into());
    }
    if crate::part::crc32_lvm(&lab[20..512]) != le32(lab, 16) {
        return Err("LVM label checksum".into());
    }
    let off = le32(lab, 20) as usize;
    if !(32..=400).contains(&off) {
        return Err("LVM label: PV header offset".into());
    }
    let ph = &lab[off..];
    let uuid = String::from_utf8_lossy(&ph[..32]).into_owned();
    if !uuid.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("LVM label: PV UUID".into());
    }
    // disk_locn lists: data areas, 0-terminated, then metadata areas, 0-terminated
    let mut i = 40;
    let mut lists: [Vec<(u64, u64)>; 2] = [Vec::new(), Vec::new()];
    for list in &mut lists {
        loop {
            if i + 16 > ph.len() {
                return Err("LVM label: area list".into());
            }
            let (o, s) = (le64(ph, i), le64(ph, i + 8));
            i += 16;
            if o == 0 {
                break;
            }
            list.push((o, s));
        }
    }
    let mut text: Option<(u64, String)> = None;
    for (mda, msize) in &lists[1] {
        if let Ok(Some((seq, t))) = read_mda(v, *mda, *msize) {
            if text.as_ref().is_none_or(|(s, _)| seq > *s) {
                text = Some((seq, t));
            }
        }
    }
    Ok(Pv {
        uuid,
        text: text.map(|t| t.1),
    })
}

fn read_mda(v: &Vol, mda: u64, msize: u64) -> Result<Option<(u64, String)>, String> {
    let h = v.read_vec(mda, 512).map_err(|e| e.to_string())?;
    if h.get(4..20) != Some(MDA_MAGIC) {
        return Err("metadata area magic".into());
    }
    if crate::part::crc32_lvm(&h[4..512]) != le32(&h, 0) {
        return Err("metadata area checksum".into());
    }
    let size = le64(&h, 32).min(msize.max(1024));
    let (roff, rsize, flags) = (le64(&h, 40), le64(&h, 48), le32(&h, 60));
    if rsize == 0 || flags & 1 != 0 {
        return Ok(None);
    }
    if rsize > MAX_TEXT || roff < 512 || roff >= size || size <= 512 {
        return Err("metadata text location".into());
    }
    // circular buffer: may wrap to just after the header
    let first = rsize.min(size - roff);
    let mut buf = v.read_vec(mda + roff, first as usize).map_err(|e| e.to_string())?;
    if first < rsize {
        let rest = rsize - first;
        if rest > size - 512 {
            return Err("metadata text location".into());
        }
        buf.extend(v.read_vec(mda + 512, rest as usize).map_err(|e| e.to_string())?);
    }
    if buf.len() as u64 != rsize {
        return Err("metadata text truncated".into());
    }
    let text = String::from_utf8_lossy(buf.split(|b| *b == 0).next().unwrap_or(&[])).into_owned();
    let seq = parse(&text)
        .ok()
        .and_then(|c| c.iter().find_map(|(_, v)| v.sec()?.iter().find(|(k, _)| k == "seqno")?.1.int()))
        .unwrap_or(0);
    Ok(Some((seq as u64, text)))
}

// ------------------------------------------------------------ config text

#[derive(Clone, Debug, PartialEq)]
pub enum Val {
    Str(String),
    Int(i64),
    List(Vec<Val>),
    Sec(Vec<(String, Val)>),
}

impl Val {
    pub fn sec(&self) -> Option<&[(String, Val)]> {
        match self {
            Val::Sec(s) => Some(s),
            _ => None,
        }
    }
    pub fn int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        match self {
            Val::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn list(&self) -> Option<&[Val]> {
        match self {
            Val::List(l) => Some(l),
            _ => None,
        }
    }
}

fn get<'a>(s: &'a [(String, Val)], k: &str) -> Option<&'a Val> {
    s.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Sym(char),
}

fn lex(t: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut it = t.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '#' => {
                for c in it.by_ref() {
                    if c == '\n' {
                        break;
                    }
                }
            }
            c if c.is_whitespace() => {}
            '=' | '{' | '}' | '[' | ']' | ',' => out.push(Tok::Sym(c)),
            '"' => {
                let mut s = String::new();
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some('\\') => s.extend(it.next()),
                        Some(c) => s.push(c),
                        None => return Err("unterminated string".into()),
                    }
                }
                out.push(Tok::Str(s));
            }
            c if c.is_ascii_alphanumeric() || "_.-+".contains(c) => {
                let mut s = String::from(c);
                while let Some(&c) = it.peek() {
                    if c.is_ascii_alphanumeric() || "_.-+".contains(c) {
                        s.push(c);
                        it.next();
                    } else {
                        break;
                    }
                }
                out.push(Tok::Word(s));
            }
            c => return Err(format!("unexpected character {c:?}")),
        }
        if out.len() > MAX_ITEMS * 4 {
            return Err("metadata too large".into());
        }
    }
    Ok(out)
}

struct P {
    t: Vec<Tok>,
    i: usize,
}

impl P {
    fn section(&mut self, depth: usize, top: bool) -> Result<Vec<(String, Val)>, String> {
        if depth > MAX_DEPTH {
            return Err("metadata nested too deeply".into());
        }
        let mut out = Vec::new();
        loop {
            match self.t.get(self.i) {
                None if top => return Ok(out),
                None => return Err("unterminated section".into()),
                Some(Tok::Sym('}')) if !top => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(Tok::Word(k)) | Some(Tok::Str(k)) => {
                    let k = k.clone();
                    self.i += 1;
                    match self.t.get(self.i) {
                        Some(Tok::Sym('=')) => {
                            self.i += 1;
                            let v = self.value(depth)?;
                            out.push((k, v));
                        }
                        Some(Tok::Sym('{')) => {
                            self.i += 1;
                            let s = self.section(depth + 1, false)?;
                            out.push((k, Val::Sec(s)));
                        }
                        _ => return Err(format!("expected = or {{ after {k}")),
                    }
                }
                Some(t) => return Err(format!("unexpected {t:?}")),
            }
            if out.len() > MAX_ITEMS {
                return Err("metadata too large".into());
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Val, String> {
        let t = self.t.get(self.i).ok_or("missing value")?;
        self.i += 1;
        Ok(match t {
            Tok::Str(s) => Val::Str(s.clone()),
            Tok::Word(w) => match w.parse::<i64>() {
                Ok(n) => Val::Int(n),
                Err(_) => Val::Str(w.clone()),
            },
            Tok::Sym('[') => {
                let mut l = Vec::new();
                loop {
                    match self.t.get(self.i) {
                        Some(Tok::Sym(']')) => {
                            self.i += 1;
                            break;
                        }
                        Some(Tok::Sym(',')) => self.i += 1,
                        None => return Err("unterminated list".into()),
                        _ => {
                            if depth > MAX_DEPTH {
                                return Err("metadata nested too deeply".into());
                            }
                            l.push(self.value(depth + 1)?);
                            if l.len() > MAX_ITEMS {
                                return Err("metadata too large".into());
                            }
                        }
                    }
                }
                Val::List(l)
            }
            t => return Err(format!("unexpected {t:?}")),
        })
    }
}

/// Parses LVM2 text metadata into its top-level items.
pub fn parse(text: &str) -> Result<Vec<(String, Val)>, String> {
    let mut p = P { t: lex(text)?, i: 0 };
    p.section(0, true)
}

// --------------------------------------------------------------- volumes

#[derive(Clone, Debug, PartialEq)]
pub struct Lv {
    pub vg: String,
    pub name: String,
    pub id: String,
    /// segments on disks, or why the LV cannot be read
    pub map: Result<Vec<Segment>, String>,
}

/// Where each PV (by UUID without dashes) starts: (disk, byte offset).
pub type PvMap = BTreeMap<String, (usize, u64)>;

/// The visible logical volumes of the volume groups in `texts` (newest seqno
/// per VG wins), mapped to disk bytes through `pvs`.
pub fn volumes(texts: &[String], pvs: &PvMap) -> Vec<Lv> {
    let mut vgs: BTreeMap<String, (i64, Vec<(String, Val)>)> = BTreeMap::new();
    for t in texts {
        let Ok(top) = parse(t) else { continue };
        for (name, v) in top {
            let Some(sec) = v.sec() else { continue };
            let (Some(id), Some(seq)) = (get(sec, "id").and_then(Val::str), get(sec, "seqno").and_then(Val::int)) else {
                continue;
            };
            let key = format!("{id}\0{name}");
            if vgs.get(&key).is_none_or(|(s, _)| seq > *s) {
                vgs.insert(key, (seq, sec.to_vec()));
            }
        }
    }
    let mut out = Vec::new();
    for (key, (_, vg)) in vgs {
        let name = key.split('\0').nth(1).unwrap_or_default().to_owned();
        out.extend(vg_volumes(&name, &vg, pvs));
    }
    out
}

fn status_has(sec: &[(String, Val)], flag: &str) -> bool {
    get(sec, "status")
        .and_then(Val::list)
        .is_some_and(|l| l.iter().any(|v| v.str() == Some(flag)))
}

fn vg_volumes(vg: &str, sec: &[(String, Val)], pvs: &PvMap) -> Vec<Lv> {
    let ext = get(sec, "extent_size").and_then(Val::int).unwrap_or(0);
    let empty = Vec::new();
    let lvs = get(sec, "logical_volumes").and_then(Val::sec).unwrap_or(&empty);
    // pv name (pv0) -> (disk, offset of the first extent)
    let mut pv_at: BTreeMap<&str, (usize, u64)> = BTreeMap::new();
    let mut missing = Vec::new();
    for (pname, p) in get(sec, "physical_volumes").and_then(Val::sec).unwrap_or(&empty) {
        let Some(p) = p.sec() else { continue };
        let id: String = get(p, "id").and_then(Val::str).unwrap_or_default().chars().filter(|c| *c != '-').collect();
        let pe_start = get(p, "pe_start").and_then(Val::int).unwrap_or(-1);
        match pvs.get(&id) {
            Some((d, off)) if pe_start >= 0 => {
                pv_at.insert(pname, (*d, off + pe_start as u64 * 512));
            }
            _ => missing.push(pname.clone()),
        }
    }
    let lv = |name: &str, map| Lv {
        vg: vg.to_owned(),
        name: name.to_owned(),
        id: lvs
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, s)| get(s.sec()?, "id")?.str())
            .unwrap_or_default()
            .to_owned(),
        map,
    };
    let visible: Vec<&str> = lvs
        .iter()
        .filter(|(_, s)| s.sec().is_some_and(|s| status_has(s, "VISIBLE")))
        .map(|(n, _)| n.as_str())
        .collect();
    if !(1..=(1 << 30)).contains(&ext) {
        return visible.iter().map(|n| lv(n, Err("volume group: invalid extent size".into()))).collect();
    }
    if !missing.is_empty() {
        let why = format!("volume group {vg}: physical volume missing ({})", missing.join(", "));
        return visible.iter().map(|n| lv(n, Err(why.clone()))).collect();
    }
    let ctx = Ctx {
        lvs,
        pv_at: &pv_at,
        ext: ext as u64 * 512,
    };
    visible.iter().map(|n| lv(n, ctx.map(n, 0))).collect()
}

struct Ctx<'a> {
    lvs: &'a [(String, Val)],
    pv_at: &'a BTreeMap<&'a str, (usize, u64)>,
    ext: u64,
}

impl Ctx<'_> {
    fn map(&self, name: &str, depth: usize) -> Result<Vec<Segment>, String> {
        if depth > 4 {
            return Err("logical volume stacked too deeply".into());
        }
        let lv = get(self.lvs, name).and_then(Val::sec).ok_or_else(|| format!("logical volume {name} not in the metadata"))?;
        let mut segs = Vec::new();
        for (k, s) in lv {
            if !k.starts_with("segment") {
                continue;
            }
            let Some(s) = s.sec() else { continue };
            let start = get(s, "start_extent").and_then(Val::int).filter(|x| *x >= 0).ok_or("segment start")? as u64;
            let count = get(s, "extent_count").and_then(Val::int).filter(|x| *x > 0).ok_or("segment length")? as u64;
            let (lstart, len) = (
                start.checked_mul(self.ext).ok_or("segment start")?,
                count.checked_mul(self.ext).ok_or("segment length")?,
            );
            let ty = get(s, "type").and_then(Val::str).unwrap_or_default();
            match ty {
                "striped" | "linear" => {
                    let stripes = get(s, "stripes").and_then(Val::list).ok_or("segment without stripes")?;
                    let n = stripes.len() / 2;
                    if n == 0 || stripes.len() % 2 != 0 || count % n as u64 != 0 {
                        return Err("striped segment layout".into());
                    }
                    let mut legs = Vec::new();
                    for pair in stripes.chunks(2) {
                        let (Some(pv), Some(pe)) = (pair[0].str(), pair[1].int().filter(|x| *x >= 0)) else {
                            return Err("striped segment layout".into());
                        };
                        let (d, base) = self.pv_at.get(pv).ok_or_else(|| format!("unknown physical volume {pv}"))?;
                        legs.push((*d, base + pe as u64 * self.ext));
                    }
                    let stripe = if n > 1 {
                        let sz = get(s, "stripe_size").and_then(Val::int).filter(|x| *x > 0).ok_or("stripe size")?;
                        sz as u64 * 512
                    } else {
                        0
                    };
                    segs.push(Segment {
                        start: lstart,
                        len,
                        legs,
                        stripe,
                    });
                }
                "mirror" | "raid1" => {
                    let key = if ty == "mirror" { "mirrors" } else { "raids" };
                    let l = get(s, key).and_then(Val::list).ok_or("mirror without legs")?;
                    // mirror: [image, start_extent, …]; raid1: [rmeta, rimage, …]
                    let (img, off) = if ty == "mirror" {
                        (l.first().and_then(Val::str), l.get(1).and_then(Val::int).unwrap_or(0))
                    } else {
                        (l.get(1).and_then(Val::str), 0)
                    };
                    let img = img.ok_or("mirror without legs")?;
                    let sub = self.map(img, depth + 1)?;
                    segs.extend(crop(&sub, off.max(0) as u64 * self.ext, len, lstart)?);
                }
                "thin" | "thin-pool" => return Err("LVM thin volumes are not indexed yet".into()),
                "cache" | "cache-pool" | "writecache" => return Err("LVM cache volumes are not indexed".into()),
                "vdo" | "vdo-pool" => return Err("LVM VDO volumes are not indexed".into()),
                "snapshot" => return Err("LVM snapshot volumes are not indexed".into()),
                t if t.starts_with("raid") => return Err(format!("LVM {t} volumes are not indexed")),
                t => return Err(format!("LVM segment type {t:?} is not supported")),
            }
        }
        segs.sort_by_key(|s| s.start);
        let mut at = 0;
        for s in &segs {
            if s.start != at {
                return Err("logical volume has gaps".into());
            }
            at += s.len;
        }
        if segs.is_empty() {
            return Err("logical volume without segments".into());
        }
        Ok(segs)
    }
}

/// `len` bytes of `segs` from `from`, placed at `to`. Only whole striped
/// segments can be moved (cutting one would change its stripe phase).
fn crop(segs: &[Segment], from: u64, len: u64, to: u64) -> Result<Vec<Segment>, String> {
    let mut out = Vec::new();
    let end = from.checked_add(len).ok_or("mirror leg range")?;
    for s in segs {
        let (a, b) = (s.start.max(from), (s.start + s.len).min(end));
        if a >= b {
            continue;
        }
        if s.legs.len() > 1 && (a != s.start || b != s.start + s.len) {
            return Err("striped mirror legs are not supported".into());
        }
        out.push(Segment {
            start: a - from + to,
            len: b - a,
            legs: s.legs.iter().map(|(d, o)| (*d, if s.legs.len() > 1 { *o } else { o + (a - s.start) })).collect(),
            stripe: s.stripe,
        });
    }
    if out.iter().map(|s| s.len).sum::<u64>() != len {
        return Err("mirror leg shorter than the volume".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const META: &str = r#"
vg0 {
	id = "Vg0Id1-aaaa-bbbb-cccc-dddd-eeee-ffffff"
	seqno = 7
	format = "lvm2" # informational
	status = ["RESIZEABLE", "READ", "WRITE"]
	extent_size = 8192		# 4 Megabytes
	physical_volumes {
		pv0 { id = "AAAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAAA" device = "/dev/vda2" pe_start = 2048 pe_count = 100 }
		pv1 { id = "BBBBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBBBB" device = "/dev/vdb" pe_start = 2048 pe_count = 100 }
	}
	logical_volumes {
		root {
			id = "root-id"
			status = ["READ", "WRITE", "VISIBLE"]
			segment_count = 2
			segment1 { start_extent = 0 extent_count = 10 type = "striped" stripe_count = 1 stripes = ["pv0", 0] }
			segment2 { start_extent = 10 extent_count = 4 type = "striped" stripe_count = 2 stripe_size = 128 stripes = ["pv0", 10, "pv1", 0] }
		}
		mirrored {
			id = "m-id"
			status = ["READ", "WRITE", "VISIBLE"]
			segment1 { start_extent = 0 extent_count = 2 type = "raid1" device_count = 2 raids = ["mirrored_rmeta_0", "mirrored_rimage_0", "mirrored_rmeta_1", "mirrored_rimage_1"] }
		}
		mirrored_rimage_0 { id = "x" status = ["READ"] segment1 { start_extent = 0 extent_count = 2 type = "striped" stripe_count = 1 stripes = ["pv1", 50] } }
		pool { id = "p" status = ["READ", "VISIBLE"] segment1 { start_extent = 0 extent_count = 1 type = "thin-pool" } }
	}
}
contents = "Text Format Volume Group"
version = 1
"#;

    #[test]
    fn maps_linear_striped_raid1_and_reports_thin() {
        let mut pvs = PvMap::new();
        pvs.insert("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(), (0, 1 << 20));
        pvs.insert("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".into(), (1, 0));
        let lvs = volumes(&[META.to_owned()], &pvs);
        let names: Vec<_> = lvs.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["root", "mirrored", "pool"]);
        let e = 4u64 << 20;
        let base0 = (1 << 20) + 2048 * 512;
        let base1 = 2048 * 512;
        assert_eq!(
            lvs[0].map.as_ref().unwrap(),
            &vec![
                Segment { start: 0, len: 10 * e, legs: vec![(0, base0)], stripe: 0 },
                Segment { start: 10 * e, len: 4 * e, legs: vec![(0, base0 + 10 * e), (1, base1)], stripe: 65536 },
            ]
        );
        assert_eq!(
            lvs[1].map.as_ref().unwrap(),
            &vec![Segment { start: 0, len: 2 * e, legs: vec![(1, base1 + 50 * e)], stripe: 0 }]
        );
        assert!(lvs[2].map.as_ref().unwrap_err().contains("thin"));
        // a missing PV skips the whole volume group
        pvs.remove("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        let lvs = volumes(&[META.to_owned()], &pvs);
        assert!(lvs.iter().all(|l| l.map.as_ref().unwrap_err().contains("physical volume missing (pv1)")));
    }

    #[test]
    fn hostile_text() {
        assert!(parse("a { b = [").is_err());
        assert!(parse(&"a {".repeat(100)).is_err());
        assert!(parse("x = \"unterminated").is_err());
        assert!(parse("x = [1, \"a\", [2]] y { }").is_ok());
        assert_eq!(volumes(&["vg { id = \"i\" seqno = 1 extent_size = 0 }".into()], &PvMap::new()), vec![]);
    }
}
