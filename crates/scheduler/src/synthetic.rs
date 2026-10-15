//! Synthetic (clean-file) restore (Phase 33, docs/control-plane.md "Synthetic
//! restore"): `synthetic_restore {source, time, paths, depth?, mode, …}` for
//! file-tree snapshots (agents `host-`, TrueNAS `nas-`, shares `share-`).
//!
//! For every file of the chosen snapshot the newest version is taken that has
//! no YARA match, is not on an IOC hash list, is not a ransom note and is not
//! the output of a mass rename (21a), walking back through up to `depth` older
//! snapshots of the source (default 30); a version with the same content as a
//! flagged one (size + mtime, or SHA-256) counts as flagged too. Files a mass
//! rename deleted are brought back from before it. Files without a clean
//! version are left out. The decision is made here from the sealed name
//! indexes and the catalog ([`select`], a `Step::Store`); `nexus-agentctl …
//! synthetic` then composes the tree (`chunkstore::synthetic::compose`) and
//! writes the download (`mode: download`, tar or zip) or restores it to an
//! agent (`mode: host`). The substituted, restored and left-out files go into a
//! CSV in the downloads directory (`<report_token>.csv`, web-api
//! `GET /jobs/{id}/synthetic.csv`).

use super::*;
use crate::changes;
use crate::run::{Step, StoreOp};
use crate::search::Glob;
use chunkstore::names::{KIND_DIR, KIND_FILE};
use chunkstore::synthetic::Plan as Composition;
use chunkstore::NameIndex;
use std::collections::{BTreeMap, HashMap, HashSet};

/// Older snapshots examined by default / at most.
pub const DEFAULT_DEPTH: u64 = 30;
pub const MAX_DEPTH: u64 = 100;
/// Sources a synthetic restore accepts.
pub const PREFIXES: &[&str] = &["host-", "nas-", "share-"];

/// What makes a file version unusable, besides the content of flagged versions.
pub struct Taints {
    /// per snapshot time: YARA-matched paths (index form) → rule, and whether the
    /// scan listed fewer matches than it found (then every file of it is suspect)
    pub yara: HashMap<u64, (HashMap<String, String>, bool)>,
    /// IOC hash lists: hash → list names
    pub hashes: HashMap<chunkstore::names::Sha256, Vec<String>>,
    /// ransom-note file name globs (last path component)
    pub notes: Vec<Glob>,
}

/// One line of the CSV.
#[derive(Debug, PartialEq, Clone)]
pub struct Row {
    pub path: String,
    /// `substituted`, `restored` (deleted by a mass rename), `left_out`
    pub action: &'static str,
    /// the snapshot the file comes from (substituted, restored)
    pub version: Option<u64>,
    pub reason: String,
}

/// A file version: size, mtime, SHA-256 if recorded.
type Version = (u64, i64, Option<chunkstore::names::Sha256>);

fn files(n: &NameIndex) -> HashMap<&str, Version> {
    n.iter()
        .enumerate()
        .filter(|(_, e)| e.3 == KIND_FILE)
        .map(|(i, (p, size, mtime, _))| (p, (size, mtime, n.hash(i).copied())))
        .collect()
}

/// `docs/a` is within the request paths (`/` = everything; index form prefixes).
fn wanted(path: &str, sel: &[String]) -> bool {
    sel.is_empty()
        || sel.iter().any(|s| {
            path == s || (path.len() > s.len() && path.starts_with(s.as_str()) && path.as_bytes()[s.len()] == b'/')
        })
}

/// The request paths in index form (empty = the whole snapshot).
pub fn selection(paths: &[String]) -> Vec<String> {
    let sel: Vec<String> = paths
        .iter()
        .map(|p| chunkstore::names::normalise(p).trim_end_matches('/').to_owned())
        .collect();
    if sel.iter().any(String::is_empty) {
        Vec::new()
    } else {
        sel
    }
}

/// The mass rename between `older` and `newer` (21a thresholds): the files it
/// added (its output: a deleted file's path plus an extension, or the dominant
/// new extension, so an unrelated new file type is not caught) and the files it
/// deleted, or none.
fn mass_rename(older: &NameIndex, newer: &NameIndex) -> Option<(HashSet<String>, Vec<String>, String)> {
    let r = changes::signals(older, newer, &[]);
    let why = changes::finding(&r)?;
    if !why.contains("mass rename") {
        return None;
    }
    let old_exts: HashSet<String> = older
        .iter()
        .filter(|e| e.3 != KIND_DIR)
        .filter_map(|e| changes::ext(e.0))
        .collect();
    let ch = changes::diff(older, newer);
    let deleted: Vec<String> = ch
        .iter()
        .filter(|c| c.change == "deleted")
        .map(|c| c.path.to_owned())
        .collect();
    let gone: HashSet<&str> = deleted.iter().map(String::as_str).collect();
    let mut per_ext: HashMap<String, usize> = HashMap::new();
    let new: Vec<(&str, Option<String>)> = ch
        .iter()
        .filter(|c| c.change == "added")
        .map(|c| (c.path, changes::ext(c.path).filter(|e| !old_exts.contains(e))))
        .collect();
    for e in new.iter().filter_map(|(_, e)| e.as_ref()) {
        *per_ext.entry(e.clone()).or_default() += 1;
    }
    let top = per_ext.values().copied().max().unwrap_or(0);
    let added = new
        .into_iter()
        .filter(|(p, e)| {
            let renamed = p.rsplit_once('.').is_some_and(|(stem, _)| gone.contains(stem));
            renamed || e.as_ref().is_some_and(|e| per_ext[e] * 2 >= top)
        })
        .map(|(p, _)| p.to_owned())
        .collect();
    Some((added, deleted, why))
}

/// The decision: which version of each file to restore. `times` are the
/// snapshots of the source, newest (the chosen one) first; `load` returns a
/// snapshot's name index (`None`: it has none, the walk ends there).
pub fn select(
    source: &str,
    times: &[u64],
    sel: &[String],
    t: &Taints,
    load: &mut dyn FnMut(u64) -> std::io::Result<Option<NameIndex>>,
) -> std::io::Result<(Composition, Vec<Row>)> {
    let base_time = times[0];
    let base = load(base_time)?.ok_or_else(|| {
        std::io::Error::other(format!(
            "{source}/{base_time} has no file name index (not a file-tree snapshot?)"
        ))
    })?;
    let base_files: HashMap<String, Version> = files(&base)
        .into_iter()
        .filter(|(p, _)| wanted(p, sel))
        .map(|(p, v)| (p.to_owned(), v))
        .collect();
    // path → why its newer versions were refused (first reason kept)
    let mut need: BTreeMap<String, String> = BTreeMap::new();
    // files a mass rename deleted (not in the chosen snapshot) → why
    let mut deleted: BTreeMap<String, String> = BTreeMap::new();
    // content of flagged versions per path (size, mtime, hash, where)
    let mut bad_content: HashMap<String, Vec<(Version, u64)>> = HashMap::new();
    let mut take: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    let mut rows = Vec::new();
    let (mut examined, mut unscanned_used) = (1u64, 0u64);
    let mut cur = base;
    for (k, &time) in times.iter().enumerate() {
        let older = match times.get(k + 1) {
            Some(&o) => load(o)?,
            None => None,
        };
        if older.is_some() {
            examined += 1;
        }
        let rename = older.as_ref().and_then(|o| mass_rename(o, &cur));
        let (yara, truncated) = t.yara.get(&time).map(|(m, tr)| (Some(m), *tr)).unwrap_or((None, false));
        let cur_files = files(&cur);
        let candidates: Vec<String> = if k == 0 {
            base_files.keys().cloned().collect()
        } else {
            need.keys().chain(deleted.keys()).cloned().collect()
        };
        for p in candidates {
            let Some(v) = cur_files.get(p.as_str()).copied() else {
                continue;
            };
            let name = p.rsplit('/').next().unwrap_or(&p);
            // content-based reasons also flag the same content in older snapshots
            let (reason, content): (Option<String>, bool) = if t.notes.iter().any(|g| g.matches(name)) {
                (Some("ransom-note file name".into()), false)
            } else if rename.as_ref().is_some_and(|r| r.0.contains(&p)) {
                (Some(format!("output of a mass rename in snapshot {time}")), false)
            } else if let Some(rule) = yara.and_then(|m| m.get(&p)) {
                (Some(format!("YARA rule {rule} matched in snapshot {time}")), true)
            } else if let Some(lists) = v.2.as_ref().and_then(|h| t.hashes.get(h)) {
                (
                    Some(format!("SHA-256 on IOC list {} in snapshot {time}", lists.join(", "))),
                    true,
                )
            } else if let Some(at) = bad_content.get(&p).and_then(|b| {
                b.iter()
                    .find(|(x, _)| (x.0, x.1) == (v.0, v.1) || (x.2.is_some() && x.2 == v.2))
                    .map(|(_, at)| *at)
            }) {
                (
                    Some(format!("same content as the flagged version of snapshot {at}")),
                    true,
                )
            } else if truncated {
                (
                    Some(format!("the scan of snapshot {time} found more matches than it lists")),
                    true,
                )
            } else {
                (None, false)
            };
            match reason {
                Some(why) => {
                    if content {
                        bad_content.entry(p.clone()).or_default().push((v, time));
                    }
                    if k == 0 {
                        need.insert(p, why);
                    }
                }
                None if k == 0 => {}
                None => {
                    if !t.yara.contains_key(&time) {
                        unscanned_used += 1;
                    }
                    take.entry(time).or_default().push(p.clone());
                    if let Some(why) = need.remove(&p) {
                        rows.push(Row {
                            path: p,
                            action: "substituted",
                            version: Some(time),
                            reason: why,
                        });
                    } else if let Some(why) = deleted.remove(&p) {
                        rows.push(Row {
                            path: p,
                            action: "restored",
                            version: Some(time),
                            reason: why,
                        });
                    }
                }
            }
        }
        // the files this step's mass rename deleted: wanted back unless the chosen snapshot has them
        if let Some((_, gone, why)) = &rename {
            for p in gone.iter().filter(|p| wanted(p, sel) && !base_files.contains_key(*p)) {
                deleted
                    .entry(p.clone())
                    .or_insert_with(|| format!("deleted by a mass rename in snapshot {time} ({why})"));
            }
        }
        match older {
            Some(o) => cur = o,
            None => break,
        }
    }
    let mut drop = Vec::new();
    for (p, why) in need {
        rows.push(Row {
            path: p.clone(),
            action: "left_out",
            version: None,
            reason: format!("{why}; no clean version in the {examined} snapshots examined"),
        });
        drop.push(p);
    }
    for (p, why) in deleted {
        rows.push(Row {
            path: p,
            action: "left_out",
            version: None,
            reason: format!("{why}; no clean version before it in the {examined} snapshots examined"),
        });
    }
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    let count = |a: &str| rows.iter().filter(|r| r.action == a).count();
    let stats = json!({
        "files": base_files.len(), "substituted": count("substituted"), "restored": count("restored"),
        "left_out": count("left_out"), "snapshots_examined": examined,
        "from_unscanned": unscanned_used,
    });
    Ok((
        Composition {
            source: source.to_owned(),
            time: base_time,
            paths: Vec::new(),
            take,
            drop,
            stats,
        },
        rows,
    ))
}

fn csv_field(s: &str) -> String {
    // a leading = + - @ would be a formula in a spreadsheet
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_owned()
    };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// The CSV of the substituted, restored and left-out files.
pub fn csv(rows: &[Row]) -> String {
    let mut out = String::from("path,action,version,reason\r\n");
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{}\r\n",
            csv_field(&format!("/{}", r.path)),
            r.action,
            r.version.map(|v| v.to_string()).unwrap_or_default(),
            csv_field(&r.reason)
        ));
    }
    out
}

fn token(p: &Value, k: &str) -> Result<String> {
    let t = p[k].as_str().unwrap_or_default();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("synthetic_restore needs {k} (64 hex characters)");
    }
    Ok(t.to_owned())
}

impl Scheduler {
    /// The catalog's part of the decision: YARA results of the snapshots, IOC
    /// lists, ransom-note globs.
    fn synthetic_taints(&self, tenant: &str, source: &str, times: &[u64]) -> Result<Taints> {
        let c = self.db.conn();
        let mut yara = HashMap::new();
        for &t in times {
            let row: Option<(String, i64)> = c
                .query_row(
                    "SELECT matches, matches_total FROM snapshot_scans WHERE tenant = ?1 AND source = ?2 AND time = ?3
                     ORDER BY job_id DESC LIMIT 1",
                    params![tenant, source, t as i64],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((m, total)) = row else { continue };
            let list: Vec<Value> = serde_json::from_str(&m).unwrap_or_default();
            let paths: HashMap<String, String> = list
                .iter()
                .filter_map(|x| {
                    Some((
                        chunkstore::names::normalise(x["path"].as_str()?).into_owned(),
                        x["rule"].as_str().unwrap_or("?").to_owned(),
                    ))
                })
                .collect();
            let truncated = total as usize > list.len();
            yara.insert(t, (paths, truncated));
        }
        let cfg = crate::anomaly::Config::load(&c);
        let notes = changes::RANSOM_NOTES
            .iter()
            .map(std::string::ToString::to_string)
            .chain(cfg.ransom_notes)
            .map(|g| Glob::new(&g, true))
            .collect();
        Ok(Taints {
            yara,
            hashes: crate::threat::hash_set(&c, None)?,
            notes,
        })
    }

    pub(crate) fn plan_synthetic(&self, job: &Job, mut plan: Plan) -> Result<Plan> {
        let (p, tenant, dir) = (&job.params, job.tenant.clone(), plan.dir.clone());
        let source = ident(p, "source")?.to_owned();
        if !PREFIXES.iter().any(|x| source.starts_with(x)) {
            bail!("synthetic_restore: {source} is not a file-tree snapshot of an agent, NAS or share");
        }
        let time = num(p, "time")?;
        let depth = p["depth"].as_u64().unwrap_or(DEFAULT_DEPTH).clamp(1, MAX_DEPTH);
        let paths: Vec<String> = match p["paths"].as_array() {
            Some(_) => file_paths(p)?,
            None => vec!["/".into()],
        };
        let report = self.cfg.downloads.join(format!("{}.csv", token(p, "report_token")?));
        let times: Vec<u64> = {
            let c = self.db.conn();
            let mut q = c.prepare(
                "SELECT time FROM snapshots WHERE tenant = ?1 AND source = ?2 AND local = 1 AND time <= ?3
                 ORDER BY time DESC LIMIT ?4",
            )?;
            let rows = q.query_map(params![tenant, source, time as i64, depth as i64 + 1], |r| {
                r.get::<_, i64>(0)
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .map(|t| t as u64)
                .collect()
        };
        if times.first() != Some(&time) {
            bail!("no local snapshot {source}/{time}");
        }
        let taints = self.synthetic_taints(&tenant, &source, &times)?;
        let sel = selection(&paths);
        let plan_file = dir.join("synthetic.json");
        let (src, req_paths) = (source.clone(), paths.clone());
        plan.steps.push(Step::Store(StoreOp(Box::new(move |s| {
            let r = (|| {
                let (mut comp, rows) = select(&src, &times, &sel, &taints, &mut |t| match s.load_manifest(&src, t) {
                    Ok(m) => s.names_or_build(&m),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e),
                })?;
                comp.paths = req_paths.clone();
                std::fs::write(&plan_file, serde_json::to_vec(&comp)?)?;
                std::fs::write(&report, csv(&rows))?;
                let _ = std::fs::set_permissions(&report, std::fs::Permissions::from_mode(0o640));
                Ok::<_, std::io::Error>(comp.stats.to_string())
            })();
            r.map_err(|e| format!("synthetic restore: {e}"))
        }))));
        let mut cfg = json!({"plan": dir.join("synthetic.json")});
        let agent = match p["mode"].as_str() {
            Some("download") => {
                let ext = match p["format"].as_str().unwrap_or("tar") {
                    f @ ("tar" | "zip") => f,
                    f => bail!("invalid format {f:?}"),
                };
                let out = self
                    .cfg
                    .downloads
                    .join(format!("{}.{ext}", token(p, "download_token")?));
                cfg["out"] = json!(out);
                plan.download = Some(out);
                plan.key = format!("guest:{tenant}/{source}");
                None
            }
            Some("host") => {
                let target = match (p["agent_id"].as_str(), source.strip_prefix("host-")) {
                    (Some(a), _) | (None, Some(a)) => a.to_owned(),
                    (None, None) => bail!("synthetic_restore to a host needs agent_id"),
                };
                let a = self.agent(&tenant, &target)?;
                if a.cert_sha256.is_none() {
                    bail!("agent {} ({}) is not enrolled", a.name, a.id);
                }
                plan.key = format!("agent:{}", a.id);
                cfg["restore"] = json!({
                    "target": p["target"].as_str().context("missing parameter target")?,
                    "overwrite": p["overwrite"].as_str().unwrap_or("never"),
                    "confirm": p["confirm"].as_str().context("missing parameter confirm")?,
                });
                Some(a)
            }
            m => bail!("mode: download or host, not {m:?}"),
        };
        let name = "synthetic.agentctl.json".to_owned();
        let c = self.agentctl_base(&tenant, job, agent.as_ref(), json!({"synthetic": cfg}));
        plan.files.push((name.clone(), serde_json::to_vec_pretty(&c)?));
        plan.steps.push(Step::Cli {
            bin: self.cfg.agentctl_bin.clone(),
            args: vec![dir.join(&name).to_string_lossy().into_owned(), "synthetic".into()],
            alert: None,
            capture: true,
        });
        Ok(plan)
    }

    /// The job result: the connector's last JSON line (with the scheduler's
    /// counts), plus the download for `mode: download`.
    pub(crate) fn synthetic_result(&self, job: &Job, stdout: Option<&str>, log: &mut String) -> Option<Value> {
        let out = stdout.unwrap_or_default();
        let mut r = out
            .lines()
            .rev()
            .find_map(|l| serde_json::from_str::<Value>(l).ok().filter(Value::is_object))?;
        r["report_token"] = job.params["report_token"].clone();
        if job.params["mode"] == "download" {
            let ext = if job.params["format"] == "zip" { "zip" } else { "tar" };
            let file = format!("{}.{ext}", job.params["download_token"].as_str().unwrap_or_default());
            let path = self.cfg.downloads.join(&file);
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o640));
            r["download_token"] = job.params["download_token"].clone();
            r["format"] = json!(ext);
            r["size"] = json!(fs::metadata(&path).map(|m| m.len()).unwrap_or(0));
            r["expires"] = json!(catalog::now() + self.cfg.download_ttl_secs);
            log.push_str(&format!("[scheduler] download ready: {file}\n"));
        }
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(files: &[(&str, u64, i64)]) -> NameIndex {
        let mut n = NameIndex::default();
        n.push("docs", 0, 0, KIND_DIR);
        for (p, s, m) in files {
            n.push(p, *s, *m, KIND_FILE);
        }
        n
    }

    fn taints() -> Taints {
        Taints {
            yara: HashMap::new(),
            hashes: HashMap::new(),
            notes: changes::RANSOM_NOTES.iter().map(|g| Glob::new(g, true)).collect(),
        }
    }

    fn run(snaps: &BTreeMap<u64, NameIndex>, t: &Taints, sel: &[String]) -> (Composition, Vec<Row>) {
        let times: Vec<u64> = snaps.keys().rev().copied().collect();
        select("host-a", &times, sel, t, &mut |x| Ok(snaps.get(&x).cloned())).unwrap()
    }

    /// A YARA hit falls back to the previous version; the same content further
    /// back is flagged too; a ransom note without history is left out.
    #[test]
    fn yara_hits_fall_back_and_ransom_notes_go() {
        let snaps = BTreeMap::from([
            (1, index(&[("docs/a.exe", 10, 1), ("docs/b.txt", 5, 1)])),
            (2, index(&[("docs/a.exe", 11, 2), ("docs/b.txt", 5, 1)])),
            (
                3,
                index(&[
                    ("docs/a.exe", 11, 2),
                    ("docs/b.txt", 6, 3),
                    ("docs/HOW_TO_DECRYPT.txt", 1, 3),
                ]),
            ),
        ]);
        let mut t = taints();
        t.yara.insert(
            3,
            (HashMap::from([("docs/a.exe".to_owned(), "Evil".to_owned())]), false),
        );
        let (plan, rows) = run(&snaps, &t, &[]);
        // a.exe of 2 is the same content (11 bytes, mtime 2) as the flagged one of 3: from 1
        assert_eq!(plan.take, BTreeMap::from([(1, vec!["docs/a.exe".to_owned()])]));
        assert_eq!(plan.drop, ["docs/HOW_TO_DECRYPT.txt"]);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].action, rows[0].version), ("left_out", None));
        assert!(
            rows[0]
                .reason
                .starts_with("ransom-note file name; no clean version in the 3 snapshots"),
            "{rows:?}"
        );
        assert_eq!((rows[1].action, rows[1].version), ("substituted", Some(1)));
        assert_eq!(rows[1].reason, "YARA rule Evil matched in snapshot 3");
        assert_eq!(plan.stats["files"], 3);
        assert_eq!(plan.stats["from_unscanned"], 1);
    }

    /// A mass rename: its outputs are left out, the files it deleted come back
    /// from before it; the selection limits all of it.
    #[test]
    fn mass_renames_are_undone() {
        let before: Vec<(String, u64, i64)> = (0..60).map(|i| (format!("docs/f{i}.docx"), 100, 1)).collect();
        let after: Vec<(String, u64, i64)> = (0..60).map(|i| (format!("docs/f{i}.docx.locked"), 120, 2)).collect();
        let r = |v: &[(String, u64, i64)]| index(&v.iter().map(|(p, s, m)| (p.as_str(), *s, *m)).collect::<Vec<_>>());
        let mut keep = r(&after);
        keep.push("other/x.txt", 1, 1, KIND_FILE);
        let snaps = BTreeMap::from([(1, r(&before)), (2, keep)]);
        let (plan, rows) = run(&snaps, &taints(), &[]);
        assert_eq!(plan.drop.len(), 60);
        assert!(plan.drop.iter().all(|p| p.ends_with(".locked")));
        assert_eq!(plan.take[&1].len(), 60);
        let restored: Vec<&Row> = rows.iter().filter(|r| r.action == "restored").collect();
        assert_eq!(restored.len(), 60);
        assert!(
            restored[0].reason.starts_with("deleted by a mass rename in snapshot 2"),
            "{:?}",
            restored[0]
        );
        assert_eq!(plan.stats["left_out"], 60);
        // only below other/: nothing to do
        let (plan, rows) = run(&snaps, &taints(), &selection(&["/other".into()]));
        assert!(plan.take.is_empty() && plan.drop.is_empty() && rows.is_empty());
        assert_eq!(plan.stats["files"], 1);
    }

    /// IOC hashes, truncated scan results, depth and the CSV.
    #[test]
    fn hashes_truncation_and_csv() {
        let h = [7u8; 32];
        let mut cur = index(&[("docs/a.bin", 3, 3), ("docs/b.bin", 4, 3)]);
        cur.set_hash(1, h);
        let snaps = BTreeMap::from([(1, index(&[("docs/b.bin", 4, 1)])), (2, cur)]);
        let mut t = taints();
        t.hashes.insert(h, vec!["ir-case".into()]);
        let (plan, rows) = run(&snaps, &t, &[]);
        assert_eq!(plan.drop, ["docs/a.bin"]);
        assert!(rows[0].reason.contains("SHA-256 on IOC list ir-case"));
        // a scan that listed only part of its matches makes every file of it suspect
        let mut t = taints();
        t.yara.insert(2, (HashMap::new(), true));
        let (plan, _) = run(&snaps, &t, &[]);
        assert_eq!(plan.take[&1], ["docs/b.bin"]);
        let c = csv(&[Row {
            path: "docs/=x,y".into(),
            action: "left_out",
            version: None,
            reason: "a \"b\"".into(),
        }]);
        assert_eq!(
            c,
            "path,action,version,reason\r\n\"/docs/=x,y\",left_out,,\"a \"\"b\"\"\"\r\n"
        );
        assert_eq!(csv_field("=cmd"), "'=cmd");
        assert!(wanted("docs/a", &selection(&["/docs/".into()])) && !wanted("docsx/a", &selection(&["/docs".into()])));
    }
}
