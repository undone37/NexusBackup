//! NAS operations (Phase 22b, docs/nas-connector.md "Sizing, splitting and
//! skipped files"):
//! - sizing note: entries of the newest backup of a share / TrueNAS source and
//!   the RAM a run needs for them (both trees are held in memory), with a
//!   warning when that comes near the appliance's memory;
//! - overlap warning: two visible share sources of the same export / share whose
//!   include roots overlap (or two TrueNAS sources with nested datasets) back up
//!   the same files twice;
//! - split: a share source becomes one source per include root (each its own
//!   snapshot chain and run, copies of the original's groups); the original stays
//!   until the operator deletes it;
//! - skipped files: the entries a share backup could not read, as CSV.

use crate::auth::{Ctx, TENANT_WRITERS};
use crate::{ApiError, ApiResult, St, J};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use catalog::rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

/// RAM per entry of a run (previous + new tree, lab: 1M entries peaked at 0.73 GB).
pub const BYTES_PER_ENTRY: u64 = 800;
/// Warn above this share of the appliance's memory, or above `WARN_ENTRIES`.
const WARN_MEM_PCT: u64 = 25;
const WARN_ENTRIES: u64 = 5_000_000;

fn mem_total() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb: u64 = s
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb * 1024)
}

/// Entries of the newest successful backup of a share (`share-<id>`) or the
/// largest dataset of a TrueNAS source (`nas-<id>-…`), from the job results.
fn last_entries(c: &Connection, tenant: &str, prefix: &str, exact: bool) -> ApiResult<Option<u64>> {
    let like = if exact { prefix.to_owned() } else { format!("{prefix}%") };
    Ok(c.query_row(
        "SELECT MAX(json_extract(s.value, '$.entries')) FROM jobs j, json_each(j.result, '$.snapshots') s
         WHERE j.id = (SELECT MAX(j2.id) FROM jobs j2, json_each(j2.result, '$.snapshots') s2
                       WHERE j2.kind = 'backup' AND j2.tenant = ?1 AND j2.state = 'ok'
                         AND json_extract(s2.value, '$.source') LIKE ?2
                         AND json_extract(s2.value, '$.entries') IS NOT NULL)
           AND json_extract(s.value, '$.source') LIKE ?2",
        params![tenant, like],
        |r| r.get::<_, Option<i64>>(0),
    )
    .optional()?
    .flatten()
    .map(|n| n.max(0) as u64))
}

/// `sizing` for one source (None: no backup with an entry count yet).
pub fn sizing(entries: u64, mem: Option<u64>) -> Value {
    let est = entries * BYTES_PER_ENTRY;
    let warn = entries >= WARN_ENTRIES || mem.is_some_and(|m| est * 100 > m * WARN_MEM_PCT);
    json!({"entries": entries, "est_ram_bytes": est, "mem_total": mem, "warn": warn})
}

/// Path roots of a share source (include roots, or the whole share).
fn roots(cfg: &Value) -> Vec<String> {
    let r: Vec<String> = cfg["include"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x.as_str().map(|s| format!("/{}", s.trim_matches('/'))))
        .collect();
    if r.is_empty() {
        vec!["/".into()]
    } else {
        r
    }
}

fn path_overlap(a: &str, b: &str) -> bool {
    let under = |x: &str, root: &str| root == "/" || x == root || x.starts_with(&format!("{root}/"));
    under(a, b) || under(b, a)
}

/// What a source covers: (kind, host, share/export) + roots, or TrueNAS (host, datasets).
fn coverage(s: &Value) -> Option<(String, Vec<String>)> {
    let c = &s["config"];
    let host = c["host"].as_str()?.to_ascii_lowercase();
    match s["kind"].as_str()? {
        "nfs" => Some((format!("nfs|{host}|{}", c["export"].as_str()?), roots(c))),
        // SMB share names are case-insensitive
        "smb" => Some((
            format!("smb|{host}|{}", c["share"].as_str()?.to_ascii_lowercase()),
            roots(c),
        )),
        "truenas" => Some((
            format!("truenas|{host}"),
            c["datasets"]
                .as_array()?
                .iter()
                .filter_map(|d| d.as_str().map(|d| format!("/{d}")))
                .collect(),
        )),
        _ => None,
    }
}

/// Adds `sizing` (share and TrueNAS sources) and `overlaps` (`[{id, name}]` of
/// the other listed sources covering the same paths) to listed sources.
pub fn annotate(c: &Connection, rows: &mut [Value]) -> ApiResult<()> {
    let mem = mem_total();
    let cov: Vec<Option<(String, Vec<String>)>> = rows.iter().map(coverage).collect();
    for i in 0..rows.len() {
        let Some((key, mine)) = &cov[i] else { continue };
        let overlaps: Vec<Value> = (0..rows.len())
            .filter(|&j| j != i)
            .filter(|&j| {
                cov[j].as_ref().is_some_and(|(k, theirs)| {
                    k == key && mine.iter().any(|a| theirs.iter().any(|b| path_overlap(a, b)))
                })
            })
            .map(|j| json!({"id": rows[j]["id"], "name": rows[j]["name"]}))
            .collect();
        let (id, tenant) = (
            rows[i]["id"].as_i64().unwrap_or_default(),
            rows[i]["tenant"].as_str().unwrap_or_default(),
        );
        let entries = if rows[i]["kind"] == "truenas" {
            last_entries(c, tenant, &format!("nas-{id}-"), false)?
        } else {
            last_entries(c, tenant, &format!("share-{id}"), true)?
        };
        let r = &mut rows[i];
        r["overlaps"] = json!(overlaps);
        r["sizing"] = entries.map_or(Value::Null, |n| sizing(n, mem));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SplitReq {
    /// one new source per root (share paths, `/projects/a`)
    roots: Vec<String>,
    /// SMB: the password again (the stored one is sealed to the original source)
    #[serde(default)]
    password: Option<String>,
    /// copy the original's groups to every new source (default true)
    #[serde(default = "yes")]
    copy_groups: bool,
}

fn yes() -> bool {
    true
}

/// `POST /sources/{id}/split`: one new NFS/SMB source per include root (with
/// copies of the original's groups), in one transaction; audited `source.split`.
pub async fn split(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>, J(r): J<SplitReq>) -> ApiResult<Response> {
    ctx.require(TENANT_WRITERS)?;
    crate::vault::refuse(&st.cat.conn(), "new sources")?;
    if !(2..=32).contains(&r.roots.len()) {
        return Err(ApiError::bad("roots: 2..=32 include roots"));
    }
    crate::selection::check_include(&r.roots, "roots")?;
    let (tenant, kind, name, raw): (String, String, String, String) = st
        .cat
        .conn()
        .query_row(
            "SELECT tenant, kind, name, config FROM sources WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
            params![id, ctx.scope()],
            |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if kind != "nfs" && kind != "smb" {
        return Err(ApiError::bad("only NFS and SMB share sources can be split"));
    }
    let mut base: Value = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    let within = roots(&base);
    for (i, a) in r.roots.iter().enumerate() {
        let a = format!("/{}", a.trim_matches('/'));
        if !within
            .iter()
            .any(|w| w == "/" || a == *w || a.starts_with(&format!("{w}/")))
        {
            return Err(ApiError::bad(format!(
                "roots: {a} is outside the source's include roots"
            )));
        }
        if r.roots[..i]
            .iter()
            .any(|b| path_overlap(&a, &format!("/{}", b.trim_matches('/'))))
        {
            return Err(ApiError::bad(format!("roots: {a} overlaps another root")));
        }
    }
    if let Some(o) = base.as_object_mut() {
        for k in ["password", "keytab"] {
            o.remove(k);
        }
    }
    if let Some(p) = &r.password {
        base["password"] = json!(p);
    } else if kind == "smb" {
        return Err(ApiError::bad(
            "password: required (the stored one is sealed to the original source)",
        ));
    }
    let pk = st.seal_key()?;
    let stem: String = name.chars().take(56).collect();
    let ids = {
        let mut c = st.cat.conn();
        let tx = c.transaction()?;
        let cols: Vec<String> = tx
            .prepare("SELECT name FROM pragma_table_info('groups')")?
            .query_map([], |x| x.get(0))?
            .collect::<Result<_, _>>()?;
        let copy: Vec<&str> = cols
            .iter()
            .map(String::as_str)
            .filter(|c| !["id", "source_id", "name", "paused_until"].contains(c))
            .collect();
        let groups: Vec<(i64, String)> = tx
            .prepare("SELECT id, name FROM groups WHERE source_id = ?1")?
            .query_map([id], |x| Ok((x.get(0)?, x.get(1)?)))?
            .collect::<Result<_, _>>()?;
        let mut ids = Vec::new();
        for (i, root) in r.roots.iter().enumerate() {
            let mut cfg = base.clone();
            cfg["include"] = json!([format!("/{}", root.trim_matches('/'))]);
            let new_name = format!("{stem}-{}", i + 1);
            let nid = crate::resources::insert_share(&tx, &pk, &tenant, &kind, &new_name, cfg)
                .map_err(|e| ApiError::bad(format!("{new_name}: {}", e.1)))?;
            if r.copy_groups {
                for (gid, gname) in &groups {
                    let gname: String = format!("{}-{}", gname.chars().take(56).collect::<String>(), i + 1);
                    tx.execute(
                        &format!(
                            "INSERT INTO groups (source_id, name, {0}) SELECT ?1, ?2, {0} FROM groups WHERE id = ?3",
                            copy.join(", ")
                        ),
                        params![nid, gname, gid],
                    )
                    .map_err(|e| ApiError::conflict(format!("group {gname}: {e}")))?;
                }
            }
            ids.push(nid);
        }
        tx.commit()?;
        ids
    };
    st.audit(
        ctx.name(),
        "source.split",
        &format!("source/{id}"),
        json!({"tenant": tenant, "roots": r.roots, "sources": ids, "copy_groups": r.copy_groups}),
    )?;
    Ok((axum::http::StatusCode::CREATED, Json(json!({ "sources": ids }))).into_response())
}

/// CSV field; a leading `= + - @` is neutralised (formula injection from file names).
fn csv_field(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
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

/// The `error <path>: <reason>` lines of a backup log as CSV rows.
pub fn skipped_csv(log: &str, errors: Option<u64>) -> String {
    let mut out = String::from("path,reason,kind\r\n");
    let mut n = 0u64;
    for l in log.lines() {
        let Some(msg) = l.strip_prefix("error ") else { continue };
        let (kind, msg) = match msg.strip_prefix("note: ") {
            Some(m) => ("note", m),
            None => {
                n += 1;
                ("error", msg)
            }
        };
        let (path, why) = msg.split_once(": ").unwrap_or(("", msg));
        out.push_str(&format!("{},{},{kind}\r\n", csv_field(path), csv_field(why)));
    }
    if let Some(total) = errors.filter(|t| *t > n) {
        out.push_str(&format!(
            ",{} more not listed (the connector lists the first {n}; the job log may be truncated),error\r\n",
            total - n
        ));
    }
    out
}

/// `GET /jobs/{id}/skipped.csv`: the entries a share backup could not read.
pub async fn skipped(State(st): State<St>, ctx: Ctx, Path(id): Path<i64>) -> ApiResult<Response> {
    let (kind, log): (String, String) = st
        .cat
        .conn()
        .query_row(
            "SELECT kind, log FROM jobs WHERE id = ?1 AND (?2 IS NULL OR tenant = ?2)",
            params![id, ctx.scope()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or_else(ApiError::not_found)?;
    if kind != "backup" {
        return Err(ApiError::bad("skipped files: backup jobs only"));
    }
    // `…, <n> errors, …` of nexus-nas' committed line
    let errors = log.lines().find_map(|l| {
        let rest = l.strip_prefix("committed share-")?;
        let (a, _) = rest.split_once(" errors,")?;
        a.rsplit(' ').next()?.parse::<u64>().ok()
    });
    let mut res = skipped_csv(&log, errors).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"nexus-job-{id}-skipped.csv\""))
            .map_err(anyhow::Error::from)?,
    );
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_of_skipped_entries() {
        let log = "mounted …\nerror docs/a, b.txt: open: Permission denied (os error 13)\n\
                   error note: mnt/x: nested mount, not descended\nerror =cmd|calc: read: EIO\n\
                   committed share-3/9 in 1s: 10 entries, …, 0 inconsistent, 5 errors, 3 entries/s, live share\n";
        let csv = skipped_csv(log, Some(5));
        let lines: Vec<&str> = csv.split("\r\n").collect();
        assert_eq!(lines[0], "path,reason,kind");
        assert_eq!(
            lines[1],
            "\"docs/a, b.txt\",open: Permission denied (os error 13),error"
        );
        assert_eq!(lines[2], "mnt/x,\"nested mount, not descended\",note");
        assert_eq!(lines[3], "'=cmd|calc,read: EIO,error", "formula neutralised");
        assert!(lines[4].starts_with(",3 more not listed"));
        assert_eq!(skipped_csv("", None), "path,reason,kind\r\n");
    }

    #[test]
    fn overlap_and_sizing() {
        let mut rows = vec![
            json!({"id": 1, "tenant": "t", "name": "all", "kind": "smb", "config": {"host": "NAS", "share": "Data"}}),
            json!({"id": 2, "tenant": "t", "name": "proj", "kind": "smb", "config": {"host": "nas", "share": "data", "include": ["/projects"]}}),
            json!({"id": 3, "tenant": "t", "name": "other", "kind": "smb", "config": {"host": "nas", "share": "home"}}),
            json!({"id": 4, "tenant": "t", "name": "a", "kind": "nfs", "config": {"host": "n", "export": "/e", "include": ["/a"]}}),
            json!({"id": 5, "tenant": "t", "name": "ab", "kind": "nfs", "config": {"host": "n", "export": "/e", "include": ["/ab"]}}),
            json!({"id": 6, "tenant": "t", "name": "tn1", "kind": "truenas", "config": {"host": "tn", "datasets": ["tank/data"]}}),
            json!({"id": 7, "tenant": "t", "name": "tn2", "kind": "truenas", "config": {"host": "tn", "datasets": ["tank/data/sub"]}}),
        ];
        let cat = catalog::Catalog::open_memory().unwrap();
        let c = cat.conn();
        c.execute(
            "INSERT INTO jobs (kind, tenant, params, state, requested_by, created, result) VALUES
             ('backup','t','{}','ok','scheduler',1,'{\"snapshots\":[{\"source\":\"share-2\",\"time\":1,\"entries\":1200}]}'),
             ('backup','t','{}','ok','scheduler',2,'{\"snapshots\":[{\"source\":\"share-2\",\"time\":2,\"entries\":7000000}]}'),
             ('backup','t','{}','ok','scheduler',3,'{\"snapshots\":[{\"source\":\"nas-6-tank.data\",\"time\":3,\"entries\":10},{\"source\":\"nas-6-tank.data.x\",\"time\":3,\"entries\":20}]}')",
            [],
        )
        .unwrap();
        annotate(&c, &mut rows).unwrap();
        let ids = |r: &Value| -> Vec<i64> {
            r["overlaps"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| o["id"].as_i64().unwrap())
                .collect()
        };
        assert_eq!(
            ids(&rows[0]),
            vec![2],
            "same share (case-insensitive), whole share covers /projects"
        );
        assert_eq!(ids(&rows[2]), Vec::<i64>::new());
        assert_eq!(ids(&rows[3]), Vec::<i64>::new(), "/a and /ab do not overlap");
        assert_eq!(ids(&rows[5]), vec![7]);
        assert_eq!(rows[1]["sizing"]["entries"], 7_000_000, "newest run");
        assert_eq!(rows[1]["sizing"]["warn"], true);
        assert_eq!(rows[5]["sizing"]["entries"], 20, "largest dataset");
        assert!(rows[0]["sizing"].is_null());
        assert_eq!(sizing(1000, Some(1 << 30))["warn"], false);
        assert_eq!(sizing(1_000_000, Some(2 << 30))["warn"], true, "800 MB of 2 GiB");
    }
}
