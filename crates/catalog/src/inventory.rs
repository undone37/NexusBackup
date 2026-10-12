//! Guest inventory and auto-protect group resolution (v12, Phase 13c).
//!
//! The scheduler writes `inventory` from its `inventory` jobs (PVE
//! `/cluster/resources`, TrueNAS datasets, plugin `ListGuests`); the scheduler
//! (`groups()`, backup plans, retention) and the web-api (dashboard coverage) both
//! resolve a group's guests here, so they always agree on what a group protects.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::HashSet;

pub const MODES: &[&str] = &["explicit", "all", "tags"];
/// Tags per guest kept in the inventory.
pub const MAX_TAGS: usize = 64;
/// Guests with one of these tags are left out of `all` and `tags` groups unless the
/// group's selector names the tag: Microsoft 365 users without a license (usually
/// no mailbox or OneDrive) and team/group sites (backed up by their team or group
/// guest, so nothing is backed up twice).
pub const DEFAULT_OFF: &[&str] = &["license:none", "site:team"];

/// One listed guest.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Item {
    pub guest: String,
    pub name: String,
    pub kind: String,
    pub tags: Vec<String>,
}

/// Tags (`pool:x`, `tag:y`, `group:Sales Team`): 1..=128 bytes, no control
/// characters, no surrounding whitespace.
pub fn valid_tag(t: &str) -> bool {
    !t.is_empty() && t.len() <= 128 && t.trim() == t && !t.chars().any(char::is_control)
}

/// A guest id of `groups.guests` / `exclude` as inventory key (vmids are numbers there).
pub fn id_of(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        _ => None,
    }
}

fn strings(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<Value>>(json)
        .unwrap_or_default()
        .iter()
        .filter_map(id_of)
        .collect()
}

/// Whether a group with this mode takes its guests from the inventory.
pub fn auto(mode: &str) -> bool {
    mode == "all" || mode == "tags"
}

/// Guests of a group in the shape of `groups.guests` (vmids as numbers for `pve`
/// sources, strings otherwise): `explicit` → `guests`; `all` → the source's
/// present inventory guests; `tags` → those with any tag of `selector`; both
/// without guests carrying a [`DEFAULT_OFF`] tag the selector does not name.
/// `exclude` always wins. An unknown mode resolves to nothing (fail closed).
pub fn resolve(
    c: &Connection,
    source_id: i64,
    kind: &str,
    mode: &str,
    guests: &str,
    selector: &str,
    exclude: &str,
) -> rusqlite::Result<Vec<Value>> {
    let exclude: HashSet<String> = strings(exclude).into_iter().collect();
    if mode == "explicit" {
        let all: Vec<Value> = serde_json::from_str(guests).unwrap_or_default();
        return Ok(all
            .into_iter()
            .filter(|g| id_of(g).is_none_or(|id| !exclude.contains(&id)))
            .collect());
    }
    if !auto(mode) {
        return Ok(Vec::new());
    }
    let want: HashSet<String> = strings(selector).into_iter().collect();
    let rows: Vec<(String, String)> = c
        .prepare("SELECT guest, tags FROM inventory WHERE source_id = ?1 AND gone IS NULL ORDER BY guest")?
        .query_map([source_id], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut out: Vec<Value> = rows
        .into_iter()
        .filter(|(g, _)| !exclude.contains(g))
        .filter(|(_, tags)| {
            let tags = strings(tags);
            let off = tags
                .iter()
                .any(|t| DEFAULT_OFF.contains(&t.as_str()) && !want.contains(t));
            !off && (mode == "all" || tags.iter().any(|t| want.contains(t)))
        })
        .filter_map(|(g, _)| {
            if kind == "pve" {
                g.parse::<u32>().ok().map(Value::from)
            } else {
                Some(Value::from(g))
            }
        })
        .collect();
    if kind == "pve" {
        out.sort_by_key(|v| v.as_u64());
    }
    Ok(out)
}

/// Replaces the inventory of a source with `items` (listed at `now`): listed guests
/// are present again, the others get `gone = now` (rows are kept). Returns the
/// guests that are new or came back, and the ones that disappeared.
pub fn update(
    c: &Connection,
    source_id: i64,
    items: &[Item],
    now: i64,
) -> rusqlite::Result<(Vec<String>, Vec<String>)> {
    let tx = c.unchecked_transaction()?;
    let before: HashSet<String> = tx
        .prepare("SELECT guest FROM inventory WHERE source_id = ?1 AND gone IS NULL")?
        .query_map([source_id], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let listed: HashSet<&str> = items.iter().map(|i| i.guest.as_str()).collect();
    let mut added = Vec::new();
    for i in items {
        let tags: Vec<&String> = i.tags.iter().filter(|t| valid_tag(t)).take(MAX_TAGS).collect();
        tx.execute(
            "INSERT INTO inventory (source_id, guest, name, kind, tags, seen, gone) VALUES (?1,?2,?3,?4,?5,?6,NULL)
             ON CONFLICT(source_id, guest) DO UPDATE SET name = excluded.name, kind = excluded.kind,
               tags = excluded.tags, seen = excluded.seen, gone = NULL",
            params![source_id, i.guest, i.name, i.kind, json!(tags).to_string(), now],
        )?;
        if !before.contains(&i.guest) {
            added.push(i.guest.clone());
        }
    }
    let mut gone: Vec<String> = before.into_iter().filter(|g| !listed.contains(g.as_str())).collect();
    gone.sort();
    for g in &gone {
        tx.execute(
            "UPDATE inventory SET gone = ?3 WHERE source_id = ?1 AND guest = ?2",
            params![source_id, g, now],
        )?;
    }
    tx.commit()?;
    Ok((added, gone))
}

/// The inventory of a source for the API: present guests first, then gone ones.
pub fn list(c: &Connection, source_id: i64) -> rusqlite::Result<Vec<Value>> {
    c.prepare(
        "SELECT guest, name, kind, tags, seen, gone FROM inventory WHERE source_id = ?1
         ORDER BY gone IS NOT NULL, length(guest), guest",
    )?
    .query_map([source_id], |r| {
        let tags: String = r.get(3)?;
        Ok(
            json!({"guest": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
                  "tags": serde_json::from_str::<Value>(&tags).unwrap_or(json!([])),
                  "seen": r.get::<_, i64>(4)?, "gone": r.get::<_, Option<i64>>(5)?}),
        )
    })?
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    fn item(g: &str, tags: &[&str]) -> Item {
        Item {
            guest: g.into(),
            name: format!("guest {g}"),
            kind: "qemu".into(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
        }
    }

    fn setup() -> Catalog {
        let cat = Catalog::open_memory().unwrap();
        cat.conn()
            .execute_batch(
                "INSERT INTO tenants (name) VALUES ('t');
                 INSERT INTO sources (id, tenant, kind, name, config) VALUES (1,'t','pve','pve','{}'), (2,'t','plugin:m365','m','{}');",
            )
            .unwrap();
        cat
    }

    #[test]
    fn resolves_all_tags_and_exclude() {
        let cat = setup();
        let c = cat.conn();
        let items = [
            item("100", &["pool:prod", "tag:web"]),
            item("101", &["pool:prod"]),
            item("200", &["pool:test", "tag:web"]),
            item("1000", &[]),
        ];
        update(&c, 1, &items, 10).unwrap();
        let r = |mode: &str, sel: &str, ex: &str| resolve(&c, 1, "pve", mode, "[100]", sel, ex).unwrap();
        assert_eq!(
            r("all", "[]", "[]"),
            vec![json!(100), json!(101), json!(200), json!(1000)]
        );
        assert_eq!(r("all", "[]", r#"["101",200]"#), vec![json!(100), json!(1000)]);
        assert_eq!(r("tags", r#"["tag:web"]"#, "[]"), vec![json!(100), json!(200)]);
        assert_eq!(
            r("tags", r#"["pool:prod","tag:web"]"#, r#"["200"]"#),
            vec![json!(100), json!(101)]
        );
        assert_eq!(r("tags", "[]", "[]"), Vec::<Value>::new(), "no selector: nothing");
        assert_eq!(r("explicit", "[]", "[]"), vec![json!(100)]);
        assert_eq!(r("explicit", "[]", r#"["100"]"#), Vec::<Value>::new(), "exclude wins");
        assert_eq!(r("bogus", "[]", "[]"), Vec::<Value>::new());
        // plugin guests stay strings
        update(
            &c,
            2,
            &[
                item("user-a", &["type:user"]),
                item("site-b", &["type:site"]),
                item("user-c", &["type:user", "license:none"]),
                item("site-d", &["type:site", "site:team"]),
            ],
            10,
        )
        .unwrap();
        let m = |mode: &str, sel: &str| resolve(&c, 2, "plugin:m365", mode, "[]", sel, "[]").unwrap();
        assert_eq!(m("tags", r#"["type:user"]"#), vec![json!("user-a")]);
        // unlicensed users and team sites only when the selector names their tag
        assert_eq!(m("all", "[]"), vec![json!("site-b"), json!("user-a")]);
        assert_eq!(
            m("tags", r#"["type:user","license:none"]"#),
            vec![json!("user-a"), json!("user-c")]
        );
        assert_eq!(m("tags", r#"["site:team"]"#), vec![json!("site-d")]);
        assert_eq!(
            resolve(&c, 2, "plugin:m365", "explicit", r#"["user-c"]"#, "[]", "[]").unwrap(),
            vec![json!("user-c")],
            "explicit selection is taken as is"
        );
    }

    #[test]
    fn gone_guests_are_kept_and_return() {
        let cat = setup();
        let c = cat.conn();
        let (added, gone) = update(&c, 1, &[item("100", &[]), item("101", &[])], 10).unwrap();
        assert_eq!((added.len(), gone.len()), (2, 0));
        let (added, gone) = update(&c, 1, &[item("100", &["bad\ntag", "ok"])], 20).unwrap();
        assert_eq!((added, gone), (vec![], vec!["101".to_owned()]));
        assert_eq!(
            resolve(&c, 1, "pve", "all", "[]", "[]", "[]").unwrap(),
            vec![json!(100)]
        );
        let l = list(&c, 1).unwrap();
        assert_eq!(l[0]["tags"], json!(["ok"]), "invalid tags dropped");
        assert_eq!((l[1]["guest"].as_str(), l[1]["gone"].as_i64()), (Some("101"), Some(20)));
        let (added, gone) = update(&c, 1, &[item("100", &[]), item("101", &[])], 30).unwrap();
        assert_eq!((added, gone), (vec!["101".to_owned()], vec![]));
        assert!(list(&c, 1).unwrap().iter().all(|g| g["gone"].is_null()));
    }

    #[test]
    fn tags_syntax() {
        assert!(valid_tag("group:Sales Team"));
        assert!(!valid_tag(""));
        assert!(!valid_tag(" pool:x"));
        assert!(!valid_tag("a\u{7}"));
        assert!(!valid_tag(&"x".repeat(129)));
    }
}
