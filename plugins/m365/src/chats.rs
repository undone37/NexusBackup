//! 1:1 and group chats of a user (`chats` in the source config, off by default):
//!
//! ```text
//! u.<user>   chats/<topic or members> ~<hash>.json    chat + all its messages (Graph JSON)
//!            chats/<topic or members> ~<hash>.html    the same, readable (text only)
//! ```
//!
//! Read through the Teams export API `GET /users/{id}/chats/getAllMessages`, a
//! protected and metered Microsoft API: the app needs Chat.Read.All, Microsoft's
//! approval of the protected API request and, for `model=B`, an Azure billing
//! subscription on the app (the same `teams_export_model` as channel messages).
//! Download only: Graph cannot import chat messages into a chat.
//!
//! Incremental: the time of the last export is the version tag of the `chats`
//! directory (no state blob needed); the export filtered by `lastModifiedDateTime`
//! names the chats with changes, which are read again completely
//! (`GET /chats/{id}/messages`); every other chat is taken over from the base.

use super::{time_ns, xattr, Item, Run, X_ID, X_TAG};
use crate::format::{body_text, item_name, rfc3339};
use crate::graph::{self, enc};
use plugin_sdk::{error, BaseEntry, Kind, Meta, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

pub const CHATS_HELP: &str = "Microsoft has not enabled the protected Teams export API for this app: chats can \
only be exported after Microsoft approves the request (https://aka.ms/teamsgraph/requestaccess; see docs/m365.md) \
and, for the metered model B, an Azure subscription is linked to the app. Until then disable \"Chats\".";

/// Overlap of consecutive export windows (clock skew, late index updates).
const OVERLAP: i64 = 600;

/// Export API URL of a user's chats, optionally since a time.
pub fn export_url(c: &crate::Config, user: &str, since: Option<i64>, top: u32) -> String {
    let mut u = format!("/users/{}/chats/getAllMessages?$top={top}", enc(user));
    if let Some(m) = &c.teams_model {
        u.push_str(&format!("&model={}", enc(m)));
    }
    if let Some(s) = since {
        u.push_str(&format!(
            "&$filter={}",
            enc(&format!("lastModifiedDateTime gt {}", rfc3339(s)))
        ));
    }
    u
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn author(m: &Value) -> String {
    let f = &m["from"];
    f["user"]["displayName"]
        .as_str()
        .or(f["application"]["displayName"].as_str())
        .unwrap_or("(system)")
        .to_owned()
}

/// Readable chat (message bodies as text: no markup or remote content of the chat
/// ends up in a page the admin opens).
pub fn html(title: &str, members: &[String], msgs: &[Value]) -> String {
    let mut o = format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{t}</title>\n<style>body{{font:14px sans-serif;\
         max-width:50em;margin:2em auto}}.m{{margin:.6em 0}}.h{{color:#666;font-size:12px}}.b{{white-space:pre-wrap}}\
         .d{{color:#999;font-style:italic}}</style></head><body>\n<h1>{t}</h1>\n<p>{m}</p>\n",
        t = esc(title),
        m = esc(&members.join(", "))
    );
    for m in msgs {
        let when = m["createdDateTime"].as_str().unwrap_or_default();
        let body = if m["deletedDateTime"].is_null() {
            format!("<div class=\"b\">{}</div>", esc(&body_text(&m["body"])))
        } else {
            "<div class=\"d\">(deleted)</div>".to_owned()
        };
        o.push_str(&format!(
            "<div class=\"m\"><div class=\"h\">{} · {}</div>{body}</div>\n",
            esc(&author(m)),
            esc(when)
        ));
    }
    o.push_str("</body></html>\n");
    o
}

impl Run<'_, '_> {
    pub(super) fn chats(&mut self, u: &str, started: i64) -> Result<()> {
        let since = self
            .prev
            .by_path
            .get(b"chats".as_slice())
            .and_then(|&i| xattr(&self.prev.entries[i].meta, X_TAG))
            .and_then(|t| t.strip_prefix("since:"))
            .and_then(|t| t.parse::<i64>().ok())
            .map(|s| s - OVERLAP);
        self.out.used.insert(b"chats".to_vec());
        self.out.sink.entry(
            b"chats",
            Meta {
                kind: Some(Kind::Dir),
                mode: 0o40755,
                xattrs: super::xattrs("chats", Some(&format!("since:{started}"))),
                ..Default::default()
            },
        )?;
        // chat id → messages seen in the export
        let mut chats: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        let r = self.g.pages(&export_url(self.c, u, since, 50), &[], |m| {
            if let Some(c) = m["chatId"].as_str() {
                chats.entry(c.to_owned()).or_default().push(m);
            }
            Ok(())
        });
        if let Err(e) = r {
            if graph::is_protected_api_denied(&e) {
                return Err(error(13, CHATS_HELP));
            }
            return Err(e);
        }
        let mut written: HashSet<String> = HashSet::new();
        for (chat, mut msgs) in chats {
            if since.is_some() {
                // only the changed messages came back: read the whole chat
                msgs.clear();
                self.g
                    .pages(&format!("/chats/{}/messages?$top=50", enc(&chat)), &[], |m| {
                        msgs.push(m);
                        Ok(())
                    })?;
            }
            msgs.sort_by(|a, b| a["createdDateTime"].as_str().cmp(&b["createdDateTime"].as_str()));
            msgs.dedup_by(|a, b| a["id"] == b["id"]);
            // topic and members (Chat.ReadBasic.All); without them the authors name the chat
            let info = self
                .g
                .get(&format!("/chats/{}?$expand=members", enc(&chat)), &[])
                .unwrap_or(Value::Null);
            let mut members: Vec<String> = info["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|m| m["displayName"].as_str().map(str::to_owned))
                .collect();
            if members.is_empty() {
                members = msgs
                    .iter()
                    .filter(|m| m["from"]["user"].is_object())
                    .map(author)
                    .collect();
                members.sort();
                members.dedup();
            }
            let title = info["topic"]
                .as_str()
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| members.join(", "));
            let mtime = msgs
                .iter()
                .map(|m| time_ns(&m["lastModifiedDateTime"]).max(time_ns(&m["createdDateTime"])))
                .max()
                .unwrap_or(0);
            let tag = format!("{mtime}/{}", msgs.len());
            let doc = json!({"chat": {"id": chat, "topic": info["topic"], "chatType": info["chatType"],
                                      "members": members}, "messages": msgs});
            written.insert(chat.clone());
            for (ext, b) in [
                ("json", serde_json::to_vec_pretty(&doc)?),
                ("html", html(&title, &members, &msgs).into_bytes()),
            ] {
                let xid = format!("chat.{ext}:{chat}");
                let it = Item {
                    name: item_name(&title, &chat, ext),
                    tag: tag.clone(),
                    mtime_ns: mtime,
                };
                let path = self.out.claim(format!("chats/{}", it.name), &xid);
                if !self.out.unchanged(&self.prev, &path, &xid, &it, None)? {
                    self.out.bytes(&path, &xid, &it, &b)?;
                }
            }
        }
        if since.is_some() {
            // chats without changes since the last export: taken over from the base
            let keep: Vec<BaseEntry> = self
                .prev
                .entries
                .iter()
                .filter(|e| {
                    xattr(&e.meta, X_ID)
                        .and_then(|i| i.split_once(':'))
                        .is_some_and(|(k, c)| k.starts_with("chat.") && !written.contains(c))
                })
                .cloned()
                .collect();
            for b in keep {
                let xid = xattr(&b.meta, X_ID).unwrap_or_default().to_owned();
                let path = self.out.claim(String::from_utf8_lossy(&b.path).into_owned(), &xid);
                self.out
                    .unchanged(&self.prev, &path, &xid, &Item::from_base(&b), None)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_text_only() {
        let m = json!({"createdDateTime": "2026-10-01T10:00:00Z", "deletedDateTime": null,
            "from": {"user": {"displayName": "Eve <script>"}},
            "body": {"contentType": "html", "content": "<p>hi <img src=\"https://x/y.png\"> &amp; bye</p>"}});
        let h = html("Lunch", &["Alice".into()], &[m]);
        assert!(
            h.contains("Eve &lt;script&gt;") && !h.contains("<img") && !h.contains("<script"),
            "{h}"
        );
        assert!(h.contains("hi") && h.contains("bye"));
    }
}
