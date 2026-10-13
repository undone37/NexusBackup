//! Pure helpers: snapshot names, timestamps, and the download formats generated
//! from Graph JSON (iCalendar for events, vCard for contacts). Both carry the Graph
//! representation in an `X-NEXUSBACKUP-GRAPH` property (base64 JSON), which other
//! clients ignore and the plugin's restores use, so restores are lossless.

use base64::Engine;
use serde_json::Value;

/// Property carrying the Graph JSON in generated `.ics` / `.vcf` files.
pub const GRAPH_PROP: &str = "X-NEXUSBACKUP-GRAPH";

/// One path component from a display name: `%`, `/`, control characters and the
/// names `.`/`..` are percent-encoded (reversible with [`decode_name`]); empty
/// names become `%00`. Bounded to 200 bytes (on a character boundary).
pub fn encode_name(name: &str) -> String {
    if name.is_empty() {
        return "%00".into();
    }
    if name == "." || name == ".." {
        return name.replace('.', "%2E");
    }
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            '%' | '/' => out.push_str(&format!("%{:02X}", c as u32)),
            c if c.is_ascii_control() => out.push_str(&format!("%{:02X}", c as u32)),
            c if c.is_control() => {}
            c => out.push(c),
        }
        if out.len() >= 200 {
            break;
        }
    }
    out
}

/// Inverse of [`encode_name`] (invalid escapes are kept literally).
pub fn decode_name(s: &str) -> String {
    if s == "%00" {
        return String::new();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
            let v = u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap_or(b'%');
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Short stable hash of an item id (file names stay unique and recognisable).
pub fn short_hash(id: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, id.as_bytes());
    d.as_ref()[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// A readable file name for an item: `<label> ~<hash>.<ext>` (label sanitised and
/// shortened; the hash of the id keeps names unique within their folder).
pub fn item_name(label: &str, id: &str, ext: &str) -> String {
    let mut l: String = label
        .chars()
        .map(|c| if c.is_control() || c == '/' || c == '%' { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if l.chars().count() > 80 {
        l = l.chars().take(80).collect::<String>().trim_end().to_owned();
    }
    let l = l.trim_start_matches('.');
    if l.is_empty() {
        format!("~{}.{ext}", short_hash(id))
    } else {
        format!("{l} ~{}.{ext}", short_hash(id))
    }
}

/// `2026-10-11T12:34:56.1234567Z` / `…+02:00` / `2026-10-11T12:34:56` (UTC) → ns since the epoch.
pub fn parse_time(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da): (i64, i64, i64) = (
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
        d.next()?.parse().ok()?,
    );
    let (clock, offset) = match rest.find(['Z', 'z', '+', '-']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut t = hms.split(':');
    let (h, mi): (i64, i64) = (t.next()?.parse().ok()?, t.next()?.parse().ok()?);
    let sec: i64 = t.next().map_or(Some(0), |x| x.parse().ok())?;
    let mut ns: i64 = 0;
    for (i, c) in frac.chars().take(9).enumerate() {
        ns += c.to_digit(10)? as i64 * 10i64.pow(8 - i as u32);
    }
    let off = match offset {
        "" | "Z" | "z" => 0,
        o => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let (oh, om) = o[1..]
                .split_once(':')
                .unwrap_or((&o[1..o.len().min(3)], o.get(3..).unwrap_or("0")));
            sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().unwrap_or(0) * 60)
        }
    };
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let secs = days_from_civil(y, mo, da) * 86400 + h * 3600 + mi * 60 + sec - off;
    secs.checked_mul(1_000_000_000)?.checked_add(ns)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Seconds since the epoch → (year, month, day, hour, minute, second), UTC.
pub fn civil(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// RFC 3339 UTC (`2026-10-11T12:34:56Z`), as Graph filters expect.
pub fn rfc3339(secs: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// `2026-10-11 1234` (names of restore folders and thread files).
pub fn short_stamp(secs: i64) -> String {
    let (y, mo, d, h, mi, _) = civil(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}{mi:02}")
}

/// iCalendar date-time (UTC) of a Graph `dateTimeTimeZone` (the plugin asks for UTC).
fn ics_time(v: &Value) -> Option<String> {
    let ns = parse_time(v["dateTime"].as_str()?)?;
    let (y, mo, d, h, mi, s) = civil(ns.div_euclid(1_000_000_000));
    Some(format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"))
}

fn ics_date(v: &Value) -> Option<String> {
    let dt = v["dateTime"].as_str()?;
    Some(dt.get(..10)?.replace('-', ""))
}

/// Escapes a TEXT value (RFC 5545 §3.3.11 / RFC 6350 §3.4).
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            ';' => o.push_str("\\;"),
            ',' => o.push_str("\\,"),
            '\n' => o.push_str("\\n"),
            '\r' => {}
            c => o.push(c),
        }
    }
    o
}

/// Folds a content line at 75 octets (on character boundaries), CRLF-terminated.
fn line(out: &mut String, l: &str) {
    let mut n = 0;
    for c in l.chars() {
        if n + c.len_utf8() > 75 {
            out.push_str("\r\n ");
            n = 1;
        }
        out.push(c);
        n += c.len_utf8();
    }
    out.push_str("\r\n");
}

fn graph_line(out: &mut String, v: &Value) {
    let b = base64::engine::general_purpose::STANDARD.encode(v.to_string());
    line(out, &format!("{GRAPH_PROP}:{b}"));
}

/// Body text of a Graph `itemBody` (HTML reduced to text for DESCRIPTION / NOTE).
pub fn body_text(body: &Value) -> String {
    let c = body["content"].as_str().unwrap_or_default();
    if body["contentType"]
        .as_str()
        .is_some_and(|t| t.eq_ignore_ascii_case("html"))
    {
        strip_html(c)
    } else {
        c.to_owned()
    }
}

/// Crude HTML → text (tags dropped, a few entities, whitespace collapsed per line).
pub fn strip_html(h: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    let mut tagname = String::new();
    for c in h.chars() {
        match c {
            '<' => {
                tag = true;
                tagname.clear();
            }
            '>' if tag => {
                tag = false;
                let t = tagname.trim_start_matches('/').to_ascii_lowercase();
                if ["br", "p", "div", "li", "tr"].contains(&t.as_str()) {
                    out.push('\n');
                }
            }
            c if tag => {
                if !c.is_whitespace() && tagname.len() < 8 {
                    tagname.push(c);
                } else {
                    tagname.push_str("        ");
                }
            }
            c => out.push(c),
        }
    }
    let out = out
        .replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&");
    out.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// RRULE of a Graph `patternedRecurrence` (common patterns; None if not expressible).
fn rrule(r: &Value) -> Option<String> {
    let p = &r["pattern"];
    let range = &r["range"];
    let days = |v: &Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(|d| d.as_str())
            .map(|d| d.get(..2).unwrap_or(d).to_ascii_uppercase())
            .collect()
    };
    let idx = match p["index"].as_str().unwrap_or("first") {
        "second" => "2",
        "third" => "3",
        "fourth" => "4",
        "last" => "-1",
        _ => "1",
    };
    let mut rule = match p["type"].as_str()? {
        "daily" => "FREQ=DAILY".to_owned(),
        "weekly" => format!("FREQ=WEEKLY;BYDAY={}", days(&p["daysOfWeek"]).join(",")),
        "absoluteMonthly" => format!("FREQ=MONTHLY;BYMONTHDAY={}", p["dayOfMonth"].as_u64()?),
        "relativeMonthly" => format!("FREQ=MONTHLY;BYDAY={};BYSETPOS={idx}", days(&p["daysOfWeek"]).join(",")),
        "absoluteYearly" => format!(
            "FREQ=YEARLY;BYMONTH={};BYMONTHDAY={}",
            p["month"].as_u64()?,
            p["dayOfMonth"].as_u64()?
        ),
        "relativeYearly" => format!(
            "FREQ=YEARLY;BYMONTH={};BYDAY={};BYSETPOS={idx}",
            p["month"].as_u64()?,
            days(&p["daysOfWeek"]).join(",")
        ),
        _ => return None,
    };
    if let Some(i) = p["interval"].as_u64().filter(|i| *i > 1) {
        rule.push_str(&format!(";INTERVAL={i}"));
    }
    match range["type"].as_str() {
        Some("endDate") => rule.push_str(&format!(";UNTIL={}", range["endDate"].as_str()?.replace('-', ""))),
        Some("numbered") => rule.push_str(&format!(";COUNT={}", range["numberOfOccurrences"].as_u64()?)),
        _ => {}
    }
    Some(rule)
}

/// An `.ics` (VCALENDAR with one VEVENT) of a Graph event (times in UTC).
pub fn event_ics(e: &Value) -> String {
    let mut o = String::new();
    line(&mut o, "BEGIN:VCALENDAR");
    line(&mut o, "VERSION:2.0");
    line(&mut o, "PRODID:-//NexusBackup//M365 plugin//EN");
    line(&mut o, "BEGIN:VEVENT");
    let uid = e["iCalUId"].as_str().or(e["id"].as_str()).unwrap_or_default();
    line(&mut o, &format!("UID:{}", esc(uid)));
    if let Some(t) = e["lastModifiedDateTime"].as_str().and_then(parse_time) {
        let (y, mo, d, h, mi, s) = civil(t.div_euclid(1_000_000_000));
        line(&mut o, &format!("DTSTAMP:{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z"));
    }
    if e["isAllDay"].as_bool() == Some(true) {
        if let Some(d) = ics_date(&e["start"]) {
            line(&mut o, &format!("DTSTART;VALUE=DATE:{d}"));
        }
        if let Some(d) = ics_date(&e["end"]) {
            line(&mut o, &format!("DTEND;VALUE=DATE:{d}"));
        }
    } else {
        if let Some(t) = ics_time(&e["start"]) {
            line(&mut o, &format!("DTSTART:{t}"));
        }
        if let Some(t) = ics_time(&e["end"]) {
            line(&mut o, &format!("DTEND:{t}"));
        }
    }
    if let Some(r) = e.get("recurrence").filter(|r| r.is_object()).and_then(rrule) {
        line(&mut o, &format!("RRULE:{r}"));
    }
    line(
        &mut o,
        &format!("SUMMARY:{}", esc(e["subject"].as_str().unwrap_or_default())),
    );
    if let Some(l) = e["location"]["displayName"].as_str().filter(|l| !l.is_empty()) {
        line(&mut o, &format!("LOCATION:{}", esc(l)));
    }
    let body = body_text(&e["body"]);
    if !body.is_empty() {
        line(&mut o, &format!("DESCRIPTION:{}", esc(&body)));
    }
    if let Some(a) = e["organizer"]["emailAddress"]["address"].as_str() {
        let n = e["organizer"]["emailAddress"]["name"].as_str().unwrap_or(a);
        line(&mut o, &format!("ORGANIZER;CN=\"{}\":mailto:{a}", n.replace('"', "'")));
    }
    for at in e["attendees"].as_array().into_iter().flatten() {
        if let Some(a) = at["emailAddress"]["address"].as_str() {
            let n = at["emailAddress"]["name"].as_str().unwrap_or(a);
            let role = if at["type"] == "optional" {
                "OPT-PARTICIPANT"
            } else {
                "REQ-PARTICIPANT"
            };
            line(
                &mut o,
                &format!("ATTENDEE;CN=\"{}\";ROLE={role}:mailto:{a}", n.replace('"', "'")),
            );
        }
    }
    if let Some(c) = e["categories"].as_array().filter(|c| !c.is_empty()) {
        let c: Vec<String> = c.iter().filter_map(|x| x.as_str()).map(esc).collect();
        line(&mut o, &format!("CATEGORIES:{}", c.join(",")));
    }
    let class = match e["sensitivity"].as_str() {
        Some("private") | Some("confidential") => "PRIVATE",
        _ => "PUBLIC",
    };
    line(&mut o, &format!("CLASS:{class}"));
    if e["showAs"] == "free" {
        line(&mut o, "TRANSP:TRANSPARENT");
    }
    graph_line(&mut o, e);
    line(&mut o, "END:VEVENT");
    line(&mut o, "END:VCALENDAR");
    o
}

/// A vCard 3.0 of a Graph contact.
pub fn contact_vcf(c: &Value) -> String {
    let s = |k: &str| c[k].as_str().unwrap_or_default();
    let mut o = String::new();
    line(&mut o, "BEGIN:VCARD");
    line(&mut o, "VERSION:3.0");
    let fn_ = if s("displayName").is_empty() {
        format!("{} {}", s("givenName"), s("surname")).trim().to_owned()
    } else {
        s("displayName").to_owned()
    };
    line(&mut o, &format!("FN:{}", esc(&fn_)));
    line(
        &mut o,
        &format!(
            "N:{};{};{};{};{}",
            esc(s("surname")),
            esc(s("givenName")),
            esc(s("middleName")),
            esc(s("title")),
            esc(s("generation"))
        ),
    );
    if !s("nickName").is_empty() {
        line(&mut o, &format!("NICKNAME:{}", esc(s("nickName"))));
    }
    for e in c["emailAddresses"].as_array().into_iter().flatten() {
        if let Some(a) = e["address"].as_str() {
            line(&mut o, &format!("EMAIL;TYPE=INTERNET:{}", esc(a)));
        }
    }
    for (k, t) in [("businessPhones", "WORK"), ("homePhones", "HOME")] {
        for p in c[k].as_array().into_iter().flatten().filter_map(|p| p.as_str()) {
            line(&mut o, &format!("TEL;TYPE={t},VOICE:{}", esc(p)));
        }
    }
    if !s("mobilePhone").is_empty() {
        line(&mut o, &format!("TEL;TYPE=CELL:{}", esc(s("mobilePhone"))));
    }
    if !s("companyName").is_empty() || !s("department").is_empty() {
        line(
            &mut o,
            &format!("ORG:{};{}", esc(s("companyName")), esc(s("department"))),
        );
    }
    if !s("jobTitle").is_empty() {
        line(&mut o, &format!("TITLE:{}", esc(s("jobTitle"))));
    }
    for (k, t) in [
        ("businessAddress", "WORK"),
        ("homeAddress", "HOME"),
        ("otherAddress", "OTHER"),
    ] {
        let a = &c[k];
        if a.as_object()
            .is_some_and(|m| m.values().any(|v| v.as_str().is_some_and(|x| !x.is_empty())))
        {
            let f = |x: &str| esc(a[x].as_str().unwrap_or_default());
            line(
                &mut o,
                &format!(
                    "ADR;TYPE={t}:;;{};{};{};{};{}",
                    f("street"),
                    f("city"),
                    f("state"),
                    f("postalCode"),
                    f("countryOrRegion")
                ),
            );
        }
    }
    if let Some(b) = c["birthday"].as_str().and_then(|b| b.get(..10)) {
        line(&mut o, &format!("BDAY:{b}"));
    }
    if !s("personalNotes").is_empty() {
        line(&mut o, &format!("NOTE:{}", esc(s("personalNotes"))));
    }
    graph_line(&mut o, c);
    line(&mut o, "END:VCARD");
    o
}

/// The Graph JSON embedded in a generated `.ics` / `.vcf` (unfolds content lines).
pub fn embedded_graph(text: &str) -> Option<Value> {
    let unfolded = text.replace("\r\n ", "").replace("\n ", "");
    let v = unfolded
        .lines()
        .find_map(|l| l.strip_prefix(GRAPH_PROP).and_then(|r| r.strip_prefix(':')))?;
    let raw = base64::engine::general_purpose::STANDARD.decode(v.trim()).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Graph JSON of a backed-up item without the server-managed properties, ready to
/// be created again (events additionally lose their attendees: no invitations are
/// sent by a restore; the attendee list stays in the backup's `.ics`).
pub fn for_create(mut v: Value, event: bool) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.retain(|k, _| !k.starts_with('@') && !k.contains("@odata"));
        for k in [
            "id",
            "changeKey",
            "createdDateTime",
            "lastModifiedDateTime",
            "parentFolderId",
            "iCalUId",
            "uid",
            "webLink",
            "seriesMasterId",
            "type",
            "occurrenceId",
            "originalStart",
            "originalStartTimeZone",
            "originalEndTimeZone",
            "responseStatus",
            "isOrganizer",
            "organizer",
            "onlineMeeting",
            "onlineMeetingUrl",
            "isOnlineMeeting",
            "onlineMeetingProvider",
            "hasAttachments",
            "bodyPreview",
            "isDraft",
            "cancelledOccurrences",
            "exceptionOccurrences",
            "transactionId",
            "allowNewTimeProposals",
            "isCancelled",
            "photo",
            "flag",
        ] {
            o.remove(k);
        }
        if event {
            o.remove("attendees");
            o.insert("isReminderOn".into(), Value::Bool(false));
        }
        o.retain(|_, v| !v.is_null());
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names_roundtrip() {
        for n in ["Inbox", "a/b", "100%", ".", "..", "", "x\ny", "Ä ö 𠀋", "%2F"] {
            let e = encode_name(n);
            assert!(plugin_sdk::proto::valid_path(e.as_bytes()), "{n:?} → {e:?}");
            assert!(!e.contains('/'));
            if !n.contains('\n') {
                assert_eq!(decode_name(&e), n, "{n:?}");
            }
        }
        assert_eq!(encode_name("a/b"), "a%2Fb");
        let n = item_name("  Re: hello/world  ", "AAMk=", "eml");
        assert!(n.starts_with("Re: hello world ~") && n.ends_with(".eml"), "{n}");
        assert_eq!(item_name("", "x", "ics"), format!("~{}.ics", short_hash("x")));
        assert_eq!(item_name("...", "x", "ics"), format!("~{}.ics", short_hash("x")));
        assert!(item_name(&"x".repeat(500), "id", "eml").len() < 100);
    }

    #[test]
    fn times() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_time("2026-10-11T12:34:56Z"), Some(1_791_722_096_000_000_000));
        assert_eq!(
            parse_time("2026-10-11T14:34:56+02:00"),
            parse_time("2026-10-11T12:34:56Z")
        );
        assert_eq!(parse_time("2026-10-11T12:34:56.5Z"), Some(1_791_722_096_500_000_000));
        assert_eq!(
            parse_time("2026-10-11T12:34:56.1234567"),
            Some(1_791_722_096_123_456_700)
        );
        assert_eq!(parse_time("garbage"), None);
        assert_eq!(rfc3339(1_791_722_096), "2026-10-11T12:34:56Z");
        assert_eq!(short_stamp(1_791_722_096), "2026-10-11 1234");
        for s in [0i64, 951_782_400, 4_102_444_800, -86_400] {
            assert_eq!(parse_time(&rfc3339(s)), Some(s * 1_000_000_000));
        }
    }

    #[test]
    fn ics_and_vcf() {
        let e = json!({"id": "AAMk1", "iCalUId": "uid-1", "subject": "Planning; Q4, all",
            "lastModifiedDateTime": "2026-10-01T08:00:00Z",
            "start": {"dateTime": "2026-10-12T09:00:00.0000000", "timeZone": "UTC"},
            "end": {"dateTime": "2026-10-12T10:00:00.0000000", "timeZone": "UTC"},
            "body": {"contentType": "html", "content": "<p>Agenda</p><p>1 &amp; 2</p>"},
            "location": {"displayName": "Room 1"},
            "recurrence": {"pattern": {"type": "weekly", "interval": 2, "daysOfWeek": ["monday", "friday"]},
                           "range": {"type": "numbered", "numberOfOccurrences": 10}},
            "attendees": [{"type": "required", "emailAddress": {"name": "Bob", "address": "bob@contoso.test"}}],
            "organizer": {"emailAddress": {"name": "Alice", "address": "alice@contoso.test"}}});
        let ics = event_ics(&e);
        assert!(ics.contains("SUMMARY:Planning\\; Q4\\, all\r\n"), "{ics}");
        assert!(ics.contains("DTSTART:20261012T090000Z\r\n"));
        assert!(ics.contains("RRULE:FREQ=WEEKLY;BYDAY=MO,FR;INTERVAL=2;COUNT=10\r\n"));
        assert!(ics.contains("DESCRIPTION:Agenda\\n1 & 2\r\n"));
        assert!(ics.lines().all(|l| l.len() <= 76), "folded");
        assert_eq!(embedded_graph(&ics).unwrap(), e);
        let c = for_create(embedded_graph(&ics).unwrap(), true);
        assert!(c.get("id").is_none() && c.get("attendees").is_none() && c.get("organizer").is_none());
        assert_eq!(c["subject"], e["subject"]);

        let p = json!({"id": "c1", "displayName": "Bob Builder", "givenName": "Bob", "surname": "Builder",
            "emailAddresses": [{"address": "bob@contoso.test"}], "mobilePhone": "+49 1", "birthday": "1980-02-03T11:59:00Z",
            "businessAddress": {"street": "Main 1", "city": "Town"}});
        let v = contact_vcf(&p);
        assert!(
            v.contains("FN:Bob Builder\r\n") && v.contains("N:Builder;Bob;;;\r\n"),
            "{v}"
        );
        assert!(v.contains("EMAIL;TYPE=INTERNET:bob@contoso.test") && v.contains("BDAY:1980-02-03"));
        assert!(v.contains("ADR;TYPE=WORK:;;Main 1;Town;;;\r\n"));
        assert_eq!(embedded_graph(&v).unwrap(), p);
        assert_eq!(strip_html("<div>a<br>b &lt;c&gt;</div>"), "a\nb <c>");
    }
}
