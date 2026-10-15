//! Mail conversions for the export (contract v1.9 `download` with conversion):
//! RFC 4155 mbox ("mboxrd" quoting, LF line endings) and `.eml` (MIME) → PST message
//! properties ([`to_pst`]).

use crate::pst::ltp::Val;
use crate::pst::Message;
use mail_parser::{Address, MessageParser, MimeHeaders};
use std::io::{self, Write};

/// Seconds since 1970 → FILETIME (100 ns since 1601).
pub fn filetime(unix: i64) -> u64 {
    ((unix + 11_644_473_600).max(0) as u64) * 10_000_000
}

/// asctime() of a UNIX time in UTC ("Thu Jan  1 00:00:00 1970").
fn asctime(t: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, secs) = (t.div_euclid(86400), t.rem_euclid(86400));
    // civil from days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} {}",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[(m - 1) as usize],
        d,
        secs / 3600,
        secs / 60 % 60,
        secs % 60,
        y
    )
}

/// The envelope line of a message: `From <sender> <asctime date>`.
pub fn from_line(eml: &[u8]) -> String {
    let parsed = MessageParser::default().parse_headers(eml);
    let sender = parsed
        .as_ref()
        .and_then(|m| {
            m.return_address()
                .map(str::to_owned)
                .or_else(|| first_address(m.from()))
        })
        .filter(|a| !a.is_empty() && !a.contains(char::is_whitespace))
        .unwrap_or_else(|| "MAILER-DAEMON".into());
    let date = parsed
        .as_ref()
        .and_then(|m| m.date())
        .map_or(0, mail_parser::DateTime::to_timestamp);
    format!("From {sender} {}", asctime(date))
}

fn first_address(a: Option<&Address>) -> Option<String> {
    a?.iter().find_map(|x| x.address().map(str::to_owned))
}

/// Appends one message to an mbox: the `From ` line, the message with CRLF → LF and
/// `>*From ` lines quoted with one more `>` (mboxrd), a final newline and a blank line.
pub fn mbox_append(out: &mut impl Write, eml: &[u8]) -> io::Result<()> {
    writeln!(out, "{}", from_line(eml))?;
    let mut lines = eml.split(|&b| b == b'\n').peekable();
    while let Some(line) = lines.next() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if lines.peek().is_none() && line.is_empty() {
            break; // the message's own final newline
        }
        let quoted = line
            .iter()
            .position(|&b| b != b'>')
            .is_some_and(|i| line[i..].starts_with(b"From "));
        if quoted {
            out.write_all(b">")?;
        }
        out.write_all(line)?;
        out.write_all(b"\n")?;
    }
    out.write_all(b"\n")
}

/// Splits an mboxrd mailbox back into messages (LF line endings), unquoting `>From `.
pub fn mbox_split(mbox: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Option<Vec<u8>> = None;
    for line in mbox.split_inclusive(|&b| b == b'\n') {
        if line.starts_with(b"From ") {
            if let Some(m) = cur.take() {
                out.push(m);
            }
            cur = Some(Vec::new());
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let unq = line
            .iter()
            .position(|&b| b != b'>')
            .is_some_and(|i| i > 0 && line[i..].starts_with(b"From "));
        m.extend_from_slice(if unq { &line[1..] } else { line });
    }
    out.extend(cur);
    for m in &mut out {
        // the separating blank line
        if m.ends_with(b"\n\n") {
            m.pop();
        }
    }
    out
}

fn s(v: impl Into<String>) -> Val {
    Val::Str(v.into())
}

/// Display text of an address list ("Name; other@example.com").
fn display(a: Option<&Address>) -> String {
    a.map(|a| {
        a.iter()
            .map(|x| {
                x.name()
                    .filter(|n| !n.is_empty())
                    .or(x.address())
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("; ")
    })
    .unwrap_or_default()
}

/// A MAPI one-off EntryID ([MS-OXCDATA] 2.2.5.1) for an SMTP recipient.
fn one_off(name: &str, addr: &str) -> Vec<u8> {
    let mut b = vec![0u8; 4];
    b.extend_from_slice(&[
        0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02,
    ]);
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0x8190u16.to_le_bytes()); // Unicode, no rich text, don't look up
    for part in [name, "SMTP", addr] {
        b.extend(part.encode_utf16().flat_map(u16::to_le_bytes));
        b.extend_from_slice(&[0, 0]);
    }
    b
}

fn ext_of(mime: &str) -> &'static str {
    match mime {
        "message/rfc822" => "eml",
        "text/plain" => "txt",
        "text/html" => "html",
        "text/calendar" => "ics",
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "application/pdf" => "pdf",
        _ => "bin",
    }
}

/// `.eml` → the properties, recipients and attachments of an `IPM.Note`.
/// A message that cannot be parsed keeps its raw bytes as `message.eml`.
pub fn to_pst(eml: &[u8]) -> Message {
    let key = ring::digest::digest(&ring::digest::SHA256, eml);
    let mut props: Vec<(u16, Val)> = vec![
        (0x001A, s("IPM.Note")),
        (0x0E08, Val::I32(eml.len().min(i32::MAX as usize) as i32)),
        (0x0E17, Val::I32(0)),
        (0x300B, Val::Bin(key.as_ref()[..16].to_vec())),
        (0x3FDE, Val::I32(65001)), // PidTagInternetCodepage: the HTML body is UTF-8
    ];
    let Some(m) = MessageParser::default().parse(eml) else {
        props.extend([(0x0037, s("(message could not be parsed)")), (0x0E07, Val::I32(0x11))]);
        return Message {
            props,
            recipients: Vec::new(),
            attachments: vec![attachment(1, "message.eml", "message/rfc822", eml.to_vec(), None)],
        };
    };
    let subject = m.subject().unwrap_or_default().to_owned();
    props.push((0x0037, s(subject.clone())));
    props.push((0x0070, s(m.thread_name().unwrap_or(&subject).to_owned())));
    let sent = m.date().map(mail_parser::DateTime::to_timestamp);
    let received = m
        .received()
        .and_then(|r| r.date.as_ref())
        .map(mail_parser::DateTime::to_timestamp)
        .or(sent);
    if let Some(t) = sent {
        props.push((0x0039, Val::Time(filetime(t))));
    }
    if let Some(t) = received {
        for id in [0x0E06, 0x3007, 0x3008] {
            props.push((id, Val::Time(filetime(t))));
        }
    }
    let from = m.from().and_then(|a| a.first());
    let sender = m.sender().and_then(|a| a.first()).or(from);
    for (addr, name_id, type_id, mail_id, smtp_id, eid_id) in [
        (from, 0x0042, 0x0064, 0x0065, 0x5D02, 0x0041),
        (sender, 0x0C1A, 0x0C1E, 0x0C1F, 0x5D01, 0x0C19),
    ] {
        let Some(a) = addr else { continue };
        let mail = a.address().unwrap_or_default();
        let name = a.name().filter(|n| !n.is_empty()).unwrap_or(mail);
        props.extend([
            (name_id, s(name)),
            (type_id, s("SMTP")),
            (mail_id, s(mail)),
            (smtp_id, s(mail)),
            (eid_id, Val::Bin(one_off(name, mail))),
        ]);
    }
    props.push((0x0E04, s(display(m.to()))));
    props.push((0x0E03, s(display(m.cc()))));
    props.push((0x0E02, s(display(m.bcc()))));
    let importance = match (
        m.header_raw("Importance").map(|v| v.trim().to_ascii_lowercase()),
        m.header_raw("X-Priority").and_then(|v| v.trim().chars().next()),
    ) {
        (Some(v), _) if v == "high" => 2,
        (Some(v), _) if v == "low" => 0,
        (_, Some('1' | '2')) => 2,
        (_, Some('4' | '5')) => 0,
        _ => 1,
    };
    props.push((0x0017, Val::I32(importance)));
    props.push((0x0036, Val::I32(0)));
    if let Some(id) = m.message_id() {
        props.push((0x1035, s(format!("<{id}>"))));
    }
    if let Some(v) = m.header_raw("In-Reply-To") {
        props.push((0x1042, s(v.trim())));
    }
    if let Some(v) = m.header_raw("References") {
        props.push((0x1039, s(v.split_whitespace().collect::<Vec<_>>().join(" "))));
    }
    let root = m.root_part();
    let headers = &eml[root.offset_header as usize..(root.offset_body as usize).min(eml.len())];
    props.push((0x007D, s(String::from_utf8_lossy(headers).into_owned())));
    if let Some(t) = m.body_text(0) {
        props.push((0x1000, s(t.into_owned())));
    }
    let html: Option<Vec<u8>> = m
        .html_body
        .iter()
        .filter_map(|i| m.part(*i))
        .find(|p| p.is_text_html())
        .map(|p| p.contents().to_vec());
    let cids = html
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(h) = html {
        props.push((0x1013, Val::Bin(h)));
    }
    let mut recipients = Vec::new();
    for (kind, list) in [(1, m.to()), (2, m.cc()), (3, m.bcc())] {
        for a in list.into_iter().flat_map(|l| l.iter()) {
            let mail = a.address().unwrap_or_default();
            let name = a.name().filter(|n| !n.is_empty()).unwrap_or(mail);
            recipients.push(vec![
                (0x0C15, Val::I32(kind)),
                (0x3001, s(name)),
                (0x3002, s("SMTP")),
                (0x3003, s(mail)),
                (0x39FE, s(mail)),
                (0x39FF, s(name)),
                (0x0FFE, Val::I32(6)), // MAPI_MAILUSER
                (0x3900, Val::I32(0)), // DT_MAILUSER
                (0x0E0F, Val::Bool(false)),
                (0x3A40, Val::Bool(false)),
                (0x5FFD, Val::I32(1)),
                (0x0FFF, Val::Bin(one_off(name, mail))),
                (
                    0x300B,
                    Val::Bin(format!("SMTP:{}\0", mail.to_ascii_uppercase()).into_bytes()),
                ),
            ]);
        }
    }
    let mut attachments = Vec::new();
    for (i, p) in m.attachments().enumerate() {
        let mime = p
            .content_type()
            .map(|c| format!("{}/{}", c.ctype(), c.subtype().unwrap_or("octet-stream")).to_ascii_lowercase())
            .unwrap_or_else(|| "application/octet-stream".into());
        let name = match (p.attachment_name(), p.message()) {
            (Some(n), _) if !n.trim().is_empty() => n.trim().to_owned(),
            (_, Some(inner)) => format!("{}.eml", inner.subject().unwrap_or("message").trim()),
            _ => format!("attachment-{}.{}", i + 1, ext_of(&mime)),
        };
        let cid = p
            .content_id()
            .map(|c| c.trim_matches(['<', '>']).to_owned())
            .filter(|c| !c.is_empty() && cids.contains(&format!("cid:{}", c.to_ascii_lowercase())));
        attachments.push(attachment(i, &name, &mime, p.contents().to_vec(), cid));
    }
    let flags = 0x01 | if attachments.is_empty() { 0 } else { 0x10 }; // read, has attachments
    props.push((0x0E07, Val::I32(flags)));
    props.push((0x0E1B, Val::Bool(!attachments.is_empty())));
    Message {
        props,
        recipients,
        attachments,
    }
}

/// Properties of a by-value attachment (inline images: content id, hidden).
fn attachment(i: usize, name: &str, mime: &str, data: Vec<u8>, cid: Option<String>) -> Vec<(u16, Val)> {
    let mut a = vec![
        (0x0E20, Val::I32(data.len().min(i32::MAX as usize) as i32)),
        (0x3001, s(name)),
        (0x3704, s(name)),
        (0x3707, s(name)),
        (0x3705, Val::I32(1)), // ATTACH_BY_VALUE
        (0x370B, Val::I32(-1)),
        (0x370E, s(mime)),
        (0x0E21, Val::I32(i as i32)), // PidTagAttachNumber
        (0x3701, Val::Bin(data)),
    ];
    if let Some(c) = cid {
        a.push((0x3712, s(c)));
        a.push((0x7FFE, Val::Bool(true))); // PidTagAttachmentHidden: shown inline
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(p: &[(u16, Val)], id: u16) -> Option<&Val> {
        p.iter().find(|x| x.0 == id).map(|x| &x.1)
    }

    #[test]
    fn asctime_dates() {
        assert_eq!(asctime(0), "Thu Jan  1 00:00:00 1970");
        assert_eq!(asctime(1_760_282_400), "Sun Oct 12 15:20:00 2025");
        assert_eq!(asctime(951_782_400), "Tue Feb 29 00:00:00 2000");
    }

    #[test]
    fn mboxrd_quoting_roundtrip() {
        let eml = b"Return-Path: <a@example.com>\r\nFrom: A <a@example.com>\r\nDate: Thu, 1 Jan 2026 10:00:00 +0100\r\nSubject: x\r\n\r\nFrom here\r\n>From there\r\n>>From further\r\nFromage\r\n\r\n";
        let mut out = Vec::new();
        mbox_append(&mut out, eml).unwrap();
        mbox_append(&mut out, b"Subject: second\n\nno newline at the end").unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(
            text.starts_with("From a@example.com Thu Jan  1 09:00:00 2026\n"),
            "{text}"
        );
        assert!(text.contains("\n>From here\n>>From there\n>>>From further\nFromage\n"));
        assert!(!text.contains('\r'));
        assert!(text.contains("\nFrom MAILER-DAEMON Thu Jan  1 00:00:00 1970\nSubject: second\n"));
        let back = mbox_split(&out);
        assert_eq!(back.len(), 2);
        let lf = String::from_utf8_lossy(eml).replace("\r\n", "\n");
        assert_eq!(String::from_utf8_lossy(&back[0]), lf);
        assert_eq!(back[1], b"Subject: second\n\nno newline at the end\n");
    }

    #[test]
    fn eml_to_pst_properties() {
        let eml = b"From: \"M\xc3\xbcller, Anna\" <anna@example.com>\r\n\
To: Bob <bob@example.com>, carol@example.com\r\n\
Cc: Dave <dave@example.com>\r\n\
Subject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n\
Date: Mon, 12 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <id-1@example.com>\r\n\
Importance: high\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=b1\r\n\
\r\n\
--b1\r\n\
Content-Type: multipart/alternative; boundary=b2\r\n\
\r\n\
--b2\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hallo Bob\r\n\
--b2\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hallo <img src=\"cid:img1@x\"></p>\r\n\
--b2--\r\n\
--b1\r\n\
Content-Type: image/png\r\n\
Content-ID: <img1@x>\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgo=\r\n\
--b1\r\n\
Content-Type: application/pdf; name=\"report.pdf\"\r\n\
Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--b1--\r\n";
        let m = to_pst(eml);
        assert_eq!(get(&m.props, 0x0037), Some(&s("Grüße")));
        assert_eq!(get(&m.props, 0x0042), Some(&s("Müller, Anna")));
        assert_eq!(get(&m.props, 0x0065), Some(&s("anna@example.com")));
        assert_eq!(get(&m.props, 0x0E04), Some(&s("Bob; carol@example.com")));
        assert_eq!(get(&m.props, 0x0E03), Some(&s("Dave")));
        assert_eq!(get(&m.props, 0x0017), Some(&Val::I32(2)));
        assert_eq!(get(&m.props, 0x1035), Some(&s("<id-1@example.com>")));
        assert_eq!(get(&m.props, 0x0039), Some(&Val::Time(filetime(1_791_799_200))));
        assert!(matches!(get(&m.props, 0x1000), Some(Val::Str(t)) if t.trim() == "Hallo Bob"));
        assert!(matches!(get(&m.props, 0x1013), Some(Val::Bin(h)) if h.starts_with(b"<p>Hallo")));
        assert!(matches!(get(&m.props, 0x007D), Some(Val::Str(h)) if h.contains("Importance: high")));
        assert_eq!(get(&m.props, 0x0E07), Some(&Val::I32(0x11)));
        assert_eq!(m.recipients.len(), 3);
        assert_eq!(get(&m.recipients[1], 0x3001), Some(&s("carol@example.com")));
        assert_eq!(get(&m.recipients[2], 0x0C15), Some(&Val::I32(2)));
        assert_eq!(m.attachments.len(), 2);
        assert_eq!(get(&m.attachments[0], 0x3712), Some(&s("img1@x")), "inline image");
        assert_eq!(
            get(&m.attachments[0], 0x3701),
            Some(&Val::Bin(b"\x89PNG\r\n\x1a\n".to_vec()))
        );
        assert_eq!(get(&m.attachments[1], 0x3707), Some(&s("report.pdf")));
        assert_eq!(get(&m.attachments[1], 0x3701), Some(&Val::Bin(b"%PDF-1.4\n".to_vec())));
        assert_eq!(get(&m.attachments[1], 0x3712), None);
    }

    #[test]
    fn unparseable_messages_are_kept() {
        let m = to_pst(b"");
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(get(&m.attachments[0], 0x3707), Some(&s("message.eml")));
    }
}
