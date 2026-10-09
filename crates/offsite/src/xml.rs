//! Tiny XML reader for S3 responses (ListObjectsV2, errors, multipart, retention).
//! Builds an element tree; attributes, comments, processing instructions and
//! namespace prefixes are dropped. No DTDs (refused), no custom entities, bounded
//! depth. Input comes from the network: every error is a value, never a panic
//! (fuzz target `s3_xml`).

use std::fmt;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Element {
    /// local name (namespace prefix removed)
    pub name: String,
    pub children: Vec<Element>,
    /// concatenated character data directly inside this element
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct XmlError(pub &'static str, pub usize);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xml: {} at byte {}", self.0, self.1)
    }
}

impl std::error::Error for XmlError {}

pub const MAX_DEPTH: usize = 32;

impl Element {
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.name == name)
    }
    pub fn children<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }
    /// Text of the first child `name`.
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn decode(raw: &str, at: usize, out: &mut String) -> Result<(), XmlError> {
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 1..];
        let end = tail.find(';').filter(|&e| e <= 10).ok_or(XmlError("bad entity", at))?;
        let ent = &tail[..end];
        let c = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let n = if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                    u32::from_str_radix(h, 16).ok()
                } else if let Some(d) = ent.strip_prefix('#') {
                    d.parse().ok()
                } else {
                    None
                };
                n.and_then(char::from_u32).ok_or(XmlError("bad entity", at))?
            }
        };
        out.push(c);
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    Ok(())
}

/// Parses a document and returns its root element.
pub fn parse(input: &[u8]) -> Result<Element, XmlError> {
    let s = std::str::from_utf8(input).map_err(|e| XmlError("not utf-8", e.valid_up_to()))?;
    let s = s.strip_prefix('\u{feff}').unwrap_or(s);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut i = 0;
    let b = s.as_bytes();
    while i < b.len() {
        if b[i] != b'<' {
            let end = s[i..].find('<').map_or(b.len(), |e| i + e);
            let txt = &s[i..end];
            match stack.last_mut() {
                Some(top) => decode(txt, i, &mut top.text)?,
                None if txt.trim().is_empty() => {}
                None => return Err(XmlError("text outside the root element", i)),
            }
            i = end;
            continue;
        }
        let rest = &s[i..];
        if let Some(r) = rest.strip_prefix("<?") {
            i += 2 + r.find("?>").ok_or(XmlError("unterminated declaration", i))? + 2;
        } else if let Some(r) = rest.strip_prefix("<!--") {
            i += 4 + r.find("-->").ok_or(XmlError("unterminated comment", i))? + 3;
        } else if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let e = r.find("]]>").ok_or(XmlError("unterminated CDATA", i))?;
            stack
                .last_mut()
                .ok_or(XmlError("CDATA outside the root element", i))?
                .text
                .push_str(&r[..e]);
            i += 9 + e + 3;
        } else if rest.starts_with("<!") {
            return Err(XmlError("DTDs are not supported", i));
        } else if let Some(r) = rest.strip_prefix("</") {
            let e = r.find('>').ok_or(XmlError("unterminated end tag", i))?;
            let name = r[..e].trim();
            let el = stack.pop().ok_or(XmlError("unexpected end tag", i))?;
            if local(name) != el.name {
                return Err(XmlError("mismatched end tag", i));
            }
            i += 2 + e + 1;
            match stack.last_mut() {
                Some(p) => p.children.push(el),
                None => root = Some(el),
            }
        } else {
            // start tag: name, then attributes up to '>' (quoted values may contain '>')
            let mut j = i + 1;
            let mut quote = None;
            while j < b.len() {
                match (quote, b[j]) {
                    (None, b'>') => break,
                    (None, q @ (b'"' | b'\'')) => quote = Some(q),
                    (Some(q), c) if c == q => quote = None,
                    _ => {}
                }
                j += 1;
            }
            if j >= b.len() {
                return Err(XmlError("unterminated start tag", i));
            }
            let inner = &s[i + 1..j];
            let (inner, empty) = match inner.strip_suffix('/') {
                Some(x) => (x, true),
                None => (inner, false),
            };
            let name = inner.split(|c: char| c.is_ascii_whitespace()).next().unwrap_or("");
            if name.is_empty() || name.contains(['<', '&', '"', '\'', '=']) {
                return Err(XmlError("bad element name", i));
            }
            if root.is_some() {
                return Err(XmlError("content after the root element", i));
            }
            if stack.len() >= MAX_DEPTH {
                return Err(XmlError("nesting too deep", i));
            }
            let el = Element {
                name: local(name).to_owned(),
                ..Default::default()
            };
            i = j + 1;
            if empty {
                match stack.last_mut() {
                    Some(p) => p.children.push(el),
                    None => root = Some(el),
                }
            } else {
                stack.push(el);
            }
        }
    }
    if !stack.is_empty() {
        return Err(XmlError("unclosed element", b.len()));
    }
    root.ok_or(XmlError("no root element", 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_result() {
        let x = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/</Prefix>
<IsTruncated>true</IsTruncated><NextContinuationToken>1a&amp;b</NextContinuationToken>
<Contents><Key>p/a&lt;b&#x41;&#66;</Key><Size>10</Size></Contents>
<CommonPrefixes><Prefix>p/d/</Prefix></CommonPrefixes><Empty/><!-- c --><X a="x>y"><![CDATA[<raw>]]></X>
</ListBucketResult>"#;
        let r = parse(x).unwrap();
        assert_eq!(r.name, "ListBucketResult");
        assert_eq!(r.text_of("NextContinuationToken"), Some("1a&b"));
        let c = r.child("Contents").unwrap();
        assert_eq!(c.text_of("Key"), Some("p/a<bAB"));
        assert_eq!(c.text_of("Size"), Some("10"));
        assert_eq!(r.children("CommonPrefixes").count(), 1);
        assert_eq!(r.text_of("X"), Some("<raw>"));
        assert!(r.child("Empty").is_some());
    }

    #[test]
    fn malformed() {
        for x in [
            &b""[..],
            b"<a>",
            b"<a></b>",
            b"</a>",
            b"<a>&bogus;</a>",
            b"<a>&#xFFFFFFFF;</a>",
            b"<!DOCTYPE a [<!ENTITY x 'y'>]><a>&x;</a>",
            b"<a/><b/>",
            b"text<a/>",
            b"<a x='>",
            b"<>",
            b"\xff",
        ] {
            assert!(parse(x).is_err(), "{:?}", String::from_utf8_lossy(x));
        }
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        assert_eq!(parse(deep.as_bytes()).unwrap_err().0, "nesting too deep");
        assert_eq!(
            parse(b"<s3:Error><s3:Code>X</s3:Code></s3:Error>")
                .unwrap()
                .text_of("Code"),
            Some("X")
        );
    }
}
