//! Logical dumps of one database and their restore.
//!
//! Two producers, one format (a mysqldump-style SQL script, `mysql db < x.sql` works
//! on a download):
//! - over SSH: `mysqldump` / `mariadb-dump --single-transaction` on the database
//!   host (the server's own, version-matched tool; credentials in a private option
//!   file fed through stdin);
//! - over the connection (TLS): generated here in one `REPEATABLE READ` transaction
//!   `WITH CONSISTENT SNAPSHOT` (what `--single-transaction` does): tables
//!   (`SHOW CREATE TABLE` + `INSERT`s of ≤ 1 MiB), MariaDB sequences, views (stand-ins
//!   first, as mysqldump does, so views on views need no ordering), routines,
//!   triggers (after the data) and events, each with its own `sql_mode`.
//!
//! Both start with a `-- nexus: ` header line (the database's default character
//! set and collation, used by the restore's `CREATE DATABASE`). The restore splits
//! the script into statements (quotes, comments, `DELIMITER`) and runs them one by
//! one over the connection.

use crate::my::{ident, lit, lit_str, Column, Conn, BINARY_CHARSET};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};

#[derive(Default, Debug)]
pub struct Stats {
    pub tables: u64,
    pub rows: u64,
    pub views: u64,
    pub routines: u64,
    pub triggers: u64,
    pub events: u64,
    /// objects the dump could not read (missing privileges)
    pub skipped: Vec<String>,
    /// tables of non-transactional engines (not consistent with the rest)
    pub non_transactional: Vec<String>,
    /// rows per table as dumped: the `-- nexus:rows` trailer, for restore tests
    pub per_table: Vec<(String, u64)>,
}

const BATCH: usize = 1 << 20;

/// The trailer line with the rows per table (dumps made over the connection only).
pub const ROWS_PREFIX: &str = "-- nexus:rows ";

/// `-- nexus: {"charset":…,"collation":…}` for the database `db`.
pub fn header(c: &mut Conn, db: &str) -> Result<String> {
    let r = c.query(&format!(
        "SELECT DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA \
         WHERE SCHEMA_NAME = {}",
        lit_str(db)
    ))?;
    let r = r
        .into_iter()
        .next()
        .with_context(|| format!("database {db:?} not found"))?;
    let get = |i: usize| r.get(i).cloned().flatten().unwrap_or_default();
    Ok(format!(
        "-- nexus: {}\n",
        serde_json::json!({"database": db, "charset": get(0), "collation": get(1)})
    ))
}

/// Reads the `-- nexus:` header of a dump (consumes only that line).
pub fn read_header(r: &mut impl BufRead) -> Result<serde_json::Value> {
    let mut line = String::new();
    r.read_line(&mut line)?;
    let j = line
        .strip_prefix("-- nexus: ")
        .context("not a NexusBackup MySQL dump (header missing)")?;
    Ok(serde_json::from_str(j.trim())?)
}

fn is_numeric(ty: u8) -> bool {
    // DECIMAL, TINY, SHORT, LONG, FLOAT, DOUBLE, LONGLONG, INT24, YEAR, NEWDECIMAL
    matches!(ty, 0 | 1 | 2 | 3 | 4 | 5 | 8 | 9 | 13 | 246)
}

/// One value of a text result row as an SQL literal.
pub fn value(col: &Column, v: Option<&[u8]>, out: &mut Vec<u8>) {
    let Some(v) = v else {
        out.extend_from_slice(b"NULL");
        return;
    };
    // binary strings/blobs, BIT, GEOMETRY: hex (JSON is "binary" in MySQL's metadata but text)
    let binary = col.ty != 245 && (col.charset == BINARY_CHARSET && !is_numeric(col.ty) || matches!(col.ty, 16 | 255));
    if is_numeric(col.ty) && !v.is_empty() {
        out.extend_from_slice(v);
    } else if binary && !v.is_empty() {
        out.extend_from_slice(b"0x");
        for b in v {
            out.extend_from_slice(format!("{b:02X}").as_bytes());
        }
    } else {
        out.extend_from_slice(&lit(v));
    }
}

fn strs(c: &mut Conn, sql: &str) -> Result<Vec<Vec<String>>> {
    Ok(c.query(sql)?
        .into_iter()
        .map(|r| r.into_iter().map(Option::unwrap_or_default).collect())
        .collect())
}

/// `SHOW CREATE …` column `i` (None: no privilege to see the definition).
fn show_create(c: &mut Conn, what: &str, name: &str, i: usize) -> Result<Option<Vec<String>>> {
    let r = c.query(&format!("SHOW CREATE {what} {}", ident(name)))?;
    Ok(r.into_iter().next().and_then(|r| {
        let ok = r.get(i).is_some_and(Option::is_some);
        ok.then(|| r.into_iter().map(Option::unwrap_or_default).collect())
    }))
}

/// How an object was created: sql_mode, time zone (events), client character set and collation.
#[derive(Default)]
struct Env<'a> {
    sql_mode: Option<&'a str>,
    tz: Option<&'a str>,
    charset: Option<(&'a str, &'a str)>,
}

/// An object definition under its creation environment (as mysqldump writes it);
/// `compound` = a routine/trigger/event body (`DELIMITER ;;`).
fn object(w: &mut impl Write, drop: &str, env: &Env, body: &str, compound: bool) -> Result<()> {
    writeln!(w, "{drop};")?;
    let mut reset = String::new();
    if let Some((cs, coll)) = env.charset {
        write!(
            w,
            "SET @nexus_saved_cs = @@character_set_client, @nexus_saved_cr = @@character_set_results, \
             @nexus_saved_co = @@collation_connection;\nSET character_set_client = {0}, character_set_results = {0}, \
             collation_connection = {1};\n",
            lit_str(cs),
            lit_str(coll)
        )?;
        reset += "SET character_set_client = @nexus_saved_cs, character_set_results = @nexus_saved_cr, \
                  collation_connection = @nexus_saved_co;\n";
    }
    if let Some(m) = env.sql_mode {
        writeln!(
            w,
            "SET @nexus_saved_sql_mode = @@sql_mode;\nSET sql_mode = {};",
            lit_str(m)
        )?;
        reset += "SET sql_mode = @nexus_saved_sql_mode;\n";
    }
    if let Some(tz) = env.tz {
        writeln!(
            w,
            "SET @nexus_saved_tz = @@time_zone;\nSET time_zone = {};",
            lit_str(tz)
        )?;
        reset += "SET time_zone = @nexus_saved_tz;\n";
    }
    if compound {
        writeln!(w, "DELIMITER ;;\n{body} ;;\nDELIMITER ;")?;
    } else {
        writeln!(w, "{body};")?;
    }
    w.write_all(reset.as_bytes())?;
    Ok(())
}

/// Native dump of the connection's database (see the module doc).
pub fn dump(c: &mut Conn, db: &str, w: &mut impl Write) -> Result<Stats> {
    let mut st = Stats::default();
    for s in [
        "SET NAMES utf8mb4",
        "SET SESSION time_zone = '+00:00'",
        "SET SESSION sql_mode = ''",
        "SET SESSION sql_quote_show_create = 1",
        "SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "START TRANSACTION WITH CONSISTENT SNAPSHOT",
    ] {
        c.exec(s)?;
    }
    w.write_all(header(c, db)?.as_bytes())?;
    writeln!(
        w,
        "-- NexusBackup dump of {} from {}\n/*!40101 SET NAMES utf8mb4 */;\nSET @nexus_old_fk = @@FOREIGN_KEY_CHECKS, \
         @nexus_old_uc = @@UNIQUE_CHECKS, @nexus_old_mode = @@SQL_MODE, @nexus_old_tz = @@TIME_ZONE;\n\
         SET FOREIGN_KEY_CHECKS = 0, UNIQUE_CHECKS = 0, SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO', TIME_ZONE = '+00:00';",
        ident(db),
        c.server_version
    )?;
    let tables = strs(
        c,
        "SELECT TABLE_NAME, TABLE_TYPE, COALESCE(ENGINE, '') FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME",
    )?;
    let mut views = Vec::new();
    for t in &tables {
        let (name, ty, engine) = (&t[0], &t[1], &t[2]);
        if ty == "VIEW" {
            // stand-in with the view's columns, replaced at the end
            let cols = strs(
                c,
                &format!(
                    "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() \
                     AND TABLE_NAME = {} ORDER BY ORDINAL_POSITION",
                    lit_str(name)
                ),
            )?;
            let cols: Vec<String> = cols.iter().map(|c| format!("1 AS {}", ident(&c[0]))).collect();
            writeln!(
                w,
                "DROP TABLE IF EXISTS {0};\nDROP VIEW IF EXISTS {0};\nCREATE VIEW {0} AS SELECT {1};",
                ident(name),
                if cols.is_empty() {
                    "1 AS `x`".into()
                } else {
                    cols.join(", ")
                }
            )?;
            views.push(name.clone());
            continue;
        }
        let what = if ty == "SEQUENCE" { "SEQUENCE" } else { "TABLE" };
        let Some(create) = show_create(c, what, name, 1)? else {
            st.skipped.push(format!("table {name}"));
            continue;
        };
        writeln!(w, "DROP TABLE IF EXISTS {};\n{};", ident(name), create[1])?;
        if ty == "SEQUENCE" {
            let next = c
                .value(&format!("SELECT next_not_cached_value FROM {}", ident(name)))?
                .unwrap_or_default();
            writeln!(w, "DO SETVAL({}, {}, 0);", ident(name), next.parse::<i64>()?)?;
            st.tables += 1;
            continue;
        }
        if !engine.is_empty() && !matches!(engine.to_ascii_lowercase().as_str(), "innodb" | "rocksdb") {
            st.non_transactional.push(format!("{name} ({engine})"));
        }
        // explicit columns: invisible ones included, generated ones left out
        let cols: Vec<String> = strs(
            c,
            &format!(
                "SELECT COLUMN_NAME, EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() \
                 AND TABLE_NAME = {} ORDER BY ORDINAL_POSITION",
                lit_str(name)
            ),
        )?
        .into_iter()
        .filter(|r| {
            let e = r[1].to_ascii_uppercase();
            !(e.contains("VIRTUAL GENERATED") || e.contains("STORED GENERATED") || e.contains("PERSISTENT GENERATED"))
        })
        .map(|r| ident(&r[0]))
        .collect();
        st.tables += 1;
        if cols.is_empty() {
            continue;
        }
        let list = cols.join(", ");
        let head = format!("INSERT INTO {} ({list}) VALUES ", ident(name));
        let mut buf: Vec<u8> = Vec::new();
        let mut rows = 0u64;
        c.query_each(&format!("SELECT {list} FROM {}", ident(name)), |cols, r| {
            buf.extend_from_slice(if buf.is_empty() { head.as_bytes() } else { b",\n" });
            buf.push(b'(');
            for (i, v) in r.iter().enumerate() {
                if i > 0 {
                    buf.push(b',');
                }
                value(&cols[i], v.as_deref(), &mut buf);
            }
            buf.push(b')');
            rows += 1;
            if buf.len() >= BATCH {
                buf.extend_from_slice(b";\n");
                w.write_all(&buf)?;
                buf.clear();
            }
            Ok(())
        })?;
        if !buf.is_empty() {
            buf.extend_from_slice(b";\n");
            w.write_all(&buf)?;
        }
        st.rows += rows;
        st.per_table.push((name.clone(), rows));
    }
    for v in &views {
        // columns: View, Create View, character_set_client, collation_connection
        match show_create(c, "VIEW", v, 1)? {
            Some(r) => {
                let env = Env {
                    charset: Some((&r[2], &r[3])),
                    ..Env::default()
                };
                object(w, &format!("DROP VIEW IF EXISTS {}", ident(v)), &env, &r[1], false)?;
                st.views += 1;
            }
            None => st.skipped.push(format!("view {v}")),
        }
    }
    for r in strs(
        c,
        "SELECT ROUTINE_NAME, ROUTINE_TYPE FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE() \
         AND ROUTINE_TYPE IN ('PROCEDURE', 'FUNCTION') ORDER BY ROUTINE_TYPE, ROUTINE_NAME",
    )? {
        // columns: name, sql_mode, Create …, character_set_client, collation_connection
        match show_create(c, &r[1], &r[0], 2)? {
            Some(s) => {
                let env = Env {
                    sql_mode: Some(&s[1]),
                    tz: None,
                    charset: Some((&s[3], &s[4])),
                };
                object(
                    w,
                    &format!("DROP {} IF EXISTS {}", r[1], ident(&r[0])),
                    &env,
                    &s[2],
                    true,
                )?;
                st.routines += 1;
            }
            None => st.skipped.push(format!("{} {}", r[1].to_lowercase(), r[0])),
        }
    }
    for r in strs(
        c,
        "SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() \
         ORDER BY EVENT_OBJECT_TABLE, ACTION_ORDER",
    )? {
        // columns: Trigger, sql_mode, SQL Original Statement, character_set_client, collation_connection
        match show_create(c, "TRIGGER", &r[0], 2)? {
            Some(s) => {
                let env = Env {
                    sql_mode: Some(&s[1]),
                    tz: None,
                    charset: Some((&s[3], &s[4])),
                };
                object(
                    w,
                    &format!("DROP TRIGGER IF EXISTS {}", ident(&r[0])),
                    &env,
                    &s[2],
                    true,
                )?;
                st.triggers += 1;
            }
            None => st.skipped.push(format!("trigger {}", r[0])),
        }
    }
    let events = match strs(
        c,
        "SELECT EVENT_NAME FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE() ORDER BY EVENT_NAME",
    ) {
        Ok(e) => e,
        Err(e) => {
            st.skipped.push(format!("events ({e:#})"));
            Vec::new()
        }
    };
    for r in events {
        // columns: Event, sql_mode, time_zone, Create Event, character_set_client, collation_connection
        match show_create(c, "EVENT", &r[0], 3) {
            Ok(Some(s)) => {
                let env = Env {
                    sql_mode: Some(&s[1]),
                    tz: Some(&s[2]),
                    charset: Some((&s[4], &s[5])),
                };
                object(w, &format!("DROP EVENT IF EXISTS {}", ident(&r[0])), &env, &s[3], true)?;
                st.events += 1;
            }
            _ => st.skipped.push(format!("event {}", r[0])),
        }
    }
    writeln!(
        w,
        "SET FOREIGN_KEY_CHECKS = @nexus_old_fk, UNIQUE_CHECKS = @nexus_old_uc, SQL_MODE = @nexus_old_mode, \
         TIME_ZONE = @nexus_old_tz;"
    )?;
    // a comment: `mysql db < x.sql` ignores it; the restore test compares the restored rows with it
    let rows: serde_json::Map<String, serde_json::Value> =
        st.per_table.iter().map(|(t, n)| (t.clone(), (*n).into())).collect();
    writeln!(
        w,
        "{ROWS_PREFIX}{}\n-- NexusBackup dump complete",
        serde_json::Value::Object(rows)
    )?;
    c.exec("COMMIT")?;
    Ok(st)
}

/// Splits an SQL script into statements the way the `mysql` client does: quotes
/// (`'`, `"`, `` ` ``), comments (`-- `, `#`, `/* */`; `/*!…*/` and `/*M!…*/` are
/// code), `DELIMITER` lines. Comment-only statements are dropped.
pub struct Splitter<R> {
    /// the `-- nexus:rows` trailer, when the script had one
    pub rows: Option<String>,
    r: R,
    delim: Vec<u8>,
    line: Vec<u8>,
    at: usize,
}

impl<R: BufRead> Splitter<R> {
    pub fn new(r: R) -> Self {
        Splitter {
            rows: None,
            r,
            delim: b";".to_vec(),
            line: Vec::new(),
            at: 0,
        }
    }

    fn next_line(&mut self) -> Result<bool> {
        self.line.clear();
        self.at = 0;
        Ok(self.r.read_until(b'\n', &mut self.line)? > 0)
    }

    /// Next statement (without its delimiter), None at the end.
    pub fn next_statement(&mut self) -> Result<Option<Vec<u8>>> {
        let mut stmt: Vec<u8> = Vec::new();
        let mut code = false; // stmt has something besides plain comments/whitespace
        #[derive(PartialEq)]
        enum S {
            Normal,
            Quote(u8),
            Block,
            CodeBlock,
        }
        let mut s = S::Normal;
        loop {
            if self.at >= self.line.len() {
                if !self.next_line()? {
                    if s != S::Normal && code {
                        bail!("the dump ends inside a quoted string or comment");
                    }
                    return Ok(code.then_some(stmt));
                }
                if s == S::Normal && !code {
                    let t = self.line.trim_ascii();
                    if t.len() > 10 && t[..10].eq_ignore_ascii_case(b"DELIMITER ") {
                        self.delim = t[10..].trim_ascii().to_vec();
                        if self.delim.is_empty() {
                            bail!("empty DELIMITER");
                        }
                        self.at = self.line.len();
                        continue;
                    }
                }
            }
            let rest = &self.line[self.at..];
            let c = rest[0];
            match s {
                S::Quote(q) => {
                    stmt.push(c);
                    self.at += 1;
                    if c == b'\\' && q != b'`' {
                        if let Some(&n) = self.line.get(self.at) {
                            stmt.push(n);
                            self.at += 1;
                        }
                    } else if c == q {
                        s = S::Normal;
                    }
                }
                S::Block | S::CodeBlock => {
                    if rest.starts_with(b"*/") {
                        if s == S::CodeBlock {
                            stmt.extend_from_slice(b"*/");
                        }
                        self.at += 2;
                        s = S::Normal;
                    } else {
                        if s == S::CodeBlock {
                            stmt.push(c);
                        }
                        self.at += 1;
                    }
                }
                S::Normal => {
                    if rest.starts_with(&self.delim) {
                        self.at += self.delim.len();
                        if code {
                            return Ok(Some(stmt));
                        }
                        stmt.clear();
                        continue;
                    }
                    let line_comment = rest.starts_with(b"#")
                        || (rest.starts_with(b"--") && rest.get(2).is_none_or(u8::is_ascii_whitespace));
                    if line_comment {
                        if let Some(j) = rest.strip_prefix(ROWS_PREFIX.as_bytes()) {
                            self.rows = Some(String::from_utf8_lossy(j).trim_end().to_owned());
                        }
                        self.at = self.line.len();
                        stmt.push(b'\n');
                    } else if rest.starts_with(b"/*!") || rest.starts_with(b"/*M!") {
                        stmt.extend_from_slice(b"/*");
                        self.at += 2;
                        s = S::CodeBlock;
                        code = true;
                    } else if rest.starts_with(b"/*") {
                        self.at += 2;
                        s = S::Block;
                        stmt.push(b' ');
                    } else {
                        if matches!(c, b'\'' | b'"' | b'`') {
                            s = S::Quote(c);
                        }
                        if !c.is_ascii_whitespace() {
                            code = true;
                        }
                        if code {
                            stmt.push(c);
                        }
                        self.at += 1;
                    }
                }
            }
        }
    }
}

#[derive(Default, Debug)]
pub struct Restored {
    pub statements: u64,
    /// rows per table from the dump's trailer (None: a dump without one, e.g. mysqldump over SSH)
    pub rows: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Restore test: every table of the trailer holds as many rows as the dump had for it.
pub fn check_counts(c: &mut Conn, rows: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    let mut bad = Vec::new();
    for (t, want) in rows {
        let have: u64 = c
            .value(&format!("SELECT COUNT(*) FROM {}", ident(t)))?
            .unwrap_or_default()
            .parse()
            .unwrap_or(u64::MAX);
        if Some(have) != want.as_u64() {
            bad.push(format!("{t}: {have} rows, the dump had {want}"));
        }
    }
    if !bad.is_empty() {
        bail!("restore test: row counts differ: {}", bad.join("; "));
    }
    Ok(())
}

/// Runs the statements of a dump (header already read) on `c`.
pub fn restore(c: &mut Conn, r: impl BufRead) -> Result<Restored> {
    let mut st = Restored::default();
    c.exec("SET NAMES utf8mb4")?;
    let mut sp = Splitter::new(r);
    while let Some(s) = sp.next_statement()? {
        let sql = String::from_utf8(s).context("the dump is not UTF-8")?;
        match c.exec(&sql) {
            Ok(()) => st.statements += 1,
            // a statement that is a version comment the server skips (e.g. mariadb-dump's sandbox line on MySQL)
            Err(e) if crate::my::code(&e) == Some(1065) => {}
            Err(e) => {
                let mut head: String = sql.chars().take(200).collect();
                if head.len() < sql.len() {
                    head += "…";
                }
                return Err(e.context(format!("statement {}: {head}", st.statements + 1)));
            }
        }
    }
    st.rows = match sp.rows.as_deref().map(serde_json::from_str::<serde_json::Value>) {
        Some(Ok(serde_json::Value::Object(m))) => Some(m),
        Some(_) => bail!("the dump's row trailer is not a JSON object"),
        None => None,
    };
    Ok(st)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(s: &str) -> Vec<String> {
        let mut sp = Splitter::new(s.as_bytes());
        let mut out = Vec::new();
        while let Some(x) = sp.next_statement().unwrap() {
            out.push(String::from_utf8(x).unwrap().trim().to_owned());
        }
        out
    }

    #[test]
    fn splitting() {
        let sql = "-- MySQL dump\n/*!40101 SET NAMES utf8mb4 */;\n/*M!999999\\- enable the sandbox mode */ \n\
                   INSERT INTO `t` VALUES (1,'a;b\\';c'),(2,\"x;\");\n# note\n/* plain; comment */\n\
                   DELIMITER ;;\nCREATE TRIGGER x BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.a = 1; END ;;\n\
                   DELIMITER ;\nSELECT `a;b` FROM t -- trailing\n;\n-- end\n";
        assert_eq!(
            split(sql),
            vec![
                "/*!40101 SET NAMES utf8mb4 */",
                // mariadb-dump's first line has no delimiter: a comment on every server, sent with the next statement
                "/*M!999999\\- enable the sandbox mode */ \nINSERT INTO `t` VALUES (1,'a;b\\';c'),(2,\"x;\")",
                "CREATE TRIGGER x BEFORE INSERT ON t FOR EACH ROW BEGIN SET NEW.a = 1; END",
                "SELECT `a;b` FROM t",
            ]
        );
        assert!(split("-- only\n/* comments */\n").is_empty());
        assert_eq!(split("SELECT 1"), vec!["SELECT 1"]);
        assert!(Splitter::new(&b"SELECT 'open;\n"[..]).next_statement().is_err());
    }

    #[test]
    fn values() {
        let col = |ty, charset| Column { ty, charset };
        let mut o = Vec::new();
        value(&col(3, 63), Some(b"42"), &mut o);
        o.push(b' ');
        value(&col(252, 63), Some(&[0, 0xff]), &mut o);
        o.push(b' ');
        value(&col(252, 45), Some(b"it's"), &mut o);
        o.push(b' ');
        value(&col(245, 63), Some(b"{\"a\": 1}"), &mut o);
        o.push(b' ');
        value(&col(16, 63), Some(&[5]), &mut o);
        o.push(b' ');
        value(&col(253, 63), Some(b""), &mut o);
        o.push(b' ');
        value(&col(3, 63), None, &mut o);
        assert_eq!(
            String::from_utf8(o).unwrap(),
            "42 0x00FF 'it\\'s' '{\"a\": 1}' 0x05 '' NULL"
        );
    }

    #[test]
    fn rows_trailer() {
        let mut sp = Splitter::new(
            &b"CREATE TABLE t (a int);\nINSERT INTO t VALUES (1),(2);\n-- nexus:rows {\"t\":2,\"u v\":0}\n-- NexusBackup dump complete\n"[..],
        );
        let mut n = 0;
        while sp.next_statement().unwrap().is_some() {
            n += 1;
        }
        assert_eq!(n, 2, "the trailer is a comment, not a statement");
        assert_eq!(sp.rows.as_deref(), Some("{\"t\":2,\"u v\":0}"));
    }

    #[test]
    fn header_line() {
        let mut r = &b"-- nexus: {\"charset\":\"utf8mb4\"}\nSELECT 1;\n"[..];
        assert_eq!(read_header(&mut r).unwrap()["charset"], "utf8mb4");
        assert_eq!(r, b"SELECT 1;\n");
        assert!(read_header(&mut &b"SELECT 1;\n"[..]).is_err());
    }
}
