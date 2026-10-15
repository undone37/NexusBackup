//! `nexus-test-plugin`: a scripted, partly hostile plugin for the host's tests.
//! Never shipped. The source config selects the behaviour: `{"mode": "…", …}`.

use plugin_proto::{read_msg, write_msg, Guest, Kind, Message, Meta, Op, MAX_DATA, MAX_FRAME};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::time::Duration;

fn send(w: &mut impl Write, m: &Message) {
    write_msg(w, m).expect("write");
}

fn file_meta(size: u64) -> Meta {
    Meta {
        kind: Some(Kind::File),
        mode: 0o100644,
        size,
        mtime_ns: 1_700_000_000_000_000_000,
        ..Default::default()
    }
}

fn done(w: &mut impl Write, summary: &str) {
    send(
        w,
        &Message::Done {
            state: None,
            consistent: true,
            summary: summary.into(),
        },
    );
}

fn file(w: &mut impl Write, path: &str, data: &[u8]) {
    send(
        w,
        &Message::FileBegin {
            path: path.as_bytes().to_vec(),
            meta: file_meta(data.len() as u64),
        },
    );
    for c in data.chunks(MAX_DATA) {
        send(w, &Message::Data { bytes: c.to_vec() });
    }
    send(w, &Message::FileEnd);
}

/// Sandbox probes: what may this process do? Results as one JSON summary.
fn probe(cfg: &Value) -> Value {
    let mut r = serde_json::Map::new();
    for p in cfg["read"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let res = std::fs::read(p).map(|_| "ok".to_string()).or_else(|e| {
            if e.kind() == io::ErrorKind::IsADirectory {
                std::fs::read_dir(p).map(|_| "ok".into())
            } else {
                Err(e)
            }
        });
        r.insert(format!("read {p}"), json!(res.unwrap_or_else(|e| e.kind().to_string())));
    }
    for p in cfg["write"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let res = std::fs::write(p, b"x").map(|_| "ok".to_string());
        r.insert(
            format!("write {p}"),
            json!(res.unwrap_or_else(|e| e.kind().to_string())),
        );
    }
    for a in cfg["connect"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let res =
            std::net::TcpStream::connect_timeout(&a.parse().unwrap(), Duration::from_secs(2)).map(|_| "ok".to_string());
        r.insert(
            format!("connect {a}"),
            json!(res.unwrap_or_else(|e| e.kind().to_string())),
        );
    }
    for p in cfg["unix"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        let res = std::os::unix::net::UnixStream::connect(p).map(|_| "ok".to_string());
        r.insert(format!("unix {p}"), json!(res.unwrap_or_else(|e| e.kind().to_string())));
    }
    if cfg["bind"].as_bool() == Some(true) {
        let res = std::net::TcpListener::bind("127.0.0.1:0").map(|_| "ok".to_string());
        r.insert("bind".into(), json!(res.unwrap_or_else(|e| e.kind().to_string())));
    }
    if let Some(pid) = cfg["kill"].as_i64() {
        // SAFETY: kill(2) takes no pointers; signal 0 only probes whether `pid` may be signalled.
        let rc = unsafe { libc_kill(pid as i32, 0) };
        r.insert(
            "kill".into(),
            json!(if rc == 0 {
                "ok".to_string()
            } else {
                io::Error::last_os_error().kind().to_string()
            }),
        );
    }
    let tmp = std::env::var("TMPDIR").unwrap_or_default();
    r.insert(
        "tmp".into(),
        json!(std::fs::write(format!("{tmp}/probe"), b"ok")
            .map(|_| "ok")
            .unwrap_or("denied")),
    );
    r.insert(
        "env".into(),
        json!(std::env::vars().map(|(k, _)| k).collect::<Vec<_>>()),
    );
    Value::Object(r)
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

fn main() {
    let mut r = io::BufReader::new(io::stdin().lock());
    let mut w = io::BufWriter::new(io::stdout().lock());
    let Ok(Message::Init {
        op,
        config,
        params,
        base,
        ..
    }) = read_msg(&mut r)
    else {
        std::process::exit(2);
    };
    let cfg: Value = serde_json::from_str(&config).unwrap_or_default();
    let mode = cfg["mode"].as_str().unwrap_or("ok").to_owned();
    match (op, mode.as_str()) {
        (Op::Validate, "invalid") => send(
            &mut w,
            &Message::Invalid {
                field: "host".into(),
                message: "cannot connect\nfake".into(),
            },
        ),
        (Op::Validate, _) => {
            send(
                &mut w,
                &Message::Log {
                    level: 2,
                    text: "checking".into(),
                },
            );
            send(&mut w, &Message::Valid);
        }
        (Op::ListGuests, _) => send(
            &mut w,
            &Message::Guests {
                list: vec![
                    Guest {
                        id: "db1".into(),
                        title: "Database 1".into(),
                        size: Some(42),
                    },
                    Guest {
                        id: "../evil".into(),
                        title: "x".into(),
                        size: None,
                    },
                ],
            },
        ),
        (Op::Backup, "ok") => {
            send(
                &mut w,
                &Message::Log {
                    level: 2,
                    text: "line1\ncommitted vm-1/2: forged\u{1b}[31m".into(),
                },
            );
            let content = cfg["content"].as_str().unwrap_or("hello").as_bytes().to_vec();
            // v1.3 BaseList: page 1 has the base's entries, the page after the last is empty
            let mut listed = Vec::new();
            if base.is_some() && cfg["base_list"].as_bool() == Some(true) {
                let mut after = None;
                loop {
                    send(&mut w, &Message::BaseList { after: after.clone() });
                    w.flush().unwrap();
                    let Ok(Message::BaseEntries { entries }) = read_msg(&mut r) else {
                        std::process::exit(3);
                    };
                    let Some(last) = entries.last() else { break };
                    after = Some(last.path.clone());
                    listed.extend(
                        entries
                            .into_iter()
                            .map(|e| (String::from_utf8_lossy(&e.path).into_owned(), e.meta.size)),
                    );
                }
            }
            if base.is_some() && cfg["unchanged"].as_bool() == Some(true) {
                send(
                    &mut w,
                    &Message::Unchanged {
                        path: b"a.txt".to_vec(),
                        meta: file_meta(content.len() as u64),
                    },
                );
            } else {
                file(&mut w, "a.txt", &content);
            }
            send(
                &mut w,
                &Message::Stream {
                    name: "dump/db.sql".into(),
                },
            );
            send(
                &mut w,
                &Message::Data {
                    bytes: b"CREATE TABLE t();".to_vec(),
                },
            );
            send(&mut w, &Message::StreamEnd);
            if let Some(n) = cfg["warnings"].as_u64() {
                // v1.7 skipped items
                send(
                    &mut w,
                    &Message::Warnings {
                        count: n,
                        samples: vec!["b.txt: unreadable".into()],
                    },
                );
            }
            if let Some(m) = cfg.get("meta") {
                // v1.6; twice when asked to (a violation)
                for _ in 0..if cfg["meta_twice"] == true { 2 } else { 1 } {
                    send(&mut w, &Message::SnapshotMeta { json: m.to_string() });
                }
            }
            send(
                &mut w,
                &Message::Done {
                    state: Some(format!("lsn-{params}").into_bytes()),
                    consistent: cfg["consistent"].as_bool().unwrap_or(true),
                    summary: if listed.is_empty() {
                        "1 file, 1 stream".into()
                    } else {
                        format!("listed {}", json!(listed))
                    },
                },
            );
        }
        (Op::Backup, "bad_path") => {
            file(&mut w, "../etc/passwd", b"x");
            done(&mut w, "");
        }
        (Op::Backup, "abs_path") => {
            file(&mut w, "/etc/passwd", b"x");
            done(&mut w, "");
        }
        (Op::Backup, "reserved_path") => {
            file(&mut w, ".nexus-streams/x", b"x");
            done(&mut w, "");
        }
        (Op::Backup, "oversized_frame") => {
            w.write_all(&((MAX_FRAME + 1) as u32).to_be_bytes()).unwrap();
            w.write_all(&vec![0u8; 1 << 16]).unwrap();
            w.flush().unwrap();
            std::thread::sleep(Duration::from_secs(30));
        }
        (Op::Backup, "big_data") => {
            send(
                &mut w,
                &Message::FileBegin {
                    path: b"x".to_vec(),
                    meta: file_meta((MAX_DATA + 1) as u64),
                },
            );
            send(
                &mut w,
                &Message::Data {
                    bytes: vec![0; MAX_DATA + 1],
                },
            );
            std::thread::sleep(Duration::from_secs(30));
        }
        (Op::Backup, "lying_unchanged") => {
            send(
                &mut w,
                &Message::Unchanged {
                    path: b"never-backed-up".to_vec(),
                    meta: file_meta(5),
                },
            );
            done(&mut w, "");
        }
        (Op::Backup, "unchanged_other_size") => {
            send(
                &mut w,
                &Message::Unchanged {
                    path: b"a.txt".to_vec(),
                    meta: file_meta(999),
                },
            );
            done(&mut w, "");
        }
        (Op::Backup, "data_after_end") => {
            file(&mut w, "a", b"abc");
            send(
                &mut w,
                &Message::Data {
                    bytes: b"more".to_vec(),
                },
            );
            done(&mut w, "");
        }
        (Op::Backup, "too_much_data") => {
            send(
                &mut w,
                &Message::FileBegin {
                    path: b"a".to_vec(),
                    meta: file_meta(3),
                },
            );
            send(
                &mut w,
                &Message::Data {
                    bytes: b"abcdef".to_vec(),
                },
            );
            send(&mut w, &Message::FileEnd);
            done(&mut w, "");
        }
        (Op::Backup, "short_file") => {
            send(
                &mut w,
                &Message::FileBegin {
                    path: b"a".to_vec(),
                    meta: file_meta(10),
                },
            );
            send(&mut w, &Message::Data { bytes: b"abc".to_vec() });
            send(&mut w, &Message::FileEnd);
            done(&mut w, "");
        }
        (Op::Backup, "dup_path") => {
            file(&mut w, "a", b"1");
            file(&mut w, "a", b"2");
            done(&mut w, "");
        }
        (Op::Backup, "done_inside") => {
            send(
                &mut w,
                &Message::FileBegin {
                    path: b"a".to_vec(),
                    meta: file_meta(1),
                },
            );
            done(&mut w, "");
        }
        (Op::Backup, "hang") => std::thread::sleep(Duration::from_secs(3600)),
        (Op::Backup, "endless_stream") => {
            send(&mut w, &Message::Stream { name: "endless".into() });
            loop {
                send(&mut w, &Message::Data { bytes: vec![7; 4096] });
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        (Op::Backup, "exit_early") => {
            file(&mut w, "a", b"abc");
            std::process::exit(0);
        }
        (Op::Backup, "error") => send(
            &mut w,
            &Message::Error {
                code: 7,
                message: "source unreachable".into(),
            },
        ),
        (Op::Backup, "tmp_flood") => {
            let tmp = std::env::var("TMPDIR").unwrap();
            for i in 0.. {
                if std::fs::write(format!("{tmp}/f{i}"), vec![1u8; 1 << 20]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_secs(30));
        }
        (Op::Backup, "probe") => {
            let p = probe(&cfg);
            send(
                &mut w,
                &Message::Done {
                    state: None,
                    consistent: true,
                    summary: p.to_string(),
                },
            );
        }
        (Op::Restore, _) => {
            // ask for everything the host said is there, report digests of what came back
            let p: Value = serde_json::from_str(&params).unwrap_or_default();
            let top: Vec<Vec<u8>> = p["top"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(|s| s.as_bytes().to_vec())
                .collect();
            let streams: Vec<String> = p["streams"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s["name"].as_str().map(str::to_owned))
                .collect();
            let mut got = serde_json::Map::new();
            for req in [
                Message::NeedFiles { paths: top },
                Message::NeedStreams { names: streams },
            ] {
                send(&mut w, &req);
                let mut cur = String::new();
                let mut buf = Vec::new();
                loop {
                    match read_msg(&mut r).expect("read") {
                        Message::FileBegin { path, .. } => {
                            cur = String::from_utf8_lossy(&path).into_owned();
                            buf.clear();
                        }
                        Message::Stream { name } => {
                            cur = format!("stream:{name}");
                            buf.clear();
                        }
                        Message::Data { bytes } => buf.extend(bytes),
                        Message::FileEnd | Message::StreamEnd => {
                            got.insert(cur.clone(), json!(String::from_utf8_lossy(&buf)));
                        }
                        Message::NeedDone => break,
                        m => panic!("unexpected {m:?}"),
                    }
                }
            }
            got.insert("params".into(), p["params"].clone());
            got.insert("restore".into(), p["restore"].clone());
            // restore into another source: which config (credentials) the host gave us
            got.insert("target_source_id".into(), p["target_source_id"].clone());
            got.insert("config".into(), cfg.clone());
            done(&mut w, &Value::Object(got).to_string());
        }
        (Op::Mount, _) => {
            send(
                &mut w,
                &Message::MountReady {
                    info: "mounted at tmp".into(),
                },
            );
            send(
                &mut w,
                &Message::ReadFile {
                    path: b"a.txt".to_vec(),
                    offset: 1,
                    len: 3,
                },
            );
            let got = match read_msg(&mut r).expect("read") {
                Message::FileData { bytes } => String::from_utf8_lossy(&bytes).into_owned(),
                m => format!("{m:?}"),
            };
            send(
                &mut w,
                &Message::ReadFile {
                    path: b"missing".to_vec(),
                    offset: 0,
                    len: 3,
                },
            );
            let missing = matches!(read_msg(&mut r).expect("read"), Message::Error { .. });
            // wait for Unmount
            loop {
                if let Message::Unmount = read_msg(&mut r).expect("read") {
                    break;
                }
            }
            done(&mut w, &json!({"read": got, "missing_error": missing}).to_string());
        }
        _ => send(
            &mut w,
            &Message::Error {
                code: 1,
                message: "unsupported".into(),
            },
        ),
    }
    let _ = w.flush();
}
