//! Mail export (download with conversion, contract v1.9) end to end: a mailbox backed
//! up from the Graph mock, exported by the real host code (`plugin_host::export`,
//! no config, no network) as eml, mbox and PST; the PST is read back with
//! outlook-pst and — when podman is available — with readpst (libpst) and
//! pffexport (libpff) in a lab container (tests/pst-tools/Containerfile).

mod mock;
mod pstread;

use m365_plugin::M365;
use mock::*;
use plugin_sdk::testing::Host;
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::Command;

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/manifest.json");

fn attachment() -> Vec<u8> {
    (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
        .collect()
}

fn b64(data: &[u8]) -> String {
    use base64::Engine;
    let s = base64::engine::general_purpose::STANDARD.encode(data);
    s.as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// A message with an HTML body, an inline image and a 300 KB attachment.
fn rich_mime() -> Vec<u8> {
    format!(
        "From: Alice <alice@contoso.test>\r\nTo: Bob <bob@contoso.test>, carol@contoso.test\r\n\
         Subject: Quarterly report\r\nDate: Mon, 12 Oct 2026 08:30:00 +0200\r\nMessage-ID: <q3@mock>\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=XX\r\n\r\n\
         --XX\r\nContent-Type: multipart/alternative; boundary=YY\r\n\r\n\
         --YY\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nFrom the start: numbers attached.\r\n\
         --YY\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Numbers <img src=\"cid:logo@x\"></p>\r\n--YY--\r\n\
         --XX\r\nContent-Type: image/png\r\nContent-ID: <logo@x>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n\
         --XX\r\nContent-Type: application/pdf; name=\"q3.pdf\"\r\nContent-Disposition: attachment; filename=\"q3.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n--XX--\r\n",
        b64(&attachment())
    )
    .into_bytes()
}

struct Setup {
    _m: Mock,
    h: Host,
    source: String,
    time: u64,
    guest: String,
}

fn setup() -> Setup {
    let m = Mock::start();
    let guest;
    {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, true);
        let inbox = t.add_folder(&alice, None, "Inbox");
        let projects = t.add_folder(&alice, Some(&inbox), "Projects/2026");
        let q3 = t.add_message(&alice, &inbox, "Quarterly report", "");
        t.msg(&q3).mime = rich_mime();
        t.add_message(&alice, &inbox, "Lunch?", "From now on: noon.\r\n>From quoted");
        t.add_message(&alice, &projects, "Plan", "q4");
        let rec = t.recoverable(&alice);
        t.add_message(&alice, &rec, "Purged contract", "gone?");
        t.add_event(&alice, "Planning");
        let d = t.user_drive(&alice);
        let root = t.drive_root(&d);
        t.add_item(&d, &root, "notes.txt", Some(b"plain file".to_vec()));
        guest = m365_plugin::Guest::User(alice).id();
    }
    let mut h = Host::in_process(MANIFEST.as_ref(), "m365", || M365).unwrap();
    h.source_id = 5;
    let b = h.backup(&m.config(), Some(&guest)).unwrap();
    Setup {
        source: format!("plugin-m365-5-{guest}"),
        time: b.time,
        _m: m,
        h,
        guest,
    }
}

/// name → content of a tar.
fn untar(p: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut a = tar::Archive::new(std::fs::File::open(p).unwrap());
    a.entries()
        .unwrap()
        .map(|e| {
            let mut e = e.unwrap();
            let mut b = Vec::new();
            e.read_to_end(&mut b).unwrap();
            (e.path().unwrap().to_string_lossy().into_owned(), b)
        })
        .collect()
}

#[test]
fn eml_and_mbox() {
    let s = setup();
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("eml.tar");
    let all = ["/".to_owned()];
    let r =
        s.h.export(&s.source, s.time, &all, json!({"mail_format": "eml"}), &out)
            .unwrap();
    let t = untar(&out);
    assert!(r.summary.contains("as stored"), "{}", r.summary);
    assert!(t
        .keys()
        .any(|k| k.starts_with("mail/Inbox/Quarterly report") && k.ends_with(".eml")));
    assert!(t.keys().any(|k| k.starts_with("onedrive/notes.txt")));

    let out = d.path().join("mbox.zip");
    let r =
        s.h.export(&s.source, s.time, &all, json!({"mail_format": "mbox"}), &out)
            .unwrap();
    assert!(r.summary.contains("4 messages as mbox (3 folders)"), "{}", r.summary);
    let mut z = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
    let mut names: Vec<String> = z.file_names().map(str::to_owned).collect();
    names.sort();
    assert!(names.contains(&"mail/Inbox.mbox".to_owned()), "{names:?}");
    assert!(
        names.contains(&"mail/Inbox/Projects%2F2026.mbox".to_owned()),
        "{names:?}"
    );
    assert!(names.contains(&"recoverable/Deletions.mbox".to_owned()), "{names:?}");
    assert!(
        names.iter().any(|n| n.starts_with("calendar/")),
        "non-mail items as stored: {names:?}"
    );
    assert!(!names.iter().any(|n| n.ends_with(".eml")), "{names:?}");
    let mut inbox = Vec::new();
    z.by_name("mail/Inbox.mbox").unwrap().read_to_end(&mut inbox).unwrap();
    let msgs = m365_plugin::mail::mbox_split(&inbox);
    assert_eq!(msgs.len(), 2);
    let text = String::from_utf8_lossy(&inbox);
    assert!(text.starts_with("From alice@contoso.test "), "{}", &text[..80]);
    assert!(
        text.contains("\n>From now on: noon.\n>>From quoted\n"),
        "mboxrd quoting"
    );
    assert!(!text.contains('\r'));
    // the selection: only the projects folder
    let out = d.path().join("sel.tar");
    s.h.export(
        &s.source,
        s.time,
        &["/mail/Inbox/Projects%2F2026".to_owned()],
        json!({"mail_format": "mbox"}),
        &out,
    )
    .unwrap();
    assert_eq!(
        untar(&out).keys().collect::<Vec<_>>(),
        ["mail/Inbox/Projects%2F2026.mbox"]
    );
    // bad parameters end in an error, nothing is left behind
    let out = d.path().join("bad.tar");
    assert!(s
        .h
        .export(&s.source, s.time, &all, json!({"mail_format": "doc"}), &out)
        .is_err());
    assert!(!out.exists() && !d.path().join("bad.d").exists());
}

#[test]
fn pst_with_independent_readers() {
    let s = setup();
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("pst.tar");
    let r =
        s.h.export(
            &s.source,
            s.time,
            &["/".to_owned()],
            json!({"mail_format": "pst"}),
            &out,
        )
        .unwrap();
    assert!(r.summary.contains("4 messages as PST"), "{}", r.summary);
    let t = untar(&out);
    let name = format!("{}.pst", s.guest);
    assert!(t.contains_key(&name), "{:?}", t.keys().collect::<Vec<_>>());
    let pst = d.path().join(&name);
    std::fs::write(&pst, &t[&name]).unwrap();
    if let Ok(keep) = std::env::var("NEXUS_PST_KEEP") {
        std::fs::write(keep, &t[&name]).unwrap(); // for looking at it with other readers
    }
    assert!(t.keys().any(|k| k.starts_with("calendar/")), "non-mail items as stored");

    let tree = pstread::read_back(&pst);
    assert_eq!(
        tree.keys().collect::<Vec<_>>(),
        [
            "",
            "Deleted Items",
            "Inbox",
            "Inbox/Projects/2026",
            "Recoverable Items",
            "Recoverable Items/Deletions"
        ]
    );
    let inbox = &tree["Inbox"];
    let q3 = inbox.iter().find(|m| m.0 == "Quarterly report").unwrap();
    assert_eq!(q3.1, ["Bob", "carol@contoso.test"]);
    let names: Vec<&str> = q3.2.iter().map(|a| a.0.as_str()).collect();
    assert_eq!(names, ["attachment-1.png", "q3.pdf"]);
    assert_eq!(q3.2[1].1, attachment());
    assert_eq!(tree["Inbox/Projects/2026"][0].0, "Plan");
    assert_eq!(tree["Recoverable Items/Deletions"][0].0, "Purged contract");

    if Command::new("podman").arg("--version").output().is_err() {
        eprintln!("podman not available: readpst / pffexport checks skipped");
        return;
    }
    let ctx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/pst-tools");
    let image = "localhost/nexus-pst-tools";
    let have = Command::new("podman")
        .args(["image", "exists", image])
        .status()
        .is_ok_and(|s| s.success());
    if !have {
        let built = Command::new("podman")
            .args(["build", "-q", "-t", image, ctx])
            .status()
            .is_ok_and(|s| s.success());
        if !built {
            eprintln!("cannot build {image} (no network?): readpst / pffexport checks skipped");
            return;
        }
    }
    let dir = d.path().to_string_lossy().into_owned();
    let run = |script: &str| {
        let o = Command::new("podman")
            .args([
                "run",
                "--rm",
                "--network=none",
                "-v",
                &format!("{dir}:/d:Z"),
                image,
                "sh",
                "-c",
                script,
            ])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(o.status.success(), "{script}: {text}");
        text
    };
    // libpst: folder counts and the attachment's bytes
    let log = run(&format!("mkdir -p /d/rp && readpst -D -S -o /d/rp /d/{name}"));
    for (folder, n) in [("Inbox", 3), ("Projects/2026", 1), ("Deletions", 1)] {
        assert!(
            log.contains(&format!("\"{folder}\" - {n} items done")),
            "{folder}: {log}"
        );
    }
    let found: Vec<_> = walk(&d.path().join("rp"))
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with("-q3.pdf"))
        .collect();
    assert_eq!(found.len(), 1, "readpst wrote the PDF once");
    assert_eq!(std::fs::read(&found[0]).unwrap(), attachment());
    let headers = walk(&d.path().join("rp"))
        .into_iter()
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().chars().all(|c| c.is_ascii_digit()))
        })
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(headers.contains("Subject: Quarterly report"), "{headers}");
    // libpff: info, then the export tree with the folder structure and the attachment
    let info = run(&format!("pffinfo /d/{name}"));
    assert!(
        info.contains("Personal Storage Tables (PST)") && info.contains("64-bit"),
        "{info}"
    );
    run(&format!("pffexport -q -t /d/pff /d/{name}"));
    let root = d.path().join("pff.export/Top of Personal Folders");
    for dir in ["Inbox/Projects_2026", "Recoverable Items/Deletions", "Deleted Items"] {
        assert!(root.join(dir).is_dir(), "{dir}: {:?}", walk(&root));
    }
    let pdfs: Vec<_> = walk(&root)
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with("q3.pdf"))
        .collect();
    assert_eq!(pdfs.len(), 1, "{:?}", walk(&root));
    assert_eq!(std::fs::read(&pdfs[0]).unwrap(), attachment());
    let subjects = walk(&root)
        .into_iter()
        .filter(|p| p.ends_with("OutlookHeaders.txt"))
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    for s in ["Quarterly report", "Lunch?", "Plan", "Purged contract"] {
        assert!(subjects.contains(s), "pffexport: {s}");
    }
}

/// The real binary in the real sandbox (Landlock without any TCP port, seccomp):
/// the export needs neither network nor credentials.
#[test]
fn sandboxed_binary_exports_pst() {
    let m = Mock::start();
    let guest = {
        let mut t = m.lock();
        let alice = t.add_user("Alice", true, false);
        let inbox = t.add_folder(&alice, None, "Inbox");
        let q3 = t.add_message(&alice, &inbox, "Quarterly report", "");
        t.msg(&q3).mime = rich_mime();
        m365_plugin::Guest::User(alice).id()
    };
    let h = Host::binary(MANIFEST.as_ref(), env!("CARGO_BIN_EXE_m365-plugin").as_ref(), "m365").unwrap();
    let mut cfg = m.config();
    cfg["teams_messages"] = json!(false);
    let b = h.backup(&cfg, Some(&guest)).unwrap();
    let d = tempfile::tempdir().unwrap();
    let out = d.path().join("x.zip");
    let r = h
        .export(
            &b.source,
            b.time,
            &["/mail".to_owned()],
            json!({"mail_format": "pst"}),
            &out,
        )
        .unwrap();
    assert!(r.summary.contains("1 messages as PST"), "{}\n{:#?}", r.summary, h.log());
    assert!(
        h.log()
            .iter()
            .any(|l| l.contains("landlock") && l.contains("(tcp ports)")),
        "{:#?}",
        h.log()
    );
    let mut z = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
    let name = format!("{guest}.pst");
    let mut pst = Vec::new();
    z.by_name(&name).unwrap().read_to_end(&mut pst).unwrap();
    let p = d.path().join(&name);
    std::fs::write(&p, pst).unwrap();
    let tree = pstread::read_back(&p);
    assert_eq!(tree["Inbox"][0].2[1].1, attachment());
}

fn walk(p: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}
