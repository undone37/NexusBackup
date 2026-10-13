//! PST writer (src/pst) read back with Microsoft's `outlook-pst` crate (an
//! independent reader of [MS-PST]): header and B-trees, store, folder hierarchy,
//! contents tables, message properties, recipient tables, attachments (small,
//! heap-sized and XBLOCK / XXBLOCK sized), many messages (multi-level BTH, multi-block
//! heaps and row matrices) and the allocation maps (compared with the AMaps
//! outlook-pst rebuilds from the B-trees).

mod pstread;

use m365_plugin::pst::ltp::Val;
use m365_plugin::pst::{Message, PstWriter};
use outlook_pst::{PstFile, UnicodePstFile};
use pstread::read_back;
use std::fs::File;

fn s(v: &str) -> Val {
    Val::Str(v.into())
}

fn message(subject: &str, n: usize, attachments: Vec<(String, Vec<u8>)>) -> Message {
    let mut m = Message {
        props: vec![
            (0x001A, s("IPM.Note")),
            (0x0037, s(subject)),
            (0x0070, s(subject)),
            (0x0E07, Val::I32(1 | if attachments.is_empty() { 0 } else { 0x10 })),
            (0x0E08, Val::I32(1000 + n as i32)),
            (0x0E17, Val::I32(0)),
            (0x3007, Val::Time(133_000_000_000_000_000)),
            (0x3008, Val::Time(133_000_000_000_000_000)),
            (0x0E06, Val::Time(133_000_000_000_000_000 + n as u64)),
            (0x300B, Val::Bin(vec![n as u8; 16])),
            (0x0042, s("Alice Example")),
            (0x0C1A, s("Alice Example")),
            (0x0E04, s("Bob")),
            (0x1000, s(&format!("body of {subject}\r\n").repeat(1 + n % 400))),
        ],
        ..Default::default()
    };
    m.recipients = vec![
        vec![
            (0x0C15, Val::I32(1)),
            (0x3001, s("Bob")),
            (0x3002, s("SMTP")),
            (0x3003, s("bob@example.com")),
            (0x39FE, s("bob@example.com")),
            (0x0FFE, Val::I32(6)),
        ],
        vec![
            (0x0C15, Val::I32(2)),
            (0x3001, s("Carol")),
            (0x3003, s("carol@example.com")),
        ],
    ];
    for (name, data) in attachments {
        m.attachments.push(vec![
            (0x0E20, Val::I32(data.len() as i32)),
            (0x3704, s(&name)),
            (0x3707, s(&name)),
            (0x3705, Val::I32(1)),
            (0x370B, Val::I32(-1)),
            (0x3001, s(&name)),
            (0x3701, Val::Bin(data)),
        ]);
    }
    m
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).wrapping_add(u32::from(seed)) as u8)
        .collect()
}

#[test]
fn pst_reads_back_with_outlook_pst() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("t.pst");
    let mut w = PstWriter::new(File::create(&path).unwrap(), "Mailbox test", [7; 16]).unwrap();
    let inbox = w.folder(&["Inbox".into()]);
    let sub = w.folder(&["Inbox".into(), "Projekte 2026 – ä".into()]);
    let deleted = w.folder(&["Deleted Items".into()]);
    let small = pattern(100, 1);
    let heap = pattern(3000, 2);
    let xblock = pattern(200_000, 3);
    let xxblock = pattern(9_000_000, 4);
    w.add_message(inbox, message("first", 0, vec![("a.bin".into(), small.clone())]))
        .unwrap();
    w.add_message(
        sub,
        message(
            "second",
            1,
            vec![
                ("b.bin".into(), heap.clone()),
                ("c.bin".into(), xblock.clone()),
                ("d.bin".into(), xxblock.clone()),
            ],
        ),
    )
    .unwrap();
    w.add_message(deleted, message("gone", 2, vec![])).unwrap();
    // enough rows for a multi-level row index, a multi-block heap and row matrix
    let many = w.folder(&["Many".into()]);
    for i in 0..1200 {
        w.add_message(many, message(&format!("m{i:04} {}", "x".repeat(i % 50)), i, vec![]))
            .unwrap();
    }
    w.finish().unwrap();
    if let Ok(keep) = std::env::var("NEXUS_PST_KEEP") {
        std::fs::copy(&path, keep).unwrap(); // for looking at it with other readers
    }

    let t = read_back(&path);
    assert_eq!(
        t.keys().collect::<Vec<_>>(),
        ["", "Deleted Items", "Inbox", "Inbox/Projekte 2026 – ä", "Many"]
    );
    assert_eq!(t["Inbox"][0].0, "first");
    assert_eq!(t["Inbox"][0].1, ["Bob", "Carol"]);
    assert_eq!(t["Inbox"][0].2, [("a.bin".to_owned(), small)]);
    let second = &t["Inbox/Projekte 2026 – ä"][0];
    assert_eq!(second.0, "second");
    assert_eq!(second.2[0], ("b.bin".to_owned(), heap));
    assert_eq!(second.2[1], ("c.bin".to_owned(), xblock));
    assert_eq!(second.2[2].1.len(), xxblock.len());
    assert!(second.2[2].1 == xxblock, "XXBLOCK attachment");
    assert_eq!(t["Deleted Items"][0].0, "gone");
    let mut subjects: Vec<&str> = t["Many"].iter().map(|m| m.0.as_str()).collect();
    subjects.sort();
    assert_eq!(subjects.len(), 1200);
    assert!(subjects[1199].starts_with("m1199"));
}

/// The AMaps we write equal the ones outlook-pst rebuilds from the B-trees ([MS-PST]
/// 2.6.1.3.7), and its header / page CRC checks pass.
#[test]
fn allocation_maps_match_a_rebuild() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("a.pst");
    let mut w = PstWriter::new(File::create(&path).unwrap(), "x", [1; 16]).unwrap();
    let f = w.folder(&["Inbox".into()]);
    for i in 0..300 {
        w.add_message(
            f,
            message(&format!("s{i}"), i, vec![("p.bin".into(), pattern(5000 + 97 * i, 9))]),
        )
        .unwrap();
    }
    w.finish().unwrap();
    let ours = std::fs::read(&path).unwrap();
    // mark the AMaps invalid (header CRCs recomputed) and let outlook-pst rebuild them
    let mut bad = ours.clone();
    bad[180 + 68] = 0;
    let crc = |b: &[u8]| m365_plugin::pst::ndb::crc(b);
    let p = crc(&bad[8..8 + 471]);
    bad[4..8].copy_from_slice(&p.to_le_bytes());
    let full = crc(&bad[8..524]);
    bad[524..528].copy_from_slice(&full.to_le_bytes());
    let rebuilt = d.path().join("b.pst");
    std::fs::write(&rebuilt, &bad).unwrap();
    {
        let mut pst = UnicodePstFile::open(&rebuilt).unwrap();
        let _guard = pst.lock().unwrap();
    }
    let theirs = std::fs::read(&rebuilt).unwrap();
    assert_eq!(theirs[180 + 68], 2, "outlook-pst rebuilt the AMaps");
    let span = 496 * 8 * 64;
    let mut at = 0x4400;
    let mut n = 0;
    while at < ours.len() {
        assert_eq!(&ours[at..at + 496], &theirs[at..at + 496], "AMap at {at:#x}");
        at += span;
        n += 1;
    }
    assert!(n >= 2, "the test spans several AMap regions");
    // free space as rebuilt
    assert_eq!(&ours[180 + 20..180 + 28], &theirs[180 + 20..180 + 28], "cbAMapFree");
}

/// Attachments whose sizes sit on every heap / data-tree boundary (heap item limit
/// 3580, one block 8176, XBLOCK, full XBLOCK of 1021 blocks, XXBLOCK), in both
/// orders and one per message, read back byte for byte by outlook-pst.
#[test]
fn attachments_at_block_boundaries() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("b.pst");
    let mut w = PstWriter::new(File::create(&path).unwrap(), "Boundaries", [3; 16]).unwrap();
    let f = w.folder(&["Inbox".into()]);
    let full = 1021 * 8176;
    let sizes = [1, 3580, 3581, 8175, 8176, 8177, 16352, 16353, 300_000, full, full + 1];
    let files: Vec<(String, Vec<u8>)> = sizes
        .iter()
        .enumerate()
        .map(|(k, &n)| (format!("a{k:02}-{n}.bin"), pattern(n, k as u8)))
        .collect();
    w.add_message(f, message("ascending", 0, files.clone())).unwrap();
    let mut rev = files.clone();
    rev.reverse();
    w.add_message(f, message("descending", 1, rev.clone())).unwrap();
    for (k, file) in files.iter().enumerate() {
        w.add_message(f, message(&format!("single {k}"), 2 + k, vec![file.clone()]))
            .unwrap();
    }
    w.finish().unwrap();
    if let Ok(keep) = std::env::var("NEXUS_PST_KEEP") {
        std::fs::copy(&path, keep).unwrap(); // for looking at it with other readers
    }
    let t = read_back(&path);
    let inbox = &t["Inbox"];
    assert_eq!(inbox.len(), 2 + sizes.len());
    let find = |s: &str| &inbox.iter().find(|m| m.0 == s).unwrap().2;
    assert!(*find("ascending") == files, "ascending");
    assert!(*find("descending") == rev, "descending");
    for (k, file) in files.iter().enumerate() {
        assert!(find(&format!("single {k}"))[0] == *file, "{}", file.0);
    }
}
