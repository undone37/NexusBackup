//! A Unicode PST writer for mail ([MS-PST]): the messaging layer on top of the LTP
//! ([`ltp`]) and NDB ([`ndb`]) layers. It creates the minimal PST of [MS-PST] 2.7
//! (message store, name-to-id map, templates, root folder, "Top of Personal
//! Folders", "Deleted Items", search root, spam search folder, search queues) plus
//! the caller's folders below "Top of Personal Folders" and their messages
//! (`IPM.Note`: properties, recipient table, attachments). Messages are written as
//! they come; folders and their tables at [`PstWriter::finish`]. No named
//! properties, no encryption.

pub mod ltp;
pub mod ndb;

use ltp::{pc, tc, Built, SubData, SubIds, SubNode, Val};
use ndb::{NbtEntry, Ndb, SubEntry};
use std::collections::HashMap;
use std::io::{self, Seek, Write};

const NID_MESSAGE_STORE: u32 = 0x21;
const NID_NAME_TO_ID_MAP: u32 = 0x61;
const NID_ROOT_FOLDER: u32 = 0x122;
const NID_SEARCH_MANAGEMENT_QUEUE: u32 = 0x1E1;
const NID_SEARCH_ACTIVITY_LIST: u32 = 0x201;
const NID_HIERARCHY_TABLE_TEMPLATE: u32 = 0x60D;
const NID_CONTENTS_TABLE_TEMPLATE: u32 = 0x60E;
const NID_ASSOC_CONTENTS_TABLE_TEMPLATE: u32 = 0x60F;
const NID_SEARCH_CONTENTS_TABLE_TEMPLATE: u32 = 0x610;
const NID_ATTACHMENT_TABLE: u32 = 0x671;
const NID_RECIPIENT_TABLE: u32 = 0x692;
const NID_SPAM_SEARCH_FOLDER: u32 = 0x2223;
const NID_IPM_SUBTREE: u32 = 0x8022;
const NID_SEARCH_ROOT: u32 = 0x8042;
const NID_DELETED_ITEMS: u32 = 0x8062;

const NID_TYPE_NORMAL_FOLDER: u32 = 0x02;
const NID_TYPE_NORMAL_MESSAGE: u32 = 0x04;
const NID_TYPE_ATTACHMENT: u32 = 0x05;
const NID_TYPE_HIERARCHY_TABLE: u32 = 0x0D;
const NID_TYPE_CONTENTS_TABLE: u32 = 0x0E;
const NID_TYPE_ASSOC_CONTENTS_TABLE: u32 = 0x0F;

// property ids used here
pub const DISPLAY_NAME: u16 = 0x3001;
const CONTENT_COUNT: u16 = 0x3602;
const CONTENT_UNREAD: u16 = 0x3603;
const SUBFOLDERS: u16 = 0x360A;
const CONTAINER_CLASS: u16 = 0x3613;

/// [MS-PST] 2.4.4.4.1
const HIERARCHY_COLS: &[u32] = &[
    0x0E30_0003,
    0x0E33_0014,
    0x0E34_0102,
    0x0E38_0003,
    0x3001_001F,
    0x3602_0003,
    0x3603_0003,
    0x360A_000B,
    0x3613_001F,
    0x6635_0003,
    0x6636_0003,
];
/// [MS-PST] 2.4.4.5.1
const CONTENTS_COLS: &[u32] = &[
    0x0017_0003,
    0x001A_001F,
    0x0036_0003,
    0x0037_001F,
    0x0039_0040,
    0x0042_001F,
    0x0057_000B,
    0x0058_000B,
    0x0070_001F,
    0x0071_0102,
    0x0E03_001F,
    0x0E04_001F,
    0x0E06_0040,
    0x0E07_0003,
    0x0E08_0003,
    0x0E17_0003,
    0x0E30_0003,
    0x0E33_0014,
    0x0E34_0102,
    0x0E38_0003,
    0x0E3C_0102,
    0x0E3D_0102,
    0x1097_0003,
    0x3008_0040,
    0x65C6_0003,
];
/// [MS-PST] 2.4.4.6.1
const ASSOC_COLS: &[u32] = &[
    0x001A_001F,
    0x0E07_0003,
    0x0E17_0003,
    0x3001_001F,
    0x6800_001F,
    0x6803_000B,
    0x6805_1003,
    0x7003_0003,
    0x7004_0102,
    0x7005_0102,
    0x7006_001F,
    0x7007_0003,
];
/// [MS-PST] 2.4.8.6.2.1
const SEARCH_CONTENTS_COLS: &[u32] = &[
    0x0017_0003,
    0x001A_001F,
    0x0036_0003,
    0x0037_001F,
    0x0042_001F,
    0x0057_000B,
    0x0E03_001F,
    0x0E04_001F,
    0x0E05_001F,
    0x0E06_0040,
    0x0E07_0003,
    0x0E08_0003,
    0x0E17_0003,
    0x0E2A_000B,
    0x3008_0040,
    0x67F1_0003,
];
/// [MS-PST] 2.4.5.3.1 plus the SMTP address
pub const RECIPIENT_COLS: &[u32] = &[
    0x0C15_0003,
    0x0E0F_000B,
    0x0FF9_0102,
    0x0FFE_0003,
    0x0FFF_0102,
    0x3001_001F,
    0x3002_001F,
    0x3003_001F,
    0x300B_0102,
    0x3900_0003,
    0x39FE_001F,
    0x39FF_001F,
    0x3A40_000B,
    0x5FFD_0003,
];
/// [MS-PST] 2.4.6.1.1 plus long file name and MIME type
pub const ATTACHMENT_COLS: &[u32] = &[
    0x0E20_0003,
    0x3704_001F,
    0x3705_0003,
    0x370B_0003,
    0x3707_001F,
    0x370E_001F,
];

/// A message to write: its properties, recipients (one property list each) and
/// attachments (property lists including `PidTagAttachDataBinary`).
#[derive(Default)]
pub struct Message {
    pub props: Vec<(u16, Val)>,
    pub recipients: Vec<Vec<(u16, Val)>>,
    pub attachments: Vec<Vec<(u16, Val)>>,
}

struct Folder {
    nid: u32,
    parent: u32,
    name: String,
    class: Option<String>,
    children: Vec<u32>,
    rows: Vec<(u32, Vec<(u32, Val)>)>,
}

/// The tag (id + type) of a property.
fn tag(id: u16, v: &Val) -> u32 {
    (u32::from(id) << 16) | u32::from(v.ptype())
}

fn row_of(props: &[(u16, Val)], cols: &[u32]) -> Vec<(u32, Val)> {
    props
        .iter()
        .map(|(id, v)| (tag(*id, v), v.clone()))
        .filter(|(t, _)| cols.contains(t))
        .collect()
}

pub struct PstWriter<W: Write + Seek> {
    ndb: Ndb<W>,
    uid: [u8; 16],
    name: String,
    folders: HashMap<u32, Folder>,
    by_path: HashMap<Vec<String>, u32>,
    next_folder: u32,
    next_message: u32,
    pub messages: u64,
}

impl<W: Write + Seek> PstWriter<W> {
    /// A new PST named `name` (the store's display name); `uid`: its provider UID.
    pub fn new(w: W, name: &str, uid: [u8; 16]) -> io::Result<PstWriter<W>> {
        let mut p = PstWriter {
            ndb: Ndb::new(w)?,
            uid,
            name: name.into(),
            folders: HashMap::new(),
            by_path: HashMap::new(),
            next_folder: 0x404,
            next_message: 0x10000,
            messages: 0,
        };
        let mut add = |nid, parent, name: &str, class: Option<&str>| {
            p.folders.insert(
                nid,
                Folder {
                    nid,
                    parent,
                    name: name.into(),
                    class: class.map(str::to_owned),
                    children: Vec::new(),
                    rows: Vec::new(),
                },
            );
        };
        add(NID_ROOT_FOLDER, NID_ROOT_FOLDER, "", None);
        add(NID_IPM_SUBTREE, NID_ROOT_FOLDER, "Top of Personal Folders", None);
        add(NID_SEARCH_ROOT, NID_ROOT_FOLDER, "Search Root", None);
        add(NID_DELETED_ITEMS, NID_IPM_SUBTREE, "Deleted Items", Some("IPF.Note"));
        let root = p.folders.get_mut(&NID_ROOT_FOLDER).unwrap();
        root.children = vec![NID_IPM_SUBTREE, NID_SEARCH_ROOT, NID_SPAM_SEARCH_FOLDER];
        p.folders.get_mut(&NID_IPM_SUBTREE).unwrap().children = vec![NID_DELETED_ITEMS];
        p.by_path.insert(vec!["Deleted Items".into()], NID_DELETED_ITEMS);
        Ok(p)
    }

    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.ndb.size()
    }

    /// The folder at `path` below "Top of Personal Folders" (created with its parents;
    /// a top-level "Deleted Items" is the PST's own).
    pub fn folder(&mut self, path: &[String]) -> u32 {
        let mut parent = NID_IPM_SUBTREE;
        for i in 0..path.len() {
            let key = path[..=i].to_vec();
            if let Some(n) = self
                .by_path
                .get(&key)
                .copied()
                .or_else(|| (i == 0 && path[0].eq_ignore_ascii_case("Deleted Items")).then_some(NID_DELETED_ITEMS))
            {
                parent = n;
                continue;
            }
            self.next_folder += 1;
            let nid = (self.next_folder << 5) | NID_TYPE_NORMAL_FOLDER;
            self.folders.insert(
                nid,
                Folder {
                    nid,
                    parent,
                    name: path[i].clone(),
                    class: Some("IPF.Note".into()),
                    children: Vec::new(),
                    rows: Vec::new(),
                },
            );
            self.folders.get_mut(&parent).unwrap().children.push(nid);
            self.by_path.insert(key, nid);
            parent = nid;
        }
        parent
    }

    fn write_sub(&mut self, s: SubNode) -> io::Result<SubEntry> {
        let data = match &s.data {
            SubData::Blocks(b) => self.ndb.data_blocks(b)?,
            SubData::Raw(r) => self.ndb.data(r)?,
        };
        let mut subs = Vec::with_capacity(s.subs.len());
        for c in s.subs {
            subs.push(self.write_sub(c)?);
        }
        let sub = self.ndb.subnodes(subs)?;
        Ok(SubEntry { nid: s.nid, data, sub })
    }

    /// A top-level node (NBT entry) for built content.
    fn node(&mut self, nid: u32, parent: u32, b: Built) -> io::Result<()> {
        let data = self.ndb.data_blocks(&b.blocks)?;
        let mut subs = Vec::with_capacity(b.subs.len());
        for s in b.subs {
            subs.push(self.write_sub(s)?);
        }
        let sub = self.ndb.subnodes(subs)?;
        self.ndb.add_node(NbtEntry { nid, data, sub, parent });
        Ok(())
    }

    /// Writes a message into folder `folder` (from [`PstWriter::folder`]).
    pub fn add_message(&mut self, folder: u32, m: Message) -> io::Result<()> {
        self.next_message += 1;
        let nid = (self.next_message << 5) | NID_TYPE_NORMAL_MESSAGE;
        let mut ids = SubIds::default();
        let mut subs = Vec::new();
        let rec_rows: Vec<(u32, Vec<(u32, Val)>)> = m
            .recipients
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u32, row_of(r, RECIPIENT_COLS)))
            .collect();
        let rt = tc(RECIPIENT_COLS, &rec_rows, &mut ids);
        subs.push(SubNode {
            nid: NID_RECIPIENT_TABLE,
            data: SubData::Blocks(rt.blocks),
            subs: rt.subs,
        });
        if !m.attachments.is_empty() {
            let mut rows = Vec::new();
            for (i, a) in m.attachments.into_iter().enumerate() {
                let anid = ((i as u32 + 1) << 5) | NID_TYPE_ATTACHMENT;
                rows.push((anid, row_of(&a, ATTACHMENT_COLS)));
                let mut aids = SubIds::default();
                let b = pc(&a, &mut aids);
                subs.push(SubNode {
                    nid: anid,
                    data: SubData::Blocks(b.blocks),
                    subs: b.subs,
                });
            }
            let at = tc(ATTACHMENT_COLS, &rows, &mut ids);
            subs.push(SubNode {
                nid: NID_ATTACHMENT_TABLE,
                data: SubData::Blocks(at.blocks),
                subs: at.subs,
            });
        }
        let row = row_of(&m.props, CONTENTS_COLS);
        let b = pc(&m.props, &mut ids);
        subs.extend(b.subs);
        self.node(nid, folder, Built { blocks: b.blocks, subs })?;
        self.folders.get_mut(&folder).expect("folder").rows.push((nid, row));
        self.messages += 1;
        Ok(())
    }

    fn entry_id(&self, nid: u32) -> Val {
        let mut b = vec![0u8; 4];
        b.extend_from_slice(&self.uid);
        b.extend_from_slice(&nid.to_le_bytes());
        Val::Bin(b)
    }

    fn template(&mut self, nid: u32, cols: &[u32]) -> io::Result<()> {
        let b = tc(cols, &[], &mut SubIds::default());
        self.node(nid, 0, b)
    }

    /// Writes folders, tables, the store and the NDB metadata; returns the writer.
    pub fn finish(mut self) -> io::Result<W> {
        let store = vec![
            (0x0FF9, Val::Bin(self.uid.to_vec())),
            (DISPLAY_NAME, Val::Str(self.name.clone())),
            (0x35DF, Val::I32(0x89)),
            (0x35E0, self.entry_id(NID_IPM_SUBTREE)),
            (0x35E3, self.entry_id(NID_DELETED_ITEMS)),
            (0x35E7, self.entry_id(NID_SEARCH_ROOT)),
            (0x6633, Val::Bool(true)),
            (0x67FF, Val::I32(0)),
        ];
        let b = pc(&store, &mut SubIds::default());
        self.node(NID_MESSAGE_STORE, 0, b)?;
        // name-to-id map ([MS-PST] 2.4.7): bucket count, GUID / entry / string streams
        // and the hash bucket of one entry (PSETID_Common 0x8580; readers such as
        // libpff refuse a map without entries)
        let guid = [0x08, 0x20, 0x06, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
        let nameid = [0x80, 0x85, 0, 0, 3 << 1, 0, 0, 0];
        let bucket = 0x1000 + ((0x8580u32 ^ (3 << 1)) % 251) as u16;
        let b = pc(
            &[
                (0x0001, Val::I32(251)),
                (0x0002, Val::Bin(guid.to_vec())),
                (0x0003, Val::Bin(nameid.to_vec())),
                (0x0004, Val::Bin(Vec::new())),
                (bucket, Val::Bin(nameid.to_vec())),
            ],
            &mut SubIds::default(),
        );
        self.node(NID_NAME_TO_ID_MAP, 0, b)?;
        for nid in [NID_SEARCH_MANAGEMENT_QUEUE, NID_SEARCH_ACTIVITY_LIST] {
            self.ndb.add_node(NbtEntry {
                nid,
                data: 0,
                sub: 0,
                parent: 0,
            });
        }
        self.template(NID_HIERARCHY_TABLE_TEMPLATE, HIERARCHY_COLS)?;
        self.template(NID_CONTENTS_TABLE_TEMPLATE, CONTENTS_COLS)?;
        self.template(NID_ASSOC_CONTENTS_TABLE_TEMPLATE, ASSOC_COLS)?;
        let mut cols = SEARCH_CONTENTS_COLS.to_vec();
        cols.dedup();
        self.template(NID_SEARCH_CONTENTS_TABLE_TEMPLATE, &cols)?;
        self.template(NID_RECIPIENT_TABLE, RECIPIENT_COLS)?;
        self.template(NID_ATTACHMENT_TABLE, ATTACHMENT_COLS)?;
        let spam_props = vec![
            (DISPLAY_NAME, Val::Str("SPAM Search Folder 2".into())),
            (CONTENT_COUNT, Val::I32(0)),
            (CONTENT_UNREAD, Val::I32(0)),
            (SUBFOLDERS, Val::Bool(false)),
        ];
        let spam = pc(&spam_props, &mut SubIds::default());
        self.node(NID_SPAM_SEARCH_FOLDER, NID_ROOT_FOLDER, spam)?;
        // folder properties (also the parent's hierarchy row of each folder)
        let summary: HashMap<u32, Vec<(u16, Val)>> = self
            .folders
            .values()
            .map(|f| {
                let mut p = vec![
                    (DISPLAY_NAME, Val::Str(f.name.clone())),
                    (CONTENT_COUNT, Val::I32(f.rows.len() as i32)),
                    (CONTENT_UNREAD, Val::I32(0)),
                    (SUBFOLDERS, Val::Bool(!f.children.is_empty())),
                ];
                if let Some(c) = &f.class {
                    p.push((CONTAINER_CLASS, Val::Str(c.clone())));
                }
                (f.nid, p)
            })
            .chain(std::iter::once((NID_SPAM_SEARCH_FOLDER, spam_props.clone())))
            .collect();
        let mut nids: Vec<u32> = self.folders.keys().copied().collect();
        nids.sort_unstable();
        for nid in nids {
            let f = self.folders.remove(&nid).unwrap();
            let b = pc(&summary[&nid], &mut SubIds::default());
            self.node(f.nid, f.parent, b)?;
            let rows: Vec<(u32, Vec<(u32, Val)>)> = f
                .children
                .iter()
                .map(|c| (*c, row_of(&summary[c], HIERARCHY_COLS)))
                .collect();
            let idx = nid >> 5;
            let b = tc(HIERARCHY_COLS, &rows, &mut SubIds::default());
            self.node((idx << 5) | NID_TYPE_HIERARCHY_TABLE, 0, b)?;
            let b = tc(CONTENTS_COLS, &f.rows, &mut SubIds::default());
            self.node((idx << 5) | NID_TYPE_CONTENTS_TABLE, 0, b)?;
            let b = tc(ASSOC_COLS, &[], &mut SubIds::default());
            self.node((idx << 5) | NID_TYPE_ASSOC_CONTENTS_TABLE, 0, b)?;
        }
        self.ndb.finish()
    }
}
