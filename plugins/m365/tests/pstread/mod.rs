//! Reads a PST back with Microsoft's `outlook-pst` crate (shared by the tests).
#![allow(dead_code)]

use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::messaging::attachment::{Attachment, AttachmentData, UnicodeAttachment};
use outlook_pst::messaging::message::{Message as _, UnicodeMessage};
use outlook_pst::messaging::store::{EntryId, Store, UnicodeStore};
use outlook_pst::ndb::node_id::NodeId;
use outlook_pst::UnicodePstFile;
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

pub fn text(v: Option<&PropertyValue>) -> String {
    match v {
        Some(PropertyValue::Unicode(u)) => u.to_string(),
        Some(PropertyValue::String8(u)) => u.to_string(),
        other => panic!("not a string: {other:?}"),
    }
}

/// folder path → (subject, recipient names, attachments) of every message, read with outlook-pst.
pub type Tree = BTreeMap<String, Vec<(String, Vec<String>, Vec<(String, Vec<u8>)>)>>;

pub fn read_back(path: &Path) -> Tree {
    let pst = Rc::new(UnicodePstFile::open(path).unwrap());
    let store = UnicodeStore::read(pst).unwrap();
    let ipm = store.properties().ipm_sub_tree_entry_id().unwrap();
    let mut out = Tree::new();
    let mut stack = vec![(String::new(), ipm)];
    while let Some((name, id)) = stack.pop() {
        let folder = store.open_folder(&id).unwrap();
        if let Some(h) = folder.hierarchy_table() {
            for row in h.rows_matrix() {
                let child = store
                    .properties()
                    .make_entry_id(NodeId::from(u32::from(row.id())))
                    .unwrap();
                let f = store.open_folder(&child).unwrap();
                let n = f.properties().display_name().unwrap();
                stack.push((if name.is_empty() { n } else { format!("{name}/{n}") }, child));
            }
        }
        let Some(ct) = folder.contents_table() else { continue };
        let msgs = out.entry(name.clone()).or_default();
        let count = folder.properties().content_count().unwrap();
        assert_eq!(count as usize, ct.rows_matrix().count(), "{name}: content count");
        for row in ct.rows_matrix() {
            let eid = EntryId::new(
                store.properties().record_key().unwrap(),
                NodeId::from(u32::from(row.id())),
            );
            let m = UnicodeMessage::read(store.clone(), &eid, None).unwrap();
            let subject = text(m.properties().get(0x0037));
            let mut rcpts = Vec::new();
            if let Some(rt) = m.recipient_table() {
                let ctx = rt.context();
                for r in rt.rows_matrix() {
                    for (col, v) in ctx.columns().iter().zip(r.columns(ctx).unwrap()) {
                        if col.prop_id() == 0x3001 {
                            let v = rt.read_column(&v.unwrap(), col.prop_type()).unwrap();
                            rcpts.push(text(Some(&v)));
                        }
                    }
                }
            }
            let mut atts = Vec::new();
            if let Some(at) = m.attachment_table() {
                for r in at.rows_matrix() {
                    let a = UnicodeAttachment::read(m.clone(), NodeId::from(u32::from(r.id())), None).unwrap();
                    let name = text(a.properties().get(0x3707));
                    let data = match a.data() {
                        Some(AttachmentData::Binary(b)) => b.buffer().to_vec(),
                        _ => panic!("attachment without binary data"),
                    };
                    atts.push((name, data));
                }
            }
            msgs.push((subject, rcpts, atts));
        }
    }
    out
}
