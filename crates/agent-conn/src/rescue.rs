//! Bare-metal recovery onto a rescue agent (docs/bmr.md "Recovery steps"):
//! `RescueApply` with the layout stored in the host snapshot → the ordinary
//! restore stream of the whole snapshot into the target the rescue agent named →
//! `RescueFinish` (boot loader, initramfs, optional reboot).
//!
//! The rescue agent has its own temporary identity; the restore keeps the full
//! metadata of the original host (owners, setuid bits, devices, SELinux labels),
//! because the target *is* that host.

use crate::map::MapDb;
use crate::restore::{self, Spec as RestoreSpec};
use crate::tls::Session;
use crate::{name, source_name};
use agent_proto::layout::{Layout, LAYOUT_PATH};
use agent_proto::{Message, Overwrite, ScanStats, CAP_RESCUE};
use anyhow::{bail, Context, Result};
use chunkstore::{Index, Store, TreeKind};

pub struct Spec {
    pub job: u64,
    /// the original agent (`host-<id>` snapshot)
    pub agent: String,
    pub time: u64,
    pub reboot: bool,
}

/// The layout JSON of `host-<agent>/<time>` (`.nexus-system/layout.json`).
pub fn load_layout(store: &Store, agent: &str, time: u64) -> Result<String> {
    let m = store.load_manifest(&source_name(agent), time)?;
    let Index::Tree { entries } = store.load_index(&m, crate::TREE_INDEX)? else {
        bail!("{}/{time} is not a file tree snapshot", m.source);
    };
    let e = entries
        .iter()
        .find(|e| e.path == LAYOUT_PATH.as_bytes() && e.kind == TreeKind::File)
        .with_context(|| {
            format!(
                "{}/{time} has no machine layout ({LAYOUT_PATH}): it was taken by an agent without layout support (update the agent) or the layout could not be recorded",
                m.source
            )
        })?;
    if e.size > agent_proto::MAX_LAYOUT as u64 {
        bail!("{LAYOUT_PATH} is too large");
    }
    let mut out = Vec::with_capacity(e.size as usize);
    store.write_chunks(&e.chunks, &mut out)?;
    let json = String::from_utf8(out).context("layout is not UTF-8")?;
    serde_json::from_str::<Layout>(&json).context("layout")?;
    Ok(json)
}

fn answer(s: &mut Session, what: &str, job: u64, log: &mut dyn FnMut(&str)) -> Result<String> {
    match s.recv()? {
        Message::RescueDone {
            job: j,
            target,
            log: text,
        } if j == job => {
            for l in text.lines() {
                log(&format!("rescue: {l:?}"));
            }
            Ok(target)
        }
        Message::Error { message, .. } => {
            for l in message.lines() {
                log(&format!("rescue: {l:?}"));
            }
            bail!(
                "{what} failed on the rescue agent: {}",
                message.lines().last().unwrap_or_default()
            )
        }
        m => bail!("unexpected answer to {what}: {}", name(&m)),
    }
}

/// #19: every image of the snapshot written to its partition on the rescue agent (`BlockWrite` to target n of
/// [`Layout::image_order`]). Zero blocks are skipped only when the rescue agent zeroed the partitions first
/// (CAP_IMAGE_ZEROED): otherwise a reused disk's old data would stay where the image has zeros.
fn write_images(
    store: &Store,
    s: &mut Session,
    spec: &Spec,
    l: &agent_proto::layout::Layout,
    log: &mut dyn FnMut(&str),
) -> Result<()> {
    use agent_proto::{BLOCK_SIZE, MAX_BLOCK_TARGET};
    use chunkstore::Index;
    let m = store.load_manifest(&source_name(&spec.agent), spec.time)?;
    // a rescue agent that zeroed the partitions: the zero blocks (free space) need not travel
    let skip_zero = s.has_cap(agent_proto::CAP_IMAGE_ZEROED);
    for (k, (_, p)) in l.image_order().into_iter().enumerate() {
        let target = u32::try_from(k + 1).unwrap_or(u32::MAX);
        if target > MAX_BLOCK_TARGET {
            bail!("more than {MAX_BLOCK_TARGET} images");
        }
        let Index::Fixed { size, chunks, .. } = store
            .load_index(&m, &p.image)
            .with_context(|| format!("image {} is not in the snapshot", p.image))?
        else {
            bail!("{} is not an image", p.image);
        };
        let bjob = spec.job * 16 + u64::from(target);
        let (mut sent, mut skipped) = (0u64, 0u64);
        for (i, id) in chunks.iter().enumerate() {
            let mut block = store.read_chunk(id)?;
            if skip_zero && block.iter().all(|b| *b == 0) {
                skipped += 1;
                continue;
            }
            // the last block: no further than the image
            let end = size.saturating_sub(i as u64 * BLOCK_SIZE).min(BLOCK_SIZE) as usize;
            block.truncate(end);
            s.send(&Message::BlockWrite {
                job: bjob,
                target,
                offset: i as u64 * BLOCK_SIZE,
                data: block,
            })?;
            sent += 1;
        }
        s.send(&Message::BlockWriteEnd { job: bjob, target })?;
        match s.recv()? {
            Message::BlockWritten { job: j, bytes } if j == bjob => {
                log(&format!(
                    "image {}: {sent} blocks written ({bytes} bytes), {skipped} zero blocks skipped, to partition {}",
                    p.image, p.number
                ));
            }
            Message::Error { message, .. } => bail!("image {}: {message}", p.image),
            m => bail!("unexpected answer to BlockWriteEnd: {}", name(&m)),
        }
    }
    Ok(())
}

/// Runs the recovery on a connected rescue agent. `step` gets `apply`, `restore`,
/// `finish` as they begin (the scheduler shows them as progress).
pub fn recover(
    store: &Store,
    map: &MapDb,
    s: &mut Session,
    spec: &Spec,
    log: &mut dyn FnMut(&str),
    step: &mut dyn FnMut(&str),
) -> Result<ScanStats> {
    if !s.has_cap(CAP_RESCUE) {
        bail!("the agent is not a rescue agent (boot the machine from the rescue ISO)");
    }
    let layout = load_layout(store, &spec.agent, spec.time)?;
    let parsed: agent_proto::layout::Layout = serde_json::from_str(&layout).context("the snapshot's layout")?;
    let imaged = !parsed.image_order().is_empty();
    if imaged && !s.has_cap(agent_proto::CAP_VOLUME_IMAGE) {
        bail!("this snapshot restores from volume images (Windows): boot a rescue ISO from this release or newer");
    }
    step("apply");
    s.send(&Message::RescueApply { job: spec.job, layout })?;
    let target = answer(s, "RescueApply", spec.job, log)?;
    step("restore");
    if imaged {
        write_images(store, s, spec, &parsed, log)?;
        step("finish");
        s.send(&Message::RescueFinish {
            job: spec.job,
            reboot: spec.reboot,
        })?;
        answer(s, "RescueFinish", spec.job, log)?;
        return Ok(ScanStats::default());
    }
    let st = restore::restore(
        store,
        map,
        s,
        &RestoreSpec {
            job: spec.job,
            source: source_name(&spec.agent),
            time: spec.time,
            paths: vec!["/".into()],
            target,
            overwrite: Overwrite::Always,
            confirm: format!("bare-metal recovery, job {}", spec.job),
            // the snapshot's own host: full metadata
            target_agent: spec.agent.clone(),
        },
        log,
    )?;
    if !st.errors.is_empty() {
        for e in st.errors.iter().take(50) {
            log(&format!("restore error: {e:?}"));
        }
        log(&format!(
            "warning: {} entries could not be restored (listed above, at most 50)",
            st.errors.len()
        ));
    }
    step("finish");
    s.send(&Message::RescueFinish {
        job: spec.job,
        reboot: spec.reboot,
    })?;
    answer(s, "RescueFinish", spec.job, log)?;
    Ok(st)
}
