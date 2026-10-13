//! dist/nexus-agent-gui.ico (Windows exe resource via build.rs, MSI shortcut and Add/Remove
//! Programs icon) is the plain logo of src/icon.rs, the same artwork as
//! dist/nexus-agent-gui.svg (Linux). Committed, so the Windows build needs no image tools;
//! this test fails when it is out of date. Regenerate with
//!   UPDATE_ICONS=1 cargo test -p agent-gui --test icon_files

use nexus_agent_gui::{icon, model::Badge};
use std::path::Path;

/// Shell sizes at 100–200 % scaling; 256 as PNG (Vista+), the others as 32-bit DIBs, which
/// every consumer (Explorer, msiexec, windres) reads.
const SIZES: [u32; 8] = [16, 20, 24, 32, 40, 48, 64, 256];

fn dib(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mask_row = size.div_ceil(32) * 4;
    let mut out = Vec::new();
    for v in [40u32, size, size * 2] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&1u16.to_le_bytes()); // planes
    out.extend_from_slice(&32u16.to_le_bytes()); // bits per pixel
    out.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
    out.extend_from_slice(&(size * size * 4 + mask_row * size).to_le_bytes());
    // resolution, palette
    out.extend_from_slice(&[0; 16]);
    // bottom-up BGRA, then the AND mask (1 = transparent), also bottom-up
    for y in (0..size).rev() {
        for x in 0..size {
            let i = ((y * size + x) * 4) as usize;
            out.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    for y in (0..size).rev() {
        let mut row = vec![0u8; mask_row as usize];
        for x in 0..size {
            if rgba[((y * size + x) * 4 + 3) as usize] == 0 {
                row[(x / 8) as usize] |= 0x80 >> (x % 8);
            }
        }
        out.extend_from_slice(&row);
    }
    out
}

fn png(size: u32, rgba: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = png::Encoder::new(&mut out, size, size);
    e.set_color(png::ColorType::Rgba);
    e.set_compression(png::Compression::High);
    e.write_header().unwrap().write_image_data(rgba).unwrap();
    out
}

fn ico() -> Vec<u8> {
    let images: Vec<(u32, Vec<u8>)> = SIZES
        .iter()
        .map(|&s| {
            let px = icon::rgba(Badge::None, s);
            (s, if s >= 256 { png(s, &px) } else { dib(s, &px) })
        })
        .collect();
    let mut out = vec![0, 0, 1, 0]; // reserved, type 1 = icon
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (s, data) in &images {
        let dim = if *s >= 256 { 0 } else { *s as u8 };
        out.extend_from_slice(&[dim, dim, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for (_, data) in &images {
        out.extend_from_slice(data);
    }
    out
}

#[test]
fn windows_icon_is_current() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("dist/nexus-agent-gui.ico");
    let want = ico();
    if std::env::var_os("UPDATE_ICONS").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read(&path).unwrap_or_default();
    assert!(
        have == want,
        "{} is out of date with src/icon.rs: UPDATE_ICONS=1 cargo test -p agent-gui --test icon_files",
        path.display()
    );
}
