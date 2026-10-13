//! Tray and window icons: the web UI logo (web/src/favicon.svg) with a state badge in the
//! lower right corner, rasterised with tiny-skia (no image files to ship).

use crate::model::Badge;
use tiny_skia::{Color, FillRule, LineCap, LineJoin, Paint, PathBuilder, Pixmap, Stroke, Transform};

fn paint(rgb: u32) -> Paint<'static> {
    let mut p = Paint::default();
    p.set_color(Color::from_rgba8((rgb >> 16) as u8, (rgb >> 8) as u8, rgb as u8, 255));
    p.anti_alias = true;
    p
}

fn stroke(width: f32) -> Stroke {
    Stroke {
        width,
        line_cap: LineCap::Round,
        line_join: LineJoin::Round,
        ..Stroke::default()
    }
}

/// Badge colour (RGB), shared with the window's status card.
pub fn badge_color(b: Badge) -> u32 {
    match b {
        Badge::None => 0x0d1b2e,
        Badge::Clock => 0x2563eb,
        Badge::Play => 0x2563eb,
        Badge::Check => 0x1f9d55,
        Badge::Warn => 0xe0a100,
        Badge::Cross => 0xd13438,
        Badge::Stop => 0x7a7a7a,
        Badge::Offline => 0x6b7280,
    }
}

/// Straight RGBA pixels (size × size × 4) of the logo with `badge`.
pub fn rgba(badge: Badge, size: u32) -> Vec<u8> {
    let mut pm = Pixmap::new(size, size).expect("icon size > 0");
    let t = Transform::from_scale(size as f32 / 32.0, size as f32 / 32.0);

    // rounded square, teal "N", white dot (favicon.svg)
    let bg = rounded_rect(0.0, 0.0, 32.0, 32.0, 8.0);
    pm.fill_path(&bg, &paint(0x0d1b2e), FillRule::Winding, t, None);
    let mut n = PathBuilder::new();
    n.move_to(9.5, 22.5);
    n.line_to(9.5, 9.5);
    n.line_to(22.5, 22.5);
    n.line_to(22.5, 9.5);
    pm.stroke_path(&n.finish().unwrap(), &paint(0x2ec4b2), &stroke(3.2), t, None);
    let dot = PathBuilder::from_circle(22.5, 9.5, 2.6).unwrap();
    pm.fill_path(&dot, &paint(0xffffff), FillRule::Winding, t, None);

    if badge != Badge::None {
        let (cx, cy, r) = (23.0, 23.0, 8.5);
        let ring = PathBuilder::from_circle(cx, cy, r + 1.2).unwrap();
        pm.fill_path(&ring, &paint(0xffffff), FillRule::Winding, t, None);
        let disc = PathBuilder::from_circle(cx, cy, r).unwrap();
        pm.fill_path(&disc, &paint(badge_color(badge)), FillRule::Winding, t, None);
        let glyph = if badge == Badge::Warn { 0x1a1a1a } else { 0xffffff };
        let mut g = PathBuilder::new();
        match badge {
            Badge::Check => {
                g.move_to(19.0, 23.2);
                g.line_to(22.0, 26.2);
                g.line_to(27.2, 19.8);
            }
            Badge::Cross => {
                g.move_to(19.8, 19.8);
                g.line_to(26.2, 26.2);
                g.move_to(26.2, 19.8);
                g.line_to(19.8, 26.2);
            }
            Badge::Warn => {
                g.move_to(23.0, 18.8);
                g.line_to(23.0, 23.6);
                g.move_to(23.0, 27.0);
                g.line_to(23.0, 27.1);
            }
            Badge::Clock => {
                g.move_to(23.0, 18.5);
                g.line_to(23.0, 23.0);
                g.line_to(26.5, 25.0);
            }
            Badge::Stop => {
                g.move_to(19.5, 23.0);
                g.line_to(26.5, 23.0);
            }
            Badge::Offline => {
                g.move_to(19.5, 26.5);
                g.line_to(26.5, 19.5);
            }
            Badge::Play | Badge::None => {}
        }
        if badge == Badge::Play {
            let mut p = PathBuilder::new();
            p.move_to(20.8, 18.8);
            p.line_to(27.4, 23.0);
            p.line_to(20.8, 27.2);
            p.close();
            pm.fill_path(&p.finish().unwrap(), &paint(glyph), FillRule::Winding, t, None);
        } else if let Some(g) = g.finish() {
            pm.stroke_path(&g, &paint(glyph), &stroke(2.4), t, None);
        }
    }

    // tiny-skia stores premultiplied RGBA; tray and window icons take straight alpha
    pm.pixels()
        .iter()
        .flat_map(|p| {
            let c = p.demultiply();
            [c.red(), c.green(), c.blue(), c.alpha()]
        })
        .collect()
}

fn rounded_rect(x: f32, y: f32, w: f32, h: f32, r: f32) -> tiny_skia::Path {
    const K: f32 = 0.552_284_8; // circle approximation with cubic Béziers
    let mut pb = PathBuilder::new();
    pb.move_to(x + r, y);
    pb.line_to(x + w - r, y);
    pb.cubic_to(x + w - r + r * K, y, x + w, y + r - r * K, x + w, y + r);
    pb.line_to(x + w, y + h - r);
    pb.cubic_to(x + w, y + h - r + r * K, x + w - r + r * K, y + h, x + w - r, y + h);
    pb.line_to(x + r, y + h);
    pb.cubic_to(x + r - r * K, y + h, x, y + h - r + r * K, x, y + h - r);
    pb.line_to(x, y + r);
    pb.cubic_to(x, y + r - r * K, x + r - r * K, y, x + r, y);
    pb.close();
    pb.finish().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn px(img: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let i = ((y * size + x) * 4) as usize;
        img[i..i + 4].try_into().unwrap()
    }

    #[test]
    fn logo_and_badges() {
        let plain = rgba(Badge::None, 32);
        assert_eq!(plain.len(), 32 * 32 * 4);
        assert_eq!(px(&plain, 32, 0, 0)[3], 0, "rounded corner is transparent");
        assert_eq!(px(&plain, 32, 16, 2), [0x0d, 0x1b, 0x2e, 255]);
        // every badge has its own colour in the badge area, distinct icons per state
        let all = [
            Badge::Clock,
            Badge::Play,
            Badge::Check,
            Badge::Warn,
            Badge::Cross,
            Badge::Stop,
            Badge::Offline,
        ];
        let imgs: Vec<Vec<u8>> = all.iter().map(|b| rgba(*b, 32)).collect();
        for (i, a) in imgs.iter().enumerate() {
            assert_ne!(a, &plain);
            for b in &imgs[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_eq!(rgba(Badge::Check, 64).len(), 64 * 64 * 4);
    }
}
