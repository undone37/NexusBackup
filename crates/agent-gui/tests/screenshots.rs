//! Headless rendering of the Control Panel (iced_test, tiny-skia) with demo data.
//!
//! Always: renders the window light and dark (no panic, sane pixels).
//! Manual screenshots: `cargo test -p agent-gui --test screenshots -- --ignored` writes
//! manual/images/desktop-agent-{window,window-dark,tray-states}.png.

use iced::window;
use iced_test::simulator;
use nexus_agent_gui::app::App;
use nexus_agent_gui::{demo, icon, model, palette};
use std::path::{Path, PathBuf};

const NOW: u64 = 1_791_900_000; // fixed: identical screenshots on every run

fn demo_app(dark: bool) -> App {
    let snap = demo::snapshot(NOW);
    let sel = snap.sessions[7].clone();
    let app = App::with_snapshot(snap, Some(sel.id), Some(demo::detail(&sel)));
    if dark {
        app.dark()
    } else {
        app
    }
}

/// Renders into `dir/name.png` (iced_test appends the renderer name; renamed back).
fn render(app: &App, dir: &Path, name: &str) -> PathBuf {
    let id = window::Id::unique();
    let theme = app.theme(id);
    let size = window_size();
    let mut sim = simulator::Simulator::with_size(iced::Settings::default(), size, app.view(id));
    let snap = sim.snapshot(&theme).expect("snapshot");
    let _ = std::fs::remove_dir_all(dir.join("tmp"));
    assert!(snap.matches_image(dir.join("tmp").join(name)).unwrap());
    let written = std::fs::read_dir(dir.join("tmp"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let out = dir.join(format!("{name}.png"));
    std::fs::rename(written, &out).unwrap();
    std::fs::remove_dir_all(dir.join("tmp")).unwrap();
    out
}

fn window_size() -> iced::Size {
    nexus_agent_gui::app::window_settings().size
}

fn decode(path: &Path) -> (u32, u32, Vec<u8>) {
    let d = png::Decoder::new(std::io::BufReader::new(std::fs::File::open(path).unwrap()));
    let mut r = d.read_info().unwrap();
    let mut buf = vec![0; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

#[test]
fn control_panel_renders_light_and_dark() {
    let dir = std::env::temp_dir().join(format!("nexus-agent-gui-shots-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut means = Vec::new();
    for dark in [false, true] {
        let p = render(&demo_app(dark), &dir, if dark { "dark" } else { "light" });
        let (w, h, px) = decode(&p);
        assert_eq!((w, h), (1920, 1520), "2x scale of the 960x760 window");
        let mean = px
            .chunks(4)
            .map(|p| p[0] as u64 + p[1] as u64 + p[2] as u64)
            .sum::<u64>()
            / (w * h) as u64;
        // web UI palette: success bars in --c-ok, navy header (no policy accent in the demo),
        // page background --bg
        let k = palette::tokens(dark);
        let has = |c: u32| {
            let c = [(c >> 16) as u8, (c >> 8) as u8, c as u8];
            px.chunks(4).any(|p| p[..3] == c)
        };
        assert!(has(k.c_ok), "no success bar (dark {dark})");
        assert!(has(k.navy), "no navy header (dark {dark})");
        assert!(has(k.bg), "no page background (dark {dark})");
        assert!(has(k.surface), "no card surface (dark {dark})");
        means.push(mean);
    }
    assert!(means[0] > means[1] + 150, "dark mode is darker: {means:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn manual_images() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../manual/images")
}

#[test]
#[ignore = "writes the manual screenshots"]
fn manual_screenshots() {
    let dir = manual_images();
    render(&demo_app(false), &dir, "desktop-agent-window");
    render(&demo_app(true), &dir, "desktop-agent-window-dark");

    // tray states side by side, 64 px each with 16 px gaps
    let badges = [
        model::Badge::None,
        model::Badge::Clock,
        model::Badge::Play,
        model::Badge::Check,
        model::Badge::Warn,
        model::Badge::Cross,
        model::Badge::Stop,
        model::Badge::Offline,
    ];
    let (s, gap) = (64u32, 16u32);
    let w = badges.len() as u32 * (s + gap) + gap;
    let h = s + 2 * gap;
    let mut img = vec![255u8; (w * h * 4) as usize];
    for (i, b) in badges.iter().enumerate() {
        let icon = icon::rgba(*b, s);
        let x0 = gap + i as u32 * (s + gap);
        for y in 0..s {
            for x in 0..s {
                let src = ((y * s + x) * 4) as usize;
                let dst = (((y + gap) * w + x0 + x) * 4) as usize;
                let a = icon[src + 3] as u32;
                for c in 0..3 {
                    img[dst + c] = ((icon[src + c] as u32 * a + 255 * (255 - a)) / 255) as u8;
                }
            }
        }
    }
    let f = std::fs::File::create(dir.join("desktop-agent-tray-states.png")).unwrap();
    let mut e = png::Encoder::new(f, w, h);
    e.set_color(png::ColorType::Rgba);
    e.write_header().unwrap().write_image_data(&img).unwrap();
}
