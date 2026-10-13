//! Colours of the appliance web UI (web/src/app.css custom properties, `light-dark()` pairs):
//! navy chrome, teal accent, grey-blue surfaces, semantic status colours. Keep in sync when
//! the web palette changes.

use iced::{Color, Theme};

/// One theme's tokens; the names are the web UI's custom properties without `--`.
pub struct Tokens {
    pub navy: u32,
    pub navy_text: u32,
    pub navy_muted: u32,
    pub bg: u32,
    pub surface: u32,
    pub surface_2: u32,
    pub border: u32,
    pub border_strong: u32,
    pub text: u32,
    pub muted: u32,
    pub accent: u32,
    pub ok: u32,
    pub warn: u32,
    pub bad: u32,
    pub info: u32,
    pub info_soft: u32,
    pub bad_soft: u32,
    /// chart fills
    pub c_ok: u32,
    pub c_warn: u32,
    pub c_bad: u32,
    pub c_neutral: u32,
}

pub const LIGHT: Tokens = Tokens {
    navy: 0x0d1b2e,
    navy_text: 0xc3cee0,
    navy_muted: 0x8494ad,
    bg: 0xf2f4f7,
    surface: 0xffffff,
    surface_2: 0xf6f8fb,
    border: 0xdfe4eb,
    border_strong: 0xc6cfdb,
    text: 0x0f1b2d,
    muted: 0x5a677b,
    accent: 0x0b7c72,
    ok: 0x17724a,
    warn: 0x965400,
    bad: 0xbb2525,
    info: 0x1f5bb8,
    info_soft: 0xe5eefb,
    bad_soft: 0xfce8e6,
    c_ok: 0x2f9e6c,
    c_warn: 0xe09c12,
    c_bad: 0xd64545,
    c_neutral: 0x9aa6b8,
};

pub const DARK: Tokens = Tokens {
    navy: 0x070e1a,
    navy_text: 0xc3cee0,
    navy_muted: 0x8494ad,
    bg: 0x0a111d,
    surface: 0x0f1928,
    surface_2: 0x142033,
    border: 0x23324a,
    border_strong: 0x33445f,
    text: 0xe3e9f2,
    muted: 0x8d9cb3,
    accent: 0x2ec4b2,
    ok: 0x5fcf96,
    warn: 0xf2b85b,
    bad: 0xff8a82,
    info: 0x8ab2f7,
    info_soft: 0x142440,
    bad_soft: 0x3b1719,
    c_ok: 0x3db37e,
    c_warn: 0xd9a02a,
    c_bad: 0xe8615a,
    c_neutral: 0x4a5a75,
};

pub fn tokens(dark: bool) -> &'static Tokens {
    if dark {
        &DARK
    } else {
        &LIGHT
    }
}

/// Tokens of the theme a style function gets.
pub fn of(theme: &Theme) -> &'static Tokens {
    tokens(theme.extended_palette().is_dark)
}

pub fn rgb(c: u32) -> Color {
    Color::from_rgb8((c >> 16) as u8, (c >> 8) as u8, c as u8)
}
