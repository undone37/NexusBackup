//! Embedded SPA (`web/dist`, see build.rs). Hashed assets under `/assets/`
//! are cached for a year; everything else that is not a file falls back to
//! `index.html` so client-side routes work on reload.

use axum::http::{header, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

include!(concat!(env!("OUT_DIR"), "/assets.rs"));

const PLACEHOLDER: &str = "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>NexusBackup</title></head>\n<body><h1>NexusBackup</h1><p>The web UI was not bundled into this build (web/dist missing). The REST API is available under /api/v1.</p></body></html>\n";

fn mime(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, e)| e) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn asset(path: &str) -> Option<&'static [u8]> {
    ASSETS.iter().find(|(p, _)| *p == path).map(|(_, b)| *b)
}

fn respond(body: &'static [u8], ctype: &'static str, cache: &'static str) -> Response {
    let mut r = body.into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    r
}

pub async fn serve(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let path = uri.path().trim_start_matches('/');
    if let Some(b) = asset(path).filter(|_| !path.is_empty()) {
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        return respond(b, mime(path), cache);
    }
    // missing files under /assets/ (or with an extension) are real 404s, not routes
    if path.starts_with("assets/") || path.rsplit('/').next().is_some_and(|s| s.contains('.')) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let index = asset("index.html").unwrap_or(PLACEHOLDER.as_bytes());
    respond(index, "text/html; charset=utf-8", "no-cache")
}
