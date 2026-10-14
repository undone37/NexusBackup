//! Configuration freeze of incident mode (Phase 29, docs/control-plane.md
//! "Incident freezes"): while the active incident has `freeze.config`, every
//! changing API call (not GET/HEAD) is refused with 409, for every role,
//! except what an incident needs ([`allowed`]): signing in and out and the
//! own account, incident mode and tenant lockdowns, approvals, disabling
//! accounts and ending sessions or tokens, alerts, holds, pausing groups,
//! jobs (restores to production have their own freeze), scans, hunts,
//! searches and diagnostics. Lifting the freeze is the approval action
//! `incident.freeze.lift` (crate::incident).

use crate::St;
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// `(method, path pattern)` still accepted under a configuration freeze;
/// `*` matches one path segment, a trailing `**` any rest.
const ALLOWED: &[(&str, &str)] = &[
    ("*", "/auth/**"),
    ("*", "/incident/**"),
    ("POST", "/incident"),
    ("*", "/tenants/*/lockdown/**"),
    ("POST", "/tenants/*/lockdown"),
    ("POST", "/quorum/*/approve"),
    ("POST", "/quorum/*/reject"),
    ("POST", "/users/*/sessions/revoke"),
    ("POST", "/users/*/risk/clear"),
    ("DELETE", "/sessions/*"),
    ("POST", "/sessions/revoke-all"),
    ("POST", "/alerts/*/ack"),
    ("POST", "/alerts/*/resolve"),
    ("POST", "/holds"),
    ("POST", "/snapshots/*/*/*/hold"),
    ("POST", "/snapshots/*/*/*/scan"),
    ("POST", "/snapshots/*/*/*/scan-back"),
    ("POST", "/snapshots/diff"),
    ("POST", "/groups/*/pause"),
    ("POST", "/jobs"),
    ("POST", "/jobs/*/cancel"),
    ("POST", "/restores"),
    ("POST", "/search"),
    ("POST", "/hunts"),
    ("POST", "/diagnostics/checks"),
    ("POST", "/diagnostics/bundle"),
];

fn matches(pattern: &str, path: &str) -> bool {
    let mut p = pattern.trim_start_matches('/').split('/');
    let mut s = path.trim_start_matches('/').split('/');
    loop {
        match (p.next(), s.next()) {
            (Some("**"), Some(_)) => return true,
            (Some("*"), Some(x)) if !x.is_empty() => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Is `method path` (relative to /api/v1) accepted under a configuration freeze?
pub fn allowed(method: &Method, path: &str) -> bool {
    if method == Method::GET || method == Method::HEAD {
        return true;
    }
    ALLOWED
        .iter()
        .any(|(m, p)| (*m == "*" || *m == method.as_str()) && matches(p, path))
}

/// `PUT /users/{id}` that only disables an account, takes its download
/// privilege away or changes the caller's own credentials.
fn protective_user_update(body: &[u8]) -> bool {
    let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    !o.is_empty()
        && o.iter().all(|(k, v)| match k.as_str() {
            "disabled" => v == true,
            "can_download" => v == false,
            "password" | "reset_totp" | "current_password" | "current_totp" => true,
            _ => false,
        })
}

fn refused() -> Response {
    (
        StatusCode::CONFLICT,
        Json(
            json!({"error": "incident mode: configuration changes are frozen; lifting the freeze needs a second \
                             approver (Settings, Incident mode)"}),
        ),
    )
        .into_response()
}

pub async fn layer(State(st): State<St>, req: Request, next: Next) -> Response {
    let Some(path) = req.uri().path().strip_prefix("/api/v1").map(str::to_owned) else {
        return next.run(req).await;
    };
    if allowed(req.method(), &path) {
        return next.run(req).await;
    }
    let frozen = catalog::incident::appliance(&st.cat.conn()).is_ok_and(|f| f.config);
    if !frozen {
        return next.run(req).await;
    }
    if req.method() == Method::PUT && matches("/users/*", &path) {
        let (parts, body) = req.into_parts();
        let Ok(bytes) = to_bytes(body, 1 << 20).await else {
            return refused();
        };
        if !protective_user_update(&bytes) {
            return refused();
        }
        return next.run(Request::from_parts(parts, Body::from(bytes))).await;
    }
    refused()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list() {
        let post = Method::POST;
        assert!(allowed(&Method::GET, "/groups"));
        assert!(allowed(&post, "/auth/login"));
        assert!(allowed(&post, "/auth/step-up"));
        assert!(allowed(&post, "/incident/freeze/lift"));
        assert!(allowed(&post, "/tenants/acme/lockdown"));
        assert!(allowed(&post, "/tenants/acme/lockdown/freeze/lift"));
        assert!(allowed(&post, "/quorum/7/approve"));
        assert!(allowed(&post, "/snapshots/acme/vm-100/17/scan-back"));
        assert!(allowed(&Method::DELETE, "/sessions/3"));
        assert!(!allowed(&post, "/groups"));
        assert!(!allowed(&Method::PUT, "/groups/1"));
        assert!(!allowed(&Method::PUT, "/tenants/acme"));
        assert!(!allowed(&Method::DELETE, "/snapshots/acme/vm-100/17"));
        assert!(!allowed(&post, "/tenants/acme/deactivate"));
        assert!(!allowed(&Method::PUT, "/settings/mgmt-allow"));
        assert!(!allowed(&post, "/incidentx"));
        assert!(protective_user_update(br#"{"disabled": true}"#));
        assert!(protective_user_update(
            br#"{"password": "x", "current_password": "y", "current_totp": "1"}"#
        ));
        assert!(!protective_user_update(br#"{"disabled": false}"#));
        assert!(!protective_user_update(br#"{"disabled": true, "role": "admin"}"#));
        assert!(!protective_user_update(br#"{}"#));
    }
}
