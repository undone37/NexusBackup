//! The published API description (Phase 23a, Veeam comparison row 10):
//! `GET /api/openapi.json` (no authentication: it describes the open-source
//! API, nothing about this appliance) and `GET /api/v1/openapi.json` (also for
//! API tokens). Hand-maintained in `crates/web-api/openapi.json`; the test below
//! keeps it covering every endpoint on the token allow-list (crate::tokens).

use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Response};

pub const DOCUMENT: &str = include_str!("../openapi.json");

pub async fn document() -> Response {
    let mut res = DOCUMENT.into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// `/jobs/{id}/cancel` → `/jobs/*/cancel` (the allow-list's form).
    fn pattern(path: &str) -> String {
        path.split('/')
            .map(|s| if s.starts_with('{') { "*" } else { s })
            .collect::<Vec<_>>()
            .join("/")
    }

    #[test]
    fn covers_the_token_allow_list() {
        let doc: Value = serde_json::from_str(DOCUMENT).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        let paths = doc["paths"].as_object().unwrap();
        let has = |method: &str, p: &str| paths.iter().any(|(k, v)| pattern(k) == p && v.get(method).is_some());
        for p in crate::tokens::READ {
            assert!(has("get", p), "GET {p} missing in openapi.json");
        }
        for p in crate::tokens::OPERATE {
            assert!(has("post", p), "POST {p} missing in openapi.json");
        }
        // nothing documented as token-reachable that the allow-list refuses, and nothing
        // documented as session only (`x-token: false`, the SDKs refuse it for tokens) that it lets through
        for (k, v) in paths {
            for (m, op) in v.as_object().unwrap() {
                let method = axum::http::Method::from_bytes(m.to_uppercase().as_bytes()).unwrap();
                let reachable = crate::tokens::allowed(true, &method, &k.replace('{', "x").replace('}', ""));
                if op["x-token"] == false {
                    assert!(
                        !reachable,
                        "{m} {k} is documented as session only but on the token allow-list"
                    );
                } else {
                    assert!(reachable, "{m} {k} is documented but not on the token allow-list");
                }
            }
        }
    }

    /// Every operation has a unique lowerCamelCase `operationId`: the SDKs in `sdk/` name their methods after it
    /// (`sdk/codegen.py`), so a new operation without one fails here before it fails the SDK check.
    #[test]
    fn every_operation_has_a_unique_operation_id() {
        let doc: Value = serde_json::from_str(DOCUMENT).unwrap();
        let mut seen = std::collections::HashSet::new();
        for (k, v) in doc["paths"].as_object().unwrap() {
            for (m, op) in v.as_object().unwrap() {
                let id = op["operationId"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{m} {k}: no operationId"));
                assert!(
                    id.starts_with(|c: char| c.is_ascii_lowercase()) && id.chars().all(|c| c.is_ascii_alphanumeric()),
                    "{m} {k}: operationId {id} is not lowerCamelCase"
                );
                assert!(seen.insert(id.to_owned()), "operationId {id} used twice");
            }
        }
    }
}
