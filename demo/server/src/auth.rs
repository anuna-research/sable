//! Operator-provisioned demo credentials, never inferred from request identity fields.

use axum::{extract::{Request, State}, http::{header, StatusCode}, middleware::Next, response::{IntoResponse, Response}};
use parking_lot::Mutex;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::{Duration, Instant}};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Identity authenticated by the credential middleware.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(pub(crate) String);

impl Principal {
    pub(crate) fn key(&self, id: &str) -> String { format!("{}:{id}", self.0) }
    pub(crate) fn prefix(&self) -> String { format!("{}:", self.0) }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential { principal: String, token: String }
impl Drop for Credential { fn drop(&mut self) { self.token.zeroize(); } }

struct Entry {
    principal: Principal,
    digest: [u8; 32],
    window: Instant,
    requests: u32,
}

/// Bounded credential set, with twelve operations per principal per minute.
#[derive(Clone)]
pub struct Credentials(Arc<Mutex<Vec<Entry>>>);

impl Credentials {
    pub fn from_env() -> Result<Self, String> {
        let raw = Zeroizing::new(std::env::var("SABLE_API_CREDENTIALS")
            .map_err(|_| "SABLE_API_CREDENTIALS is required; no anonymous API mode exists")?);
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        if raw.len() > 16 * 1024 { return Err("Credential configuration too large".into()); }
        let credentials: Vec<Credential> = serde_json::from_str(raw)
            .map_err(|_| "Invalid credential configuration")?;
        if credentials.is_empty() || credentials.len() > 32 {
            return Err("Configure between one and 32 credentials".into());
        }
        let mut entries: Vec<Entry> = Vec::new();
        for credential in credentials {
            if credential.principal.is_empty() || credential.principal.len() > 64
                || !credential.principal.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || credential.token.len() != 64
                || !credential.token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            { return Err("Principals must be short identifiers and tokens must be 32-byte lowercase hex secrets".into()); }
            let digest: [u8; 32] = Sha256::digest(credential.token.as_bytes()).into();
            if entries.iter().any(|entry| entry.principal.0 == credential.principal || entry.digest == digest) {
                return Err("Duplicate principal or credential".into());
            }
            entries.push(Entry { principal: Principal(credential.principal.clone()), digest, window: Instant::now(), requests: 0 });
        }
        Ok(Self(Arc::new(Mutex::new(entries))))
    }

    fn authenticate(&self, header: Option<&str>) -> Result<Principal, StatusCode> {
        let token = header.and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| value.len() == 64).ok_or(StatusCode::UNAUTHORIZED)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut entries = self.0.lock();
        let mut matched = None;
        for (index, entry) in entries.iter().enumerate() {
            if bool::from(entry.digest.ct_eq(&digest)) { matched = Some(index); }
        }
        let entry = &mut entries[matched.ok_or(StatusCode::UNAUTHORIZED)?];
        if entry.window.elapsed() >= Duration::from_secs(60) {
            entry.window = Instant::now(); entry.requests = 0;
        }
        if entry.requests >= 12 { return Err(StatusCode::TOO_MANY_REQUESTS); }
        entry.requests += 1;
        Ok(entry.principal.clone())
    }
}

/// Authenticate before body reads or expensive-operation admission.
pub async fn authenticate(State(credentials): State<Credentials>, mut request: Request, next: Next) -> Response {
    let credential = if request.headers().get_all(header::AUTHORIZATION).iter().count() == 1 {
        request.headers().get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
    } else { None };
    let mut response = match credentials.authenticate(credential) {
        Ok(principal) => { request.extensions_mut().insert(principal); next.run(request).await }
        Err(status) => (status, axum::Json(serde_json::json!({"error": "Credential missing, invalid or rate limited"}))).into_response(),
    };
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_and_rate_budgets_are_isolated() {
        let raw = format!(r#"[{{"principal":"alice","token":"{}"}},{{"principal":"bob","token":"{}"}}]"#, "ab".repeat(32), "cd".repeat(32));
        let credentials = Credentials::from_json(&raw).unwrap();
        for invalid in [None, Some(""), Some("Bearer bad")] {
            assert_eq!(credentials.authenticate(invalid), Err(StatusCode::UNAUTHORIZED));
        }
        let alice = format!("Bearer {}", "ab".repeat(32));
        for _ in 0..12 { assert_eq!(credentials.authenticate(Some(&alice)).unwrap().0, "alice"); }
        assert_eq!(credentials.authenticate(Some(&alice)), Err(StatusCode::TOO_MANY_REQUESTS));
        assert_eq!(credentials.authenticate(Some(&format!("Bearer {}", "cd".repeat(32)))).unwrap().0, "bob");
        credentials.0.lock()[0].window = Instant::now() - Duration::from_secs(61);
        assert!(credentials.authenticate(Some(&alice)).is_ok());
    }

    #[test]
    fn configuration_fails_closed() {
        for raw in ["", "[]", "{}", r#"[{"principal":"a","token":"short"}]"#] {
            assert!(Credentials::from_json(raw).is_err());
        }
        let credential = format!(r#"{{"principal":"alice","token":"{}"}}"#, "ab".repeat(32));
        assert!(Credentials::from_json(&format!("[{credential},{credential}]")).is_err());
        assert!(Credentials::from_json(&format!(r#"[{{"principal":"a:b","token":"{}"}}]"#, "ab".repeat(32))).is_err());
    }
}
