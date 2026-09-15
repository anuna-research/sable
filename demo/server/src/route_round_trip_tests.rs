//! Complete production-router exercise using synthetic RGB capture fixtures.
//! This is NOT a camera/provenance test: fabricated pixels are intentionally
//! sufficient to exercise the software-only circuit and current trust boundary.

use crate::{
    auth::{Credentials, Principal},
    flash_challenge::derive_flash_pattern,
    routes::api_router,
    state::AppState,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::Engine;
use ff::PrimeField;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

async fn post(app: &Router, path: &str, token: &str, value: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(value.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

fn jpeg(rgb: &[u8]) -> String {
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 100)
        .encode(rgb, 256, 256, image::ExtendedColorType::Rgb8)
        .unwrap();
    format!(
        "data:image/jpeg;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

fn capture(client_nonce: &[u8; 32], server_nonce: &[u8; 32]) -> Vec<String> {
    let pattern = derive_flash_pattern(client_nonce, server_nonce);
    let mut frames = vec![jpeg(&vec![30; 256 * 256 * 3])];
    for round in pattern.rounds {
        // Match the central 60% face ROI and verifier's shifted quadrant split.
        let split_x = 51 + (154.0 * (0.35 + round.offset_x * 0.3)) as usize;
        let split_y = 51 + (154.0 * (0.35 + round.offset_y * 0.3)) as usize;
        let mut rgb = Vec::with_capacity(256 * 256 * 3);
        for y in 0..256 {
            for x in 0..256 {
                let color = match (x < split_x, y < split_y) {
                    (true, true) => round.tl_color,
                    (false, true) => round.tr_color,
                    (true, false) => round.bl_color,
                    (false, false) => round.br_color,
                };
                rgb.extend([30 + color.r / 2, 30 + color.g / 2, 30 + color.b / 2]);
            }
        }
        frames.push(jpeg(&rgb));
    }
    frames
}

#[tokio::test]
#[ignore = "Real proof generation: run in release mode with default demo liveness settings"]
async fn authenticated_capture_prove_verify_round_trip() {
    for variable in [
        "SABLE_GEOMETRY_FLOORS",
        "SABLE_CORNEAL_TOLERANCE",
        "SABLE_LIVENESS_THRESHOLDS",
        "SABLE_MAGNITUDE_SCALE",
    ] {
        assert!(
            std::env::var_os(variable).is_none(),
            "Fixture requires default {variable}"
        );
    }
    let state = AppState::new();
    let alice = "ab".repeat(32);
    let bob = "cd".repeat(32);
    let credentials = Credentials::from_json(
        &json!([
            {"principal":"alice", "token":alice}, {"principal":"bob", "token":bob}
        ])
        .to_string(),
    )
    .unwrap();
    let app = api_router(state.clone(), credentials);
    let embedding: Vec<f64> = (0..1024).map(|i| 0.1 + i as f64 / 2048.0).collect();
    let (status, enrollment) = post(
        &app,
        "/enroll",
        &alice,
        json!({"user_id":"fixture", "face_embedding":embedding}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enrollment}");
    let session_id = enrollment["session_id"].as_str().unwrap();
    let registered = state
        .get_session(&Principal("alice".into()), session_id)
        .unwrap();
    let expected_template = hex::encode(registered.template_commitment.to_repr());
    let client_nonce = [1u8; 32];
    let (status, challenge) = post(
        &app,
        "/auth/challenge",
        &alice,
        json!({
            "session_id":session_id, "client_commitment":hex::encode(Sha256::digest(client_nonce))
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let server_nonce: [u8; 32] = hex::decode(challenge["nonce_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let prove_request = json!({"challenge_id":challenge["challenge_id"], "face_embedding":embedding,
        "c_nonce":hex::encode(client_nonce), "flash_frames":capture(&client_nonce, &server_nonce)});
    let (status, proof) = post(&app, "/auth/prove", &alice, prove_request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{proof}");
    assert_eq!(proof["public_inputs_hex"].as_array().unwrap().len(), 5);
    assert_eq!(proof["public_inputs_hex"][4], expected_template);
    let verify_request = json!({"proof_hex":proof["proof_hex"], "public_inputs_hex":proof["public_inputs_hex"],
        "challenge_id":challenge["challenge_id"]});
    // A wrong owner must neither use nor consume the successful proof's policy.
    let (status, rejected) = post(&app, "/verify", &bob, verify_request.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(
        rejected["error"],
        "Challenge not found, expired or already consumed"
    );
    let (status, verified) = post(&app, "/verify", &alice, verify_request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["valid"], true);
    assert_eq!(verified["details"]["liveness_proved_in_zk"], true);
    let (status, rejected) = post(&app, "/verify", &alice, verify_request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(
        rejected["error"],
        "Challenge not found, expired or already consumed"
    );
    let (status, rejected) = post(&app, "/auth/prove", &alice, prove_request).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{rejected}");
    assert_eq!(rejected["error"], "Challenge not found or expired");
}
