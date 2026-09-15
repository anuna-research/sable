//! Regression checks for the request-handler logging policy. These do not audit
//! proxy logs, core-library output, decoder copies, or deployment telemetry.

#[test]
fn enrolled_state_does_not_retain_converted_feature_copy_or_simulation_fallback() {
    let state = include_str!("state.rs");
    assert!(!state.contains("pub features:"));
    assert!(state.contains("pub face_embedding: Vec<f64>"));
    let handlers = include_str!("handlers.rs");
    assert!(!handlers.contains("simulation::"));
    assert!(!handlers.contains("session.features"));
    assert!(!handlers.contains("embedding.clone()"));
}

#[test]
fn handlers_do_not_emit_request_diagnostics_to_logs_or_stdout() {
    let source = include_str!("handlers.rs");
    for diagnostic in ["tracing::", "log::", "println!", "eprintln!", "print!", "eprint!", "dbg!"] {
        assert!(!source.contains(diagnostic), "Request handler diagnostic reintroduced: {diagnostic}");
    }
}

#[test]
fn rejection_messages_do_not_include_biometric_scores() {
    let source = include_str!("handlers.rs");
    for diagnostic in ["Similarity: {:.1}%", "Hamming distance {} > threshold {}", "overall_spatial_score={:.4}"] {
        assert!(!source.contains(diagnostic), "Scored rejection reintroduced: {diagnostic}");
    }
}
