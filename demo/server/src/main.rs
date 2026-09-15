use axum::Router;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use demo_server::state::AppState;
use demo_server::auth::Credentials;
use demo_server::routes::api_router;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let credentials = Credentials::from_env().expect("Valid SABLE_API_CREDENTIALS must be configured");
    // Create application state
    let state = AppState::new();
    let eviction_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            eviction_state.evict_expired();
        }
    });

    // Same-origin by default; optional explicit allowlist must be valid.
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.is_empty() => {
            let origins: Vec<_> = origins
                .split(',')
                .map(|o| {
                    assert!(o.trim() != "*", "Wildcard CORS is not permitted");
                    o.trim().parse().expect("Invalid ALLOWED_ORIGINS entry")
                })
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
        }
        _ => CorsLayer::new(),
    };

    // Build API routes
    let api_routes = api_router(state, credentials);

    // Build main router
    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("../web/dist"))
        .layer(cors);

    // Read bind config from environment (PORT for PaaS, BIND_ADDRESS for flexibility)
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);
    let bind_addr: std::net::IpAddr = std::env::var("BIND_ADDRESS")
        .ok()
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| [127, 0, 0, 1].into());
    let addr = SocketAddr::from((bind_addr, port));

    tracing::info!("SABLE Demo Server starting on http://{}", addr);
    tracing::info!("   API endpoints:");
    tracing::info!("   - POST /api/enroll                  Create biometric enrollment");
    tracing::info!("   - POST /api/auth/challenge          Get authentication challenge");
    tracing::info!("   - POST /api/auth/prove              Generate ZK proof");
    tracing::info!("   - POST /api/liveness/screen-flash   Screen flash liveness check");
    tracing::info!("   - POST /api/verify                  Verify ZK proof");
    tracing::info!("   - GET  /api/health                  Health check");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
