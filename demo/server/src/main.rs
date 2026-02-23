use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use demo_server::handlers;
use demo_server::state::AppState;

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

    // Create application state
    let state = AppState::new();

    // Configure CORS from ALLOWED_ORIGINS env (comma-separated) or allow any
    let cors = match std::env::var("ALLOWED_ORIGINS") {
        Ok(origins) if !origins.is_empty() => {
            let origins: Vec<_> = origins
                .split(',')
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods(Any)
                .allow_headers(Any)
        }
        _ => CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any),
    };

    // Build API routes
    let api_routes = Router::new()
        .route("/health", get(handlers::health))
        .route("/enroll", post(handlers::enroll))
        .route("/auth/challenge", post(handlers::auth_challenge))
        .route("/auth/prove", post(handlers::auth_prove))
        .route("/liveness/screen-flash", post(handlers::screen_flash_check))
        .route("/verify", post(handlers::verify))
        // Fuzzy commitment endpoints (optional enrollment mode)
        .route("/fuzzy/enroll", post(handlers::fuzzy_enroll))
        .route("/fuzzy/verify", post(handlers::fuzzy_verify))
        .route("/fuzzy/check-unique", post(handlers::fuzzy_check_unique));

    // Build main router
    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("../web/dist"))
        .layer(cors)
        .with_state(state);

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
