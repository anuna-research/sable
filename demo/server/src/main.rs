use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
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

    // Configure CORS for development
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build API routes
    let api_routes = Router::new()
        .route("/health", get(handlers::health))
        .route("/enroll", post(handlers::enroll))
        .route("/auth/challenge", post(handlers::auth_challenge))
        .route("/auth/prove", post(handlers::auth_prove))
        .route("/liveness/screen-flash", post(handlers::screen_flash_check))
        .route("/verify", post(handlers::verify));

    // Build main router
    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("../web/dist"))
        .layer(cors)
        .with_state(state);

    // Start server (use 3001 to avoid conflicts)
    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    tracing::info!("🚀 SABLE Demo Server starting on http://{}", addr);
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
