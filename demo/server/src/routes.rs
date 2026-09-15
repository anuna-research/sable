//! API composition: authenticate before admission or request-body processing.

use axum::{extract::DefaultBodyLimit, middleware, routing::{get, post}, Router};
use crate::{admission::{Admission, limit_request, MAX_REQUEST_BYTES}, auth::{Credentials, authenticate}, handlers, state::AppState};

pub fn api_router(state: AppState, credentials: Credentials) -> Router {
    Router::new()
        .route("/enroll", post(handlers::enroll))
        .route("/auth/challenge", post(handlers::auth_challenge))
        .route("/auth/prove", post(handlers::auth_prove))
        .route("/liveness/screen-flash", post(handlers::screen_flash_check))
        .route("/verify", post(handlers::verify))
        .route_layer(middleware::from_fn_with_state(Admission::new(), limit_request))
        .route_layer(middleware::from_fn_with_state(credentials, authenticate))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .route("/health", get(handlers::health))
        .with_state(state)
}
