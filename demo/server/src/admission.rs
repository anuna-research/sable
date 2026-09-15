//! Bounded admission and body buffering for CPU-intensive demo endpoints.

use axum::{body::{to_bytes, Body}, extract::{Request, State}, http::{header, StatusCode}, middleware::Next, response::{IntoResponse, Response}};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

/// Maximum complete JSON request, including all encoded capture images.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// One admitted operation per process; no unbounded waiting queue.
#[derive(Clone)]
pub struct Admission {
    permits: Arc<Semaphore>,
    operation_timeout: Duration,
}

impl Admission {
    pub fn new() -> Self {
        Self { permits: Arc::new(Semaphore::new(1)), operation_timeout: Duration::from_secs(30) }
    }
}

impl Default for Admission {
    fn default() -> Self { Self::new() }
}

/// Read bounded bodies with a deadline, then run the handler on a blocking worker.
/// The worker owns the permit, so response timeout cannot admit overlapping work.
pub async fn limit_request(State(state): State<Admission>, request: Request, next: Next) -> Response {
    let mut response = admitted(state, request, next).await;
    response.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

async fn admitted(state: Admission, request: Request, next: Next) -> Response {
    let Ok(permit) = state.permits.clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "1")], "Server busy").into_response();
    };
    if request.headers().get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()).and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > MAX_REQUEST_BYTES as u64)
    {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Request exceeds byte limit").into_response();
    }
    let (parts, body) = request.into_parts();
    let bytes = match tokio::time::timeout(Duration::from_secs(10), to_bytes(body, MAX_REQUEST_BYTES)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return (StatusCode::PAYLOAD_TOO_LARGE, "Invalid or oversized body").into_response(),
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "Request body timed out").into_response(),
    };
    let request = Request::from_parts(parts, Body::from(bytes));
    let runtime = tokio::runtime::Handle::current();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        runtime.block_on(next.run(request))
    });
    match tokio::time::timeout(state.operation_timeout, task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => (StatusCode::INTERNAL_SERVER_ERROR, "Operation failed").into_response(),
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "Operation timed out").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{middleware, routing::post, Router};
    use tower::ServiceExt;

    fn router(admission: Admission) -> Router {
        Router::new().route("/work", post(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(admission, limit_request))
    }

    #[tokio::test]
    async fn busy_requests_fail_immediately_and_responses_are_not_cached() {
        let admission = Admission::new();
        let permit = admission.permits.clone().acquire_owned().await.unwrap();
        let app = router(admission);
        let request = || Request::builder().uri("/work").method("POST").body(Body::empty()).unwrap();
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        drop(permit);
        assert_eq!(app.oneshot(request()).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn declared_and_actual_oversized_bodies_are_rejected() {
        let app = router(Admission::new());
        let declared = Request::builder().uri("/work").method("POST")
            .header(header::CONTENT_LENGTH, (MAX_REQUEST_BYTES + 1).to_string())
            .body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(declared).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
        let actual = Request::builder().uri("/work").method("POST")
            .body(Body::from(vec![0; MAX_REQUEST_BYTES + 1])).unwrap();
        assert_eq!(app.oneshot(actual).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn timed_out_operation_retains_permit_until_worker_finishes() {
        use tokio::sync::Notify;
        let mut admission = Admission::new();
        admission.operation_timeout = Duration::from_millis(30);
        let release = Arc::new(Notify::new());
        let worker_release = release.clone();
        let app = Router::new()
            .route("/slow", post(move || {
                let release = worker_release.clone();
                async move { release.notified().await; "finished" }
            }))
            .route("/fast", post(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(admission.clone(), limit_request));
        let request = |path| Request::builder().uri(path).method("POST").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(request("/slow")).await.unwrap().status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(app.clone().oneshot(request("/fast")).await.unwrap().status(), StatusCode::TOO_MANY_REQUESTS);
        release.notify_one();
        let permit = tokio::time::timeout(Duration::from_secs(2), admission.permits.clone().acquire_owned()).await.unwrap().unwrap();
        drop(permit);
        assert_eq!(app.oneshot(request("/fast")).await.unwrap().status(), StatusCode::OK);
    }
}
