//! Static UI hosting contract (`with_ui_assets`): the service serves the
//! installed Vite bundle at `/` without bearer auth (assets are not secrets;
//! the listener is loopback-only), unknown non-API paths fall back to
//! `index.html` for client-side routing, `/api/*` auth is untouched, and no
//! request can escape the UI directory.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use lattice_service::{AppState, app, with_ui_assets};
use lattice_store::{M2StateRepository, connect_memory};
use tower::ServiceExt;

const TOKEN: &str = "owner-token-0123456789abcdefghijkl";
const INDEX_MARKER: &str = "NEONHEARTH-UI-FIXTURE-INDEX";
const SECRET_MARKER: &str = "OUTSIDE-UI-DIR-SECRET";

struct Fixture {
    // Held for its Drop; the ui/ dir and the sibling secret live inside it.
    _base: tempfile::TempDir,
    router: axum::Router,
}

async fn fixture() -> Fixture {
    let base = tempfile::tempdir().expect("create temp dir");
    let ui_dir = base.path().join("ui");
    std::fs::create_dir_all(ui_dir.join("assets")).expect("create ui dirs");
    std::fs::write(
        ui_dir.join("index.html"),
        format!("<!doctype html><html><body>{INDEX_MARKER}</body></html>"),
    )
    .expect("write index");
    std::fs::write(ui_dir.join("assets").join("app.js"), "console.log('ui')").expect("write asset");
    // A sibling of ui/ that must never be reachable through the router.
    std::fs::write(base.path().join("secret.txt"), SECRET_MARKER).expect("write secret");
    let state = AppState::new(
        TOKEN,
        M2StateRepository::new(connect_memory().await.unwrap()),
    )
    .unwrap();
    let router = with_ui_assets(app(state), &ui_dir);
    Fixture {
        _base: base,
        router,
    }
}

async fn get(router: axum::Router, path: &str) -> (StatusCode, String, String) {
    let response = router
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap_or("").to_owned())
        .unwrap_or_default();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&body).into_owned(),
    )
}

#[tokio::test]
async fn root_serves_index_html() {
    let fx = fixture().await;
    let (status, content_type, body) = get(fx.router.clone(), "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.starts_with("text/html"), "{content_type}");
    assert!(body.contains(INDEX_MARKER));
}

#[tokio::test]
async fn hashed_asset_is_served_with_javascript_media_type() {
    let fx = fixture().await;
    let (status, content_type, body) = get(fx.router.clone(), "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type.contains("javascript"), "{content_type}");
    assert!(body.contains("console.log"));
}

#[tokio::test]
async fn unknown_client_route_falls_back_to_index() {
    let fx = fixture().await;
    for path in ["/devices", "/guard/some/deep/route", "/settings"] {
        let (status, content_type, body) = get(fx.router.clone(), path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            content_type.starts_with("text/html"),
            "{path}: {content_type}"
        );
        assert!(
            body.contains(INDEX_MARKER),
            "{path} should serve the SPA index"
        );
    }
}

#[tokio::test]
async fn api_routes_keep_bearer_auth() {
    let fx = fixture().await;
    // Unauthenticated API access is still refused with the auth challenge,
    // not silently answered by the static fallback.
    let response = fx
        .router
        .clone()
        .oneshot(Request::get("/api/v1/state").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    // And the token still works with the UI layer attached.
    let response = fx
        .router
        .clone()
        .oneshot(
            Request::get("/api/v1/state")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // Health stays public and JSON.
    let (status, content_type, body) = get(fx.router.clone(), "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type.starts_with("application/json"),
        "{content_type}"
    );
    assert!(body.contains("\"status\":\"ok\""));
}

#[tokio::test]
async fn traversal_cannot_escape_the_ui_directory() {
    let fx = fixture().await;
    for path in [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/assets/../../secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%2fsecret.txt",
        "/%2e%2e%2fsecret.txt",
    ] {
        let (status, _content_type, body) = get(fx.router.clone(), path).await;
        assert!(
            !body.contains(SECRET_MARKER),
            "{path} leaked content from outside the ui dir"
        );
        // Whatever the exact refusal shape (404 or SPA index fallback), it
        // must never be a server error and never the sibling file.
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "{path}: unexpected status {status}"
        );
    }
}
