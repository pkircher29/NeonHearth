use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Bearer authentication remains mandatory. Also refuse browser requests whose
/// origin differs from the exact host, including malicious pages targeting localhost.
pub async fn browser_boundary(request: Request, next: Next) -> Response {
    let headers = request.headers();
    let mut rejected = headers
        .get("sec-fetch-site")
        .is_some_and(|value| value == "cross-site");
    if let Some(origin) = headers.get("origin") {
        let same = origin
            .to_str()
            .ok()
            .and_then(|origin| url::Url::parse(origin).ok())
            .is_some_and(|origin| {
                matches!(origin.scheme(), "http" | "https")
                    && headers
                        .get("host")
                        .and_then(|host| host.to_str().ok())
                        .is_some_and(|host| {
                            let expected = format!("{}://{host}", origin.scheme());
                            url::Url::parse(&expected)
                                .ok()
                                .is_some_and(|expected| expected.origin() == origin.origin())
                        })
            });
        rejected |= !same;
    }
    let mut response = if rejected {
        StatusCode::FORBIDDEN.into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; worker-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}
