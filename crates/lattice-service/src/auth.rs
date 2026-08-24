use crate::AppState;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
pub struct Authorized;
impl FromRequestParts<AppState> for Authorized {
    type Rejection = Response;
    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let values: Vec<_> = parts
            .headers
            .get_all(axum::http::header::AUTHORIZATION)
            .iter()
            .collect();
        // A phone session authenticated by the remote-access layer is an
        // alternative principal; the marker cannot arrive from the wire.
        let phone = parts
            .extensions
            .get::<crate::tailscale::PhoneAuthorized>()
            .is_some();
        let valid = phone
            || (values.len() == 1
                && values[0]
                    .to_str()
                    .ok()
                    .and_then(|v| v.strip_prefix("Bearer "))
                    .filter(|v| !v.is_empty())
                    .is_some_and(|v| state.token_matches(v)));
        async move {
            if valid {
                Ok(Self)
            } else {
                Err((StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response())
            }
        }
    }
}
