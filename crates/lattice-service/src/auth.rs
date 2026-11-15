use crate::AppState;
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use lattice_store::AuditActor;
use uuid::Uuid;

/// The token of a request carrying exactly one `Authorization: Bearer <token>`
/// header with a non-empty token. Zero, several, malformed, or non-Bearer
/// headers all yield `None`, so ambiguity can never authenticate.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, [("WWW-Authenticate", "Bearer")]).into_response()
}

pub struct Authorized;
impl FromRequestParts<AppState> for Authorized {
    type Rejection = Response;
    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        // A phone session authenticated by the remote-access layer is an
        // alternative principal; the marker cannot arrive from the wire.
        let phone = parts
            .extensions
            .get::<crate::tailscale::PhoneAuthorized>()
            .is_some();
        let valid = phone
            || bearer_token(&parts.headers).is_some_and(|token| state.token_matches(token));
        async move {
            if valid {
                Ok(Self)
            } else {
                Err(unauthorized())
            }
        }
    }
}

/// Who an authenticated request acts as. Handlers that audit or bind state to
/// the caller take this instead of [`Authorized`]; it authenticates exactly
/// like `Authorized` (and is therefore subject to the same phone allowlist).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Principal {
    /// The service bearer token: the local owner.
    Owner,
    /// A paired phone session.
    Phone(Uuid),
}

impl Principal {
    /// The audit actor to record for this principal.
    pub fn audit_actor(self) -> AuditActor {
        match self {
            Self::Owner => AuditActor::Owner,
            Self::Phone(_) => AuditActor::Phone,
        }
    }

    /// The phone session id, when this is a phone principal.
    pub fn session_id(self) -> Option<Uuid> {
        match self {
            Self::Owner => None,
            Self::Phone(id) => Some(id),
        }
    }

    /// `detail` with a `principal` field naming the caller added, so an audit
    /// row can always be traced to a session.
    pub fn annotate(self, mut detail: serde_json::Value) -> serde_json::Value {
        if let Some(object) = detail.as_object_mut() {
            object.insert(
                "principal".to_owned(),
                match self {
                    Self::Owner => serde_json::json!("owner"),
                    Self::Phone(id) => serde_json::json!({ "phone_session": id }),
                },
            );
        }
        detail
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = Response;
    fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let phone = parts
            .extensions
            .get::<crate::tailscale::PhoneAuthorized>()
            .map(|marker| marker.session_id);
        let owner = bearer_token(&parts.headers).is_some_and(|token| state.token_matches(token));
        async move {
            match (phone, owner) {
                (Some(session), _) => Ok(Self::Phone(session)),
                (None, true) => Ok(Self::Owner),
                (None, false) => Err(unauthorized()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(header::AUTHORIZATION, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn bearer_token_requires_exactly_one_well_formed_header() {
        assert_eq!(bearer_token(&headers(&["Bearer abc"])), Some("abc"));
        assert_eq!(bearer_token(&headers(&[])), None);
        assert_eq!(bearer_token(&headers(&["Bearer "])), None);
        assert_eq!(bearer_token(&headers(&["bearer abc"])), None);
        assert_eq!(bearer_token(&headers(&["Basic abc"])), None);
        assert_eq!(bearer_token(&headers(&["Bearer abc", "Bearer abc"])), None);
        assert_eq!(bearer_token(&headers(&["Bearer abc", "PhoneSession x:y"])), None);
    }

    #[test]
    fn principals_map_to_audit_actors_and_annotate_detail() {
        let session = Uuid::new_v4();
        assert_eq!(Principal::Owner.audit_actor(), AuditActor::Owner);
        assert_eq!(Principal::Phone(session).audit_actor(), AuditActor::Phone);
        assert_eq!(Principal::Owner.session_id(), None);
        assert_eq!(Principal::Phone(session).session_id(), Some(session));
        let detail = Principal::Phone(session).annotate(serde_json::json!({"a": 1}));
        assert_eq!(detail["a"], 1);
        assert_eq!(detail["principal"]["phone_session"], session.to_string());
        assert_eq!(
            Principal::Owner.annotate(serde_json::json!({}))["principal"],
            "owner"
        );
    }
}
