//! Owner-facing read access to the hash-chained audit log (History view).
//!
//! Two routes, both bearer-only through [`Authorized`]:
//!
//! * `GET /api/v1/audit?before=<id>&limit=<n>&category=<c>&actor=<a>` — one
//!   newest-first page plus the current chain head, so the UI can show the
//!   same commitment the service logs after every prune.
//! * `GET /api/v1/audit/verify?tail=<n>` — recomputes hashes over the newest
//!   `n` entries (or the whole chain from its trusted root when `tail` is
//!   omitted) and reports the first break.
//!
//! Phone sessions reach these only after PIN step-up: the remote-access
//! layer classifies every `/api/v1/audit/**` path as high-impact.

use axum::{
    Extension, Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use lattice_store::{
    AppendedEntry, AuditActor, AuditCategory, AuditFilter, AuditLog, AuditLogError, ChainHead,
    ChainReport, ChainScope, MAX_LIST_PAGE,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{auth::Authorized, state::AppState};

/// Default page size for the History view; the store caps at [`MAX_LIST_PAGE`].
const DEFAULT_PAGE: u32 = 50;
/// Largest tail window the verify route accepts in one call.
const MAX_VERIFY_TAIL: u64 = 10_000;

#[derive(Clone)]
pub struct AuditApiState {
    log: AuditLog,
}

impl AuditApiState {
    pub fn for_service(state: &AppState) -> Self {
        Self {
            log: AuditLog::new(state.state_repository().pool().clone()),
        }
    }
}

pub(crate) fn routes(audit: AuditApiState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/audit", get(page_route))
        .route("/api/v1/audit/verify", get(verify_route))
        .layer(Extension(audit))
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditPageQuery {
    /// Keyset cursor: only entries with `id < before` are returned.
    pub before: Option<i64>,
    /// Page size, 1..=512; defaults to 50.
    pub limit: Option<u32>,
    pub category: Option<String>,
    pub actor: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AuditPageResponse {
    pub entries: Vec<AppendedEntry>,
    /// Current chain head; compare with the head the service last logged.
    pub head: Option<ChainHead>,
    /// Cursor for the next (older) page, or `None` at the end.
    pub next_before: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditVerifyQuery {
    /// Verify only the newest `tail` entries; omit to walk the whole chain.
    pub tail: Option<u64>,
}

#[derive(Serialize, ToSchema)]
pub struct AuditVerifyResponse {
    pub report: ChainReport,
    pub head: Option<ChainHead>,
    pub valid: bool,
}

fn status_for(error: &AuditLogError) -> StatusCode {
    match error {
        AuditLogError::Invalid(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// The head is `None` on an empty chain rather than an error, so an empty
/// History view still renders.
async fn head_or_none(log: &AuditLog) -> Result<Option<ChainHead>, AuditLogError> {
    match log.head().await {
        Ok(head) if head.id > 0 => Ok(Some(head)),
        Ok(_) => Ok(None),
        Err(error) => Err(error),
    }
}

#[utoipa::path(get, path = "/api/v1/audit", params(("before" = Option<i64>, Query), ("limit" = Option<u32>, Query), ("category" = Option<String>, Query), ("actor" = Option<String>, Query)), responses((status = 200, body = AuditPageResponse), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn page_route(
    _: Authorized,
    State(_state): State<AppState>,
    Extension(audit): Extension<AuditApiState>,
    query: Result<Query<AuditPageQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let limit = query.limit.unwrap_or(DEFAULT_PAGE);
    if limit == 0 || limit > MAX_LIST_PAGE {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if query.before.is_some_and(|before| before <= 0) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let category = match query.category.as_deref() {
        None => None,
        Some(raw) => match AuditCategory::parse(raw) {
            Some(category) => Some(category),
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    let actor = match query.actor.as_deref() {
        None => None,
        Some(raw) => match AuditActor::parse(raw) {
            Some(actor) => Some(actor),
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
    };
    let filter = AuditFilter {
        actor,
        category,
        subject: None,
        since: None,
        until: None,
    };
    let entries = match audit.log.list_newest(&filter, query.before, limit).await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::warn!(%error, "audit page failed");
            return status_for(&error).into_response();
        }
    };
    let head = match head_or_none(&audit.log).await {
        Ok(head) => head,
        Err(error) => {
            tracing::warn!(%error, "audit head failed");
            return status_for(&error).into_response();
        }
    };
    let next_before = if entries.len() == limit as usize {
        entries.last().map(|entry| entry.id)
    } else {
        None
    };
    Json(AuditPageResponse {
        entries,
        head,
        next_before,
    })
    .into_response()
}

#[utoipa::path(get, path = "/api/v1/audit/verify", params(("tail" = Option<u64>, Query)), responses((status = 200, body = AuditVerifyResponse), (status = 400), (status = 401), (status = 503)), security(("bearer_auth" = [])))]
pub(crate) async fn verify_route(
    _: Authorized,
    Extension(audit): Extension<AuditApiState>,
    query: Result<Query<AuditVerifyQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let scope = match query.tail {
        None => ChainScope::All,
        Some(0) => return StatusCode::BAD_REQUEST.into_response(),
        Some(tail) if tail > MAX_VERIFY_TAIL => return StatusCode::BAD_REQUEST.into_response(),
        Some(tail) => ChainScope::Tail(tail),
    };
    let report = match audit.log.verify_chain(scope).await {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(%error, "audit verify failed");
            return status_for(&error).into_response();
        }
    };
    let head = match head_or_none(&audit.log).await {
        Ok(head) => head,
        Err(error) => return status_for(&error).into_response(),
    };
    let valid = report.is_valid();
    Json(AuditVerifyResponse {
        report,
        head,
        valid,
    })
    .into_response()
}
