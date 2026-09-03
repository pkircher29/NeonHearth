//! RLS2: append-only, hash-chained audit log.
//!
//! Every entry's `entry_hash` is a SHA-256 over the canonical encoding of
//! `(id, occurred_at, actor, category, action, subject, detail, prev_hash)`.
//! The genesis entry chains from a fixed domain-separation constant. Appends
//! serialize through a `BEGIN IMMEDIATE` transaction so the newest head hash
//! is read under the database write lock. The transaction is an sqlx
//! [`sqlx::Transaction`] (rolled back on drop) *and* the whole transactional
//! section runs on a detached task, so a caller that is cancelled mid-append
//! (a dropped request future) can never return a connection to the pool with
//! the write lock still held — see [`uncancellable`]. UPDATE/DELETE are
//! refused by SQL triggers.
//!
//! Retention (RLS3) prunes only a contiguous oldest-side prefix and records a
//! `pruned_through` anchor `(id, entry_hash)`; verification then restarts from
//! the anchor instead of genesis. Rows older than the cutoff that sit behind a
//! newer-side row are never removed, because deleting mid-chain would break
//! hash verification.
//!
//! # Threat model
//!
//! The chain is tamper-evident against anyone who edits, removes, or reorders
//! rows without also recomputing every later `entry_hash` and rewriting the
//! retention anchor. It carries no secret, so it is **not** tamper-evident
//! against a party with unrestricted write access to the database file: such
//! a party can rewrite the whole chain consistently and `verify_chain` will
//! pass. To detect that, keep the chain head out of band: [`AuditLog::head`]
//! returns the current `(id, entry_hash)` commitment, retention logs it after
//! every prune, and [`AuditLog::verify_chain_against`] checks a stored head
//! against the live chain.

use chrono::{DateTime, Datelike, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{QueryBuilder, Sqlite, SqlitePool, Transaction};
use std::fmt::Write as _;
use thiserror::Error;
use utoipa::ToSchema;

/// Maximum `action` length in bytes (the migration mirrors this per character).
pub const MAX_ACTION_BYTES: usize = 128;
/// Maximum `subject` length in bytes (the migration mirrors this per character).
pub const MAX_SUBJECT_BYTES: usize = 256;
/// Maximum canonical `detail` JSON length in bytes.
pub const MAX_DETAIL_BYTES: usize = 16_384;
/// Hard cap for one `list` page.
pub const MAX_LIST_PAGE: u32 = 512;

const ENTRY_DOMAIN: &[u8] = b"neonhearth.audit-log.entry.v1";
const GENESIS_DOMAIN: &[u8] = b"neonhearth.audit-log.genesis.v1";
const VERIFY_PAGE: i64 = 512;
/// Must match `022_audit_log.sql` exactly; retention re-creates this trigger
/// inside the prune transaction.
const NO_DELETE_TRIGGER_SQL: &str = "CREATE TRIGGER audit_log_no_delete\n\
     BEFORE DELETE ON audit_log\n\
     BEGIN\n    SELECT RAISE(ABORT, 'audit_log is append-only');\nEND";

type StoredEntryRow = (
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditActor {
    Owner,
    Service,
    Module,
}

impl AuditActor {
    fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Service => "service",
            Self::Module => "module",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "owner" => Some(Self::Owner),
            "service" => Some(Self::Service),
            "module" => Some(Self::Module),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Approval,
    Scan,
    Enforcement,
    DoctorAction,
    AuditModule,
}

impl AuditCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Scan => "scan",
            Self::Enforcement => "enforcement",
            Self::DoctorAction => "doctor_action",
            Self::AuditModule => "audit_module",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "approval" => Some(Self::Approval),
            "scan" => Some(Self::Scan),
            "enforcement" => Some(Self::Enforcement),
            "doctor_action" => Some(Self::DoctorAction),
            "audit_module" => Some(Self::AuditModule),
            _ => None,
        }
    }
}

/// Caller-supplied entry; the store allocates the id and computes the chain.
#[derive(Clone, Debug, PartialEq)]
pub struct NewAuditEntry {
    pub occurred_at: DateTime<Utc>,
    pub actor: AuditActor,
    pub category: AuditCategory,
    pub action: String,
    pub subject: Option<String>,
    pub detail: serde_json::Value,
}

/// A durable audit entry, as chained and stored.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub struct AppendedEntry {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor: AuditActor,
    pub category: AuditCategory,
    pub action: String,
    pub subject: Option<String>,
    #[schema(value_type = Object)]
    pub detail: serde_json::Value,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainScope {
    /// Verify from the trusted root (prune anchor or genesis) to the head.
    All,
    /// Verify only the newest `n` entries; when the window does not reach the
    /// trusted root the window's first `prev_hash` is taken on trust and the
    /// report's `anchored` flag is false.
    Tail(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChainBreakKind {
    /// The id sequence is not contiguous (a row was removed or never chained).
    IdGap,
    /// The row's `prev_hash` does not commit to the previous entry.
    PrevHashMismatch,
    /// The recomputed hash over the stored fields differs from `entry_hash`.
    EntryHashMismatch,
    /// The stored row cannot be decoded (unknown actor/category or bad text).
    InvalidRow,
    /// The out-of-band head commitment handed to
    /// [`AuditLog::verify_chain_against`] does not match the live chain: the
    /// committed id is missing or carries a different hash.
    HeadMismatch,
}

/// The chain's current commitment: the newest entry's `(id, entry_hash)`, or
/// the trusted root (prune anchor or genesis) when the log is empty. Store it
/// outside the database and pass it back to
/// [`AuditLog::verify_chain_against`] to detect a consistently rewritten chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ChainHead {
    pub id: i64,
    pub entry_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct ChainBreak {
    /// Id of the first entry at which the chain fails to verify.
    pub id: i64,
    pub kind: ChainBreakKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct ChainReport {
    /// Number of entries whose hashes were recomputed.
    pub checked: u64,
    pub start_id: Option<i64>,
    pub end_id: Option<i64>,
    /// True when verification started from a trusted root (the prune anchor or
    /// the genesis constant) rather than a taken-on-trust tail window.
    pub anchored: bool,
    pub first_break: Option<ChainBreak>,
}

impl ChainReport {
    pub fn is_valid(&self) -> bool {
        self.first_break.is_none()
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuditFilter {
    pub actor: Option<AuditActor>,
    pub category: Option<AuditCategory>,
    /// Exact subject match.
    pub subject: Option<String>,
    /// Inclusive lower bound on `occurred_at`.
    pub since: Option<DateTime<Utc>>,
    /// Exclusive upper bound on `occurred_at`.
    pub until: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditPage {
    /// Keyset cursor: return entries with `id > after_id`.
    pub after_id: Option<i64>,
    /// Page size, 1..=[`MAX_LIST_PAGE`].
    pub limit: u32,
}

/// Result of an oldest-side retention prune.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct PruneReport {
    pub pruned_rows: u64,
    pub remaining_rows: u64,
    /// New anchor id, when anything was pruned.
    pub pruned_through_id: Option<i64>,
    /// New anchor hash, when anything was pruned.
    pub pruned_through_hash: Option<String>,
    /// Rows older than the cutoff that were kept because a newer-timestamped
    /// row sits below them in the chain: removing them would cut mid-chain,
    /// which the prune refuses to do.
    pub kept_out_of_order_rows: u64,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum AuditLogError {
    #[error("audit entry is invalid: {0}")]
    Invalid(String),
    #[error("audit log is corrupt: {0}")]
    Corrupt(String),
    #[error("audit log storage failed: {0}")]
    Storage(String),
}

fn storage(error: sqlx::Error) -> AuditLogError {
    AuditLogError::Storage(error.to_string())
}

#[derive(Clone)]
pub struct AuditLog {
    pool: SqlitePool,
}

impl AuditLog {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Appends one entry, computing the hash chain inside a single
    /// `BEGIN IMMEDIATE` transaction so the newest head hash is read under the
    /// database write lock and concurrent appends serialize.
    pub async fn append(&self, entry: NewAuditEntry) -> Result<AppendedEntry, AuditLogError> {
        let occurred_at = encode_time(entry.occurred_at)
            .ok_or_else(|| AuditLogError::Invalid("occurred_at is out of range".into()))?;
        if entry.action.is_empty() || entry.action.len() > MAX_ACTION_BYTES {
            return Err(AuditLogError::Invalid(format!(
                "action must be 1..={MAX_ACTION_BYTES} bytes"
            )));
        }
        if entry
            .subject
            .as_ref()
            .is_some_and(|subject| subject.is_empty() || subject.len() > MAX_SUBJECT_BYTES)
        {
            return Err(AuditLogError::Invalid(format!(
                "subject must be 1..={MAX_SUBJECT_BYTES} bytes"
            )));
        }
        let detail = serde_json::to_string(&entry.detail).map_err(|error| {
            AuditLogError::Invalid(format!("detail is not serializable: {error}"))
        })?;
        if detail.len() > MAX_DETAIL_BYTES {
            return Err(AuditLogError::Invalid(format!(
                "detail exceeds the {MAX_DETAIL_BYTES}-byte cap"
            )));
        }

        let pool = self.pool.clone();
        uncancellable(async move {
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(storage)?;
            let appended = append_locked(&mut tx, &entry, &occurred_at, &detail).await?;
            tx.commit().await.map_err(storage)?;
            Ok(appended)
        })
        .await
    }

    /// Returns the chain's current commitment (see [`ChainHead`]).
    pub async fn head(&self) -> Result<ChainHead, AuditLogError> {
        let mut conn = self.pool.acquire().await.map_err(storage)?;
        head_on(&mut conn).await
    }

    /// Walks the chain and recomputes every hash in scope, reporting the first
    /// break. [`ChainScope::All`] starts from the trusted root (the prune
    /// anchor when one exists, otherwise the genesis constant).
    pub async fn verify_chain(&self, scope: ChainScope) -> Result<ChainReport, AuditLogError> {
        self.verify_chain_against(scope, None).await
    }

    /// [`Self::verify_chain`] plus an out-of-band head check: when
    /// `expected_head` is given, the entry with that id must still exist in
    /// the chain with exactly that hash (or be the retention anchor itself).
    /// A chain that was rewritten consistently, or truncated below the
    /// committed head, is reported as [`ChainBreakKind::HeadMismatch`].
    ///
    /// The whole walk runs inside one read transaction, so a concurrent prune
    /// cannot make a healthy chain look like it has an id gap.
    pub async fn verify_chain_against(
        &self,
        scope: ChainScope,
        expected_head: Option<&ChainHead>,
    ) -> Result<ChainReport, AuditLogError> {
        let mut tx = self.pool.begin().await.map_err(storage)?;
        let report = verify_in(&mut tx, scope, expected_head).await;
        // Read-only: nothing to commit, and an explicit rollback keeps the
        // connection's state obvious.
        tx.rollback().await.map_err(storage)?;
        report
    }

    /// Lists entries oldest-first with keyset paging.
    pub async fn list(
        &self,
        filter: &AuditFilter,
        page: AuditPage,
    ) -> Result<Vec<AppendedEntry>, AuditLogError> {
        if page.limit == 0 || page.limit > MAX_LIST_PAGE {
            return Err(AuditLogError::Invalid(format!(
                "page limit must be 1..={MAX_LIST_PAGE}"
            )));
        }
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash \
             FROM audit_log WHERE 1=1",
        );
        if let Some(actor) = filter.actor {
            query.push(" AND actor = ").push_bind(actor.as_str());
        }
        if let Some(category) = filter.category {
            query.push(" AND category = ").push_bind(category.as_str());
        }
        if let Some(subject) = &filter.subject {
            query.push(" AND subject = ").push_bind(subject.clone());
        }
        if let Some(since) = filter.since {
            let since = encode_time(since)
                .ok_or_else(|| AuditLogError::Invalid("since is out of range".into()))?;
            query.push(" AND occurred_at >= ").push_bind(since);
        }
        if let Some(until) = filter.until {
            let until = encode_time(until)
                .ok_or_else(|| AuditLogError::Invalid("until is out of range".into()))?;
            query.push(" AND occurred_at < ").push_bind(until);
        }
        if let Some(after_id) = page.after_id {
            query.push(" AND id > ").push_bind(after_id);
        }
        query
            .push(" ORDER BY id ASC LIMIT ")
            .push_bind(i64::from(page.limit));
        let rows: Vec<StoredEntryRow> = query
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(storage)?;
        rows.into_iter().map(decode_entry).collect()
    }

    /// Prunes a contiguous oldest-side prefix of the chain (RLS3 retention).
    ///
    /// * `before`: remove entries whose `occurred_at` predates the cutoff —
    ///   but only up to the first retained entry, never mid-chain.
    /// * `max_rows`: additionally keep at most this many newest entries.
    ///
    /// The last pruned entry's `(id, entry_hash)` is recorded in
    /// `audit_log_anchor`, and the forbid-delete trigger is dropped and
    /// re-created inside the same write-locked transaction, so append-only
    /// stays enforced for every other writer. The post-prune [`ChainHead`] is
    /// logged at `info` so an out-of-band record can be refreshed.
    pub async fn retention_prune(
        &self,
        before: Option<DateTime<Utc>>,
        max_rows: Option<u64>,
        now: DateTime<Utc>,
    ) -> Result<PruneReport, AuditLogError> {
        if before.is_none() && max_rows.is_none() {
            return Err(AuditLogError::Invalid(
                "retention prune needs a max-age cutoff or a max-rows bound".into(),
            ));
        }
        let cutoff = before
            .map(|value| {
                encode_time(value)
                    .ok_or_else(|| AuditLogError::Invalid("cutoff is out of range".into()))
            })
            .transpose()?;
        let pruned_at = encode_time(now)
            .ok_or_else(|| AuditLogError::Invalid("prune time is out of range".into()))?;
        let pool = self.pool.clone();
        let (report, head) = uncancellable(async move {
            let mut tx = pool.begin_with("BEGIN IMMEDIATE").await.map_err(storage)?;
            let report = prune_locked(&mut tx, cutoff.as_deref(), max_rows, &pruned_at).await?;
            let head = head_on(&mut tx).await?;
            tx.commit().await.map_err(storage)?;
            Ok((report, head))
        })
        .await?;
        tracing::info!(
            head_id = head.id,
            head_hash = %head.entry_hash,
            pruned_rows = report.pruned_rows,
            "audit log head after retention prune"
        );
        Ok(report)
    }
}

/// Runs a transactional section to completion even if the caller stops
/// waiting for it.
///
/// A dropped `sqlx::Transaction` rolls back on drop, but the transaction
/// only exists once `begin_with` has returned. For a custom `BEGIN`
/// statement sqlx-sqlite 0.8 executes the statement and then awaits a
/// second round-trip to confirm the connection is in a transaction; a
/// caller cancelled inside that second await has already taken the write
/// lock and owns no guard that would release it, and the connection goes
/// back to the pool still holding it. Spawning the section as its own task
/// removes every such window: the work finishes with a commit or a rollback
/// whether or not the caller is still there, which is also the right
/// semantics for an audit record of an action that has already happened.
async fn uncancellable<T, F>(work: F) -> Result<T, AuditLogError>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, AuditLogError>> + Send + 'static,
{
    tokio::spawn(work).await.unwrap_or_else(|join| {
        Err(AuditLogError::Storage(format!(
            "audit log task did not complete: {join}"
        )))
    })
}

/// The fixed root of every un-pruned chain.
pub fn genesis_hash() -> String {
    hex_encode(&Sha256::digest(GENESIS_DOMAIN))
}

async fn trusted_root_on(
    conn: &mut sqlx::SqliteConnection,
) -> Result<(i64, String), AuditLogError> {
    let anchor: Option<(i64, String)> = sqlx::query_as(
        "SELECT pruned_through_id, pruned_through_hash FROM audit_log_anchor WHERE singleton = 1",
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(storage)?;
    Ok(anchor.unwrap_or_else(|| (0, genesis_hash())))
}

async fn head_on(conn: &mut sqlx::SqliteConnection) -> Result<ChainHead, AuditLogError> {
    let head: Option<(i64, String)> =
        sqlx::query_as("SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await
            .map_err(storage)?;
    let (id, entry_hash) = match head {
        Some(head) => head,
        None => trusted_root_on(conn).await?,
    };
    Ok(ChainHead { id, entry_hash })
}

async fn verify_in(
    tx: &mut Transaction<'_, Sqlite>,
    scope: ChainScope,
    expected_head: Option<&ChainHead>,
) -> Result<ChainReport, AuditLogError> {
    let (root_id, root_hash) = trusted_root_on(tx).await?;
    if let Some(expected) = expected_head
        && expected.id < root_id
    {
        return Err(AuditLogError::Invalid(format!(
            "expected head {} predates the retention anchor {root_id}",
            expected.id
        )));
    }
    let max_id: Option<i64> = sqlx::query_scalar("SELECT MAX(id) FROM audit_log")
        .fetch_one(&mut **tx)
        .await
        .map_err(storage)?;
    let Some(max_id) = max_id else {
        let first_break = expected_head
            .filter(|expected| expected.id != root_id || expected.entry_hash != root_hash)
            .map(|expected| ChainBreak {
                id: expected.id,
                kind: ChainBreakKind::HeadMismatch,
            });
        return Ok(ChainReport {
            checked: 0,
            start_id: None,
            end_id: None,
            anchored: true,
            first_break,
        });
    };
    let root_start = root_id
        .checked_add(1)
        .ok_or_else(|| AuditLogError::Corrupt("audit log id space exhausted".into()))?;
    let (start_id, mut expected_prev, anchored) = match scope {
        ChainScope::All => (root_start, root_hash.clone(), true),
        ChainScope::Tail(0) => {
            return Err(AuditLogError::Invalid("tail scope must be nonzero".into()));
        }
        ChainScope::Tail(n) => {
            let window = i64::try_from(n).unwrap_or(i64::MAX);
            let tail_start = max_id.saturating_sub(window.saturating_sub(1));
            if tail_start <= root_start {
                (root_start, root_hash.clone(), true)
            } else {
                let trusted: Option<String> =
                    sqlx::query_scalar("SELECT prev_hash FROM audit_log WHERE id = ?")
                        .bind(tail_start)
                        .fetch_optional(&mut **tx)
                        .await
                        .map_err(storage)?;
                match trusted {
                    Some(prev) => (tail_start, prev, false),
                    None => {
                        return Ok(ChainReport {
                            checked: 0,
                            start_id: Some(tail_start),
                            end_id: None,
                            anchored: false,
                            first_break: Some(ChainBreak {
                                id: tail_start,
                                kind: ChainBreakKind::IdGap,
                            }),
                        });
                    }
                }
            }
        }
    };

    let mut expected_id = start_id;
    let mut checked: u64 = 0;
    let mut end_id = None;
    let mut cursor = start_id
        .checked_sub(1)
        .ok_or_else(|| AuditLogError::Corrupt("audit log id underflow".into()))?;
    loop {
        let rows: Vec<StoredEntryRow> = sqlx::query_as(
            "SELECT id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash \
             FROM audit_log WHERE id > ? ORDER BY id ASC LIMIT ?",
        )
        .bind(cursor)
        .bind(VERIFY_PAGE)
        .fetch_all(&mut **tx)
        .await
        .map_err(storage)?;
        if rows.is_empty() {
            break;
        }
        for (id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash) in
            &rows
        {
            let break_kind = if *id != expected_id {
                Some(ChainBreakKind::IdGap)
            } else if AuditActor::parse(actor).is_none() || AuditCategory::parse(category).is_none()
            {
                Some(ChainBreakKind::InvalidRow)
            } else if *prev_hash != expected_prev {
                Some(ChainBreakKind::PrevHashMismatch)
            } else if compute_entry_hash(
                *id,
                occurred_at,
                actor,
                category,
                action,
                subject.as_deref(),
                detail,
                prev_hash,
            ) != *entry_hash
            {
                Some(ChainBreakKind::EntryHashMismatch)
            } else {
                None
            };
            if let Some(kind) = break_kind {
                return Ok(ChainReport {
                    checked,
                    start_id: Some(start_id),
                    end_id,
                    anchored,
                    first_break: Some(ChainBreak { id: *id, kind }),
                });
            }
            checked = checked.saturating_add(1);
            end_id = Some(*id);
            expected_prev = entry_hash.clone();
            expected_id = id
                .checked_add(1)
                .ok_or_else(|| AuditLogError::Corrupt("audit log id space exhausted".into()))?;
            cursor = *id;
        }
        if rows.len() < VERIFY_PAGE as usize {
            break;
        }
    }
    // Out-of-band head commitment: the committed id must still carry the
    // committed hash. A consistently rewritten or truncated chain fails here
    // even though every remaining link verifies.
    if let Some(expected) = expected_head {
        let live_hash = if expected.id == root_id {
            Some(root_hash.clone())
        } else {
            sqlx::query_scalar::<_, String>("SELECT entry_hash FROM audit_log WHERE id = ?")
                .bind(expected.id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(storage)?
        };
        if live_hash.as_deref() != Some(expected.entry_hash.as_str()) {
            return Ok(ChainReport {
                checked,
                start_id: (checked > 0).then_some(start_id),
                end_id,
                anchored,
                first_break: Some(ChainBreak {
                    id: expected.id,
                    kind: ChainBreakKind::HeadMismatch,
                }),
            });
        }
    }
    Ok(ChainReport {
        checked,
        start_id: (checked > 0).then_some(start_id),
        end_id,
        anchored,
        first_break: None,
    })
}

async fn append_locked(
    tx: &mut Transaction<'_, Sqlite>,
    entry: &NewAuditEntry,
    occurred_at: &str,
    detail: &str,
) -> Result<AppendedEntry, AuditLogError> {
    let head: Option<(i64, String)> =
        sqlx::query_as("SELECT id, entry_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
    let (head_id, prev_hash) = match head {
        Some(head) => head,
        None => {
            let anchor: Option<(i64, String)> = sqlx::query_as(
                "SELECT pruned_through_id, pruned_through_hash FROM audit_log_anchor WHERE singleton = 1",
            )
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
            anchor.unwrap_or_else(|| (0, genesis_hash()))
        }
    };
    let id = head_id
        .checked_add(1)
        .ok_or_else(|| AuditLogError::Corrupt("audit log id space exhausted".into()))?;
    let entry_hash = compute_entry_hash(
        id,
        occurred_at,
        entry.actor.as_str(),
        entry.category.as_str(),
        &entry.action,
        entry.subject.as_deref(),
        detail,
        &prev_hash,
    );
    sqlx::query(
        "INSERT INTO audit_log(id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash) \
         VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(occurred_at)
    .bind(entry.actor.as_str())
    .bind(entry.category.as_str())
    .bind(&entry.action)
    .bind(entry.subject.as_deref())
    .bind(detail)
    .bind(&prev_hash)
    .bind(&entry_hash)
    .execute(&mut **tx)
    .await
    .map_err(storage)?;
    let detail: serde_json::Value = serde_json::from_str(detail)
        .map_err(|error| AuditLogError::Corrupt(format!("stored detail is not JSON: {error}")))?;
    let occurred_at = decode_time(occurred_at)?;
    Ok(AppendedEntry {
        id,
        occurred_at,
        actor: entry.actor,
        category: entry.category,
        action: entry.action.clone(),
        subject: entry.subject.clone(),
        detail,
        prev_hash,
        entry_hash,
    })
}

async fn prune_locked(
    tx: &mut Transaction<'_, Sqlite>,
    cutoff: Option<&str>,
    max_rows: Option<u64>,
    pruned_at: &str,
) -> Result<PruneReport, AuditLogError> {
    let (min_id, max_id, count): (Option<i64>, Option<i64>, i64) =
        sqlx::query_as("SELECT MIN(id), MAX(id), COUNT(*) FROM audit_log")
            .fetch_one(&mut **tx)
            .await
            .map_err(storage)?;
    let (Some(min_id), Some(max_id)) = (min_id, max_id) else {
        return Ok(PruneReport {
            pruned_rows: 0,
            remaining_rows: 0,
            pruned_through_id: None,
            pruned_through_hash: None,
            kept_out_of_order_rows: 0,
        });
    };
    let mut prune_through: i64 = min_id - 1;
    let mut kept_out_of_order: i64 = 0;
    if let Some(cutoff) = cutoff {
        // Oldest-side only: stop at the first entry that must be retained.
        // Older-timestamped rows above it stay, because cutting mid-chain
        // would break hash verification for everything after the cut.
        let first_kept: Option<i64> =
            sqlx::query_scalar("SELECT MIN(id) FROM audit_log WHERE occurred_at >= ?")
                .bind(cutoff)
                .fetch_one(&mut **tx)
                .await
                .map_err(storage)?;
        let age_boundary = first_kept.map_or(max_id, |kept| kept - 1);
        kept_out_of_order =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE id > ? AND occurred_at < ?")
                .bind(age_boundary)
                .bind(cutoff)
                .fetch_one(&mut **tx)
                .await
                .map_err(storage)?;
        prune_through = prune_through.max(age_boundary);
    }
    if let Some(max_rows) = max_rows {
        let keep = i64::try_from(max_rows).unwrap_or(i64::MAX);
        prune_through = prune_through.max(max_id.saturating_sub(keep));
    }
    let remaining_after = max_id - prune_through;
    if prune_through < min_id {
        return Ok(PruneReport {
            pruned_rows: 0,
            remaining_rows: u64::try_from(count).unwrap_or(0),
            pruned_through_id: None,
            pruned_through_hash: None,
            kept_out_of_order_rows: u64::try_from(kept_out_of_order).unwrap_or(0),
        });
    }
    let anchor_hash: Option<String> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_log WHERE id = ?")
            .bind(prune_through)
            .fetch_optional(&mut **tx)
            .await
            .map_err(storage)?;
    let anchor_hash = anchor_hash.ok_or_else(|| {
        AuditLogError::Corrupt("prune boundary entry is missing from the chain".into())
    })?;
    // The one sanctioned exception to the forbid-delete trigger: the trigger
    // is dropped and re-created inside this same write-locked transaction.
    sqlx::query("DROP TRIGGER audit_log_no_delete")
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    let deleted = sqlx::query("DELETE FROM audit_log WHERE id <= ?")
        .bind(prune_through)
        .execute(&mut **tx)
        .await
        .map_err(storage)?
        .rows_affected();
    sqlx::query(NO_DELETE_TRIGGER_SQL)
        .execute(&mut **tx)
        .await
        .map_err(storage)?;
    sqlx::query(
        "INSERT INTO audit_log_anchor(singleton, pruned_through_id, pruned_through_hash, pruned_at) \
         VALUES(1, ?, ?, ?) \
         ON CONFLICT(singleton) DO UPDATE SET pruned_through_id=excluded.pruned_through_id, \
         pruned_through_hash=excluded.pruned_through_hash, pruned_at=excluded.pruned_at",
    )
    .bind(prune_through)
    .bind(&anchor_hash)
    .bind(pruned_at)
    .execute(&mut **tx)
    .await
    .map_err(storage)?;
    Ok(PruneReport {
        pruned_rows: deleted,
        remaining_rows: u64::try_from(remaining_after).unwrap_or(0),
        pruned_through_id: Some(prune_through),
        pruned_through_hash: Some(anchor_hash),
        kept_out_of_order_rows: u64::try_from(kept_out_of_order).unwrap_or(0),
    })
}

fn decode_entry(row: StoredEntryRow) -> Result<AppendedEntry, AuditLogError> {
    let (id, occurred_at, actor, category, action, subject, detail, prev_hash, entry_hash) = row;
    let actor = AuditActor::parse(&actor)
        .ok_or_else(|| AuditLogError::Corrupt(format!("entry {id} has an unknown actor")))?;
    let category = AuditCategory::parse(&category)
        .ok_or_else(|| AuditLogError::Corrupt(format!("entry {id} has an unknown category")))?;
    let detail: serde_json::Value = serde_json::from_str(&detail)
        .map_err(|_| AuditLogError::Corrupt(format!("entry {id} detail is not JSON")))?;
    Ok(AppendedEntry {
        id,
        occurred_at: decode_time(&occurred_at)?,
        actor,
        category,
        action,
        subject,
        detail,
        prev_hash,
        entry_hash,
    })
}

/// Canonical encoding hashed into `entry_hash`: a domain-separation constant,
/// the big-endian id, then every text field length-prefixed (with an explicit
/// presence tag for the nullable subject), ending with `prev_hash`.
#[allow(clippy::too_many_arguments)] // fields mirror one durable chain entry
fn compute_entry_hash(
    id: i64,
    occurred_at: &str,
    actor: &str,
    category: &str,
    action: &str,
    subject: Option<&str>,
    detail: &str,
    prev_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, ENTRY_DOMAIN);
    hasher.update(id.to_be_bytes());
    hash_str(&mut hasher, occurred_at);
    hash_str(&mut hasher, actor);
    hash_str(&mut hasher, category);
    hash_str(&mut hasher, action);
    match subject {
        None => hasher.update([0u8]),
        Some(subject) => {
            hasher.update([1u8]);
            hash_str(&mut hasher, subject);
        }
    }
    hash_str(&mut hasher, detail);
    hash_str(&mut hasher, prev_hash);
    hex_encode(&hasher.finalize())
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn encode_time(value: DateTime<Utc>) -> Option<String> {
    (value.year() >= 1970 && value.year() <= 9999)
        .then(|| value.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

fn decode_time(value: &str) -> Result<DateTime<Utc>, AuditLogError> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|_| AuditLogError::Corrupt("stored timestamp is invalid".into()))?
        .with_timezone(&Utc);
    if encode_time(parsed).as_deref() == Some(value) {
        Ok(parsed)
    } else {
        Err(AuditLogError::Corrupt(
            "stored timestamp is not canonical".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_stable_hex() {
        let genesis = genesis_hash();
        assert_eq!(genesis.len(), 64);
        assert!(genesis.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(genesis, genesis_hash());
    }

    #[test]
    fn entry_hash_distinguishes_missing_and_empty_like_fields() {
        let base = compute_entry_hash(1, "t", "owner", "scan", "a", None, "{}", "p");
        let with_subject = compute_entry_hash(1, "t", "owner", "scan", "a", Some(""), "{}", "p");
        assert_ne!(base, with_subject);
        // Length prefixing prevents field-boundary ambiguity.
        let ab = compute_entry_hash(1, "t", "owner", "scan", "ab", Some("c"), "{}", "p");
        let a_bc = compute_entry_hash(1, "t", "owner", "scan", "a", Some("bc"), "{}", "p");
        assert_ne!(ab, a_bc);
    }

    #[test]
    fn actor_and_category_round_trip() {
        for actor in [AuditActor::Owner, AuditActor::Service, AuditActor::Module] {
            assert_eq!(AuditActor::parse(actor.as_str()), Some(actor));
        }
        for category in [
            AuditCategory::Approval,
            AuditCategory::Scan,
            AuditCategory::Enforcement,
            AuditCategory::DoctorAction,
            AuditCategory::AuditModule,
        ] {
            assert_eq!(AuditCategory::parse(category.as_str()), Some(category));
        }
        assert_eq!(AuditActor::parse("root"), None);
        assert_eq!(AuditCategory::parse("misc"), None);
    }
}
