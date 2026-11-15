//! M6 remote access persistence (T3, I1): phone pairing sessions with PIN
//! step-up state, and scoped read-only integration tokens.
//!
//! This module stores only hashes, never secrets: the caller (the service)
//! hashes the pairing secret and integration token with SHA-256 and the
//! step-up PIN with Argon2id, and hands the digests down as opaque strings.
//! Rate-limit and step-up state live on the session row so a lockout
//! survives a service restart.

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone, Debug, Error, PartialEq)]
pub enum RemoteAccessStoreError {
    #[error("remote access record is invalid: {0}")]
    Invalid(String),
    #[error("remote access storage is corrupt: {0}")]
    Corrupt(String),
    #[error("remote access storage failed: {0}")]
    Storage(String),
}

fn storage(error: sqlx::Error) -> RemoteAccessStoreError {
    RemoteAccessStoreError::Storage(error.to_string())
}

fn encode_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn decode_time(value: &str) -> Result<DateTime<Utc>, RemoteAccessStoreError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| RemoteAccessStoreError::Corrupt("stored timestamp is invalid".into()))
}

fn decode_opt_time(value: Option<String>) -> Result<Option<DateTime<Utc>>, RemoteAccessStoreError> {
    value.as_deref().map(decode_time).transpose()
}

fn decode_uuid(value: &str) -> Result<Uuid, RemoteAccessStoreError> {
    Uuid::parse_str(value)
        .map_err(|_| RemoteAccessStoreError::Corrupt("stored id is not a uuid".into()))
}

/// A new pairing; the service mints the id and hashes before insertion.
#[derive(Clone, Debug)]
pub struct NewPhoneSession {
    pub id: Uuid,
    /// SHA-256 hex of the pairing secret.
    pub secret_hash: String,
    pub device_label: String,
    /// Argon2id PHC string of the 6-digit step-up PIN.
    pub pin_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The full durable session row, hashes included — for authentication only.
#[derive(Clone, Debug, PartialEq)]
pub struct PhoneSessionRow {
    pub id: Uuid,
    pub secret_hash: String,
    pub device_label: String,
    pub pin_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub stepup_expires_at: Option<DateTime<Utc>>,
    pub pin_failed_count: u32,
    pub pin_window_started_at: Option<DateTime<Utc>>,
    pub pin_locked_until: Option<DateTime<Utc>>,
}

/// The accounting that resulted from one atomically recorded PIN failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinFailureOutcome {
    /// Failures charged inside the current window, this one included.
    pub failed_count: u32,
    /// Set when this failure locked the session.
    pub locked_until: Option<DateTime<Utc>>,
}

/// Outcome of [`RemoteAccessRepository::reserve_pin_attempt`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinReservation {
    /// The attempt was admitted; the caller may now verify the PIN.
    Reserved { attempt: u32 },
    /// The budget is spent or the session is locked; do not verify.
    Locked { until: DateTime<Utc> },
    NoSession,
}

/// A durable replay record for one phone command id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandReplay {
    pub fingerprint: String,
    /// False while the command may still be (or may have been) executing.
    pub completed: bool,
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// The response was too large to retain; only its status is replayed.
    pub body_omitted: bool,
}

/// The hash-free projection served to the owner session list.
#[derive(Clone, Debug, PartialEq)]
pub struct PhoneSessionSummary {
    pub id: Uuid,
    pub device_label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// A new integration token; the service mints the id and hash.
#[derive(Clone, Debug)]
pub struct NewIntegrationToken {
    pub id: Uuid,
    pub name: String,
    /// SHA-256 hex of the token secret.
    pub token_hash: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// The hash-free durable integration token row.
#[derive(Clone, Debug, PartialEq)]
pub struct IntegrationTokenRow {
    pub id: Uuid,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

type PhoneSessionSqlRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    i64,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
);

type IntegrationTokenSqlRow = (String, String, String, String, i64);

fn decode_phone_session(
    row: PhoneSessionSqlRow,
) -> Result<PhoneSessionRow, RemoteAccessStoreError> {
    let (
        id,
        secret_hash,
        device_label,
        pin_hash,
        created_at,
        expires_at,
        last_used_at,
        revoked,
        stepup_expires_at,
        pin_failed_count,
        pin_window_started_at,
        pin_locked_until,
    ) = row;
    Ok(PhoneSessionRow {
        id: decode_uuid(&id)?,
        secret_hash,
        device_label,
        pin_hash,
        created_at: decode_time(&created_at)?,
        expires_at: decode_time(&expires_at)?,
        last_used_at: decode_opt_time(last_used_at)?,
        revoked: revoked != 0,
        stepup_expires_at: decode_opt_time(stepup_expires_at)?,
        pin_failed_count: u32::try_from(pin_failed_count)
            .map_err(|_| RemoteAccessStoreError::Corrupt("negative pin failure count".into()))?,
        pin_window_started_at: decode_opt_time(pin_window_started_at)?,
        pin_locked_until: decode_opt_time(pin_locked_until)?,
    })
}

fn decode_integration_token(
    row: IntegrationTokenSqlRow,
) -> Result<IntegrationTokenRow, RemoteAccessStoreError> {
    let (id, name, scopes, created_at, revoked) = row;
    let scopes: Vec<String> = serde_json::from_str(&scopes).map_err(|_| {
        RemoteAccessStoreError::Corrupt("stored scopes are not a JSON array".into())
    })?;
    Ok(IntegrationTokenRow {
        id: decode_uuid(&id)?,
        name,
        scopes,
        created_at: decode_time(&created_at)?,
        revoked: revoked != 0,
    })
}

#[derive(Clone)]
pub struct RemoteAccessRepository {
    pool: SqlitePool,
}

impl RemoteAccessRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn insert_phone_session(
        &self,
        session: &NewPhoneSession,
    ) -> Result<(), RemoteAccessStoreError> {
        sqlx::query(
            "INSERT INTO phone_sessions(id, secret_hash, device_label, pin_hash, created_at, expires_at) \
             VALUES(?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.to_string())
        .bind(&session.secret_hash)
        .bind(&session.device_label)
        .bind(&session.pin_hash)
        .bind(encode_time(session.created_at))
        .bind(encode_time(session.expires_at))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    pub async fn load_phone_session(
        &self,
        id: Uuid,
    ) -> Result<Option<PhoneSessionRow>, RemoteAccessStoreError> {
        let row: Option<PhoneSessionSqlRow> = sqlx::query_as(
            "SELECT id, secret_hash, device_label, pin_hash, created_at, expires_at, last_used_at, \
             revoked, stepup_expires_at, pin_failed_count, pin_window_started_at, pin_locked_until \
             FROM phone_sessions WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(decode_phone_session).transpose()
    }

    pub async fn list_phone_sessions(
        &self,
    ) -> Result<Vec<PhoneSessionSummary>, RemoteAccessStoreError> {
        let rows: Vec<(String, String, String, String, Option<String>, i64)> = sqlx::query_as(
            "SELECT id, device_label, created_at, expires_at, last_used_at, revoked \
             FROM phone_sessions ORDER BY created_at ASC, id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter()
            .map(
                |(id, device_label, created_at, expires_at, last_used_at, revoked)| {
                    Ok(PhoneSessionSummary {
                        id: decode_uuid(&id)?,
                        device_label,
                        created_at: decode_time(&created_at)?,
                        expires_at: decode_time(&expires_at)?,
                        last_used_at: decode_opt_time(last_used_at)?,
                        revoked: revoked != 0,
                    })
                },
            )
            .collect()
    }

    /// Marks the session revoked; returns false when no such session exists.
    pub async fn revoke_phone_session(&self, id: Uuid) -> Result<bool, RemoteAccessStoreError> {
        let result = sqlx::query("UPDATE phone_sessions SET revoked = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected() > 0)
    }

    /// Records a successful authentication and slides the expiry forward.
    /// Only a live session is touched: a revoked or already-expired row is
    /// never resurrected. Returns false when nothing was updated.
    pub async fn touch_phone_session(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, RemoteAccessStoreError> {
        let result = sqlx::query(
            "UPDATE phone_sessions SET last_used_at = ?, expires_at = ? \
             WHERE id = ? AND revoked = 0 AND expires_at > ?",
        )
        .bind(encode_time(now))
        .bind(encode_time(expires_at))
        .bind(id.to_string())
        .bind(encode_time(now))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() > 0)
    }

    /// Deletes sessions that can never authenticate again: expired ones, and
    /// revoked ones older than `revoked_retention` (kept briefly so the owner
    /// still sees them in the list). Replay records cascade. Returns the
    /// number of sessions removed. Intended for the maintenance task.
    pub async fn purge_dead_phone_sessions(
        &self,
        now: DateTime<Utc>,
        revoked_retention: chrono::Duration,
    ) -> Result<u64, RemoteAccessStoreError> {
        let result = sqlx::query(
            "DELETE FROM phone_sessions WHERE expires_at <= ?1 \
             OR (revoked = 1 AND COALESCE(last_used_at, created_at) <= ?2)",
        )
        .bind(encode_time(now))
        .bind(encode_time(now - revoked_retention))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected())
    }

    /// Grants a step-up grace window and clears PIN failure state. Refused
    /// (returns false) while the session is PIN-locked: a correct PIN that
    /// arrives after the budget was spent, or raced the lock, never wins.
    pub async fn grant_stepup(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, RemoteAccessStoreError> {
        let result = sqlx::query(
            "UPDATE phone_sessions SET stepup_expires_at = ?, pin_failed_count = 0, \
             pin_window_started_at = NULL, pin_locked_until = NULL \
             WHERE id = ? AND (pin_locked_until IS NULL OR pin_locked_until <= ?)",
        )
        .bind(encode_time(expires_at))
        .bind(id.to_string())
        .bind(encode_time(now))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(result.rows_affected() > 0)
    }

    /// Withdraws a step-up grace window (used when the grant could not be audited).
    pub async fn revoke_stepup(&self, id: Uuid) -> Result<(), RemoteAccessStoreError> {
        sqlx::query("UPDATE phone_sessions SET stepup_expires_at = NULL WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Atomically reserves one PIN attempt BEFORE the PIN is verified.
    ///
    /// The window check, the budget check and the increment are one
    /// `UPDATE ... RETURNING`, so no more than `max_attempts` verifications
    /// can ever be admitted per window no matter how many requests race: the
    /// request that cannot reserve is refused without being evaluated. A
    /// successful verification calls [`Self::grant_stepup`] (which resets the
    /// counter); a failed one calls [`Self::finish_pin_failure`].
    pub async fn reserve_pin_attempt(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
        window: chrono::Duration,
        max_attempts: u32,
    ) -> Result<PinReservation, RemoteAccessStoreError> {
        let window_floor = encode_time(now - window);
        let now_text = encode_time(now);
        let row: Option<(i64,)> = sqlx::query_as(
            "UPDATE phone_sessions SET \
                pin_failed_count = CASE \
                    WHEN pin_window_started_at IS NOT NULL AND pin_window_started_at > ?1 \
                    THEN pin_failed_count + 1 ELSE 1 END, \
                pin_window_started_at = CASE \
                    WHEN pin_window_started_at IS NOT NULL AND pin_window_started_at > ?1 \
                    THEN pin_window_started_at ELSE ?2 END \
             WHERE id = ?4 \
               AND (pin_window_started_at IS NULL OR pin_window_started_at <= ?1 \
                    OR pin_failed_count < ?3) \
               AND (pin_locked_until IS NULL OR pin_locked_until <= ?2) \
             RETURNING pin_failed_count",
        )
        .bind(window_floor)
        .bind(&now_text)
        .bind(i64::from(max_attempts))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        if let Some((count,)) = row {
            return Ok(PinReservation::Reserved {
                attempt: u32::try_from(count).map_err(|_| {
                    RemoteAccessStoreError::Corrupt("negative pin failure count".into())
                })?,
            });
        }
        let existing: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT pin_locked_until, pin_window_started_at FROM phone_sessions WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some((locked_until, started)) = existing else {
            return Ok(PinReservation::NoSession);
        };
        let until = match decode_opt_time(locked_until)? {
            Some(until) if until > now => until,
            _ => decode_opt_time(started)?.map_or(now + window, |started| started + window),
        };
        Ok(PinReservation::Locked { until })
    }

    /// Completes a failed, previously reserved attempt. `attempt` is the
    /// number [`PinReservation::Reserved`] reported; the reservation that
    /// spent the last of the budget (`attempt >= max_attempts`) locks the
    /// session until `now + window`. Returns `None` for an unknown session.
    pub async fn finish_pin_failure(
        &self,
        id: Uuid,
        attempt: u32,
        now: DateTime<Utc>,
        window: chrono::Duration,
        max_attempts: u32,
    ) -> Result<Option<PinFailureOutcome>, RemoteAccessStoreError> {
        let locks = attempt >= max_attempts;
        let locked_until = now + window;
        let result = sqlx::query(
            "UPDATE phone_sessions SET pin_locked_until = CASE WHEN ?1 THEN ?2 ELSE pin_locked_until END
             WHERE id = ?3",
        )
        .bind(locks)
        .bind(encode_time(locked_until))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        if result.rows_affected() == 0 {
            return Ok(None);
        }
        Ok(Some(PinFailureOutcome {
            failed_count: attempt,
            locked_until: locks.then_some(locked_until),
        }))
    }

    /// Claims `command_id` for the request with `fingerprint`, writing an
    /// in-flight record. Returns the existing record when the id was already
    /// claimed (replay / conflict / outcome unknown), or `None` when the claim
    /// was newly made and the caller must execute the command.
    pub async fn claim_command(
        &self,
        session_id: Uuid,
        command_id: Uuid,
        fingerprint: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<CommandReplay>, RemoteAccessStoreError> {
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO phone_command_replays \
             (session_id, command_id, request_fingerprint, created_at, seq) \
             VALUES (?1, ?2, ?3, ?4, \
                COALESCE((SELECT MAX(seq) FROM phone_command_replays WHERE session_id = ?1), 0) + 1)",
        )
        .bind(session_id.to_string())
        .bind(command_id.to_string())
        .bind(fingerprint)
        .bind(encode_time(now))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        if inserted.rows_affected() > 0 {
            return Ok(None);
        }
        let row: Option<(String, i64, i64, Option<String>, Option<Vec<u8>>, i64)> =
            sqlx::query_as(
                "SELECT request_fingerprint, completed, status, content_type, body, body_omitted \
                 FROM phone_command_replays WHERE session_id = ? AND command_id = ?",
            )
            .bind(session_id.to_string())
            .bind(command_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(storage)?;
        let Some((fingerprint, completed, status, content_type, body, omitted)) = row else {
            return Err(RemoteAccessStoreError::Storage(
                "command record vanished during claim".into(),
            ));
        };
        Ok(Some(CommandReplay {
            fingerprint,
            completed: completed != 0,
            status: u16::try_from(status).unwrap_or(500),
            content_type,
            body: body.unwrap_or_default(),
            body_omitted: omitted != 0,
        }))
    }

    /// Completes a claimed command with its response, then trims the session's
    /// settled records to the newest `keep`.
    pub async fn complete_command(
        &self,
        session_id: Uuid,
        command_id: Uuid,
        status: u16,
        content_type: Option<&str>,
        body: Option<&[u8]>,
        keep: u32,
    ) -> Result<(), RemoteAccessStoreError> {
        sqlx::query(
            "UPDATE phone_command_replays SET completed = 1, status = ?, content_type = ?, \
             body = ?, body_omitted = ? WHERE session_id = ? AND command_id = ?",
        )
        .bind(i64::from(status))
        .bind(content_type)
        .bind(body)
        .bind(i64::from(body.is_none()))
        .bind(session_id.to_string())
        .bind(command_id.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        sqlx::query(
            "DELETE FROM phone_command_replays WHERE session_id = ?1 AND completed = 1 AND seq <= \
             (SELECT MAX(seq) FROM phone_command_replays WHERE session_id = ?1) - ?2",
        )
        .bind(session_id.to_string())
        .bind(i64::from(keep))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// Records one failed PIN attempt atomically and returns the resulting
    /// accounting.
    ///
    /// The window check, the counter increment, and the lock decision all
    /// happen inside a single `UPDATE ... RETURNING`, so concurrent failures
    /// can never observe the same stale count: N parallel wrong guesses are
    /// charged as N failures, not one. A window is live while it started less
    /// than `window` ago; otherwise the failure opens a new window at `now`.
    /// Reaching `max_failures` inside a live window locks the session until
    /// `now + window`. Returns `None` when no such session exists.
    pub async fn record_pin_failure(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
        window: chrono::Duration,
        max_failures: u32,
    ) -> Result<Option<PinFailureOutcome>, RemoteAccessStoreError> {
        // Stored timestamps are fixed-width RFC 3339 (micros, `Z`), so a
        // lexical comparison is a chronological one.
        let window_floor = encode_time(now - window);
        let now_text = encode_time(now);
        let locked_until = encode_time(now + window);
        let row: Option<(i64, Option<String>)> = sqlx::query_as(
            "UPDATE phone_sessions SET \
                pin_failed_count = CASE \
                    WHEN pin_window_started_at IS NOT NULL AND pin_window_started_at > ?1 \
                    THEN pin_failed_count + 1 ELSE 1 END, \
                pin_window_started_at = CASE \
                    WHEN pin_window_started_at IS NOT NULL AND pin_window_started_at > ?1 \
                    THEN pin_window_started_at ELSE ?2 END, \
                pin_locked_until = CASE \
                    WHEN (CASE \
                        WHEN pin_window_started_at IS NOT NULL AND pin_window_started_at > ?1 \
                        THEN pin_failed_count + 1 ELSE 1 END) >= ?3 \
                    THEN ?4 ELSE NULL END \
             WHERE id = ?5 \
             RETURNING pin_failed_count, pin_locked_until",
        )
        .bind(window_floor)
        .bind(now_text)
        .bind(i64::from(max_failures))
        .bind(locked_until)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        let Some((failed_count, locked_until)) = row else {
            return Ok(None);
        };
        Ok(Some(PinFailureOutcome {
            failed_count: u32::try_from(failed_count).map_err(|_| {
                RemoteAccessStoreError::Corrupt("negative pin failure count".into())
            })?,
            locked_until: decode_opt_time(locked_until)?,
        }))
    }

    pub async fn insert_integration_token(
        &self,
        token: &NewIntegrationToken,
    ) -> Result<(), RemoteAccessStoreError> {
        if token.scopes.is_empty() {
            return Err(RemoteAccessStoreError::Invalid(
                "an integration token needs at least one scope".into(),
            ));
        }
        let scopes = serde_json::to_string(&token.scopes)
            .map_err(|error| RemoteAccessStoreError::Invalid(error.to_string()))?;
        sqlx::query(
            "INSERT INTO integration_tokens(id, name, token_hash, scopes, created_at) \
             VALUES(?, ?, ?, ?, ?)",
        )
        .bind(token.id.to_string())
        .bind(&token.name)
        .bind(&token.token_hash)
        .bind(scopes)
        .bind(encode_time(token.created_at))
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// Looks up a live token row by its SHA-256 hex digest.
    pub async fn find_integration_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<IntegrationTokenRow>, RemoteAccessStoreError> {
        let row: Option<IntegrationTokenSqlRow> = sqlx::query_as(
            "SELECT id, name, scopes, created_at, revoked FROM integration_tokens \
             WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        row.map(decode_integration_token).transpose()
    }

    pub async fn list_integration_tokens(
        &self,
    ) -> Result<Vec<IntegrationTokenRow>, RemoteAccessStoreError> {
        let rows: Vec<IntegrationTokenSqlRow> = sqlx::query_as(
            "SELECT id, name, scopes, created_at, revoked FROM integration_tokens \
             ORDER BY created_at ASC, id ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(storage)?;
        rows.into_iter().map(decode_integration_token).collect()
    }

    /// Marks the token revoked; returns false when no such token exists.
    pub async fn revoke_integration_token(&self, id: Uuid) -> Result<bool, RemoteAccessStoreError> {
        let result = sqlx::query("UPDATE integration_tokens SET revoked = 1 WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(result.rows_affected() > 0)
    }
}
