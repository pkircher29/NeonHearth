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
    pub async fn touch_phone_session(
        &self,
        id: Uuid,
        last_used_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RemoteAccessStoreError> {
        sqlx::query("UPDATE phone_sessions SET last_used_at = ?, expires_at = ? WHERE id = ?")
            .bind(encode_time(last_used_at))
            .bind(encode_time(expires_at))
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(storage)?;
        Ok(())
    }

    /// Grants a step-up grace window and clears PIN failure state.
    pub async fn grant_stepup(
        &self,
        id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<(), RemoteAccessStoreError> {
        sqlx::query(
            "UPDATE phone_sessions SET stepup_expires_at = ?, pin_failed_count = 0, \
             pin_window_started_at = NULL, pin_locked_until = NULL WHERE id = ?",
        )
        .bind(encode_time(expires_at))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
    }

    /// Writes the caller-computed PIN failure accounting for one session.
    pub async fn record_pin_failure(
        &self,
        id: Uuid,
        failed_count: u32,
        window_started_at: DateTime<Utc>,
        locked_until: Option<DateTime<Utc>>,
    ) -> Result<(), RemoteAccessStoreError> {
        sqlx::query(
            "UPDATE phone_sessions SET pin_failed_count = ?, pin_window_started_at = ?, \
             pin_locked_until = ? WHERE id = ?",
        )
        .bind(i64::from(failed_count))
        .bind(encode_time(window_started_at))
        .bind(locked_until.map(encode_time))
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(storage)?;
        Ok(())
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
