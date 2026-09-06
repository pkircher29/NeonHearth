//! RLS3: SQLite integrity checks, atomic backup, verified restore, retention,
//! and disk-pressure reporting.
//!
//! Backup strategy: `VACUUM INTO` writes a complete, consistent, compacted
//! snapshot of the database. It is not the online-backup API, but it runs
//! against the live pool without blocking writers for the whole copy, and we
//! make the destination atomic by writing to a temporary file in the
//! destination directory and renaming it into place — the backup either exists
//! completely at its final path or not at all.
//!
//! Restore strategy: [`DbMaintenance::restore_from`] consumes `self` and closes
//! the pool before touching any files, so the type system prevents restoring
//! underneath an open pool. The current database is kept next to the restored
//! one as `<db>.pre-restore` until the next restore overwrites it.

use crate::audit_log::{AuditLog, AuditLogError, PruneReport};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::path::{Path, PathBuf};
use thiserror::Error;
use utoipa::ToSchema;

#[derive(Clone, Debug, Error, PartialEq)]
pub enum MaintenanceError {
    #[error("path is not usable: {0}")]
    InvalidPath(String),
    #[error("backup failed verification: {0}")]
    BackupInvalid(String),
    #[error("restore refused: {0}")]
    RestoreRefused(String),
    #[error("retention job is invalid: {0}")]
    InvalidJob(String),
    #[error("maintenance file operation failed: {0}")]
    Io(String),
    #[error("maintenance storage failed: {0}")]
    Storage(String),
    #[error("audit retention failed: {0}")]
    Audit(#[from] AuditLogError),
}

fn storage(error: sqlx::Error) -> MaintenanceError {
    MaintenanceError::Storage(error.to_string())
}

fn io_error(context: &str, error: std::io::Error) -> MaintenanceError {
    MaintenanceError::Io(format!("{context}: {error}"))
}

/// One foreign-key violation reported by `PRAGMA foreign_key_check`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct ForeignKeyViolation {
    pub table: String,
    pub rowid: Option<i64>,
    pub parent: String,
}

/// Result of `PRAGMA integrity_check` + `PRAGMA foreign_key_check`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct IntegrityReport {
    pub ok: bool,
    /// Messages from `integrity_check` (empty when healthy). A check that
    /// cannot even run (malformed image) is reported here, never hidden.
    pub integrity_errors: Vec<String>,
    pub foreign_key_violations: Vec<ForeignKeyViolation>,
}

/// A verified backup's provenance facts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct BackupVerification {
    /// `MAX(version)` from `_sqlx_migrations` — the schema the backup carries.
    pub migration_version: i64,
    /// The `install_state.schema_version` footer, when an install row exists.
    pub install_schema_version: Option<i64>,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct BackupReport {
    pub destination: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct RestoreReport {
    pub restored_from: String,
    /// Where the pre-restore database was kept, when one existed.
    pub previous_database: Option<String>,
    pub verification: BackupVerification,
}

/// Retention configuration for the audit log. At least one bound must be set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct RetentionJob {
    /// Prune audit entries older than this many seconds (oldest-side only).
    pub max_age_seconds: Option<u64>,
    /// Keep at most this many newest audit entries.
    pub max_rows: Option<u64>,
}

/// Free-space report. This module never deletes anything on pressure —
/// callers decide what, if anything, to do.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct DiskPressureReport {
    pub path: String,
    pub available_bytes: u64,
    pub min_free_bytes: u64,
    /// True when available space is below the requested floor.
    pub low: bool,
    /// How many bytes short of the floor the volume is (0 when not low).
    pub shortfall_bytes: u64,
}

#[derive(Clone)]
pub struct DbMaintenance {
    pool: SqlitePool,
    db_path: PathBuf,
}

impl DbMaintenance {
    /// `db_path` must be the file backing `pool`.
    pub fn new(pool: SqlitePool, db_path: impl Into<PathBuf>) -> Self {
        Self {
            pool,
            db_path: db_path.into(),
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check` against
    /// the live pool.
    pub async fn integrity_check(&self) -> Result<IntegrityReport, MaintenanceError> {
        integrity_check_pool(&self.pool).await
    }

    /// Writes a complete snapshot of the database to `destination` using
    /// `VACUUM INTO` a temporary file in the destination directory, then an
    /// atomic rename. See the module docs for why this is the chosen strategy.
    ///
    /// Durability: the temporary file is created private (0600 on Unix) and
    /// fsynced before the rename, and the directory is fsynced after it, so a
    /// power loss cannot publish a truncated file at the final path. The live
    /// database and its sidecars are refused as destinations.
    pub async fn backup_to(&self, destination: &Path) -> Result<BackupReport, MaintenanceError> {
        let destination_text = utf8_path(destination)?;
        self.refuse_live_paths(destination)?;
        let temp = suffixed(destination, ".tmp");
        let temp_text = utf8_path(&temp)?;
        if temp.exists() {
            std::fs::remove_file(&temp)
                .map_err(|error| io_error("remove stale backup temp file", error))?;
        }
        // VACUUM INTO accepts an existing *empty* file, which lets the file be
        // created with private permissions before any data lands in it.
        create_private_empty(&temp)?;
        // VACUUM INTO takes no bind parameters for its target; escape quotes.
        let sql = format!("VACUUM INTO '{}'", temp_text.replace('\'', "''"));
        if let Err(error) = sqlx::query(&sql).execute(&self.pool).await {
            let _ = std::fs::remove_file(&temp);
            return Err(storage(error));
        }
        let size_bytes = sync_file(&temp)?;
        std::fs::rename(&temp, destination)
            .map_err(|error| io_error("rename backup into place", error))?;
        sync_parent_dir(destination)?;
        Ok(BackupReport {
            destination: destination_text,
            size_bytes,
        })
    }

    /// Refuses `candidate` when it resolves to the live database file or one
    /// of its sidecars (`-wal`, `-shm`, `.migrate.lock`): renaming a backup
    /// over the open database would corrupt it.
    fn refuse_live_paths(&self, candidate: &Path) -> Result<(), MaintenanceError> {
        let live = [
            self.db_path.clone(),
            suffixed(&self.db_path, "-wal"),
            suffixed(&self.db_path, "-shm"),
            suffixed(&self.db_path, ".migrate.lock"),
        ];
        if live.iter().any(|path| same_target(candidate, path)) {
            return Err(MaintenanceError::InvalidPath(format!(
                "{} is the live database or one of its sidecar files",
                candidate.display()
            )));
        }
        Ok(())
    }

    /// Opens `path` read-only and proves it is a healthy NeonHearth database:
    /// integrity + foreign-key checks pass and the migration/schema versions
    /// are readable.
    pub async fn verify_backup(path: &Path) -> Result<BackupVerification, MaintenanceError> {
        let size_bytes = std::fs::metadata(path)
            .map_err(|error| {
                MaintenanceError::BackupInvalid(format!("cannot stat backup: {error}"))
            })?
            .len();
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .create_if_missing(false);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(|error| {
                MaintenanceError::BackupInvalid(format!("cannot open backup: {error}"))
            })?;
        let result = verify_open_backup(&pool, size_bytes).await;
        pool.close().await;
        result
    }

    /// Replaces the database file with a verified backup.
    ///
    /// Consumes `self` and closes the pool first, so a restore cannot run
    /// underneath open connections; reconnect with [`crate::connect_path`]
    /// afterwards. Refuses any backup that fails [`Self::verify_backup`].
    pub async fn restore_from(self, backup: &Path) -> Result<RestoreReport, MaintenanceError> {
        let verification = Self::verify_backup(backup)
            .await
            .map_err(|error| match error {
                MaintenanceError::BackupInvalid(reason) => MaintenanceError::RestoreRefused(reason),
                other => other,
            })?;
        let backup_text = utf8_path(backup)?;
        self.refuse_live_paths(backup)?;
        self.pool.close().await;

        let staged = suffixed(&self.db_path, ".restore-tmp");
        if staged.exists() {
            std::fs::remove_file(&staged)
                .map_err(|error| io_error("remove stale restore staging file", error))?;
        }
        create_private_empty(&staged)?;
        std::fs::copy(backup, &staged).map_err(|error| io_error("stage restore copy", error))?;
        sync_file(&staged)?;
        // The incoming snapshot has no journal; stale sidecar files from the
        // old database must not be replayed into it.
        for suffix in ["-wal", "-shm"] {
            let sidecar = suffixed(&self.db_path, suffix);
            if sidecar.exists() {
                std::fs::remove_file(&sidecar)
                    .map_err(|error| io_error("remove database sidecar file", error))?;
            }
        }
        let previous = suffixed(&self.db_path, ".pre-restore");
        let previous_kept = if self.db_path.exists() {
            std::fs::rename(&self.db_path, &previous)
                .map_err(|error| io_error("set aside current database", error))?;
            true
        } else {
            false
        };
        if let Err(error) = std::fs::rename(&staged, &self.db_path) {
            // Best-effort rollback: put the original database back.
            if previous_kept {
                let _ = std::fs::rename(&previous, &self.db_path);
            }
            return Err(io_error("activate restored database", error));
        }
        sync_parent_dir(&self.db_path)?;
        Ok(RestoreReport {
            restored_from: backup_text,
            previous_database: previous_kept.then(|| previous.display().to_string()),
            verification,
        })
    }

    /// Applies audit-log retention (RLS3): oldest-side pruning with a
    /// `pruned_through` anchor, delegated to [`AuditLog::retention_prune`].
    pub async fn retention(
        &self,
        job: RetentionJob,
        now: DateTime<Utc>,
    ) -> Result<PruneReport, MaintenanceError> {
        if job.max_age_seconds.is_none() && job.max_rows.is_none() {
            return Err(MaintenanceError::InvalidJob(
                "set max_age_seconds and/or max_rows".into(),
            ));
        }
        let before = job
            .max_age_seconds
            .map(|seconds| {
                let age = i64::try_from(seconds)
                    .ok()
                    .and_then(Duration::try_seconds)
                    .ok_or_else(|| {
                        MaintenanceError::InvalidJob("max_age_seconds is out of range".into())
                    })?;
                now.checked_sub_signed(age).ok_or_else(|| {
                    MaintenanceError::InvalidJob("max_age_seconds underflows the epoch".into())
                })
            })
            .transpose()?;
        let report = AuditLog::new(self.pool.clone())
            .retention_prune(before, job.max_rows, now)
            .await?;
        Ok(report)
    }

    /// Reports free space on the volume holding `path` against a floor.
    /// Never deletes anything: on pressure, callers decide.
    pub fn disk_pressure(
        path: &Path,
        min_free_bytes: u64,
    ) -> Result<DiskPressureReport, MaintenanceError> {
        // Windows resolves free space for missing paths by walking up the
        // tree; require the queried path to actually exist so a typo'd data
        // directory cannot masquerade as a healthy volume.
        if !path.exists() {
            return Err(MaintenanceError::Io(format!(
                "path does not exist: {}",
                path.display()
            )));
        }
        let available_bytes = fs2::available_space(path)
            .map_err(|error| io_error("query available disk space", error))?;
        let shortfall_bytes = min_free_bytes.saturating_sub(available_bytes);
        Ok(DiskPressureReport {
            path: path.display().to_string(),
            available_bytes,
            min_free_bytes,
            low: available_bytes < min_free_bytes,
            shortfall_bytes,
        })
    }
}

async fn integrity_check_pool(pool: &SqlitePool) -> Result<IntegrityReport, MaintenanceError> {
    let integrity_errors = match sqlx::query_scalar::<_, String>("PRAGMA integrity_check")
        .fetch_all(pool)
        .await
    {
        Ok(rows) => rows.into_iter().filter(|row| row != "ok").collect(),
        // A database too damaged to even run the check is a failed check,
        // not a hidden success.
        Err(error) => vec![format!("integrity_check failed: {error}")],
    };
    let foreign_key_violations: Vec<ForeignKeyViolation> =
        match sqlx::query_as::<_, (String, Option<i64>, String, i64)>("PRAGMA foreign_key_check")
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|(table, rowid, parent, _fkid)| ForeignKeyViolation {
                    table,
                    rowid,
                    parent,
                })
                .collect(),
            Err(error) => {
                return Ok(IntegrityReport {
                    ok: false,
                    integrity_errors: vec![format!("foreign_key_check failed: {error}")],
                    foreign_key_violations: Vec::new(),
                });
            }
        };
    Ok(IntegrityReport {
        ok: integrity_errors.is_empty() && foreign_key_violations.is_empty(),
        integrity_errors,
        foreign_key_violations,
    })
}

async fn verify_open_backup(
    pool: &SqlitePool,
    size_bytes: u64,
) -> Result<BackupVerification, MaintenanceError> {
    let report = integrity_check_pool(pool).await?;
    if !report.ok {
        let mut reasons = report.integrity_errors;
        reasons.extend(
            report
                .foreign_key_violations
                .iter()
                .map(|violation| format!("foreign key violation in {}", violation.table)),
        );
        return Err(MaintenanceError::BackupInvalid(reasons.join("; ")));
    }
    let migration_version: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .map_err(|error| {
                MaintenanceError::BackupInvalid(format!(
                    "not a NeonHearth database (no migration history): {error}"
                ))
            })?;
    let migration_version = migration_version
        .ok_or_else(|| MaintenanceError::BackupInvalid("migration history is empty".into()))?;
    let install_schema_version: Option<i64> =
        sqlx::query_scalar("SELECT schema_version FROM install_state WHERE singleton = 1")
            .fetch_optional(pool)
            .await
            .map_err(|error| {
                MaintenanceError::BackupInvalid(format!(
                    "not a NeonHearth database (no install state table): {error}"
                ))
            })?;
    Ok(BackupVerification {
        migration_version,
        install_schema_version,
        size_bytes,
    })
}

fn utf8_path(path: &Path) -> Result<String, MaintenanceError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| MaintenanceError::InvalidPath(format!("{} is not UTF-8", path.display())))
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Creates `path` as a new, empty file readable only by the owner (Unix mode
/// 0600). Fails if the file already exists.
fn create_private_empty(path: &Path) -> Result<(), MaintenanceError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map(drop)
        .map_err(|error| io_error("create private file", error))
}

/// Flushes `path`'s contents to stable storage and returns its size.
fn sync_file(path: &Path) -> Result<u64, MaintenanceError> {
    // FlushFileBuffers requires write access on Windows. Do not truncate or
    // recreate the verified backup when opening its existing handle for sync.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(cfg!(windows))
        .open(path)
        .map_err(|error| io_error("open file for fsync", error))?;
    file.sync_all()
        .map_err(|error| io_error("fsync file", error))?;
    let size = file
        .metadata()
        .map_err(|error| io_error("stat file", error))?
        .len();
    Ok(size)
}

/// Flushes the directory entry for `path` so a rename survives power loss.
/// Directory fsync is a Unix notion; Windows has no equivalent through std.
fn sync_parent_dir(path: &Path) -> Result<(), MaintenanceError> {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
            _ => PathBuf::from("."),
        };
        let handle = std::fs::File::open(&dir)
            .map_err(|error| io_error("open directory for fsync", error))?;
        handle
            .sync_all()
            .map_err(|error| io_error("fsync directory", error))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Resolves a path to `canonical(parent)/file_name` so two spellings of the
/// same file compare equal even when the file itself does not exist yet.
fn resolve_target(path: &Path) -> PathBuf {
    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.canonicalize().ok(),
        _ => std::env::current_dir().ok(),
    };
    match (parent, path.file_name()) {
        (Some(dir), Some(name)) => dir.join(name),
        _ => path.to_path_buf(),
    }
}

fn same_target(a: &Path, b: &Path) -> bool {
    resolve_target(a) == resolve_target(b)
}
