//! Offline database restore and the post-restore reconciliation that follows it.
//!
//! A restore replaces the database file, so it cannot run inside the live
//! service (the pool must be closed). `lattice-service restore --from <file>`
//! runs it offline; the next normal startup then reconciles.
//!
//! Why a marker file and not a row: the restore swaps the whole database file,
//! so anything written inside the old database is discarded and anything
//! written into the new one needs a second write after the swap that a crash
//! could skip. The marker is a small file in the state directory, outside the
//! database it describes. It is written (temp file, fsync, rename) BEFORE the
//! swap starts, so there is no moment at which the database has been replaced
//! but the "reconcile required" fact is not durable. The price is that a crash
//! before the swap leaves a marker for a restore that never happened; the next
//! startup then runs one harmless extra reconciliation and says so in the
//! audit row. The marker is cleared only after reconciliation succeeded.
//!
//! Reconciliation reuses the policy coordinator's sweep, which is the
//! existing crash-recovery path: it re-evaluates every enrolled device, and
//! for any device whose actuation journal or decision outbox is pending it
//! reconciles with the actuator (read-only; anything it cannot prove stays
//! pending and fails closed) before it will act again. No second mechanism is
//! introduced.

use crate::{AppState, PlatformPaths};
use anyhow::Context;
use chrono::{DateTime, Utc};
use lattice_store::{
    AuditActor, AuditCategory, AuditLog, DbMaintenance, M2StateRepository, MaintenanceError,
    NewAuditEntry, PolicyRepository, RestoreReport,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};

/// File (in the state directory) whose presence means "a restore happened and
/// enforcement state has not been reconciled yet".
pub const RESTORE_MARKER_FILE: &str = "restore-reconcile.pending";

/// The name the supervised-task failure is reported under when
/// reconciliation fails (shown in the degraded status detail).
pub const RECONCILE_TASK: &str = "restore_reconcile";

pub fn marker_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RESTORE_MARKER_FILE)
}

/// Contents of the marker file. Informational: only its presence matters.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestoreMarker {
    pub restored_from: String,
    pub requested_at: String,
}

pub fn write_marker(path: &Path, marker: &RestoreMarker) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(marker).context("encode restore marker")?;
    crate::vault::write_private_atomically(path, &bytes)
        .map_err(|error| anyhow::anyhow!("write restore marker {}: {error:?}", path.display()))
}

/// `Ok(None)` when no marker exists. A marker that exists but cannot be parsed
/// still counts as present (fail safe): only a file that cannot be read at all
/// is an error.
pub fn read_marker(path: &Path) -> anyhow::Result<Option<RestoreMarker>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::Error::new(error)
                .context(format!("read restore marker {}", path.display())));
        }
    };
    Ok(Some(serde_json::from_str(&text).unwrap_or_else(|_| {
        RestoreMarker {
            restored_from: "unknown (marker content unreadable)".to_owned(),
            requested_at: "unknown".to_owned(),
        }
    })))
}

/// Removes the marker; a marker that is already gone is fine.
pub fn clear_marker(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(anyhow::Error::new(error)
                .context(format!("remove restore marker {}", path.display())))
        }
    }
}

/// Parses the arguments after `restore`: exactly `--from <file>` (or
/// `--from=<file>`).
pub fn parse_restore_args<I>(args: I) -> Result<PathBuf, String>
where
    I: IntoIterator<Item = OsString>,
{
    const USAGE: &str = "usage: lattice-service restore --from <backup-file>";
    let mut from: Option<PathBuf> = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let value = if arg == "--from" {
            args.next()
                .ok_or_else(|| format!("--from needs a backup file path; {USAGE}"))?
        } else if let Some(inline) = arg.to_str().and_then(|text| text.strip_prefix("--from=")) {
            OsString::from(inline)
        } else {
            return Err(format!("unrecognized argument {arg:?}; {USAGE}"));
        };
        if value.is_empty() {
            return Err(format!("--from needs a backup file path; {USAGE}"));
        }
        if from.replace(PathBuf::from(value)).is_some() {
            return Err(format!("--from was given more than once; {USAGE}"));
        }
    }
    from.ok_or_else(|| format!("restore needs --from <backup-file>; {USAGE}"))
}

/// Replaces the database under `paths` with `backup`. The caller must have
/// established that no service is running on this state directory (the binary
/// holds the loopback listen port for the duration).
///
/// Guarantees (from `DbMaintenance::restore_from`): the backup is verified
/// (integrity, foreign keys, migration history, not newer than this build)
/// before anything is touched, the current database is kept as
/// `<db>.pre-restore`, and any refusal leaves the original database in place.
///
/// The marker is written before the swap. If the restore is refused before
/// the swap, a marker this call created is removed again; if it fails at a
/// point where the swap may have started, the marker is kept.
pub async fn restore_database(
    paths: &PlatformPaths,
    backup: &Path,
) -> anyhow::Result<RestoreReport> {
    std::fs::create_dir_all(&paths.state_dir).context("create service state directory")?;
    let marker_file = marker_path(&paths.state_dir);
    let marker_existed = marker_file.exists();
    // A lazy pool never opens a connection, so a damaged live database cannot
    // block the restore that is meant to replace it. `restore_from` only
    // closes it.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_lazy_with(
            SqliteConnectOptions::new()
                .filename(&paths.database)
                .create_if_missing(false),
        );
    let maintenance = DbMaintenance::new(pool, paths.database.clone());
    write_marker(
        &marker_file,
        &RestoreMarker {
            restored_from: backup.display().to_string(),
            requested_at: Utc::now().to_rfc3339(),
        },
    )?;
    match maintenance.restore_from(backup).await {
        Ok(report) => Ok(report),
        Err(error) => {
            let untouched = matches!(
                error,
                MaintenanceError::BackupInvalid(_)
                    | MaintenanceError::RestoreRefused(_)
                    | MaintenanceError::InvalidPath(_)
            );
            if untouched && !marker_existed {
                let _ = clear_marker(&marker_file);
            }
            Err(anyhow::Error::new(error).context(if untouched {
                "restore refused; the database was not changed"
            } else {
                "restore failed part-way; check the database and its .pre-restore copy \
                 (a reconcile marker was kept)"
            }))
        }
    }
}

/// What a startup reconciliation did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    /// No marker: nothing to do.
    NotNeeded,
    /// The marker was present, the sweep ran, the audit row was written and
    /// the marker was cleared. `devices_reevaluated` is what `sweep` reported.
    Reconciled { devices_reevaluated: usize },
}

/// Marker-gated reconciliation. `sweep` re-derives enforcement state (the
/// production caller passes the policy coordinator's sweep) and returns how
/// many devices it re-evaluated. The marker is cleared only after the sweep
/// and the audit append both succeeded; on any error it stays.
///
/// A crash between the audit append and the marker removal repeats the
/// reconciliation on the next start (a second audit row), never skips it.
pub async fn reconcile_pending_restore<F, Fut>(
    marker_file: &Path,
    audit: &AuditLog,
    now: DateTime<Utc>,
    sweep: F,
) -> anyhow::Result<ReconcileOutcome>
where
    F: FnOnce(DateTime<Utc>) -> Fut,
    Fut: Future<Output = anyhow::Result<usize>>,
{
    let Some(marker) = read_marker(marker_file)? else {
        return Ok(ReconcileOutcome::NotNeeded);
    };
    let devices_reevaluated = sweep(now)
        .await
        .context("re-derive enforcement state after restore")?;
    audit
        .append(NewAuditEntry {
            occurred_at: now,
            actor: AuditActor::Service,
            category: AuditCategory::Enforcement,
            action: "restore.reconciled".to_owned(),
            subject: None,
            detail: json!({
                "restored_from": marker.restored_from,
                "restore_requested_at": marker.requested_at,
                "devices_reevaluated": devices_reevaluated,
                "actuation_state": "pre-restore actuation journal and decision outbox were treated as unknown and re-derived by a policy sweep",
                "audit_history": "replaced by the restored backup's history; entries written after the backup was taken are gone",
            }),
        })
        .await
        .context("record restore reconciliation in the audit log")?;
    clear_marker(marker_file)?;
    Ok(ReconcileOutcome::Reconciled {
        devices_reevaluated,
    })
}

/// Startup entry point with an injectable sweep (tests). Returns true when the
/// service may trust its enforcement state: no marker, or reconciliation
/// succeeded. On failure the marker is kept and the service is marked
/// degraded through [`AppState::report_task_failure`], which stays degraded
/// until the next (retrying) start.
pub async fn reconcile_at_startup_with<F, Fut>(
    state: &AppState,
    pool: &SqlitePool,
    state_dir: &Path,
    sweep: F,
) -> bool
where
    F: FnOnce(DateTime<Utc>) -> Fut,
    Fut: Future<Output = anyhow::Result<usize>>,
{
    let audit = AuditLog::new(pool.clone());
    match reconcile_pending_restore(&marker_path(state_dir), &audit, Utc::now(), sweep).await {
        Ok(ReconcileOutcome::NotNeeded) => true,
        Ok(ReconcileOutcome::Reconciled {
            devices_reevaluated,
        }) => {
            tracing::info!(
                devices_reevaluated,
                "reconciled enforcement state after a database restore"
            );
            true
        }
        Err(error) => {
            tracing::error!(
                "post-restore reconciliation failed; the restore marker is kept and the service is degraded: {error:#}"
            );
            state.report_task_failure(RECONCILE_TASK).await;
            false
        }
    }
}

/// Production startup reconciliation: the policy coordinator's sweep, the same
/// recovery path the discovery loop runs every cycle, run once up front.
pub async fn reconcile_at_startup(state: &AppState, pool: &SqlitePool, state_dir: &Path) -> bool {
    let coordinator = crate::policy::PolicyCoordinator::with_state(
        PolicyRepository::new(pool.clone()),
        Some(state.events().clone()),
        M2StateRepository::new(pool.clone()),
    );
    reconcile_at_startup_with(state, pool, state_dir, move |now| async move {
        // Policy is only active once the first-start baseline exists; before
        // that there is no enforcement state to reconcile.
        if !coordinator.enabled().await? {
            return Ok::<usize, anyhow::Error>(0);
        }
        Ok::<usize, anyhow::Error>(coordinator.sweep(now).await?.len())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_store::{AuditFilter, AuditPage, InstallRepository};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TOKEN: &str = "restore-test-token-0123456789abcdefghij";

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    async fn fixture() -> (tempfile::TempDir, SqlitePool, AppState) {
        let dir = tempfile::tempdir().unwrap();
        let pool = lattice_store::connect_path(dir.path().join("lattice.db"))
            .await
            .unwrap();
        let state = AppState::new(TOKEN, M2StateRepository::new(pool.clone())).unwrap();
        (dir, pool, state)
    }

    async fn audit_actions(pool: &SqlitePool) -> Vec<String> {
        AuditLog::new(pool.clone())
            .list(
                &AuditFilter::default(),
                AuditPage {
                    after_id: None,
                    limit: 100,
                },
            )
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.action)
            .collect()
    }

    fn sample_marker() -> RestoreMarker {
        RestoreMarker {
            restored_from: "backup.db".to_owned(),
            requested_at: "2026-11-15T00:00:00+00:00".to_owned(),
        }
    }

    #[test]
    fn restore_args_accept_from_in_both_spellings() {
        assert_eq!(
            parse_restore_args(args(&["--from", "b.db"])),
            Ok(PathBuf::from("b.db"))
        );
        assert_eq!(
            parse_restore_args(args(&["--from=dir/b.db"])),
            Ok(PathBuf::from("dir/b.db"))
        );
    }

    #[test]
    fn restore_args_reject_everything_else() {
        for bad in [
            args(&[]),
            args(&["--from"]),
            args(&["--from="]),
            args(&["--from", ""]),
            args(&["b.db"]),
            args(&["--from", "a.db", "--from", "b.db"]),
            args(&["--from", "a.db", "--force"]),
            args(&["--frm", "a.db"]),
        ] {
            let error = parse_restore_args(bad.clone()).unwrap_err();
            assert!(error.contains("--from"), "{bad:?}: {error}");
        }
    }

    #[test]
    fn marker_lifecycle_write_read_clear() {
        let dir = tempfile::tempdir().unwrap();
        let path = marker_path(dir.path());
        assert_eq!(read_marker(&path).unwrap(), None);
        write_marker(&path, &sample_marker()).unwrap();
        assert_eq!(read_marker(&path).unwrap(), Some(sample_marker()));
        // Rewriting replaces; clearing is idempotent.
        write_marker(&path, &sample_marker()).unwrap();
        clear_marker(&path).unwrap();
        clear_marker(&path).unwrap();
        assert_eq!(read_marker(&path).unwrap(), None);
    }

    #[test]
    fn an_unparseable_marker_still_counts_as_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = marker_path(dir.path());
        std::fs::write(&path, "not json").unwrap();
        let marker = read_marker(&path).unwrap().expect("marker is present");
        assert!(marker.restored_from.contains("unknown"));
    }

    #[tokio::test]
    async fn restore_swaps_the_database_and_leaves_the_marker() {
        let dir = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            state_dir: dir.path().to_path_buf(),
            database: dir.path().join("lattice.db"),
            backups: dir.path().join("backups"),
        };
        std::fs::create_dir_all(&paths.backups).unwrap();
        let pool = lattice_store::connect_path(&paths.database).await.unwrap();
        let log = AuditLog::new(pool.clone());
        let entry = |action: &str| NewAuditEntry {
            occurred_at: Utc::now(),
            actor: AuditActor::Service,
            category: AuditCategory::Enforcement,
            action: action.to_owned(),
            subject: None,
            detail: json!({}),
        };
        log.append(entry("before.backup")).await.unwrap();
        let backup = paths.backups.join("snapshot.db");
        DbMaintenance::new(pool.clone(), paths.database.clone())
            .backup_to(&backup)
            .await
            .unwrap();
        log.append(entry("after.backup")).await.unwrap();
        // The service is stopped before a restore: no open handles remain.
        pool.close().await;

        let report = restore_database(&paths, &backup).await.unwrap();
        assert!(report.reconcile_required);
        let marker = read_marker(&marker_path(&paths.state_dir))
            .unwrap()
            .expect("marker is written by the restore");
        assert_eq!(marker.restored_from, backup.display().to_string());

        let pool = lattice_store::connect_path(&paths.database).await.unwrap();
        assert_eq!(audit_actions(&pool).await, vec!["before.backup"]);
    }

    #[tokio::test]
    async fn a_refused_restore_keeps_the_database_and_removes_its_own_marker() {
        let dir = tempfile::tempdir().unwrap();
        let paths = PlatformPaths {
            state_dir: dir.path().to_path_buf(),
            database: dir.path().join("lattice.db"),
            backups: dir.path().join("backups"),
        };
        let pool = lattice_store::connect_path(&paths.database).await.unwrap();
        InstallRepository::new(pool.clone())
            .initialize(Utc::now())
            .await
            .unwrap();
        pool.close().await;
        let fake = dir.path().join("fake.db");
        std::fs::write(&fake, b"definitely not a sqlite database").unwrap();

        let error = restore_database(&paths, &fake).await.unwrap_err();
        assert!(format!("{error:#}").contains("not changed"), "{error:#}");
        assert!(!marker_path(&paths.state_dir).exists());
        let pool = lattice_store::connect_path(&paths.database).await.unwrap();
        assert!(InstallRepository::new(pool).load().await.unwrap().is_some());

        // A marker left by an earlier restore is never deleted by a refusal.
        write_marker(&marker_path(&paths.state_dir), &sample_marker()).unwrap();
        restore_database(&paths, &fake).await.unwrap_err();
        assert!(marker_path(&paths.state_dir).exists());
    }

    #[tokio::test]
    async fn startup_without_a_marker_does_not_sweep_or_audit() {
        let (dir, pool, state) = fixture().await;
        let swept = Arc::new(AtomicUsize::new(0));
        let seen = swept.clone();
        let trusted = reconcile_at_startup_with(&state, &pool, dir.path(), move |_| async move {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(0)
        })
        .await;
        assert!(trusted);
        assert_eq!(swept.load(Ordering::SeqCst), 0);
        assert!(audit_actions(&pool).await.is_empty());
        assert_eq!(state.service_status().await, "ready");
    }

    #[tokio::test]
    async fn startup_with_a_marker_reconciles_audits_and_clears_it() {
        let (dir, pool, state) = fixture().await;
        write_marker(&marker_path(dir.path()), &sample_marker()).unwrap();
        let swept = Arc::new(AtomicUsize::new(0));
        let seen = swept.clone();

        let trusted = reconcile_at_startup_with(&state, &pool, dir.path(), move |_| async move {
            seen.fetch_add(1, Ordering::SeqCst);
            Ok(3)
        })
        .await;

        assert!(trusted);
        assert_eq!(swept.load(Ordering::SeqCst), 1);
        assert_eq!(audit_actions(&pool).await, vec!["restore.reconciled"]);
        assert!(!marker_path(dir.path()).exists());
        assert_eq!(state.service_status().await, "ready");
    }

    #[tokio::test]
    async fn a_failed_reconciliation_keeps_the_marker_and_degrades_the_service() {
        let (dir, pool, state) = fixture().await;
        write_marker(&marker_path(dir.path()), &sample_marker()).unwrap();

        let trusted = reconcile_at_startup_with(&state, &pool, dir.path(), |_| async {
            Err(anyhow::anyhow!("router unreachable"))
        })
        .await;

        assert!(!trusted);
        assert!(marker_path(dir.path()).exists());
        assert!(audit_actions(&pool).await.is_empty());
        assert_eq!(state.service_status().await, "degraded");
    }

    #[tokio::test]
    async fn production_reconciliation_runs_the_policy_sweep_and_clears_the_marker() {
        let (dir, pool, state) = fixture().await;
        InstallRepository::new(pool.clone())
            .initialize(Utc::now())
            .await
            .unwrap();
        PolicyRepository::new(pool.clone())
            .mark_successful_service_start(Utc::now())
            .await
            .unwrap();
        write_marker(&marker_path(dir.path()), &sample_marker()).unwrap();

        assert!(reconcile_at_startup(&state, &pool, dir.path()).await);

        assert!(!marker_path(dir.path()).exists());
        assert_eq!(audit_actions(&pool).await, vec!["restore.reconciled"]);
        assert_eq!(state.service_status().await, "ready");
    }
}
