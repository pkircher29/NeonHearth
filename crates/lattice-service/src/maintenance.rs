//! Background retention and compaction.
//!
//! The store exposes one bounded maintenance entry point. `main.rs` starts [`spawn`] with
//! `MaintenancePolicy::default()`, so the running service calls it: first pass after about two
//! minutes, then every 15 minutes (both jittered). [`spawn`] runs a [`MaintenanceRunner`] on
//! that timer, never overlaps itself, logs a per-step summary, backs off on error and re-runs
//! promptly while a pass reports that it hit its row bound.
//!
//! The runner is a small local trait so the schedule can be tested without a database.
//! [`StoreMaintenance`] delegates to `DbMaintenance::run_maintenance(policy, now, batch_limit)`,
//! purges dead phone sessions and records the policy clock heartbeat in the same pass.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_store::{
    ClockStatus, DbMaintenance, MaintenancePolicy, PolicyRepository, RemoteAccessRepository,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle};

/// What one maintenance step did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub step: &'static str,
    /// Rows removed or compacted by this step.
    pub rows: u64,
}

/// The result of one full pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaintenanceRun {
    pub steps: Vec<StepReport>,
    /// Some step hit its row bound, so another pass should follow promptly.
    pub may_have_more: bool,
}

#[async_trait]
pub trait MaintenanceRunner: Send + Sync + 'static {
    /// Runs every step once. An `Err` means at least one step failed; `spawn` backs off.
    async fn run_once(&self, now: DateTime<Utc>) -> Result<MaintenanceRun, String>;
}

#[derive(Clone, Debug)]
pub struct MaintenanceConfig {
    pub initial_delay: Duration,
    pub interval: Duration,
    pub max_backoff: Duration,
    /// Wait before the next pass when the previous one reported `may_have_more`.
    pub drain_delay: Duration,
    /// Plus or minus this percentage of each wait, so installs do not align.
    pub jitter_percent: u8,
}
impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(120),
            interval: Duration::from_secs(15 * 60),
            max_backoff: Duration::from_secs(60 * 60),
            drain_delay: Duration::from_secs(2),
            jitter_percent: 10,
        }
    }
}

fn jittered(base: Duration, percent: u8) -> Duration {
    let span = base.as_millis() as u64 * u64::from(percent.min(50)) / 100;
    if span == 0 {
        return base;
    }
    let noise = u64::from(Utc::now().timestamp_subsec_nanos()) % (2 * span + 1);
    base - Duration::from_millis(span) + Duration::from_millis(noise)
}

/// Starts the maintenance loop. Runs are strictly sequential: the next wait starts only after
/// the previous run finished, so a slow run can never overlap the next one.
pub fn spawn(
    runner: Arc<dyn MaintenanceRunner>,
    config: MaintenanceConfig,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut wait = jittered(config.initial_delay, config.jitter_percent);
        let mut failures = 0u32;
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
                () = tokio::time::sleep(wait) => {}
            }
            if *shutdown.borrow() {
                return;
            }
            let started = std::time::Instant::now();
            match runner.run_once(Utc::now()).await {
                Ok(run) => {
                    failures = 0;
                    let summary: Vec<String> = run
                        .steps
                        .iter()
                        .map(|s| format!("{}={}", s.step, s.rows))
                        .collect();
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        steps = %summary.join(","),
                        more = run.may_have_more,
                        "maintenance completed"
                    );
                    wait = if run.may_have_more {
                        config.drain_delay
                    } else {
                        jittered(config.interval, config.jitter_percent)
                    };
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    let backoff = config
                        .interval
                        .saturating_mul(1u32 << failures.min(6))
                        .min(config.max_backoff);
                    tracing::warn!(%error, failures, "maintenance failed; backing off");
                    wait = jittered(backoff, config.jitter_percent);
                }
            }
        }
    })
}

/// Rows each retention step may remove per pass; a step that hits it triggers a prompt re-run.
pub const BATCH_LIMIT: usize = 5_000;

/// Maintenance over the store's single entry point, plus the two periodic duties that live
/// outside it: the dead phone-session purge and the policy clock heartbeat.
pub struct StoreMaintenance {
    pub db: DbMaintenance,
    pub policy: MaintenancePolicy,
    pub batch_limit: usize,
    pub remote_access: RemoteAccessRepository,
    pub policy_repo: PolicyRepository,
}

#[async_trait]
impl MaintenanceRunner for StoreMaintenance {
    async fn run_once(&self, now: DateTime<Utc>) -> Result<MaintenanceRun, String> {
        let mut steps = Vec::new();
        let mut errors = Vec::new();

        // Heartbeat first: it only advances while the clock is trusted, and a suspect result
        // is a state to surface, not a failure of this pass.
        match self.policy_repo.record_clock_heartbeat(now).await {
            Ok(ClockStatus::Trusted) => {}
            Ok(ClockStatus::Suspect(reason)) => {
                tracing::warn!(%reason, "policy clock is suspect; deadline enforcement is suppressed");
            }
            Err(error) => errors.push(format!("clock_heartbeat: {error:#}")),
        }

        let report = self
            .db
            .run_maintenance(&self.policy, now, self.batch_limit)
            .await;
        for failed in report.failures() {
            let error = failed.error.as_deref().unwrap_or_default();
            tracing::warn!(step = failed.step, %error, "maintenance step failed");
            errors.push(format!("{}: {error}", failed.step));
        }
        let may_have_more = report.may_have_more(self.batch_limit);
        steps.extend(
            report
                .steps
                .iter()
                .filter(|s| s.error.is_none())
                .map(|s| StepReport {
                    step: s.step,
                    rows: s.rows,
                }),
        );

        match self
            .remote_access
            .purge_dead_phone_sessions(now, self.policy.phone_session_grace)
            .await
        {
            Ok(rows) => steps.push(StepReport {
                step: "phone_sessions_purge",
                rows,
            }),
            Err(error) => {
                tracing::warn!(%error, "phone session purge failed");
                errors.push(format!("phone_sessions_purge: {error}"));
            }
        }

        if errors.is_empty() {
            Ok(MaintenanceRun {
                steps,
                may_have_more,
            })
        } else {
            Err(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Fake {
        running: AtomicU32,
        max_running: AtomicU32,
        runs: AtomicU32,
        fail_first: u32,
        more_first: bool,
    }
    #[async_trait]
    impl MaintenanceRunner for Fake {
        async fn run_once(&self, _: DateTime<Utc>) -> Result<MaintenanceRun, String> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            // Longer than the interval: an overlapping scheduler would start a second run.
            tokio::time::sleep(Duration::from_secs(90)).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
            let n = self.runs.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                Err("boom".into())
            } else {
                Ok(MaintenanceRun {
                    steps: vec![StepReport { step: "x", rows: 1 }],
                    may_have_more: self.more_first && n == self.fail_first,
                })
            }
        }
    }

    fn fake(fail_first: u32, more_first: bool) -> Arc<Fake> {
        Arc::new(Fake {
            running: AtomicU32::new(0),
            max_running: AtomicU32::new(0),
            runs: AtomicU32::new(0),
            fail_first,
            more_first,
        })
    }

    #[tokio::test(start_paused = true)]
    async fn runs_repeatedly_without_overlap_and_backs_off_on_error() {
        let fake = fake(1, false);
        let (tx, rx) = watch::channel(false);
        let handle = spawn(
            fake.clone(),
            MaintenanceConfig {
                initial_delay: Duration::from_secs(10),
                interval: Duration::from_secs(60),
                max_backoff: Duration::from_secs(600),
                drain_delay: Duration::from_secs(1),
                jitter_percent: 0,
            },
            rx,
        );
        // 10 s wait + 90 s run (fails) + 120 s backoff + 90 s run + 60 s + 90 s run ...
        tokio::time::sleep(Duration::from_secs(10 + 90 + 120 + 90 + 60 + 90 + 5)).await;
        assert_eq!(fake.runs.load(Ordering::SeqCst), 3);
        assert_eq!(fake.max_running.load(Ordering::SeqCst), 1, "never overlaps");
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_that_may_have_more_is_followed_promptly() {
        let fake = fake(0, true);
        let (tx, rx) = watch::channel(false);
        let handle = spawn(
            fake.clone(),
            MaintenanceConfig {
                initial_delay: Duration::from_secs(10),
                interval: Duration::from_secs(3600),
                max_backoff: Duration::from_secs(7200),
                drain_delay: Duration::from_secs(1),
                jitter_percent: 0,
            },
            rx,
        );
        // 10 s wait + 90 s run (reports more) + 1 s drain + 90 s run: far inside one interval.
        tokio::time::sleep(Duration::from_secs(10 + 90 + 1 + 90 + 5)).await;
        assert_eq!(fake.runs.load(Ordering::SeqCst), 2);
        tx.send(true).unwrap();
        handle.await.unwrap();
    }

    fn at(second: i64) -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, second, 0)
            .single()
            .unwrap()
    }

    #[tokio::test]
    async fn store_maintenance_records_the_clock_heartbeat_and_runs_clean() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        let pool = lattice_store::connect_path(&path).await.unwrap();
        let runner = StoreMaintenance {
            db: DbMaintenance::new(pool.clone(), &path),
            policy: MaintenancePolicy::default(),
            batch_limit: 100,
            remote_access: RemoteAccessRepository::new(pool.clone()),
            policy_repo: PolicyRepository::new(pool.clone()),
        };
        let first = 1_800_000_000;
        let run = runner.run_once(at(first)).await.unwrap();
        assert!(!run.may_have_more);
        assert!(run.steps.iter().any(|s| s.step == "phone_sessions_purge"));
        // The heartbeat is durable: a clock three hours behind it is now suspect.
        let repo = PolicyRepository::new(pool);
        assert!(
            repo.clock_status(at(first + 60))
                .await
                .unwrap()
                .is_trusted()
        );
        assert!(
            !repo
                .clock_status(at(first - 3 * 3600))
                .await
                .unwrap()
                .is_trusted()
        );
    }

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..50 {
            let d = jittered(Duration::from_secs(100), 10);
            assert!(d >= Duration::from_secs(90) && d <= Duration::from_secs(110));
        }
        assert_eq!(jittered(Duration::from_secs(5), 0), Duration::from_secs(5));
    }
}
