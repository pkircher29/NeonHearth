//! Background retention and compaction.
//!
//! The store exposes retention primitives (flow compaction, audit-log pruning) but nothing
//! called them, so the database only ever grew. [`spawn`] runs a [`MaintenanceRunner`] on a
//! jittered timer, never overlaps itself, logs a per-step summary and backs off on error.
//!
//! The runner is a small local trait so the schedule can be tested without a database and so
//! the single store entry point (`run_maintenance(policy, now, batch_limit)`, once it exists)
//! can replace [`StoreMaintenance`] in one place.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use lattice_store::{CompactionPolicy, DbMaintenance, FlowRepository, RetentionJob};
use std::{sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle};

/// What one maintenance step did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepReport {
    pub step: &'static str,
    /// Rows removed or compacted by this step.
    pub rows: u64,
}

#[async_trait]
pub trait MaintenanceRunner: Send + Sync + 'static {
    /// Runs every step once. An `Err` means at least one step failed; `spawn` backs off.
    async fn run_once(&self, now: DateTime<Utc>) -> Result<Vec<StepReport>, String>;
}

#[derive(Clone, Debug)]
pub struct MaintenanceConfig {
    pub initial_delay: Duration,
    pub interval: Duration,
    pub max_backoff: Duration,
    /// Plus or minus this percentage of each wait, so installs do not align.
    pub jitter_percent: u8,
}
impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(120),
            interval: Duration::from_secs(15 * 60),
            max_backoff: Duration::from_secs(60 * 60),
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
                Ok(steps) => {
                    failures = 0;
                    let summary: Vec<String> = steps
                        .iter()
                        .map(|s| format!("{}={}", s.step, s.rows))
                        .collect();
                    tracing::info!(
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        steps = %summary.join(","),
                        "maintenance completed"
                    );
                    wait = jittered(config.interval, config.jitter_percent);
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

/// Maintenance over the store primitives that exist today. Switch to the store's single
/// maintenance entry point once it lands.
pub struct StoreMaintenance {
    pub flow: FlowRepository,
    pub compaction: CompactionPolicy,
    pub db: DbMaintenance,
    pub audit_retention: RetentionJob,
}

#[async_trait]
impl MaintenanceRunner for StoreMaintenance {
    async fn run_once(&self, now: DateTime<Utc>) -> Result<Vec<StepReport>, String> {
        let mut steps = Vec::new();
        let mut errors = Vec::new();
        match self.flow.compact(now, &self.compaction).await {
            Ok(rows) => steps.push(StepReport {
                step: "flow_compact",
                rows,
            }),
            Err(error) => errors.push(format!("flow_compact: {error}")),
        }
        match self.db.retention(self.audit_retention, now).await {
            Ok(report) => steps.push(StepReport {
                step: "audit_retention",
                rows: report.pruned_rows,
            }),
            Err(error) => errors.push(format!("audit_retention: {error}")),
        }
        if errors.is_empty() {
            Ok(steps)
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
    }
    #[async_trait]
    impl MaintenanceRunner for Fake {
        async fn run_once(&self, _: DateTime<Utc>) -> Result<Vec<StepReport>, String> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(now, Ordering::SeqCst);
            // Longer than the interval: an overlapping scheduler would start a second run.
            tokio::time::sleep(Duration::from_secs(90)).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
            let n = self.runs.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                Err("boom".into())
            } else {
                Ok(vec![StepReport { step: "x", rows: 1 }])
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn runs_repeatedly_without_overlap_and_backs_off_on_error() {
        let fake = Arc::new(Fake {
            running: AtomicU32::new(0),
            max_running: AtomicU32::new(0),
            runs: AtomicU32::new(0),
            fail_first: 1,
        });
        let (tx, rx) = watch::channel(false);
        let handle = spawn(
            fake.clone(),
            MaintenanceConfig {
                initial_delay: Duration::from_secs(10),
                interval: Duration::from_secs(60),
                max_backoff: Duration::from_secs(600),
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

    #[test]
    fn jitter_stays_within_bounds() {
        for _ in 0..50 {
            let d = jittered(Duration::from_secs(100), 10);
            assert!(d >= Duration::from_secs(90) && d <= Duration::from_secs(110));
        }
        assert_eq!(jittered(Duration::from_secs(5), 0), Duration::from_secs(5));
    }
}
