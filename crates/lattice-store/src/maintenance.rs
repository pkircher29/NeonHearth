//! One bounded, fault-isolated maintenance entry point for the whole store.
//!
//! [`DbMaintenance::run_maintenance`] is meant to be called from a periodic
//! service task. It never returns an error: every step runs independently, is
//! bounded by `batch_limit` rows, and reports its own success or failure so
//! one broken step cannot starve the others.
//!
//! All age comparisons use `unixepoch(column)` against an integer cutoff, so
//! they are correct for every timestamp spelling the store has ever written
//! (`...Z`, `...+00:00`, fractional seconds).

use crate::{CompactionPolicy, DbMaintenance, FlowRepository, RetentionJob};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::SqlitePool;
use utoipa::ToSchema;

/// Retention windows. Every field has a documented default; see [`Default`].
#[derive(Clone, Debug)]
pub struct MaintenancePolicy {
    /// Flow rollup compaction. Default: seconds 24 h, minutes 90 d, hours 2 y.
    pub flow: CompactionPolicy,
    /// Audit log: prune entries older than this (oldest-side only). Default 365 d.
    pub audit_max_age: Option<Duration>,
    /// Audit log: keep at most this many newest entries. Default 1_000_000.
    pub audit_max_rows: Option<u64>,
    /// Non-identity evidence older than this is pruned, but the newest row per
    /// (device, family, source, key) is always kept, and `link_layer` and
    /// owner-confirmed rows are never pruned (they back identity lookup).
    /// Default 90 d.
    pub evidence_retention: Duration,
    /// Presence transitions older than this are pruned except each device's
    /// latest transition and latest enforcement control transition, and any
    /// row still referenced by `correction_of`. Default 365 d.
    pub presence_transition_retention: Duration,
    /// Idempotent-replay window for `discovery_commits`. A commit input older
    /// than this is no longer recognised as a duplicate (a replay is then
    /// rejected by the monotonic checkpoint sequence instead). Default 30 d.
    pub discovery_commit_retention: Duration,
    /// Camera evidence older than this, or expired longer ago than this. Default 90 d.
    pub camera_evidence_retention: Duration,
    /// Advisory fetch log rows older than this (newest per source is kept). Default 30 d.
    pub advisory_fetch_retention: Duration,
    /// Phone sessions expired/revoked longer ago than this are deleted. Default 30 d.
    pub phone_session_grace: Duration,
    /// Revoked integration tokens older than this are deleted. Default 30 d.
    pub revoked_token_retention: Duration,
    /// Editor drafts that belong to a home other than the current plan's are
    /// deleted after this long. Default 30 d.
    pub stale_draft_retention: Duration,
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        Self {
            flow: CompactionPolicy {
                hours: Some(Duration::days(730)),
                ..CompactionPolicy::default()
            },
            audit_max_age: Some(Duration::days(365)),
            audit_max_rows: Some(1_000_000),
            evidence_retention: Duration::days(90),
            presence_transition_retention: Duration::days(365),
            discovery_commit_retention: Duration::days(30),
            camera_evidence_retention: Duration::days(90),
            advisory_fetch_retention: Duration::days(30),
            phone_session_grace: Duration::days(30),
            revoked_token_retention: Duration::days(30),
            stale_draft_retention: Duration::days(30),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct StepOutcome {
    pub step: &'static str,
    /// Rows removed (or compacted away) by this step.
    pub rows: u64,
    /// Set when the step failed; other steps still ran.
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, ToSchema)]
pub struct MaintenanceReport {
    pub steps: Vec<StepOutcome>,
}

impl MaintenanceReport {
    pub fn total_rows(&self) -> u64 {
        self.steps.iter().map(|s| s.rows).sum()
    }
    pub fn failures(&self) -> impl Iterator<Item = &StepOutcome> {
        self.steps.iter().filter(|s| s.error.is_some())
    }
    pub fn is_clean(&self) -> bool {
        self.failures().next().is_none()
    }
    /// True when some step hit its row bound, so another run is worthwhile.
    pub fn may_have_more(&self, batch_limit: usize) -> bool {
        self.steps
            .iter()
            .any(|s| s.error.is_none() && s.rows >= batch_limit as u64)
    }
}

fn epoch(now: DateTime<Utc>, age: Duration) -> Option<i64> {
    now.checked_sub_signed(age).map(|value| value.timestamp())
}

async fn delete_batch(
    pool: &SqlitePool,
    sql: &str,
    cutoff: i64,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    // One short IMMEDIATE transaction per batch.
    let mut tx = crate::begin_write(pool).await?;
    let rows = sqlx::query(sql)
        .bind(cutoff)
        .bind(limit)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(rows)
}

const EVIDENCE_SQL: &str = "DELETE FROM evidence WHERE evidence_id IN (
  SELECT e.evidence_id FROM evidence e
  WHERE unixepoch(e.observed_at) < ?1 AND e.family NOT IN ('link_layer','owner') AND e.owner_confirmed=0
    AND EXISTS (SELECT 1 FROM evidence n WHERE n.device_id IS e.device_id AND n.family=e.family
                AND n.source=e.source AND n.fact_key=e.fact_key AND n.observed_at>e.observed_at)
  LIMIT ?2)";

const TRANSITIONS_SQL: &str = "DELETE FROM presence_transitions WHERE transition_id IN (
  SELECT p.transition_id FROM presence_transitions p
  WHERE unixepoch(p.occurred_at) < ?1
    AND NOT EXISTS (SELECT 1 FROM presence_transitions c WHERE c.correction_of=p.transition_id)
    AND p.transition_id <> COALESCE((SELECT q.transition_id FROM presence_transitions q
        WHERE q.device_id=p.device_id AND q.trigger_kind NOT IN ('enforcement_blocked','enforcement_unblocked')
        ORDER BY q.occurred_at DESC, q.transition_id DESC LIMIT 1), 0)
    AND p.transition_id <> COALESCE((SELECT q.transition_id FROM presence_transitions q
        WHERE q.device_id=p.device_id AND q.trigger_kind IN ('enforcement_blocked','enforcement_unblocked')
        ORDER BY q.occurred_at DESC, q.transition_id ASC LIMIT 1), 0)
  ORDER BY p.transition_id LIMIT ?2)";

const DISCOVERY_SQL: &str = "DELETE FROM discovery_commits WHERE input_hash IN (
  SELECT input_hash FROM discovery_commits WHERE unixepoch(committed_at) < ?1 LIMIT ?2)";

const CAMERA_EVIDENCE_SQL: &str = "DELETE FROM camera_evidence WHERE rowid IN (
  SELECT rowid FROM camera_evidence
  WHERE unixepoch(observed_at) < ?1 OR (expires_at IS NOT NULL AND unixepoch(expires_at) < ?1)
  LIMIT ?2)";

const ADVISORY_FETCH_SQL: &str = "DELETE FROM advisory_source_fetches WHERE fetch_id IN (
  SELECT f.fetch_id FROM advisory_source_fetches f
  WHERE unixepoch(f.retrieved_at) < ?1
    AND EXISTS (SELECT 1 FROM advisory_source_fetches n WHERE n.source=f.source AND n.retrieved_at>f.retrieved_at)
  LIMIT ?2)";

const PHONE_SESSION_SQL: &str = "DELETE FROM phone_sessions WHERE id IN (
  SELECT id FROM phone_sessions
  WHERE unixepoch(expires_at) < ?1
     OR (revoked=1 AND unixepoch(COALESCE(last_used_at, created_at)) < ?1)
  LIMIT ?2)";

// Placements and estimates for devices that no longer exist can never be
// shown or edited; the tables have no foreign key to `devices`.
const PLACEMENT_ORPHAN_SQL: &str = "DELETE FROM owner_placements WHERE device_id IN (
  SELECT device_id FROM owner_placements
  WHERE ?1 IS NOT NULL AND device_id NOT IN (SELECT device_id FROM devices) LIMIT ?2)";

const ESTIMATE_ORPHAN_SQL: &str = "DELETE FROM location_estimates WHERE device_id IN (
  SELECT device_id FROM location_estimates
  WHERE ?1 IS NOT NULL AND device_id NOT IN (SELECT device_id FROM devices) LIMIT ?2)";

const STALE_DRAFT_SQL: &str = "DELETE FROM home_drafts WHERE home_id IN (
  SELECT d.home_id FROM home_drafts d
  WHERE unixepoch(d.updated_at) < ?1
    AND EXISTS (SELECT 1 FROM home_plans)
    AND d.home_id NOT IN (SELECT home_id FROM home_plans) LIMIT ?2)";

const TOKEN_SQL: &str = "DELETE FROM integration_tokens WHERE id IN (
  SELECT id FROM integration_tokens WHERE revoked=1 AND unixepoch(created_at) < ?1 LIMIT ?2)";

impl DbMaintenance {
    /// Runs every retention step once.
    ///
    /// `batch_limit` bounds the rows each step may remove in this call (flow
    /// compaction is bounded by child rows compacted). Steps are independent:
    /// a failure is recorded in the report and the next step still runs. Call
    /// again (see [`MaintenanceReport::may_have_more`]) to drain a backlog.
    pub async fn run_maintenance(
        &self,
        policy: &MaintenancePolicy,
        now: DateTime<Utc>,
        batch_limit: usize,
    ) -> MaintenanceReport {
        let limit = i64::try_from(batch_limit.max(1)).unwrap_or(i64::MAX);
        let pool = self.pool();
        let mut steps = Vec::new();
        let mut push = |step: &'static str, result: Result<u64, String>| {
            steps.push(match result {
                Ok(rows) => StepOutcome {
                    step,
                    rows,
                    error: None,
                },
                Err(error) => StepOutcome {
                    step,
                    rows: 0,
                    error: Some(error),
                },
            });
        };

        let flow = match FlowRepository::new(pool.clone(), 1) {
            Ok(flow) => {
                flow.compact_limited(now, &policy.flow, batch_limit.max(1) as u64)
                    .await
            }
            Err(error) => Err(error),
        };
        push("flow_compaction", flow.map_err(|e| e.to_string()));
        push("audit_retention", self.audit_step(policy, now).await);

        let table_steps: [(&'static str, &str, Duration); 10] = [
            ("evidence", EVIDENCE_SQL, policy.evidence_retention),
            (
                "presence_transitions",
                TRANSITIONS_SQL,
                policy.presence_transition_retention,
            ),
            (
                "discovery_commits",
                DISCOVERY_SQL,
                policy.discovery_commit_retention,
            ),
            (
                "camera_evidence",
                CAMERA_EVIDENCE_SQL,
                policy.camera_evidence_retention,
            ),
            (
                "advisory_source_fetches",
                ADVISORY_FETCH_SQL,
                policy.advisory_fetch_retention,
            ),
            (
                "phone_sessions",
                PHONE_SESSION_SQL,
                policy.phone_session_grace,
            ),
            (
                "integration_tokens",
                TOKEN_SQL,
                policy.revoked_token_retention,
            ),
            (
                "owner_placement_orphans",
                PLACEMENT_ORPHAN_SQL,
                Duration::zero(),
            ),
            (
                "location_estimate_orphans",
                ESTIMATE_ORPHAN_SQL,
                Duration::zero(),
            ),
            (
                "stale_home_drafts",
                STALE_DRAFT_SQL,
                policy.stale_draft_retention,
            ),
        ];
        for (name, sql, age) in table_steps {
            let result = match epoch(now, age) {
                Some(cutoff) => delete_batch(pool, sql, cutoff, limit)
                    .await
                    .map_err(|e| e.to_string()),
                None => Ok(0),
            };
            push(name, result);
        }
        MaintenanceReport { steps }
    }

    async fn audit_step(
        &self,
        policy: &MaintenancePolicy,
        now: DateTime<Utc>,
    ) -> Result<u64, String> {
        if policy.audit_max_age.is_none() && policy.audit_max_rows.is_none() {
            return Ok(0);
        }
        let job = RetentionJob {
            max_age_seconds: policy
                .audit_max_age
                .map(|d| u64::try_from(d.num_seconds()).unwrap_or(0)),
            max_rows: policy.audit_max_rows,
        };
        self.retention(job, now)
            .await
            .map(|report| report.pruned_rows)
            .map_err(|e| e.to_string())
    }
}
