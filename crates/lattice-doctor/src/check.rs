//! Typed diagnostic checks arranged as a dependency DAG.
//!
//! Each [`CheckKind`] declares its parents via [`CheckKind::dependencies`].
//! [`CheckKind::EXECUTION_ORDER`] is a fixed topological order over that DAG:
//! a failed or skipped parent short-circuits every descendant into
//! [`CheckStatus::Skipped`] so the Doctor never diagnoses DNS while the
//! adapter is down.

use crate::DoctorError;
use crate::probe::{DnsFailureReason, LeaseState, MAX_PROBE_TIMEOUT_MS, RouteEntry};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The nodes of the diagnostic graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    CollectorHealth,
    AdapterLink,
    AddressDhcp,
    DuplicateIp,
    WifiQuality,
    Gateway,
    RouterHealth,
    LossLatency,
    Mtu,
    Dns,
    RouteVpn,
    InternetReachability,
}

impl CheckKind {
    /// A fixed topological order over [`CheckKind::dependencies`].
    pub const EXECUTION_ORDER: [CheckKind; 12] = [
        CheckKind::CollectorHealth,
        CheckKind::AdapterLink,
        CheckKind::AddressDhcp,
        CheckKind::DuplicateIp,
        CheckKind::WifiQuality,
        CheckKind::Gateway,
        CheckKind::RouterHealth,
        CheckKind::LossLatency,
        CheckKind::Mtu,
        CheckKind::Dns,
        CheckKind::RouteVpn,
        CheckKind::InternetReachability,
    ];

    /// Direct parents whose failure makes this check's conclusion meaningless.
    pub fn dependencies(self) -> &'static [CheckKind] {
        match self {
            CheckKind::CollectorHealth => &[],
            CheckKind::AdapterLink => &[CheckKind::CollectorHealth],
            CheckKind::AddressDhcp | CheckKind::WifiQuality => &[CheckKind::AdapterLink],
            CheckKind::DuplicateIp | CheckKind::Gateway => &[CheckKind::AddressDhcp],
            CheckKind::RouterHealth | CheckKind::LossLatency | CheckKind::Mtu | CheckKind::Dns => {
                &[CheckKind::Gateway]
            }
            CheckKind::RouteVpn => &[CheckKind::Dns],
            CheckKind::InternetReachability => &[CheckKind::RouteVpn],
        }
    }
}

/// Confidence in a conclusion, expressed in basis points (0..=10000).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct Confidence {
    basis_points: u16,
}

impl Confidence {
    pub const LOW: Self = Self {
        basis_points: 4_000,
    };
    pub const MEDIUM: Self = Self {
        basis_points: 7_000,
    };
    pub const HIGH: Self = Self {
        basis_points: 9_500,
    };

    pub fn try_new(basis_points: u16) -> Result<Self, DoctorError> {
        if basis_points > 10_000 {
            Err(DoctorError::InvalidConfidence)
        } else {
            Ok(Self { basis_points })
        }
    }

    pub fn basis_points(self) -> u16 {
        self.basis_points
    }
}

/// What a measurement quantifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    CollectorPrivileged,
    CaptureHealthy,
    WorkerRunning,
    LinkUp,
    LinkSpeedMbps,
    AddressPresent,
    LeaseValid,
    ConflictingMacCount,
    RssiDbm,
    RetryPercent,
    RttMs,
    LossPercent,
    DnsLatencyMs,
    ResolverFailureCount,
    DefaultRouteCount,
    RouterResponsive,
    PassingMtuBytes,
    FailingMtuBytes,
    ReachabilitySuccess,
}

/// Unit for a measurement value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Milliseconds,
    Percent,
    Dbm,
    Bytes,
    MegabitsPerSecond,
    Count,
    /// 0.0 = false, 1.0 = true.
    Boolean,
}

/// One measured value with its unit and observation time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Measurement {
    pub metric: Metric,
    pub value: f64,
    pub unit: Unit,
    pub observed_at: DateTime<Utc>,
}

/// Why a check was not run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum SkipReason {
    DependencyFailed { dependency: CheckKind },
    DependencySkipped { dependency: CheckKind },
    BudgetExhausted,
}

/// Outcome state of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum CheckStatus {
    Passed,
    Failed,
    Skipped { because: SkipReason },
}

/// One resolver's contribution to the DNS check.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ResolverEvidence {
    pub resolver: String,
    /// True for the independent (non-configured) control resolver.
    pub independent: bool,
    pub outcome: ResolverOutcome,
}

/// What one resolver did with the probe query.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum ResolverOutcome {
    Answered { latency_ms: f64 },
    Failed { reason: DnsFailureReason },
    Unavailable { error: String },
}

/// Structured, check-specific findings that diagnoses are built from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "detail")]
pub enum CheckDetail {
    /// The probe itself could not run; the conclusion is about the probe.
    ProbeFailure {
        error: String,
    },
    Collector {
        privileged: bool,
        capture_ok: bool,
        worker_running: bool,
    },
    Link {
        up: bool,
    },
    Address {
        address: Option<String>,
        lease: LeaseState,
    },
    DuplicateIp {
        address: String,
        macs: Vec<String>,
    },
    Wifi {
        wireless: bool,
        rssi_dbm: Option<i16>,
        retry_percent: Option<f64>,
    },
    GatewayPing {
        sent: u32,
        received: u32,
    },
    Router {
        responsive: bool,
    },
    LossLatency {
        loss_percent: f64,
        median_rtt_ms: Option<f64>,
    },
    Mtu {
        largest_passing_bytes: Option<u16>,
        smallest_failing_bytes: Option<u16>,
    },
    Dns {
        resolvers: Vec<ResolverEvidence>,
    },
    Route {
        default_routes: Vec<RouteEntry>,
        vpn_conflict: bool,
    },
    Internet {
        reachable: bool,
        lan_ok: bool,
    },
}

/// The conclusion of one check with its typed evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct CheckResult {
    pub kind: CheckKind,
    pub status: CheckStatus,
    pub evidence: Vec<Measurement>,
    pub confidence: Confidence,
    pub detail: Option<CheckDetail>,
}

/// Bounds on how much probing one diagnostic run may perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DiagnosticBudget {
    max_probes: u32,
    per_probe_timeout_ms: u32,
}

impl DiagnosticBudget {
    pub fn new(max_probes: u32, per_probe_timeout_ms: u32) -> Result<Self, DoctorError> {
        if max_probes == 0 {
            return Err(DoctorError::InvalidBudget("max_probes must be at least 1"));
        }
        if per_probe_timeout_ms == 0 || per_probe_timeout_ms > MAX_PROBE_TIMEOUT_MS {
            return Err(DoctorError::InvalidBudget(
                "per_probe_timeout_ms must be in 1..=10000",
            ));
        }
        Ok(Self {
            max_probes,
            per_probe_timeout_ms,
        })
    }

    pub fn max_probes(self) -> u32 {
        self.max_probes
    }

    pub fn per_probe_timeout_ms(self) -> u32 {
        self.per_probe_timeout_ms
    }
}

/// The full outcome of one diagnostic run, including partial-result labeling.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DiagnosticReport {
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub budget: DiagnosticBudget,
    pub probes_used: u32,
    /// True when at least one check was skipped because the probe budget ran
    /// out; the report then carries partial results.
    pub budget_exhausted: bool,
    pub checks: Vec<CheckResult>,
}

impl DiagnosticReport {
    pub fn check(&self, kind: CheckKind) -> Option<&CheckResult> {
        self.checks.iter().find(|check| check.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_order_is_topological_over_dependencies() {
        for (index, kind) in CheckKind::EXECUTION_ORDER.iter().enumerate() {
            for dependency in kind.dependencies() {
                let dependency_index = CheckKind::EXECUTION_ORDER
                    .iter()
                    .position(|k| k == dependency)
                    .expect("dependency present in execution order");
                assert!(
                    dependency_index < index,
                    "{dependency:?} must precede {kind:?}"
                );
            }
        }
    }

    #[test]
    fn every_check_appears_exactly_once_in_execution_order() {
        for kind in CheckKind::EXECUTION_ORDER {
            assert_eq!(
                CheckKind::EXECUTION_ORDER
                    .iter()
                    .filter(|k| **k == kind)
                    .count(),
                1
            );
        }
    }

    #[test]
    fn confidence_rejects_more_than_ten_thousand_basis_points() {
        assert_eq!(
            Confidence::try_new(10_001),
            Err(DoctorError::InvalidConfidence)
        );
        assert_eq!(
            Confidence::try_new(10_000).map(Confidence::basis_points),
            Ok(10_000)
        );
        assert!(Confidence::LOW < Confidence::MEDIUM);
        assert!(Confidence::MEDIUM < Confidence::HIGH);
    }

    #[test]
    fn budget_rejects_zero_probes_and_bad_timeouts() {
        assert_eq!(
            DiagnosticBudget::new(0, 100),
            Err(DoctorError::InvalidBudget("max_probes must be at least 1"))
        );
        assert_eq!(
            DiagnosticBudget::new(10, 0),
            Err(DoctorError::InvalidBudget(
                "per_probe_timeout_ms must be in 1..=10000"
            ))
        );
        assert_eq!(
            DiagnosticBudget::new(10, MAX_PROBE_TIMEOUT_MS + 1),
            Err(DoctorError::InvalidBudget(
                "per_probe_timeout_ms must be in 1..=10000"
            ))
        );
        let budget = DiagnosticBudget::new(10, 100).expect("valid budget");
        assert_eq!(budget.max_probes(), 10);
        assert_eq!(budget.per_probe_timeout_ms(), 100);
    }
}
