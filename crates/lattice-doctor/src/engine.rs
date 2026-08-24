//! The diagnostic engine: walks the check DAG with bounded probes.

use crate::check::{
    CheckDetail, CheckKind, CheckResult, CheckStatus, Confidence, DiagnosticBudget,
    DiagnosticReport, Measurement, Metric, ResolverEvidence, ResolverOutcome, SkipReason, Unit,
};
use crate::probe::{LeaseState, Probe, ProbeError, ProbeRequest, ProbeResponse, ProbeTransport};
use crate::{Clock, DoctorError, SystemClock};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

const UNEXPECTED_RESPONSE: &str = "unexpected probe response";
const PING_PAYLOAD_BYTES: u16 = 56;
const MAX_PING_COUNT: u8 = 16;
const MAX_MTU_PROBE_SIZES: usize = 8;
const MAX_RESOLVERS: usize = 8;

/// Thresholds separating "degraded" from "healthy" measurements.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Thresholds {
    /// Loss above this percentage marks the path degraded.
    pub degraded_loss_percent: f64,
    /// Median RTT above this marks the path degraded.
    pub degraded_median_rtt_ms: f64,
    /// RSSI below this marks Wi-Fi weak.
    pub weak_rssi_dbm: i16,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            degraded_loss_percent: 2.0,
            degraded_median_rtt_ms: 100.0,
            weak_rssi_dbm: -75,
        }
    }
}

/// Static inputs for one diagnostic run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DoctorConfig {
    /// Interface the collector manages.
    pub interface: String,
    /// Default gateway address.
    pub gateway: String,
    /// Resolvers the host is configured to use.
    pub configured_resolvers: Vec<String>,
    /// A known-good resolver independent of local configuration.
    pub independent_resolver: String,
    /// Literal IP used to test internet reachability without DNS.
    pub internet_probe_address: String,
    pub internet_probe_port: u16,
    /// Name resolved during DNS checks.
    pub dns_probe_name: String,
    /// Echo requests per latency/loss sample (1..=16).
    pub ping_count: u8,
    /// Don't-fragment payload sizes probed for MTU blackholes (max 8).
    pub mtu_probe_sizes: Vec<u16>,
    pub thresholds: Thresholds,
}

impl DoctorConfig {
    fn validate(&self) -> Result<(), DoctorError> {
        if self.interface.is_empty() {
            return Err(DoctorError::InvalidConfig("interface must not be empty"));
        }
        if self.gateway.is_empty() {
            return Err(DoctorError::InvalidConfig("gateway must not be empty"));
        }
        if self.configured_resolvers.is_empty() {
            return Err(DoctorError::InvalidConfig(
                "at least one configured resolver is required",
            ));
        }
        if self.configured_resolvers.len() > MAX_RESOLVERS {
            return Err(DoctorError::InvalidConfig(
                "too many configured resolvers (max 8)",
            ));
        }
        if self.independent_resolver.is_empty() {
            return Err(DoctorError::InvalidConfig(
                "independent_resolver must not be empty",
            ));
        }
        if self.internet_probe_address.is_empty() {
            return Err(DoctorError::InvalidConfig(
                "internet_probe_address must not be empty",
            ));
        }
        if self.dns_probe_name.is_empty() {
            return Err(DoctorError::InvalidConfig(
                "dns_probe_name must not be empty",
            ));
        }
        if self.ping_count == 0 || self.ping_count > MAX_PING_COUNT {
            return Err(DoctorError::InvalidConfig("ping_count must be in 1..=16"));
        }
        if self.mtu_probe_sizes.is_empty() || self.mtu_probe_sizes.len() > MAX_MTU_PROBE_SIZES {
            return Err(DoctorError::InvalidConfig(
                "mtu_probe_sizes must contain 1..=8 sizes",
            ));
        }
        let t = &self.thresholds;
        if !t.degraded_loss_percent.is_finite()
            || !(0.0..=100.0).contains(&t.degraded_loss_percent)
            || !t.degraded_median_rtt_ms.is_finite()
            || t.degraded_median_rtt_ms <= 0.0
        {
            return Err(DoctorError::InvalidConfig("thresholds are out of range"));
        }
        Ok(())
    }
}

/// Runs the diagnostic DAG through an injected [`ProbeTransport`].
#[derive(Clone, Debug)]
pub struct DiagnosticEngine {
    config: DoctorConfig,
    budget: DiagnosticBudget,
    clock: Arc<dyn Clock>,
}

impl DiagnosticEngine {
    pub fn new(config: DoctorConfig, budget: DiagnosticBudget) -> Result<Self, DoctorError> {
        Self::with_clock(config, budget, SystemClock)
    }

    pub fn with_clock(
        config: DoctorConfig,
        budget: DiagnosticBudget,
        clock: impl Clock + 'static,
    ) -> Result<Self, DoctorError> {
        config.validate()?;
        Ok(Self {
            config,
            budget,
            clock: Arc::new(clock),
        })
    }

    /// Run every check in [`CheckKind::EXECUTION_ORDER`], short-circuiting
    /// children of failed parents and stopping cleanly when the probe budget
    /// is exhausted (remaining checks are labeled, never silently dropped).
    pub async fn run<T: ProbeTransport>(&self, transport: &T) -> DiagnosticReport {
        let started_at = self.clock.now();
        let mut checks: Vec<CheckResult> = Vec::with_capacity(CheckKind::EXECUTION_ORDER.len());
        let mut probes_used = 0u32;
        let mut budget_exhausted = false;

        for kind in CheckKind::EXECUTION_ORDER {
            if let Some(because) = dependency_skip(kind, &checks) {
                checks.push(skipped(kind, because));
                continue;
            }
            let cost = self.probe_cost(kind);
            if budget_exhausted || probes_used.saturating_add(cost) > self.budget.max_probes() {
                budget_exhausted = true;
                checks.push(skipped(kind, SkipReason::BudgetExhausted));
                continue;
            }
            let result = self
                .run_check(kind, transport, &mut probes_used, &checks)
                .await;
            checks.push(result);
        }

        DiagnosticReport {
            started_at,
            finished_at: self.clock.now(),
            budget: self.budget,
            probes_used,
            budget_exhausted,
            checks,
        }
    }

    /// Worst-case probes one check may issue (used for budget admission).
    fn probe_cost(&self, kind: CheckKind) -> u32 {
        match kind {
            CheckKind::Gateway | CheckKind::LossLatency => u32::from(self.config.ping_count),
            CheckKind::Mtu => self.config.mtu_probe_sizes.len() as u32,
            CheckKind::Dns => self.config.configured_resolvers.len() as u32 + 1,
            _ => 1,
        }
    }

    async fn run_check<T: ProbeTransport>(
        &self,
        kind: CheckKind,
        transport: &T,
        used: &mut u32,
        prior: &[CheckResult],
    ) -> CheckResult {
        match kind {
            CheckKind::CollectorHealth => self.check_collector(transport, used).await,
            CheckKind::AdapterLink => self.check_adapter_link(transport, used).await,
            CheckKind::AddressDhcp => self.check_address(transport, used).await,
            CheckKind::DuplicateIp => self.check_duplicate_ip(transport, used, prior).await,
            CheckKind::WifiQuality => self.check_wifi(transport, used).await,
            CheckKind::Gateway => self.check_gateway(transport, used).await,
            CheckKind::RouterHealth => self.check_router(transport, used).await,
            CheckKind::LossLatency => self.check_loss_latency(transport, used).await,
            CheckKind::Mtu => self.check_mtu(transport, used).await,
            CheckKind::Dns => self.check_dns(transport, used).await,
            CheckKind::RouteVpn => self.check_route_vpn(transport, used).await,
            CheckKind::InternetReachability => self.check_internet(transport, used, prior).await,
        }
    }

    async fn send<T: ProbeTransport>(
        &self,
        transport: &T,
        used: &mut u32,
        request: ProbeRequest,
    ) -> Result<ProbeResponse, ProbeError> {
        *used = used.saturating_add(1);
        transport
            .probe(Probe {
                request,
                timeout_ms: self.budget.per_probe_timeout_ms(),
            })
            .await
    }

    async fn check_collector<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::CollectorHealth;
        match self.send(t, used, ProbeRequest::CollectorStatus).await {
            Ok(ProbeResponse::CollectorStatus {
                privileged,
                capture_ok,
                worker_running,
            }) => {
                let evidence = vec![
                    self.measurement(
                        Metric::CollectorPrivileged,
                        bool_value(privileged),
                        Unit::Boolean,
                    ),
                    self.measurement(
                        Metric::CaptureHealthy,
                        bool_value(capture_ok),
                        Unit::Boolean,
                    ),
                    self.measurement(
                        Metric::WorkerRunning,
                        bool_value(worker_running),
                        Unit::Boolean,
                    ),
                ];
                self.conclude(
                    kind,
                    privileged && capture_ok && worker_running,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Collector {
                        privileged,
                        capture_ok,
                        worker_running,
                    },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_adapter_link<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::AdapterLink;
        let request = ProbeRequest::LinkStatus {
            interface: self.config.interface.clone(),
        };
        match self.send(t, used, request).await {
            Ok(ProbeResponse::LinkStatus { up, speed_mbps }) => {
                let mut evidence =
                    vec![self.measurement(Metric::LinkUp, bool_value(up), Unit::Boolean)];
                if let Some(speed) = speed_mbps {
                    evidence.push(self.measurement(
                        Metric::LinkSpeedMbps,
                        f64::from(speed),
                        Unit::MegabitsPerSecond,
                    ));
                }
                self.conclude(
                    kind,
                    up,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Link { up },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_address<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::AddressDhcp;
        let request = ProbeRequest::IpConfig {
            interface: self.config.interface.clone(),
        };
        match self.send(t, used, request).await {
            Ok(ProbeResponse::IpConfig { address, lease }) => {
                let has_address = address.is_some();
                let lease_ok = matches!(lease, LeaseState::Valid | LeaseState::Static);
                let evidence = vec![
                    self.measurement(
                        Metric::AddressPresent,
                        bool_value(has_address),
                        Unit::Boolean,
                    ),
                    self.measurement(Metric::LeaseValid, bool_value(lease_ok), Unit::Boolean),
                ];
                self.conclude(
                    kind,
                    has_address && lease_ok,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Address { address, lease },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_duplicate_ip<T: ProbeTransport>(
        &self,
        t: &T,
        used: &mut u32,
        prior: &[CheckResult],
    ) -> CheckResult {
        let kind = CheckKind::DuplicateIp;
        let address = find(prior, CheckKind::AddressDhcp).and_then(|result| match &result.detail {
            Some(CheckDetail::Address {
                address: Some(address),
                ..
            }) => Some(address.clone()),
            _ => None,
        });
        let Some(address) = address else {
            return self.failed_probe(kind, "no confirmed local address available".into());
        };
        let request = ProbeRequest::ArpProbe {
            interface: self.config.interface.clone(),
            address: address.clone(),
        };
        match self.send(t, used, request).await {
            Ok(ProbeResponse::ArpProbe { responding_macs }) => {
                let count = responding_macs.len();
                let evidence =
                    vec![self.measurement(Metric::ConflictingMacCount, count as f64, Unit::Count)];
                self.conclude(
                    kind,
                    count <= 1,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::DuplicateIp {
                        address,
                        macs: responding_macs,
                    },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_wifi<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::WifiQuality;
        let request = ProbeRequest::WifiMetrics {
            interface: self.config.interface.clone(),
        };
        match self.send(t, used, request).await {
            Ok(ProbeResponse::WifiMetrics {
                wireless,
                rssi_dbm,
                retry_percent,
            }) => {
                if !wireless {
                    return self.conclude(
                        kind,
                        true,
                        Vec::new(),
                        Confidence::HIGH,
                        CheckDetail::Wifi {
                            wireless: false,
                            rssi_dbm: None,
                            retry_percent: None,
                        },
                    );
                }
                let Some(rssi) = rssi_dbm else {
                    return self
                        .failed_probe(kind, "wireless interface reported no signal metric".into());
                };
                let mut evidence =
                    vec![self.measurement(Metric::RssiDbm, f64::from(rssi), Unit::Dbm)];
                if let Some(retry) = retry_percent {
                    evidence.push(self.measurement(Metric::RetryPercent, retry, Unit::Percent));
                }
                self.conclude(
                    kind,
                    rssi >= self.config.thresholds.weak_rssi_dbm,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Wifi {
                        wireless: true,
                        rssi_dbm: Some(rssi),
                        retry_percent,
                    },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn ping_sample<T: ProbeTransport>(
        &self,
        t: &T,
        used: &mut u32,
        target: &str,
    ) -> (u32, Vec<f64>) {
        let mut sent = 0u32;
        let mut rtts = Vec::new();
        for _ in 0..self.config.ping_count {
            sent += 1;
            let request = ProbeRequest::Ping {
                target: target.into(),
                payload_bytes: PING_PAYLOAD_BYTES,
                dont_fragment: false,
            };
            if let Ok(ProbeResponse::PingReply { rtt_ms }) = self.send(t, used, request).await {
                rtts.push(rtt_ms);
            }
        }
        (sent, rtts)
    }

    async fn check_gateway<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::Gateway;
        let gateway = self.config.gateway.clone();
        let (sent, rtts) = self.ping_sample(t, used, &gateway).await;
        let received = rtts.len() as u32;
        let loss_percent = loss_percent(sent, received);
        let mut evidence = vec![self.measurement(Metric::LossPercent, loss_percent, Unit::Percent)];
        if let Some(best) = rtts.iter().copied().min_by(f64::total_cmp) {
            evidence.push(self.measurement(Metric::RttMs, best, Unit::Milliseconds));
        }
        self.conclude(
            kind,
            received >= 1,
            evidence,
            Confidence::HIGH,
            CheckDetail::GatewayPing { sent, received },
        )
    }

    async fn check_router<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::RouterHealth;
        match self.send(t, used, ProbeRequest::RouterStatus).await {
            Ok(ProbeResponse::RouterStatus { responsive, .. }) => {
                let evidence = vec![self.measurement(
                    Metric::RouterResponsive,
                    bool_value(responsive),
                    Unit::Boolean,
                )];
                self.conclude(
                    kind,
                    responsive,
                    evidence,
                    Confidence::MEDIUM,
                    CheckDetail::Router { responsive },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_loss_latency<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::LossLatency;
        let gateway = self.config.gateway.clone();
        let (sent, mut rtts) = self.ping_sample(t, used, &gateway).await;
        let received = rtts.len() as u32;
        let loss = loss_percent(sent, received);
        let median = median(&mut rtts);
        let mut evidence = vec![self.measurement(Metric::LossPercent, loss, Unit::Percent)];
        if let Some(median_rtt) = median {
            evidence.push(self.measurement(Metric::RttMs, median_rtt, Unit::Milliseconds));
        }
        let thresholds = self.config.thresholds;
        let healthy = loss <= thresholds.degraded_loss_percent
            && median.is_none_or(|m| m <= thresholds.degraded_median_rtt_ms)
            && received >= 1;
        self.conclude(
            kind,
            healthy,
            evidence,
            Confidence::MEDIUM,
            CheckDetail::LossLatency {
                loss_percent: loss,
                median_rtt_ms: median,
            },
        )
    }

    async fn check_mtu<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::Mtu;
        let mut sizes = self.config.mtu_probe_sizes.clone();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        sizes.dedup();
        let mut passing: Vec<u16> = Vec::new();
        let mut silent_failures: Vec<u16> = Vec::new();
        for size in sizes {
            let request = ProbeRequest::Ping {
                target: self.config.internet_probe_address.clone(),
                payload_bytes: size,
                dont_fragment: true,
            };
            match self.send(t, used, request).await {
                Ok(ProbeResponse::PingReply { .. }) => passing.push(size),
                Ok(ProbeResponse::PingTimeout) => silent_failures.push(size),
                // The path signaled its MTU properly: not a blackhole.
                Ok(ProbeResponse::FragmentationNeeded { .. }) => {}
                Ok(_) => return self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
                Err(error) => return self.failed_probe(kind, error.to_string()),
            }
        }
        let largest_passing_bytes = passing.iter().copied().max();
        let smallest_failing_bytes = silent_failures.iter().copied().min();
        let mut evidence = Vec::new();
        if let Some(bytes) = largest_passing_bytes {
            evidence.push(self.measurement(Metric::PassingMtuBytes, f64::from(bytes), Unit::Bytes));
        }
        if let Some(bytes) = smallest_failing_bytes {
            evidence.push(self.measurement(Metric::FailingMtuBytes, f64::from(bytes), Unit::Bytes));
        }
        self.conclude(
            kind,
            silent_failures.is_empty(),
            evidence,
            Confidence::MEDIUM,
            CheckDetail::Mtu {
                largest_passing_bytes,
                smallest_failing_bytes,
            },
        )
    }

    async fn query_resolver<T: ProbeTransport>(
        &self,
        t: &T,
        used: &mut u32,
        resolver: &str,
        independent: bool,
    ) -> ResolverEvidence {
        let request = ProbeRequest::DnsQuery {
            resolver: resolver.into(),
            name: self.config.dns_probe_name.clone(),
        };
        let outcome = match self.send(t, used, request).await {
            Ok(ProbeResponse::DnsAnswer { latency_ms, .. }) => {
                ResolverOutcome::Answered { latency_ms }
            }
            Ok(ProbeResponse::DnsFailure { reason }) => ResolverOutcome::Failed { reason },
            Ok(_) => ResolverOutcome::Unavailable {
                error: UNEXPECTED_RESPONSE.into(),
            },
            Err(error) => ResolverOutcome::Unavailable {
                error: error.to_string(),
            },
        };
        ResolverEvidence {
            resolver: resolver.into(),
            independent,
            outcome,
        }
    }

    async fn check_dns<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::Dns;
        let mut resolvers = Vec::new();
        let configured = self.config.configured_resolvers.clone();
        for resolver in &configured {
            resolvers.push(self.query_resolver(t, used, resolver, false).await);
        }
        let independent = self.config.independent_resolver.clone();
        resolvers.push(self.query_resolver(t, used, &independent, true).await);

        let configured_total = configured.len();
        let configured_failures = resolvers
            .iter()
            .filter(|r| !r.independent)
            .filter(|r| !matches!(r.outcome, ResolverOutcome::Answered { .. }))
            .count();
        let mut evidence = vec![self.measurement(
            Metric::ResolverFailureCount,
            configured_failures as f64,
            Unit::Count,
        )];
        let best_latency = resolvers
            .iter()
            .filter_map(|r| match r.outcome {
                ResolverOutcome::Answered { latency_ms } => Some(latency_ms),
                _ => None,
            })
            .min_by(f64::total_cmp);
        if let Some(latency) = best_latency {
            evidence.push(self.measurement(Metric::DnsLatencyMs, latency, Unit::Milliseconds));
        }
        let confidence = if configured_failures == 0 {
            Confidence::HIGH
        } else {
            Confidence::MEDIUM
        };
        self.conclude(
            kind,
            configured_failures < configured_total,
            evidence,
            confidence,
            CheckDetail::Dns { resolvers },
        )
    }

    async fn check_route_vpn<T: ProbeTransport>(&self, t: &T, used: &mut u32) -> CheckResult {
        let kind = CheckKind::RouteVpn;
        match self.send(t, used, ProbeRequest::RouteTable).await {
            Ok(ProbeResponse::RouteTable { default_routes }) => {
                let count = default_routes.len();
                let vpn_conflict = count > 1;
                let evidence =
                    vec![self.measurement(Metric::DefaultRouteCount, count as f64, Unit::Count)];
                self.conclude(
                    kind,
                    count == 1,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Route {
                        default_routes,
                        vpn_conflict,
                    },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    async fn check_internet<T: ProbeTransport>(
        &self,
        t: &T,
        used: &mut u32,
        prior: &[CheckResult],
    ) -> CheckResult {
        let kind = CheckKind::InternetReachability;
        let lan_ok = find(prior, CheckKind::Gateway)
            .is_some_and(|result| matches!(result.status, CheckStatus::Passed));
        let request = ProbeRequest::ReachIp {
            address: self.config.internet_probe_address.clone(),
            port: self.config.internet_probe_port,
        };
        match self.send(t, used, request).await {
            Ok(ProbeResponse::Reachable { latency_ms }) => {
                let evidence = vec![
                    self.measurement(Metric::ReachabilitySuccess, 1.0, Unit::Boolean),
                    self.measurement(Metric::RttMs, latency_ms, Unit::Milliseconds),
                ];
                self.conclude(
                    kind,
                    true,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Internet {
                        reachable: true,
                        lan_ok,
                    },
                )
            }
            Ok(ProbeResponse::Unreachable) => {
                let evidence =
                    vec![self.measurement(Metric::ReachabilitySuccess, 0.0, Unit::Boolean)];
                self.conclude(
                    kind,
                    false,
                    evidence,
                    Confidence::HIGH,
                    CheckDetail::Internet {
                        reachable: false,
                        lan_ok,
                    },
                )
            }
            Ok(_) => self.failed_probe(kind, UNEXPECTED_RESPONSE.into()),
            Err(error) => self.failed_probe(kind, error.to_string()),
        }
    }

    fn measurement(&self, metric: Metric, value: f64, unit: Unit) -> Measurement {
        Measurement {
            metric,
            value,
            unit,
            observed_at: self.clock.now(),
        }
    }

    fn conclude(
        &self,
        kind: CheckKind,
        pass: bool,
        evidence: Vec<Measurement>,
        confidence: Confidence,
        detail: CheckDetail,
    ) -> CheckResult {
        CheckResult {
            kind,
            status: if pass {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            evidence,
            confidence,
            detail: Some(detail),
        }
    }

    fn failed_probe(&self, kind: CheckKind, error: String) -> CheckResult {
        CheckResult {
            kind,
            status: CheckStatus::Failed,
            evidence: Vec::new(),
            confidence: Confidence::LOW,
            detail: Some(CheckDetail::ProbeFailure { error }),
        }
    }
}

fn dependency_skip(kind: CheckKind, checks: &[CheckResult]) -> Option<SkipReason> {
    for dependency in kind.dependencies() {
        match find(checks, *dependency).map(|result| result.status) {
            Some(CheckStatus::Passed) => {}
            Some(CheckStatus::Failed) => {
                return Some(SkipReason::DependencyFailed {
                    dependency: *dependency,
                });
            }
            Some(CheckStatus::Skipped { .. }) | None => {
                return Some(SkipReason::DependencySkipped {
                    dependency: *dependency,
                });
            }
        }
    }
    None
}

fn skipped(kind: CheckKind, because: SkipReason) -> CheckResult {
    CheckResult {
        kind,
        status: CheckStatus::Skipped { because },
        evidence: Vec::new(),
        confidence: Confidence::HIGH,
        detail: None,
    }
}

fn find(checks: &[CheckResult], kind: CheckKind) -> Option<&CheckResult> {
    checks.iter().find(|check| check.kind == kind)
}

fn bool_value(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}

fn loss_percent(sent: u32, received: u32) -> f64 {
    if sent == 0 {
        return 100.0;
    }
    100.0 * f64::from(sent.saturating_sub(received)) / f64::from(sent)
}

/// Upper median of the sample (deterministic and adequate for small counts).
fn median(values: &mut [f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(values[values.len() / 2])
}
