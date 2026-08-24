//! Typed diagnoses derived from check results (N2).

use crate::check::{
    CheckDetail, CheckKind, CheckResult, CheckStatus, Confidence, DiagnosticReport, Measurement,
    ResolverEvidence,
};
use crate::probe::{LeaseState, RouteEntry};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What is wrong, in typed form.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DiagnosisKind {
    CollectorFault {
        privileged: bool,
        capture_ok: bool,
        worker_running: bool,
    },
    AdapterLinkDown,
    AddressMissing {
        lease: LeaseState,
    },
    DuplicateIp {
        address: String,
        macs: Vec<String>,
    },
    WeakWifiQuality {
        rssi_dbm: i16,
    },
    GatewayUnreachable,
    RouterFault,
    LossLatencyDegraded {
        loss_percent: f64,
        median_rtt_ms: Option<f64>,
    },
    MtuBlackhole {
        largest_passing_bytes: Option<u16>,
        smallest_failing_bytes: Option<u16>,
    },
    DnsFailure {
        resolvers: Vec<ResolverEvidence>,
    },
    RouteVpnConflict {
        default_routes: Vec<RouteEntry>,
    },
    InternetUnreachable {
        /// True when the LAN (gateway) was reachable, isolating the fault to
        /// the WAN side.
        lan_ok: bool,
    },
    /// The diagnostic probe itself could not run; the check is inconclusive.
    DiagnosticProbeFailure {
        check: CheckKind,
        error: String,
    },
}

/// A diagnosis with its supporting evidence, confidence, and impact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Diagnosis {
    pub kind: DiagnosisKind,
    pub evidence: Vec<Measurement>,
    pub confidence: Confidence,
    /// Owner-facing description of what this fault affects.
    pub impact: String,
}

/// Map every failed check in a report to a typed diagnosis.
///
/// Skipped checks produce nothing: their causes are already explained by the
/// parent that failed.
pub fn diagnose(report: &DiagnosticReport) -> Vec<Diagnosis> {
    report
        .checks
        .iter()
        .filter(|check| matches!(check.status, CheckStatus::Failed))
        .map(diagnosis_for)
        .collect()
}

fn diagnosis_for(result: &CheckResult) -> Diagnosis {
    let kind = kind_for(result);
    let impact = impact_for(&kind).to_owned();
    Diagnosis {
        kind,
        evidence: result.evidence.clone(),
        confidence: result.confidence,
        impact,
    }
}

fn kind_for(result: &CheckResult) -> DiagnosisKind {
    if let Some(CheckDetail::ProbeFailure { error }) = &result.detail {
        return DiagnosisKind::DiagnosticProbeFailure {
            check: result.kind,
            error: error.clone(),
        };
    }
    match (result.kind, &result.detail) {
        (
            CheckKind::CollectorHealth,
            Some(CheckDetail::Collector {
                privileged,
                capture_ok,
                worker_running,
            }),
        ) => DiagnosisKind::CollectorFault {
            privileged: *privileged,
            capture_ok: *capture_ok,
            worker_running: *worker_running,
        },
        (CheckKind::AdapterLink, _) => DiagnosisKind::AdapterLinkDown,
        (CheckKind::AddressDhcp, Some(CheckDetail::Address { lease, .. })) => {
            DiagnosisKind::AddressMissing { lease: *lease }
        }
        (CheckKind::DuplicateIp, Some(CheckDetail::DuplicateIp { address, macs })) => {
            DiagnosisKind::DuplicateIp {
                address: address.clone(),
                macs: macs.clone(),
            }
        }
        (
            CheckKind::WifiQuality,
            Some(CheckDetail::Wifi {
                rssi_dbm: Some(rssi),
                ..
            }),
        ) => DiagnosisKind::WeakWifiQuality { rssi_dbm: *rssi },
        (CheckKind::Gateway, _) => DiagnosisKind::GatewayUnreachable,
        (CheckKind::RouterHealth, _) => DiagnosisKind::RouterFault,
        (
            CheckKind::LossLatency,
            Some(CheckDetail::LossLatency {
                loss_percent,
                median_rtt_ms,
            }),
        ) => DiagnosisKind::LossLatencyDegraded {
            loss_percent: *loss_percent,
            median_rtt_ms: *median_rtt_ms,
        },
        (
            CheckKind::Mtu,
            Some(CheckDetail::Mtu {
                largest_passing_bytes,
                smallest_failing_bytes,
            }),
        ) => DiagnosisKind::MtuBlackhole {
            largest_passing_bytes: *largest_passing_bytes,
            smallest_failing_bytes: *smallest_failing_bytes,
        },
        (CheckKind::Dns, Some(CheckDetail::Dns { resolvers })) => DiagnosisKind::DnsFailure {
            resolvers: resolvers.clone(),
        },
        (CheckKind::RouteVpn, Some(CheckDetail::Route { default_routes, .. })) => {
            DiagnosisKind::RouteVpnConflict {
                default_routes: default_routes.clone(),
            }
        }
        (CheckKind::InternetReachability, Some(CheckDetail::Internet { lan_ok, .. })) => {
            DiagnosisKind::InternetUnreachable { lan_ok: *lan_ok }
        }
        // A failed check whose detail does not match its kind: report the
        // inconsistency instead of guessing.
        (check, _) => DiagnosisKind::DiagnosticProbeFailure {
            check,
            error: "diagnostic detail missing or inconsistent".into(),
        },
    }
}

fn impact_for(kind: &DiagnosisKind) -> &'static str {
    match kind {
        DiagnosisKind::CollectorFault { .. } => {
            "NeonHearth cannot observe the network; monitoring and protection are degraded."
        }
        DiagnosisKind::AdapterLinkDown => {
            "No traffic can flow on this adapter; every dependent service is offline."
        }
        DiagnosisKind::AddressMissing { .. } => {
            "The host has no usable IP address; nothing on the network can be reached."
        }
        DiagnosisKind::DuplicateIp { .. } => {
            "Two devices claim the same address; connections will fail intermittently."
        }
        DiagnosisKind::WeakWifiQuality { .. } => {
            "Weak Wi-Fi signal causes slow transfers and dropped connections."
        }
        DiagnosisKind::GatewayUnreachable => {
            "The router cannot be reached; all traffic beyond this host is blocked."
        }
        DiagnosisKind::RouterFault => {
            "The router's management interface is unhealthy; visibility and control are reduced."
        }
        DiagnosisKind::LossLatencyDegraded { .. } => {
            "Packet loss or latency is elevated; calls, streams, and games will stutter."
        }
        DiagnosisKind::MtuBlackhole { .. } => {
            "Large packets are silently dropped; some sites and VPNs will hang."
        }
        DiagnosisKind::DnsFailure { .. } => {
            "Name resolution is failing; sites appear down even though the connection is up."
        }
        DiagnosisKind::RouteVpnConflict { .. } => {
            "The default route is missing or contested; traffic may take a broken path."
        }
        DiagnosisKind::InternetUnreachable { lan_ok: true } => {
            "The local network works but the internet is down; the fault is on the WAN side."
        }
        DiagnosisKind::InternetUnreachable { lan_ok: false } => {
            "Neither the local network nor the internet is reachable from this host."
        }
        DiagnosisKind::DiagnosticProbeFailure { .. } => {
            "A diagnostic probe could not run; this area of the network is unassessed."
        }
    }
}
