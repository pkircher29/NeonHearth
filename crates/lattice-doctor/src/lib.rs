//! Network Doctor core for NeonHearth (Stage 6, N1-N4).
//!
//! This crate is a pure, transport-injected diagnostic and repair engine:
//!
//! - [`engine::DiagnosticEngine`] walks a typed dependency DAG of checks
//!   ([`check::CheckKind`]) with bounded probes through an injected
//!   [`probe::ProbeTransport`]. A failed parent short-circuits its children
//!   into a skipped state so downstream causes are never mis-diagnosed.
//! - [`diagnosis::diagnose`] maps check results into typed
//!   [`diagnosis::Diagnosis`] values carrying evidence, confidence, and impact.
//! - [`repair`] classifies repairs into safe-automatic, approval-required
//!   reversible (constructible only with an [`repair::ApprovalId`] token),
//!   guided-physical, or observation-only plans.
//! - [`executor::RepairExecutor`] runs the snapshot -> apply -> verify ->
//!   rollback lifecycle through an injected [`executor::RepairTransport`],
//!   producing an auditable typed event sequence.
//!
//! The crate never touches a real network; all side effects flow through the
//! two transport traits, which the service layer implements.

pub mod check;
pub mod diagnosis;
pub mod engine;
pub mod executor;
pub mod probe;
pub mod repair;

use chrono::{DateTime, Utc};

/// Errors produced when constructing doctor inputs with invalid values.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DoctorError {
    #[error("confidence exceeds 10000 basis points")]
    InvalidConfidence,
    #[error("diagnostic budget is invalid: {0}")]
    InvalidBudget(&'static str),
    #[error("doctor configuration is invalid: {0}")]
    InvalidConfig(&'static str),
    #[error("symptom definition is invalid: {0}")]
    InvalidSymptom(&'static str),
    #[error("approval token is invalid")]
    InvalidApproval,
}

/// Injectable time source so engines and executors stay deterministic in tests.
pub trait Clock: Send + Sync + std::fmt::Debug {
    fn now(&self) -> DateTime<Utc>;
}

/// Wall-clock time source used in production wiring.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A frozen clock for deterministic tests and replays.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock(pub DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}
