use crate::{InterfaceId, TargetGuard, TargetGuardError};
use chrono::{DateTime, Utc};
use lattice_camera::{CameraEvidence, CameraEvidenceFamily};
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CameraObservationError {
    #[error(transparent)]
    Target(#[from] TargetGuardError),
    #[error("camera observation evidence is invalid")]
    InvalidEvidence,
}

/// Converts an observation only after the existing owner-approved target boundary.
#[allow(clippy::too_many_arguments)]
pub fn camera_evidence_from_observation(
    guard: &TargetGuard,
    interface: InterfaceId,
    target: IpAddr,
    family: CameraEvidenceFamily,
    source: impl Into<String>,
    fact: impl Into<String>,
    confidence: f32,
    observed_at: DateTime<Utc>,
) -> Result<CameraEvidence, CameraObservationError> {
    guard.authorize(interface, target)?;
    CameraEvidence::new(family, source, fact, confidence, observed_at, None)
        .map_err(|_| CameraObservationError::InvalidEvidence)
}
