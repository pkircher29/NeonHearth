//! Domain types and logic for NeonHearth.
mod device;
mod event;
mod evidence;
mod flow;
mod policy;
mod presence;

pub use device::DeviceId;
pub use event::{
    BandwidthFrame, BandwidthSample, EventEnvelope, EventPayload, PolicyChanged, ServiceStatus,
};
pub use evidence::{EvidenceFact, EvidenceFamily};
pub use flow::{ByteCount, Coverage};
pub use policy::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, Deadline, DeadlineKind,
    DeadlineWarning, DevicePolicy, Evaluation, Identification, OwnerDecision, PolicyReason,
    Protection, RequestedAction, RiskSignal, UNKNOWN_POLICY_DEADLINE_HOURS,
};
pub use presence::{PresenceChanged, PresenceState};
