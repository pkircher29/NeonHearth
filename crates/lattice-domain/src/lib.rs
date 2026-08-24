//! Domain types and logic for NeonHearth.
mod device;
mod event;
mod evidence;
mod flow;
mod policy;
mod presence;

pub use device::DeviceId;
pub use event::{BandwidthFrame, BandwidthSample, EventEnvelope, EventPayload, ServiceStatus};
pub use evidence::{EvidenceFact, EvidenceFamily};
pub use flow::{ByteCount, Coverage};
pub use policy::{
    Deadline, DeadlineKind, DeadlineWarning, DevicePolicy, Evaluation, Identification,
    OwnerDecision, PolicyReason, Protection, RequestedAction, RiskSignal,
};
pub use presence::{PresenceChanged, PresenceState};
