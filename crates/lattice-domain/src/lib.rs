//! Domain types and logic for NeonHearth.
mod device;
mod event;
mod evidence;
mod flow;
mod home;
mod policy;
mod presence;

pub use device::DeviceId;
pub use event::{
    BandwidthFrame, BandwidthSample, EventEnvelope, EventPayload, PolicyChanged, ServiceStatus,
};
pub use evidence::{EvidenceFact, EvidenceFamily};
pub use flow::{ByteCount, Coverage};
pub use home::{
    EffectiveLocation, Floor, FloorId, HomeChanged, HomeId, HomePlan, LocationEstimate,
    MAX_CEILING_HEIGHT_M, MAX_COORDINATE_M, MAX_FLOORS, MAX_NAME_CHARS, MAX_ROOMS_PER_FLOOR,
    MAX_WALLS_PER_FLOOR, MIN_CEILING_HEIGHT_M, MIN_NAME_CHARS, Mounting, Opening, OpeningId,
    OpeningKind, OwnerPlacement, PlacementId, PlanValidationError, Point, Room, RoomId,
    UNCERTAIN_CONFIDENCE_THRESHOLD, Wall, WallId, effective_location,
};
pub use policy::{
    AUTOMATIC_IDENTITY_THRESHOLD_BPS, AUTOMATIC_POLICY_DEADLINE_HOURS, Deadline, DeadlineKind,
    DeadlineWarning, DevicePolicy, EnforcementStatus, Evaluation, Identification, OwnerDecision,
    PolicyReason, Protection, RequestedAction, RiskSignal, UNKNOWN_POLICY_DEADLINE_HOURS,
};
pub use presence::{PresenceChanged, PresenceState};
