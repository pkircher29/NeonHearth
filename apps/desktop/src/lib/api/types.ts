export type PresenceState = 'online' | 'quiet' | 'offline' | 'blocked' | 'unknown';

export interface PresenceChanged {
  transition_id: number;
  device_id: string;
  from: PresenceState;
  to: PresenceState;
  reason: string;
  occurred_at: string;
  trigger_source: string;
  trigger_kind: string;
  evidence_observed_at: string;
  evidence_valid_until: string | null;
  trigger_arrival_at: string;
  correction_of: number | null;
}

export interface ByteCount { upload: number; download: number }
export type Coverage = 'complete' | 'router-reported' | 'local-only' | 'estimated';
export interface BandwidthSample {
  device_id: string; delta: ByteCount; upload_bytes_per_second: number;
  download_bytes_per_second: number; coverage: Coverage;
}
export interface BandwidthFrame { interval_ms: number; observed_at: string; emitted_at: string; samples: BandwidthSample[] }

export interface ServiceStatus {
  state: string;
  detail: string;
}

export type PolicyReason = 'pending_confirmation' | 'baseline_exempt' | 'high_confidence_danger'
  | 'unknown_deadline_expired' | 'automatic_deadline_expired' | 'owner_extension'
  | 'owner_approved' | 'owner_rejected' | 'owner_quarantined' | 'protected_device';
export type RequestedAction = 'none' | 'quarantine' | 'permanent_ban' | 'owner_attention';
export type EnforcementStatus = 'not_requested' | 'verified' | 'manual_required' | 'failed';
export type DeadlineWarning = 'hours24' | 'hours6' | 'hour1';
export interface PolicyDeadline { kind: 'unknown48_hours' | 'automatic7_days'; due_at: string }
export interface PolicyEvaluation {
  policy_version: number;
  reason: PolicyReason;
  requested_action: RequestedAction;
  deadline: PolicyDeadline | null;
  warning: DeadlineWarning | null;
}
export interface PolicyChanged {
  device_id: string;
  policy_version: number;
  evaluation: PolicyEvaluation;
  requested_action: RequestedAction;
  evidence_summary: string;
  enforcement_result: EnforcementStatus;
  undo_available: boolean;
}
export type OwnerDecision = 'pending' | 'approved' | 'rejected' | 'quarantined';
export type Protection = 'none' | 'router' | 'collector' | 'administrator_phone' | 'safety_device';
export interface PolicyProjection {
  owner_decision: OwnerDecision;
  protection: Protection;
  evaluation: PolicyEvaluation;
  enforcement_result: EnforcementStatus;
  undo_available: boolean;
  delivery_pending: boolean;
}

// Bandwidth frames are emitted by the collector at a bounded cadence.
export type EventPayload =
  | { type: 'presence_changed'; data: PresenceChanged }
  | { type: 'service_status'; data: ServiceStatus }
  | { type: 'bandwidth_frame'; data: BandwidthFrame }
  | { type: 'policy_changed'; data: PolicyChanged };

export interface EventEnvelope {
  sequence: number;
  occurred_at: string;
  payload: EventPayload;
}

export type ServerMessage =
  | { type: 'event'; data: EventEnvelope }
  | { type: 'resync_required' };

export interface Snapshot {
  sequence: number;
  devices: DeviceSnapshot[];
  next_after: string | null;
  service_status: string;
}
export interface DeviceSnapshot {
  device_id: string;
  first_seen_at: string;
  last_seen_at: string;
  owner_name: string | null;
  owner_type: string | null;
  owner_confirmed: boolean;
  presence: Presence;
  evidence: Evidence | null;
  identity: Identity;
  bandwidth: Bandwidth;
  policy: PolicyProjection | null;
}

export interface Presence {
  state: PresenceState;
  observed_at: string | null;
  source: string | null;
  kind: string | null;
}

export interface Evidence {
  family: string;
  source: string;
  confidence: number;
  observed_at: string;
  expires_at: string | null;
}

export interface Identity {
  available: boolean;
  classification: string | null;
  confidence: number | null;
}

export interface Bandwidth {
  available: boolean;
  upload: number | null;
  download: number | null;
  coverage: Coverage | null;
  observed_at: string | null;
}

export interface Health {
  status: string;
  api_version: string;
}
export interface CameraSummary { camera_id: string; classification: string; confidence: number; health: string; observed_at: string }
export interface CameraList { items: CameraSummary[]; next_after: string | null }
export interface CameraDetail extends CameraSummary { inventory: CameraInventoryProjection | null }
export interface CameraHealth { health: string; confidence: number }
export interface CameraInventoryProjection { manufacturer: string | null; model: string | null; firmware: string | null; serial: string | null; capabilities: string[]; health: string }
export interface CameraSessionResponse { session_id: string }

export interface EventTicket {
  ticket: string;
  expires_in_seconds: number;
}
