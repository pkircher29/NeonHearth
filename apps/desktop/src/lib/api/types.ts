export type PresenceState = 'online' | 'quiet' | 'offline' | 'blocked' | 'unknown';

export interface PresenceChanged {
  device_id: string;
  from: PresenceState;
  to: PresenceState;
  reason: string;
}

export interface ServiceStatus {
  state: string;
  detail: string;
}

export type EventPayload =
  | { type: 'presence_changed'; data: PresenceChanged }
  | { type: 'service_status'; data: ServiceStatus };

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
  coverage: string | null;
  observed_at: string | null;
}

export interface Health {
  status: string;
  api_version: string;
}

export interface EventTicket {
  ticket: string;
  expires_in_seconds: number;
}
