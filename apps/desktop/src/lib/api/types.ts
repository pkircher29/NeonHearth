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
  devices: unknown[];
  service_status: string;
}

export interface Health {
  status: string;
  api_version: string;
}

export interface EventTicket {
  ticket: string;
  expires_in_seconds: number;
}
