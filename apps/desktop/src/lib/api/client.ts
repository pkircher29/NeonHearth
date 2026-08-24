import type { Bandwidth, DeviceSnapshot, Evidence, EventTicket, Health, Identity, Presence, ServerMessage, Snapshot } from './types';

type ConnectionState = 'open' | 'closed' | 'error';

export interface ApiClientOptions {
  baseUrl: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
}

export interface SnapshotPageOptions {
  limit?: number;
  after?: string;
}

export interface ApiClient {
  health(): Promise<Health>;
  snapshot(options?: SnapshotPageOptions): Promise<Snapshot>;
  issueEventTicket(): Promise<EventTicket>;
  openEvents(
    afterSequence: number,
    onMessage: (message: ServerMessage) => void,
    onState: (state: ConnectionState) => void
  ): Promise<WebSocket>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * TypeScript numbers are accepted only through MAX_SAFE_INTEGER. At 4Hz this
 * exceeds the product lifetime; server and client must resync or reject any
 * value beyond it instead of silently rounding.
 */
export function isSequence(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isServerMessage(value: unknown): value is ServerMessage {
  if (!isRecord(value) || typeof value.type !== 'string') return false;
  if (value.type === 'resync_required') return !('data' in value);
  if (value.type !== 'event' || !isRecord(value.data)) return false;
  const event = value.data;
  if (!isSequence(event.sequence) || !isDate(event.occurred_at) || !isRecord(event.payload)) return false;
  const payload = event.payload;
  if (payload.type === 'service_status') return isRecord(payload.data) && typeof payload.data.state === 'string' && typeof payload.data.detail === 'string';
  return payload.type === 'presence_changed' && isRecord(payload.data)
    && typeof payload.data.device_id === 'string'
    && typeof payload.data.from === 'string'
    && typeof payload.data.to === 'string'
    && typeof payload.data.reason === 'string';
}

function isHealth(value: unknown): value is Health {
  return isRecord(value) && typeof value.status === 'string' && typeof value.api_version === 'string';
}

const presenceStates = new Set(['online', 'quiet', 'offline', 'blocked', 'unknown']);
const evidenceFamilies = new Set(['link_layer', 'addressing', 'naming', 'service', 'cryptographic', 'router_hint', 'owner']);
const coverages = new Set(['complete', 'router-reported', 'local-only', 'estimated']);
const utcRfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const isDate = (value: unknown): value is string => {
  if (typeof value !== 'string' || !utcRfc3339.test(value)) return false;
  const date = new Date(value);
  return !Number.isNaN(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
};
const isConfidence = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const isBytes = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const isDeviceId = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);

function isPresence(value: unknown): value is Presence {
  if (!isRecord(value) || !presenceStates.has(String(value.state))) return false;
  const fields = [value.observed_at, value.source, value.kind];
  const noTransition = fields.every((field) => field === null);
  const transition = isDate(value.observed_at)
    && typeof value.source === 'string' && value.source.length > 0
    && typeof value.kind === 'string' && value.kind.length > 0;
  return noTransition ? value.state === 'unknown' : transition;
}
function isEvidence(value: unknown): value is Evidence {
  return isRecord(value) && typeof value.family === 'string' && evidenceFamilies.has(value.family)
    && typeof value.source === 'string' && value.source.length > 0 && isConfidence(value.confidence)
    && isDate(value.observed_at) && (value.expires_at === null || isDate(value.expires_at));
}
function isIdentity(value: unknown): value is Identity {
  if (!isRecord(value) || typeof value.available !== 'boolean') return false;
  if (!value.available) return value.classification === null && value.confidence === null;
  return typeof value.classification === 'string' && value.classification.length > 0 && isConfidence(value.confidence);
}
function isBandwidth(value: unknown): value is Bandwidth {
  if (!isRecord(value) || typeof value.available !== 'boolean') return false;
  const fields = [value.upload, value.download, value.coverage, value.observed_at];
  if (!value.available) return fields.every((field) => field === null);
  return isBytes(value.upload) && isBytes(value.download) && typeof value.coverage === 'string'
    && coverages.has(value.coverage) && isDate(value.observed_at);
}
function isDeviceSnapshot(value: unknown): value is DeviceSnapshot {
  return isRecord(value) && isDeviceId(value.device_id) && isDate(value.first_seen_at) && isDate(value.last_seen_at)
    && (value.owner_name === null || typeof value.owner_name === 'string')
    && (value.owner_type === null || typeof value.owner_type === 'string') && typeof value.owner_confirmed === 'boolean'
    && isPresence(value.presence) && (value.evidence === null || isEvidence(value.evidence))
    && isIdentity(value.identity) && isBandwidth(value.bandwidth);
}

function isSnapshot(value: unknown): value is Snapshot {
  return isRecord(value) && isSequence(value.sequence) && Array.isArray(value.devices)
    && value.devices.every(isDeviceSnapshot) && (value.next_after === null || isDeviceId(value.next_after))
    && typeof value.service_status === 'string';
}

function isEventTicket(value: unknown): value is EventTicket {
  return isRecord(value) && typeof value.ticket === 'string' && value.ticket.length > 0 && isSequence(value.expires_in_seconds);
}

export function createApiClient({ baseUrl, serviceToken, fetchImpl = fetch, WebSocketImpl = WebSocket }: ApiClientOptions): ApiClient {
  const apiUrl = (path: string) => new URL(path, baseUrl).toString();

  async function request(path: string, init?: RequestInit): Promise<unknown> {
    const response = await fetchImpl(apiUrl(path), init);
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    return response.json() as Promise<unknown>;
  }

  function authorized(method: 'GET' | 'POST') {
    return { method, headers: { Authorization: `Bearer ${serviceToken}` } };
  }

  async function health(): Promise<Health> {
    const value = await request('/api/v1/health');
    if (!isHealth(value)) throw new Error('Invalid health response');
    return value;
  }

  async function snapshot(options?: SnapshotPageOptions): Promise<Snapshot> {
    if (options?.limit !== undefined && (!Number.isSafeInteger(options.limit) || options.limit < 1 || options.limit > 256)) {
      throw new Error('Invalid snapshot page');
    }
    if (options?.after !== undefined && !isDeviceId(options.after)) {
      throw new Error('Invalid snapshot page');
    }
    const params = new URLSearchParams();
    if (options?.limit !== undefined) params.set('limit', String(options.limit));
    if (options?.after !== undefined) params.set('after', options.after);
    const query = params.toString();
    const value = await request(query ? `/api/v1/state?${query}` : '/api/v1/state', authorized('GET'));
    if (!isSnapshot(value)) throw new Error('Invalid snapshot response');
    return value;
  }

  async function issueEventTicket(): Promise<EventTicket> {
    const value = await request('/api/v1/events/ticket', authorized('POST'));
    if (!isEventTicket(value)) throw new Error('Invalid event ticket response');
    return value;
  }

  async function openEvents(afterSequence: number, onMessage: (message: ServerMessage) => void, onState: (state: ConnectionState) => void): Promise<WebSocket> {
      if (!isSequence(afterSequence)) throw new Error('Invalid event sequence');
      const { ticket } = await issueEventTicket();
      const url = new URL('/api/v1/events', baseUrl);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      url.search = new URLSearchParams({ ticket, after_sequence: String(afterSequence) }).toString();
      const socket = new WebSocketImpl(url.toString());
      socket.onopen = () => onState('open');
      socket.onclose = () => onState('closed');
      socket.onerror = () => onState('error');
      socket.onmessage = (event) => {
        if (typeof event.data !== 'string') return;
        try {
          const message: unknown = JSON.parse(event.data);
          if (isServerMessage(message)) onMessage(message);
        } catch {
          // Ignore malformed network data; only typed server messages enter the live store.
        }
      };
      return socket;
  }

  return { health, snapshot, issueEventTicket, openEvents };
}
