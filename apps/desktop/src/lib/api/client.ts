import type { Bandwidth, BandwidthFrame, DeviceSnapshot, Evidence, EventTicket, Health, Identity, PolicyChanged, PolicyEvaluation, PolicyProjection, Presence, ServerMessage, Snapshot } from './types';

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
  snapshotAll(options?: { limit?: number; maxPages?: number; maxRecords?: number }): Promise<Snapshot>;
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
  if (payload.type === 'bandwidth_frame') return isBandwidthFrame(payload.data);
  if (payload.type === 'policy_changed') return isPolicyChanged(payload.data);
  return payload.type === 'presence_changed' && isRecord(payload.data)
    && isSequence(payload.data.transition_id)
    && isDeviceId(payload.data.device_id)
    && presenceStates.has(String(payload.data.from))
    && presenceStates.has(String(payload.data.to))
    && typeof payload.data.reason === 'string' && payload.data.reason.length > 0
    && isDate(payload.data.occurred_at) && typeof payload.data.trigger_source === 'string'
    && payload.data.trigger_source.length > 0 && typeof payload.data.trigger_kind === 'string' && payload.data.trigger_kind.length > 0 && isDate(payload.data.evidence_observed_at)
    && (payload.data.evidence_valid_until === null || isDate(payload.data.evidence_valid_until))
    && isDate(payload.data.trigger_arrival_at) && Object.hasOwn(payload.data, 'correction_of')
    && (payload.data.correction_of === null || isSequence(payload.data.correction_of));
}

function isHealth(value: unknown): value is Health {
  return isRecord(value) && typeof value.status === 'string' && typeof value.api_version === 'string';
}

const presenceStates = new Set(['online', 'quiet', 'offline', 'blocked', 'unknown']);
const evidenceFamilies = new Set(['link_layer', 'addressing', 'naming', 'service', 'cryptographic', 'router_hint', 'owner']);
const coverages = new Set(['complete', 'router-reported', 'local-only', 'estimated']);
const policyReasons = new Set(['pending_confirmation', 'baseline_exempt', 'high_confidence_danger', 'unknown_deadline_expired', 'automatic_deadline_expired', 'owner_extension', 'owner_approved', 'owner_rejected', 'owner_quarantined', 'protected_device']);
const requestedActions = new Set(['none', 'quarantine', 'permanent_ban', 'owner_attention']);
const enforcementStatuses = new Set(['not_requested', 'verified', 'manual_required', 'failed']);
const deadlineKinds = new Set(['unknown48_hours', 'automatic7_days']);
const deadlineWarnings = new Set(['hours24', 'hours6', 'hour1']);
const ownerDecisions = new Set(['pending', 'approved', 'rejected', 'quarantined']);
const protections = new Set(['none', 'router', 'collector', 'administrator_phone', 'safety_device']);
const actionForReason = new Map([
  ['pending_confirmation', 'none'], ['baseline_exempt', 'none'], ['high_confidence_danger', 'quarantine'],
  ['unknown_deadline_expired', 'quarantine'], ['automatic_deadline_expired', 'quarantine'],
  ['owner_extension', 'none'], ['owner_approved', 'none'], ['owner_rejected', 'permanent_ban'],
  ['owner_quarantined', 'quarantine'], ['protected_device', 'owner_attention']
]);
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
function isBandwidthFrame(value: unknown): value is BandwidthFrame {
  if (!isRecord(value) || !isSequence(value.interval_ms) || value.interval_ms < 1 || !isDate(value.observed_at) || !isDate(value.emitted_at) || !Array.isArray(value.samples) || value.samples.length > 4096) return false;
  return value.samples.every((sample) => isRecord(sample) && isDeviceId(sample.device_id) && isRecord(sample.delta)
    && isBytes(sample.delta.upload) && isBytes(sample.delta.download) && isBytes(sample.upload_bytes_per_second)
    && isBytes(sample.download_bytes_per_second) && typeof sample.coverage === 'string' && coverages.has(sample.coverage));
}
function isPolicyVersion(value: unknown): value is number {
  return isSequence(value) && value <= 0xffff_ffff;
}
function isPolicyEvaluation(value: unknown): value is PolicyEvaluation {
  if (!isRecord(value) || !isPolicyVersion(value.policy_version)
    || typeof value.reason !== 'string' || !policyReasons.has(value.reason)
    || typeof value.requested_action !== 'string' || !requestedActions.has(value.requested_action)
    || !(value.warning === null || (typeof value.warning === 'string' && deadlineWarnings.has(value.warning)))) return false;
  if (actionForReason.get(value.reason) !== value.requested_action) return false;
  return value.deadline === null || (isRecord(value.deadline)
    && typeof value.deadline.kind === 'string' && deadlineKinds.has(value.deadline.kind)
    && isDate(value.deadline.due_at));
}
function isPolicyProjection(value: unknown): value is PolicyProjection {
  return isRecord(value)
    && typeof value.owner_decision === 'string' && ownerDecisions.has(value.owner_decision)
    && typeof value.protection === 'string' && protections.has(value.protection)
    && isPolicyEvaluation(value.evaluation)
    && typeof value.enforcement_result === 'string' && enforcementStatuses.has(value.enforcement_result)
    && typeof value.undo_available === 'boolean';
}
function isPolicyChanged(value: unknown): value is PolicyChanged {
  return isRecord(value) && isDeviceId(value.device_id) && isPolicyVersion(value.policy_version)
    && isPolicyEvaluation(value.evaluation) && value.policy_version === value.evaluation.policy_version
    && typeof value.requested_action === 'string' && requestedActions.has(value.requested_action)
    && value.requested_action === value.evaluation.requested_action
    && typeof value.evidence_summary === 'string' && value.evidence_summary.length > 0 && value.evidence_summary.length <= 4096
    && typeof value.enforcement_result === 'string' && enforcementStatuses.has(value.enforcement_result)
    && typeof value.undo_available === 'boolean';
}
function isDeviceSnapshot(value: unknown): value is DeviceSnapshot {
  return isRecord(value) && isDeviceId(value.device_id) && isDate(value.first_seen_at) && isDate(value.last_seen_at)
    && (value.owner_name === null || typeof value.owner_name === 'string')
    && (value.owner_type === null || typeof value.owner_type === 'string') && typeof value.owner_confirmed === 'boolean'
    && isPresence(value.presence) && (value.evidence === null || isEvidence(value.evidence))
    && isIdentity(value.identity) && isBandwidth(value.bandwidth)
    && Object.hasOwn(value, 'policy') && (value.policy === null || isPolicyProjection(value.policy));
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

  async function snapshotAll(options: { limit?: number; maxPages?: number; maxRecords?: number } = {}): Promise<Snapshot> {
    const limit = options.limit ?? 256;
    const maxPages = options.maxPages ?? 256;
    const maxRecords = options.maxRecords ?? 65536;
    if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 256 || !Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 65536) throw new Error('Invalid snapshot bounds');
    const devices: DeviceSnapshot[] = [];
    let after: string | undefined;
    let sequence: number | undefined;
    let serviceStatus = 'unknown';
    const cursors = new Set<string>();
    for (let page = 0; page < maxPages; page += 1) {
      const current = await snapshot({ limit, ...(after ? { after } : {}) });
      if (sequence === undefined) sequence = current.sequence;
      if (current.sequence !== sequence) throw new Error('Snapshot sequence changed');
      serviceStatus = current.service_status;
      devices.push(...current.devices);
      if (devices.length > maxRecords) throw new Error('Snapshot exceeds safety bound');
      if (current.next_after === null) return { sequence, devices, next_after: null, service_status: serviceStatus };
      if (cursors.has(current.next_after)) throw new Error('Snapshot cursor cycle');
      cursors.add(current.next_after);
      after = current.next_after;
    }
    throw new Error('Snapshot page bound exceeded');
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

  return { health, snapshot, snapshotAll, issueEventTicket, openEvents };
}
