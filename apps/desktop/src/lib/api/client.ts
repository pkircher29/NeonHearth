import type { EventTicket, Health, ServerMessage, Snapshot } from './types';

type ConnectionState = 'open' | 'closed' | 'error';

export interface ApiClientOptions {
  baseUrl: string;
  serviceToken: string;
  fetchImpl?: typeof fetch;
  WebSocketImpl?: typeof WebSocket;
}

export interface ApiClient {
  health(): Promise<Health>;
  snapshot(): Promise<Snapshot>;
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
  if (!isSequence(event.sequence) || typeof event.occurred_at !== 'string' || !isRecord(event.payload)) return false;
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

function isSnapshot(value: unknown): value is Snapshot {
  return isRecord(value) && isSequence(value.sequence) && Array.isArray(value.devices) && typeof value.service_status === 'string';
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

  async function snapshot(): Promise<Snapshot> {
    const value = await request('/api/v1/state', authorized('GET'));
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
