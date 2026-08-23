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

function isServerMessage(value: unknown): value is ServerMessage {
  if (!isRecord(value) || typeof value.type !== 'string') return false;
  if (value.type === 'resync_required') return !('data' in value);
  if (value.type !== 'event' || !isRecord(value.data)) return false;
  const event = value.data;
  if (typeof event.sequence !== 'number' || typeof event.occurred_at !== 'string' || !isRecord(event.payload)) return false;
  const payload = event.payload;
  if (payload.type === 'service_status') return isRecord(payload.data) && typeof payload.data.state === 'string' && typeof payload.data.detail === 'string';
  return payload.type === 'presence_changed' && isRecord(payload.data)
    && typeof payload.data.device_id === 'string'
    && typeof payload.data.from === 'string'
    && typeof payload.data.to === 'string'
    && typeof payload.data.reason === 'string';
}

export function createApiClient({ baseUrl, serviceToken, fetchImpl = fetch, WebSocketImpl = WebSocket }: ApiClientOptions): ApiClient {
  const apiUrl = (path: string) => new URL(path, baseUrl).toString();

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetchImpl(apiUrl(path), init);
    if (!response.ok) throw new Error(`Request failed with status ${response.status}`);
    return response.json() as Promise<T>;
  }

  function authorized(method: 'GET' | 'POST') {
    return { method, headers: { Authorization: `Bearer ${serviceToken}` } };
  }

  return {
    health: () => request<Health>('/api/v1/health'),
    snapshot: () => request<Snapshot>('/api/v1/state', authorized('GET')),
    async issueEventTicket() {
      const ticket = await request<unknown>('/api/v1/events/ticket', authorized('POST'));
      if (!isRecord(ticket) || typeof ticket.ticket !== 'string' || typeof ticket.expires_in_seconds !== 'number') {
        throw new Error('Invalid event ticket response');
      }
      return { ticket: ticket.ticket, expires_in_seconds: ticket.expires_in_seconds };
    },
    async openEvents(afterSequence, onMessage, onState) {
      const { ticket } = await this.issueEventTicket();
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
  };
}
