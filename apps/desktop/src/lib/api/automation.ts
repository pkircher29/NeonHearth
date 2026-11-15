export interface NetworkDetails {
  status: string; observed_at: string;
  devices: Array<{ device_id: string; mac_addresses: string[]; ip_addresses: string[];
    home_assistant: {device_id: string; name: string; manufacturer: string | null; model: string | null; area: string | null} | null;
    mac_assignments?: Array<{mac_address: string; organization: string | null; registry: string | null; status: string}>;
  }>;
}
export interface AutomationEntity {
  entity_id: string; name: string; state: string; last_changed: string | null;
  last_updated: string | null; area: string | null; platform: string | null;
  power_capable: boolean; control_enabled: boolean;
}
export interface AutomationDevice {
  device_id: string; upstream_id: string; name: string; manufacturer: string | null;
  model: string | null; area: string | null; mac_addresses: string[];
  first_seen_at: string; last_seen_at: string; entities: AutomationEntity[];
}
export interface AutomationSnapshot {
  mqtt?: { status: string; detail: string };
  status: string; detail: string; source: string | null; updated_at: string | null;
  devices: AutomationDevice[]; areas: string[];
}
export interface CommandReceipt { command_id: string; status: string; detail: string }
export interface AutomationApi {
  snapshot(): Promise<AutomationSnapshot>;
  network(): Promise<NetworkDetails>;
  connect(url: string, access_token: string): Promise<void>;
  disconnect(): Promise<void>;
  permissions(entity_ids: string[]): Promise<void>;
  command(entity: AutomationEntity, action: 'turn_on' | 'turn_off'): Promise<CommandReceipt>;
}
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length <= 1024;
const nullable = (v: unknown): v is string | null => v === null || text(v);
export function isAutomationSnapshot(v: unknown): v is AutomationSnapshot {
  return record(v) && text(v.status) && text(v.detail) && nullable(v.source) && nullable(v.updated_at)
    && Array.isArray(v.areas) && v.areas.length <= 4096 && v.areas.every(text)
    && Array.isArray(v.devices) && v.devices.length <= 4096 && v.devices.every(d => record(d)
      && text(d.device_id) && /^[0-9a-f-]{36}$/.test(d.device_id) && text(d.upstream_id) && text(d.name)
      && nullable(d.manufacturer) && nullable(d.model) && nullable(d.area) && text(d.first_seen_at) && text(d.last_seen_at)
      && Array.isArray(d.mac_addresses) && d.mac_addresses.length <= 32 && d.mac_addresses.every(text)
      && Array.isArray(d.entities) && d.entities.length <= 4096 && d.entities.every(e => record(e)
        && text(e.entity_id) && text(e.name) && text(e.state) && nullable(e.area) && nullable(e.platform)
        && nullable(e.last_changed) && nullable(e.last_updated) && typeof e.power_capable === 'boolean' && typeof e.control_enabled === 'boolean'));
}
export function createAutomationApi(serviceToken: string | { header(): string | null }, fetchImpl: typeof fetch = fetch): AutomationApi {
  async function request(path: string, method = 'GET', body?: unknown): Promise<unknown> {
    const response = await fetchImpl(`/api/v1/automation${path}`, {
      method, headers: { Authorization: typeof serviceToken === 'string' ? `Bearer ${serviceToken}` : serviceToken.header() ?? '', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(path === '/commands' ? 25_000 : 10_000),
    });
    if (!response.ok) {
      const messages: Record<number, string> = {
        400: 'Check the connection address or command. Home Assistant requires HTTPS; HTTP is available only on this computer.',
        401: 'Open NeonHearth from its launcher to pair this window.',
        403: 'Power control is not enabled for this entity.',
        409: 'The connection or device state changed. Refresh and review the action again.',
        429: 'An operation is already in progress. Wait a few seconds and try again.',
      };
      throw new Error(messages[response.status] ?? 'The service could not complete this request. Check the device state before retrying a power command.');
    }
    return response.status === 204 || response.status === 202 ? null : response.json();
  }
  return {
    async network() {
      const value = await request('/network');
      if (!record(value) || !text(value.status) || !text(value.observed_at) || !Array.isArray(value.devices) || value.devices.length > 4096 ||
          !value.devices.every(d => record(d) && text(d.device_id) &&
            Array.isArray(d.mac_addresses) && d.mac_addresses.length <= 32 && d.mac_addresses.every(text) &&
            Array.isArray(d.ip_addresses) && d.ip_addresses.length <= 32 && d.ip_addresses.every(text) &&
            (d.mac_assignments === undefined || (Array.isArray(d.mac_assignments) && d.mac_assignments.length <= 32 && d.mac_assignments.every(a => record(a) && text(a.mac_address) && nullable(a.organization) && nullable(a.registry) && text(a.status)))) &&
            (d.home_assistant === null || (record(d.home_assistant) && text(d.home_assistant.device_id) && text(d.home_assistant.name) &&
              nullable(d.home_assistant.manufacturer) && nullable(d.home_assistant.model) && nullable(d.home_assistant.area))))) {
        throw new Error('Network address details are unavailable.');
      }
      return value as unknown as NetworkDetails;
    },
    async snapshot() { const value = await request(''); if (!isAutomationSnapshot(value)) throw new Error('The automation inventory could not be verified.'); return value; },
    async connect(url, access_token) { await request('/connect', 'POST', { url, access_token }); },
    async disconnect() { await request('/disconnect', 'POST'); },
    async permissions(entity_ids) { await request('/permissions', 'PUT', { entity_ids }); },
    async command(entity, action) {
      const value = await request('/commands', 'POST', { command_id: crypto.randomUUID(), entity_id: entity.entity_id, action, expected_last_changed: entity.last_changed, issued_at: new Date().toISOString(), confirmed: true });
      if (!record(value) || !text(value.command_id) || !text(value.status) || !text(value.detail)) throw new Error('No command receipt. Check the observed device state before retrying.');
      return value as unknown as CommandReceipt;
    },
  };
}
