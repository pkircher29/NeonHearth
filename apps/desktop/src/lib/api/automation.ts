import { SIGN_IN_AGAIN, createHttp, isNullableText, isRecord, isText, validRows, type AuthSource } from './http';
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
const record = isRecord;
const MAX_TEXT = 1024;
const text = isText(MAX_TEXT);
const nullable = isNullableText(MAX_TEXT);
/** Over-long device-supplied text is clipped, not a reason to reject the whole inventory. */
const clip = (value: unknown): unknown => (typeof value === 'string' && value.length > MAX_TEXT ? value.slice(0, MAX_TEXT) : value);
const clipTextFields = <T extends Record<string, unknown>>(row: T, keys: string[]): T => { const out: Record<string, unknown> = { ...row }; for (const key of keys) out[key] = clip(out[key]); return out as T; };
const ENTITY_TEXT = ['entity_id', 'name', 'state', 'area', 'platform', 'last_changed', 'last_updated'];
const DEVICE_TEXT = ['device_id', 'upstream_id', 'name', 'manufacturer', 'model', 'area', 'first_seen_at', 'last_seen_at'];
const isEntity = (e: unknown): e is AutomationEntity => record(e)
  && text(e.entity_id) && text(e.name) && text(e.state) && nullable(e.area) && nullable(e.platform)
  && nullable(e.last_changed) && nullable(e.last_updated) && typeof e.power_capable === 'boolean' && typeof e.control_enabled === 'boolean';
const isDevice = (d: unknown): d is AutomationDevice => record(d)
  && text(d.device_id) && /^[0-9a-f-]{36}$/.test(d.device_id) && text(d.upstream_id) && text(d.name)
  && nullable(d.manufacturer) && nullable(d.model) && nullable(d.area) && text(d.first_seen_at) && text(d.last_seen_at)
  && Array.isArray(d.mac_addresses) && d.mac_addresses.length <= 32 && d.mac_addresses.every(text)
  && Array.isArray(d.entities) && d.entities.length <= 4096 && d.entities.every(isEntity);
export function isAutomationSnapshot(v: unknown): v is AutomationSnapshot {
  return record(v) && text(v.status) && text(v.detail) && nullable(v.source) && nullable(v.updated_at)
    && Array.isArray(v.areas) && v.areas.length <= 4096 && v.areas.every(text)
    && Array.isArray(v.devices) && v.devices.length <= 4096 && v.devices.every(isDevice);
}
/**
 * Lenient parse: clips over-long strings and drops structurally invalid devices and entities (counting
 * them) so one odd Home Assistant name cannot blank the Home and Automation views. Returns null only
 * when the envelope itself is not an inventory.
 */
export function sanitizeAutomationSnapshot(v: unknown): { snapshot: AutomationSnapshot; dropped: number } | null {
  if (!record(v) || !Array.isArray(v.devices) || !Array.isArray(v.areas)) return null;
  let dropped = 0;
  const areas = v.areas.slice(0, 4096).map(clip).filter((area): area is string => typeof area === 'string');
  const devices: AutomationDevice[] = [];
  for (const raw of v.devices.slice(0, 4096)) {
    if (!record(raw) || !Array.isArray(raw.entities) || !Array.isArray(raw.mac_addresses)) { dropped += 1; continue; }
    const entities = raw.entities.slice(0, 4096).filter(isEntityLoose).map((e) => clipTextFields(e as Record<string, unknown>, ENTITY_TEXT) as unknown as AutomationEntity).filter(isEntity);
    dropped += raw.entities.length - entities.length;
    const device = clipTextFields({ ...raw, entities, mac_addresses: raw.mac_addresses.slice(0, 32).map(clip) }, DEVICE_TEXT);
    if (isDevice(device)) devices.push(device); else dropped += 1;
  }
  const head = clipTextFields(v as Record<string, unknown>, ['status', 'detail', 'source', 'updated_at']);
  const snapshot = { ...head, areas, devices } as unknown as AutomationSnapshot;
  if (!text(snapshot.status) || !text(snapshot.detail) || !nullable(snapshot.source) || !nullable(snapshot.updated_at)) return null;
  return { snapshot, dropped: dropped + Math.max(0, v.devices.length - 4096) };
}
const isEntityLoose = (e: unknown): boolean => record(e) && typeof e.entity_id === 'string';

const isNetworkRow = (d: unknown): d is NetworkDetails['devices'][number] => record(d) && text(d.device_id)
  && Array.isArray(d.mac_addresses) && d.mac_addresses.length <= 32 && d.mac_addresses.every(text)
  && Array.isArray(d.ip_addresses) && d.ip_addresses.length <= 32 && d.ip_addresses.every(text)
  && (d.mac_assignments === undefined || (Array.isArray(d.mac_assignments) && d.mac_assignments.length <= 32 && d.mac_assignments.every((a) => record(a) && text(a.mac_address) && nullable(a.organization) && nullable(a.registry) && text(a.status))))
  && (d.home_assistant === null || (record(d.home_assistant) && text(d.home_assistant.device_id) && text(d.home_assistant.name)
    && nullable(d.home_assistant.manufacturer) && nullable(d.home_assistant.model) && nullable(d.home_assistant.area)));

export function createAutomationApi(serviceToken: string | AuthSource, fetchImpl?: typeof fetch): AutomationApi {
  const http = createHttp(typeof serviceToken === 'string' ? { serviceToken, fetchImpl } : { auth: serviceToken, fetchImpl });
  async function request(path: string, method = 'GET', body?: unknown): Promise<unknown> {
    const response = await http.send(`/api/v1/automation${path}`, {
      method, headers: http.authHeaders(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(body !== undefined ? { body: JSON.stringify(body) } : {})
    }, { timeoutMs: path === '/commands' ? 25_000 : 10_000 });
    if (!response.ok) {
      const messages: Record<number, string> = {
        400: 'Check the connection address or command. Home Assistant requires HTTPS; HTTP is available only on this computer.',
        401: SIGN_IN_AGAIN,
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
      if (!record(value) || !text(value.status) || !text(value.observed_at) || !Array.isArray(value.devices)) throw new Error('Network address details are unavailable.');
      // Rows that do not validate are skipped; the rest of the inventory still shows.
      const rows = validRows(value.devices.slice(0, 4096), 4096, isNetworkRow);
      return { ...value, devices: rows?.rows ?? [] } as unknown as NetworkDetails;
    },
    async snapshot() { const value = await request(''); const parsed = sanitizeAutomationSnapshot(value); if (!parsed) throw new Error('The automation inventory could not be verified.'); return parsed.snapshot; },
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
