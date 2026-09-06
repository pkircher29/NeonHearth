export interface DeviceLabel { device_id: string; owner_name: string | null; owner_confirmed: boolean }
export interface DeviceLabelsApi {
  list(): Promise<DeviceLabel[]>;
  confirm(device: DeviceLabel, name: string): Promise<DeviceLabel>;
}
export function validDeviceName(name: string): boolean {
  return name.length > 0 && new TextEncoder().encode(name).length <= 128 && name.trim() === name
    && !/[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u.test(name);
}
const isLabel = (v: unknown): v is DeviceLabel => {
  if (!v || typeof v !== 'object') return false;
  const d = v as DeviceLabel;
  return typeof d.device_id === 'string' && /^[0-9a-f-]{36}$/i.test(d.device_id)
    && (d.owner_name === null || (typeof d.owner_name === 'string' && d.owner_name.length <= 4096)) && typeof d.owner_confirmed === 'boolean';
};
export function createDeviceLabelsApi(auth: {header(): string | null}, fetchImpl: typeof fetch = fetch): DeviceLabelsApi {
  async function request(path: string, body?: unknown): Promise<unknown> {
    const response = await fetchImpl(`/api/v1/devices/${path}`, { method: body ? 'PUT' : 'GET',
      headers: {Authorization: auth.header() ?? '', ...(body ? {'Content-Type':'application/json'} : {})},
      ...(body ? {body: JSON.stringify(body)} : {}), signal: AbortSignal.timeout(10_000), credentials:'omit', redirect:'error' });
    if (!response.ok) throw new Error(response.status === 409 ? 'The name changed in another window. Review the current name and try again.'
      : response.status === 401 ? 'Sign in as the owner to confirm names.' : 'The name could not be saved. Refresh and try again.');
    return response.json();
  }
  return {
    async list() { const value = await request('labels'); if (!Array.isArray(value) || value.length > 4096 || !value.every(isLabel)) throw new Error('Device labels are unavailable.'); return value; },
    async confirm(device, name) {
      name = name.trim();
      if (!isLabel(device) || !validDeviceName(name)) throw new Error('Use a name of 1 to 128 bytes without invisible formatting characters.');
      const value = await request(`${device.device_id}/name`, {name,expected_name:device.owner_name,expected_confirmed:device.owner_confirmed});
      if (!isLabel(value) || value.device_id !== device.device_id || value.owner_name !== name || !value.owner_confirmed) throw new Error('The saved name could not be verified.');
      return value;
    },
  };
}
