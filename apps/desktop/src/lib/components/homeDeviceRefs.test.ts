import { describe, expect, it } from 'vitest';

import type { DeviceSnapshot } from '../api/types';
import { buildDeviceRefs } from './homeViewData';

describe('buildDeviceRefs', () => {
  it('names a device by owner, then Home Assistant, and otherwise leaves it unnamed with vendor, MAC and IP', () => {
    const live = {
      a: { device_id: 'a', owner_name: 'Porch' }, b: { device_id: 'b', owner_name: null }, c: { device_id: 'c', owner_name: null }, d: { device_id: 'd', owner_name: null }
    } as unknown as Record<string, DeviceSnapshot>;
    const network = { devices: [
      { device_id: 'a', mac_addresses: ['AA:AA:AA:00:00:01'], ip_addresses: [], home_assistant: null },
      { device_id: 'b', mac_addresses: ['00:04:4B:82:87:11'], ip_addresses: ['192.168.1.9'], home_assistant: null, mac_assignments: [{ mac_address: '00:04:4B:82:87:11', organization: 'Espressif Inc.', registry: 'MA-L', status: 'assigned' }] },
      { device_id: 'c', mac_addresses: ['11:22:33:44:55:66'], ip_addresses: [], home_assistant: { device_id: 'ha', name: 'Hall lamp', manufacturer: 'IKEA', model: null, area: null } }
    ] };
    const refs = buildDeviceRefs(live, network, [{ device_id: 'ha-only', name: 'Thermostat' }]);
    expect(refs.find((r) => r.device_id === 'a')).toMatchObject({ name: 'Porch', mac: 'AA:AA:AA:00:00:01' });
    expect(refs.find((r) => r.device_id === 'b')).toMatchObject({ name: null, vendor: 'Espressif Inc.', mac: '00:04:4B:82:87:11', ip: '192.168.1.9' });
    expect(refs.find((r) => r.device_id === 'c')).toMatchObject({ name: 'Hall lamp', vendor: 'IKEA' });
    expect(refs.find((r) => r.device_id === 'd')).toMatchObject({ name: null, vendor: null, mac: null });
    expect(refs.at(-1)).toEqual({ device_id: 'ha-only', name: 'Thermostat' });
    expect(buildDeviceRefs(live, null)).toHaveLength(4);
  });
});
