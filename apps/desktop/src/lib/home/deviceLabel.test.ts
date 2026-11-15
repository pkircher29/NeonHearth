import { describe, expect, it } from 'vitest';

import type { HomeDeviceRef } from '../stores/home';
import { deviceLabel, filterDevices, macTail, shortVendor, sortDevices } from './deviceLabel';
import { eightyNine } from './deviceFixtures';

describe('labels', () => {
  it('shortens vendors and takes the last three MAC octets', () => {
    expect(shortVendor('Espressif Inc.')).toBe('Espressif');
    expect(shortVendor('Apple, Inc.')).toBe('Apple');
    expect(shortVendor('Intel Corporate')).toBe('Intel Corporate');
    expect(shortVendor('Hon Hai Precision Industry Co., Ltd.')).toBe('Hon Hai');
    expect(shortVendor(null)).toBeNull();
    expect(macTail('00:04:4B:82:87:11')).toBe('82:87:11');
    expect(macTail('00-04-4b-82-87-11')).toBe('82:87:11');
    expect(macTail('ab:cd')).toBe('ab:cd');
    expect(macTail(null)).toBeNull();
  });
  it('owner names always win, then "Vendor · tail", vendor, MAC, and a short id', () => {
    const base = { device_id: 'abcdef12-0000-4000-8000-000000000000', name: null };
    expect(deviceLabel({ ...base, name: 'Porch node', vendor: 'Espressif Inc.', mac: '00:04:4B:82:87:11' })).toBe('Porch node');
    expect(deviceLabel({ ...base, vendor: 'Espressif Inc.', mac: '00:04:4B:82:87:11' })).toBe('Espressif · 82:87:11');
    expect(deviceLabel({ ...base, vendor: 'Espressif Inc.' })).toBe('Espressif');
    expect(deviceLabel({ ...base, mac: '00:04:4B:82:87:11' })).toBe('00:04:4B:82:87:11');
    expect(deviceLabel(base)).toBe('Device abcdef12');
    expect(deviceLabel(base, 'Unnamed device')).toBe('Unnamed device');
  });
});

describe('sorting', () => {
  it('puts named devices first (A-Z), then unnamed by vendor, vendorless last, then MAC', () => {
    const list: HomeDeviceRef[] = [
      { device_id: '1', name: null, vendor: null, mac: '00:00:00:00:00:01' },
      { device_id: '2', name: null, vendor: 'Tuya Smart Inc.', mac: '00:00:00:00:00:09' },
      { device_id: '3', name: 'Zed lamp' },
      { device_id: '4', name: null, vendor: 'Apple, Inc.', mac: '00:00:00:00:00:05' },
      { device_id: '5', name: 'Attic fan' },
      { device_id: '6', name: null, vendor: 'Apple, Inc.', mac: '00:00:00:00:00:02' }
    ];
    expect(sortDevices(list).map((d) => d.device_id)).toEqual(['5', '3', '6', '4', '2', '1']);
  });
  it('sorts 89 unnamed devices deterministically without mutating the input', () => {
    const input = eightyNine();
    const copy = [...input];
    const sorted = sortDevices(input);
    expect(input).toEqual(copy);
    expect(sorted).toHaveLength(89);
    const labels = sorted.map((d) => shortVendor(d.vendor));
    const firstVendorless = labels.indexOf(null);
    expect(labels.slice(0, firstVendorless).every((v) => v !== null)).toBe(true);
    expect(labels.slice(firstVendorless).every((v) => v === null)).toBe(true);
    const vendors = labels.slice(0, firstVendorless) as string[];
    expect(vendors).toEqual([...vendors].sort((a, b) => a.localeCompare(b)));
    expect(sortDevices(sorted).map((d) => d.device_id)).toEqual(sorted.map((d) => d.device_id));
  });
});

describe('filtering', () => {
  const devices = eightyNine();
  it('matches name, vendor, MAC (any separator), IP and the displayed label, case-insensitively', () => {
    const named = [...devices, { device_id: 'n', name: 'Hall Sensor', vendor: null, mac: null }];
    expect(filterDevices(named, 'hall').map((d) => d.device_id)).toEqual(['n']);
    expect(filterDevices(devices, 'espressif').length).toBe(devices.filter((d) => d.vendor === 'Espressif Inc.').length);
    expect(filterDevices(devices, '192.168.1.105').map((d) => d.ip)).toEqual(['192.168.1.105']);
    const one = devices[10];
    expect(filterDevices(devices, one.mac!.toLowerCase()).map((d) => d.device_id)).toContain(one.device_id);
    expect(filterDevices(devices, one.mac!.replace(/:/g, '')).map((d) => d.device_id)).toContain(one.device_id);
    expect(filterDevices(devices, 'ESPRESSIF · ').length).toBeGreaterThan(0);
  });
  it('returns everything for an empty or blank query and nothing for a miss', () => {
    expect(filterDevices(devices, '')).toHaveLength(89);
    expect(filterDevices(devices, '   ')).toHaveLength(89);
    expect(filterDevices(devices, 'no such device')).toEqual([]);
  });
});
