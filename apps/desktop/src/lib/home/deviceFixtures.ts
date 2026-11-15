import type { HomeDeviceRef } from '../stores/home';

const VENDORS = ['Espressif Inc.', 'Apple, Inc.', 'Tuya Smart Inc.', 'Intel Corporate', null];

/** Test fixture: a real home with 89 devices, none named. */
export function eightyNine(): HomeDeviceRef[] {
  return Array.from({ length: 89 }, (_, i) => ({
    device_id: `00000000-0000-4000-8000-${i.toString(16).padStart(12, '0')}`,
    name: null,
    vendor: VENDORS[i % VENDORS.length],
    mac: `00:04:4B:${((i * 7) % 256).toString(16).padStart(2, '0')}:${((i * 13) % 256).toString(16).padStart(2, '0')}:${((i * 29) % 256).toString(16).padStart(2, '0')}`.toUpperCase(),
    ip: `192.168.1.${100 + i}`
  }));
}
