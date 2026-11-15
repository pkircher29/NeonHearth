// Labels, sorting and filtering for the device tray (home tools v2).
import type { HomeDeviceRef } from '../stores/home';

const LEGAL_WORDS = /\b(inc|incorporated|ltd|limited|llc|corp|corporation|co|company|gmbh|ag|sa|plc|technologies|technology|electronics|international)\b\.?,?/gi;

/** A short vendor name: legal suffixes dropped, at most two words ("Espressif Inc." -> "Espressif"). */
export function shortVendor(organization: string | null | undefined): string | null {
  if (!organization) return null;
  const words = organization.replace(LEGAL_WORDS, ' ').replace(/[,.]/g, ' ').split(/\s+/).filter(Boolean);
  const short = words.slice(0, 2).join(' ');
  return short || organization.trim() || null;
}

/** The last three octets of a MAC ("00:04:4B:82:87:11" -> "82:87:11"). */
export function macTail(mac: string | null | undefined): string | null {
  if (!mac) return null;
  const octets = mac.split(/[:-]/).filter(Boolean);
  return octets.length >= 3 ? octets.slice(-3).join(':') : mac;
}

/** The owner's name always wins; otherwise "Vendor · tail", then the MAC, then a short id. */
export function deviceLabel(device: Pick<HomeDeviceRef, 'device_id' | 'name' | 'vendor' | 'mac'>, fallback?: string): string {
  if (device.name) return device.name;
  const vendor = shortVendor(device.vendor);
  const tail = macTail(device.mac);
  if (vendor && tail) return `${vendor} · ${tail}`;
  if (vendor) return vendor;
  if (device.mac) return device.mac;
  return fallback ?? `Device ${device.device_id.slice(0, 8)}`;
}

/** Named devices first (A-Z), then unnamed by vendor (vendorless last), then MAC. */
export function sortDevices(devices: readonly HomeDeviceRef[]): HomeDeviceRef[] {
  const text = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });
  const rank = (device: HomeDeviceRef) => (device.name ? 0 : shortVendor(device.vendor) ? 1 : 2);
  return [...devices].sort((a, b) => {
    const byRank = rank(a) - rank(b);
    if (byRank) return byRank;
    if (a.name && b.name) return text.compare(a.name, b.name) || text.compare(a.device_id, b.device_id);
    return text.compare(shortVendor(a.vendor) ?? '', shortVendor(b.vendor) ?? '') || text.compare(a.mac ?? '', b.mac ?? '') || text.compare(a.device_id, b.device_id);
  });
}

/** Case-insensitive match on name, vendor, MAC (with or without separators) and IP. */
export function filterDevices(devices: readonly HomeDeviceRef[], query: string): HomeDeviceRef[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...devices];
  const bare = needle.replace(/[:.-]/g, '');
  return devices.filter((device) => {
    const hay = [device.name, device.vendor, shortVendor(device.vendor), device.mac, device.ip, deviceLabel(device)].filter(Boolean).join('\n').toLowerCase();
    if (hay.includes(needle)) return true;
    return bare.length >= 2 && (device.mac ?? '').toLowerCase().replace(/[:-]/g, '').includes(bare);
  });
}
