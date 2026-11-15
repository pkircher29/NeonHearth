/** Numeric keys for observed IP addresses. Missing or malformed values sort last. */
export function ipSortKey(value: string): number[] | null {
  const ipv4 = (text: string): number[] | null => {
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) return null;
    const bytes = text.split('.').map(Number);
    return bytes.every(byte => byte <= 255) ? bytes : null;
  };
  const v4 = ipv4(value);
  if (v4) return [4, ...v4];
  let address = value.split('%')[0] ?? '';
  if (!address.includes(':')) return null;
  if (address.includes('.')) {
    const colon = address.lastIndexOf(':');
    const tail = ipv4(address.slice(colon + 1));
    if (!tail) return null;
    address = `${address.slice(0, colon)}:${((tail[0]! << 8) | tail[1]!).toString(16)}:${((tail[2]! << 8) | tail[3]!).toString(16)}`;
  }
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  if (![...left, ...right].every(group => /^[0-9a-f]{1,4}$/i.test(group))) return null;
  const omitted = 8 - left.length - right.length;
  if (halves.length === 1 ? omitted !== 0 : omitted < 1) return null;
  return [6, ...left.map(group => parseInt(group, 16)), ...Array<number>(omitted).fill(0), ...right.map(group => parseInt(group, 16))];
}

export function compareIpKeys(left: number[] | null, right: number[] | null, descending = false): number {
  if (!left || !right) return left ? -1 : right ? 1 : 0;
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    const difference = (left[i] ?? 0) - (right[i] ?? 0);
    if (difference) return descending ? -difference : difference;
  }
  return 0;
}

/** A device with several addresses uses its lowest IPv4, or otherwise IPv6, address. */
export function deviceIpSortKey(addresses: readonly string[]): number[] | null {
  let lowest: number[] | null = null;
  for (const address of addresses) {
    const key = ipSortKey(address);
    if (key && (!lowest || compareIpKeys(key, lowest) < 0)) lowest = key;
  }
  return lowest;
}
