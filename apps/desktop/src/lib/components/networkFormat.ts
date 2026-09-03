// The service reports rates in BYTES per second (see BandwidthSample in
// api/types.ts and HEAT_STOPS in twin/heat.ts). Humans read network speed in
// bits, so every display path converts here and nowhere else.

const BITS_PER_BYTE = 8;

export function bytesToMegabits(bytesPerSecond: number): number {
  return (bytesPerSecond * BITS_PER_BYTE) / 1_000_000;
}

export function formatThroughput(bytesPerSecond: number | null | undefined): string {
  if (bytesPerSecond === null || bytesPerSecond === undefined || !Number.isFinite(bytesPerSecond) || bytesPerSecond < 0) return 'unavailable';
  const megabits = bytesToMegabits(bytesPerSecond);
  if (megabits >= 1000) return `${(megabits / 1000).toFixed(megabits >= 10_000 ? 0 : 1)} Gbps`;
  if (megabits >= 10) return `${Math.round(megabits)} Mbps`;
  if (megabits >= 1) return `${megabits.toFixed(1)} Mbps`;
  const kilobits = megabits * 1000;
  return kilobits >= 1 ? `${Math.round(kilobits)} kbps` : '0 kbps';
}
