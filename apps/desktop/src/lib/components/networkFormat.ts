export function formatThroughput(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return 'unavailable';
  const mbps = value / 1_000_000;
  return `${mbps < 10 ? mbps.toFixed(1) : Math.round(mbps)} Mbps`;
}
