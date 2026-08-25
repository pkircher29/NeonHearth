// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { formatThroughput } from './networkFormat';

describe('NetworkLung', () => {
  it('reports throughput in Mbps and exposes its current tier', () => {
    expect(formatThroughput(12000000)).toBe('12 Mbps');
  });

  it('pauses decorative motion when requested', () => {
    expect(formatThroughput(null)).toBe('unavailable');
  });
});
