// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { formatThroughput } from './networkFormat';

describe('NetworkHearth', () => {
  it('reports throughput in Mbps and formats correctly', () => {
    expect(formatThroughput(12000000)).toBe('12 Mbps');
    expect(formatThroughput(300000)).toBe('0.3 Mbps');
  });

  it('handles unavailable / null throughput without throwing', () => {
    expect(formatThroughput(null)).toBe('unavailable');
  });
});
