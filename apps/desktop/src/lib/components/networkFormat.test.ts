import { describe, expect, it } from 'vitest';
import { formatThroughput } from './networkFormat';

describe('formatThroughput', () => {
  it('converts bytes per second to Mbps', () => {
    expect(formatThroughput(12000000)).toBe('96 Mbps');
  });

  it('reports missing readings as unavailable', () => {
    expect(formatThroughput(null)).toBe('unavailable');
  });
});
