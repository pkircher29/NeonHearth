import { describe, expect, it } from 'vitest';

import { collectorStateFor } from './CollectorStatus.svelte';

describe('collectorStateFor', () => {
  it('follows the live connection rather than a one-shot health probe', () => {
    expect(collectorStateFor({ connected: false, serviceStatus: 'unknown', sequence: 0 })).toBe('connecting');
    expect(collectorStateFor({ connected: true, serviceStatus: 'ready', sequence: 4 })).toBe('ready');
    // A snapshot arrived once, then the socket dropped: the collector is known and unreachable.
    expect(collectorStateFor({ connected: false, serviceStatus: 'ready', sequence: 4 })).toBe('offline');
    expect(collectorStateFor({ connected: false, serviceStatus: 'unknown', sequence: 4 })).toBe('offline');
  });
});
