import { describe, expect, it } from 'vitest';
import type { DeviceSnapshot } from '../api/types';
import { createLabelMerger } from './labels';

const dev = (id: string, extra: Partial<DeviceSnapshot> = {}) => ({ device_id: id, owner_name: null, owner_confirmed: false, ...extra }) as DeviceSnapshot;

describe('createLabelMerger', () => {
  it('keeps object identity for unchanged devices and for an unchanged map', () => {
    const merge = createLabelMerger();
    const a = dev('a'); const b = dev('b');
    const first = merge({ a, b }, {});
    const again = merge({ a, b }, {});
    expect(again).toBe(first);
    const b2 = dev('b', { owner_name: 'x' });
    const second = merge({ a, b: b2 }, {});
    expect(second).not.toBe(first);
    expect(second.a).toBe(first.a);
  });

  it('applies and re-applies labels only when the label object changes', () => {
    const merge = createLabelMerger();
    const a = dev('a');
    const label = { device_id: 'a', owner_name: 'Printer', owner_confirmed: true };
    const first = merge({ a }, { a: label });
    expect(first.a!.owner_name).toBe('Printer');
    expect(merge({ a }, { a: label }).a).toBe(first.a);
    expect(merge({ a }, { a: { ...label, owner_name: 'Scanner' } }).a!.owner_name).toBe('Scanner');
  });
});
