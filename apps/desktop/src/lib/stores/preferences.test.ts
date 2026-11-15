import { describe, expect, it } from 'vitest';

import { MOTION_KEY, applyMotion, motionReduced, readMotion } from './preferences';

function memoryStorage(): Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> & { map: Map<string, string> } {
  const map = new Map<string, string>();
  return { map, getItem: (key) => map.get(key) ?? null, setItem: (key, value) => { map.set(key, value); }, removeItem: (key) => { map.delete(key); } };
}

describe('preferences', () => {
  it('defaults to auto and round-trips reduced', () => {
    const store = memoryStorage();
    expect(readMotion(store)).toBe('auto');
    const root = { dataset: {} as DOMStringMap } as HTMLElement;
    applyMotion('reduced', store, root);
    expect(store.map.get(MOTION_KEY)).toBe('reduced');
    expect(root.dataset.motion).toBe('reduced');
    expect(readMotion(store)).toBe('reduced');
    expect(motionReduced(root)).toBe(true);
    applyMotion('auto', store, root);
    expect(store.map.has(MOTION_KEY)).toBe(false);
    expect(root.dataset.motion).toBeUndefined();
    expect(motionReduced(root)).toBe(false);
  });

  it('survives a throwing storage', () => {
    const broken = { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); }, removeItem: () => { throw new Error('blocked'); } };
    expect(readMotion(broken)).toBe('auto');
    const root = { dataset: {} as DOMStringMap } as HTMLElement;
    expect(() => applyMotion('reduced', broken, root)).not.toThrow();
    expect(root.dataset.motion).toBe('reduced');
  });
});
