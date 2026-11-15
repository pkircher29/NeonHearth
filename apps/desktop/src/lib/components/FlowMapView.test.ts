// @vitest-environment jsdom
import { cleanup, fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DeviceSnapshot } from '../api/types';
import FlowMap from './FlowMap.svelte';

function device(id: string, overrides: Partial<DeviceSnapshot> = {}): DeviceSnapshot {
  return {
    device_id: id,
    first_seen_at: '2026-08-23T00:00:00Z',
    last_seen_at: '2026-08-23T00:00:00Z',
    owner_name: null,
    owner_type: null,
    owner_confirmed: false,
    presence: { state: 'online', observed_at: null, source: null, kind: null },
    evidence: null,
    identity: { available: false, classification: null, confidence: null },
    bandwidth: { available: true, upload: 125_000, download: 1_250_000, coverage: 'complete', observed_at: null },
    policy: null,
    ...overrides
  };
}

// A context that accepts any canvas call and records them so tests can assert on drawing.
function stubContext() {
  const gradient = { addColorStop: vi.fn() };
  const store: Record<string, unknown> = { lineWidth: 0, strokeStyle: '', fillStyle: '', font: '', textAlign: '', globalAlpha: 1 };
  const fns: Record<string, ReturnType<typeof vi.fn>> = {};
  const ctx = new Proxy(store, {
    get(target, prop: string) {
      if (prop in target) return target[prop];
      if (prop === 'createRadialGradient' || prop === 'createLinearGradient') return (fns[prop] ??= vi.fn(() => gradient));
      if (prop === 'measureText') return (fns[prop] ??= vi.fn((text: string) => ({ width: String(text).length * 6 })));
      return (fns[prop] ??= vi.fn());
    },
    set(target, prop: string, value) { target[prop] = value; return true; }
  });
  return { ctx, fns };
}

describe('FlowMap', () => {
  let stub: ReturnType<typeof stubContext>;
  let rafCallbacks: FrameRequestCallback[];

  beforeEach(() => {
    stub = stubContext();
    rafCallbacks = [];
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(() => stub.ctx as unknown as CanvasRenderingContext2D);
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { rafCallbacks.push(callback); return rafCallbacks.length; });
    vi.stubGlobal('cancelAnimationFrame', vi.fn());
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    document.documentElement.removeAttribute('data-motion');
  });
  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); document.documentElement.removeAttribute('data-motion'); });

  it('describes the live network for assistive technology and draws animated frames', () => {
    const { getByRole } = render(FlowMap, { devices: [device('a', { owner_name: 'Studio Mac' }), device('b', { presence: { state: 'blocked', observed_at: null, source: null, kind: null } })], upload: 125_000, download: 1_250_000, connected: true });
    const label = getByRole('img').getAttribute('aria-label') ?? '';
    expect(label).toContain('Network flow map: 11 Mbps total');
    expect(label).toContain('1 of 2 devices online');
    expect(label).toContain('1 blocked');
    expect(label).toContain('Top talkers: Studio Mac');
    expect(rafCallbacks.length).toBe(1);
    rafCallbacks[0]!(16);
    rafCallbacks[1]?.(32);
    expect(stub.fns.clearRect).toHaveBeenCalled();
    expect(stub.fns.arc).toHaveBeenCalled();
    expect(stub.fns.fillText).toHaveBeenCalled();
    expect(stub.fns.quadraticCurveTo).toHaveBeenCalled();
  });

  it('draws one static, fully informative frame when paused', () => {
    render(FlowMap, { devices: [device('a')], upload: 125_000, download: 1_250_000, connected: true, paused: true });
    expect(rafCallbacks.length).toBe(0);
    expect(stub.fns.clearRect).toHaveBeenCalled();
    expect(stub.fns.closePath).toHaveBeenCalled(); // direction arrowheads are closed triangles
    const texts = stub.fns.fillText!.mock.calls.map((call) => String(call[0]));
    expect(texts).toContain('11 Mbps');
  });

  it('draws once when the viewer prefers reduced motion (OS setting)', () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    render(FlowMap, { devices: [device('a')], upload: 1, download: 1, connected: true });
    expect(rafCallbacks.length).toBe(0);
    expect(stub.fns.clearRect).toHaveBeenCalled();
  });

  it('draws once when the in-app motion switch asks for reduced motion', () => {
    document.documentElement.dataset.motion = 'reduced';
    render(FlowMap, { devices: [device('a')], upload: 1, download: 1, connected: true });
    expect(rafCallbacks.length).toBe(0);
    expect(stub.fns.clearRect).toHaveBeenCalled();
  });

  it('says plainly when the collector is unavailable', () => {
    const { getByRole, getByText } = render(FlowMap, { devices: [], connected: false, paused: true });
    expect(getByRole('img').getAttribute('aria-label')).toBe('Network flow map: collector connection unavailable; reconnect or sign in if requested.');
    expect(getByText('Collector offline')).toBeTruthy();
    expect(stub.fns.clearRect).toHaveBeenCalled();
  });

  it('shows a calm empty state with no devices', () => {
    const { getByText } = render(FlowMap, { devices: [], upload: 0, download: 0, connected: true, paused: true });
    expect(getByText('No devices yet')).toBeTruthy();
  });

  it('labels missing counters instead of drawing fake zeros', () => {
    const { getByText, getByRole } = render(FlowMap, { devices: [device('a', { bandwidth: { available: false, upload: null, download: null, coverage: null, observed_at: null } })], upload: null, download: null, connected: true, paused: true });
    expect(getByText('No per-device counters')).toBeTruthy();
    expect(getByRole('img').getAttribute('aria-label')).toContain('Per-device counters unavailable.');
    const texts = stub.fns.fillText!.mock.calls.map((call) => String(call[0]));
    expect(texts).not.toContain('0 kbps');
  });

  it('offers a keyboard path to every device and shows its tooltip on focus', async () => {
    const onselect = vi.fn();
    const { getByRole, findByRole } = render(FlowMap, { devices: [device('abcdef-1', { owner_name: 'Kitchen speaker', owner_type: 'speaker' })], upload: 1, download: 1, connected: true, paused: true, onselect });
    const button = getByRole('button', { name: /Kitchen speaker, Media, online/ });
    await fireEvent.focus(button);
    const tip = await findByRole('tooltip');
    expect(tip.textContent).toContain('Kitchen speaker');
    expect(tip.textContent).toContain('Media');
    await fireEvent.click(button);
    expect(onselect).toHaveBeenCalledWith('abcdef-1');
  });

  it('does not offer buttons when selection is not wired', () => {
    const { queryByRole } = render(FlowMap, { devices: [device('a')], upload: 1, download: 1, connected: true, paused: true });
    expect(queryByRole('button')).toBeNull();
  });

  it('cancels its frame loop on unmount', () => {
    const { unmount } = render(FlowMap, { devices: [device('a')], upload: 1, download: 1, connected: true });
    rafCallbacks[0]!(16);
    unmount();
    expect(globalThis.cancelAnimationFrame).toHaveBeenCalled();
  });
});
