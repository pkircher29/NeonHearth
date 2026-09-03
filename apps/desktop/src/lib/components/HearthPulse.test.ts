// @vitest-environment jsdom
import { cleanup, fireEvent, render } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { DeviceSnapshot } from '../api/types';
import HearthPulse from './HearthPulse.svelte';

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

function stubContext() {
  const gradient = { addColorStop: vi.fn() };
  const ctx = {
    clearRect: vi.fn(), beginPath: vi.fn(), arc: vi.fn(), stroke: vi.fn(), fill: vi.fn(), fillRect: vi.fn(), fillText: vi.fn(),
    moveTo: vi.fn(), lineTo: vi.fn(), setLineDash: vi.fn(), setTransform: vi.fn(),
    createRadialGradient: vi.fn(() => gradient),
    lineWidth: 0, lineCap: 'butt', strokeStyle: '', fillStyle: '', font: '', textAlign: '', textBaseline: ''
  };
  return ctx;
}

describe('HearthPulse', () => {
  let ctx: ReturnType<typeof stubContext>;
  let rafCallbacks: FrameRequestCallback[];

  beforeEach(() => {
    ctx = stubContext();
    rafCallbacks = [];
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(() => ctx as unknown as CanvasRenderingContext2D);
    vi.stubGlobal('requestAnimationFrame', (callback: FrameRequestCallback) => { rafCallbacks.push(callback); return rafCallbacks.length; });
    vi.stubGlobal('cancelAnimationFrame', vi.fn());
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
  });
  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it('describes the live network for assistive technology and draws a frame', () => {
    const { getByRole } = render(HearthPulse, { devices: [device('a'), device('b', { presence: { state: 'blocked', observed_at: null, source: null, kind: null } })], upload: 125_000, download: 1_250_000, connected: true });
    const label = getByRole('img').getAttribute('aria-label') ?? '';
    expect(label).toContain('11 Mbps total');
    expect(label).toContain('1 of 2 devices online');
    expect(label).toContain('1 blocked');
    expect(rafCallbacks.length).toBe(1);
    rafCallbacks[0]!(16);
    expect(ctx.clearRect).toHaveBeenCalled();
    expect(ctx.arc).toHaveBeenCalled();
  });

  it('draws once and schedules no frames when paused', () => {
    render(HearthPulse, { devices: [device('a')], upload: 1, download: 1, connected: true, paused: true });
    expect(rafCallbacks.length).toBe(0);
    expect(ctx.clearRect).toHaveBeenCalledTimes(1);
  });

  it('draws once when the viewer prefers reduced motion', () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })));
    render(HearthPulse, { devices: [device('a')], upload: 1, download: 1, connected: true });
    expect(rafCallbacks.length).toBe(0);
    expect(ctx.clearRect).toHaveBeenCalled();
  });

  it('falls back to an unavailable description before pairing', () => {
    const { getByRole, getByText } = render(HearthPulse, { devices: [], connected: false });
    expect(getByRole('img').getAttribute('aria-label')).toMatch(/unavailable until the collector is paired/);
    expect(getByText('unavailable')).toBeTruthy();
  });

  it('offers a keyboard path to every device when selection is wired', async () => {
    const onselect = vi.fn();
    const { getByRole } = render(HearthPulse, { devices: [device('abcdef-1', { owner_name: 'Kitchen speaker' })], upload: 1, download: 1, connected: true, onselect });
    const button = getByRole('button', { name: /Kitchen speaker/ });
    await fireEvent.click(button);
    expect(onselect).toHaveBeenCalledWith('abcdef-1');
  });
});
