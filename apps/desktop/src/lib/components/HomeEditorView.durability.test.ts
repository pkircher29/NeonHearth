// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { HomeApi, HomePlan } from '../stores/home';
import HomeEditorView from './HomeEditorView.svelte';

const homeId = '018f47a0-9b5c-7a22-8a33-aabbccdd0001';
const groundId = '018f47a0-9b5c-7a22-8a33-aabbccdd0010';
const wallId = '018f47a0-9b5c-7a22-8a33-aabbccdd0020';

function fixturePlan(): HomePlan {
  return {
    home_id: homeId, version: 3, name: 'Home',
    floors: [{ floor_id: groundId, level: 0, name: 'Ground', ceiling_height_m: 2.4, walls: [{ wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4.2, y: 0 }, openings: [] }], rooms: [] }]
  };
}
function apiStub(overrides: Partial<HomeApi> = {}): HomeApi {
  return {
    fetchHome: vi.fn(async () => ({ plan: fixturePlan(), placements: [], estimates: [] })),
    savePlan: vi.fn(async () => ({ status: 'saved' as const, version: 4 })),
    saveDraft: vi.fn(async () => undefined),
    loadDraft: vi.fn(async () => ({ status: 'none' as const })),
    deleteDraft: vi.fn(async () => undefined),
    putPlacement: vi.fn(async () => undefined),
    deletePlacement: vi.fn(async () => undefined),
    ...overrides
  };
}

const store = new Map<string, string>();
beforeEach(() => {
  store.clear();
  vi.stubGlobal('localStorage', { getItem: (key: string) => store.get(key) ?? null, setItem: (key: string, value: string) => store.set(key, value), removeItem: (key: string) => store.delete(key) });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

/** Select the wall and delete it from the canvas: a plan edit that marks the draft dirty. */
async function dirtyTheDraft() {
  await screen.findByRole('application');
  await fireEvent.click(screen.getByRole('button', { name: /^Wall, / }));
  await fireEvent.keyDown(screen.getByRole('application'), { key: 'Delete' });
}

describe('HomeEditorView durability', () => {
  it('flushes the draft when the view is torn down with unsaved edits inside the autosave window', async () => {
    const api = apiStub();
    const view = render(HomeEditorView, { api, devices: [] });
    await dirtyTheDraft();
    expect(api.saveDraft).not.toHaveBeenCalled(); // still inside the 2 s debounce
    view.unmount();
    expect(api.saveDraft).toHaveBeenCalledTimes(1);
    const saved = (api.saveDraft as ReturnType<typeof vi.fn>).mock.calls[0]![0] as { plan: HomePlan };
    expect(saved.plan.floors[0]!.walls).toHaveLength(0);
  });

  it('does not write a draft on teardown when nothing changed', async () => {
    const api = apiStub();
    const view = render(HomeEditorView, { api, devices: [] });
    await screen.findByRole('application');
    view.unmount();
    expect(api.saveDraft).not.toHaveBeenCalled();
  });

  it('asks before the tab closes while edits are unsaved, and not otherwise', async () => {
    const api = apiStub();
    render(HomeEditorView, { api, devices: [] });
    await screen.findByRole('application');
    const clean = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(clean);
    expect(clean.defaultPrevented).toBe(false);
    await dirtyTheDraft();
    const dirty = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(dirty);
    expect(dirty.defaultPrevented).toBe(true);
    expect(api.saveDraft).toHaveBeenCalled(); // and it still tries to leave a draft behind
  });
});

describe('HomeEditorView keyboard gating', () => {
  it('ignores shortcuts and undo while inactive, and handles them when active', async () => {
    const view = render(HomeEditorView, { api: apiStub(), devices: [], active: false });
    await screen.findByRole('application');
    await fireEvent.keyDown(document.body, { key: 'w' });
    expect(screen.getByRole('button', { name: 'Wall' }).getAttribute('aria-pressed')).toBe('false');
    await view.rerender({ active: true });
    await fireEvent.keyDown(document.body, { key: 'w' });
    expect(screen.getByRole('button', { name: 'Wall' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('single-letter shortcuts can be switched off (WCAG 2.1.4) while Escape and Ctrl+Z still work', async () => {
    store.set('neonhearth.home.letterShortcuts', 'off');
    render(HomeEditorView, { api: apiStub(), devices: [] });
    await screen.findByRole('application');
    await fireEvent.keyDown(document.body, { key: 'w' });
    expect(screen.getByRole('button', { name: 'Wall' }).getAttribute('aria-pressed')).toBe('false');
    await fireEvent.click(screen.getByRole('button', { name: 'Wall' })); // tools still work with the mouse
    expect(screen.getByRole('button', { name: 'Wall' }).getAttribute('aria-pressed')).toBe('true');
    await fireEvent.keyDown(document.body, { key: 'Escape' });
  });
});

describe('HomeEditorView limits', () => {
  it('says so, and does not discard, a draft that only exceeds the size limits', async () => {
    const api = apiStub({ loadDraft: vi.fn(async () => ({ status: 'draft' as const, draft: { plan: fixturePlan(), saved_at: '2026-08-23T00:00:00Z' }, overLimits: true })) });
    render(HomeEditorView, { api, devices: [] });
    expect(await screen.findByText(/over the plan size limits/)).toBeTruthy();
    expect(api.deleteDraft).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Resume draft' })).toBeTruthy();
  });

  it('reports the real reason when the plan cannot be stored', async () => {
    const { PlanLimitError } = await import('../stores/home');
    const api = apiStub({ savePlan: vi.fn(async () => { throw new PlanLimitError('This plan is over the size limits (Ground: 2053 walls, max 2048). Remove some before saving.'); }) });
    render(HomeEditorView, { api, devices: [] });
    await screen.findByRole('application');
    await fireEvent.click(screen.getByRole('button', { name: 'Save plan' }));
    expect(await screen.findByText(/2053 walls, max 2048/)).toBeTruthy();
  });
});

describe('HomeEditorView plan keyboard navigation', () => {
  it('gives the plan one tab stop and moves between items with the arrow keys', async () => {
    const api = apiStub({ fetchHome: vi.fn(async () => ({ plan: { ...fixturePlan(), floors: [{ ...fixturePlan().floors[0]!, walls: [{ wall_id: wallId, start: { x: 0, y: 0 }, end: { x: 4, y: 0 }, openings: [] }, { wall_id: '018f47a0-9b5c-7a22-8a33-aabbccdd0021', start: { x: 0, y: 1 }, end: { x: 4, y: 1 }, openings: [] }] }] }, placements: [], estimates: [] })) });
    render(HomeEditorView, { api, devices: [] });
    await screen.findByRole('application');
    const walls = screen.getAllByRole('button', { name: /^Wall, / });
    expect(walls.map((wall) => wall.getAttribute('tabindex'))).toEqual(['0', '-1']);
    walls[0]!.focus();
    await fireEvent.keyDown(walls[0]!, { key: 'ArrowRight' });
    await Promise.resolve();
    expect(document.activeElement).toBe(walls[1]);
    expect(walls.map((wall) => wall.getAttribute('tabindex'))).toEqual(['-1', '0']);
  });

  it('arrows still nudge the selected wall instead of moving focus', async () => {
    const api = apiStub();
    render(HomeEditorView, { api, devices: [] });
    await screen.findByRole('application');
    const wall = screen.getByRole('button', { name: /^Wall, / });
    await fireEvent.click(wall);
    wall.focus();
    await fireEvent.keyDown(wall, { key: 'ArrowDown' });
    expect(screen.getByRole('button', { name: 'Undo' }).hasAttribute('disabled')).toBe(false);
  });
});
