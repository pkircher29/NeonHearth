import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createPoller } from './polling';

function fakeDoc(hidden = false) {
  const listeners = new Set<() => void>();
  return {
    hidden,
    addEventListener: (_: string, l: () => void) => listeners.add(l),
    removeEventListener: (_: string, l: () => void) => listeners.delete(l),
    set(value: boolean) { this.hidden = value; listeners.forEach((l) => l()); },
    count: () => listeners.size
  };
}

describe('createPoller', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('runs serially on the interval', async () => {
    const task = vi.fn(async () => {});
    const poller = createPoller(task, 1000, fakeDoc() as never);
    await vi.advanceTimersByTimeAsync(0);
    expect(task).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(2500);
    expect(task).toHaveBeenCalledTimes(3);
    poller.stop();
  });

  it('makes no requests while the tab is hidden and resumes immediately when visible', async () => {
    const doc = fakeDoc();
    const task = vi.fn(async () => {});
    const poller = createPoller(task, 1000, doc as never);
    await vi.advanceTimersByTimeAsync(0);
    doc.set(true);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(task).toHaveBeenCalledTimes(1);
    doc.set(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(task).toHaveBeenCalledTimes(2);
    poller.stop();
    expect(doc.count()).toBe(0);
  });

  it('does not start while hidden, survives a throwing task, and stop cancels the timer', async () => {
    const hiddenDoc = fakeDoc(true);
    const task = vi.fn(async () => { throw new Error('boom'); });
    const poller = createPoller(task, 500, hiddenDoc as never);
    await vi.advanceTimersByTimeAsync(5000);
    expect(task).not.toHaveBeenCalled();
    hiddenDoc.set(false);
    await vi.advanceTimersByTimeAsync(1200);
    expect(task.mock.calls.length).toBeGreaterThanOrEqual(2);
    poller.stop();
    const before = task.mock.calls.length;
    await vi.advanceTimersByTimeAsync(5000);
    expect(task.mock.calls.length).toBe(before);
  });

  it('kick runs once now and coalesces while a run is in flight', async () => {
    let release!: () => void;
    const task = vi.fn(() => new Promise<void>((resolve) => { release = resolve; }));
    const poller = createPoller(task, 10_000, fakeDoc() as never);
    await vi.advanceTimersByTimeAsync(0);
    poller.kick(); poller.kick();
    expect(task).toHaveBeenCalledTimes(1);
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(task).toHaveBeenCalledTimes(2);
    release();
    poller.stop();
  });
});
