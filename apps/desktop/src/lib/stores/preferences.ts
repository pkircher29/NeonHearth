// Viewer preferences that live only in this browser (localStorage). Nothing
// here is secret or shared; the collector never sees it.

export type MotionPreference = 'auto' | 'reduced';
export const MOTION_KEY = 'neonhearth.motion';

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function storage(): StorageLike | null {
  try { return typeof window !== 'undefined' ? window.localStorage : null; } catch { return null; }
}

export function readMotion(store: StorageLike | null = storage()): MotionPreference {
  try { return store?.getItem(MOTION_KEY) === 'reduced' ? 'reduced' : 'auto'; } catch { return 'auto'; }
}

/** Persists and applies the choice: a `data-motion` stamp on the root element
 * lets CSS and canvas code treat it exactly like prefers-reduced-motion. */
export function applyMotion(preference: MotionPreference, store: StorageLike | null = storage(), root: HTMLElement | null = typeof document !== 'undefined' ? document.documentElement : null): void {
  try { if (preference === 'reduced') store?.setItem(MOTION_KEY, 'reduced'); else store?.removeItem(MOTION_KEY); } catch { /* storage unavailable: apply for this session only */ }
  if (root) { if (preference === 'reduced') root.dataset.motion = 'reduced'; else delete root.dataset.motion; }
  try { if (typeof window !== 'undefined') window.dispatchEvent(new Event('neonhearth:motion')); } catch { /* no window */ }
}

/** True when either the OS or this app's own setting asks for less motion. */
export function motionReduced(root: HTMLElement | null = typeof document !== 'undefined' ? document.documentElement : null): boolean {
  const osReduced = typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  return osReduced || root?.dataset.motion === 'reduced';
}
