// One serial, visibility-aware poll loop. A hidden tab neither fetches nor
// keeps a timer ticking; becoming visible runs the task once immediately.

export interface Poller { stop(): void; kick(): void }
type DocumentLike = Pick<Document, 'hidden' | 'addEventListener' | 'removeEventListener'>;

export function createPoller(task: () => Promise<void> | void, intervalMs: number, doc: DocumentLike | null = typeof document === 'undefined' ? null : document): Poller {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running = false;
  let stopped = false;
  let rerun = false;
  const hidden = () => doc?.hidden === true;
  const schedule = () => { if (!stopped && !hidden()) { clearTimeout(timer); timer = setTimeout(() => void run(), intervalMs); } };
  async function run(): Promise<void> {
    if (stopped) return;
    if (hidden()) return; // resumed by visibilitychange
    if (running) { rerun = true; return; }
    running = true;
    clearTimeout(timer);
    try { await task(); } catch { /* a failing task must not stop the loop */ }
    running = false;
    if (stopped) return;
    if (rerun) { rerun = false; void run(); return; }
    schedule();
  }
  const onVisibility = () => { if (!hidden()) void run(); else clearTimeout(timer); };
  doc?.addEventListener('visibilitychange', onVisibility);
  void run();
  return {
    stop() { stopped = true; clearTimeout(timer); doc?.removeEventListener('visibilitychange', onVisibility); },
    kick() { void run(); }
  };
}
