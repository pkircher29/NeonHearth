// Small keyboard-accessibility helpers shared by dialogs and tab lists.

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Modal behaviour for a dialog element: focus moves inside on open (first `[data-autofocus]` or first focusable),
 * Tab and Shift+Tab wrap inside it, Escape calls `onescape`, and focus returns to what had it before on destroy.
 */
export function modal(node: HTMLElement, options: { onescape?: () => void } = {}) {
  const previous = typeof document !== 'undefined' ? (document.activeElement as HTMLElement | null) : null;
  const items = () => [...node.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((item) => item.getAttribute('aria-hidden') !== 'true');
  queueMicrotask(() => (node.querySelector<HTMLElement>('[data-autofocus]') ?? items()[0] ?? node).focus());
  const onKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') { event.stopPropagation(); options.onescape?.(); return; }
    if (event.key !== 'Tab') return;
    const list = items();
    if (list.length === 0) { event.preventDefault(); return; }
    const first = list[0]!; const last = list[list.length - 1]!;
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !node.contains(active))) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (active === last || !node.contains(active))) { event.preventDefault(); first.focus(); }
  };
  node.addEventListener('keydown', onKeydown);
  return {
    update(next: { onescape?: () => void }) { options = next; },
    destroy() { node.removeEventListener('keydown', onKeydown); if (previous && document.contains(previous)) previous.focus(); }
  };
}

/**
 * Arrow-key navigation for `role="tablist"`: Left/Right (and Up/Down), Home and End move to and activate the
 * neighbouring tab, wrapping at the ends. Pair with tabindex 0 on the selected tab and -1 on the others.
 */
export function onTablistKeydown(event: KeyboardEvent): void {
  const keys = ['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'];
  if (!keys.includes(event.key) || event.ctrlKey || event.metaKey || event.altKey) return;
  const list = event.currentTarget as HTMLElement;
  const tabs = [...list.querySelectorAll<HTMLElement>('[role="tab"]')];
  if (tabs.length === 0) return;
  const current = tabs.findIndex((tab) => tab === document.activeElement || tab.contains(document.activeElement));
  const from = current < 0 ? tabs.findIndex((tab) => tab.getAttribute('aria-selected') === 'true') : current;
  let to = from;
  if (event.key === 'Home') to = 0;
  else if (event.key === 'End') to = tabs.length - 1;
  else to = (from + (event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? -1 : 1) + tabs.length) % tabs.length;
  event.preventDefault();
  tabs[to]!.focus();
  tabs[to]!.click();
}
