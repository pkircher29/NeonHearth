// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

import SignInView from './SignInView.svelte';
import StepUpPrompt from './StepUpPrompt.svelte';

afterEach(cleanup);
const tick = () => new Promise<void>((resolve) => queueMicrotask(resolve));

describe('StepUpPrompt (PIN dialog)', () => {
  it('moves focus to the PIN input on open and puts it back on close', async () => {
    const opener = document.createElement('button');
    document.body.append(opener);
    opener.focus();
    const view = render(StepUpPrompt, { onsubmit: vi.fn(), oncancel: vi.fn() });
    await tick();
    expect(document.activeElement).toBe(screen.getByLabelText('Six-digit PIN'));
    view.unmount();
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });

  it('traps Tab inside the dialog in both directions', async () => {
    render(StepUpPrompt, { onsubmit: vi.fn(), oncancel: vi.fn() });
    await tick();
    const dialog = screen.getByRole('dialog');
    const cancel = screen.getByRole('button', { name: 'Cancel' });
    const input = screen.getByLabelText('Six-digit PIN');
    cancel.focus();
    await fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement).toBe(input);
    input.focus();
    await fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement).toBe(cancel);
  });

  it('Escape cancels', async () => {
    const oncancel = vi.fn();
    render(StepUpPrompt, { onsubmit: vi.fn(), oncancel });
    await tick();
    await fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(oncancel).toHaveBeenCalledTimes(1);
  });
});

describe('tab lists', () => {
  it('SignInView tabs: one tab stop, arrows and Home/End move and activate', async () => {
    render(SignInView, { onowner: vi.fn(), onphone: vi.fn() });
    const [owner, phone] = screen.getAllByRole('tab');
    expect(owner!.getAttribute('tabindex')).toBe('0');
    expect(phone!.getAttribute('tabindex')).toBe('-1');
    owner!.focus();
    await fireEvent.keyDown(owner!, { key: 'ArrowRight' });
    expect(document.activeElement).toBe(phone);
    expect(phone!.getAttribute('aria-selected')).toBe('true');
    expect(phone!.getAttribute('tabindex')).toBe('0');
    await fireEvent.keyDown(phone!, { key: 'Home' });
    expect(document.activeElement).toBe(owner);
    await fireEvent.keyDown(owner!, { key: 'ArrowLeft' }); // wraps
    expect(document.activeElement).toBe(phone);
  });

  it('SignInView says where a launcher pairing is kept', () => {
    render(SignInView, { onowner: vi.fn(), onphone: vi.fn() });
    expect(screen.getByText(/session storage so a reload does not sign you out/)).toBeTruthy();
  });
});
