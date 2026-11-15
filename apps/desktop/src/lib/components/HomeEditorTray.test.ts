// @vitest-environment jsdom
import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import { eightyNine } from '../home/deviceFixtures';
import HomeEditorTray from './HomeEditorTray.svelte';

const mount = (unplaced = eightyNine(), extra: Record<string, unknown> = {}) => {
  const onpick = vi.fn();
  const view = render(HomeEditorTray, { unplaced, placing: null, estimated: [], onpick, ...extra });
  return { onpick, view };
};
const MAC = /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/;

describe('HomeEditorTray with a real home', () => {
  it('counts devices in the heading, labels unnamed ones by vendor and MAC tail with the IP beside, and scrolls inside a fixed region', () => {
    const { view } = mount();
    expect(screen.getByRole('heading', { name: 'Unplaced devices · 89' })).toBeTruthy();
    const rows = view.container.querySelectorAll('.tray-device');
    expect(rows).toHaveLength(89);
    expect(rows[0].querySelector('.tray-label')!.textContent).toMatch(/^(Apple|Espressif|Intel Corporate|Tuya Smart) · [0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$/);
    expect(rows[0].querySelector('.tray-ip')!.textContent).toMatch(/^192\.168\.1\.\d+$/);
    expect(screen.getByRole('region', { name: 'Device list' }).getAttribute('tabindex')).toBe('0');
    // Raw MACs only for vendorless devices, and those sort last.
    const labels = [...rows].map((row) => row.querySelector('.tray-label')!.textContent!);
    const firstMac = labels.findIndex((label) => MAC.test(label));
    expect(firstMac).toBeGreaterThan(0);
    expect(labels.slice(firstMac).every((label) => MAC.test(label))).toBe(true);
  });

  it('filters by vendor and IP, shows a no-match state, and clears', async () => {
    const { view } = mount();
    const input = screen.getByRole('searchbox', { name: 'Filter devices' }) as HTMLInputElement;
    await fireEvent.input(input, { target: { value: 'espressif' } });
    const shown = view.container.querySelectorAll('.tray-device').length;
    expect(shown).toBeGreaterThan(5);
    expect(shown).toBeLessThan(89);
    await fireEvent.input(input, { target: { value: '192.168.1.100' } });
    expect(view.container.querySelectorAll('.tray-device')).toHaveLength(1);
    await fireEvent.input(input, { target: { value: 'zzz-nothing' } });
    expect(screen.getByText(/No devices match/)).toBeTruthy();
    expect(view.container.querySelectorAll('.tray-device')).toHaveLength(0);
    await fireEvent.click(screen.getByRole('button', { name: 'Clear filter' }));
    expect(input.value).toBe('');
    expect(view.container.querySelectorAll('.tray-device')).toHaveLength(89);
    expect(screen.queryByRole('button', { name: 'Clear filter' })).toBeNull();
  });

  it('keeps click-to-arm and drag-to-place on the compact rows', async () => {
    const { onpick, view } = mount();
    const row = view.container.querySelector('.tray-device')!;
    expect(row.getAttribute('draggable')).toBe('true');
    const setData = vi.fn();
    await fireEvent.dragStart(row, { dataTransfer: { setData } });
    expect(setData).toHaveBeenCalledWith('text/plain', expect.stringMatching(/^00000000-/));
    await fireEvent.click(row);
    expect(onpick).toHaveBeenCalledTimes(1);
  });

  it('owner names win and sort first; a short list needs no filter box', () => {
    const devices = [...eightyNine().slice(0, 3), { device_id: 'named', name: 'Porch node', vendor: 'Espressif Inc.', mac: '00:04:4B:82:87:11' }];
    const { view } = mount(devices);
    expect(view.container.querySelector('.tray-device .tray-label')!.textContent).toBe('Porch node');
    expect(screen.queryByRole('searchbox')).toBeNull();
  });

  it('shows estimated rows untouched and an empty state', () => {
    mount([], { estimated: [{ device_id: 'e', name: 'Kiosk', label: 'Kitchen · Ground', confidence: 0.4 }] });
    expect(screen.getByText(/Every known device has an owner-confirmed spot/)).toBeTruthy();
    expect(screen.getByText('estimated · 40% confidence')).toBeTruthy();
    expect(within(screen.getByRole('complementary', { name: 'Unplaced devices' })).getByRole('heading', { name: 'Estimated only — not confirmed' })).toBeTruthy();
  });
});
