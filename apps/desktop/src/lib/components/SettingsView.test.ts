// @vitest-environment jsdom
import { describe, expect, it, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import SettingsView from './SettingsView.svelte';

describe('SettingsView', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('renders settings toggles and defaults passive-only to true', () => {
    const { container, getByText } = render(SettingsView);
    
    const passiveCheckbox = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
    expect(passiveCheckbox.checked).toBe(true);
    expect(getByText('PASSIVE ACTIVE')).toBeTruthy();
  });

  it('toggles passive-only mode and updates description badge', async () => {
    const { container, getByText } = render(SettingsView);
    
    const passiveCheckbox = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
    await fireEvent.click(passiveCheckbox);

    expect(passiveCheckbox.checked).toBe(false);
    expect(getByText('ACTIVE PROBING ENABLED')).toBeTruthy();
    expect(localStorage.getItem('neonhearth.passive_only')).toBe('false');
  });

  it('renders security and audit verification metadata', () => {
    const { getByText } = render(SettingsView);
    expect(getByText('127.0.0.1:58120 (Loopback Only)')).toBeTruthy();
    expect(getByText('SQLite WAL + SHA-256 Chained Triggers')).toBeTruthy();
  });
});
