// @vitest-environment jsdom
import { cleanup, fireEvent, render, waitFor } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AuditEntry, AuditPage, AuditVerify } from '../api/client';
import HistoryView from './HistoryView.svelte';

const HASH = 'a'.repeat(64);
function entry(id: number, overrides: Partial<AuditEntry> = {}): AuditEntry {
  return { id, occurred_at: `2026-08-23T0${id % 10}:00:00Z`, actor: 'owner', category: 'approval', action: 'policy.approve', subject: `device-${id}`, detail: { id }, prev_hash: HASH, entry_hash: HASH, ...overrides };
}
const intact: AuditVerify = { report: { checked: 3, start_id: 1, end_id: 3, anchored: true, first_break: null }, head: { id: 3, entry_hash: HASH }, valid: true };

function client(pages: AuditPage[], verify: AuditVerify | Error = intact) {
  const auditPage = vi.fn();
  for (const page of pages) auditPage.mockResolvedValueOnce(page);
  const auditVerify = vi.fn(async () => { if (verify instanceof Error) throw verify; return verify; });
  return { auditPage, auditVerify };
}

afterEach(cleanup);

describe('HistoryView', () => {
  it('lists entries newest first, shows the intact chain, and expands detail', async () => {
    const api = client([{ entries: [entry(3), entry(2, { category: 'enforcement', action: 'guard.quarantine' })], head: { id: 3, entry_hash: HASH }, next_before: null }]);
    const { getByText, getByRole, queryByText } = render(HistoryView, { client: api });
    await waitFor(() => expect(getByText('Chain intact')).toBeTruthy());
    expect(getByText(/3 entries checked from the trusted root/)).toBeTruthy();
    const rows = document.querySelectorAll('.audit-row');
    expect(rows.length).toBe(2);
    expect(rows[0]!.textContent).toContain('#3');
    expect(queryByText('Load older entries')).toBeNull();
    await fireEvent.click(getByRole('button', { name: /guard · quarantine/ }));
    expect(document.querySelector('.audit-detail pre')!.textContent).toContain('"id": 2');
  });

  it('pages older entries with the cursor and keeps the filter', async () => {
    const api = client([
      { entries: [entry(9)], head: { id: 9, entry_hash: HASH }, next_before: 9 },
      { entries: [entry(8)], head: { id: 9, entry_hash: HASH }, next_before: null }
    ]);
    const { getByText, findByText } = render(HistoryView, { client: api, pageSize: 1 });
    await findByText('Load older entries');
    await fireEvent.click(getByText('Load older entries'));
    await waitFor(() => expect(document.querySelectorAll('.audit-row').length).toBe(2));
    expect(api.auditPage).toHaveBeenLastCalledWith({ limit: 1, before: 9 });
  });

  it('surfaces a chain break and a load failure with a reload path', async () => {
    const broken: AuditVerify = { report: { checked: 5, start_id: 1, end_id: 5, anchored: true, first_break: { id: 4, kind: 'prev_hash_mismatch' } }, head: { id: 5, entry_hash: HASH }, valid: false };
    const api = { auditPage: vi.fn().mockRejectedValueOnce(new Error('503')).mockResolvedValueOnce({ entries: [entry(1)], head: { id: 1, entry_hash: HASH }, next_before: null }), auditVerify: vi.fn(async () => broken) };
    const { findByText, getByText } = render(HistoryView, { client: api });
    expect(await findByText('Chain break at entry #4')).toBeTruthy();
    expect(await findByText('History is unavailable')).toBeTruthy();
    await fireEvent.click(getByText('Reload'));
    await waitFor(() => expect(document.querySelectorAll('.audit-row').length).toBe(1));
  });

  it('shows an honest empty state', async () => {
    const api = client([{ entries: [], head: null, next_before: null }]);
    const { findByText } = render(HistoryView, { client: api });
    expect(await findByText('Nothing on the record yet')).toBeTruthy();
  });
});
