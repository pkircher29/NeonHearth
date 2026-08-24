// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';

import type { ApiClient, CheckResult, DoctorFinding, DoctorRun, Measurement, RepairReport } from '../api/client';
import DoctorView from './DoctorView.svelte';

type DoctorClient = Pick<ApiClient, 'doctorRun' | 'doctorReport' | 'doctorApprove' | 'doctorRepair'>;

const measurement = (metric: Measurement['metric'], value: number, unit: Measurement['unit']): Measurement =>
  ({ metric, value, unit, observed_at: '2026-08-24T00:00:00Z' });

const passedCheck: CheckResult = { kind: 'gateway', status: { state: 'passed' }, evidence: [measurement('rtt_ms', 12.5, 'milliseconds')], confidence: { basis_points: 9500 }, detail: null };
const skippedCheck: CheckResult = { kind: 'dns', status: { state: 'skipped', because: { reason: 'dependency_failed', dependency: 'gateway' } }, evidence: [], confidence: { basis_points: 4000 }, detail: null };

function envelope(findings: DoctorFinding[] = [], checks: CheckResult[] = [passedCheck, skippedCheck]): DoctorRun {
  return {
    run_id: 'run-0001', started_at: '2026-08-24T00:00:00Z',
    report: {
      started_at: '2026-08-24T00:00:00Z', finished_at: '2026-08-24T00:00:05Z',
      budget: { max_probes: 32, per_probe_timeout_ms: 1000 }, probes_used: 12, budget_exhausted: false, checks
    },
    findings
  };
}

const routerFinding: DoctorFinding = {
  diagnosis: { kind: { kind: 'router_fault' }, evidence: [measurement('router_responsive', 0, 'boolean')], confidence: { basis_points: 7000 }, impact: "The router's management interface is unhealthy; visibility and control are reduced." },
  plan: { class: 'safe_automatic', action: { action: 'retry_router_session' }, rationale: 'retrying the router management session is local and harmless' }
};
const gatewayFinding: DoctorFinding = {
  diagnosis: { kind: { kind: 'gateway_unreachable' }, evidence: [measurement('loss_percent', 100, 'percent')], confidence: { basis_points: 9500 }, impact: 'The router cannot be reached; all traffic beyond this host is blocked.' },
  plan: { class: 'approval_required_reversible', action: { action: 'reboot_router' }, rationale: 'a router reboot disconnects every device and needs approval' }
};
const wifiFinding: DoctorFinding = {
  diagnosis: { kind: { kind: 'weak_wifi_quality', rssi_dbm: -82 }, evidence: [measurement('rssi_dbm', -82, 'dbm')], confidence: { basis_points: 7000 }, impact: 'Weak Wi-Fi signal causes slow transfers and dropped connections.' },
  plan: { class: 'guided_physical', action: 'move_hardware', rationale: 'signal strength is a physical placement problem the Doctor cannot change remotely' }
};
const observationFinding: DoctorFinding = {
  diagnosis: { kind: { kind: 'loss_latency_degraded', loss_percent: 8, median_rtt_ms: 120 }, evidence: [measurement('loss_percent', 8, 'percent')], confidence: { basis_points: 4000 }, impact: 'Packet loss or latency is elevated; calls, streams, and games will stutter.' },
  plan: { class: 'observation_only', rationale: 'degradation needs more samples before any disruptive change is worth proposing' }
};

function verifiedRepair(overrides: Partial<RepairReport> = {}): RepairReport {
  return {
    class: 'safe_automatic', description: 'retry_router_session',
    outcome: { outcome: 'completed', verdict: 'improved' },
    verification: { verdict: 'improved', before: measurement('loss_percent', 20, 'percent'), after: measurement('loss_percent', 2, 'percent') },
    rollback: { outcome: 'not_attempted', reason: 'not_needed' },
    events: [],
    ...overrides
  };
}

function fakeClient(overrides: Partial<DoctorClient> = {}): DoctorClient {
  return {
    doctorRun: vi.fn(async () => ({ status: 'completed' as const, run: envelope() })),
    doctorReport: vi.fn(async () => null),
    doctorApprove: vi.fn(async () => ({ approval_id: 'appr-0001', expires_at: '2026-08-24T00:10:00Z' })),
    doctorRepair: vi.fn(async () => verifiedRepair()),
    ...overrides
  };
}

describe('DoctorView', () => {
  it('shows the empty state with the run action before any diagnostic exists', async () => {
    render(DoctorView, { client: fakeClient() });

    await waitFor(() => expect(screen.getByText('No diagnostic has run yet')).toBeTruthy());
    expect(screen.getByRole('button', { name: 'Run diagnostic' })).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Diagnostic checks' })).toBeNull();
  });

  it('runs a diagnostic and renders the checks with skip reasons, measurements, and confidence', async () => {
    const client = fakeClient();
    render(DoctorView, { client });
    await waitFor(() => screen.getByText('No diagnostic has run yet'));

    await fireEvent.click(screen.getByRole('button', { name: 'Run diagnostic' }));

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Diagnostic checks' })).toBeTruthy());
    expect(client.doctorRun).toHaveBeenCalledOnce();
    expect(screen.getByText(/^✓?\s*Passed$/m)).toBeTruthy();
    expect(screen.getByText(/Skipped — dependency failed: gateway/)).toBeTruthy();
    expect(screen.getByText('rtt ms: 12.5 ms')).toBeTruthy();
    expect(screen.getByText('95% confidence')).toBeTruthy();
    expect(screen.getByText('40% confidence')).toBeTruthy();
    expect(screen.getByText('No faults were found. Every completed check passed.')).toBeTruthy();
  });

  it('executes a safe repair in one click with an in-flight state', async () => {
    let resolveRepair!: (report: RepairReport) => void;
    const client = fakeClient({
      doctorReport: vi.fn(async () => envelope([routerFinding])),
      doctorRepair: vi.fn(() => new Promise<RepairReport>((resolve) => { resolveRepair = resolve; }))
    });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Repair Router fault' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Repair Router fault' }));

    expect(client.doctorRepair).toHaveBeenCalledExactlyOnceWith({ kind: 'router_fault' });
    const button = screen.getByRole('button', { name: 'Repair Router fault' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.textContent).toContain('Repairing…');
    resolveRepair(verifiedRepair());
    await waitFor(() => expect(screen.getByText('Repair verified — the symptom improved.')).toBeTruthy());
    expect(screen.queryByRole('button', { name: 'Repair Router fault' })).toBeNull();
  });

  it('walks the two-step approval flow and confirms with the minted approval id', async () => {
    const client = fakeClient({ doctorReport: vi.fn(async () => envelope([gatewayFinding])) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Request approval for Gateway unreachable' }));
    expect(screen.queryByRole('button', { name: 'Confirm repair Gateway unreachable' })).toBeNull();

    await fireEvent.click(screen.getByRole('button', { name: 'Request approval for Gateway unreachable' }));

    await waitFor(() => screen.getByRole('button', { name: 'Confirm repair Gateway unreachable' }));
    expect(client.doctorApprove).toHaveBeenCalledExactlyOnceWith({ kind: 'gateway_unreachable' });
    expect(client.doctorRepair).not.toHaveBeenCalled();
    expect(screen.getByText(/Approval expires/)).toBeTruthy();

    await fireEvent.click(screen.getByRole('button', { name: 'Confirm repair Gateway unreachable' }));

    expect(client.doctorRepair).toHaveBeenCalledExactlyOnceWith({ kind: 'gateway_unreachable' }, 'appr-0001');
    await waitFor(() => expect(screen.getByText('Repair verified — the symptom improved.')).toBeTruthy());
  });

  it('renders guided plans as numbered steps and observation plans as explanation, with no execute control', async () => {
    const client = fakeClient({ doctorReport: vi.fn(async () => envelope([wifiFinding, observationFinding])) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('heading', { name: 'Weak wifi quality' }));

    const steps = screen.getByRole('list', { name: 'Guided steps for Weak wifi quality' });
    expect(steps.tagName).toBe('OL');
    expect(steps.querySelectorAll('li').length).toBeGreaterThan(2);
    expect(screen.getByText(/The Doctor is only observing this fault/)).toBeTruthy();
    // The only button on the page is the run action: neither plan is executable.
    expect(screen.getAllByRole('button')).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Run diagnostic' })).toBeTruthy();
  });

  it('shows verification before and after values side by side after a repair', async () => {
    const client = fakeClient({ doctorReport: vi.fn(async () => envelope([routerFinding])) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Repair Router fault' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Repair Router fault' }));

    await waitFor(() => expect(screen.getByText('Before')).toBeTruthy());
    expect(screen.getByText('After')).toBeTruthy();
    expect(screen.getByText('loss percent: 20%')).toBeTruthy();
    expect(screen.getByText('loss percent: 2%')).toBeTruthy();
  });

  it('reports a regressed repair with its rollback prominently and never as success', async () => {
    const regressed = verifiedRepair({
      outcome: { outcome: 'completed', verdict: 'regressed' },
      verification: { verdict: 'regressed', before: measurement('loss_percent', 5, 'percent'), after: measurement('loss_percent', 40, 'percent') },
      rollback: { outcome: 'succeeded' }
    });
    const client = fakeClient({ doctorReport: vi.fn(async () => envelope([routerFinding])), doctorRepair: vi.fn(async () => regressed) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Repair Router fault' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Repair Router fault' }));

    await waitFor(() => expect(screen.getByText('Repair made the symptom worse.')).toBeTruthy());
    expect(screen.getByText(/Rolled back — the change was reverted to the pre-repair snapshot/)).toBeTruthy();
    expect(screen.queryByText(/Repair verified/)).toBeNull();
  });

  it('marks an unverified repair distinctly, never as success, and alerts on a failed rollback', async () => {
    const unverified = verifiedRepair({
      outcome: { outcome: 'verification_failed', error: 'router stopped answering' },
      verification: null,
      rollback: { outcome: 'failed', error: 'restore timed out' }
    });
    const client = fakeClient({ doctorReport: vi.fn(async () => envelope([routerFinding])), doctorRepair: vi.fn(async () => unverified) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Repair Router fault' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Repair Router fault' }));

    await waitFor(() => expect(screen.getByText(/Unverified — the outcome could not be verified/)).toBeTruthy());
    expect(screen.getByText(/not confirmed as successful/)).toBeTruthy();
    expect(screen.queryByText(/Repair verified/)).toBeNull();
    expect(screen.getByText('No before-and-after verification is available for this repair.')).toBeTruthy();
    const rollbackAlert = screen.getAllByRole('alert').find((element) => element.textContent?.includes('Rollback failed'));
    expect(rollbackAlert?.textContent).toContain('restore timed out');
  });

  it('surfaces a concurrent diagnostic run as an inline alert', async () => {
    const client = fakeClient({ doctorRun: vi.fn(async () => ({ status: 'already_running' as const })) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Run diagnostic' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Run diagnostic' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('A diagnostic is already running'));
    expect((screen.getByRole('button', { name: 'Run diagnostic' }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('surfaces a failed run as an inline alert without blocking another attempt', async () => {
    const client = fakeClient({ doctorRun: vi.fn(async () => { throw new Error('Request failed with status 503'); }) });
    render(DoctorView, { client });
    await waitFor(() => screen.getByRole('button', { name: 'Run diagnostic' }));

    await fireEvent.click(screen.getByRole('button', { name: 'Run diagnostic' }));

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Request failed with status 503'));
    expect((screen.getByRole('button', { name: 'Run diagnostic' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
