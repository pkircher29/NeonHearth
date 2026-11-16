import { describe, expect, it, vi } from 'vitest';
import { createApiClient } from './client';
import realRun from './fixtures-doctor-run-windows.json';

// A real response from `POST /api/v1/doctor/run`, captured from the service on
// Windows with outside-network checks allowed (addresses generalised). The
// hand-written fixtures in client.test.ts drifted from what the service sends
// for the MTU check; this keeps the strict validators honest against the
// real wire shape.
describe('doctor run contract against a captured service response', () => {
  const clientFor = (body: unknown) => createApiClient({
    baseUrl: 'https://collector.example', serviceToken: 'secret',
    fetchImpl: vi.fn(async () => new Response(JSON.stringify(body), { status: 200 })),
  });

  it('accepts the response the service really sends', async () => {
    const result = await clientFor(realRun).doctorRun();
    expect(result.status).toBe('completed');
    if (result.status !== 'completed') return;
    const mtu = result.run.report.checks.find((check) => check.kind === 'mtu');
    expect(mtu?.detail).toEqual({ detail: 'mtu', largest_passing_payload_bytes: 1472, smallest_failing_payload_bytes: null, ip_version: 'v4' });
    expect(result.run.report.checks.map((check) => check.kind)).toHaveLength(12);
  });

  it('still rejects a malformed MTU detail', async () => {
    const broken = structuredClone(realRun) as { report: { checks: { kind: string; detail: unknown }[] } };
    const mtu = broken.report.checks.find((check) => check.kind === 'mtu')!;
    mtu.detail = { detail: 'mtu', largest_passing_payload_bytes: 70000, smallest_failing_payload_bytes: null, ip_version: 'v4' };
    await expect(clientFor(broken).doctorRun()).rejects.toThrow('Invalid doctor run response');
    mtu.detail = { detail: 'mtu', largest_passing_payload_bytes: 1472, smallest_failing_payload_bytes: null, ip_version: 'v9' };
    await expect(clientFor(broken).doctorRun()).rejects.toThrow('Invalid doctor run response');
  });
});
