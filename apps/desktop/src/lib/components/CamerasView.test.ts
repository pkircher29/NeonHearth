// @vitest-environment jsdom
import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, type ApiClient } from '../api/client';
import CamerasView from './CamerasView.svelte';

const id = '018f47a0-9b5c-7a22-8a33-112233445599';
const detail = { camera_id: id, classification: 'camera', confidence: .91, health: 'healthy', observed_at: '2026-01-01T00:00:00Z', inventory: { manufacturer: 'Luma', model: 'Porch', firmware: '1.2', serial: 'OWNER-4', capabilities: ['snapshot'], health: 'healthy' }, streams: [] };
function clientStub(overrides: Partial<ApiClient> = {}) { return { cameras: vi.fn(async () => ({ items: [detail], next_after: null })), camera: vi.fn(async () => detail), cameraSnapshot: vi.fn(async () => new Blob(['safe'], { type: 'image/jpeg' })), ...overrides } as unknown as ApiClient; }

describe('CamerasView', () => {
  it('renders a safe camera card with confidence, health, inventory and a snapshot action', async () => {
    render(CamerasView, { client: clientStub() });
    expect(await screen.findByRole('heading', { name: 'Watch the threshold.' })).toBeTruthy();
    expect(screen.getAllByText('91% confident')).toHaveLength(2);
    expect(screen.getAllByText('Healthy')).toHaveLength(3);
    expect(screen.getAllByText('Luma Porch')).toHaveLength(2);
    const snapshot = screen.getByRole('button', { name: /capture snapshot/i });
    expect(snapshot.tabIndex).toBe(0);
    await fireEvent.click(snapshot);
    expect(screen.getByAltText('Latest camera snapshot')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/rtsp|192\.168|aa:bb|password/i);
  });

  it.each([[404, /No longer available/i], [429, /Try again shortly/i], [503, /Collector is unavailable/i]])('shows actionable %s status', async (status, message) => {
    render(CamerasView, { client: clientStub({ cameras: vi.fn(async () => { throw new Error(`Request failed with status ${status}`); }) }) });
    expect(await screen.findByText(message)).toBeTruthy();
  });

  it('offers a retry on failure that reloads the list (M-28)', async () => {
    const cameras = vi.fn().mockRejectedValueOnce(new Error('Request failed with status 503')).mockResolvedValue({ items: [detail], next_after: null });
    render(CamerasView, { client: clientStub({ cameras }) });
    expect(await screen.findByText(/Collector is unavailable/i)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findAllByText('Luma Porch')).toHaveLength(2);
    expect(cameras).toHaveBeenCalledTimes(2);
  });

  it('shows the readable cameras with a count of the unreadable ones', async () => {
    const other = '018f47a0-9b5c-7a22-8a33-112233445588';
    const client = clientStub({
      cameras: vi.fn(async () => ({ items: [detail, { ...detail, camera_id: other }], next_after: null })),
      camera: vi.fn(async (cameraId: string) => { if (cameraId === other) throw new Error('Request failed with status 404'); return detail; })
    });
    render(CamerasView, { client });
    expect(await screen.findByText(/1 camera could not be read this time/)).toBeTruthy();
    expect(screen.getAllByText('Luma Porch')).toHaveLength(2);
  });

  it('uses an honest live fallback and a mobile-safe grid', async () => {
    const view = render(CamerasView, { client: clientStub() });
    expect(await screen.findByText(/Live view needs a stream selected/i)).toBeTruthy();
    expect(view.container.querySelector('.camera-grid')).toBeTruthy();
    expect(view.container.querySelector('.camera-actions button')?.className).toBeTruthy();
  });
});

describe('CamerasView camera media status', () => {
  const off = { enabled: false, reason: 'ffmpeg_not_found', detail: 'ffmpeg was expected at /usr/bin/ffmpeg but is not there. Install ffmpeg.', setup_available: false, setup_detail: 'No camera can be added yet.' };

  it('tells the owner why live view is off and what to do', async () => {
    render(CamerasView, { client: clientStub({ cameraMedia: vi.fn(async () => off) as unknown as ApiClient['cameraMedia'] }) });
    expect(await screen.findByText(/Live view is off because ffmpeg is not installed/i)).toBeTruthy();
    expect(screen.getByText(/Install ffmpeg\./)).toBeTruthy();
    expect(await screen.findByText(/Live view is off on this machine/i)).toBeTruthy();
  });

  it('says plainly that no camera can be added yet when the list is empty', async () => {
    const ready = { ...off, enabled: true, reason: 'ready' };
    render(CamerasView, { client: clientStub({ cameras: vi.fn(async () => ({ items: [], next_after: null })), cameraMedia: vi.fn(async () => ready) as unknown as ApiClient['cameraMedia'] }) });
    expect(await screen.findByText('No cameras yet')).toBeTruthy();
    expect(await screen.findByText('No camera can be added yet.')).toBeTruthy();
  });
});

describe('CamerasView add a camera', () => {
  const ready = { enabled: true, reason: 'ready', detail: 'Camera media is running.', setup_available: true, setup_detail: '' };
  const added = { camera_id: id, name: 'Porch', streams: [{ stream_id: '018f47a0-9b5c-4a22-8a33-112233445599' }] };
  const media = (value = ready) => vi.fn(async () => value) as unknown as ApiClient['cameraMedia'];
  const fill = async (overrides: Record<string, string> = {}) => {
    const values = { 'Camera address': '192.168.1.50', 'User name': 'admin', Password: 'sup3r-secret!', 'Name (optional)': 'Porch', ...overrides };
    for (const [label, value] of Object.entries(values)) await fireEvent.input(screen.getByLabelText(label), { target: { value } });
  };
  const passwordField = () => screen.getByLabelText('Password') as HTMLInputElement;

  it('shows the form to the owner only, and only when the service says setup works', async () => {
    const owner = render(CamerasView, { client: clientStub({ cameraMedia: media() }), owner: true });
    expect(await screen.findByRole('heading', { name: 'Add a camera' })).toBeTruthy();
    expect(passwordField().type).toBe('password');
    const basic = screen.getByRole('checkbox', { name: /allow less secure sign-in \(basic\)/i }) as HTMLInputElement;
    expect(basic.checked).toBe(false);
    expect(screen.getByText(/sends the camera's password without protection/i)).toBeTruthy();
    owner.unmount();

    const phone = render(CamerasView, { client: clientStub({ cameraMedia: media() }), owner: false });
    await screen.findAllByText('Luma Porch');
    expect(screen.queryByRole('heading', { name: 'Add a camera' })).toBeNull();
    expect(screen.queryByRole('button', { name: /remove camera/i })).toBeNull();
    phone.unmount();

    render(CamerasView, { client: clientStub({ cameraMedia: media({ ...ready, setup_available: false, setup_detail: 'Fix video first.' }) }), owner: true });
    await screen.findAllByText('Luma Porch');
    expect(screen.queryByRole('heading', { name: 'Add a camera' })).toBeNull();
  });

  it('sends the details once, empties the password field, and refreshes the list', async () => {
    const addCamera = vi.fn(async () => added);
    const cameras = vi.fn(async () => ({ items: [detail], next_after: null }));
    render(CamerasView, { client: clientStub({ cameraMedia: media(), addCamera: addCamera as unknown as ApiClient['addCamera'], cameras }), owner: true });
    await screen.findByRole('heading', { name: 'Add a camera' });
    await fill();
    await fireEvent.click(screen.getByRole('button', { name: 'Add camera' }));
    await vi.waitFor(() => expect(addCamera).toHaveBeenCalledTimes(1));
    expect(addCamera).toHaveBeenCalledWith({ address: '192.168.1.50', username: 'admin', password: 'sup3r-secret!', name: 'Porch' });
    await vi.waitFor(() => expect(cameras).toHaveBeenCalledTimes(2));
    expect(passwordField().value).toBe('');
    expect(document.body.textContent).not.toContain('sup3r-secret!');
    await vi.waitFor(() => expect((screen.getByLabelText('Camera address') as HTMLInputElement).value).toBe(''));
  });

  it('sends the Basic choice only when it is ticked, and leaves out an empty name', async () => {
    const addCamera = vi.fn(async () => added);
    render(CamerasView, { client: clientStub({ cameraMedia: media(), addCamera: addCamera as unknown as ApiClient['addCamera'] }), owner: true });
    await screen.findByRole('heading', { name: 'Add a camera' });
    await fill({ 'Name (optional)': '  ' });
    await fireEvent.click(screen.getByRole('checkbox', { name: /allow less secure sign-in/i }));
    await fireEvent.click(screen.getByRole('button', { name: 'Add camera' }));
    await vi.waitFor(() => expect(addCamera).toHaveBeenCalledWith({ address: '192.168.1.50', username: 'admin', password: 'sup3r-secret!', allow_basic: true }));
  });

  it.each([
    ['not_on_your_network', 422, null, null, /not on your network/i],
    ['unreachable', 502, null, null, /could not reach the camera/i],
    ['sign_in_refused', 422, null, null, /refused that user name or password/i],
    ['streams_elsewhere', 422, null, null, /points its video somewhere else/i],
    ['onvif_not_enabled', 422, null, null, /ONVIF does not appear to be enabled/i],
    ['video_unavailable', 503, 'ffmpeg_not_found', 'Install ffmpeg at the expected path.', /Video support is not available: Install ffmpeg at the expected path\./],
    ['rate_limited', 429, null, null, /too many tries/i],
    ['already_added', 409, null, null, /already added at that address/i]
  ])('says plainly why adding failed (%s) without echoing the password', async (code, status, reason, detailText, message) => {
    const addCamera = vi.fn(async () => { throw new ApiError(status, code, reason, detailText); });
    render(CamerasView, { client: clientStub({ cameraMedia: media(), addCamera: addCamera as unknown as ApiClient['addCamera'] }), owner: true });
    await screen.findByRole('heading', { name: 'Add a camera' });
    await fill();
    await fireEvent.click(screen.getByRole('button', { name: 'Add camera' }));
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toMatch(message);
    expect(document.body.textContent).not.toContain('sup3r-secret!');
    expect(passwordField().value).toBe('');
    // The typed address and name stay so a retry only needs the password again.
    expect((screen.getByLabelText('Camera address') as HTMLInputElement).value).toBe('192.168.1.50');
  });

  it('asks before removing, then removes the camera and refreshes the list', async () => {
    const removeCamera = vi.fn(async () => undefined);
    const cameras = vi.fn(async () => ({ items: [detail], next_after: null }));
    render(CamerasView, { client: clientStub({ removeCamera: removeCamera as unknown as ApiClient['removeCamera'], cameras }), owner: true });
    await screen.findAllByText('Luma Porch');
    await fireEvent.click(screen.getByRole('button', { name: 'Remove camera' }));
    expect(removeCamera).not.toHaveBeenCalled();
    expect(screen.getByText(/Remove this camera and its saved password\?/)).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Keep it' }));
    expect(removeCamera).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Remove camera' })).toBeTruthy();
    await fireEvent.click(screen.getByRole('button', { name: 'Remove camera' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Yes, remove it' }));
    await vi.waitFor(() => expect(removeCamera).toHaveBeenCalledWith(id));
    await vi.waitFor(() => expect(cameras).toHaveBeenCalledTimes(2));
  });

  it('says plainly when a removal could not finish', async () => {
    const removeCamera = vi.fn(async () => { throw new ApiError(503, 'incomplete'); });
    render(CamerasView, { client: clientStub({ removeCamera: removeCamera as unknown as ApiClient['removeCamera'] }), owner: true });
    await screen.findAllByText('Luma Porch');
    await fireEvent.click(screen.getByRole('button', { name: 'Remove camera' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Yes, remove it' }));
    expect((await screen.findByRole('alert')).textContent).toMatch(/some of its stored data could not be removed yet/i);
  });
});

describe('CamerasView live view for an owner-added camera', () => {
  const firstStream = '018f47a0-9b5c-4a22-8a33-1122334455aa';
  const secondStream = '018f47a0-9b5c-4a22-8a33-1122334455bb';
  const sessionId = '018f47a0-9b5c-7a22-8a33-112233445500';
  const added = { ...detail, streams: [{ stream_id: firstStream }, { stream_id: secondStream }] };

  it('asks for a session with the stream id the camera detail lists, and snapshots by camera', async () => {
    const startCameraSession = vi.fn(async () => ({ session_id: sessionId }));
    const cameraSnapshot = vi.fn(async () => new Blob(['safe'], { type: 'image/jpeg' }));
    render(CamerasView, { client: clientStub({ camera: vi.fn(async () => added) as unknown as ApiClient['camera'], startCameraSession: startCameraSession as unknown as ApiClient['startCameraSession'], cameraSnapshot }), owner: true });
    await fireEvent.click(await screen.findByRole('button', { name: /start live view/i }));
    await vi.waitFor(() => expect(startCameraSession).toHaveBeenCalledWith(id, firstStream));
    await fireEvent.click(screen.getByRole('button', { name: /capture snapshot/i }));
    await vi.waitFor(() => expect(cameraSnapshot).toHaveBeenCalledWith(id, undefined));
  });
});
