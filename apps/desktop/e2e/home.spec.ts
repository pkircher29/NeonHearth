// M5 gate proof: an owner can draw, save, reopen, and rotate a multi-floor home
// with live devices and truthful location confidence.
// The Home API is faked in fixtures/home.ts with an in-memory server object, so
// committed saves and placements persist across page.reload() within a test.
import { test, expect, type Page } from '@playwright/test';
import {
  atticDraft, basePlan, installHomeFixture, seededCameraPlacement, seededTwinPlan, speakerEstimate,
  CAMERA_DEVICE_ID, CAMERA_DEVICE_NAME, GROUND_ID, HOME_ID, SPEAKER_DEVICE_ID, SPEAKER_DEVICE_NAME
} from './fixtures/home';

// A wide viewport keeps the whole plan canvas reachable for position clicks.
test.use({ viewport: { width: 1600, height: 1000 } });
test.beforeEach(async ({ page }) => {
  test.setTimeout(45_000); // the dev server cold-transforms the Home tab on first visit
  await page.emulateMedia({ reducedMotion: 'reduce' });
});

const planCanvas = (page: Page) => page.locator('svg.plan-canvas');
const editorTools = (page: Page) => page.getByRole('toolbar', { name: 'Editor tools' });
const floorBar = (page: Page) => page.getByRole('navigation', { name: 'Floors' });

async function openHome(page: Page) {
  await page.getByRole('button', { name: 'Home' }).first().click();
  await expect(page.getByRole('heading', { name: 'Draw the home you protect.' })).toBeVisible();
}

/** Two snapped clicks with the wall tool already armed. Coordinates are SVG pixels (40 px = 1 m). */
async function drawWall(page: Page, x1: number, y1: number, x2: number, y2: number) {
  await planCanvas(page).click({ position: { x: x1, y: y1 } });
  await planCanvas(page).click({ position: { x: x2, y: y2 } });
}

test('owner draws a multi-floor home, saves it with expected_version, and reopens it after reload', async ({ page }) => {
  const server = await installHomeFixture(page);
  await page.goto('/');
  await openHome(page);

  // --- Draw: two walls on the ground floor ---
  await expect(floorBar(page).getByRole('button', { name: /Ground/ })).toHaveAttribute('aria-pressed', 'true');
  await editorTools(page).getByRole('button', { name: 'Wall' }).click();
  await drawWall(page, 80, 80, 320, 80);
  await drawWall(page, 320, 80, 320, 240);
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(2);

  // --- Add a second floor; it starts empty, then gets two walls and a room ---
  await floorBar(page).getByRole('button', { name: '+ Add floor' }).click();
  await expect(floorBar(page).getByRole('button', { name: /Floor 1/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(0);
  await drawWall(page, 80, 80, 240, 80);
  await drawWall(page, 80, 80, 80, 200);
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(2);

  await editorTools(page).getByRole('button', { name: 'Room' }).click();
  await planCanvas(page).click({ position: { x: 320, y: 120 } });
  await planCanvas(page).click({ position: { x: 440, y: 120 } });
  await planCanvas(page).click({ position: { x: 380, y: 220 } });
  await editorTools(page).getByRole('button', { name: /^Finish room/ }).click();
  await expect(planCanvas(page).locator('polygon.room')).toHaveCount(1);
  await expect(planCanvas(page).locator('text.room-label')).toHaveText('Room 1');

  // --- Place a live device from the unplaced tray onto floor 1 (Ground) ---
  await floorBar(page).getByRole('button', { name: /Ground/ }).click();
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(2);
  await page.getByRole('complementary', { name: 'Unplaced devices' })
    .getByRole('button', { name: CAMERA_DEVICE_NAME }).click();
  await expect(page.getByText(`Placing ${CAMERA_DEVICE_NAME} — click the plan.`)).toBeVisible();
  await planCanvas(page).click({ position: { x: 160, y: 160 } });
  const pin = planCanvas(page).locator(`g.placement[data-device-id="${CAMERA_DEVICE_ID}"]`);
  await expect(pin).toBeVisible();
  await expect(pin).toHaveAttribute('aria-label', `${CAMERA_DEVICE_NAME} — owner-placed`);
  await expect.poll(() => server.placementPuts.length).toBeGreaterThan(0);
  expect(server.placementPuts.at(-1)).toMatchObject({
    device_id: CAMERA_DEVICE_ID, floor_id: GROUND_ID, x: 4, y: 4
  });

  // --- Save + version: the PUT carries expected_version and the full plan ---
  await expect(page.locator('.autosave')).toHaveText('Draft saved', { timeout: 10_000 });
  await page.getByRole('button', { name: 'Save plan' }).click();
  await expect(page.getByText('Plan saved as version 1.')).toBeVisible();
  expect(server.planPuts).toHaveLength(1);
  const put = server.planPuts[0];
  expect(put.expected_version).toBe(0);
  expect(put.plan.home_id).toBe(HOME_ID);
  expect(put.plan.floors).toHaveLength(2);
  const ground = put.plan.floors.find((floor) => floor.floor_id === GROUND_ID)!;
  const upper = put.plan.floors.find((floor) => floor.floor_id !== GROUND_ID)!;
  expect(ground.walls).toHaveLength(2);
  expect(upper.walls).toHaveLength(2);
  expect(upper.rooms).toHaveLength(1);
  expect(server.plan.version).toBe(1);
  await expect.poll(() => server.draft).toBeNull(); // the committed save discards the autosaved draft

  // --- Reopen: the persisted plan and placement render again after reload ---
  await page.reload();
  await openHome(page);
  await expect(floorBar(page).getByRole('button', { name: /Ground/ })).toHaveAttribute('aria-pressed', 'true');
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(2);
  await expect(planCanvas(page).locator(`g.placement[data-device-id="${CAMERA_DEVICE_ID}"]`)).toBeVisible();
  await floorBar(page).getByRole('button', { name: /Floor 1/ }).click();
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(2);
  await expect(planCanvas(page).locator('polygon.room')).toHaveCount(1);

  // Version continuity: the next save must send the incremented version it reloaded.
  await page.getByRole('button', { name: 'Save plan' }).click();
  await expect(page.getByText('Plan saved as version 2.')).toBeVisible();
  expect(server.planPuts[1].expected_version).toBe(1);
});

test('a low-confidence device stays advisory until the owner places it by hand', async ({ page }) => {
  const server = await installHomeFixture(page, { estimates: [speakerEstimate()] });
  await page.goto('/');
  await openHome(page);

  // The uncertain prompt lists the device with its honest confidence.
  const prompt = page.getByRole('region', { name: 'Place these devices' });
  await expect(prompt).toBeVisible();
  await expect(prompt).toContainText(`${SPEAKER_DEVICE_NAME} · 45%`);

  // The tray's advisory list labels it estimated-only, never confirmed.
  const tray = page.getByRole('complementary', { name: 'Unplaced devices' });
  await expect(tray.getByRole('heading', { name: 'Estimated only — not confirmed' })).toBeVisible();
  const estimateRow = tray.locator('.estimate-list li');
  await expect(estimateRow).toHaveCount(1);
  await expect(estimateRow).toContainText(SPEAKER_DEVICE_NAME);
  await expect(estimateRow).toContainText('estimated · 45% confidence');
  await expect(estimateRow).toContainText('Ground');
  // No placement pin exists for an estimate — estimates never render as located.
  await expect(planCanvas(page).locator('g.placement')).toHaveCount(0);

  // Place it by hand from the prompt.
  await prompt.getByRole('button', { name: new RegExp(SPEAKER_DEVICE_NAME) }).click();
  await expect(page.getByText(`Placing ${SPEAKER_DEVICE_NAME} — click the plan.`)).toBeVisible();
  await planCanvas(page).click({ position: { x: 200, y: 120 } });

  await expect.poll(() => server.placementPuts.length).toBe(1);
  expect(server.placementPuts[0]).toMatchObject({
    device_id: SPEAKER_DEVICE_ID, floor_id: GROUND_ID, x: 5, y: 3
  });
  await expect(planCanvas(page).locator(`g.placement[data-device-id="${SPEAKER_DEVICE_ID}"]`)).toBeVisible();
  // Once owner-placed, both the prompt and the advisory list clear.
  await expect(prompt).toHaveCount(0);
  await expect(tray.getByRole('heading', { name: 'Estimated only — not confirmed' })).toHaveCount(0);
});

test('a version conflict on save is reported honestly with no success claim', async ({ page }) => {
  const server = await installHomeFixture(page, { conflictOnPlanSave: true });
  await page.goto('/');
  await openHome(page);

  await editorTools(page).getByRole('button', { name: 'Wall' }).click();
  await drawWall(page, 80, 80, 200, 80);
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(1);

  await page.getByRole('button', { name: 'Save plan' }).click();
  const conflict = page.getByRole('alert').filter({ hasText: 'Save conflict.' });
  await expect(conflict).toBeVisible();
  await expect(conflict).toContainText('Reload the latest plan');
  expect(server.planPuts).toHaveLength(1);
  await expect(page.getByText(/Plan saved as version/)).toHaveCount(0);

  // Recovery reloads the server's truth: the rejected local wall does not survive.
  server.conflictOnPlanSave = false;
  await conflict.getByRole('button', { name: 'Reload latest plan' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Save conflict.' })).toHaveCount(0);
  await expect(floorBar(page).getByRole('button', { name: /Ground/ })).toBeVisible();
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(0);
});

test('a stored draft is offered on mount and Resume applies it', async ({ page }) => {
  await installHomeFixture(page, { draft: atticDraft() });
  await page.goto('/');
  await openHome(page);

  const banner = page.getByRole('region', { name: 'Draft found' });
  await expect(banner).toBeVisible();
  await expect(banner).toContainText('Unsaved draft found');
  await expect(banner.getByRole('button', { name: 'Discard draft' })).toBeVisible();
  // The committed plan (no Attic) is what renders until the owner chooses.
  await expect(floorBar(page).getByRole('button', { name: /Attic/ })).toHaveCount(0);

  await banner.getByRole('button', { name: 'Resume draft' }).click();
  await expect(page.getByRole('region', { name: 'Draft found' })).toHaveCount(0);
  const attic = floorBar(page).getByRole('button', { name: /Attic/ });
  await expect(attic).toBeVisible();
  await attic.click();
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(1);
  await expect(page.locator('.autosave')).toHaveText('Draft saved');
});

test('3D twin: rotate by drag-orbit, isolate floors, and list placed devices (or honest fallback)', async ({ page }, testInfo) => {
  await installHomeFixture(page, { plan: seededTwinPlan(), placements: [seededCameraPlacement()] });
  await page.goto('/');
  await openHome(page);

  await page.getByRole('tab', { name: '3D view' }).click();
  const twin = page.locator('.twin');
  await expect.poll(() => twin.getAttribute('data-mode')).not.toBe('pending');
  const mode = await twin.getAttribute('data-mode');
  testInfo.annotations.push({ type: '3d-path', description: mode ?? 'unknown' });
  console.log(`[home.spec] 3D twin path: ${mode}`);

  if (mode === '3d') {
    const stage = page.locator('.twin-stage');
    await expect(stage.locator('canvas')).toBeVisible();
    await expect(twin).toHaveAttribute('data-floor-count', '2');
    await expect(twin).toHaveAttribute('data-pin-count', '1');

    // Rotate: drag-orbit changes the rendered camera; Reset view restores it exactly.
    // (Orbit angles live outside the DOM, so the rendered pixels are the observable state.
    // Reduced motion is active, so every render is a deterministic single frame.)
    const box = (await stage.boundingBox())!;
    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;
    const before = await stage.screenshot();
    await page.mouse.move(cx, cy);
    await page.mouse.down();
    await page.mouse.move(cx + 140, cy + 70, { steps: 10 });
    await page.mouse.up();
    const after = await stage.screenshot();
    expect(Buffer.compare(after, before)).not.toBe(0); // the scene visibly rotated
    await page.getByRole('toolbar', { name: '3D view controls' }).getByRole('button', { name: 'Reset view' }).click();
    const reset = await stage.screenshot();
    expect(Buffer.compare(reset, before)).toBe(0); // reset returns to the exact initial camera

    // Floor isolation removes the other floor from the render.
    const controls = page.getByRole('toolbar', { name: '3D view controls' });
    await expect(controls.getByRole('button', { name: 'All floors' })).toHaveAttribute('aria-pressed', 'true');
    await controls.getByRole('button', { name: 'Ground' }).click();
    await expect(controls.getByRole('button', { name: 'Ground' })).toHaveAttribute('aria-pressed', 'true');
    await expect(controls.getByRole('button', { name: 'All floors' })).toHaveAttribute('aria-pressed', 'false');
    const isolated = await stage.screenshot();
    expect(Buffer.compare(isolated, reset)).not.toBe(0);

    // The accessible device list shows the placed live device with its presence.
    const deviceButton = page.locator(`.twin-devices button[data-device-id="${CAMERA_DEVICE_ID}"]`);
    await expect(deviceButton).toHaveText(`${CAMERA_DEVICE_NAME} — online`);
    // The list is visually hidden (1px clip) for screen readers, so activate it the
    // way its audience does: focus + Enter rather than a pointer click.
    await deviceButton.focus();
    await page.keyboard.press('Enter');
    await expect(twin).toHaveAttribute('data-selected', CAMERA_DEVICE_ID);
    await expect(page.getByText(`Selected device: ${CAMERA_DEVICE_NAME}`)).toBeVisible();
  } else {
    // Documented fallback path (H10): honest banner, back to the 2D editor, same devices.
    expect(mode).toBe('fallback');
    await expect(page.locator('.home-banner')).toContainText('3D unavailable on this device');
    await expect(page.getByRole('tab', { name: 'Plan editor' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('.twin-fallback')).toContainText('3D view is unavailable on this device');
    await expect(planCanvas(page).locator(`g.placement[data-device-id="${CAMERA_DEVICE_ID}"]`)).toBeVisible();
  }
});
