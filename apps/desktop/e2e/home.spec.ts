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

/**
 * Two snapped clicks with the wall tool already armed, then Escape: walls now chain (the next wall
 * starts where the last ended), so Escape ends the chain and each call draws one standalone wall.
 * Coordinates are SVG pixels (40 px = 1 m at the default view).
 */
async function drawWall(page: Page, x1: number, y1: number, x2: number, y2: number) {
  await planCanvas(page).click({ position: { x: x1, y: y1 } });
  await planCanvas(page).click({ position: { x: x2, y: y2 } });
  await page.keyboard.press('Escape');
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

test('pan and zoom the plan, then close a chain of walls and accept the offered room', async ({ page }) => {
  await installHomeFixture(page);
  await page.goto('/');
  await openHome(page);
  const viewBox = async () => (await planCanvas(page).getAttribute('viewBox'))!.split(' ').map(Number);
  const zoomText = () => page.locator('.zoom-readout').innerText();
  const viewControls = page.getByRole('toolbar', { name: 'Plan view' });

  // Default view: 40 px/m from the origin, filling the frame.
  expect(await zoomText()).toBe('40 px/m');
  const [x0, y0, width, height] = await viewBox();
  expect([x0, y0]).toEqual([0, 0]);
  expect(width).toBeGreaterThan(400);
  expect(height).toBeGreaterThan(400);

  // Zoom: buttons and the wheel (anchored at the cursor).
  await viewControls.getByRole('button', { name: 'Zoom in' }).click();
  expect(await zoomText()).toBe('50 px/m');
  await planCanvas(page).hover({ position: { x: 100, y: 100 } });
  await page.mouse.wheel(0, -300);
  await expect.poll(async () => Number((await zoomText()).replace(' px/m', ''))).toBeGreaterThan(50);
  await viewControls.getByRole('button', { name: '100%' }).click();
  expect(await zoomText()).toBe('40 px/m');

  // Pan with the Pan tool, then with the middle mouse button; neither draws anything.
  await planCanvas(page).scrollIntoViewIfNeeded(); // page.mouse works in viewport coordinates
  const box = (await planCanvas(page).boundingBox())!;
  const before = await viewBox();
  await editorTools(page).getByRole('button', { name: 'Pan' }).click();
  await page.mouse.move(box.x + 300, box.y + 300);
  await page.mouse.down();
  await page.mouse.move(box.x + 360, box.y + 340, { steps: 6 });
  await page.mouse.up();
  const panned = await viewBox();
  expect(panned[0]).toBeCloseTo(before[0] - 60, 0);
  expect(panned[1]).toBeCloseTo(before[1] - 40, 0);
  await editorTools(page).getByRole('button', { name: 'Wall' }).click();
  await page.mouse.move(box.x + 500, box.y + 300);
  await page.mouse.down({ button: 'middle' });
  await page.mouse.move(box.x + 450, box.y + 300, { steps: 5 });
  await page.mouse.up({ button: 'middle' });
  expect((await viewBox())[0]).toBeCloseTo(panned[0] + 50, 0);
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(0);

  // Draw a closed loop with chained walls: the last click lands on the first point.
  const corners: Array<[number, number]> = [[200, 150], [440, 150], [440, 330], [200, 330], [200, 150]];
  for (const [x, y] of corners) await planCanvas(page).click({ position: { x, y } });
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(4);
  const offer = page.getByRole('region', { name: 'Detected rooms' });
  await expect(offer).toBeVisible();
  await expect(offer).toContainText('m²');
  await expect(planCanvas(page).locator('polygon.candidate')).toHaveCount(1);
  await offer.getByRole('button', { name: 'Add' }).click();
  await expect(planCanvas(page).locator('polygon.room')).toHaveCount(1);
  await expect(planCanvas(page).locator('text.room-label')).toHaveText('Room 1');
  await expect(planCanvas(page).locator('text.room-area')).toContainText('m²');
  await expect(offer).toHaveCount(0);

  // The view is remembered per floor across a reload.
  await viewControls.getByRole('button', { name: 'Zoom in' }).click();
  const remembered = await zoomText();
  await page.reload();
  await openHome(page);
  expect(await zoomText()).toBe(remembered);
});

test('drag a wall endpoint (snapping onto another wall) and drag a wall body, each one undo step', async ({ page }) => {
  await installHomeFixture(page);
  await page.goto('/');
  await openHome(page);
  await editorTools(page).getByRole('button', { name: 'Wall' }).click();
  await drawWall(page, 80, 80, 320, 80); // (2,2) -> (8,2)
  await drawWall(page, 80, 200, 200, 200); // (2,5) -> (5,5)
  await editorTools(page).getByRole('button', { name: 'Select' }).click();
  const walls = planCanvas(page).locator('line.wall');
  await expect(walls).toHaveCount(2);
  await planCanvas(page).scrollIntoViewIfNeeded();
  const box = (await planCanvas(page).boundingBox())!;
  const at = (x: number, y: number) => ({ x: box.x + x, y: box.y + y });

  // Select the lower wall by clicking its middle, then drag its right handle up onto the upper wall's body.
  await planCanvas(page).click({ position: { x: 140, y: 200 } });
  const handle = planCanvas(page).locator('[data-handle="end"]');
  await expect(handle).toBeVisible();
  const from = at(200, 200);
  await page.mouse.move(from.x, from.y);
  await page.mouse.down();
  const to = at(200, 81);
  await page.mouse.move(to.x, to.y, { steps: 8 });
  await expect(planCanvas(page).locator('.snap-marker')).toHaveAttribute('data-snap-kind', /on-wall|midpoint/);
  await page.mouse.up();
  // The upper wall was split where the dragged end landed, so the three walls now truly join.
  await expect(walls).toHaveCount(3);
  await page.getByRole('button', { name: 'Undo' }).click();
  await expect(walls).toHaveCount(2); // split + move undo together

  // Drag the upper wall as a whole: both ends shift by the same grid-snapped amount.
  await planCanvas(page).click({ position: { x: 200, y: 80 } });
  const before = await walls.first().evaluate((line) => [line.getAttribute('x1'), line.getAttribute('y1'), line.getAttribute('x2'), line.getAttribute('y2')]);
  const grab = at(200, 80);
  await page.mouse.move(grab.x, grab.y);
  await page.mouse.down();
  await page.mouse.move(grab.x + 40, grab.y + 40, { steps: 6 });
  await page.mouse.up();
  const after = await walls.first().evaluate((line) => [line.getAttribute('x1'), line.getAttribute('y1'), line.getAttribute('x2'), line.getAttribute('y2')]);
  expect(after.map(Number)).toEqual(before.map((value, index) => Number(value) + 40));
  await expect(planCanvas(page).locator('.dimension')).toHaveText('6.00 m'); // moving does not change the length
});

test('imperial: a chained closed room joins exactly, is detected with an ft² area, and a typed length is in feet', async ({ page }) => {
  const server = await installHomeFixture(page);
  await page.goto('/');
  await openHome(page);
  await page.getByRole('combobox', { name: 'Measurement units' }).selectOption('imperial');
  await editorTools(page).getByRole('button', { name: 'Wall' }).click();

  // A closed chain: the last click lands on the first point, so the loop ends itself.
  for (const [x, y] of [[160, 120], [400, 120], [400, 300], [160, 300], [160, 120]]) await planCanvas(page).click({ position: { x, y } });
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(4);
  const offer = page.getByRole('region', { name: 'Detected rooms' });
  await expect(offer).toBeVisible();
  await expect(offer).toContainText(/\d+ ft²/);
  await expect(offer).not.toContainText('m²');
  await offer.getByRole('button', { name: 'Add' }).click();
  await expect(planCanvas(page).locator('text.room-area')).toContainText(/^\d+ ft²$/);
  await expect(floorBar(page)).toContainText(/\d+ ft²/);

  // A typed length in feet: 10 ft is exactly 3.048 m.
  await planCanvas(page).click({ position: { x: 500, y: 440 } });
  await page.keyboard.type('10');
  await page.keyboard.press('Enter');
  await page.keyboard.press('Escape');
  await expect(planCanvas(page).locator('line.wall')).toHaveCount(5);
  await expect(planCanvas(page).locator('text.dimension')).toHaveText('10.00 ft');

  await page.getByRole('button', { name: 'Save plan' }).click();
  await expect(page.getByText('Plan saved as version 1.')).toBeVisible();
  const walls = server.planPuts[0].plan.floors[0].walls;
  expect(walls).toHaveLength(5);
  for (let i = 0; i < 4; i += 1) expect(walls[i].end).toEqual(walls[(i + 1) % 4].start); // every corner joins exactly, on inch grid points
  const typed = walls[4];
  expect(typed.end.x - typed.start.x).toBeCloseTo(3.048, 6);
  expect(typed.end.y).toBeCloseTo(typed.start.y, 6);
  expect(server.planPuts[0].plan.floors[0].rooms).toHaveLength(1);
  for (const wall of walls) expect(wall.thickness_m).toBe(0.1);
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


// --- Twin v2 (spec E): camera presets, pin detail card, room hover ---------

/** Opens the 3D tab; returns false (and notes the fallback) when WebGL is unavailable. */
async function openTwin(page: Page): Promise<boolean> {
  await installHomeFixture(page, { plan: seededTwinPlan(), placements: [seededCameraPlacement()] });
  await page.goto('/');
  await openHome(page);
  await page.getByRole('tab', { name: '3D view' }).click();
  const twin = page.locator('.twin');
  await expect.poll(() => twin.getAttribute('data-mode')).not.toBe('pending');
  return (await twin.getAttribute('data-mode')) === '3d';
}

test('3D twin v2: camera presets switch the view and mark the active preset', async ({ page }) => {
  test.skip(!(await openTwin(page)), 'WebGL unavailable here; the fallback path is covered by the first twin test');
  const twin = page.locator('.twin');
  const stage = page.locator('.twin-stage');
  const controls = page.getByRole('toolbar', { name: '3D view controls' });
  await expect(twin).toHaveAttribute('data-camera-preset', 'iso');
  const iso = await stage.screenshot();

  await controls.getByRole('button', { name: 'Top' }).click();
  await expect(twin).toHaveAttribute('data-camera-preset', 'top');
  await expect(controls.getByRole('button', { name: 'Top' })).toHaveAttribute('aria-pressed', 'true');
  await expect(controls.getByRole('button', { name: 'Isometric' })).toHaveAttribute('aria-pressed', 'false');
  const top = await stage.screenshot();
  expect(Buffer.compare(top, iso)).not.toBe(0);

  await controls.getByRole('button', { name: 'Front' }).click();
  await expect(twin).toHaveAttribute('data-camera-preset', 'front');
  const front = await stage.screenshot();
  expect(Buffer.compare(front, top)).not.toBe(0);

  // Reduced motion: the switch is instant, so Isometric restores the exact first frame.
  await controls.getByRole('button', { name: 'Isometric' }).click();
  await expect(twin).toHaveAttribute('data-camera-preset', 'iso');
  expect(Buffer.compare(await stage.screenshot(), iso)).toBe(0);

  // Dragging leaves every preset (the camera is no longer on one).
  const box = (await stage.boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 + 90, box.y + box.height / 2 + 40, { steps: 6 });
  await page.mouse.up();
  await expect(twin).toHaveAttribute('data-camera-preset', '');
});

test('3D twin v2: a selected pin opens a glass detail card with Show in Devices', async ({ page }) => {
  test.skip(!(await openTwin(page)), 'WebGL unavailable here; the fallback path is covered by the first twin test');
  const twin = page.locator('.twin');
  await expect(page.locator('.twin-card')).toHaveCount(0);

  // Select the way the device list's audience does (focus + Enter).
  const deviceButton = page.locator(`.twin-devices button[data-device-id="${CAMERA_DEVICE_ID}"]`);
  await deviceButton.focus();
  await page.keyboard.press('Enter');
  await expect(twin).toHaveAttribute('data-selected', CAMERA_DEVICE_ID);

  const card = page.getByRole('complementary', { name: 'Device details' });
  await expect(card).toBeVisible();
  await expect(card.getByRole('heading', { name: CAMERA_DEVICE_NAME })).toBeVisible();
  await expect(card.locator('[data-field="presence"]')).toHaveText('Online');
  await expect(card.locator('[data-field="room"]')).toHaveText('Den');
  await expect(card.locator('[data-field="evidence"]')).toHaveText('—'); // no evidence recorded: honest dash
  await expect(card.locator('[data-field="last-seen"]')).not.toHaveText('—');

  await card.getByRole('button', { name: 'Show in Devices' }).click();
  await expect(page.locator('nav[aria-label="Primary"] button[aria-current="page"]')).toContainText('Devices');
});

test('3D twin v2: the close button dismisses the detail card; hovering a room names it with its area', async ({ page }) => {
  test.skip(!(await openTwin(page)), 'WebGL unavailable here; the fallback path is covered by the first twin test');
  const twin = page.locator('.twin');
  const stage = page.locator('.twin-stage');
  const card = page.getByRole('complementary', { name: 'Device details' });

  const deviceButton = page.locator(`.twin-devices button[data-device-id="${CAMERA_DEVICE_ID}"]`);
  await deviceButton.focus();
  await page.keyboard.press('Enter');
  await expect(card).toBeVisible();
  await card.getByRole('button', { name: 'Close device details' }).click();
  await expect(card).toHaveCount(0);

  // The Den room (2.5 m x 2.5 m) sits left of the model centre: scan for it.
  const box = (await stage.boundingBox())!;
  const cx = box.x + box.width / 2;
  const cy = box.y + box.height / 2;
  let found = false;
  for (const dx of [-60, -100, -140, -30, -180, 0]) {
    for (const dy of [0, 40, -40, 80]) {
      await page.mouse.move(cx + dx, cy + dy);
      if ((await twin.getAttribute('data-hover-room')) !== '') { found = true; break; }
    }
    if (found) break;
  }
  expect(found).toBe(true);
  const tip = page.locator('.twin-room-tip');
  await expect(tip).toContainText('Den');
  await expect(tip).toContainText(/6\.\d m²/);
  await page.mouse.move(box.x + 4, box.y + 4); // off the room: the tip goes away
  await expect(tip).toHaveCount(0);
});

// Real multi-touch: CDP Input.dispatchTouchEvent makes Chromium emit genuine pointer events with
// pointerType "touch" (and the browser's own touch-action handling), unlike the jsdom synthetic events.
test.describe('touch gestures on the plan canvas', () => {
  test.use({ hasTouch: true });

  type Finger = { x: number; y: number; id: number };
  async function openTouchEditor(page: Page) {
    await installHomeFixture(page, { plan: seededTwinPlan() });
    await page.goto('/');
    await openHome(page);
    await planCanvas(page).scrollIntoViewIfNeeded();
    const box = (await planCanvas(page).boundingBox())!;
    const cdp = await page.context().newCDPSession(page);
    const send = (type: 'touchStart' | 'touchMove' | 'touchEnd', fingers: Finger[]) =>
      cdp.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchEnd' ? [] : fingers.map((f) => ({ x: box.x + f.x, y: box.y + f.y, id: f.id })) });
    /** Move fingers from one layout to another in small steps, like a real gesture. */
    async function drag(from: Finger[], to: Finger[], steps = 12) {
      for (let step = 1; step <= steps; step += 1) {
        const t = step / steps;
        await send('touchMove', from.map((f, i) => ({ id: f.id, x: f.x + (to[i].x - f.x) * t, y: f.y + (to[i].y - f.y) * t })));
      }
    }
    const state = async () => {
      const [vx, vy] = (await planCanvas(page).getAttribute('viewBox'))!.split(' ').map(Number);
      const scale = Number((await page.locator('.zoom-readout').innerText()).replace(' px/m', ''));
      return { vx, vy, scale };
    };
    return { box, send, drag, state };
  }

  test('canvas opts out of browser touch handling and the page never zooms or scrolls', async ({ page }) => {
    const { send, drag } = await openTouchEditor(page);
    expect(await planCanvas(page).evaluate((svg) => getComputedStyle(svg).touchAction)).toBe('none');
    const scrollBefore = await page.evaluate(() => window.scrollY);
    const f = (dx: number): Finger[] => [{ id: 0, x: 300 - dx, y: 200 }, { id: 1, x: 300 + dx, y: 200 }];
    await send('touchStart', f(40));
    await drag(f(40), f(140));
    await send('touchEnd', []);
    expect(await page.evaluate(() => window.visualViewport?.scale ?? 1)).toBe(1);
    expect(await page.evaluate(() => window.scrollY)).toBe(scrollBefore);
  });

  test('(a) spreading two fingers zooms about the pinch midpoint', async ({ page }) => {
    const { send, drag, state } = await openTouchEditor(page);
    const before = await state();
    expect(before.scale).toBe(40);
    const mid = { x: 300, y: 200 };
    const plan = { x: (before.vx + mid.x) / before.scale, y: (before.vy + mid.y) / before.scale }; // the plan point under the midpoint
    const f = (dx: number): Finger[] => [{ id: 0, x: mid.x - dx, y: mid.y }, { id: 1, x: mid.x + dx, y: mid.y }];
    await send('touchStart', f(40));
    await drag(f(40), f(120));
    const during = await state();
    expect(during.scale).toBeGreaterThan(100); // 80 px apart -> 240 px apart is 3x
    expect(during.scale).toBeLessThan(130);
    // The same plan point is still under the (unmoved) midpoint, within a few px.
    expect(plan.x * during.scale - during.vx).toBeCloseTo(mid.x, -1);
    expect(Math.abs(plan.x * during.scale - during.vx - mid.x)).toBeLessThan(4);
    expect(Math.abs(plan.y * during.scale - during.vy - mid.y)).toBeLessThan(4);
    await page.screenshot({ path: 'D:/worktrees/nh-editor/output/editor-v2/5-pinch.png' }); // mid-pinch, fingers still down
    await send('touchEnd', []);
    // Pinching back in reduces the zoom again.
    await send('touchStart', f(120));
    await drag(f(120), f(60));
    await send('touchEnd', []);
    expect((await state()).scale).toBeLessThan(during.scale);
  });

  test('(b) two fingers moving together pan without changing zoom', async ({ page }) => {
    const { send, drag, state } = await openTouchEditor(page);
    const before = await state();
    const start: Finger[] = [{ id: 0, x: 250, y: 200 }, { id: 1, x: 350, y: 200 }];
    const end: Finger[] = start.map((p) => ({ ...p, x: p.x + 60, y: p.y + 30 }));
    await send('touchStart', start);
    await drag(start, end);
    await send('touchEnd', []);
    const after = await state();
    expect(after.scale).toBe(before.scale);
    expect(after.vx).toBeCloseTo(before.vx - 60, 0);
    expect(after.vy).toBeCloseTo(before.vy - 30, 0);
  });

  test('(c) lifting the fingers after a pinch and a pan draws nothing, even with the Wall tool armed', async ({ page }) => {
    const { send, drag } = await openTouchEditor(page);
    await editorTools(page).getByRole('button', { name: 'Wall' }).tap();
    await expect(editorTools(page).getByRole('button', { name: 'Wall' })).toHaveAttribute('aria-pressed', 'true');
    const walls = planCanvas(page).locator('line.wall');
    const count = await walls.count();
    const f = (dx: number, oy = 0): Finger[] => [{ id: 0, x: 300 - dx, y: 200 + oy }, { id: 1, x: 300 + dx, y: 200 + oy }];
    await send('touchStart', f(40));
    await drag(f(40), f(100));
    await send('touchEnd', []);
    await send('touchStart', f(100));
    await drag(f(100), f(100, 40));
    await send('touchEnd', []);
    await page.waitForTimeout(150); // any stray click from the lift would land by now
    await expect(planCanvas(page).locator('.pending-start')).toHaveCount(0);
    await expect(walls).toHaveCount(count);
    await expect(planCanvas(page).locator('g.placement')).toHaveCount(0);
  });

  test('(d) a single-finger tap with the Wall tool still starts a wall', async ({ page }) => {
    const { send } = await openTouchEditor(page);
    await editorTools(page).getByRole('button', { name: 'Wall' }).tap();
    const tap: Finger[] = [{ id: 0, x: 500, y: 300 }];
    await send('touchStart', tap);
    await send('touchEnd', []);
    await expect(planCanvas(page).locator('.pending-start')).toHaveCount(1);
    // ...and a second tap finishes it.
    await send('touchStart', [{ id: 0, x: 620, y: 300 }]);
    await send('touchEnd', []);
    await expect(planCanvas(page).locator('line.wall')).toHaveCount(5); // the seeded plan has 4
  });
});
