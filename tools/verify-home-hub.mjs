// Run against the isolated QA instance and tools/ha-fixture.py. No household controls.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
const require = createRequire(new URL('../apps/desktop/package.json', import.meta.url));
const { chromium, expect } = require('@playwright/test');
const root = fileURLToPath(new URL('../', import.meta.url));
const connection = JSON.parse(await readFile(root + '.local/qa-runtime-v2/connection.json', 'utf8'));
const artifact = root + 'artifacts/home-hub-verification/';
await mkdir(artifact, { recursive: true });
async function api(path, method = 'GET', body) {
  const response = await fetch(connection.url + '/api/v1/' + path, {
    method, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { Authorization: `Bearer ${connection.token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}
const browser = await chromium.launch({ executablePath: process.env.NEONHEARTH_CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
try {
  const page = await browser.newPage({ viewport: { width: 1500, height: 1100 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(connection.url + '/#token=' + connection.token);
  await expect(page).not.toHaveURL(/#token=/);
  await page.getByRole('button', { name: 'Automation', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your home, connected.' })).toBeVisible();
  await page.getByLabel('Home Assistant address').fill('http://127.0.0.1:58124');
  await page.getByLabel('Access token', { exact: true }).fill('local-fixture-token-never-use-for-real-ha');
  await page.getByRole('button', { name: 'Connect & import' }).click();
  await expect(page.getByRole('heading', { name: 'Demo lounge lamp', exact: true })).toBeVisible({ timeout: 15000 });
  await expect(page.getByLabel('Access token', { exact: true })).toHaveValue('');
  const lamp = page.locator('.automation-device').filter({ has: page.getByRole('heading', { name: 'Demo lounge lamp', exact: true }) });
  await expect(lamp.getByRole('button', { name: 'Turn on', exact: true })).toBeDisabled();
  await lamp.getByRole('button', { name: 'Allow power control', exact: true }).click();
  await lamp.getByRole('button', { name: 'Turn on', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(lamp.locator('.state')).toHaveText('off');
  await lamp.getByRole('button', { name: 'Turn on', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm turn on' }).click();
  await expect(lamp.locator('.state')).toHaveText('on', { timeout: 10000 });
  await expect(page.locator('.mqtt-state strong')).toContainText('connected', { timeout: 10000 });
  await page.screenshot({ path: artifact + 'automation-desktop.png', fullPage: true });

  const snapshot = await api('automation');
  const current = await api('home');
  const homeId = current.plan.version ? current.plan.home_id : randomUUID();
  const floorId = randomUUID();
  const points = [[0, 0], [9, 0], [9, 8], [0, 8]].map(([x,y]) => ({ x,y }));
  const rooms = [
    { name:'Lounge', polygon:[{x:0,y:0},{x:5,y:0},{x:5,y:4},{x:0,y:4}] },
    { name:'Kitchen', polygon:[{x:5,y:0},{x:9,y:0},{x:9,y:4},{x:5,y:4}] },
    { name:'Office', polygon:[{x:0,y:4},{x:9,y:4},{x:9,y:8},{x:0,y:8}] },
  ].map(r => ({ ...r, room_id:randomUUID() }));
  const walls = points.map((start,i) => ({ wall_id:randomUUID(), start, end:points[(i+1)%4], openings:[] }));
  walls.push({wall_id:randomUUID(),start:{x:0,y:4},end:{x:9,y:4},openings:[]});
  walls.push({wall_id:randomUUID(),start:{x:5,y:0},end:{x:5,y:4},openings:[]});
  await api('home/plan','PUT',{expected_version:current.plan.version,plan:{home_id:homeId,version:current.plan.version,name:'QA demonstration home',floors:[{floor_id:floorId,name:'Ground floor',level:0,ceiling_height_m:2.6,walls,rooms}]}});
  for (const [i, device] of snapshot.devices.entries()) {
    await api(`home/placements/${device.device_id}`,'PUT',{floor_id:floorId,x:[2,7,4][i],y:[2,2,6][i],height_m:1.2,mounting:'shelf'});
  }
  await page.getByRole('button', { name:'Open home map →' }).click();
  await page.getByRole('tab', { name:'3D view', exact:true }).click();
  await expect(page.locator('.home-view canvas')).toBeVisible({timeout:15000});
  await page.waitForTimeout(1500);
  await page.screenshot({path:artifact+'home-3d.png',fullPage:true});
  await page.reload();
  await page.getByRole('button',{name:'Home',exact:true}).first().click();
  await page.getByRole('tab',{name:'3D view',exact:true}).click();
  await expect(page.locator('.home-view canvas')).toBeVisible({timeout:10000});
  const persisted = await api('home');
  expect(persisted.placements).toHaveLength(3);
  expect(persisted.plan.floors[0].rooms).toHaveLength(3);

  await page.setViewportSize({width:390,height:844});
  await page.getByRole('button',{name:'More',exact:true}).click();
  await page.getByRole('button',{name:'Automation',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Your home, connected.'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Demo lounge lamp',exact:true})).toBeVisible({timeout:10000});
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBe(false);
  await page.screenshot({path:artifact+'automation-mobile.png',fullPage:true});
  expect(errors).toEqual([]);
  const network = await api('state');
  expect(network.service_status).toBe('ready');
  const result = { checked_at:new Date().toISOString(), native_service:true, simulated_ha_devices:snapshot.devices.length,
    simulated_power_command:'observed on after confirmation', mqtt:snapshot.mqtt.status,
    persisted_rooms:3,persisted_device_placements:3,mobile_overflow:overflow,page_errors:errors,
    live_network_device_count:network.devices.length, collector_status:network.service_status };
  await writeFile(artifact+'result.json',JSON.stringify(result,null,2));
  console.log(JSON.stringify(result));
} finally { await browser.close(); }
