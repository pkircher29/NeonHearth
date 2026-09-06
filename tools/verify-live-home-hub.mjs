// Read-only acceptance against the user instance. Never sends appliance commands.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(new URL('../apps/desktop/package.json', import.meta.url));
const { chromium, expect } = require('@playwright/test');
const root = fileURLToPath(new URL('../', import.meta.url));
const connection = JSON.parse(await readFile(root + '.local/runtime/connection.json', 'utf8'));
const artifact = root + 'artifacts/home-hub-verification/';
await mkdir(artifact, { recursive: true });
async function api(path, authenticated = true, extra = {}) {
  const response = await fetch(connection.url + '/api/v1/' + path, {
    redirect:'error', signal:AbortSignal.timeout(10000),
    headers:{...(authenticated ? {Authorization:`Bearer ${connection.token}`} : {}), ...extra}
  });
  return {status:response.status, body:response.ok ? await response.json() : null};
}
expect((await api('state', false)).status).toBe(401);
expect((await api('automation', true, {Origin:'https://untrusted.example',Host:new URL(connection.url).host})).status).toBe(403);
const initial = (await api('state')).body;
expect(initial.service_status).toBe('ready');
expect(initial.devices.length).toBeGreaterThan(0);
const addresses = (await api('automation/network')).body;
expect(addresses.status).toBe('ready');
expect(addresses.devices.length).toBeGreaterThan(0);
const withIps = addresses.devices.filter(device=>device.ip_addresses.length > 0);
expect(withIps.length).toBeGreaterThan(0);
const automation = (await api('automation')).body;
expect(automation.status).toBe('disconnected');
expect(automation.devices).toHaveLength(0);
expect(automation.mqtt.status).toBe('connected');
const spec = (await api('openapi.json')).body;
expect(spec.paths['/api/v1/automation/commands'].post.security).toEqual([{bearer_auth:[]}]);
const browser = await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
try {
  const page = await browser.newPage({viewport:{width:1500,height:1000}});
  const errors=[];
  page.on('pageerror', error=>errors.push(error.message));
  await page.goto(connection.url+'/#token='+connection.token);
  await expect.poll(()=>page.url()).toBe(connection.url+'/');
  await page.getByRole('button',{name:'Devices',exact:true}).first().click();
  await expect(page.getByRole('heading',{name:'Know what is home.'})).toBeVisible();
  await expect(page.getByText(addresses.devices[0].mac_addresses[0],{exact:false}).first()).toBeVisible({timeout:10000});
  await page.screenshot({path:artifact+'live-devices.png',fullPage:false});
  await page.getByRole('button',{name:'Automation',exact:true}).first().click();
  await expect(page.getByRole('heading',{name:'Your home, connected.'})).toBeVisible();
  await expect(page.getByText('MQTT hub · connected',{exact:true})).toBeVisible();
  await page.screenshot({path:artifact+'live-automation.png',fullPage:true});
  expect(errors).toEqual([]);
  const result={checked_at:new Date().toISOString(),native_service:true,network_devices:initial.devices.length,
    collector_status:initial.service_status,devices_with_addresses:addresses.devices.length,devices_with_current_ips:withIps.length,unauthenticated_status:401,cross_origin_status:403,
    paired_url_fragment_removed:true,production_fixture_devices:0,mqtt:'connected',page_errors:errors};
  await writeFile(artifact+'live-result.json',JSON.stringify(result,null,2));
  console.log(JSON.stringify(result));
} finally { await browser.close(); }
