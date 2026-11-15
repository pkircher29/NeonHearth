import {test,expect} from '@playwright/test';
import {installHomeFixture} from './fixtures/home';

test('owner sees separate household WAN readings and can open the supported Traffic setup',async({page},info)=>{
  const errors:string[]=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.route('**/api/v1/**',route=>route.fulfill({status:503,json:{error:'optional fixture source unavailable'}}));
  await installHomeFixture(page);
  let routerStatus='ready';
  let failedRefresh=false;
  await page.route('**/api/v1/network/monitor?*',route=>failedRefresh
    ? route.fulfill({status:503,json:{error:'fixture router source unavailable'}})
    : route.fulfill({json:{
    settings:{discovery_enabled:false,interval_seconds:120,router_ip:'192.168.1.1',router_port:8080},
    router:{status:routerStatus,observed_at:new Date().toISOString(),source:'192.168.1.1:8080',download:2500000,upload:125000,connected_devices:2},
    discovery:{state:'idle',started_at:null,finished_at:null,total:0,completed:0,responding:0,errors:0,skipped_networks:0},
    devices:[],events:[],points:[],bucket_seconds:1,
  }}));
  await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
  const household=page.getByRole('region',{name:'Household internet traffic'});
  await expect(household).toContainText('20 Mbps');
  await expect(household).toContainText('Predator Connect W6');
  await expect(page.getByText('Live readings connected',{exact:true})).toBeVisible();
  await expect(page.getByText('No per-device counter source',{exact:true})).toBeVisible();
  await expect(page.getByText('Unavailable until paired',{exact:true})).toHaveCount(0);
  await expect(page.getByRole('img',{name:/Network hearth:/})).toHaveAttribute('aria-label',/unavailable total/);
  await page.setViewportSize({width:1440,height:1000});
  await page.screenshot({path:info.outputPath('pulse-desktop.png'),fullPage:true});
  for(const width of [320,390,768,1440]){
    await page.setViewportSize({width,height:1000});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    if(width===390)await page.screenshot({path:info.outputPath('pulse-mobile.png'),fullPage:true});
  }
  routerStatus='stale';
  await expect(household).toContainText('No fresh router readings');
  await expect(household.getByText('20 Mbps',{exact:true})).toHaveCount(0);
  routerStatus='ready';
  await expect(household).toContainText('20 Mbps');
  failedRefresh=true;
  await expect(household).toContainText('No fresh router readings');
  await expect(household.getByText('20 Mbps',{exact:true})).toHaveCount(0);
  await page.getByRole('button',{name:'Open Traffic',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Your whole home, connected.'})).toBeVisible();
  await page.getByRole('button',{name:'Network preferences',exact:true}).click();
  await expect(page.getByRole('heading',{name:'Home network collection'})).toBeVisible();
  expect(errors).toEqual([]);
});

test('owner can open Traffic before the first household source request completes',async({page})=>{
  await page.route('**/api/v1/**',route=>route.fulfill({status:503,json:{error:'optional fixture source unavailable'}}));
  await installHomeFixture(page);
  let release:()=>void=()=>{};
  const pending=new Promise<void>(resolve=>release=resolve);
  await page.route('**/api/v1/network/monitor?*',async route=>{
    await pending;
    await route.fulfill({status:503,json:{error:'fixture source unavailable'}});
  });
  await page.goto('/#token=fixture-only-pulse-owner-0000000000000000000');
  try {
    await page.getByRole('button',{name:'Open Traffic',exact:true}).click();
    await expect(page.getByRole('heading',{name:'Your whole home, connected.'})).toBeVisible();
  } finally { release(); }
  await expect(page.getByRole('alert')).toContainText('Network monitoring is unavailable');
});
