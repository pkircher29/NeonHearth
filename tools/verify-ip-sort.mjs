import { readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../apps/desktop/package.json', import.meta.url));
const { chromium, expect } = require('@playwright/test');
const connection = JSON.parse(process.env.NEONHEARTH_CONNECTION_STDIN === '1'
  ? require('node:fs').readFileSync(0, 'utf8')
  : await readFile(process.env.NEONHEARTH_QA_CONNECTION || new URL('../.local/runtime/connection.json', import.meta.url), 'utf8'));
const browser = await chromium.launch({ executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe' });
try {
  const page = await browser.newPage({ viewport:{width:1500,height:1000} });
  const errors=[];
  page.on('pageerror', error=>errors.push(error.message));
  await page.goto(connection.url+'/#token='+connection.token);
  await expect.poll(()=>page.url()).toBe(connection.url+'/');
  await page.getByRole('button',{name:'Devices',exact:true}).first().click();
  const sort = page.getByRole('combobox',{name:'Sort devices'});
  await expect(sort).toHaveValue('ip-asc');
  const ipv4Values=async()=>page.locator('.device-card p.addresses:first-of-type').evaluateAll(rows=>rows.flatMap(row=>{
    const match=row.textContent.match(/(?:\d{1,3}\.){3}\d{1,3}/);
    return match ? [match[0].split('.').reduce((sum,byte)=>sum*256+Number(byte),0)] : [];
  }));
  await expect.poll(async()=>(await ipv4Values()).length).toBeGreaterThan(10);
  let values=await ipv4Values();
  expect(values).toEqual([...values].sort((a,b)=>a-b));
  await sort.selectOption('ip-desc');
  values=await ipv4Values();
  expect(values).toEqual([...values].sort((a,b)=>b-a));
  await sort.selectOption('ip-asc');
  await page.screenshot({path:new URL('../artifacts/home-hub-verification/ip-sort.png',import.meta.url).pathname.replace(/^\/(.:)/,'$1')});
  await page.setViewportSize({width:390,height:844});
  await expect(sort).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth)).toBe(false);
  expect(errors).toEqual([]);
  const result={checked_at:new Date().toISOString(),numeric_ipv4_cards:values.length,ascending:true,descending:true,mobile_overflow:false,page_errors:errors};
  await writeFile(new URL('../artifacts/home-hub-verification/ip-sort.json',import.meta.url),JSON.stringify(result,null,2));
  console.log(JSON.stringify(result));
} finally { await browser.close(); }
