import {test,expect} from '@playwright/test';
for(const width of [1440,375]){
 test(`traffic scope sample preview at ${width}px`,async({page},info)=>{
  await page.setViewportSize({width,height:900});
  await page.goto('/e2e/fixtures/traffic-scope.html');
  await expect(page.getByRole('img')).toHaveAttribute('aria-label',/60 samples, shared scale 41 Mbps/);
  await expect(page.locator('path.trace')).toHaveCount(2);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:info.outputPath('scope.png'),fullPage:true});
 });
}
