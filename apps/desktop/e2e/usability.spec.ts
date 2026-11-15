import { test, expect } from '@playwright/test';

for (const [width, height] of [[1440, 1000], [960, 900], [375, 812], [812, 375]]) {
  test(`offline navigation stays usable at ${width}x${height}`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height });
    await page.route('**/api/v1/**', route => route.fulfill({ status: 503, contentType: 'application/json', body: '{}' }));
    await page.goto('/');
    await expect(page.locator('#main-content')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Network control.' })).toBeVisible();
    await expect(page.locator('.pulse-view > [role=img]')).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath('pulse.png'), fullPage: true });
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('#main-content')).toBeFocused();
    const nav = page.getByRole('navigation', { name: width <= 850 ? 'Mobile navigation' : 'Primary', exact: true });
    await nav.getByRole('button', { name: 'Devices', exact: true }).click();
    await expect(nav.getByRole('button', { name: 'Devices', exact: true })).toHaveAttribute('aria-current', 'page');
    await expect(page.getByText('Live device list unavailable')).toBeVisible();
    await page.getByRole('searchbox', { name: 'Search devices' }).fill('missing');
    await page.getByRole('button', { name: 'Clear filters' }).click();
    await expect(page.getByRole('searchbox')).toHaveValue('');
    if (width <= 850) {
      const more = nav.getByRole('button', { name: 'More' });
      await more.click();
      await expect(more).toHaveAttribute('aria-expanded', 'true');
      await page.keyboard.press('Escape');
      await expect(more).toHaveAttribute('aria-expanded', 'false');
      await expect(more).toBeFocused();
    } else {
      await expect(page.getByText('Live updates unavailable')).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath('devices.png'), fullPage: true });
  });
}
