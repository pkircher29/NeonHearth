import type { Page } from '@playwright/test';

/**
 * Call FIRST in any test that mocks API routes (Playwright matches the most recently registered route first, so the
 * specific mocks registered afterwards win). Every other `/api/**` request is answered locally with 503 instead of
 * falling through the dev server's proxy to a collector that may be running on this machine.
 */
export async function isolateApi(page: Page): Promise<void> {
  await page.route('**/api/**', (route) => route.fulfill({ status: 503, json: { error: 'not mocked by this test' } }));
}

/** Waits for the page to have painted at least two frames and for fonts to load: an assertion-friendly replacement for a fixed sleep before a screenshot. */
export async function settled(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await document.fonts?.ready;
    await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
  });
}
