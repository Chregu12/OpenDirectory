import { test, expect } from '@playwright/test';
import { mockApi, seedAuth } from './fixtures/api';

/**
 * Regression test for the desktop sidebar overlap bug in UnifiLayout.
 *
 * The fixed 240px sidebar takes no space in the layout flow, so the main
 * content column must be offset by the sidebar width on lg+ screens. That
 * offset lived in a `lg:ml-[...]` class, but an inline `marginLeft: 0` on
 * the same element always won (inline styles beat class selectors), pinning
 * the margin to 0 at every breakpoint. The sidebar then physically overlapped
 * the content — e.g. a click on the DevicesView "Treiber" tab landed on the
 * sidebar item behind it.
 *
 * These tests run at an lg width (where the bug manifested) and assert the
 * content is actually offset and the tab is reachable with a normal,
 * actionability-checked click (no force, no <main> scoping trick needed).
 */

test.use({ viewport: { width: 1440, height: 900 } });

test.describe('UnifiLayout desktop sidebar offset', () => {
  test('main content is offset by the sidebar width and is not overlapped', async ({ page }) => {
    await seedAuth(page);
    await mockApi(page);
    await page.goto('/devices');
    await expect(page).toHaveTitle(/Devices/);

    const sidebar = page.locator('aside').first();
    const main = page.getByRole('main');
    await expect(sidebar).toBeVisible();
    await expect(main).toBeVisible();

    const sidebarBox = await sidebar.boundingBox();
    const mainBox = await main.boundingBox();
    expect(sidebarBox).not.toBeNull();
    expect(mainBox).not.toBeNull();

    // The main column must start at (or after) the sidebar's right edge —
    // i.e. no horizontal overlap. Before the fix, mainBox.x was 0.
    expect(mainBox!.x).toBeGreaterThanOrEqual(sidebarBox!.x + sidebarBox!.width - 1);

    // And the offset should equal the sidebar width (240px), sourced from
    // the computed margin-left of the offset wrapper.
    const marginLeft = await main.evaluate(
      el => getComputedStyle(el.parentElement as HTMLElement).marginLeft
    );
    expect(marginLeft).toBe('240px');
  });

  test('the DevicesView "Treiber" tab is clickable at desktop width (no overlap)', async ({ page }) => {
    await seedAuth(page);
    await mockApi(page);
    await page.goto('/devices');
    await expect(page).toHaveTitle(/Devices/);

    // A plain click — no force, no scoping. If the sidebar overlapped the
    // tab bar (the bug), this click would hit a sidebar item and navigate
    // away instead of switching the inner tab.
    await page.getByRole('main').getByRole('button', { name: 'Treiber' }).click();
    await expect(page.getByRole('heading', { name: 'Geräte-Treiber' })).toBeVisible();
  });
});
