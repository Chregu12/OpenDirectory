import { expect, test } from '@playwright/test';
import { VIEWS } from '../src/lib/views';
import { mockApi, seedAuth } from './fixtures/api';

test.use({ viewport: { width: 1280, height: 900 } });

// This checks that every registered deep link renders the shared shell when
// unavailable services return errors. It does not prove provider capabilities.
for (const view of VIEWS) {
  test(`registered route /${view.id} renders without an uncaught error`, async ({ page }) => {
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await seedAuth(page);
    await mockApi(page);
    await page.goto(`/${view.id}`);
    await expect(page.getByRole('navigation', { name: 'Hauptbereiche' })).toBeVisible();
    await expect(page.locator('main').first()).toBeVisible();
    await expect(page).toHaveTitle(`${view.name} — OpenDirectory`);
    expect(errors).toEqual([]);
  });
}
