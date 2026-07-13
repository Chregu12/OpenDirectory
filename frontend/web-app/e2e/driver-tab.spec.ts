import { test, expect, type Page, type ConsoleMessage } from '@playwright/test';
import { mockApi, seedAuth, DEVICE_DRIVERS_FIXTURE } from './fixtures/api';

/**
 * Real-browser smoke test for the device drivers UI
 * (src/components/views/tabs/DeviceDriversTab.tsx, rendered as the
 * "Treiber" tab inside src/components/views/DevicesView.tsx at /devices).
 *
 * No real backend is running. Every `/api/**` call is intercepted with
 * page.route() and answered with fixtures (see ./fixtures/api.ts), and the
 * OIDC auth guard in src/app/[view]/page.tsx is bypassed by pre-seeding
 * localStorage the same way a completed login flow would.
 */

function trackConsoleProblems(page: Page) {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];

  page.on('console', (msg: ConsoleMessage) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text());
  });
  page.on('pageerror', (err: Error) => {
    pageErrors.push(err.message);
  });

  return { consoleErrors, pageErrors };
}

async function gotoDriversTab(page: Page) {
  await page.goto('/devices');

  // Sanity-check the auth guard let us through to DevicesView (rather than
  // redirecting to /login) — the document title is set per active view in
  // src/app/[view]/page.tsx.
  await expect(page).toHaveTitle(/Devices/);

  // The DevicesView "Treiber" main-tab toggle. Scope to <main> so we never
  // accidentally match anything in the sidebar; at this viewport the sidebar
  // is off-canvas anyway, so a normal (actionability-checked) click lands on
  // the real tab button and no `force` is needed.
  const driversTab = page.getByRole('main').getByRole('button', { name: 'Treiber' });
  await expect(driversTab).toBeVisible();
  await driversTab.click();

  // Confirm the DeviceDriversTab actually mounted before returning.
  await expect(page.getByRole('heading', { name: 'Geräte-Treiber' })).toBeVisible();
}

test.describe('Device Drivers tab', () => {
  test('renders the installed driver list with no unhandled console errors', async ({ page }) => {
    const { consoleErrors, pageErrors } = trackConsoleProblems(page);
    await seedAuth(page);
    await mockApi(page);

    await gotoDriversTab(page);

    // Heading for the installed-drivers section.
    await expect(page.getByRole('heading', { name: 'Geräte-Treiber' })).toBeVisible();

    // Every fixture driver should render as a row with its name visible.
    for (const driver of DEVICE_DRIVERS_FIXTURE) {
      await expect(page.getByText(driver.name, { exact: true })).toBeVisible();
    }

    // Core action buttons are present.
    await expect(page.getByText('Treiber hochladen')).toBeVisible();
    await expect(page.getByRole('button', { name: /Aus Katalog/ })).toBeVisible();

    // Recommendations panel (search-by-hostname) renders too.
    await expect(
      page.getByRole('heading', { name: 'Treiber-Empfehlungen für ein Gerät' })
    ).toBeVisible();

    await page.screenshot({ path: 'e2e/screenshots/driver-list.png', fullPage: true });

    expect(pageErrors, `Unhandled page errors: ${pageErrors.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Unhandled console.error calls: ${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('renders the empty state when no drivers are installed', async ({ page }) => {
    const { consoleErrors, pageErrors } = trackConsoleProblems(page);
    await seedAuth(page);
    await mockApi(page, { drivers: [] });

    await gotoDriversTab(page);

    await expect(page.getByText('Keine Geräte-Treiber installiert')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Treiber-Katalog öffnen' })).toBeVisible();
    await expect(page.getByText('Treiber hochladen')).toBeVisible();

    await page.screenshot({ path: 'e2e/screenshots/driver-empty-state.png', fullPage: true });

    expect(pageErrors, `Unhandled page errors: ${pageErrors.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Unhandled console.error calls: ${consoleErrors.join('\n')}`).toEqual([]);
  });

  test('opens the driver catalog browser modal', async ({ page }) => {
    const { consoleErrors, pageErrors } = trackConsoleProblems(page);
    await seedAuth(page);
    // mockApi()'s catch-all already answers the catalog's own endpoints
    // (/api/printer/catalog/vendors, /api/printer/catalog/search) with `{}`,
    // which DriverCatalogBrowser handles gracefully (falls back to an empty
    // result set / a hardcoded vendor list).
    await mockApi(page);

    await gotoDriversTab(page);

    await page.getByRole('button', { name: /Aus Katalog/ }).click();

    await expect(page.getByRole('heading', { name: 'Treiber-Katalog' })).toBeVisible();
    await expect(
      page.getByPlaceholder('Suche: "HP LaserJet", "Dell WiFi", "Universal PCL"…')
    ).toBeVisible();

    await page.screenshot({ path: 'e2e/screenshots/driver-catalog-modal.png', fullPage: true });

    expect(pageErrors, `Unhandled page errors: ${pageErrors.join('\n')}`).toEqual([]);
    expect(consoleErrors, `Unhandled console.error calls: ${consoleErrors.join('\n')}`).toEqual([]);
  });
});
