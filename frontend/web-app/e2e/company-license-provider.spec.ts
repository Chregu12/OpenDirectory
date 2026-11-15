import { test, expect, type Page } from '@playwright/test';
import { mockApi, seedAuth, actor, tenant } from './fixtures/api';

const cloud = '44444444-4444-4444-8444-444444444444';
const poolId = '55555555-5555-4555-8555-555555555555';
const envelope = { schemaVersion: 1, companyLicenseProviderProtocol: 1, actorUserId: actor, tenantId: tenant, provider: 'microsoft-365' };
async function fixture(page: Page) {
  await seedAuth(page); await mockApi(page); let mode = 'connected'; let reads = 0;
  await page.route('**/api/mfa/company-license-activation', route => route.fulfill({ json: { schemaVersion: 1, scope: 'company-licenses', tenant: { id: tenant, version: '1', generation: '1' }, durations: [3600], requiresFreshMfa: false, activation: null } }));
  await page.route('**/api/licenses/company/**', route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith('/capabilities')) return route.fulfill({ json: { schemaVersion: 1, companyLicenseProtocol: 1, actorUserId: actor, tenantId: tenant, permissions: ['company.apps.read'], allocationMode: 'local-only', supportedTargets: ['user'] } });
    if (path.endsWith('/pools')) return route.fulfill({ json: { schemaVersion: 1, actorUserId: actor, tenantId: tenant, page: 1, limit: 25, total: 1, pools: [{ id: poolId, tenantId: tenant, revision: '1', name: 'Lokaler Editor', vendor: 'Lokaler Anbieter', description: '', totalSeats: 2, usedSeats: 0, availableSeats: 2, licenseType: 'per_user', allocationMode: 'local-only', createdAt: '2026-11-15T10:00:00.000Z', updatedAt: '2026-11-15T10:00:00.000Z' }] } });
    if (path.endsWith('/provider')) {
      reads++;
      if (mode === 'denied') return route.fulfill({ status: 401, json: { error: 'Original source revoked' } });
      return route.fulfill({ json: mode === 'failed' ? { ...envelope, state: 'failed', errorCode: 'graph_capacity_http_403' } : {
        ...envelope, state: 'connected', microsoftTenantId: cloud, checkedAt: '2026-11-15T18:00:00.000Z', products: [{ skuId: cloud, skuPartNumber: 'MICROSOFT_TEST_SKU', appliesTo: 'User', capabilityStatus: 'Enabled', prepaidUnits: { enabled: 12, warning: 2, suspended: 1, lockedOut: 0 }, consumedUnits: 7 }],
      } });
    }
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto('/applications'); await expect(page.getByRole('button', { name: 'Lokaler Editor' })).toBeVisible();
  await page.getByText('Microsoft 365 · Anbieterbestand').click();
  return { reads: () => reads, mode: (value: string) => { mode = value; } };
}

test('reads Microsoft stock only on request and displays an independent mobile-friendly provider inventory', async ({ page }) => {
  const state = await fixture(page); expect(state.reads()).toBe(0);
  await page.getByRole('button', { name: 'Verbindung prüfen' }).click();
  const panel = page.getByRole('region', { name: 'Microsoft-365-Verbindung' });
  await expect(panel.getByRole('heading', { name: 'MICROSOFT_TEST_SKU' })).toBeVisible();
  await expect(panel.getByText('Aktive Einheiten').locator('..')).toHaveText('Aktive Einheiten12');
  await expect(panel.getByText('Verbraucht').locator('..')).toHaveText('Verbraucht7');
  await expect(page.getByRole('button', { name: 'Lokaler Editor' })).toBeVisible(); expect(state.reads()).toBe(1);
  await panel.screenshot({ path: test.info().outputPath('company-provider-desktop.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await panel.screenshot({ path: test.info().outputPath('company-provider-mobile.png') });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test('a cloud denial clears old products while revoked company access also clears the local license view', async ({ page }) => {
  const state = await fixture(page); await page.getByRole('button', { name: 'Verbindung prüfen' }).click();
  await expect(page.getByText('MICROSOFT_TEST_SKU')).toBeVisible(); state.mode('failed');
  await page.getByRole('button', { name: 'Verbindung prüfen' }).click();
  await expect(page.getByText(/Leseberechtigung und Administratorzustimmung/)).toBeVisible();
  await expect(page.getByText('MICROSOFT_TEST_SKU')).toHaveCount(0); await expect(page.getByRole('button', { name: 'Lokaler Editor' })).toBeVisible();
  state.mode('denied'); await page.getByRole('button', { name: 'Verbindung prüfen' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Die Sitzung ist nicht mehr gültig' })).toContainText('Die Sitzung ist nicht mehr gültig');
  await expect(page.getByRole('button', { name: 'Lokaler Editor' })).toHaveCount(0);
});
