import { test, expect, type Page } from '@playwright/test';
import { mockApi, seedAuth, actor, tenant, device } from './fixtures/api';

async function dashboardFixture(page: Page) {
  await seedAuth(page); await mockApi(page); await page.clock.install({ time: new Date() });
  let denied = false;
  const devices = Array.from({ length: 25 }, (_, index) => ({ ...device, id: `33333333-3333-4333-8333-${String(index).padStart(12, '0')}`, assetId: `DASH-${index}`, serialNumber: `SER-${index}` }));
  await page.route(/\/api\/devices(?:\/|\?|$)/, route => {
    const path = new URL(route.request().url()).pathname;
    if (denied) return route.fulfill({ status: 428, json: { error: 'fresh MFA required' } });
    if (path === '/api/devices/capabilities') return route.fulfill({ json: { schemaVersion: 1, inventoryProtocol: 2, userId: actor, tenantId: tenant, permissions: ['devices.inventory.read'], managementMode: 'inventory-only', supportedActions: [] } });
    if (path === '/api/devices/fleet') return route.fulfill({ json: { schemaVersion: 1, actorUserId: actor, devices, total: 40, page: 1, limit: 25, fleet: {
      protocol: 1, tenantId: tenant, checkedAt: new Date().toISOString(), counts: { total: 40, connected: 8, offline: 3, pending: 2, 'not-enrolled': 27, expired: 0, revoked: 0 },
      connections: devices.map(row => ({ deviceId: row.id, status: 'not-enrolled', enrolledAt: null, lastSeen: null, credentialExpiresAt: null, enrollmentExpiresAt: null, report: null })),
    } } });
    if (path === '/api/devices/compliance') return route.fulfill({ json: { schemaVersion: 1, actorUserId: actor, tenantId: tenant, checkedAt: new Date().toISOString(), page: 1, limit: 25, total: 40,
      counts: { total: 40, compliant: 10, 'non-compliant': 8, unknown: 4, 'not-configured': 6, pending: 5, stale: 4, historical: 3 },
      devices: devices.map((row, index) => ({ deviceId: row.id, assetId: row.assetId, platform: row.platform, status: index < 10 ? 'compliant' : index < 18 ? 'non-compliant' : index < 22 ? 'unknown' : 'pending', policyRevision: '1', evaluatedAt: new Date().toISOString() })),
    } });
    return route.fallback();
  });
  return { deny: () => { denied = true; } };
}

test('dashboard shows complete fleet counts and actual compliance states on desktop and mobile', async ({ page }) => {
  await dashboardFixture(page); await page.goto('/dashboard');
  const card = page.getByRole('group', { name: 'Geräte', exact: true });
  await expect(card).toContainText('40'); await expect(card).toContainText('8 online'); await expect(card).toContainText('3 offline'); await expect(card).toContainText('29 ohne aktive Verbindung');
  const assessment = page.getByRole('region', { name: 'Geräte-Compliance' });
  await expect(assessment.locator('dl > div').filter({ hasText: 'Konform' })).toHaveText('Konform10');
  await expect(assessment.locator('dl > div').filter({ hasText: 'Meldung abgelaufen' })).toHaveText('Meldung abgelaufen4');
  await page.getByText('Geräte nach Plattform', { exact: true }).click(); await expect(page.getByText('Erste 25 von 40 Geräten.')).toBeVisible();
  await card.screenshot({ path: test.info().outputPath('od-dashboard-devices-desktop.png') });
  await assessment.screenshot({ path: test.info().outputPath('od-dashboard-compliance-desktop.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await card.screenshot({ path: test.info().outputPath('od-dashboard-devices-mobile.png') });
  await assessment.screenshot({ path: test.info().outputPath('od-dashboard-compliance-mobile.png') });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test('expired device access clears dashboard counts and assessments on refresh', async ({ page }) => {
  const fixture = await dashboardFixture(page); await page.goto('/dashboard');
  await expect(page.getByText('29 ohne aktive Verbindung')).toBeVisible();
  fixture.deny(); await page.clock.fastForward(31000);
  await expect(page.getByText('29 ohne aktive Verbindung')).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Geräte-Compliance' })).toContainText('fünf Minuten');
  await expect(page.getByRole('region', { name: 'Geräte-Compliance' }).getByText('Konform', { exact: true })).toHaveCount(0);
});
