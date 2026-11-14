import { test, expect, type Page } from '@playwright/test';
import { mockApi, seedAuth, actor, tenant, deviceId } from './fixtures/api';

async function fleetFixture(page: Page) {
  await seedAuth(page); await mockApi(page); await page.clock.install({ time: new Date() });
  let denied = false, connected = false, reads = 0;
  const rows = ['connected', 'offline', 'not-enrolled', 'pending'].map((status, i) => ({
    id: i ? `33333333-3333-4333-8333-${String(i).padStart(12, '0')}` : deviceId, tenantId: tenant, assetId: `FLEET-00${i + 1}`, serialNumber: `SER-${i + 1}`, manufacturer: 'Framework', model: 'Laptop 13', deviceClass: 'laptop', platform: 'linux', osVersion: '', ownership: 'corporate', purchaseDate: '', warrantyEnd: '', description: '', revision: '1', lifecycle: 'available', managementMode: 'inventory-only', enrollmentStatus: 'not-enrolled', managementProvider: null, complianceStatus: 'unknown', lastSeen: null, assignedUserId: null, assignmentId: null, createdAt: '2026-01-01T10:00:00.000Z', updatedAt: '2026-01-01T10:00:00.000Z',
  }));
  const statusAt = (i: number) => connected && i === 3 ? 'connected' : ['connected', 'offline', 'not-enrolled', 'pending'][i];
  await page.route(/\/api\/devices(?:\/|\?|$)/, async route => {
    const url = new URL(route.request().url()), json = (data: unknown, status = 200) => route.fulfill({ json: data, status });
    if (url.pathname.includes('/compliance')) return route.fallback();
    if (url.pathname.endsWith('/capabilities')) return json({ schemaVersion: 1, inventoryProtocol: 2, userId: actor, tenantId: tenant, permissions: ['devices.inventory.read', 'devices.inventory.create', 'devices.inventory.assign'], managementMode: 'inventory-only', supportedActions: [] });
    if (url.pathname === '/api/devices/fleet' || url.pathname === '/api/devices/fleet/export') {
      reads += 1; if (denied) return json({ error: 'fresh MFA required' }, 428);
      const selected = rows.map((device, i) => ({ device, status: statusAt(i), index: i })).filter(row => !url.searchParams.has('connectionStatus') || row.status === url.searchParams.get('connectionStatus'));
      if (url.pathname.endsWith('/export')) return route.fulfill({ headers: { 'Content-Type': 'text/csv', 'X-Inventory-Tenant': tenant, 'X-Inventory-Count': String(selected.length) }, body: '\uFEFF"assetId","connectionStatus"\r\n' + selected.map(row => `"${row.device.assetId}","${row.status}"\r\n`).join('') });
      const now = Date.now(), checkedAt = new Date(now).toISOString();
      return json({ schemaVersion: 1, actorUserId: actor, devices: selected.map(row => row.device), total: selected.length, page: Number(url.searchParams.get('page') || 1), limit: 25, fleet: {
        protocol: 1, tenantId: tenant, checkedAt, counts: { total: 4, connected: connected ? 2 : 1, offline: 1, pending: connected ? 0 : 1, 'not-enrolled': 1, expired: 0, revoked: 0 },
        connections: selected.map(row => ({ deviceId: row.device.id, status: row.status, enrolledAt: ['connected', 'offline'].includes(row.status) ? new Date(now - 3600000).toISOString() : null, lastSeen: ['connected', 'offline'].includes(row.status) ? new Date(now - (row.status === 'offline' ? 600000 : 1000)).toISOString() : null, credentialExpiresAt: ['connected', 'offline'].includes(row.status) ? new Date(now + 86400000).toISOString() : null, enrollmentExpiresAt: row.status === 'pending' ? new Date(now + 600000).toISOString() : null, report: ['connected', 'offline'].includes(row.status) ? { hostname: `workstation-${row.index}`, platform: 'linux', architecture: 'x86_64', osVersion: 'Linux', agentVersion: '1.1.0' } : null })),
      } });
    }
    return json({ error: 'Unexpected fixture operation' }, 404);
  });
  return { deny: () => { denied = true; }, connect: () => { connected = true; }, reads: () => reads };
}

test('fleet filters real status, exports the selection and refreshes on desktop and mobile', async ({ page }) => {
  const fixture = await fleetFixture(page); await page.goto('/devices');
  const overview = page.getByRole('region', { name: 'Verbindungsübersicht' }); await expect(overview).toContainText('Geräte gesamt4'); await expect(overview).toContainText('Online1');
  await page.getByLabel('Verbindung filtern').selectOption('offline'); await expect(page.getByRole('button', { name: 'FLEET-002', exact: true })).toBeVisible(); await expect(page.getByRole('button', { name: 'FLEET-001', exact: true })).toHaveCount(0); await expect(overview).toContainText('Geräte gesamt4');
  const exported = page.waitForRequest(request => request.url().includes('/api/devices/fleet/export'));
  await page.getByRole('button', { name: 'CSV exportieren' }).click(); expect(new URL((await exported).url()).searchParams.get('connectionStatus')).toBe('offline'); await expect(page.getByText('CSV-Export bereitgestellt.')).toBeVisible();
  await page.getByLabel('Verbindung filtern').selectOption(''); fixture.connect(); const before = fixture.reads(); await page.clock.fastForward(31000); await expect.poll(() => fixture.reads()).toBeGreaterThan(before); await expect(overview).toContainText('Online2'); await expect(overview).toContainText('Registrierung ausstehend0');
  await page.screenshot({ path: '/private/tmp/od-device-fleet-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await page.screenshot({ path: '/private/tmp/od-device-fleet-mobile.png', fullPage: true }); expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});

test('expiry during automatic refresh clears device data and keeps a return link', async ({ page }) => {
  const fixture = await fleetFixture(page); await page.goto('/devices'); await expect(page.getByRole('button', { name: 'FLEET-001', exact: true })).toBeVisible();
  fixture.deny(); await page.clock.fastForward(31000); await expect(page.getByRole('alert').filter({ hasText: 'fünf Minuten' })).toBeVisible(); await expect(page.getByRole('button', { name: 'FLEET-001', exact: true })).toHaveCount(0);
  await expect(page.getByRole('link', { name: 'Erneut anmelden' })).toHaveAttribute('href', '/api/auth/oidc/login?returnTo=%2Fdevices');
});
