import { test, expect } from '@playwright/test';
import { seedAuth, mockApi, actor, tenant, deviceId } from './fixtures/api';
const ouId = '44444444-4444-4444-8444-444444444444', eventId = '55555555-5555-4555-8555-555555555555';
const ou = { id: ouId, generation: '2', revision: '3', name: 'Engineering devices', parentId: null };
for (const width of [390, 1440]) test(`own device OU selection, removal and retained history at ${width}px`, async ({ page }) => {
  await page.setViewportSize({ width, height: 1000 }); await seedAuth(page); await mockApi(page);
  const base = '/api/devices/' + deviceId + '/organizational-unit';
  let record: any = { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId, deviceRevision: '1', revision: '0', ou: null, updatedAt: null, updatedBy: null };
  const events: any[] = [], writes: any[] = [];
  let currentOu = { ...ou };
  await page.route(/\/api\/devices\/.*organizational-unit/, async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    if (path === '/api/devices/organizational-units') return route.fulfill({ json: { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, page: 1, limit: 25, total: 1, units: [ou] } });
    if (path.endsWith('/history')) return route.fulfill({ json: { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId, page: 1, limit: 25, total: events.length, events: [...events].reverse() } });
    if (path.endsWith('/status')) {
      expect(req.headers()['if-match']).toBe(`"device-ou-${deviceId}-1-${record.revision}"`);
      return route.fulfill({ json: { schemaVersion: 1, deviceOuStatusProtocol: 1, actorUserId: actor, tenantId: tenant, deviceId, deviceRevision: '1', revision: record.revision,
        selection: record.ou ? { id: ouId, generation: ou.generation } : null, state: record.ou ? currentOu.revision === record.ou.revision ? 'current' : 'changed' : 'unassigned', currentOu: record.ou ? currentOu : null, checkedAt: new Date().toISOString(), validUntil: Math.floor(Date.now() / 1000) + 60 } });
    }
    if (req.method() === 'GET') return route.fulfill({ headers: { etag: `"device-ou-${deviceId}-1-${record.revision}"` }, json: record });
    const body = req.postDataJSON(), old = record;
    expect(req.method()).toBe('PUT'); expect(req.headers()['if-match']).toBe(`"device-ou-${deviceId}-1-${record.revision}"`); expect(Object.keys(body).sort()).toEqual(['confirm', 'ou', 'reason']);
    writes.push(body); const createdAt = new Date().toISOString(); record = { ...record, revision: String(Number(record.revision) + 1), ou: body.ou ? ou : null, updatedAt: createdAt, updatedBy: actor };
    const snapshot = (value: any) => ({ revision: value.revision, ou: value.ou, updatedAt: value.updatedAt, updatedBy: value.updatedBy });
    events.push({ id: events.length ? ouId : eventId, actorUserId: actor, correlationId: eventId, reason: body.reason, createdAt, before: old.revision === '0' ? null : snapshot(old), after: snapshot(record), deliveryStatus: 'pending' });
    return route.fulfill({ json: { ...record, operationId: eventId, deliveryStatus: 'pending' } });
  });
  await page.goto('/devices'); await page.getByRole('button', { name: 'TEST-001', exact: true }).click();
  const panel = page.getByRole('region', { name: 'Geräte-Organisationseinheit', exact: true });
  await panel.getByRole('button', { name: 'Zuordnung ändern', exact: true }).click(); await panel.getByRole('combobox', { name: 'Organisationseinheit auswählen', exact: true }).selectOption(ouId);
  await panel.getByRole('button', { name: 'OU-Zuordnung prüfen' }).click(); let dialog = page.getByRole('alertdialog');
  await expect(dialog.getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); await dialog.getByLabel('Begründung für OU-Zuordnung').fill('Gerät für diesen Engineering-Arbeitsplatz eingeordnet'); expect(writes).toHaveLength(0);
  await dialog.getByRole('button', { name: 'Bestätigen' }).click(); await expect(panel.getByText('Engineering devices', { exact: true })).toBeVisible(); expect(writes[0].ou).toEqual({ id: ouId, generation: '2', revision: '3' });
  const current = panel.getByRole('region', { name: 'Aktueller OU-Stand', exact: true }); await expect(current.getByText('OU aktuell bestätigt.', { exact: true })).toBeVisible();
  currentOu = { ...ou, name: 'Aktuelle Geräte-OU ' + 'x'.repeat(100), revision: '4' };
  await current.getByRole('button', { name: 'OU-Stand prüfen', exact: true }).click(); await expect(current.getByText('Die OU wurde seit der Zuordnung geändert.', { exact: true })).toBeVisible(); await expect(current).toContainText(currentOu.name); expect(writes).toHaveLength(1);
  await panel.getByRole('button', { name: 'OU-Verlauf', exact: true }).click();
  await expect(panel.getByLabel('OU-Zuordnungsverlauf')).toContainText('Engineering-Arbeitsplatz');
  await panel.scrollIntoViewIfNeeded(); await page.screenshot({ path: test.info().outputPath(`device-ou-${width}.png`), fullPage: true }); expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
  await panel.getByRole('button', { name: 'OU-Zuordnung aufheben' }).click(); dialog = page.getByRole('alertdialog'); await dialog.getByLabel('Begründung für OU-Zuordnung').fill('Gerät aus diesem organisatorischen Bereich zurückgenommen'); await dialog.getByRole('button', { name: 'Bestätigen' }).click();
  await expect(panel.getByText('Keine Organisationseinheit zugeordnet.', { exact: true })).toBeVisible(); expect(writes).toHaveLength(2); expect(writes[1].ou).toBeNull();
});
