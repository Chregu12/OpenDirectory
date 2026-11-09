import { test, expect, Page } from '@playwright/test';
import { mockApi, seedAuth, actor } from './fixtures/api';
const groupId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const securityId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const eligibilityId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const other = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
async function pimFixture(page: Page) {
  await seedAuth(page); await mockApi(page);
  const now = new Date().toISOString(); const writes: { path: string; body: any }[] = []; const requests: any[] = [];
  const group = { id: groupId, name: 'Lizenzen', description: 'Lizenzbestand und Benutzerzuweisungen verwalten', role: 'license-administrator', maxDurationSeconds: 36000, configuredMaxDurationSeconds: 36000, enabled: true, protected: false, createdAt: now, canManage: true };
  const eligibility = { id: eligibilityId, userId: actor, role: group.role, reason: 'Independent license task eligibility', maxDurationSeconds: 36000, createdAt: now, expiresAt: new Date(Date.now() + 86400000).toISOString(), revokedAt: null, status: 'eligible' };
  await page.route('**/api/identity/pim/**', async route => {
    const path = new URL(route.request().url()).pathname; const method = route.request().method();
    const json = (value: unknown, status = 200) => route.fulfill({ status, json: value });
    if (method === 'POST') {
      const body = route.request().postDataJSON(); writes.push({ path, body });
      if (path.endsWith('/requests')) {
        const request = { ...body, userId: actor, role: group.role, createdAt: now, deadlineAt: new Date(Date.now() + 86400000).toISOString(), status: 'pending', decidedAt: null, decidedBy: null, approvalExpiresAt: null, assignmentId: null, expiresAt: null };
        requests.push(request); return json(request);
      }
      if (path.endsWith('/eligibilities')) return json({ schemaVersion: 1, groupId, eligibility: { ...eligibility, userId: body.userId, maxDurationSeconds: body.maxDurationSeconds, reason: body.reason, createdAt: now, expiresAt: new Date(Date.parse(now) + body.validForSeconds * 1000).toISOString() } }, 201);
      return json({ error: 'Unexpected mutation in UI test' }, 503);
    }
    if (path.endsWith('/groups')) return json({ schemaVersion: 1, userId: actor, groups: [group, { ...group, id: securityId, name: 'Global Security', description: 'Vollständige Administration', role: 'admin', protected: true }], bindings: [{ groupId, eligibilityId, userId: actor }], standingRoles: ['admin'], canCreate: true, canReview: false, truncated: false });
    if (path.endsWith('/self')) return json({ userId: actor, eligibilities: [eligibility], requests, truncated: false });
    if (path.endsWith('/catalog')) return json({ roles: [{ role: group.role, protected: false, assignable: true, reviewable: true, activationRequired: false, maxDurationSeconds: 36000 }], minDurationSeconds: 60, maxDurationSeconds: 36000, maxEligibilitySeconds: 2592000, approvalWindowSeconds: 300 });
    return json({ error: 'UI fixture endpoint unavailable' }, 503);
  });
  await page.route('**/api/users?*', route => route.fulfill({ json: { users: [{ id: other, username: 'engineering', email: 'engineering@example.test', displayName: 'Engineering User', enabled: true, revision: '1', createdAt: now }], total: 1, page: 1, limit: 25 } }));
  return writes;
}
for (const width of [390, 1440]) {
  test(`simple PIM activation and cancellation at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 }); const writes = await pimFixture(page); await page.goto('/pim');
    await page.getByLabel('Darstellung').selectOption('light');
    const row = page.getByRole('row', { name: 'PIM-Gruppe Lizenzen' }); const activate = row.getByRole('button', { name: 'Aktivieren' });
    await expect(row).toBeVisible(); await expect(page.getByRole('row', { name: 'PIM-Gruppe Global Security' })).toHaveCount(0);
    await page.screenshot({ path: `/private/tmp/od-pim-entra-${width}-light.png` });
    await activate.click(); const dialog = page.getByRole('dialog', { name: 'Aktivieren – Lizenzen' }); await expect(dialog).toBeVisible();
    const box = await dialog.locator('.od-pim-blade').boundingBox(); expect(box && box.x >= 0 && box.x + box.width <= width + 1).toBeTruthy();
    await page.keyboard.press('Escape'); await expect(dialog).toHaveCount(0); await expect(activate).toBeFocused(); expect(writes).toEqual([]);
    await activate.click(); await dialog.getByLabel('Dauer (Stunden)').fill('10'); await dialog.getByLabel('Begründung').fill('Lizenzzuweisungen für Engineering bearbeiten');
    await page.screenshot({ path: `/private/tmp/od-pim-entra-${width}-activate.png` });
    await dialog.getByRole('button', { name: 'Aktivieren', exact: true }).click();
    await expect(page.getByRole('status')).toContainText('wartet auf eine unabhängige Freigabe');
    expect(writes).toHaveLength(1); expect(writes[0].path).toBe('/api/identity/pim/requests');
    expect(writes[0].body).toEqual({ id: expect.any(String), eligibilityId, durationSeconds: 36000, reason: 'Lizenzzuweisungen für Engineering bearbeiten' });
    await expect(page.getByRole('tab', { name: 'Meine Anträge' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('alertdialog')).toHaveCount(0);
    await page.getByRole('tab', { name: 'Aktiv', exact: true }).click(); await expect(page.getByRole('row', { name: 'PIM-Gruppe Global Security' })).toContainText('Direkt aktiv');
    await expect(page.getByRole('row', { name: 'PIM-Gruppe Lizenzen' })).toHaveCount(0);
    await page.getByLabel('Darstellung').selectOption('dark'); await page.screenshot({ path: `/private/tmp/od-pim-entra-${width}-dark.png` });
    expect(await page.locator('body').evaluate(element => element.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
test('user assignment remains separate from activation and binds the selected actual directory user', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 }); const writes = await pimFixture(page); await page.goto('/pim?userId=' + other);
  await expect(page.getByRole('tab', { name: 'Gruppen', exact: true })).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('row', { name: 'PIM-Gruppe Lizenzen' }).getByRole('button', { name: 'Zuweisen' }).click();
  const dialog = page.getByRole('dialog', { name: 'Zuweisung hinzufügen – Lizenzen' });
  await dialog.getByLabel('Benutzer auswählen').selectOption(other); await dialog.getByLabel('Begründung').fill('Engineering unabhängig für Lizenzverwaltung berechtigen');
  await dialog.getByRole('button', { name: 'Weiter', exact: true }).click(); expect(writes).toEqual([]);
  await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen' }).click(); await expect(page.getByRole('status')).toContainText('gespeichert');
  expect(writes).toHaveLength(1); expect(writes[0].path).toBe(`/api/identity/pim/groups/${groupId}/eligibilities`); expect(writes[0].body.userId).toBe(other);
});
test('dashboard presents one set of verified metrics and keeps the simplified PIM entry point', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1100 }); await pimFixture(page); await page.goto('/dashboard');
  await page.getByLabel('Darstellung').selectOption('light');
  await expect(page.getByRole('row', { name: 'PIM-Gruppe Lizenzen' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Systemressourcen' })).toBeVisible();
  const dashboard = page.locator('.od-dashboard');
  await expect(dashboard.locator('.od-dashboard-kpi').getByText('Benutzer', { exact: true })).toHaveCount(1);
  await expect(dashboard.locator('.od-dashboard-kpi').getByText('Geräte', { exact: true })).toHaveCount(1);
  await expect(dashboard.getByRole('heading', { name: 'Letzte Anmeldungen' })).toHaveCount(1);
  await expect(dashboard.getByText('Letzte Aktivitäten', { exact: true })).toHaveCount(0);
  await expect(dashboard.getByText('Apps verbunden', { exact: true })).toHaveCount(0);
  await page.screenshot({ path: '/private/tmp/od-pim-entra-dashboard.png' });
});
