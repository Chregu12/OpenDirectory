import { test, expect, type Page } from '@playwright/test';
import { mockApi, seedAuth, actor, tenant, deviceId } from './fixtures/api';
async function fixture(page: Page, manage = true, staleWrite = false) {
 await seedAuth(page); await mockApi(page); let denied = false; const writes: any[] = [];
 const settings = { enabled: true, maxReportAgeSeconds: 3600, minimumOsVersion: null, requireDiskEncryption: false, requireFirewall: true, minimumDiskFreePercent: null };
 const stamp = new Date(Date.now() - 1000).toISOString(), enrolled = new Date(Date.now() - 3600000).toISOString();
 const permissions = ['devices.compliance.read', ...(manage ? ['devices.compliance.manage'] : [])];
 const policies = ['macos', 'windows', 'linux'].map(platform => ({ tenantId: tenant, platform, revision: '1', settings: { ...settings }, createdAt: stamp, updatedAt: stamp }));
 let effective = 'unknown';
 const assessment = { schemaVersion: 1, tenantId: tenant, deviceId, platform: 'linux', policyRevision: '1', policySettings: settings, evaluatedAt: stamp, validUntil: new Date(Date.now() + 3600000).toISOString(), enrolledAt: enrolled, agentRevision: '3', security: { schemaVersion: 1, facts: { schemaVersion: 1, osVersion: '6.10', diskEncryption: { state: 'unknown', reason: 'not-supported' }, firewall: { state: 'unknown', reason: 'probe-failed' } }, receivedAt: stamp, enrolledAt: enrolled, revision: '3', platform: 'linux', agentVersion: '1.3.0' }, hardware: null, checks: [{ id: 'firewall', status: 'unknown', actual: 'unknown', expected: true, reason: 'probe-failed' }], status: 'unknown', fingerprint: 'a'.repeat(32) };
 await page.route(/\/api\/devices(?:\/|\?|$)/, async route => {
  const req = route.request(), url = new URL(req.url()), path = url.pathname, json = (value: any, status = 200) => route.fulfill({ json: value, status });
  if (denied) return json({ error: 'Fresh MFA required' }, 428);
  const policy = policies.find(value => path.includes('/policies/' + value.platform));
  if (path === '/api/devices/compliance/capabilities') return json({ schemaVersion: 1, complianceProtocol: 1, actorUserId: actor, tenantId: tenant, permissions });
  if (path === '/api/devices/compliance/policies') return json({ schemaVersion: 1, actorUserId: actor, tenantId: tenant, permissions, policies });
  if (req.method() === 'PUT' && policy) {
   const body = req.postDataJSON(); writes.push({ body, etag: req.headers()['if-match'] });
   if (staleWrite) return json({ error: 'Actual policy changed' }, 412);
   policy.settings = body.settings; policy.revision = '2'; policy.updatedAt = new Date().toISOString(); effective = 'pending';
   return json({ schemaVersion: 1, actorUserId: actor, policy, eventId: deviceId, deliveryStatus: 'pending' });
  }
  if (path.endsWith('/history')) return json({ schemaVersion: 1, actorUserId: actor, tenantId: tenant, target: policy?.platform || deviceId, page: 1, limit: 25, total: 1, events: [{ id: deviceId, createdAt: stamp, correlationId: actor, before: null, after: policy || assessment, ...(policy ? { actorUserId: actor, reason: 'Actual company policy reviewed explicitly', deliveryStatus: 'pending' } : {}) }] });
  if (path === '/api/devices/' + deviceId + '/compliance') return json({ schemaVersion: 1, actorUserId: actor, tenantId: tenant, deviceId, assetId: 'COMPLIANCE-001', platform: 'linux', checkedAt: new Date().toISOString(), policyRevision: policies[2].revision, status: effective, assessment });
  if (path === '/api/devices/compliance') {
   const status = url.searchParams.get('status'), platform = url.searchParams.get('platform'), search = url.searchParams.get('search'); const matches = (!platform || platform === 'linux') && (!search || 'COMPLIANCE-001'.toLowerCase().includes(search.toLowerCase()));
   const counts: any = { total: matches ? 1 : 0, compliant: 0, 'non-compliant': 0, unknown: 0, 'not-configured': 0, pending: 0, stale: 0, historical: 0 }; if (matches) counts[effective] = 1;
   const devices = matches && (!status || status === effective) ? [{ deviceId, assetId: 'COMPLIANCE-001', platform: 'linux', status: effective, policyRevision: policies[2].revision, evaluatedAt: stamp }] : [];
   return json({ schemaVersion: 1, actorUserId: actor, tenantId: tenant, checkedAt: new Date().toISOString(), page: 1, limit: 25, total: devices.length, counts, devices });
  }
  return json({ error: 'Unexpected fixture operation' }, 404);
 }); return { writes, deny: () => { denied = true; }, status: (value: string) => { effective = value; } };
}
async function editor(page: Page) { await page.getByRole('button', { name: 'Firmenrichtlinien', exact: true }).click(); await page.getByLabel('Richtlinienplattform').selectOption('linux'); return page.getByRole('region', { name: 'Firmenrichtlinie', exact: true }); }
test('actual policy settings require confirmation and send the current strong version', async ({ page }) => {
 const fixtureState = await fixture(page); await page.goto('/compliance'); await expect(page.getByRole('button', { name: 'COMPLIANCE-001', exact: true })).toBeVisible();
 const section = await editor(page); await section.getByLabel('Systemdatenträger-Verschlüsselung verlangen').check(); await section.getByRole('button', { name: 'Richtlinie speichern', exact: true }).click();
 const confirm = page.getByRole('alertdialog'); await expect(confirm.getByRole('button', { name: 'Bestätigen' })).toBeDisabled(); await confirm.getByLabel('Begründung').fill('Verschlüsselung für Firmenlaptops verlangen'); await confirm.getByRole('button', { name: 'Bestätigen' }).click(); await expect(page.getByText('Richtlinie gespeichert und protokolliert.', { exact: false })).toBeVisible();
 expect(fixtureState.writes).toHaveLength(1); expect(fixtureState.writes[0].etag).toBe(`"device-compliance-${tenant}-linux-1"`); expect(fixtureState.writes[0].body).toMatchObject({ settings: { requireDiskEncryption: true }, confirm: true });
 await page.getByRole('button', { name: 'Geräte', exact: true }).click(); await expect(page.getByRole('table')).toContainText('Neue Meldung ausstehend');
});
test('unknown and historical assessments remain distinct, history and filters work on mobile', async ({ page }) => {
 const state = await fixture(page); await page.goto('/compliance'); await page.getByRole('button', { name: 'COMPLIANCE-001', exact: true }).click(); const panel = page.getByRole('region', { name: 'Geräte-Compliance', exact: true }); await expect(panel).toContainText('Firewall · Unbekannt'); await expect(panel).toContainText('Abfrage fehlgeschlagen');
 await panel.getByText('Bewertungsverlauf', { exact: true }).click(); await expect(panel).toContainText('Geräteagent · Korrelations-ID');
 state.status('historical'); await panel.getByRole('button', { name: 'Compliance aktualisieren' }).click(); await expect(panel).toContainText('Frühere Geräteverbindung'); await expect(panel).toContainText('Eine neue Registrierung übernimmt ihre Bewertung nicht.');
 await page.getByRole('button', { name: 'Neu laden', exact: true }).click(); await page.getByLabel('Bewertung filtern').selectOption('compliant'); await expect(page.getByRole('table')).toContainText('Keine Geräte in dieser Auswahl.'); await page.getByLabel('Bewertung filtern').selectOption('historical'); await expect(page.getByRole('table')).toContainText('COMPLIANCE-001');
 await page.screenshot({ path: test.info().outputPath('od-compliance-desktop.png'), fullPage: true }); await page.setViewportSize({ width: 390, height: 844 }); await page.screenshot({ path: test.info().outputPath('od-compliance-mobile.png'), fullPage: true }); expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
});
test('read duty cannot edit policy and MFA expiry removes previously displayed data', async ({ page }) => {
 const state = await fixture(page, false); await page.goto('/compliance'); const section = await editor(page); await expect(section.getByLabel('Firewall verlangen')).toBeDisabled(); await expect(section.getByRole('button', { name: 'Richtlinie speichern' })).toHaveCount(0); await section.getByText('Änderungsverlauf der Richtlinie', { exact: true }).click(); await expect(section).toContainText('Actual company policy reviewed explicitly');
 state.deny(); await page.getByRole('button', { name: 'Neu laden', exact: true }).click(); await expect(page.getByRole('alert').filter({ hasText: 'fünf Minuten' })).toBeVisible(); await expect(page.getByRole('table')).toHaveCount(0); await expect(page.getByRole('link', { name: 'Erneut anmelden' })).toHaveAttribute('href', '/api/auth/oidc/login?returnTo=%2Fcompliance'); expect(state.writes).toHaveLength(0);
});
test('stale policy conflict is displayed without repeating the command', async ({ page }) => {
 const state = await fixture(page, true, true); await page.goto('/compliance'); const section = await editor(page); await section.getByLabel('Firewall verlangen').uncheck(); await section.getByLabel('Minimale Betriebssystemversion').fill('6.10'); await section.getByRole('button', { name: 'Richtlinie speichern' }).click(); const confirm = page.getByRole('alertdialog'); await confirm.getByLabel('Begründung').fill('Betriebssystem nach neuer Vorgabe prüfen'); await confirm.getByRole('button', { name: 'Bestätigen' }).click(); await expect(section.getByRole('alert')).toContainText('Neu laden'); await expect(page.getByRole('alertdialog')).toHaveCount(0); expect(state.writes).toHaveLength(1);
});
