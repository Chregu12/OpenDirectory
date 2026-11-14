import {test,expect} from '@playwright/test';
import {mockApi,seedAuth} from './fixtures/api';
test('confirmed inventory is distinct from device management', async ({page}) => {
  await seedAuth(page); await mockApi(page); await page.goto('/devices');
  await page.getByText('Inventar und Geräteverwaltung').click();
  await expect(page.getByText('Compliance bleibt bis zur Richtlinienprüfung unbekannt.', { exact: false })).toBeVisible();
  await page.getByRole('button', {name:'TEST-001'}).click();
  await expect(page.getByRole('region', {name:'Geräteverbindung'}).getByText('Nicht verbunden', {exact:true})).toBeVisible();
  await expect(page.getByRole('article', {name:'Gerätedetails'})).toContainText('Noch keine Systemdaten gemeldet.');
});
