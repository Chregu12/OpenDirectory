import { expect, test } from '@playwright/test';
import { actor, deviceId, mockApi, seedAuth } from './fixtures/api';

test('global search opens the selected person in the correct context', async ({ page }) => {
  await seedAuth(page);
  await mockApi(page);
  await page.goto('/devices');
  await page.getByRole('button', { name: 'Globale Suche öffnen' }).click();
  await page.getByRole('combobox', { name: 'Suchbegriff' }).fill('Test Person');
  await page.getByRole('option', { name: 'Person Test Person' }).click();
  await expect(page).toHaveURL(new RegExp(`/users\\?selected=${actor}`));
  await expect(page.getByRole('article', { name: 'Benutzerdetails' })).toContainText('testperson');
});

test('global search opens the selected device in the correct context', async ({ page }) => {
  await seedAuth(page);
  await mockApi(page);
  await page.goto('/users');
  await page.getByRole('button', { name: 'Globale Suche öffnen' }).click();
  await page.getByRole('combobox', { name: 'Suchbegriff' }).fill('TEST-001');
  await page.getByRole('option', { name: 'Gerät TEST-001 · Laptop' }).click();
  await expect(page).toHaveURL(new RegExp(`/devices\\?selected=${deviceId}`));
  await expect(page.getByRole('article', { name: 'Gerätedetails' })).toContainText('SER-001');
});

test('an unavailable password reset is not presented as a success', async ({ page }) => {
  await seedAuth(page);
  await mockApi(page);
  await page.goto('/sspr');
  await page.getByLabel('E-Mail-Adresse').fill('person@example.test');
  await page.getByRole('button', { name: 'Rücksetzlink anfordern' }).click();
  await expect(page.getByRole('status')).toContainText('Die Rücksetzanfrage konnte nicht bestätigt werden');
  await expect(page.getByText('Anfrage angenommen.', { exact: false })).toHaveCount(0);
});

test('theme selection applies and persists after reload', async ({ page }) => {
  await seedAuth(page);
  await mockApi(page);
  await page.goto('/devices');
  const theme = page.getByRole('combobox', { name: 'Darstellung' });
  await theme.selectOption('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  await expect(theme).toHaveValue('dark');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await theme.selectOption('light');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
});
