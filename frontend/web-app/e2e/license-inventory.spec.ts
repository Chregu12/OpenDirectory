import {test,expect} from '@playwright/test';
import {mockApi,seedAuth} from './fixtures/api';
test('records an obtained license and assigns one seat to a person',async({page})=>{
 await seedAuth(page);await mockApi(page);await page.goto('/licenses');
 await page.getByRole('button',{name:'Erhaltene Lizenz erfassen'}).click();const dialog=page.getByRole('dialog');
 await dialog.getByLabel('Produktname').fill('Test Suite');await dialog.getByLabel('Hersteller').fill('Example Vendor');
 await dialog.getByLabel('Lizenz-/Vertragsreferenz').fill('CONTRACT-TEST');await dialog.getByLabel('Bestell-/Belegreferenz').fill('ORDER-TEST');await dialog.getByLabel('Lieferant').fill('Test Supplier');
 await dialog.getByLabel('Gekaufte Plätze (Gesamtbestand)').fill('3');await dialog.getByRole('button',{name:'Speichern'}).click();
 await expect(page.getByText('CONTRACT-TEST')).toBeVisible();await page.getByRole('button',{name:'Personen zuweisen'}).click();
 const assignment=page.getByRole('dialog');await assignment.getByRole('combobox',{name:'Person',exact:true}).selectOption({label:'Test Person · testperson'});await assignment.getByRole('button',{name:'Zuweisung prüfen'}).click();await page.getByRole('button',{name:'Bestätigen'}).click();
 await expect(page.getByText(/Lokaler Lizenzplatz bestätigt zugewiesen/)).toBeVisible();await expect(page.getByText(/Zusätzliche Geräte dieser Person/)).toBeVisible();
});

test('filters renewals and exports only the visible inventory', async ({ page }) => {
 await seedAuth(page); await mockApi(page);
 const entry={id:'renewal-pool',name:'Overdue Suite',vendor:'Test Vendor',category:'Software',license_type:'per_user',total_seats:3,used_seats:3,cost_per_seat:'15.00',currency:'CHF',auto_approve:false,renewal_date:'2000-01-01',inventory_details:{reference:'CONTRACT-OVERDUE'}};
 await page.route('**/api/licenses', route => route.fulfill({ json:{ licenses:[entry,{...entry,id:'future-pool',name:'Future Suite',used_seats:1,renewal_date:'2099-01-01',inventory_details:{reference:'CONTRACT-FUTURE'}}],total:2} }));
 await page.goto('/licenses');
 await page.getByRole('button',{name:'Erneuerungen ansehen'}).click();
 await expect(page.getByText('Overdue Suite',{exact:true})).toBeVisible();
 await expect(page.getByText('Future Suite',{exact:true})).toHaveCount(0);
 const downloadPromise=page.waitForEvent('download');
 await page.getByRole('button',{name:'CSV exportieren'}).click();
 const download=await downloadPromise;
 expect(download.suggestedFilename()).toMatch(/^lizenzbestand-.*\.csv$/);
 const stream=await download.createReadStream(); if(!stream) throw new Error('No CSV stream');
 let csv='';for await(const part of stream) csv+=part.toString('utf8');
 expect(csv).toContain('CONTRACT-OVERDUE');expect(csv).not.toContain('CONTRACT-FUTURE');
 await page.getByRole('button',{name:'Filter zurücksetzen'}).click();
 await page.getByRole('combobox',{name:'Platzverfügbarkeit'}).selectOption('available');
 await expect(page.getByText('Future Suite',{exact:true})).toBeVisible();
 await expect(page.getByText('Overdue Suite',{exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:'Filter zurücksetzen'}).click();
 await page.setViewportSize({width:1440,height:1000});
 await page.screenshot({path:'/private/tmp/opendirectory-license-renewals.png',fullPage:true});
});

test('catalog deletion waits for confirmation', async ({ page }) => {
 await seedAuth(page);await mockApi(page);
 let deleted=false;
 const entry={id:'delete-pool',name:'Disposable Contract',vendor:'Test Vendor',category:'Software',license_type:'per_user',total_seats:1,used_seats:0,auto_approve:false};
 await page.route('**/api/licenses',route=>route.fulfill({json:{licenses:deleted?[]:[entry]}}));
 await page.route('**/api/licenses/delete-pool',route=>{deleted=true;return route.fulfill({status:204});});
 await page.goto('/licenses');
 await page.getByRole('button',{name:'Lizenz Disposable Contract entfernen'}).click();
 expect(deleted).toBe(false);
 await page.getByRole('alertdialog',{name:'Lizenzeintrag löschen'}).getByRole('button',{name:'Abbrechen'}).click();
 expect(deleted).toBe(false);
 await page.getByRole('button',{name:'Lizenz Disposable Contract entfernen'}).click();
 await page.getByRole('alertdialog',{name:'Lizenzeintrag löschen'}).getByRole('button',{name:'Bestätigen'}).click();
 await expect(page.getByText('Disposable Contract',{exact:true})).toHaveCount(0);expect(deleted).toBe(true);
});
