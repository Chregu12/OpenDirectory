import {test,expect} from '@playwright/test';
import {mockApi,seedAuth} from './fixtures/api';
for(const width of [320,768,1280,1920])test(`navigation remains usable at ${width}px`,async({page})=>{
 await page.setViewportSize({width,height:900});await seedAuth(page);await mockApi(page);await page.goto('/devices');
 await expect(page.getByRole('heading',{name:'Geräteinventar'})).toBeVisible();
 const nav=page.getByRole('navigation',{name:'Hauptbereiche'});await expect(nav.getByRole('button',{name:'Devices'})).toHaveAttribute('aria-current','true');
 await expect(nav.getByRole('button',{name:'People'})).toBeVisible();
 if(width>=1024){const side=await page.locator('aside').boundingBox(),main=await page.locator('main').boundingBox(),header=await page.locator('header').first().boundingBox();expect(side&&main&&header).toBeTruthy();expect(main!.x).toBeGreaterThanOrEqual(side!.x+side!.width-1);expect(side!.y).toBeGreaterThanOrEqual(header!.y+header!.height-1);}
 else{await page.getByRole('button',{name:'Navigation öffnen'}).click();await expect(page.getByRole('dialog',{name:'Hauptnavigation'}).getByRole('navigation',{name:'Bereichsnavigation'})).toBeVisible();await page.keyboard.press('Escape');await expect(page.getByRole('dialog',{name:'Hauptnavigation'})).toHaveCount(0);}
});
