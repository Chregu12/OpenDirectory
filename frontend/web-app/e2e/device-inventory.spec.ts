import {test,expect,type Page} from '@playwright/test';
import {randomUUID} from 'node:crypto';
import {mockApi,seedAuth,actor,tenant,deviceId} from './fixtures/api';
async function fixture(page:Page,stale=false){
 await seedAuth(page);await mockApi(page);let unit:any=null;const events:any[]=[],writes:any[]=[];
 const summary=(value:any)=>value?{revision:value.revision,assignedUserId:value.assignedUserId,assignmentId:value.assignmentId}:null;
 await page.route(/\/api\/devices(?:\/|\?|$)/,async route=>{
  const req=route.request(),url=new URL(req.url()),p=url.pathname,m=req.method(),json=(value:any,status=200)=>route.fulfill({status,json:value});
  if(p.endsWith('/capabilities'))return json({schemaVersion:1,inventoryProtocol:2,userId:actor,tenantId:tenant,permissions:['devices.inventory.read','devices.inventory.create','devices.inventory.assign'],managementMode:'inventory-only',supportedActions:[]});
  if(p.endsWith('/export'))return route.fulfill({headers:{'Content-Type':'text/csv; charset=utf-8','X-Inventory-Tenant':tenant,'X-Inventory-Count':unit?'1':'0'},body:'\uFEFF"assetId","model"\r\n'+(unit?'"'+unit.assetId+'","'+unit.model+'"\r\n':'')});
  if(p.endsWith('/history'))return json({schemaVersion:1,actorUserId:actor,deviceId,events:[...events].reverse(),total:events.length,page:1,limit:25});
  if(m==='GET'&&p==='/api/devices'){const show=unit&&(!url.searchParams.has('lifecycle')||url.searchParams.get('lifecycle')===unit.lifecycle);return json({schemaVersion:1,actorUserId:actor,devices:show?[unit]:[],total:show?1:0,page:1,limit:25});}
  if(m==='GET')return json(unit);
  const body=req.postDataJSON();writes.push({body,etag:req.headers()['if-match']});
  if(unit&&(stale||req.headers()['if-match']!==`"device-${deviceId}-${unit.revision}"`))return json({error:'Device changed; reload before retrying'},412);
  const before=unit?{...unit}:null;let type='device.registered';
  if(!unit)unit={...body,id:deviceId,tenantId:tenant,revision:'1',lifecycle:'available',managementMode:'inventory-only',enrollmentStatus:'not-enrolled',managementProvider:null,complianceStatus:'unknown',lastSeen:null,assignedUserId:null,assignmentId:null,createdAt:'2026-01-01T10:00:00.000Z',updatedAt:'2026-01-01T10:00:00.000Z'};
  else{unit={...unit,revision:String(Number(unit.revision)+1),updatedAt:`2026-01-01T10:00:${String(Number(unit.revision)+1).padStart(2,'0')}.000Z`};
   if(p.endsWith('/assignment')){unit.assignedUserId=body.userId;unit.assignmentId=body.userId?randomUUID():null;unit.lifecycle=body.userId?'assigned':'available';type=body.userId?'device.assigned':'device.assignment.released';}
   else if(p.endsWith('/lifecycle')){unit.lifecycle=body.lifecycle;type='device.lifecycle.changed';}
   else{const {reason,confirm,...values}=body;unit={...unit,...values};type='device.updated';}}
  events.push({id:randomUUID(),tenantId:tenant,deviceId,type,version:1,actorUserId:actor,correlationId:randomUUID(),createdAt:unit.updatedAt,before:summary(before),after:summary(unit),deliveryStatus:'pending',...(['device.updated','device.lifecycle.changed'].includes(type)?{reason:body.reason,changes:Object.keys(unit).filter(k=>before[k]!==unit[k]&&!['revision','updatedAt'].includes(k)).map(field=>({field,before:before[field],after:unit[field]}))}:{})});
  return json(unit,before?200:201);
 });return writes;
}
async function create(page:Page){
 await page.goto('/devices');await page.getByRole('button',{name:'Gerät erfassen',exact:true}).click();const dialog=page.getByRole('dialog');
 for(const [label,value] of Object.entries({Inventarnummer:'BROWSER-001',Seriennummer:'BROWSER-SERIAL-001',Hersteller:'Example',Modell:'Laptop'}))await dialog.getByLabel(label,{exact:true}).fill(value);
 await dialog.getByRole('combobox',{name:'Plattform',exact:true}).selectOption('linux');await dialog.getByRole('button',{name:'Im Inventar speichern'}).click();await page.getByRole('button',{name:'BROWSER-001',exact:true}).click();await expect(page.getByRole('article',{name:'Gerätedetails'})).toBeVisible();
}
test('device UI saves metadata, assignments, lifecycle, CSV and audit with exact versions',async({page})=>{
 const writes=await fixture(page);await page.setViewportSize({width:1440,height:1000});await create(page);
 await page.getByRole('button',{name:'Stammdaten bearbeiten'}).click();const edit=page.getByRole('dialog');await edit.getByLabel('Modell',{exact:true}).fill('Reviewed Laptop');await edit.getByLabel('Änderungsbegründung').fill('Modell anhand des Gerätes geprüft');await edit.getByRole('button',{name:'Änderungen speichern'}).click();await expect(page.getByText('Stammdaten gespeichert und protokolliert.')).toBeVisible();
 await page.getByLabel('Benutzer auswählen').selectOption(actor);await page.getByRole('button',{name:'Benutzer zuweisen',exact:true}).click();await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen'}).click();await expect(page.getByText('Inventarzuweisung gespeichert.')).toBeVisible();await expect(page.getByRole('button',{name:'Archivieren',exact:true})).toHaveCount(0);
 await page.getByRole('button',{name:'Zuweisung aufheben',exact:true}).click();await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen'}).click();await expect(page.getByText('Zuweisung aufgehoben.',{exact:true})).toBeVisible();
 for(const action of ['In Wartung nehmen','Archivieren','Wieder bereitstellen']){await page.getByRole('button',{name:action,exact:true}).click();const confirm=page.getByRole('alertdialog');await expect(confirm.getByRole('button',{name:'Bestätigen'})).toBeDisabled();await confirm.getByLabel('Begründung').fill('Bestätigte Änderung des Gerätezustands');await confirm.getByRole('button',{name:'Bestätigen'}).click();await expect(confirm).toHaveCount(0);}
 await expect(page.getByRole('region',{name:'Gerätehistorie'}).getByText('Stammdaten geändert',{exact:true})).toBeVisible();const download=page.waitForEvent('download');await page.getByRole('button',{name:'CSV exportieren'}).click();expect((await download).suggestedFilename()).toBe('opendirectory-devices.csv');
 expect(writes.map(write=>write.etag)).toEqual([undefined,...[1,2,3,4,5,6].map(rev=>`"device-${deviceId}-${rev}"`)]);
 await page.getByLabel('Status filtern').selectOption('retired');await expect(page.getByText('Keine Geräte gefunden.')).toBeVisible();await page.getByLabel('Status filtern').selectOption('available');await expect(page.getByRole('button',{name:'BROWSER-001',exact:true})).toBeVisible();
 await page.screenshot({path:'/private/tmp/opendirectory-devices-desktop.png',fullPage:true});await page.setViewportSize({width:390,height:844});await page.getByRole('button',{name:'BROWSER-001',exact:true}).click();await page.screenshot({path:'/private/tmp/opendirectory-devices-mobile.png',fullPage:true});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
});
test('stale writes stop without retry and keep a return link to devices',async({page})=>{
 const writes=await fixture(page,true);await create(page);await page.getByRole('button',{name:'Archivieren',exact:true}).click();const confirm=page.getByRole('alertdialog');await confirm.getByLabel('Begründung').fill('Veraltete Geräteversion nicht überschreiben');await confirm.getByRole('button',{name:'Bestätigen'}).click();await expect(page.getByRole('alert').filter({hasText:'Das Gerät'})).toContainText('geändert');await expect(page.getByRole('link',{name:'Erneut anmelden'})).toHaveAttribute('href','/api/auth/oidc/login?returnTo=%2Fdevices');expect(writes).toHaveLength(2);
});

test('device agent enrollment and revocation require confirmation and show the actual connection status',async({page})=>{
 await fixture(page);let connection:any={schemaVersion:1,agentProtocol:1,actorUserId:actor,tenantId:tenant,deviceId,revision:'0',status:'not-enrolled',enrolledAt:null,lastSeen:null,credentialExpiresAt:null,enrollmentExpiresAt:null,report:null,history:{total:0,page:1,limit:25,events:[]}};
 const writes:any[]=[];const token='odae_'+'a'.repeat(43);
 await page.route(/\/api\/devices\/[^/]+\/agent(?:\/|\?|$)/,async route=>{
  const request=route.request();if(request.method()==='GET')return route.fulfill({json:connection});
  const action=new URL(request.url()).pathname.endsWith('/issue')?'issue':'revoke';const body=request.postDataJSON();writes.push({action,body,etag:request.headers()['if-match']});
  if(request.headers()['if-match']!==`"agent-${deviceId}-${connection.revision}"`)return route.fulfill({status:412,json:{error:'stale'}});
  const expiresAt=new Date(Date.now()+600000).toISOString();connection={...connection,revision:String(Number(connection.revision)+1),status:action==='issue'?'pending':'revoked',enrollmentExpiresAt:action==='issue'?expiresAt:null};
  return route.fulfill({status:action==='issue'?201:200,json:action==='issue'?{connection,enrollmentToken:token,expiresAt}:connection});
 });
 await create(page);const panel=page.getByRole('region',{name:'Geräteverbindung'});await expect(panel.getByText('Nicht verbunden',{exact:true})).toBeVisible();
 await panel.getByRole('button',{name:'Registrierungscode erstellen'}).click();let dialog=page.getByRole('alertdialog');await expect(dialog.getByRole('button',{name:'Bestätigen'})).toBeDisabled();await dialog.getByLabel('Begründung').fill('Erste Registrierung des Firmenlaptops');await dialog.getByRole('button',{name:'Bestätigen'}).click();
 await expect(panel.getByLabel('Registrierungscode',{exact:true})).toHaveValue(token);await expect(panel.getByText('Registrierung ausstehend',{exact:true})).toBeVisible();await panel.getByRole('button',{name:'Code ausblenden'}).click();await expect(panel.getByLabel('Registrierungscode',{exact:true})).toHaveCount(0);
 connection={...connection,status:'connected',revision:'3',enrolledAt:new Date().toISOString(),lastSeen:new Date().toISOString(),credentialExpiresAt:new Date(Date.now()+86400000).toISOString(),enrollmentExpiresAt:null,report:{hostname:'registered-laptop',platform:'linux',architecture:'x86_64',osVersion:'Linux',agentVersion:'1.1.0'}};
 await panel.getByRole('button',{name:'Verbindungsstatus aktualisieren'}).click();await expect(panel.getByText('Online',{exact:true})).toBeVisible();await expect(panel.getByText('registered-laptop')).toBeVisible();await page.screenshot({path:'/private/tmp/opendirectory-agent-desktop.png',fullPage:true});
 await panel.getByRole('button',{name:'Gerätezugang widerrufen'}).click();dialog=page.getByRole('alertdialog');await dialog.getByLabel('Begründung').fill('Verbindung nach bestätigtem Test widerrufen');await dialog.getByRole('button',{name:'Bestätigen'}).click();await expect(panel.getByText('Zugang widerrufen',{exact:true})).toBeVisible();
 expect(writes.map(write=>write.etag)).toEqual([`"agent-${deviceId}-0"`,`"agent-${deviceId}-3"`]);expect(writes.every(write=>write.body.confirm===true&&write.body.reason.length>=10)).toBe(true);
 await page.setViewportSize({width:390,height:844});await panel.getByRole('heading',{name:'Geräteverbindung',exact:true}).scrollIntoViewIfNeeded();await page.screenshot({path:'/private/tmp/opendirectory-agent-mobile.png',fullPage:true});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
});
