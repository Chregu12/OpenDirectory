import type { Page, Route } from '@playwright/test';
export const actor='11111111-1111-4111-8111-111111111111', tenant='22222222-2222-4222-8222-222222222222', deviceId='33333333-3333-4333-8333-333333333333';
const person={id:actor,username:'testperson',email:'person@example.test',displayName:'Test Person',enabled:true,revision:'1',createdAt:'2026-01-01T10:00:00.000Z'};
const device={id:deviceId,tenantId:tenant,assetId:'TEST-001',serialNumber:'SER-001',manufacturer:'Test',model:'Laptop',deviceClass:'laptop',platform:'linux',osVersion:'',ownership:'corporate',purchaseDate:'',warrantyEnd:'',description:'',revision:'1',lifecycle:'available',managementMode:'inventory-only',enrollmentStatus:'not-enrolled',managementProvider:null,complianceStatus:'unknown',lastSeen:null,assignedUserId:null,assignmentId:null,createdAt:'2026-01-01T10:00:00.000Z',updatedAt:'2026-01-01T10:00:00.000Z'};
export async function seedAuth(page:Page){await page.addInitScript(()=>localStorage.setItem('od_onboarded','true'));}
export async function mockApi(page:Page){
 let licenses:any[]=[];let assignments:any[]=[];
 await page.context().route('**/*',route=>{const url=new URL(route.request().url());return url.hostname==='127.0.0.1'||url.hostname==='localhost'?route.continue():route.abort();});
 await page.route(/\/(api\/|oauth\/|saml\/|\.well-known\/|health(?:\/|$))/,async(route:Route)=>{
  const url=new URL(route.request().url()),p=url.pathname,m=route.request().method(),body=()=>route.request().postDataJSON();
  const json=(value:unknown,status=200)=>route.fulfill({status,json:value});
  if(p==='/api/auth/oidc/session')return json({access_token:'fixture-only-token',expires_at:Date.now()+3600000,user:{id:actor,name:'Test Person',username:'testperson',email:person.email,roles:['admin'],role:'admin'}});
  if(p==='/api/platform/capabilities')return json({configuredServices:['app-store']});
  if(p==='/api/identity/access')return json({subject:'fixture',userId:actor,permissions:['users.read','users.create','groups.read','groups.create','organization.read','ous.read','licenses.users.read'],demoMode:false,companyOwner:true,directoryReadProtocol:1,directoryCreationProtocol:1,directoryUserMutationProtocol:1,directoryGroupMutationProtocol:1});
  if(p==='/api/config/modules')return json(Object.fromEntries(['monitoring-analytics','secrets-management','device-management','network-infrastructure','security-suite'].map(id=>[id,{enabled:true,name:id,description:''}])));
  if(p==='/api/auth/audit/login-history')return json({history:[]});
  if(p==='/api/users')return json({users:[person],total:1,page:Number(url.searchParams.get('page')||1),limit:25});
  if(p===`/api/users/${actor}`)return json(person);
  if(p==='/api/devices/capabilities')return json({schemaVersion:1,inventoryProtocol:1,userId:actor,tenantId:tenant,permissions:['devices.inventory.read','devices.inventory.create','devices.inventory.assign'],managementMode:'inventory-only',supportedActions:[]});
  if(p==='/api/devices')return json({schemaVersion:1,actorUserId:actor,devices:[device],total:1,page:1,limit:25});
  if(p===`/api/devices/${deviceId}`)return json(device);
  if(p===`/api/devices/${deviceId}/history`)return json({schemaVersion:1,actorUserId:actor,deviceId,events:[],total:0,page:1,limit:25});
  if(p==='/api/licenses/access')return json({subject:actor,identityState:'active',permissions:['licenses.catalog.read','licenses.catalog.manage','licenses.assignments.read','licenses.assignments.manage'],demoMode:false});
  if(p==='/api/licenses'&&m==='GET')return json({licenses,total:licenses.length});
  if(p==='/api/licenses'&&m==='POST'){const entry={...body(),id:'55555555-5555-4555-8555-555555555555',used_seats:0,created_at:'2026-01-01T00:00:00Z'};licenses=[...licenses,entry];return json(entry,201);}
  if(p==='/api/licenses/requests')return json({requests:[]});
  if(p==='/api/licenses/groups')return json({groups:[]});if(p==='/api/licenses/users')return json({users:[]});
  if(p.match(/^\/api\/licenses\/[^/]+\/assignments$/)&&m==='GET')return json({assignments,total:assignments.length});
  if(p.match(/^\/api\/licenses\/[^/]+\/assign$/)&&m==='POST'){const record={...body(),id:'66666666-6666-4666-8666-666666666666',license_id:licenses[0].id,sources:[{type:'direct',id:'direct'}]};assignments=[record];licenses[0].used_seats=1;return json(record,201);}
  if(p==='/api/store/catalog')return json({apps:[],total:0,page:1,totalPages:0});
  if(p==='/api/services')return json([]);
  if(p==='/api/gateway/access')return json({subject:'fixture',permissions:['gateway.status.read','gateway.webhooks.read','gateway.webhooks.manage','gateway.keys.read'],webhooks:{allowedOrigins:[]}});
  if(p==='/api/gateway/webhooks'||p==='/api/gateway/api-keys')return json([]);
  if(p==='/oauth/federation/providers')return json({providers:[]});
  if(p==='/.well-known/openid-configuration')return json({issuer:url.origin,authorization_endpoint:url.origin+'/oauth/authorize',token_endpoint:url.origin+'/oauth/token',jwks_uri:url.origin+'/jwks'});
  return json({error:'Fixture endpoint not configured'},503);
 });
}
