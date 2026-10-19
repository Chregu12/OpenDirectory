'use strict';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash, generateKeyPairSync } = require('node:crypto');
const { once } = require('node:events');
const { createRequire } = require('node:module');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');
const net = require('node:net');
const { Pool } = require('pg');
const { TokenRevocationStore } = require('../TokenRevocationStore');
const { SigningKeys } = require('../SigningKeys');
const { SessionStore } = require('../SessionStore');
const jwt = require('jsonwebtoken');
const { bootstrapApplications } = require('./fixtures/bootstrapApplications.cjs');
const { nextOtp, rememberFactor } = require('./fixtures/mfa.cjs');
const { totp } = require('../MfaAuthority');
const { provenMfa } = require('../../../../../packages/mfa-authorization-contract');
const { MFA_LOCKED_ROLES } = require('../../../../../packages/directory-role-contract');
const { changeSource } = require('../../../identity-service/scripts/license-user-source-operator');

const schemas = ['oauth', 'identity', 'policy'].map(name => `${name}_revocation_${randomUUID().replaceAll('-', '')}`);
const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 });
const issuer = 'https://revocation.test';
const clientId = 'devportal-od-client';
const clientSecret = 'disposable-revocation-client';
const canonicalUser = randomUUID();
let issuerDb; let identityDb; let policyDb; let Gateway; let gateway; let issuerServer; let identityServer; let policyServer; let credentialServer;
let inventoryFixture;
let issuerBase; let gatewayBase; let identityBase; let policyBase;
let quickBase; let quickProcess; let receiverServer; let receiverBase; let receiverCalls = []; let forbiddenServiceTokens = 0; let joinGate;
let keyDirectory; let firstKeyFile; let secondKeyFile; let previousKeyFile;
const canonicalSubjects = new Map([['operator', canonicalUser], ...['alice', 'bob', 'second-admin', 'session-operator', 'lifecycle', 'pim-manager', 'pim-reviewer', 'app-operator', 'app-reader', 'app-access-manager', 'app-access-reader'].map(name => [name, randomUUID()])]);
const separateTenant=randomUUID();for(const name of ['tenant-session-user','tenant-pending-user','tenant-creation-admin'])canonicalSubjects.set(name,randomUUID());
for(const name of ['mutation-self-reset','mutation-self-disable','mutation-self-delete','mutation-self-withdrawn'])canonicalSubjects.set(name,randomUUID());
canonicalSubjects.set('company-blueprint-reviewer', randomUUID());
canonicalSubjects.set('company-assignment-reviewer', randomUUID());
const credentialRoleOverrides = new Map();
const credentialGroupOverrides = new Map();
for (const username of ['pim-owner-1', 'pim-owner-2', 'pim-owner-3', 'pim-owner-4', 'pim-owner-5', 'mfa-owner', 'mfa-device-owner']) canonicalSubjects.set(username, randomUUID());
for (const username of ['recovery-code-owner', 'recovery-device-owner', 'recovery-identity-owner']) canonicalSubjects.set(username, randomUUID());
canonicalSubjects.set('recovery-redaction-owner', randomUUID());
for (const name of ['auth-policy-admin-1','auth-policy-admin-2','auth-policy-admin-3','auth-policy-admin-4','auth-policy-user-1','auth-policy-user-2','auth-policy-user-3','auth-policy-user-4','auth-policy-manager','auth-policy-reader']) canonicalSubjects.set(name, randomUUID());
for (const name of ['auth-policy-admin-5', 'auth-policy-user-5']) canonicalSubjects.set(name, randomUUID());
let authenticationPolicyNumber = 0;
for (const name of ['role-policy-admin','role-policy-manager','role-policy-reader','role-policy-user','role-policy-pending','role-policy-age']) canonicalSubjects.set(name,randomUUID());
let pimOwnerNumber = 0;
const activationPolicyRoles = new Map([['pim-policy-manager','privileged-access-policy-administrator'],['pim-policy-reader','privileged-access-policy-reader'],['pim-policy-owner','license-manager'],['pim-policy-pending','license-manager'],['pim-policy-foreign-reviewer','pim-approver']]);
for (const name of activationPolicyRoles.keys()) canonicalSubjects.set(name,randomUUID());
const reviewRoles=new Map([['review-config','access-review-administrator'],['review-voter','access-reviewer'],['review-voter-two','access-reviewer'],['review-reader','access-review-reader']]);
for(const name of [...reviewRoles.keys(),'review-target','review-directory-target'])canonicalSubjects.set(name,randomUUID());
const reviewFactors=new Set();
const fulfillmentRoles=new Map([['fulfillment-configurator','license-provider-administrator'],['fulfillment-reader','license-fulfillment-reader'],['fulfillment-operator','license-fulfillment-operator'],['fulfillment-license-admin','license-administrator'],['fulfillment-revoked-config','license-provider-administrator']]);
for(const[name,role]of [['capacity-config','license-provider-administrator'],['capacity-reader','license-fulfillment-reader'],['capacity-license-manager','license-administrator']])fulfillmentRoles.set(name,role);
for(const prefix of ['membership-review','membership-revoked','membership-scope','tenant-group'])for(const[suffix,role]of [['config','group-review-administrator'],['voter','group-reviewer'],['grantor','group-administrator'],['holder','user']])fulfillmentRoles.set(prefix+'-'+suffix,role);
for(const name of ['group-self-remove','group-self-delete','group-self-revoked'])fulfillmentRoles.set(name,'group-administrator');
for(const name of ['production-group-operator','production-foreign-group-operator','production-withdrawn-operator'])fulfillmentRoles.set(name,'group-administrator');
for(const [name,role] of [['users','license-eligibility-reader'],['groups','license-group-reader'],['reviewers','license-review-administrator'],['scope-reviewers','license-delegation-review-administrator'],['delegates','license-scope-administrator'],['publication','policy-administrator']])fulfillmentRoles.set('production-snapshot-'+name,role);
for(const[name,role]of [['production-role-operator','role-administrator'],['production-pim-operator','pim-administrator']])fulfillmentRoles.set(name,role);
fulfillmentRoles.set('production-command-reviewer','pim-approver');fulfillmentRoles.set('production-command-assurance','authentication-policy-administrator');
const authorityCommandKinds=['grant','revoke','eligibility-grant','eligibility-revoke','request','approve','deny','activate','cancel-pending','cancel-active','revoke-active','assurance','issuer-outage'];
for(const kind of [...authorityCommandKinds,'positive-self-change'])canonicalSubjects.set('production-command-'+kind,randomUUID());
for(const name of ['production-global-admin','production-ordinary','production-member','production-foreign-member','production-foreign-extra'])canonicalSubjects.set(name,randomUUID());
canonicalSubjects.set('production-foreign-authority-admin',randomUUID());
fulfillmentRoles.set('license-source-manager','license-manager');
for(const prefix of ['source-refresh','source-cutoff','source-rotation','source-withdrawn'])fulfillmentRoles.set(prefix+'-config','license-scope-administrator');
fulfillmentRoles.set('source-metadata-reader','license-scope-reader');
for (const [name, role] of [['policy-config', 'policy-administrator'], ['policy-read', 'policy-reader'], ['policy-deploy', 'policy-deployment-operator'], ['policy-withdrawn', 'policy-deployment-operator']]) fulfillmentRoles.set(name, role);
for (const name of ['policy-transaction-config','policy-content-config']) fulfillmentRoles.set(name,'policy-administrator');
for (const name of ['policy-first-review','policy-delivery-review','policy-content-review','publication-dml-review','publication-role-review','publication-stop-review','publication-gpo-review']) fulfillmentRoles.set(name,'policy-publication-reviewer');
for (const name of ['publication-dml-config','publication-role-config','publication-stop-config','publication-gpo-config']) fulfillmentRoles.set(name,'policy-administrator');
for(const prefix of ['receiver-raw','receiver-actor-loss','receiver-approval-loss','receiver-pull','receiver-legacy','receiver-cancel','receiver-cancel-revoked','receiver-cancel-audit']){fulfillmentRoles.set(prefix+'-config','policy-administrator');fulfillmentRoles.set(prefix+'-review','policy-publication-reviewer');}
fulfillmentRoles.set('receiver-fresh-admin','admin');
fulfillmentRoles.set('receiver-cancel-admin','admin');
fulfillmentRoles.set('pool-scope-config','license-scope-administrator');
fulfillmentRoles.set('pool-scope-operator','license-delegate');
fulfillmentRoles.set('pool-scope-approver','license-delegate');
fulfillmentRoles.set('pool-scope-revoked-config','license-scope-administrator');
fulfillmentRoles.set('pool-scope-revoked-operator','license-delegate');
for(const prefix of ['scope-pim','scope-pim-revoked','scope-pim-link'])for(const [suffix,role]of [['config','license-scope-administrator'],['operator','license-delegate'],['reviewer','license-scope-activation-reviewer']])fulfillmentRoles.set(prefix+'-'+suffix,role);
for(const prefix of ['pool-policy','pool-policy-revoked'])for(const [suffix,role]of [['config','license-scope-administrator'],['operator','license-delegate'],['reviewer','license-scope-activation-reviewer'],['policy','license-scope-policy-administrator']])fulfillmentRoles.set(prefix+'-'+suffix,role);
for(const prefix of ['authority-review','authority-review-revoked'])for(const [suffix,role]of [['config','license-scope-administrator'],['operator','license-delegate'],['reviewer','license-scope-activation-reviewer'],['policy','license-delegation-review-administrator'],['voter','license-delegation-reviewer']])fulfillmentRoles.set(prefix+'-'+suffix,role);
fulfillmentRoles.set('license-review-config','license-review-administrator');
fulfillmentRoles.set('license-review-voter','license-reviewer');
fulfillmentRoles.set('license-review-reader','license-review-reader');
fulfillmentRoles.set('license-review-config-revocation','license-review-administrator');
fulfillmentRoles.set('license-review-voter-revocation','license-reviewer');
for (const name of [...fulfillmentRoles.keys(),'fulfillment-beneficiary']) canonicalSubjects.set(name,randomUUID());
let identityRequests = 0; let identityRateDenials = 0;
let identityBudget = null;
let issuerWindowStarted=0;let issuerRequests=0;

function databaseUrl(schema) {
  const url = new URL(process.env.OAUTH_TEST_DATABASE_URL);
  url.searchParams.set('options', `-c search_path=${schema},public`);
  url.searchParams.set('application_name', 'od-native-' + schema);
  return url.toString();
}

async function listening(server) {
  if (!server.listening) await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}

async function request(base, route, { method = 'GET', token, body, headers = {}, timeout = 10000 } = {}) {
  const response = await fetch(base + route, { method, signal: AbortSignal.timeout(timeout), headers: {
    ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers },
    ...(body ? { body: JSON.stringify(body) } : {}), redirect: 'manual' }).catch(error => { throw new Error(method + ' ' + route + ': ' + error.message, { cause: error }); });
  if(![204,302].includes(response.status)) assert.ok(response.headers.get('content-type')?.includes('application/json'),`Expected JSON for ${method} ${route} (HTTP ${response.status})`);
  return { status: response.status, headers: response.headers, body: response.status === 204 || response.status === 302 ? null : await response.json() };
}

async function groupRequest(base, route, options = {}) {
  const target = /^\/api\/groups\/([0-9a-f-]+)(?:\/|$)/i.exec(route);
  if (!target || !['POST', 'PUT', 'DELETE'].includes(options.method)) return request(base, route, options);
  const current = (await identityDb.query('SELECT revision FROM groups WHERE id=$1', [target[1]])).rows[0];
  assert.ok(current, 'Explicit fixture group must exist before selecting its current version');
  return request(base, route, { ...options, headers: { 'If-Match': `"group-${target[1]}-${current.revision}"`, ...options.headers } });
}

async function issue(username = 'operator', scope = 'openid roles') {
  const otpCode = await nextOtp(username);
  const login = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: {
    client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username, password: 'disposable-password', scope, ...(otpCode ? { otpCode } : {}) } });
  assert.equal(login.status, 302);
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const pair = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'authorization_code', code, client_id: clientId,
    client_secret: clientSecret, redirect_uri: 'http://localhost:4000/callback' } });
  assert.equal(pair.status, 200);
  return pair.body;
}

async function scopePimFixture(prefix) {
  const config=await firstRoleFactor(prefix+'-config');const operator=await firstRoleFactor(prefix+'-operator');const reviewer=await firstRoleFactor(prefix+'-reviewer');
  const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual scope PIM pool',3) RETURNING id")).rows[0].id;const base='/api/licenses/delegations/pim';
  const configured=await request(gatewayBase,base+'/eligibilities',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get(prefix+'-operator'),duty:'allocator',durationSeconds:3600,maxDurationSeconds:300,reviewerUserIds:[canonicalSubjects.get(prefix+'-reviewer')],reason:'Actual independent resource eligibility',confirm:true}});assert.equal(configured.status,201,JSON.stringify(configured.body));
  const pending=await request(policyBase,base+'/eligibilities/'+configured.body.id+'/requests',{method:'POST',token:operator.access_token,headers:{'If-Match':configured.headers.get('etag')},body:{durationSeconds:60,reason:'Actual canonical just in time scope request',confirm:true}});assert.equal(pending.status,201,JSON.stringify(pending.body));
  return{config,operator,reviewer,poolId,base,configured,pending};
}
test('actual administrative reviews retain bounded authority, invalidate old approvals and independently revoke eligibility without removing business licenses',async()=>{
 const prefix='authority-review';const{config,operator,reviewer,poolId,base,configured,pending}=await scopePimFixture(prefix);const maker=await firstRoleFactor(prefix+'-policy');const voter=await firstRoleFactor(prefix+'-voter');const reviews='/api/licenses/delegations/reviews';const scoped='/api/licenses/scoped/pools/'+poolId;
 const snapshot=await request(gatewayBase,'/api/license-scope-reviewers/'+canonicalSubjects.get(prefix+'-voter')+'/snapshot',{token:maker.access_token});assert.equal(snapshot.status,200,JSON.stringify(snapshot.body));assert.equal(Object.keys(snapshot.body).length,5);assert.equal(snapshot.body.canReview,true);
 assert.equal((await request(gatewayBase,'/api/license-scope-reviewers/'+canonicalSubjects.get(prefix+'-voter')+'/snapshot',{token:operator.access_token})).status,403);assert.equal((await request(policyBase,reviews+'/policies',{method:'POST',token:voter.access_token,body:{}})).status,403);
 assert.equal((await request(gatewayBase,'/api/license-scope-reviewers/'+canonicalSubjects.get(prefix+'-voter')+'/snapshot?roles=admin',{token:maker.access_token})).status,400);assert.equal((await request(identityBase,'/api/users',{token:maker.access_token})).status,403);
 const standing=await request(policyBase,'/api/licenses/delegations',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get(prefix+'-operator'),duty:'allocator',durationSeconds:3600,reason:'Review actual independent standing administrative authority',confirm:true}});assert.equal(standing.status,201);
 const settings={licenseId:poolId,duty:'allocator',targetKind:'grant',intervalSeconds:300,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get(prefix+'-voter')],acknowledgeCutoffs:true,reason:'Bound recurring review of administrative pool rights',confirm:true};
 const created=await request(gatewayBase,reviews+'/policies',{method:'POST',token:maker.access_token,body:settings});assert.equal(created.status,201,JSON.stringify(created.body));assert.equal((await request(policyBase,'/api/licenses',{token:voter.access_token})).status,403);
 const own=await request(gatewayBase,reviews+'/self',{token:operator.access_token});assert.equal(own.status,200);assert.equal(own.body.reviews[0].targetId,standing.body.id);assert.equal(own.body.reviews[0].canRetain,false);
 const assigned=await request(policyBase,reviews+'/assigned',{token:voter.access_token});assert.equal(assigned.status,200);const row=assigned.body.reviews[0];const known=await request(policyBase,reviews+'/'+row.id,{token:voter.access_token});assert.equal(Object.keys(known.body).length,20);
 const decision={decision:'retain',acknowledgeScope:true,reason:'Independent actual administrative recertification',confirm:true};const retained=await request(gatewayBase,reviews+'/'+row.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':known.headers.get('etag')},body:decision});assert.equal(retained.status,200,JSON.stringify(retained.body));assert.equal(retained.body.cycle,'2');assert.equal(retained.body.baseExpiresAt,standing.body.expiresAt);
 assert.equal((await request(policyBase,reviews+'/'+row.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':known.headers.get('etag')},body:decision})).status,412);
 assert.equal((await request(policyBase,scoped+'/assign',{method:'POST',token:operator.access_token,body:{assigneeType:'user',assigneeId:canonicalSubjects.get('fulfillment-beneficiary'),expiresAt:null,reason:'Recertified pool authority allocates only this owned pool',confirm:true}})).status,201);
 const eligibilityPolicy=await request(policyBase,reviews+'/policies',{method:'POST',token:maker.access_token,body:{...settings,targetKind:'eligibility'}});assert.equal(eligibilityPolicy.status,201);
 assert.equal((await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'Earlier request cannot cross the review-origin boundary',confirm:true}})).status,409);
 assert.equal((await request(policyBase,base+'/requests/'+pending.body.id+'/cancel',{method:'POST',token:operator.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{reason:'Retire the request captured before eligibility review',confirm:true}})).status,200);
 assert.equal((await request(policyBase,'/api/licenses/delegations/'+standing.body.id+'/revoke',{method:'POST',token:config.access_token,headers:{'If-Match':standing.headers.get('etag')},body:{reason:'Retire standing authority before independent PIM use',confirm:true}})).status,200);
 const requested=await request(policyBase,base+'/eligibilities/'+configured.body.id+'/requests',{method:'POST',token:operator.access_token,headers:{'If-Match':configured.headers.get('etag')},body:{durationSeconds:300,reason:'New request with the current eligibility review incarnation',confirm:true}});assert.equal(requested.status,201);
 const approved=await request(policyBase,base+'/requests/'+requested.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':requested.headers.get('etag')},body:{decision:'approved',reason:'New independent approval of the reviewed parent',confirm:true}});assert.equal(approved.status,200);
 const active=await request(policyBase,base+'/requests/'+requested.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':approved.headers.get('etag')},body:{reason:'Owner activates a grant capped by its parent review',confirm:true}});assert.equal(active.status,200,JSON.stringify(active.body));
 const queue=await request(policyBase,reviews+'/assigned',{token:voter.access_token});const parent=queue.body.reviews.find(value=>value.targetId===configured.body.id);assert.ok(parent);assert.equal(active.body.grantExpiresAt,parent.deadlineAt);assert.ok(queue.body.reviews.some(value=>value.targetId===active.body.grantId));
 const parentRead=await request(policyBase,reviews+'/'+parent.id,{token:voter.access_token});const denied=await request(policyBase,reviews+'/'+parent.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':parentRead.headers.get('etag')},body:{...decision,decision:'deny'}});assert.equal(denied.status,200,JSON.stringify(denied.body));assert.equal(denied.body.targetVersion,'2');assert.equal((await request(policyBase,scoped,{token:operator.access_token})).status,404);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
});
test('revoking the original administrative reviewer during actual audit DML rolls back target, cycle and evidence',async()=>{
 const prefix='authority-review-revoked';const{config,operator,poolId}=await scopePimFixture(prefix);const maker=await firstRoleFactor(prefix+'-policy');const voter=await firstRoleFactor(prefix+'-voter');const base='/api/licenses/delegations/reviews';
 const standing=await request(policyBase,'/api/licenses/delegations',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get(prefix+'-operator'),duty:'allocator',durationSeconds:3600,reason:'Owned authority before review revocation audit gate',confirm:true}});assert.equal(standing.status,201);
 assert.equal((await request(policyBase,base+'/policies',{method:'POST',token:maker.access_token,body:{licenseId:poolId,duty:'allocator',targetKind:'grant',intervalSeconds:300,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get(prefix+'-voter')],acknowledgeCutoffs:true,reason:'Owned independent review before original caller withdrawal',confirm:true}})).status,201);
 const queued=await request(policyBase,base+'/assigned',{token:voter.access_token});const original=await request(policyBase,base+'/'+queued.body.reviews[0].id,{token:voter.access_token});const gate='authority-review-'+randomUUID();const blocker=await policyDb.getClient();let operation;
 await policyDb.query(`CREATE FUNCTION pause_authority_review() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='deny' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); END IF; RETURN NEW; END $$;CREATE TRIGGER pause_authority_review BEFORE INSERT ON license_scope_review_audit FOR EACH ROW EXECUTE FUNCTION pause_authority_review()`);await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
 try{operation=request(policyBase,base+'/'+original.body.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':original.headers.get('etag')},body:{decision:'deny',acknowledgeScope:true,reason:'Withdrawal by a reviewer losing original issuer authority',confirm:true}});
  let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE license_scope_review_leases SET version=%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(voter.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await operation).status));
  const lease=(await policyDb.query('SELECT version,cycle,state FROM license_scope_review_leases WHERE id=$1',[original.body.id])).rows[0];assert.deepEqual(lease,{version:'1',cycle:'1',state:'pending'});assert.equal((await policyDb.query("SELECT count(*)::int AS count FROM license_scope_review_audit WHERE review_id=$1 AND action='deny'",[original.body.id])).rows[0].count,0);assert.equal((await request(policyBase,'/api/licenses/scoped/pools/'+poolId,{token:operator.access_token})).status,200);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(operation)await operation.catch(()=>{});await policyDb.query('DROP TRIGGER pause_authority_review ON license_scope_review_audit;DROP FUNCTION pause_authority_review()');}
});
test('actual mandatory pool policy fences global and legacy allocation, auto approval and old PIM origins',async()=>{
 const prefix='pool-policy';const{config,operator,reviewer,poolId,base,configured,pending}=await scopePimFixture(prefix);const policymaker=await firstRoleFactor(prefix+'-policy');const root=await issue();
 const route='/api/licenses/delegations/policies/pools/'+poolId+'/allocator';const before=await request(gatewayBase,route,{token:policymaker.access_token});assert.equal(before.status,200);assert.equal(before.body.version,'1');
 const settings={activationRequired:true,maxDurationSeconds:300,preparedEligibilityIds:[configured.body.id],acknowledgeInvalidation:true,reason:'Independently require actual pool PIM on every allocation path',confirm:true};
 const changed=await request(gatewayBase,route,{method:'PUT',token:policymaker.access_token,headers:{'If-Match':before.headers.get('etag')},body:settings});assert.equal(changed.status,200,JSON.stringify(changed.body));assert.equal(changed.body.version,'2');
 const assignment={assignee_type:'user',assignee_id:canonicalSubjects.get('fulfillment-beneficiary')};for(const target of [gatewayBase,policyBase])assert.equal((await request(target,`/api/licenses/${poolId}/assign`,{method:'POST',token:root.access_token,body:assignment})).status,403);
 const{createService}=require('../../../license-management/src/index');const{PolicyLicenseClient}=require('../../../license-management/src/PolicyLicenseClient');const adapter=createService({client:new PolicyLicenseClient({baseUrl:policyBase})}).server;adapter.listen(0,'127.0.0.1');const legacy=await listening(adapter);
 try{assert.equal((await request(legacy,`/api/license/licenses/${poolId}/assign`,{method:'POST',token:root.access_token,body:assignment})).status,403);}finally{await new Promise(resolve=>adapter.close(resolve));}
 await policyDb.query('UPDATE license_catalog SET auto_approve=true WHERE id=$1',[poolId]);const alice=await issue('alice');const regular=await request(policyBase,`/api/licenses/${poolId}/request`,{method:'POST',token:alice.access_token,body:{assignee_type:'user',assignee_id:canonicalSubjects.get('alice'),justification:'Cannot use auto approval to bypass a mandatory resource policy'}});assert.equal(regular.status,201);assert.equal(regular.body.status,'pending');
 assert.equal((await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'Old request must not cross the policy birth boundary',confirm:true}})).status,409);
 assert.equal((await request(policyBase,base+'/requests/'+pending.body.id+'/cancel',{method:'POST',token:operator.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{reason:'Retire the stale original pending activation request',confirm:true}})).status,200);
 const fresh=await request(policyBase,base+'/eligibilities/'+configured.body.id+'/requests',{method:'POST',token:operator.access_token,headers:{'If-Match':configured.headers.get('etag')},body:{durationSeconds:60,reason:'Explicitly request the newly required policy origin',confirm:true}});assert.equal(fresh.status,201);
 const vote=await request(policyBase,base+'/requests/'+fresh.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':fresh.headers.get('etag')},body:{decision:'approved',reason:'Independent approval under the current resource policy',confirm:true}});assert.equal(vote.status,200);
 const active=await request(policyBase,base+'/requests/'+fresh.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':vote.headers.get('etag')},body:{reason:'Owner activates only the current policy incarnation',confirm:true}});assert.equal(active.status,200,JSON.stringify(active.body));
 const scoped='/api/licenses/scoped/pools/'+poolId+'/assign';const allocated=await request(policyBase,scoped,{method:'POST',token:operator.access_token,body:{assigneeType:'user',assigneeId:assignment.assignee_id,expiresAt:null,reason:'Only this actual PIM lease may allocate the protected pool',confirm:true}});assert.equal(allocated.status,201,JSON.stringify(allocated.body));
 const relaxed=await request(policyBase,route,{method:'PUT',token:policymaker.access_token,headers:{'If-Match':changed.headers.get('etag')},body:{...settings,activationRequired:false,preparedEligibilityIds:[],reason:'Explicit relaxation must never revive old scoped authority'}});assert.equal(relaxed.status,200);
 assert.equal((await request(policyBase,scoped,{method:'POST',token:operator.access_token,body:{assigneeType:'user',assigneeId:canonicalSubjects.get('bob'),expiresAt:null,reason:'The old activation may not revive after policy relaxation',confirm:true}})).status,404);
 assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
});
test('revoking the original policy writer during actual policy audit DML rolls back policy and invalidation',async()=>{
 const prefix='pool-policy-revoked';const{config,operator,poolId,configured}=await scopePimFixture(prefix);const policymaker=await firstRoleFactor(prefix+'-policy');const route='/api/licenses/delegations/policies/pools/'+poolId+'/allocator';const before=await request(policyBase,route,{token:policymaker.access_token});assert.equal(before.status,200);
 const standing=await request(policyBase,'/api/licenses/delegations',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get(prefix+'-operator'),duty:'allocator',durationSeconds:60,reason:'Original standing right before atomic policy transition',confirm:true}});assert.equal(standing.status,201);
 const gate='scope-policy-'+randomUUID();const blocker=await policyDb.getClient();let operation;
 await policyDb.query(`CREATE FUNCTION pause_pool_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); RETURN NEW; END $$; CREATE TRIGGER pause_pool_policy BEFORE INSERT ON license_scope_policy_audit FOR EACH ROW EXECUTE FUNCTION pause_pool_policy()`);await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
 try{operation=request(policyBase,route,{method:'PUT',token:policymaker.access_token,headers:{'If-Match':before.headers.get('etag')},body:{activationRequired:true,maxDurationSeconds:300,preparedEligibilityIds:[configured.body.id],acknowledgeInvalidation:true,reason:'A revoked original policy writer cannot commit this boundary',confirm:true}});
  let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO license_scope_activation_policies(%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(policymaker.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await operation).status));
  assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_scope_policy_audit WHERE license_id=$1',[poolId])).rows[0].count,0);assert.equal((await request(policyBase,'/api/licenses/scoped/pools/'+poolId,{token:operator.access_token})).status,200);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(operation)await operation.catch(()=>{});await policyDb.query('DROP TRIGGER pause_pool_policy ON license_scope_policy_audit;DROP FUNCTION pause_pool_policy()');}
});

test('actual resource PIM needs a named independent real-MFA vote and owner activation without acquiring a global license role',async()=>{
  const fixture=await scopePimFixture('scope-pim');const{config,operator,reviewer,poolId,base,configured,pending}=fixture;const scoped='/api/licenses/scoped/pools/'+poolId;
  const evidence=await request(gatewayBase,'/api/license-activation-reviewers/'+canonicalSubjects.get('scope-pim-reviewer')+'/snapshot',{token:config.access_token});assert.equal(evidence.status,200);assert.match(evidence.body.reviewRevision,/^[a-f0-9]{64}$/);assert.equal(Object.keys(evidence.body).length,6);
  assert.equal((await request(policyBase,scoped,{token:operator.access_token})).status,404);
  assert.equal((await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:operator.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'No canonical self approval is permitted',confirm:true}})).status,403);
  const queue=await request(policyBase,base+'/assigned',{token:reviewer.access_token});assert.equal(queue.status,200);assert.equal(queue.body.requests[0].id,pending.body.id);
  const vote=await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'Independent actual resource activation approval',confirm:true}});assert.equal(vote.status,200,JSON.stringify(vote.body));
  assert.equal((await request(policyBase,scoped,{token:operator.access_token})).status,404);
  const active=await request(policyBase,base+'/requests/'+pending.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':vote.headers.get('etag')},body:{reason:'Owner explicitly activates the independently approved resource',confirm:true}});assert.equal(active.status,200,JSON.stringify(active.body));assert.ok(active.body.grantId);
  assert.deepEqual((await request(policyBase,'/api/licenses/access',{token:operator.access_token})).body.permissions,['licenses.delegations.self']);
  const allocation=await request(policyBase,scoped+'/assign',{method:'POST',token:operator.access_token,body:{assigneeType:'user',assigneeId:canonicalSubjects.get('fulfillment-beneficiary'),expiresAt:null,reason:'Allocation only through an active scoped PIM lease',confirm:true}});assert.equal(allocation.status,201);
  assert.equal((await request(policyBase,base+'/eligibilities/'+configured.body.id+'/revoke',{method:'POST',token:config.access_token,headers:{'If-Match':configured.headers.get('etag')},body:{reason:'Retire the parent and end derived administration immediately',confirm:true}})).status,200);
  assert.equal((await request(policyBase,scoped,{token:operator.access_token})).status,404);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
  const inactive=await request(policyBase,base+'/requests/'+active.body.id+'/deactivate',{method:'POST',token:operator.access_token,headers:{'If-Match':active.headers.get('etag')},body:{reason:'Explicitly retire the original activation incarnation',confirm:true}});assert.equal(inactive.status,200);
  const replacement=await request(policyBase,base+'/eligibilities',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get('scope-pim-operator'),duty:'allocator',durationSeconds:3600,maxDurationSeconds:300,reviewerUserIds:[canonicalSubjects.get('scope-pim-reviewer')],reason:'New independently reviewed eligibility after retirement',confirm:true}});assert.equal(replacement.status,201);
  const next=await request(policyBase,base+'/eligibilities/'+replacement.body.id+'/requests',{method:'POST',token:operator.access_token,headers:{'If-Match':replacement.headers.get('etag')},body:{durationSeconds:60,reason:'A fresh request still needs an original reviewer generation',confirm:true}});assert.equal(next.status,201);
  const nextVote=await request(policyBase,base+'/requests/'+next.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':next.headers.get('etag')},body:{decision:'approved',reason:'Approval before the owned missed reviewer lifecycle',confirm:true}});assert.equal(nextVote.status,200);
  await identityDb.write('UPDATE users SET enabled=false WHERE id=$1',[canonicalSubjects.get('scope-pim-reviewer')],'fixture-scope-reviewer-disable');await identityDb.write('UPDATE users SET enabled=true WHERE id=$1',[canonicalSubjects.get('scope-pim-reviewer')],'fixture-scope-reviewer-reactivate');
  const stale=await request(policyBase,base+'/requests/'+next.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':nextVote.headers.get('etag')},body:{reason:'A replacement reviewer incarnation cannot revive approval',confirm:true}});assert.equal(stale.status,409,JSON.stringify(stale.body));
});
test('original issuer withdrawal during actual resource activation audit rolls back the lease and approval consumption',async()=>{
  const{operator,reviewer,base,pending}=await scopePimFixture('scope-pim-revoked');
  const vote=await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'Independent authority before the owned revocation gate',confirm:true}});assert.equal(vote.status,200);
  const gate='scope-pim-'+randomUUID();const blocker=await policyDb.getClient();let operation;
  await policyDb.query(`CREATE FUNCTION pause_scope_pim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='activate' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); END IF; RETURN NEW; END $$; CREATE TRIGGER pause_scope_pim BEFORE INSERT ON license_scope_pim_audit FOR EACH ROW EXECUTE FUNCTION pause_scope_pim()`);
  await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
  try{operation=request(policyBase,base+'/requests/'+pending.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':vote.headers.get('etag')},body:{reason:'A revoked original caller cannot acquire an active resource',confirm:true}});
    let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE license_scope_activation_requests SET status=%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
    assert.equal((await revoke(operator.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await operation).status));
    assert.equal((await policyDb.query('SELECT status FROM license_scope_activation_requests WHERE id=$1',[pending.body.id])).rows[0].status,'approved');assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_scope_grants WHERE activation_request_id=$1',[pending.body.id])).rows[0].count,0);
  }finally{await blocker.query('ROLLBACK');blocker.release();if(operation)await operation.catch(()=>{});await policyDb.query('DROP TRIGGER pause_scope_pim ON license_scope_pim_audit; DROP FUNCTION pause_scope_pim()');}
});

test('actual issuer relinking the same reviewer and holder cannot revive saved scope approval or eligibility',async()=>{
 const{operator,reviewer,base,configured,pending}=await scopePimFixture('scope-pim-link');
 const vote=await request(policyBase,base+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',reason:'Original issuer-linked independent approval',confirm:true}});assert.equal(vote.status,200);
 const relink=async name=>{const userId=canonicalSubjects.get(name);const original=(await identityDb.query('SELECT subject FROM identity_subject_links WHERE user_id=$1 AND issuer=$2',[userId,issuer])).rows[0];await identityDb.write('DELETE FROM identity_subject_links WHERE user_id=$1 AND issuer=$2',[userId,issuer],'fixture-scope-unlink');await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,original.subject,userId],'fixture-scope-relink');};
 await relink('scope-pim-link-reviewer');const activation=await request(policyBase,base+'/requests/'+pending.body.id+'/activate',{method:'POST',token:operator.access_token,headers:{'If-Match':vote.headers.get('etag')},body:{reason:'A re-created issuer link cannot revive the old approval',confirm:true}});assert.equal(activation.status,409,JSON.stringify(activation.body));
 await relink('scope-pim-link-operator');assert.equal((await request(policyBase,base+'/self',{token:operator.access_token})).status,401);const fresh=await issue('scope-pim-link-operator');const self=await request(policyBase,base+'/self',{token:fresh.access_token});assert.equal(self.status,200);assert.equal(self.body.eligibilities[0].id,configured.body.id);assert.equal(self.body.eligibilities[0].state,'stale');
 assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_scope_grants WHERE activation_request_id=$1',[pending.body.id])).rows[0].count,0);
});

test('actual pool delegation never becomes a global license role and separates allocation from approval', async () => {
  const config=await firstRoleFactor('pool-scope-config');const operator=await firstRoleFactor('pool-scope-operator');const approver=await firstRoleFactor('pool-scope-approver');
  const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats,cost_per_seat,notes) VALUES('Delegated issuer pool',3,17.00,'private fixture note') RETURNING id")).rows[0].id;
  const foreign=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Other issuer pool',3) RETURNING id")).rows[0].id;const base='/api/licenses/delegations';
  const create=async(licenseId,userId,duty)=>request(policyBase,base,{method:'POST',token:config.access_token,body:{licenseId,userId,duty,durationSeconds:3600,reason:'Actual independent resource-scoped delegation',confirm:true}});
  const granted=await create(poolId,canonicalSubjects.get('pool-scope-operator'),'allocator');assert.equal(granted.status,201,JSON.stringify(granted.body));
  const snapshot=await request(gatewayBase,'/api/license-delegates/'+canonicalSubjects.get('pool-scope-operator')+'/snapshot',{token:config.access_token});assert.equal(snapshot.status,200);assert.equal(Object.keys(snapshot.body).length,6);
  const access=await request(policyBase,'/api/licenses/access',{token:operator.access_token});assert.deepEqual(access.body.permissions,['licenses.delegations.self']);
  const scoped='/api/licenses/scoped/pools/';const read=await request(gatewayBase,scoped+poolId,{token:operator.access_token});assert.equal(read.status,200);assert.equal(Object.keys(read.body).length,6);assert.equal(read.body.cost_per_seat,undefined);assert.equal(read.body.notes,undefined);
  assert.equal((await request(policyBase,scoped+foreign,{token:operator.access_token})).status,404);
  const assigneeId=canonicalSubjects.get('fulfillment-beneficiary');const body={assigneeType:'user',assigneeId,expiresAt:null,reason:'Only the explicitly delegated pool may allocate',confirm:true};
  assert.equal((await request(policyBase,`/api/licenses/${poolId}/assign`,{method:'POST',token:operator.access_token,body:{assignee_type:'user',assignee_id:assigneeId}})).status,403);
  assert.equal((await request(policyBase,scoped+poolId+'/assign',{method:'POST',token:operator.access_token,body})).status,201);
  assert.equal((await request(policyBase,scoped+foreign+'/assign',{method:'POST',token:operator.access_token,body})).status,404);
  const approval=await create(foreign,canonicalSubjects.get('pool-scope-approver'),'approver');assert.equal(approval.status,201);
  const requester=await issue('alice');const pending=await request(policyBase,`/api/licenses/${foreign}/request`,{method:'POST',token:requester.access_token,body:{assignee_type:'user',assignee_id:canonicalSubjects.get('alice'),justification:'Actual canonical self-service request'}});assert.equal(pending.status,201);
  const decision={decision:'approved',reason:'Independent source-scoped approval of this pool only',confirm:true};
  assert.equal((await request(policyBase,scoped+foreign+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:operator.access_token,body:decision})).status,404);
  const accepted=await request(policyBase,scoped+foreign+'/requests/'+pending.body.id+'/decisions',{method:'POST',token:approver.access_token,body:decision});assert.equal(accepted.status,200,JSON.stringify(accepted.body));assert.equal(accepted.body.localOnly,true);
  const revoked=await request(policyBase,base+'/'+granted.body.id+'/revoke',{method:'POST',token:config.access_token,headers:{'If-Match':granted.headers.get('etag')},body:{reason:'Explicitly retire this allocator delegation',confirm:true}});assert.equal(revoked.status,200);
  assert.equal((await request(policyBase,scoped+poolId,{token:operator.access_token})).status,404);
  const roleLease=await create(poolId,canonicalSubjects.get('pool-scope-operator'),'allocator');assert.equal(roleLease.status,201);
  const operatorId=canonicalSubjects.get('pool-scope-operator');
  await identityDb.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='license-delegate' AND revoked_at IS NULL",[operatorId],'fixture-scope-role-revoke');
  await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'license-delegate','New canonical delegate role incarnation')",[operatorId],'fixture-scope-role-regrant');
  assert.equal((await request(policyBase,scoped+poolId,{token:operator.access_token})).status,401);
  const replacement=await issue('pool-scope-operator');assert.equal((await request(policyBase,scoped+poolId,{token:replacement.access_token})).status,404);
  assert.deepEqual((await request(policyBase,base+'/self',{token:replacement.access_token})).body.delegations,[]);
  const retire=await request(policyBase,base+'/'+roleLease.body.id+'/revoke',{method:'POST',token:config.access_token,headers:{'If-Match':roleLease.headers.get('etag')},body:{reason:'Retire authority bound to the former role source',confirm:true}});assert.equal(retire.status,200);
  const lifecycleLease=await create(poolId,operatorId,'allocator');assert.equal(lifecycleLease.status,201);
  await identityDb.write('UPDATE users SET enabled=false WHERE id=$1',[operatorId],'fixture-scope-disable');await identityDb.write('UPDATE users SET enabled=true WHERE id=$1',[operatorId],'fixture-scope-reactivate');
  assert.equal((await request(policyBase,scoped+poolId,{token:replacement.access_token})).status,401);
  const reactivated=await issue('pool-scope-operator');assert.equal((await request(policyBase,scoped+poolId,{token:reactivated.access_token})).status,404);
  assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
});

test('revoking an original bearer inside scoped-use audit DML rolls back the allocated source and its evidence',async()=>{
  const config=await firstRoleFactor('pool-scope-revoked-config');const operator=await firstRoleFactor('pool-scope-revoked-operator');
  const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Scoped audit revocation pool',2) RETURNING id")).rows[0].id;
  const configured=await request(policyBase,'/api/licenses/delegations',{method:'POST',token:config.access_token,body:{licenseId:poolId,userId:canonicalSubjects.get('pool-scope-revoked-operator'),duty:'allocator',durationSeconds:3600,reason:'Actual bounded delegation revocation coverage',confirm:true}});assert.equal(configured.status,201);
  const gate='scope-'+randomUUID();const blocker=await policyDb.getClient();let pending;
  await policyDb.query(`CREATE FUNCTION pause_scope_use() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='use' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); END IF; RETURN NEW; END $$; CREATE TRIGGER pause_scope_use BEFORE INSERT ON license_scope_audit FOR EACH ROW EXECUTE FUNCTION pause_scope_use()`);
  await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
  try{pending=request(policyBase,'/api/licenses/scoped/pools/'+poolId+'/assign',{method:'POST',token:operator.access_token,body:{assigneeType:'user',assigneeId:canonicalSubjects.get('fulfillment-beneficiary'),expiresAt:null,reason:'A revoked caller cannot commit this scoped allocation',confirm:true}});
    let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO license_scope_audit(grant_id,action,actor,reason,details)%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}
    assert.equal(waiting,true);assert.equal((await revoke(operator.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await pending).status));
    assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,0);assert.equal((await policyDb.query("SELECT COUNT(*)::int AS count FROM license_scope_audit WHERE grant_id=$1 AND action='use'",[configured.body.id])).rows[0].count,0);
  }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await policyDb.query('DROP TRIGGER pause_scope_use ON license_scope_audit; DROP FUNCTION pause_scope_use()');}
});

test('actual issuer license reviews separate duties, retain only the review cycle and enforce unanswered recipient cutoffs', async () => {
  const config = await firstRoleFactor('license-review-config'); const voter = await firstRoleFactor('license-review-voter');
  const reader = await issue('license-review-reader'); const admin = await issue('operator'); const ordinary = await issue('fulfillment-license-admin');
  const poolId = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual reviewed recipient pool',3) RETURNING id")).rows[0].id;
  const route = '/api/licenses/reviews'; const recipient = canonicalSubjects.get('fulfillment-beneficiary');
  const reviewerRoute = '/api/license-reviewers/' + canonicalSubjects.get('license-review-voter') + '/snapshot';
  const availability = await request(gatewayBase, reviewerRoute, { token: config.access_token }); assert.equal(availability.status, 200); assert.equal(Object.keys(availability.body).length, 5); assert.equal(availability.body.canReview, true);
  assert.equal((await request(gatewayBase, reviewerRoute, { token: ordinary.access_token })).status, 403);
  assert.equal((await request(policyBase, `/api/licenses/${poolId}/assign`, { method: 'POST', token: admin.access_token, body: { assignee_type: 'user', assignee_id: recipient } })).status, 201);
  const groupId = randomUUID(); await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Actual reviewed source team')", [groupId], 'fixture-reviewed-source-team');
  await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, recipient], 'fixture-reviewed-source-team');
  assert.equal((await request(policyBase, `/api/licenses/${poolId}/assign`, { method: 'POST', token: admin.access_token, body: { assignee_type: 'group', assignee_id: groupId } })).status, 201);
  const body = { licenseId: poolId, intervalSeconds: 3600, windowSeconds: 60, reviewerUserIds: [canonicalSubjects.get('license-review-voter')], reason: 'Actual recurring independent recipient certification', acknowledgeDeadlines: true };
  assert.equal((await request(policyBase, route + '/policies', { method: 'POST', token: ordinary.access_token, body })).status, 403);
  const configured = await request(policyBase, route + '/policies', { method: 'POST', token: config.access_token, body }); assert.equal(configured.status, 201, JSON.stringify(configured.body));
  const queued = await request(policyBase, route + '/self', { token: voter.access_token }); assert.equal(queued.status, 200); const row = queued.body.reviews.find(row => row.licenseId === poolId && row.kind === 'direct'); assert.ok(row?.canDecide);
  const delegated = await request(gatewayBase, route + '/self', { token: voter.access_token }); assert.equal(delegated.status, 200); assert.ok(delegated.body.reviews.some(review => review.id === row.id));
  const read = await request(policyBase, route + '/' + row.id, { token: reader.access_token }); assert.equal(read.status, 200); assert.equal(read.body.canDecide, false);
  const vote = async current => request(policyBase, route + '/' + current.id + '/decisions', { method: 'POST', token: voter.access_token,
    headers: { 'If-Match': `"od-license-review:${current.id}:${current.version}:${current.policyVersion}:${current.sourceVersion}"` }, body: { decision: 'retain', reason: 'Actual independent recipient source certification', acknowledgeScope: true } });
  const retained = await vote(row); assert.equal(retained.status, 200); assert.equal(retained.body.state, 'scheduled'); assert.equal(retained.body.baseExpiresAt, null);
  const retired = await request(policyBase, route + '/policies/' + configured.body.id + '/retire', { method: 'POST', token: config.access_token,
    headers: { 'If-Match': configured.headers.get('etag') }, body: { reason: 'Stop new review enrollment but preserve accepted cutoffs', acknowledgeDeadlines: true } }); assert.equal(retired.status, 200);
  assert.equal((await vote(retained.body)).status, 412);
  try {
    await policyDb.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3601 seconds'; $$");
    const assignments = await request(policyBase, `/api/licenses/${poolId}/assignments`, { token: admin.access_token }); assert.deepEqual(assignments.body.assignments[0].sources.map(source => source.type), ['direct']);
    const groupState = (await request(policyBase, '/api/licenses/groups', { token: admin.access_token })).body.groups.find(rule => rule.license_id === poolId && rule.group_id === groupId);
    assert.equal(groupState.assigned_users, 0); assert.equal(groupState.status, 'review-expired');
    const due = await request(policyBase, route + '/' + row.id, { token: voter.access_token }); const exempt = await vote(due.body);
    assert.equal(exempt.status, 200); assert.equal(exempt.body.state, 'exempt');
    assert.equal((await request(policyBase, `/api/licenses/${poolId}/assignments`, { token: admin.access_token })).body.assignments[0].expires_at, null);
    const replacement = await request(policyBase, route + '/policies', { method: 'POST', token: config.access_token, body }); assert.equal(replacement.status, 201);
    await policyDb.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3662 seconds'; $$");
    assert.equal((await request(policyBase, `/api/licenses/${poolId}/assignments`, { token: admin.access_token })).body.assignments.length, 0);
    const expired = await request(policyBase, route + '/' + row.id, { token: voter.access_token }); assert.equal(expired.body.state, 'expired'); assert.equal((await vote(expired.body)).status, 403);
    await new (require('../../../policy-service/src/licenses/LicenseAllocator').LicenseAllocator)(policyDb).expireAll();
  } finally { await policyDb.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$'); }
});

test('a real issuer revocation during license-review audit DML rolls back the cycle and projection', async () => {
  const config = await firstRoleFactor('license-review-config-revocation'); const voter = await firstRoleFactor('license-review-voter-revocation'); const admin = await issue('operator');
  const poolId = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual review revocation pool',2) RETURNING id")).rows[0].id;
  assert.equal((await request(policyBase, `/api/licenses/${poolId}/assign`, { method: 'POST', token: admin.access_token, body: { assignee_type: 'user', assignee_id: canonicalSubjects.get('fulfillment-beneficiary') } })).status, 201);
  const policy = await request(policyBase, '/api/licenses/reviews/policies', { method: 'POST', token: config.access_token, body: { licenseId: poolId, intervalSeconds: 3600, windowSeconds: 60,
    reviewerUserIds: [canonicalSubjects.get('license-review-voter-revocation')], reason: 'Actual independent revocation race coverage', acknowledgeDeadlines: true } }); assert.equal(policy.status, 201);
  const queued = await request(policyBase, '/api/licenses/reviews/self', { token: voter.access_token }); const row = queued.body.reviews.find(row => row.licenseId === poolId);
  const assignment = (await policyDb.query('SELECT * FROM license_assignments WHERE license_id=$1', [poolId])).rows;
  const gate = 'license-review-' + randomUUID(); const blocker = await policyDb.getClient(); let pending;
  await policyDb.query(`CREATE FUNCTION pause_license_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='retain' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); END IF; RETURN NEW; END $$`);
  await policyDb.query('CREATE TRIGGER pause_license_review_audit BEFORE INSERT ON license_review_audit FOR EACH ROW EXECUTE FUNCTION pause_license_review_audit()');
  await blocker.query('BEGIN'); await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [gate]);
  try {
    pending = request(policyBase, '/api/licenses/reviews/' + row.id + '/decisions', { method: 'POST', token: voter.access_token,
      headers: { 'If-Match': `"od-license-review:${row.id}:${row.version}:${row.policyVersion}:${row.sourceVersion}"` }, body: { decision: 'retain', reason: 'A revoked live authority must not commit this license review', acknowledgeScope: true } });
    let waiting = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      waiting = (await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE license_review_leases SET version=version+1 WHERE id=%'")).rows.length > 0;
      if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10));
    }
    assert.equal(waiting, true); assert.equal((await revoke(voter.access_token)).status, 200); await blocker.query('COMMIT');
    assert.ok([401, 403].includes((await pending).status));
    assert.equal((await policyDb.query('SELECT version FROM license_review_leases WHERE id=$1', [row.id])).rows[0].version, '1');
    assert.deepEqual((await policyDb.query('SELECT * FROM license_assignments WHERE license_id=$1', [poolId])).rows, assignment);
    assert.equal((await policyDb.query("SELECT COUNT(*)::int AS count FROM license_review_audit WHERE lease_id=$1 AND action='retain'", [row.id])).rows[0].count, 0);
  } finally {
    await blocker.query('ROLLBACK'); blocker.release(); if (pending) await pending.catch(() => {});
    await policyDb.query('DROP TRIGGER pause_license_review_audit ON license_review_audit; DROP FUNCTION pause_license_review_audit()');
  }
});

test('actual issuer MFA and live canonical-role revocation fence exact license-source withdrawal', async () => {
  const username = 'license-source-manager'; const userId = canonicalSubjects.get(username); const recipient = canonicalSubjects.get('fulfillment-beneficiary');
  const weak = await issue(username);
  const poolId = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual issuer source pool',3) RETURNING id")).rows[0].id;
  const assign = () => request(policyBase, `/api/licenses/${poolId}/assign`, { method: 'POST', token: weak.access_token, body: { assignee_type: 'user', assignee_id: recipient } });
  assert.equal((await assign()).status, 201);
  const grantId = (await policyDb.query('SELECT grant_id FROM license_assignment_sources WHERE license_id=$1', [poolId])).rows[0].grant_id;
  const route = `/api/licenses/${poolId}/grants/${grantId}`;
  const before = await request(policyBase, route, { token: weak.access_token }); assert.equal(before.status, 200);
  const body = { confirm: true, reason: 'Actual independently scoped source withdrawal' }; const headers = { 'If-Match': before.headers.get('etag') };
  assert.equal((await request(policyBase, route + '/revoke', { method: 'POST', token: weak.access_token, headers, body })).status, 428);
  const setup = await request(issuerBase, '/api/mfa/enroll', { method: 'POST', token: weak.access_token, body: { username, password: 'disposable-password' } }); assert.equal(setup.status, 200);
  const counter = Math.floor(Date.now() / 30000) - 1;
  assert.equal((await request(issuerBase, '/api/mfa/confirm', { method: 'POST', token: weak.access_token, body: { code: totp(setup.body.secret, counter) } })).status, 200);
  rememberFactor(username, setup.body.secret, counter); const strong = await issue(username);
  assert.deepEqual(payload(strong.access_token).amr, ['pwd', 'otp']);
  const result = await request(policyBase, route + '/revoke', { method: 'POST', token: strong.access_token, headers, body });
  assert.equal(result.status, 200); assert.equal(result.body.grant.id, grantId); assert.equal(result.body.grant.state, 'revoked');
  assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1', [poolId])).rows[0].used_seats, 0);
  await identityDb.write('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role=$2 AND revoked_at IS NULL', [userId, 'license-manager'], 'fixture-source-manager-removal');
  assert.equal((await request(policyBase, route, { token: strong.access_token })).status, 401);
});

async function revoke(token, overrides = {}) {
  return request(issuerBase, '/oauth/revoke', { method: 'POST', body: { token, client_id: clientId, client_secret: clientSecret, ...overrides } });
}

before(async () => {
  for (const schema of schemas) await administration.query(`CREATE SCHEMA ${schema}`);
  Object.assign(process.env, { NODE_ENV: 'test', OAUTH_REVOCATION_DEMO_MODE: 'false', OAUTH_ISSUER: issuer, OIDC_ISSUER: issuer,
    DEVPORTAL_CLIENT_SECRET: clientSecret, GRAFANA_CLIENT_SECRET: 'other-disposable-client', LOG_LEVEL: 'error', COMPANY_CONSOLE_CLIENT_ID: clientId });
  keyDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-oauth-keys-'));
  process.env.OAUTH_MFA_KEY_FILE = path.join(keyDirectory, 'mfa.key');
  require('../../scripts/mfa-key').generate(process.env.OAUTH_MFA_KEY_FILE);
  firstKeyFile = path.join(keyDirectory, 'first.pem'); secondKeyFile = path.join(keyDirectory, 'second.pem');
  previousKeyFile = path.join(keyDirectory, 'previous.json');
  for (const filename of [firstKeyFile, secondKeyFile]) fs.writeFileSync(filename,
    generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  const load = filename => new SigningKeys({ privateKeyFile: filename, verificationJwksFile: null, ephemeral: false, production: true });
  fs.writeFileSync(previousKeyFile, JSON.stringify(load(firstKeyFile).jwks()), { mode: 0o644 });
  const published = path.join(keyDirectory, 'prepublished.json');
  fs.writeFileSync(published, JSON.stringify(load(secondKeyFile).jwks()), { mode: 0o644 });
  Object.assign(process.env, { OAUTH_SIGNING_KEY_FILE: firstKeyFile, OAUTH_VERIFICATION_JWKS_FILE: published, OAUTH_EPHEMERAL_SIGNING_KEYS: 'false' });
  credentialServer = http.createServer(async (incoming, response) => {
    const chunks = []; for await (const chunk of incoming) chunks.push(chunk);
    const credentials = JSON.parse(Buffer.concat(chunks));
    response.setHeader('Content-Type', 'application/json');
    if (incoming.url !== '/api/auth/login' || ![...canonicalSubjects.keys(), 'gone', 'unlinked', 'company-registration-owner', 'company-blueprint-owner', 'company-assignment-owner'].includes(credentials.username) || credentials.password !== 'disposable-password') {
      response.statusCode = 401; return response.end('{}');
    }
    response.end(JSON.stringify({ success: true, user: { id: credentials.username + '-subject', username: credentials.username,
      ...(credentials.username === 'company-registration-owner' ? { email: 'verified-company-owner@example.invalid', displayName: 'Verified credential company owner', roles: ['admin'] } : credentials.username === 'company-blueprint-owner' ? { email: 'verified-blueprint-owner@example.invalid', displayName: 'Verified blueprint company owner', roles: ['admin'] } : credentials.username === 'company-assignment-owner' ? { email: 'verified-assignment-owner@example.invalid', displayName: 'Verified assignment company owner' } : {}),
      groups: credentialGroupOverrides.get(credentials.username) || [], roles: credentialRoleOverrides.get(credentials.username) || (credentials.username === 'operator' ? ['admin'] : credentials.username === 'session-operator' ? ['session-administrator'] : credentials.username === 'lifecycle' ? ['user-lifecycle-operator'] : ['user']), permissions: ['users.delete', 'identities.roles.manage'] } }));
  }).listen(0, '127.0.0.1');
  process.env.AUTH_SERVICE_URL = await listening(credentialServer);
  const probe = net.createServer().listen(0, '127.0.0.1');
  const identityPort = Number(new URL(await listening(probe)).port); await new Promise(resolve => probe.close(resolve));
  process.env.OAUTH_IDENTITY_AUTHORITY_URL = `http://127.0.0.1:${identityPort}/internal/identity/authorization-state`;
  process.env.DATABASE_URL = databaseUrl(schemas[0]);
  issuerDb = require('../db');
  await issuerDb.initDb(); assert.equal(issuerDb.isAvailable(), true);
  const issuerApp = require('../index'); await issuerApp.initializeClients();
  issuerServer = issuerApp.listen(0, '127.0.0.1'); issuerBase = await listening(issuerServer);
  issuerServer.on('request',incoming=>{if(incoming.method==='GET'&&incoming.url.split('?')[0]==='/oauth/access-state')return;if(Date.now()-issuerWindowStarted>=60000){issuerWindowStarted=Date.now();issuerRequests=0;}issuerRequests++;});
  process.env.JWKS_URI = issuerBase + '/.well-known/jwks.json';
  process.env.OIDC_ACCESS_STATE_URL = issuerBase + '/oauth/access-state';
  process.env.OIDC_TENANT_STATE_URL = issuerBase + '/oauth/tenant-state';
  process.env.DATABASE_URL = databaseUrl(schemas[1]);
  identityDb = require('../../../identity-service/src/db');
  assert.equal(await identityDb.initDb(), true);
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/045_company_offboarding_receipts.sql'), 'utf8'));
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/046_company_offboarding_groups.sql'), 'utf8'));
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/047_company_offboarding_access.sql'), 'utf8'));
  await require('../../../../../scripts/lib/tenant-ownership-fixture.cjs').installTenantFixture(identityDb,schemas[1],{userTenants:Object.fromEntries(['tenant-session-user','tenant-pending-user','tenant-creation-admin','production-foreign-group-operator','production-foreign-member','production-foreign-extra','production-foreign-authority-admin',...['config','voter','grantor','holder'].map(duty=>'tenant-group-'+duty)].map(name=>[canonicalSubjects.get(name),separateTenant]))});
  for (const [name, identifier] of canonicalSubjects) {
    await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [identifier, name, name + '@test.invalid']);
    await identityDb.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, name + '-subject', identifier]);
    const role = ['operator','second-admin','role-policy-admin'].includes(name) || name.startsWith('auth-policy-admin-') ? 'admin' : name === 'role-policy-manager' ? 'authentication-policy-administrator' : name === 'role-policy-reader' ? 'authentication-policy-reader' : name === 'role-policy-user' || name === 'role-policy-age' || name === 'role-policy-pending' ? 'license-manager' : name === 'auth-policy-manager' ? 'application-authentication-administrator' : name === 'auth-policy-reader' ? 'application-authentication-reader' : name === 'session-operator' ? 'session-administrator' : name === 'lifecycle' ? 'user-lifecycle-operator' : name === 'pim-manager' ? 'pim-administrator' : name === 'pim-reviewer' ? 'pim-approver' : name === 'app-operator' ? 'application-administrator' : name === 'app-reader' ? 'application-reader' : name === 'app-access-manager' ? 'application-access-administrator' : name === 'app-access-reader' ? 'application-access-reader' : 'user';
    await identityDb.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [identifier, name==='tenant-creation-admin'||name.startsWith('mutation-self-')?'admin':role, 'Explicit disposable fixture bootstrap'], 'fixture-bootstrap');
    if (fulfillmentRoles.has(name)) await identityDb.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[identifier,fulfillmentRoles.get(name),'Explicit independent fulfillment duty bootstrap'],'fixture-bootstrap');
    if (activationPolicyRoles.has(name)) await identityDb.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[identifier,activationPolicyRoles.get(name),'Explicit independent activation policy duty bootstrap'],'fixture-bootstrap');
    if(reviewRoles.has(name))await identityDb.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[identifier,reviewRoles.get(name),'Explicit independent recurring review duty bootstrap'],'fixture-bootstrap');
  }
  identityServer = require('../../../identity-service/src').listen(identityPort, '127.0.0.1'); identityBase = await listening(identityServer);
  identityServer.on('request', (_incoming, outgoing) => { identityRequests++; outgoing.once('finish', () => {
    if (outgoing.statusCode === 429) identityRateDenials++;
    const remaining = Number(outgoing.getHeader('X-RateLimit-Remaining')); const reset = Number(outgoing.getHeader('X-RateLimit-Reset'));
    if (Number.isInteger(remaining) && remaining >= 0 && Number.isFinite(reset) && reset > 0) identityBudget = { remaining, resetAt: reset * 1000 };
  }); });
  await bootstrapApplications(issuerDb,{ issuer,identityBase,signingKeyFile: firstKeyFile,clients: [clientId,'grafana-od-client'],users: [...canonicalSubjects.values()] });
  process.env.IDENTITY_SERVICE_URL = identityBase;
  inventoryFixture=await require('../../../../../scripts/lib/device-inventory-fixture.cjs').deviceInventoryFixture(process.env.OAUTH_TEST_DATABASE_URL,identityBase);
  process.env.DEVICE_SERVICE_URL=inventoryFixture.base;
  process.env.DATABASE_URL = databaseUrl(schemas[2]);
  policyDb = require('../../../policy-service/src/db/postgres');
  for (const migration of ['001_policies.sql', '003_blueprints.sql', '004_licenses.sql', '005_license_allocation.sql', '006_group_license_sources.sql', '007_license_principal_binding.sql', '008_user_eligibility.sql', '009_license_fulfillment.sql', '010_license_grant_lineage.sql', '011_license_reviews.sql', '012_license_delegations.sql', '013_license_scope_activation.sql', '014_license_scope_policies.sql', '015_license_delegation_reviews.sql', '016_group_directory_leases.sql', '017_group_source_consents.sql','018_policy_configuration.sql','019_policy_publication.sql','020_license_capacity.sql','021_license_capacity_admission.sql','022_company_licenses.sql','023_company_offboarding.sql','024_company_pool_updates.sql','025_company_blueprints.sql','026_company_blueprint_assignments.sql','027_company_blueprint_lifecycle.sql']) {
    await policyDb.query(fs.readFileSync(path.join(__dirname, '../../../policy-service/src/db/migrations', migration), 'utf8'));
  }
  process.env.OAUTH_PROVIDER_URL = issuerBase;
  policyServer = require('../../../policy-service/src').listen(0, '127.0.0.1'); policyBase = await listening(policyServer);
  process.env.POLICY_SERVICE_URL = policyBase;
  process.env.OAUTH_POLICY_SOURCE_URL = policyBase;
  receiverServer = http.createServer(async (incoming, outgoing) => {
    outgoing.setHeader('Content-Type', 'application/json');
    if (incoming.url === '/health') return outgoing.end('{"status":"healthy"}');
    if (incoming.url === '/forbidden-service-token') { forbiddenServiceTokens++; outgoing.statusCode = 500; return outgoing.end('{}'); }
    const chunks = []; for await (const chunk of incoming) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    const state = await request(issuerBase, '/oauth/access-state', { token: incoming.headers.authorization?.slice(7) });
    if (state.status !== 200 || !state.body.active) { outgoing.statusCode = 401; return outgoing.end('{}'); }
    const principal = payload(incoming.headers.authorization.slice(7));
    const allowed = principal.roles?.some(role => ['admin', 'application-administrator', ...(incoming.method === 'GET' ? ['application-reader'] : [])].includes(role));
    if (!allowed) { outgoing.statusCode = 403; return outgoing.end('{}'); }
    receiverCalls.push({ path: incoming.url, method: incoming.method, authorization: incoming.headers.authorization, subject: principal.sub,
      operationId: incoming.headers['x-od-operation-id'], createdBy: body.createdBy, name: body.name || body.computerName || body.principal });
    if (joinGate && incoming.url === joinGate.path) { const gate = joinGate; joinGate = null; gate.entered(); await gate.resume; }
    if (incoming.method === 'GET' && incoming.url === '/api/service-accounts') return outgoing.end(JSON.stringify({ accounts: [{ clientId: 'fixture-app', name: 'Fixture app', clientSecret: 'fixture-secret-must-not-leak' }] }));
    if (incoming.url === '/api/service-accounts') { outgoing.statusCode = 201; return outgoing.end(JSON.stringify({ success: true, clientId: body.clientId, name: body.name, createdBy: body.createdBy })); }
    outgoing.end(JSON.stringify({ success: true, dn: 'CN=Fixture,CN=Computers,DC=test,DC=invalid' }));
  }).listen(0, '127.0.0.1'); receiverBase = await listening(receiverServer);
  let quickOutput = '';
  quickProcess = spawn(process.execPath, ['-e', `const app=require('./src');const server=app.listen(0,'127.0.0.1',()=>process.stdout.write('QA_PORT '+server.address().port+'\\n'));process.on('SIGTERM',()=>{server.closeAllConnections();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();});`], {
    cwd: path.resolve(__dirname, '../../../../platform/quick-actions'), stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env,
      AUTH_SERVICE_URL: receiverBase, SAMBA_SERVICE_URL: receiverBase, KERBEROS_SERVICE_URL: receiverBase, DIRECTORY_SERVICE_URL: receiverBase,
      DEVICE_SERVICE_URL: receiverBase, PIM_SERVICE_URL: receiverBase, MDM_SERVICE_URL: receiverBase, APP_STORE_SERVICE_URL: receiverBase,
      REDIS_URL: 'redis://127.0.0.1:1', QA_CLIENT_SECRET: 'must-never-be-used', TOKEN_ENDPOINT: receiverBase + '/forbidden-service-token', SERVICE_TOKEN: 'retired-test-credential' },
  });
  for (const stream of [quickProcess.stdout, quickProcess.stderr]) stream.on('data', chunk => { quickOutput = (quickOutput + chunk).slice(-16000); });
  const deadline = Date.now() + 15000;
  while (!/QA_PORT (\d+)/.test(quickOutput)) {
    if (quickProcess.exitCode !== null || quickProcess.signalCode !== null || Date.now() > deadline) throw new Error('Quick-actions did not start: ' + quickOutput);
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  quickBase = 'http://127.0.0.1:' + /QA_PORT (\d+)/.exec(quickOutput)[1]; process.env.QUICK_ACTIONS_URL = quickBase;
  process.env.DATABASE_URL = databaseUrl(schemas[0]);
  Gateway = require('../../../api-gateway/src'); await Gateway.databaseReady;
  gateway = new Gateway({ discover: false, enabledModules: ['policy-service', 'quick-actions', 'identity-service'] });
  gateway.server.listen(0, '127.0.0.1'); gatewayBase = await listening(gateway.server);
});

beforeEach(async () => {
 if(identityBudget?.remaining<150){const delay=Math.max(0,identityBudget.resetAt+100-Date.now());if(delay){process.stdout.write(`Waiting ${delay} ms for the actual identity rate window (${identityBudget.remaining} requests left)\n`);await new Promise(resolve=>setTimeout(resolve,delay));}}
 if(issuerRequests>250)await new Promise(resolve=>setTimeout(resolve,Math.max(0,60050-(Date.now()-issuerWindowStarted))));receiverCalls = []; forbiddenServiceTokens = 0; joinGate = null; await issuerDb.query('TRUNCATE oauth_token_revocations,oauth_sessions,oauth_session_refresh,oauth_session_audit CASCADE');
});
after(()=>assert.equal(identityRateDenials,0,'The native integration fixture must stay within actual identity rate limits'));

async function registerApplication(token, metadata = {}, assignOperator = true) {
  const created = await request(issuerBase, '/api/clients', { method: 'POST', token, body: { name: 'Canonical application ' + randomUUID(),
    redirectUris: ['https://application.test/callback'], scopes: ['openid','roles'], grantTypes: ['authorization_code','refresh_token'], enabled: true, ...metadata } });
  assert.equal(created.status, 201);
  if (assignOperator && created.body.grantTypes.some(grant => ['authorization_code','urn:ietf:params:oauth:grant-type:device_code'].includes(grant))) {
    const reviewer = await issue('second-admin');
    const grant = await request(issuerBase, `/api/clients/${created.body.clientId}/assignments`, { method: 'POST',token: reviewer.access_token,
      body: { requestId: randomUUID(),targetType: 'user',targetId: canonicalUser,durationSeconds: 28800,reason: 'Independently assigned disposable operator application access' } });
    assert.equal(grant.status,201);
  }
  return created.body;
}
const clientCondition = client => ({ 'If-Match': `"od-client:${client.clientId}:${client.version}"` });
async function actualPublication(kind,id,config,reviewerName,approve=true){
 const reviewer=await firstRoleFactor(reviewerName);const root='/api/'+(kind==='policy'?'policies':'blueprints')+'/'+id;const why={reason:'Actual independent bounded publication confirmation',acknowledgeScope:true};
 const frame=await request(gatewayBase,root+'/publications',{token:config.access_token});assert.equal(frame.status,200,JSON.stringify(frame.body));
 const pending=await request(gatewayBase,root+'/publications',{method:'POST',token:config.access_token,headers:{'If-Match':`"od-${kind}:${id}:${frame.body.resourceVersion}"`},body:{reviewerUserId:canonicalSubjects.get(reviewerName),validitySeconds:300,configurationHash:frame.body.configurationHash,...why}});assert.equal(pending.status,201,JSON.stringify(pending.body));
 if(!approve)return{reviewer,root,frame:frame.body,pending};
 const approved=await request(gatewayBase,root+'/publications/'+pending.body.id+'/decisions',{method:'POST',token:reviewer.access_token,headers:{'If-Match':pending.headers.get('etag')},body:{decision:'approved',resourceVersion:frame.body.resourceVersion,configurationHash:frame.body.configurationHash,...why}});assert.equal(approved.status,200,JSON.stringify(approved.body));return{reviewer,root,frame:frame.body,pending,approved};
}
test('actual policy receiver separates ordinary users, readers, configuration and fresh-MFA deployment without licensing or profile powers', async () => {
  const config = await firstRoleFactor('policy-config'); const reader = await issue('policy-read'); const ordinary = await issue('alice');
  const weak = await issue('policy-deploy');
  assert.equal((await request(policyBase, '/api/policies/access', { token: weak.access_token })).body.freshMfa, false);
  const why = { reason: 'Actual versioned policy scope confirmation', acknowledgeScope: true };
  const draft = { name: 'Actual scoped policy configuration', type: 'security', platform: 'all', settings: { screenLock: { minutes: 5 }, firewall: true }, ...why };
  for (const base of [policyBase, gatewayBase]) {
    assert.equal((await request(base, '/api/policies', { token: ordinary.access_token })).status, 403);
    assert.equal((await request(base, '/api/policies', { method: 'POST', token: reader.access_token, body: draft })).status, 403);
  }
  assert.equal((await request(gatewayBase, '/api/policies', { method: 'POST', token: config.access_token, body: { ...draft, created_by: canonicalUser, actor: 'forged-root' } })).status, 400);
  const created = await request(gatewayBase, '/api/policies', { method: 'POST', token: config.access_token, body: draft });
  assert.equal(created.status, 201, JSON.stringify(created.body)); assert.equal(created.body.status, 'draft'); assert.equal(created.body.created_by, canonicalSubjects.get('policy-config'));
  const rows = await request(gatewayBase, '/api/policies', { token: reader.access_token }); assert.equal(rows.status, 200); assert.ok(rows.body.policies.some(row => row.id === created.body.id));
  for (const path of ['/api/gpo', '/api/blueprints', '/api/update-rings']) assert.equal((await request(gatewayBase, path, { token: reader.access_token })).status, 200);
  const route = '/api/policies/' + created.body.id + '/activate';
  assert.equal((await request(policyBase, route, { method: 'POST', token: weak.access_token, body: {} })).status, 428);
  const deployer = await configureFactor('policy-deploy', weak);
  assert.equal((await request(policyBase, '/api/policies/' + created.body.id, { method: 'PUT', token: deployer.access_token, body: { name: 'Forbidden definition edit' } })).status, 403);
  assert.equal((await request(gatewayBase, route, { method: 'POST', token: deployer.access_token, headers: { 'If-Match': created.headers.get('etag') }, body: { ...why, actor: 'forged' } })).status, 400);
  assert.equal((await request(gatewayBase, route, { method: 'POST', token: deployer.access_token, headers: { 'If-Match': created.headers.get('etag') }, body: why })).status, 400);
  const publication=await actualPublication('policy',created.body.id,config,'policy-first-review');
  assert.equal((await request(gatewayBase, route, { method: 'POST', token: deployer.access_token, headers: { 'If-Match': created.headers.get('etag') }, body: {...why,publicationId:publication.approved.body.id} })).status, 200);
  assert.equal((await policyDb.query('SELECT status FROM policies WHERE id=$1', [created.body.id])).rows[0].status, 'active');
  const audit = (await policyDb.query("SELECT actor FROM policy_configuration_audit WHERE resource_id=$1 AND action='activated'", [created.body.id])).rows;
  assert.equal(audit[0].actor.userId, canonicalSubjects.get('policy-deploy'));
  assert.equal((await request(policyBase, '/api/licenses', { token: config.access_token })).status, 403);
  assert.equal((await request(identityBase, '/api/users', { token: deployer.access_token })).status, 403);
  const device = 'policy-device-' + randomUUID();
  await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform,token,data) VALUES($1,'Owned policy recipient','windows','never-project-this-token',$2)", [device, { password: 'never-project-this-password' }]);
  const inventory = await request(issuerBase, '/api/devices/registry', { token: deployer.access_token }); assert.equal(inventory.status, 200);
  assert.deepEqual(Object.keys(inventory.body.find(row => row.id === device)).sort(), ['hostname', 'id', 'platform']); assert.equal(JSON.stringify(inventory.body).includes('never-project-this'), false);
  await issuerDb.query('ALTER TABLE enrolled_devices RENAME TO owned_unavailable_inventory');
  try { assert.equal((await request(issuerBase, '/api/devices/registry', { token: deployer.access_token })).status, 503); }
  finally { await issuerDb.query('ALTER TABLE owned_unavailable_inventory RENAME TO enrolled_devices'); }
  assert.equal((await request(issuerBase, '/api/devices/' + device + '/commands', { method: 'POST', token: deployer.access_token, body: { command: 'wipe' } })).status, 403);
  assert.equal((await request(issuerBase, '/api/devices/unknown-policy-recipient/commands', { method: 'POST', token: deployer.access_token, body: { command: 'update_policy' } })).status, 400);
});

test('actual original-operator revocation after the first queued blueprint command stops later delivery without an ambient credential', async () => {
  const config = await issue('policy-config'); const deployer = await configureFactor('policy-withdrawn', await issue('policy-withdrawn'));
  const why = { reason: 'Actual exact blueprint delivery configuration', acknowledgeScope: true };
  const blueprint = await request(policyBase, '/api/blueprints', { method: 'POST', token: config.access_token, body: { name: 'Owned actor-preserving policy delivery', platform: 'windows', ...why } }); assert.equal(blueprint.status, 201);
  let blueprintVersion = blueprint.headers.get('etag');
  for (const [config_type, config_name] of [['wifi', 'Owned first configuration'], ['screen_lock', 'Owned second configuration']]) {
    const configured = await request(policyBase, '/api/blueprints/' + blueprint.body.id + '/configurations', { method: 'POST', token: config.access_token, headers: { 'If-Match': blueprintVersion }, body: { config_type, config_name, payload: { enabled: true }, ...why } }); assert.equal(configured.status, 201); blueprintVersion = configured.headers.get('etag');
  }
  const device = 'delivery-device-' + randomUUID(); await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform) VALUES($1,'Owned delivery recipient','windows')", [device]);
  assert.equal((await request(policyBase, '/api/blueprints/' + blueprint.body.id + '/assign', { method: 'POST', token: deployer.access_token, headers: { 'If-Match': blueprintVersion }, body: { target_type: 'device', target_id: device, assigned_by: 'forged', ...why } })).status, 400);
  const assigned = await request(policyBase, '/api/blueprints/' + blueprint.body.id + '/assign', { method: 'POST', token: deployer.access_token, headers: { 'If-Match': blueprintVersion }, body: { target_type: 'device', target_id: device, ...why } }); assert.equal(assigned.status, 201); blueprintVersion = assigned.headers.get('etag');
  const publication=await actualPublication('blueprint',blueprint.body.id,config,'policy-delivery-review');
  let entered; let release; let intercepted = false; let pending;
  const reached = new Promise(resolve => { entered = resolve; }); const resume = new Promise(resolve => { release = resolve; });
  const gate = (incoming, outgoing) => {
    if (incoming.method !== 'POST' || incoming.url !== '/api/devices/' + device + '/commands' || intercepted) return;
    intercepted = true; assert.equal(incoming.headers.authorization, 'Bearer ' + deployer.access_token); assert.equal(incoming.headers['x-oauth-internal-token'], undefined);
    const finish = outgoing.end; outgoing.end = function (...args) { entered(); resume.then(() => finish.apply(this, args)); return this; };
  };
  issuerServer.prependListener('request', gate);
  try {
    pending = request(gatewayBase, '/api/blueprints/' + blueprint.body.id + '/apply', { method: 'POST', token: deployer.access_token, headers: { 'If-Match': blueprintVersion }, body: { acknowledgeScope: true,publicationId:publication.approved.body.id } });
    let timeout; try { await Promise.race([reached, new Promise((resolve, reject) => { timeout = setTimeout(() => reject(new Error('Owned command receipt gate not reached')), 5000); })]); } finally { clearTimeout(timeout); }
    assert.equal((await revoke(deployer.access_token)).status, 200); release(); const denied = await pending;
    assert.equal(denied.status, 401, JSON.stringify(denied.body)); assert.equal(denied.body.deliveryMayHaveOccurred, true); assert.equal(denied.body.enforcementConfirmed, false);
    const root = await issue(); const commands = await request(issuerBase, '/api/devices/' + device + '/commands', { token: root.access_token });
    assert.equal(commands.status, 200); assert.equal(commands.body.length, 1); assert.equal(commands.body[0].command, 'update_policy'); assert.equal(commands.body[0].status, 'pending');
    assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1', [device])).rows[0].count, 1);
  } finally { issuerServer.removeListener('request', gate); release(); if (pending) await pending.catch(() => {}); }
});

test('actual canonical policy-role withdrawal fences direct APIs and regrant cannot revive the old operator token', async () => {
  const original = await issue('policy-deploy'); const userId = canonicalSubjects.get('policy-deploy');
  assert.equal((await request(policyBase, '/api/policies', { token: original.access_token })).status, 200);
  await identityDb.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='policy-deployment-operator' AND revoked_at IS NULL", [userId], 'owned-policy-role-withdrawal');
  assert.equal((await request(policyBase, '/api/policies', { token: original.access_token })).status, 401);
  assert.equal((await request(issuerBase, '/api/devices/registry', { token: original.access_token })).status, 401);
  await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'policy-deployment-operator','Explicit new owned policy role incarnation')", [userId], 'owned-policy-role-reissue');
  assert.equal((await request(gatewayBase, '/api/policies', { token: original.access_token })).status, 401);
  assert.equal((await request(policyBase, '/api/policies', { token: (await issue('policy-deploy')).access_token })).status, 200);
});
test('actual policy configuration DML cannot commit after its original issuer token is revoked inside the mandatory audit',async()=>{
 const actor=await firstRoleFactor('policy-transaction-config');const body={name:'Actual atomic policy authority',type:'security',settings:{firewall:true},reason:'Actual policy creation with durable evidence',acknowledgeScope:true};
 const created=await request(gatewayBase,'/api/policies',{method:'POST',token:actor.access_token,body});assert.equal(created.status,201,JSON.stringify(created.body));const gate='policy-dml-'+randomUUID();const blocker=await policyDb.getClient();let pending;
 await policyDb.query(`CREATE FUNCTION owned_policy_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.resource_id='${created.body.id}'::uuid AND NEW.action='updated' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER owned_policy_audit_wait AFTER INSERT ON policy_configuration_audit FOR EACH ROW EXECUTE FUNCTION owned_policy_audit_wait()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(policyBase,'/api/policies/'+created.body.id,{method:'PUT',token:actor.access_token,headers:{'If-Match':created.headers.get('etag')},body:{settings:{firewall:false},reason:'An actually revoked writer must not commit this change',acknowledgeScope:true}});let waiting=false;
 for(let attempt=0;attempt<300;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE policies%' ")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(actor.access_token)).status,200);await blocker.query('COMMIT');const denied=await pending;assert.equal(denied.status,401,JSON.stringify(denied.body));
 const row=(await policyDb.query('SELECT * FROM policies WHERE id=$1',[created.body.id])).rows[0];assert.equal(row.version,1);assert.deepEqual(row.settings,{firewall:true});assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM policy_configuration_audit WHERE resource_id=$1',[row.id])).rows[0].count,1);assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM policy_configuration_outbox WHERE resource_id=$1',[row.id])).rows[0].count,1);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await policyDb.query('DROP TRIGGER owned_policy_audit_wait ON policy_configuration_audit;DROP FUNCTION owned_policy_audit_wait()');}
});
test('actual blueprint configuration version changes after an accepted first command stop the old delivery without silently adopting new content',async()=>{
 const actor=await firstRoleFactor('policy-content-config');const why={reason:'Actual exact blueprint configuration version',acknowledgeScope:true};
 const created=await request(policyBase,'/api/blueprints',{method:'POST',token:actor.access_token,body:{name:'Actual version-fenced blueprint delivery',platform:'windows',...why}});assert.equal(created.status,201);let version=created.headers.get('etag');
 for(const name of ['Actual first item','Actual second item']){const result=await request(policyBase,'/api/blueprints/'+created.body.id+'/configurations',{method:'POST',token:actor.access_token,headers:{'If-Match':version},body:{config_type:'screen_lock',config_name:name,payload:{minutes:5},...why}});assert.equal(result.status,201);version=result.headers.get('etag');}
 const device='content-device-'+randomUUID();await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform) VALUES($1,'Owned content target','windows')",[device]);const assigned=await request(policyBase,'/api/blueprints/'+created.body.id+'/assign',{method:'POST',token:actor.access_token,headers:{'If-Match':version},body:{target_type:'device',target_id:device,...why}});assert.equal(assigned.status,201);version=assigned.headers.get('etag');
 let entered;let release;let held=false;let pending;const reached=new Promise(resolve=>{entered=resolve;});const resume=new Promise(resolve=>{release=resolve;});const gate=(incoming,outgoing)=>{if(held||incoming.method!=='POST'||incoming.url!=='/api/devices/'+device+'/commands')return;held=true;const finish=outgoing.end;outgoing.end=function(...args){entered();resume.then(()=>finish.apply(this,args));return this;};};issuerServer.prependListener('request',gate);
 const publication=await actualPublication('blueprint',created.body.id,actor,'policy-content-review');
 try{pending=request(gatewayBase,'/api/blueprints/'+created.body.id+'/apply',{method:'POST',token:actor.access_token,headers:{'If-Match':version},body:{acknowledgeScope:true,publicationId:publication.approved.body.id}});let timeout;try{await Promise.race([reached,new Promise((resolve,reject)=>{timeout=setTimeout(()=>reject(new Error('Owned content delivery gate not reached')),5000);})]);}finally{clearTimeout(timeout);}
 const changed=await request(policyBase,'/api/blueprints/'+created.body.id+'/configurations',{method:'POST',token:actor.access_token,headers:{'If-Match':version},body:{config_type:'wifi',config_name:'Explicit newer content',payload:{ssid:'Owned'},...why}});assert.equal(changed.status,201);release();const denied=await pending;assert.equal(denied.status,412,JSON.stringify(denied.body));assert.equal(denied.body.deliveryMayHaveOccurred,true);
 const root=await issue();const queued=await request(issuerBase,'/api/devices/'+device+'/commands',{token:root.access_token});assert.equal(queued.body.length,1);assert.equal(queued.body[0].payload.configurationVersion,4);
 assert.equal((await request(policyBase,'/api/blueprints/'+created.body.id+'/apply',{method:'POST',token:actor.access_token,headers:{'If-Match':version},body:{acknowledgeScope:true}})).status,412);
 }finally{issuerServer.removeListener('request',gate);release();if(pending)await pending.catch(()=>{});}
});
test('actual publication approval DML cannot commit after its original independent reviewer token is revoked',async()=>{
 const config=await firstRoleFactor('publication-dml-config');const why={reason:'Actual bounded publication before original reviewer loss',acknowledgeScope:true};
 const global=await issue();const globalAccess=await request(policyBase,'/api/policies/access',{token:global.access_token});assert.equal(globalAccess.status,200);assert.equal(globalAccess.body.permissions.includes('policies.publication.review'),false);
 const created=await request(gatewayBase,'/api/policies',{method:'POST',token:config.access_token,body:{name:'Actual independent atomic publication',type:'security',settings:{firewall:true},...why}});assert.equal(created.status,201);
 const fixture=await actualPublication('policy',created.body.id,config,'publication-dml-review',false);const route=fixture.root+'/publications/'+fixture.pending.body.id+'/decisions';
 assert.equal((await request(policyBase,route,{method:'POST',token:config.access_token,headers:{'If-Match':fixture.pending.headers.get('etag')},body:{decision:'approved',resourceVersion:1,configurationHash:fixture.frame.configurationHash,...why}})).status,403);
 for(const denied of ['/api/licenses','/api/users'])assert.equal((await request(denied==='/api/users'?identityBase:policyBase,denied,{token:fixture.reviewer.access_token})).status,403);
 const gate='publication-dml-'+randomUUID();const blocker=await policyDb.getClient();let pending;
 await policyDb.query(`CREATE FUNCTION owned_publication_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.publication_id='${fixture.pending.body.id}'::uuid AND NEW.action='approved' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER owned_publication_audit_wait AFTER INSERT ON policy_publication_audit FOR EACH ROW EXECUTE FUNCTION owned_publication_audit_wait()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(policyBase,route,{method:'POST',token:fixture.reviewer.access_token,headers:{'If-Match':fixture.pending.headers.get('etag')},body:{decision:'approved',resourceVersion:1,configurationHash:fixture.frame.configurationHash,...why}});let waiting=false;
 for(let attempt=0;attempt<300;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE policy_publications%' ")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(fixture.reviewer.access_token)).status,200);await blocker.query('COMMIT');assert.equal((await pending).status,401);
 assert.equal((await policyDb.query('SELECT state FROM policy_publications WHERE id=$1',[fixture.pending.body.id])).rows[0].state,'pending');for(const table of ['policy_publication_audit','policy_publication_outbox'])assert.equal((await policyDb.query(`SELECT count(*)::int AS count FROM ${table} WHERE publication_id=$1`,[fixture.pending.body.id])).rows[0].count,1);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await policyDb.query('DROP TRIGGER owned_publication_audit_wait ON policy_publication_audit;DROP FUNCTION owned_publication_audit_wait()');}
});
test('actual reviewer role withdrawal and reissue cannot resurrect a stored publication or give its reviewer configuration/deployment powers',async()=>{
 const config=await firstRoleFactor('publication-role-config');const why={reason:'Actual independently approved role incarnation scope',acknowledgeScope:true};
 const created=await request(policyBase,'/api/policies',{method:'POST',token:config.access_token,body:{name:'Actual publication reviewer incarnation',type:'security',settings:{firewall:true},...why}});assert.equal(created.status,201);
 const fixture=await actualPublication('policy',created.body.id,config,'publication-role-review');const body={...why,publicationId:fixture.approved.body.id};const options={method:'POST',token:config.access_token,headers:{'If-Match':created.headers.get('etag')},body};
 assert.equal((await request(policyBase,fixture.root+'/activate',{...options,token:fixture.reviewer.access_token})).status,403);
 assert.equal((await request(policyBase,fixture.root,{method:'PUT',token:fixture.reviewer.access_token,headers:options.headers,body:{settings:{changed:true},...why}})).status,403);
 const voterId=canonicalSubjects.get('publication-role-review');await identityDb.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='policy-publication-reviewer' AND revoked_at IS NULL",[voterId],'owned-publication-reviewer-withdrawal');assert.equal((await request(gatewayBase,fixture.root+'/activate',options)).status,409);
 await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'policy-publication-reviewer','Explicit new actual publication reviewer incarnation')",[voterId],'owned-publication-reviewer-reissue');assert.equal((await request(policyBase,fixture.root+'/activate',options)).status,409);
 assert.equal((await request(policyBase,fixture.root+'/publications',{token:fixture.reviewer.access_token})).status,401);const row=(await policyDb.query('SELECT version,status FROM policies WHERE id=$1',[created.body.id])).rows[0];assert.deepEqual(row,{version:1,status:'draft'});
});
test('actual publication withdrawal after the first accepted blueprint command stops later sends and retains the possible prior side effect',async()=>{
 const config=await firstRoleFactor('publication-stop-config');const why={reason:'Actual independently approved explicit blueprint fleet',acknowledgeScope:true};
 const created=await request(policyBase,'/api/blueprints',{method:'POST',token:config.access_token,body:{name:'Actual independent delivery stop',...why}});assert.equal(created.status,201);let tag=created.headers.get('etag');
 for(const name of ['First owned configuration','Second owned configuration']){const added=await request(policyBase,'/api/blueprints/'+created.body.id+'/configurations',{method:'POST',token:config.access_token,headers:{'If-Match':tag},body:{config_type:'screen_lock',config_name:name,payload:{minutes:5},...why}});assert.equal(added.status,201);tag=added.headers.get('etag');}
 const device='publication-stop-'+randomUUID();await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform) VALUES($1,'Owned reviewed stop target','windows')",[device]);const assigned=await request(policyBase,'/api/blueprints/'+created.body.id+'/assign',{method:'POST',token:config.access_token,headers:{'If-Match':tag},body:{target_type:'device',target_id:device,...why}});assert.equal(assigned.status,201);tag=assigned.headers.get('etag');
 const fixture=await actualPublication('blueprint',created.body.id,config,'publication-stop-review');let entered;let release;let held=false;let pending;const reached=new Promise(resolve=>{entered=resolve;});const resume=new Promise(resolve=>{release=resolve;});
 const gate=(incoming,outgoing)=>{if(held||incoming.method!=='POST'||incoming.url!=='/api/devices/'+device+'/commands')return;held=true;const finish=outgoing.end;outgoing.end=function(...args){entered();resume.then(()=>finish.apply(this,args));return this;};};issuerServer.prependListener('request',gate);
 try{pending=request(gatewayBase,fixture.root+'/apply',{method:'POST',token:config.access_token,headers:{'If-Match':tag},body:{publicationId:fixture.approved.body.id,acknowledgeScope:true}});let timeout;try{await Promise.race([reached,new Promise((resolve,reject)=>{timeout=setTimeout(()=>reject(new Error('Owned publication delivery gate not reached')),5000);})]);}finally{clearTimeout(timeout);}
 const withdrawn=await request(gatewayBase,fixture.root+'/publications/'+fixture.approved.body.id+'/decisions',{method:'POST',token:fixture.reviewer.access_token,headers:{'If-Match':fixture.approved.headers.get('etag')},body:{decision:'withdrawn',resourceVersion:4,configurationHash:fixture.frame.configurationHash,...why}});assert.equal(withdrawn.status,200,JSON.stringify(withdrawn.body));release();const stopped=await pending;assert.equal(stopped.status,409,JSON.stringify(stopped.body));assert.equal(stopped.body.deliveryMayHaveOccurred,true);assert.equal(stopped.body.enforcementConfirmed,false);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[device])).rows[0].count,1);
 }finally{issuerServer.removeListener('request',gate);release();if(pending)await pending.catch(()=>{});}
});
test('actual GPO publication binds settings and explicit targets before canonical activation and managed queue delivery',async()=>{
 const config=await firstRoleFactor('publication-gpo-config');const why={reason:'Actual independent GPO content and device scope',acknowledgeScope:true};
 const created=await request(gatewayBase,'/api/gpo',{method:'POST',token:config.access_token,body:{name:'Actual independently reviewed GPO',type:'security',settings:{firewall:true},platforms:['windows'],...why}});assert.equal(created.status,201);const id=created.body.id;
 const device='publication-gpo-'+randomUUID();await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform) VALUES($1,'Owned GPO publication recipient','windows')",[device]);const assigned=await request(gatewayBase,'/api/policies/'+id+'/assign',{method:'POST',token:config.access_token,headers:{'If-Match':created.headers.get('etag')},body:{targetType:'device',targetId:device,...why}});assert.equal(assigned.status,201);
 const fixture=await actualPublication('policy',id,config,'publication-gpo-review');const active=await request(gatewayBase,fixture.root+'/activate',{method:'POST',token:config.access_token,headers:{'If-Match':assigned.headers.get('etag')},body:{publicationId:fixture.approved.body.id,...why}});assert.equal(active.status,200,JSON.stringify(active.body));
 const delivered=await request(gatewayBase,'/api/gpo/'+id+'/apply',{method:'POST',token:config.access_token,headers:{'If-Match':active.headers.get('etag')},body:{publicationId:fixture.approved.body.id,acknowledgeScope:true}});assert.equal(delivered.status,200,JSON.stringify(delivered.body));assert.equal(delivered.body.phase,'queued');assert.equal(delivered.body.enforcementConfirmed,false);const command=(await issuerDb.query('SELECT * FROM mdm_commands WHERE device_id=$1',[device])).rows;assert.equal(command.length,1);assert.deepEqual(command[0].payload.settings,{firewall:true});
});
let receiverBootstrapToken;
async function actualEnrolledPolicyDevice(name){
 if(!receiverBootstrapToken){const root=await issue();const tokens=await request(issuerBase,'/api/enrollment/tokens',{token:root.access_token});assert.equal(tokens.status,200);receiverBootstrapToken=tokens.body.find(row=>row.platform==='windows').token;}
 const registered=await request(issuerBase,'/api/enrollment/register',{method:'POST',body:{token:receiverBootstrapToken,platform:'windows',hostname:name,os:'Owned receiver test',serial:'owned-'+randomUUID()}});assert.equal(registered.status,201,JSON.stringify(registered.body));
 const device=(await issuerDb.query('SELECT id,platform,policy_generation FROM enrolled_devices WHERE id=$1',[registered.body.deviceId])).rows[0];assert.ok(device);assert.equal(payload(registered.body.deviceToken).device_generation,String(device.policy_generation));return registered.body;
}
async function actualReceiverFixture(prefix){
 const config=await firstRoleFactor(prefix+'-config');const device=await actualEnrolledPolicyDevice(prefix);const why={reason:'Actual independent receiver content and physical device scope',acknowledgeScope:true};
 const created=await request(gatewayBase,'/api/blueprints',{method:'POST',token:config.access_token,body:{name:'Actual receiver-bound '+prefix,platform:'windows',...why}});assert.equal(created.status,201);
 const added=await request(policyBase,'/api/blueprints/'+created.body.id+'/configurations',{method:'POST',token:config.access_token,headers:{'If-Match':created.headers.get('etag')},body:{config_type:'screen_lock',config_name:'Owned approved screen lock',payload:{minutes:5},...why}});assert.equal(added.status,201);
 const assigned=await request(policyBase,'/api/blueprints/'+created.body.id+'/assign',{method:'POST',token:config.access_token,headers:{'If-Match':added.headers.get('etag')},body:{target_type:'device',target_id:device.deviceId,...why}});assert.equal(assigned.status,201);
 const publication=await actualPublication('blueprint',created.body.id,config,prefix+'-review');const reference={resourceKind:'blueprint',resourceId:created.body.id,resourceVersion:assigned.body.parentVersion,publicationId:publication.approved.body.id,configurationId:added.body.id};
 return{config,device,publication,reference,tag:assigned.headers.get('etag'),why};
}
const receiverQueue=(fixture,operationId=randomUUID(),extra={})=>request(issuerBase,'/api/devices/'+fixture.device.deviceId+'/commands',{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':operationId},body:{command:'update_policy',reference:fixture.reference,...extra}});
test('actual receiver rejects free policy payloads even for a fresh global administrator or internal token and accepts only original source-derived content',async()=>{
 const fixture=await actualReceiverFixture('receiver-raw');const admin=await configureFactor('receiver-fresh-admin',await issue('receiver-fresh-admin'));const path='/api/devices/'+fixture.device.deviceId+'/commands';
 assert.equal((await request(issuerBase,path,{method:'POST',token:admin.access_token,body:{command:'update_policy',payload:{arbitrary:true}}})).status,400);
 const prior=process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;process.env.OAUTH_PROVIDER_INTERNAL_TOKEN='owned-receiver-internal-secret';
 try{assert.equal((await request(issuerBase,path,{method:'POST',headers:{'x-oauth-internal-token':process.env.OAUTH_PROVIDER_INTERNAL_TOKEN},body:{command:'update_policy',payload:{arbitrary:true}}})).status,403);}finally{if(prior===undefined)delete process.env.OAUTH_PROVIDER_INTERNAL_TOKEN;else process.env.OAUTH_PROVIDER_INTERNAL_TOKEN=prior;}
 assert.equal((await receiverQueue(fixture,randomUUID(),{payload:{minutes:999}})).status,400);
 const inventory=await request(issuerBase,'/api/devices/policy-registry',{token:admin.access_token});assert.equal(inventory.status,200);assert.deepEqual(Object.keys(inventory.body.find(row=>row.id===fixture.device.deviceId)).sort(),['hostname','id','platform']);
 const operation=randomUUID();const accepted=await receiverQueue(fixture,operation);assert.equal(accepted.status,201,JSON.stringify(accepted.body));assert.deepEqual(accepted.body.payload.settings,{minutes:5});assert.equal(accepted.body.policyReceipt.operatorUserId,canonicalSubjects.get('receiver-raw-config'));assert.equal(accepted.body.policyReceipt.operationId,operation);assert.equal(accepted.body.policyReceipt.persistence,'committed');assert.equal(accepted.body.enforcementConfirmed,false);
 const repeat=await receiverQueue(fixture,operation);assert.equal(repeat.status,201);assert.equal(repeat.body.id,accepted.body.id);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[fixture.device.deviceId])).rows[0].count,1);
 const audit=(await issuerDb.query('SELECT actor,evidence FROM policy_device_command_audit WHERE command_id=$1',[accepted.body.id])).rows;assert.equal(audit.length,1);assert.equal(audit[0].actor.userId,canonicalSubjects.get('receiver-raw-config'));assert.equal(JSON.stringify(audit).includes(fixture.config.access_token),false);
});
async function heldReceiverAcceptance(fixture,change){
 const gate='receiver-commit-'+randomUUID();const blocker=await issuerDb.pool.connect();const operation=randomUUID();let pending;
 await issuerDb.query(`CREATE FUNCTION owned_receiver_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.device_id='${fixture.device.deviceId}' AND NEW.action='queued' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER owned_receiver_audit_wait AFTER INSERT ON policy_device_command_audit FOR EACH ROW EXECUTE FUNCTION owned_receiver_audit_wait()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=receiverQueue(fixture,operation);let waiting=false;
 for(let attempt=0;attempt<300;attempt++){waiting=(await issuerDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO mdm_commands%' ")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);await change();await blocker.query('COMMIT');return await pending;
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await issuerDb.query('DROP TRIGGER owned_receiver_audit_wait ON policy_device_command_audit;DROP FUNCTION owned_receiver_audit_wait()');}
}
test('actual receiver rolls back its own queue, operation and audit when the original operator is revoked inside receiving DML',async()=>{
 const fixture=await actualReceiverFixture('receiver-actor-loss');const denied=await heldReceiverAcceptance(fixture,async()=>assert.equal((await revoke(fixture.config.access_token)).status,200));assert.equal(denied.status,401,JSON.stringify(denied.body));
 assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[fixture.device.deviceId])).rows[0].count,0);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM policy_device_command_audit WHERE device_id=$1',[fixture.device.deviceId])).rows[0].count,0);
 const polled=await request(issuerBase,'/api/devices/'+fixture.device.deviceId+'/commands/pending',{token:fixture.device.deviceToken});assert.equal(polled.status,200);assert.deepEqual(polled.body,[]);
});
test('actual receiver cannot commit after the independent reviewer withdraws publication while its mandatory receiving audit is blocked',async()=>{
 const fixture=await actualReceiverFixture('receiver-approval-loss');const denied=await heldReceiverAcceptance(fixture,async()=>{
 const withdrawn=await request(gatewayBase,fixture.publication.root+'/publications/'+fixture.publication.approved.body.id+'/decisions',{method:'POST',token:fixture.publication.reviewer.access_token,headers:{'If-Match':fixture.publication.approved.headers.get('etag')},body:{decision:'withdrawn',resourceVersion:fixture.reference.resourceVersion,configurationHash:fixture.publication.frame.configurationHash,...fixture.why}});assert.equal(withdrawn.status,200,JSON.stringify(withdrawn.body));
 });assert.equal(denied.status,409,JSON.stringify(denied.body));assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[fixture.device.deviceId])).rows[0].count,0);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM policy_device_command_outbox outbox JOIN policy_device_command_audit audit ON audit.id=outbox.id WHERE audit.device_id=$1',[fixture.device.deviceId])).rows[0].count,0);
});
test('actual generation-bound device credentials pull a committed command from a fresh issuer process and report once without an administrator impersonating the device',async()=>{
 const fixture=await actualReceiverFixture('receiver-pull');const queued=await receiverQueue(fixture);assert.equal(queued.status,201,JSON.stringify(queued.body));const path='/api/devices/'+fixture.device.deviceId+'/commands';const root=await issue();
 assert.equal((await request(issuerBase,path+'/pending',{token:root.access_token})).status,403);assert.equal((await request(issuerBase,path+'/'+queued.body.id,{method:'PATCH',token:fixture.device.deviceToken,body:{status:'completed',result:{reported:true}}})).status,409);
 const fresh=await startFreshIssuer();
 try{const offered=await request(fresh.base,path+'/pending',{token:fixture.device.deviceToken});assert.equal(offered.status,200,JSON.stringify(offered.body));assert.equal(offered.body.length,1);assert.equal(offered.body[0].id,queued.body.id);assert.deepEqual(offered.body[0].payload.settings,{minutes:5});assert.equal(offered.body[0].enforcementConfirmed,false);
 assert.equal((await request(fresh.base,path+'/'+queued.body.id,{method:'PATCH',token:root.access_token,body:{status:'completed',result:{reported:true}}})).status,403);
 const report=await request(fresh.base,path+'/'+queued.body.id,{method:'PATCH',token:fixture.device.deviceToken,body:{status:'completed',result:{reported:true}}});assert.equal(report.status,200,JSON.stringify(report.body));assert.equal(report.body.status,'completed');assert.equal(report.body.enforcementConfirmed,false);
 assert.equal((await request(fresh.base,path+'/'+queued.body.id,{method:'PATCH',token:fixture.device.deviceToken,body:{status:'failed',result:{different:true}}})).status,409);assert.deepEqual((await request(fresh.base,path+'/pending',{token:fixture.device.deviceToken})).body,[]);
 }finally{await fresh.stop();}
 const another=await receiverQueue(fixture);assert.equal(another.status,201);await issuerDb.query("UPDATE enrolled_devices SET status='flagged' WHERE id=$1",[fixture.device.deviceId]);await issuerDb.query("UPDATE enrolled_devices SET status='active' WHERE id=$1",[fixture.device.deviceId]);assert.equal((await request(issuerBase,path+'/pending',{token:fixture.device.deviceToken})).status,403);
});
test('actual managed sender refuses an old receiver during read-only preflight before any privileged write or false persistent receipt',async()=>{
 const fixture=await actualReceiverFixture('receiver-legacy');let posts=0;const older=http.createServer((incoming,outgoing)=>{if(incoming.method==='POST')posts++;outgoing.setHeader('Content-Type','application/json');outgoing.end(JSON.stringify({schemaVersion:0,legacy:true}));}).listen(0,'127.0.0.1');const oldBase=await listening(older);
 const script=`const app=require('./src');const db=require('./src/db/postgres');const server=app.listen(0,'127.0.0.1',()=>process.stdout.write('POLICY_PORT '+server.address().port+'\\n'));process.on('SIGTERM',async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await db.shutdown();process.exit(0)});`;
 const child=spawn(process.execPath,['-e',script],{cwd:path.join(__dirname,'../../../policy-service'),env:{...process.env,DATABASE_URL:databaseUrl(schemas[2]),OAUTH_PROVIDER_URL:oldBase},stdio:['ignore','pipe','pipe']});let output='';let errors='';child.stdout.on('data',chunk=>{output=(output+chunk).slice(-8192);});child.stderr.on('data',chunk=>{errors=(errors+chunk).slice(-8192);});
 try{let base;for(let attempt=0;attempt<500;attempt++){const match=/POLICY_PORT (\d+)/.exec(output);if(match){base='http://127.0.0.1:'+match[1];break;}if(child.exitCode!==null)throw new Error('Owned policy replica failed: '+errors);await new Promise(resolve=>setTimeout(resolve,20));}assert.ok(base,'Owned policy replica did not become ready: '+errors);
 const denied=await request(base,fixture.publication.root+'/apply',{method:'POST',token:fixture.config.access_token,headers:{'If-Match':fixture.tag},body:{publicationId:fixture.reference.publicationId,acknowledgeScope:true}});assert.equal(denied.status,503,JSON.stringify(denied.body));assert.equal(posts,0);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[fixture.device.deviceId])).rows[0].count,0);
 }finally{await new Promise(resolve=>older.close(resolve));if(child.exitCode===null&&child.signalCode===null){const exited=once(child,'exit');child.kill('SIGTERM');await exited;}}
});
test('actual owned policy cancellation survives publication withdrawal and fresh receiver processes while rejecting another administrator and the device itself', async () => {
 const fixture=await actualReceiverFixture('receiver-cancel');const queued=await receiverQueue(fixture);assert.equal(queued.status,201,JSON.stringify(queued.body));const receipt=queued.body.policyReceipt;
 const path='/api/devices/'+fixture.device.deviceId+'/commands/'+queued.body.id+'/cancel';const operationId=randomUUID();const body={policyReceipt:receipt,reason:'Explicitly stop the original owned receiver command',acknowledgeScope:true};
 const offered=await request(issuerBase,'/api/devices/'+fixture.device.deviceId+'/commands/pending',{token:fixture.device.deviceToken});assert.equal(offered.status,200);assert.equal(offered.body[0].id,queued.body.id);
 const other=await configureFactor('receiver-cancel-admin',await issue('receiver-cancel-admin'));assert.equal((await request(issuerBase,path,{method:'POST',token:other.access_token,headers:{'X-OD-Operation-Id':operationId},body})).status,404);
 assert.equal((await request(issuerBase,path,{method:'POST',token:fixture.publication.reviewer.access_token,headers:{'X-OD-Operation-Id':operationId},body})).status,403);
 assert.equal((await request(issuerBase,path,{method:'POST',token:fixture.device.deviceToken,headers:{'X-OD-Operation-Id':operationId},body})).status,403);
 assert.equal((await request(issuerBase,path,{method:'POST',headers:{'x-oauth-internal-token':'not-a-human'},body})).status,401);
 const withdrawn=await request(gatewayBase,fixture.publication.root+'/publications/'+fixture.publication.approved.body.id+'/decisions',{method:'POST',token:fixture.publication.reviewer.access_token,headers:{'If-Match':fixture.publication.approved.headers.get('etag')},body:{decision:'withdrawn',resourceVersion:fixture.reference.resourceVersion,configurationHash:fixture.publication.frame.configurationHash,...fixture.why}});assert.equal(withdrawn.status,200,JSON.stringify(withdrawn.body));
 const fresh=await startFreshIssuer();let cancelled;
 try{const response=await request(fresh.base,path,{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':operationId},body});assert.equal(response.status,200,JSON.stringify(response.body));cancelled=response.body;assert.equal(cancelled.previouslyOffered,true);assert.equal(cancelled.furtherOffersStopped,true);assert.equal(cancelled.enforcementConfirmed,false);assert.deepEqual(cancelled.policyReceipt,receipt);
 const repeated=await request(issuerBase,path,{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':operationId},body});assert.equal(repeated.status,200);assert.deepEqual(repeated.body,cancelled);
 assert.deepEqual((await request(fresh.base,'/api/devices/'+fixture.device.deviceId+'/commands/pending',{token:fixture.device.deviceToken})).body,[]);
 assert.equal((await request(fresh.base,'/api/devices/'+fixture.device.deviceId+'/commands/'+queued.body.id,{method:'PATCH',token:fixture.device.deviceToken,body:{status:'completed',result:'An old device result cannot overwrite cancellation'}})).status,409);
 }finally{await fresh.stop();}
 const query='/api/devices/policy-commands?resourceKind=blueprint&resourceId='+fixture.reference.resourceId;const current=await request(issuerBase,query,{token:fixture.config.access_token});assert.equal(current.status,200);assert.equal(current.body.commands.length,1);assert.deepEqual(current.body.commands[0].cancellationReceipt,cancelled);assert.equal(JSON.stringify(current.body).includes('payload"'),false);
 const foreign=await request(issuerBase,query,{token:other.access_token});assert.equal(foreign.status,200);assert.deepEqual(foreign.body.commands,[]);
 const audit=(await issuerDb.query('SELECT action FROM policy_device_command_audit WHERE command_id=$1 ORDER BY version',[queued.body.id])).rows.map(row=>row.action);assert.deepEqual(audit,['queued','dispatched','cancelled']);
});
test('actual policy cancellation rolls back its status and retained reason when the original human is revoked during receiving audit DML', async () => {
 const fixture=await actualReceiverFixture('receiver-cancel-revoked');const queued=await receiverQueue(fixture);assert.equal(queued.status,201);const gate='cancel-commit-'+randomUUID();const blocker=await issuerDb.pool.connect();let pending;
 await issuerDb.query(`CREATE FUNCTION owned_cancellation_audit_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.command_id='${queued.body.id}' AND NEW.action='cancelled' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER owned_cancellation_audit_wait AFTER INSERT ON policy_device_command_audit FOR EACH ROW EXECUTE FUNCTION owned_cancellation_audit_wait()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(issuerBase,'/api/devices/'+fixture.device.deviceId+'/commands/'+queued.body.id+'/cancel',{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':randomUUID()},body:{policyReceipt:queued.body.policyReceipt,reason:'Original human must remain current through cancellation',acknowledgeScope:true}});let waiting=false;
 for(let attempt=0;attempt<300;attempt++){waiting=(await issuerDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE mdm_commands SET status=%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(fixture.config.access_token)).status,200);await blocker.query('COMMIT');const denied=await pending;assert.equal(denied.status,401,JSON.stringify(denied.body));
 assert.equal((await issuerDb.query('SELECT status FROM mdm_commands WHERE id=$1',[queued.body.id])).rows[0].status,'pending');assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM policy_device_cancellations WHERE command_id=$1',[queued.body.id])).rows[0].count,0);assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM policy_device_command_audit WHERE command_id=$1',[queued.body.id])).rows[0].count,1);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await issuerDb.query('DROP TRIGGER owned_cancellation_audit_wait ON policy_device_command_audit;DROP FUNCTION owned_cancellation_audit_wait()');}
});
test('actual policy cancellation cannot acknowledge unavailable durable evidence or a changed original command receipt', async () => {
 const fixture=await actualReceiverFixture('receiver-cancel-audit');const queued=await receiverQueue(fixture);assert.equal(queued.status,201);const path='/api/devices/'+fixture.device.deviceId+'/commands/'+queued.body.id+'/cancel';const body={policyReceipt:queued.body.policyReceipt,reason:'Require actual retained cancellation evidence and exact source',acknowledgeScope:true};
 assert.equal((await request(issuerBase,path,{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':randomUUID()},body:{...body,policyReceipt:{...body.policyReceipt,payloadHash:'f'.repeat(64)}}})).status,409);
 await issuerDb.query('ALTER TABLE policy_device_cancellations RENAME TO owned_cancellations_unavailable');
 try{const failed=await request(issuerBase,path,{method:'POST',token:fixture.config.access_token,headers:{'X-OD-Operation-Id':randomUUID()},body});assert.equal(failed.status,503,JSON.stringify(failed.body));}finally{await issuerDb.query('ALTER TABLE owned_cancellations_unavailable RENAME TO policy_device_cancellations');}
 assert.equal((await issuerDb.query('SELECT status FROM mdm_commands WHERE id=$1',[queued.body.id])).rows[0].status,'pending');assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM policy_device_command_outbox WHERE command_id=$1',[queued.body.id])).rows[0].count,1);
});
async function issueForApplication(client,username = 'operator',scope = 'openid roles') {
  const otpCode = await nextOtp(username);
  const login = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: client.clientId, redirect_uri: client.redirectUris[0],
    username, password: 'disposable-password', scope, ...(otpCode ? { otpCode } : {}) } });
  assert.equal(login.status, 302);
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const pair = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'authorization_code', code, client_id: client.clientId, client_secret: client.clientSecret, redirect_uri: client.redirectUris[0] } });
  assert.equal(pair.status, 200); return pair.body;
}

async function applicationGrant(client,token,targetType,targetId,extra = {}) {
  return request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ method: 'POST',token,body: { requestId: randomUUID(),targetType,targetId,durationSeconds: 3600,reason: 'Reviewed independent application access',...extra } });
}
async function groupSourceFixture(prefix,seconds=3600){
 const config=await firstRoleFactor(prefix+'-config');const root=await issue();const client=await registerApplication(root.access_token,{grantTypes:['client_credentials'],scopes:['licenses.groups.derive'],redirectUris:[]},false);
 const groupId=randomUUID();await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Actual dedicated source-consent group')",[groupId],'owned-source-fixture');await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,canonicalSubjects.get('fulfillment-beneficiary')],'owned-source-fixture');
 const licenseId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual scoped source automation pool',3) RETURNING id")).rows[0].id;
 assert.equal((await request(policyBase,'/api/licenses/'+licenseId+'/assign',{method:'POST',token:root.access_token,body:{assignee_type:'group',assignee_id:groupId}})).status,201);
 const base='/api/identity/license-sources';const body={groupId,clientId:client.clientId,expectedClientRevision:client.version,expiresAt:new Date(Date.now()+seconds*1000).toISOString(),reason:'Explicit actual generation-bound group source consent',acknowledgeReadScope:true};
 const created=await request(gatewayBase,base,{method:'POST',token:config.access_token,body});assert.equal(created.status,201,JSON.stringify(created.body));
 const{GroupSnapshotClient}=require('../../../policy-service/src/licenses/GroupSnapshotClient');const{LicenseAllocator}=require('../../../policy-service/src/licenses/LicenseAllocator');const{GroupLicenseAllocator}=require('../../../policy-service/src/licenses/GroupLicenseAllocator');const{SourceCredential}=require('../../../policy-service/src/licenses/SourceCredentials');
 const source=new GroupSnapshotClient({baseUrl:identityBase});const allocator=new LicenseAllocator(policyDb,{source});const groups=new GroupLicenseAllocator({allocator,source});
 const credentials=new SourceCredential({tokenUrl:issuerBase+'/oauth/token',clientId:client.clientId,clientSecret:client.clientSecret},'licenses.groups.derive');
 return{config,root,client,groupId,licenseId,base,body,grant:created.body,allocator,groups,credentials,SourceCredential};
}
test('actual dedicated source credentials renew before signed expiry and extend only the configured group lease without human roles or profile access',async()=>{
 const fixture=await groupSourceFixture('source-refresh');const fresh=await startFreshIssuer({TOKEN_TTL_SECONDS:'60'});
 const source=new fixture.SourceCredential({tokenUrl:fresh.base+'/oauth/token',clientId:fixture.client.clientId,clientSecret:fixture.client.clientSecret},'licenses.groups.derive');
 try{
 const first=(await source.authorization()).slice(7);const proof=payload(first);assert.equal(proof.actor_type,'application');assert.equal(proof.roles,undefined);assert.equal(proof.identity_authorization,undefined);assert.deepEqual(proof.permissions,['licenses.groups.derive']);assert.equal(proof.exp-proof.iat,60);
 const snapshot=await request(gatewayBase,'/api/license-groups/'+fixture.groupId+'/snapshot',{token:first});assert.equal(snapshot.status,200,JSON.stringify(snapshot.body));assert.equal(snapshot.body.sourceAuthorization.grantId,fixture.grant.id);assert.equal(snapshot.body.viewerUserId,null);
 for(const route of ['/api/users','/api/identity/subject','/api/identity/access','/api/license-users/'+canonicalSubjects.get('fulfillment-beneficiary')+'/snapshot'])assert.equal((await request(identityBase,route,{token:first})).status,403);
 assert.equal((await request(identityBase,'/api/license-groups/'+randomUUID()+'/snapshot',{token:first})).status,403);
 assert.equal((await request(policyBase,'/api/licenses/'+fixture.licenseId+'/assign',{method:'POST',token:first,body:{assignee_type:'user',assignee_id:canonicalSubjects.get('alice')}})).status,403);
 assert.equal((await request(policyBase,'/api/policies',{method:'POST',token:first,body:{name:'A source reader cannot create policy configuration'}})).status,403);
 assert.equal((await request(identityBase,'/api/users',{token:fixture.config.access_token})).status,403);assert.equal((await request(issuerBase,'/api/clients',{token:fixture.config.access_token})).status,403);
 await fixture.groups.reconcileAll(source);const before=(await policyDb.query('SELECT * FROM license_group_observations WHERE license_id=$1',[fixture.licenseId])).rows[0];assert.equal(before.source_authorization.grantId,fixture.grant.id);
 await new Promise(resolve=>setTimeout(resolve,31000));await fixture.groups.reconcileAll(source);const second=(await source.authorization()).slice(7);assert.notEqual(second,first);assert.ok(payload(second).exp>proof.exp);
 const after=(await policyDb.query('SELECT * FROM license_group_observations WHERE license_id=$1',[fixture.licenseId])).rows[0];assert.ok(after.valid_until>before.valid_until);assert.equal(after.source_revision,before.source_revision);assert.equal(after.source_hash,before.source_hash);
 assert.equal((await policyDb.query('SELECT expires_at FROM license_assignments WHERE license_id=$1',[fixture.licenseId])).rows[0].expires_at.getTime(),after.valid_until.getTime());
 }finally{source.stop();await fresh.stop();}
});
test('the actual source-consent deadline caps local entitlement before the directory horizon without a group poll or sweeper',async()=>{
 const fixture=await groupSourceFixture('source-cutoff',120);await fixture.groups.reconcileAll(fixture.credentials);const assignment=(await policyDb.query('SELECT expires_at FROM license_assignments WHERE license_id=$1',[fixture.licenseId])).rows[0];
 assert.equal(assignment.expires_at.toISOString(),fixture.grant.expiresAt);
 try{await policyDb.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '121 seconds'; $$");assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE license_id=$1 AND expires_at>license_now()',[fixture.licenseId])).rows[0].count,0);
 const rows=await request(policyBase,'/api/licenses/groups',{token:fixture.root.access_token});assert.equal(rows.status,200);assert.equal(rows.body.groups.find(row=>row.license_id===fixture.licenseId).status,'source-consent-expired');
 }finally{fixture.credentials.stop();await policyDb.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');}
});
test('actual OAuth secret rotation cannot silently restamp a source consent; fresh client generation needs explicit withdrawal and reissue',async()=>{
 const fixture=await groupSourceFixture('source-rotation');await fixture.groups.reconcileAll(fixture.credentials);const before=(await policyDb.query('SELECT * FROM license_group_observations WHERE license_id=$1',[fixture.licenseId])).rows[0];
 const rotated=await request(issuerBase,'/api/clients/'+fixture.client.clientId+'/rotate-secret',{method:'POST',token:fixture.root.access_token,headers:clientCondition(fixture.client)});assert.equal(rotated.status,200);
 await fixture.groups.reconcileAll(fixture.credentials);assert.equal(fixture.credentials.tokens.cached,null);assert.deepEqual((await policyDb.query('SELECT * FROM license_group_observations WHERE license_id=$1',[fixture.licenseId])).rows[0],before);
 const fresh=new fixture.SourceCredential({tokenUrl:issuerBase+'/oauth/token',clientId:fixture.client.clientId,clientSecret:rotated.body.clientSecret},'licenses.groups.derive');const token=(await fresh.authorization()).slice(7);
 assert.equal((await request(identityBase,'/api/license-groups/'+fixture.groupId+'/snapshot',{token})).status,403);
 const withdrawn=await request(gatewayBase,fixture.base+'/'+fixture.grant.id+'/revoke',{method:'POST',token:fixture.config.access_token,headers:{'If-Match':`"od-group-source:${fixture.grant.id}:1"`},body:{reason:'Explicit source generation withdrawal before reissue',acknowledgeReadScope:true}});assert.equal(withdrawn.status,200,JSON.stringify(withdrawn.body));
 const stale=await request(identityBase,fixture.base,{method:'POST',token:fixture.config.access_token,body:fixture.body});assert.equal(stale.status,412);
 const replacement=await request(identityBase,fixture.base,{method:'POST',token:fixture.config.access_token,body:{...fixture.body,expectedClientRevision:rotated.body.version}});assert.equal(replacement.status,201);assert.notEqual(replacement.body.id,fixture.grant.id);assert.equal(replacement.body.clientRevision,rotated.body.version);
 await fixture.groups.reconcileAll(fresh);assert.equal((await policyDb.query('SELECT source_authorization FROM license_group_observations WHERE license_id=$1',[fixture.licenseId])).rows[0].source_authorization.grantId,replacement.body.id);fresh.stop();fixture.credentials.stop();
});
test('original consent-author revocation inside actual withdrawal audit DML rolls back scope, version and evidence without removing a valid reader',async()=>{
 const fixture=await groupSourceFixture('source-withdrawn');const gate='source-author-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query(`CREATE FUNCTION pause_owned_source_withdrawal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='revoke' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER pause_owned_source_withdrawal BEFORE INSERT ON identity_group_source_audit FOR EACH ROW EXECUTE FUNCTION pause_owned_source_withdrawal()`);await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
 try{pending=request(identityBase,fixture.base+'/'+fixture.grant.id+'/revoke',{method:'POST',token:fixture.config.access_token,headers:{'If-Match':`"od-group-source:${fixture.grant.id}:1"`},body:{reason:'A withdrawn source author must not commit consent withdrawal',acknowledgeReadScope:true}});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE identity_group_source_grants SET version=%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(fixture.config.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await pending).status));
 const row=(await identityDb.query('SELECT * FROM identity_group_source_grants WHERE id=$1',[fixture.grant.id])).rows[0];assert.equal(row.version,'1');assert.equal(row.revoked_at,null);assert.equal((await identityDb.query("SELECT count(*)::int AS count FROM identity_group_source_audit WHERE grant_id=$1 AND action='revoke'",[fixture.grant.id])).rows[0].count,0);
 const token=(await fixture.credentials.authorization()).slice(7);assert.equal((await request(identityBase,'/api/license-groups/'+fixture.groupId+'/snapshot',{token})).status,200);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_owned_source_withdrawal ON identity_group_source_audit;DROP FUNCTION pause_owned_source_withdrawal()');fixture.credentials.stop();}
});
test('an original issuer withdrawal during directory lease evidence DML rolls back the actual positive group allocation',async()=>{
 const root=await issue();const groupId=randomUUID();const recipient=canonicalSubjects.get('alice');assert.ok(recipient);
 await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Actual bounded source issuer withdrawal')",[groupId],'owned-lease-fixture');await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,recipient],'owned-lease-fixture');
 const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual bounded source issuer withdrawal',2) RETURNING id")).rows[0].id;
 const gate='group-lease-'+randomUUID();const blocker=await policyDb.getClient();let pending;
 await policyDb.query(`CREATE FUNCTION pause_owned_group_lease() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));RETURN NEW;END;$$;CREATE TRIGGER pause_owned_group_lease BEFORE INSERT ON license_group_lease_audit FOR EACH ROW EXECUTE FUNCTION pause_owned_group_lease()`);await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
 try{
 pending=request(policyBase,'/api/licenses/'+poolId+'/assign',{method:'POST',token:root.access_token,body:{assignee_type:'group',assignee_id:groupId}});let waiting=false;
 for(let attempt=0;attempt<200;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO license_group_observations%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);
 assert.equal((await revoke(root.access_token)).status,200);await blocker.query('COMMIT');const result=await pending;assert.ok([401,403].includes(result.status),JSON.stringify(result));
 assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE license_id=$1',[poolId])).rows[0].count,0);assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_group_observations WHERE license_id=$1',[poolId])).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await policyDb.query('DROP TRIGGER pause_owned_group_lease ON license_group_lease_audit;DROP FUNCTION pause_owned_group_lease()');}
});
async function membershipReviewFixture(prefix){
 const config=await firstRoleFactor(prefix+'-config');const voter=await firstRoleFactor(prefix+'-voter');const grantor=await configureFactor(prefix+'-grantor',await issue(prefix+'-grantor'));const holder=await issue(prefix+'-holder');const group=await groupRequest(identityBase,'/api/groups',{method:'POST',token:grantor.access_token,body:{name:'Actual independently reviewed application/license group'}});assert.equal(group.status,201);
 const base='/api/identity/membership-reviews';const configured=await request(gatewayBase,base+'/policies',{method:'POST',token:config.access_token,body:{groupId:group.body.id,intervalSeconds:60,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get(prefix+'-voter')],reason:'Independent actual application and license group membership governance',acknowledgeEffects:true}});assert.equal(configured.status,201,JSON.stringify(configured.body));
 const add=await groupRequest(identityBase,'/api/groups/'+group.body.id+'/members',{method:'POST',token:grantor.access_token,body:{userId:canonicalSubjects.get(prefix+'-holder')}});assert.equal(add.status,200,JSON.stringify(add.body));const queue=await request(gatewayBase,base+'/assigned',{token:voter.access_token});assert.equal(queue.status,200);const row=queue.body.reviews.find(value=>value.groupId===group.body.id);assert.ok(row);assert.equal(row.state,'awaiting');assert.equal(row.effective,false);return{base,config,voter,grantor,holder,groupId:group.body.id,row};
}
test('actual independently reviewed membership gates application sign-in, revokes real sessions at cutoff and reconciles real licensed group seats',async()=>{
 const prefix='membership-review';const fixture=await membershipReviewFixture(prefix);const{base,config,voter,holder,groupId,row}=fixture;const root=await issue();const accessManager=await issue('app-access-manager');const application=await registerApplication(root.access_token,{scopes:['openid']},false);const granted=await applicationGrant(application,accessManager.access_token,'group',groupId);assert.equal(granted.status,201,JSON.stringify(granted.body));
 const login=()=>request(issuerBase,'/oauth/authorize/login',{method:'POST',body:{client_id:application.clientId,redirect_uri:application.redirectUris[0],username:prefix+'-holder',password:'disposable-password',scope:'openid'}});assert.equal((await login()).status,403);
 const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual membership-reviewed licensing pool',3) RETURNING id")).rows[0].id;const poolRoute='/api/licenses/'+poolId;assert.equal((await request(policyBase,poolRoute+'/assign',{method:'POST',token:root.access_token,body:{assignee_type:'group',assignee_id:groupId}})).status,201);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,0);
 const vote=await request(gatewayBase,base+'/'+row.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':`"od-membership-review:${row.id}:1:1"`},body:{decision:'retain',reason:'Independent actual first membership approval',acknowledgeScope:true}});assert.equal(vote.status,200,JSON.stringify(vote.body));assert.equal(vote.body.effective,true);const pair=await issueForApplication(application,prefix+'-holder','openid');
 assert.equal((await request(policyBase,poolRoute+'/groups/'+groupId+'/reconcile',{method:'POST',token:root.access_token,body:{}})).status,200);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
 try{
  const projection=(await policyDb.query('SELECT expires_at FROM license_assignments WHERE license_id=$1',[poolId])).rows[0];assert.equal(projection.expires_at.toISOString(),vote.body.deadlineAt);assert.ok(Date.parse(vote.body.deadlineAt)-Date.now()<121000);
  await policyDb.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '121 seconds'; $$");
  assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>license_now())',[poolId])).rows[0].count,0);
  const stale=await request(policyBase,'/api/licenses/groups',{token:root.access_token});assert.equal(stale.status,200);assert.equal(stale.body.groups.find(value=>value.license_id===poolId).status,'membership-expired');
  await policyDb.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
  await identityDb.query("CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '121 seconds'; $$");assert.equal((await request(issuerBase,'/oauth/access-state',{token:pair.access_token})).body.active,false);assert.equal((await login()).status,403);
  const expired=await request(gatewayBase,'/api/license-groups/'+groupId+'/snapshot',{token:root.access_token});assert.equal(expired.status,200);assert.deepEqual(expired.body.memberIds,[]);assert.equal((await request(policyBase,poolRoute+'/groups/'+groupId+'/reconcile',{method:'POST',token:root.access_token,body:{}})).status,200);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,0);
  assert.equal((await request(policyBase,poolRoute+'/assign',{method:'POST',token:root.access_token,body:{assignee_type:'user',assignee_id:canonicalSubjects.get(prefix+'-holder')}})).status,201);assert.equal((await groupRequest(identityBase,'/api/groups/'+groupId+'/members/'+canonicalSubjects.get(prefix+'-holder'),{method:'DELETE',token:fixture.grantor.access_token})).status,200);assert.equal((await groupRequest(identityBase,'/api/groups/'+groupId+'/members',{method:'POST',token:fixture.grantor.access_token,body:{userId:canonicalSubjects.get(prefix+'-holder')}})).status,200);
  const queue=await request(identityBase,base+'/assigned',{token:voter.access_token});const current=queue.body.reviews.find(value=>value.membershipId!==row.membershipId&&value.groupId===groupId);assert.ok(current);assert.equal(current.effective,false);const denied=await request(identityBase,base+'/'+current.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':`"od-membership-review:${current.id}:1:1"`},body:{decision:'deny',reason:'Withdraw only this new group incarnation, not direct recipient licenses',acknowledgeScope:true}});assert.equal(denied.status,200);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
  assert.equal((await request(identityBase,'/api/users',{token:config.access_token})).status,403);assert.equal((await request(identityBase,base+'/'+current.id+'/decisions',{method:'POST',token:root.access_token,body:{}})).status,403);
 }finally{await policyDb.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');await identityDb.query('CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');}
});
test('original reviewer withdrawal during actual membership denial audit rolls back group edges, cutoff projection and review evidence',async()=>{
 const{base,voter,groupId,row}=await membershipReviewFixture('membership-revoked');const gate='membership-voter-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query(`CREATE FUNCTION pause_membership_vote() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='deny' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER pause_membership_vote BEFORE INSERT ON identity_membership_review_audit FOR EACH ROW EXECUTE FUNCTION pause_membership_vote()`);await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
 try{pending=request(identityBase,base+'/'+row.id+'/decisions',{method:'POST',token:voter.access_token,headers:{'If-Match':`"od-membership-review:${row.id}:1:1"`},body:{decision:'deny',reason:'A withdrawn original voter may not commit membership denial',acknowledgeScope:true}});let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE identity_membership_review_leases SET version=%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(voter.access_token)).status,200);await blocker.query('COMMIT');assert.ok([401,403].includes((await pending).status));
  assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[groupId])).rows[0].count,1);assert.equal((await identityDb.query('SELECT version FROM identity_membership_review_leases WHERE id=$1',[row.id])).rows[0].version,'1');assert.equal((await identityDb.query("SELECT count(*)::int AS count FROM identity_membership_review_audit WHERE review_id=$1 AND action='deny'",[row.id])).rows[0].count,0);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_membership_vote ON identity_membership_review_audit;DROP FUNCTION pause_membership_vote()');}
});
test('application assignment is mandatory even for global administrators and management does not imply user/profile authority', async () => {
  const administrator = await issue(); const manager = await issue('app-access-manager'); const reader = await issue('app-access-reader');
  const metadataOperator = await issue('app-operator'); const client = await registerApplication(administrator.access_token,{},false);
  const login = await request(issuerBase,'/oauth/authorize/login',{ method: 'POST',body: { client_id: client.clientId,redirect_uri: client.redirectUris[0],username: 'operator',password: 'disposable-password',scope: 'openid roles' } });
  assert.equal(login.status,403); assert.equal(login.body.error,'application_not_assigned');
  for (const token of [manager.access_token,reader.access_token]) {
    assert.equal((await request(issuerBase,'/api/clients',{ token })).status,403); assert.equal((await request(identityBase,'/api/users',{ token })).status,403);
    assert.equal((await request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ token })).status,200);
  }
  assert.equal((await applicationGrant(client,metadataOperator.access_token,'user',canonicalUser)).status,403);
  assert.equal((await applicationGrant(client,manager.access_token,'user',canonicalUser)).status,403);
  const independent = await issue('second-admin'); assert.equal((await applicationGrant(client,independent.access_token,'user',canonicalUser)).status,201);
  assert.ok((await issueForApplication(client)).access_token);
});
test('individual application revocation blocks real license writes without disabling the client or another assigned user', async () => {
  const administrator = await issue(); const independent = await issue('second-admin'); const client = await registerApplication(administrator.access_token);
  const otherGrant = await applicationGrant(client,independent.access_token,'user',canonicalSubjects.get('alice')); assert.equal(otherGrant.status,201);
  const pair = await issueForApplication(client); const other = await issueForApplication(client,'alice');
  const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,3) RETURNING id',['Application entitlement pool'])).rows[0]; const recipient = randomUUID();
  await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[recipient,recipient,recipient+'@test.invalid']);
  const route = `/api/licenses/${product.id}/assign`; const body = { assignee_type: 'user',assignee_id: recipient };
  assert.equal((await request(gatewayBase,route,{ method: 'POST',token: pair.access_token,body })).status,201);
  const page = await request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ token: independent.access_token }); const own = page.body.assignments.find(row => row.targetId === canonicalUser);
  assert.equal((await request(issuerBase,`/api/clients/${client.clientId}/assignments/${own.id}`,{ method: 'DELETE',token: independent.access_token })).status,200);
  for (const [base,path] of [[gatewayBase,route],[policyBase,route]]) assert.equal((await request(base,path,{ method: 'POST',token: pair.access_token,body })).status,401);
  assert.equal((await request(issuerBase,'/oauth/access-state',{ token: other.access_token })).body.active,true);
  assert.equal((await issuerDb.query('SELECT revision FROM oauth_clients WHERE id=$1',[client.clientId])).rows[0].revision,client.version);
  assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[product.id])).rows[0].count,1);
  assert.equal((await request(issuerBase,'/oauth/token',{ method: 'POST',body: { grant_type: 'refresh_token',client_id: client.clientId,client_secret: client.clientSecret,refresh_token: pair.refresh_token } })).body.error,'invalid_grant');
  assert.equal((await applicationGrant(client,independent.access_token,'user',canonicalUser)).status,201);
  assert.equal((await request(issuerBase,'/oauth/access-state',{ token: pair.access_token })).body.active,false); assert.ok((await issueForApplication(client)).access_token);
});
test('group app access follows canonical membership incarnations, not credential group claims, and overlapping direct grants remain usable', async () => {
  const administrator = await issue(); const metadataOperator = await issue('app-operator'); const manager = await issue('app-access-manager');
  const client = await registerApplication(metadataOperator.access_token,{ scopes: ['openid','groups'] },false);
  const group = await groupRequest(identityBase,'/api/groups',{ method: 'POST',token: administrator.access_token,body: { name: 'Application eligibility '+randomUUID() } }); assert.equal(group.status,201);
  const groupId = group.body.id; assert.equal((await applicationGrant(client,manager.access_token,'group',groupId)).status,201);
  const aliceId = canonicalSubjects.get('alice'); credentialGroupOverrides.set('alice',[groupId]);
  try {
    const credentials = { client_id: client.clientId,redirect_uri: client.redirectUris[0],username: 'alice',password: 'disposable-password',scope: 'openid groups',groups: [groupId] };
    assert.equal((await request(issuerBase,'/oauth/authorize/login',{ method: 'POST',body: credentials })).status,403);
    assert.equal((await groupRequest(identityBase,`/api/groups/${groupId}/members`,{ method: 'POST',token: administrator.access_token,body: { userId: aliceId } })).status,200);
    const pair = await issueForApplication(client,'alice','openid groups');
    const member = (await identityDb.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,aliceId])).rows[0].membership_id;
    assert.equal((await groupRequest(identityBase,`/api/groups/${groupId}/members/${aliceId}`,{ method: 'DELETE',token: administrator.access_token })).status,200);
    assert.equal((await request(issuerBase,'/oauth/access-state',{ token: pair.access_token })).body.active,false);
    assert.equal((await request(issuerBase,'/oauth/authorize/login',{ method: 'POST',body: credentials })).status,403);
    assert.equal((await groupRequest(identityBase,`/api/groups/${groupId}/members`,{ method: 'POST',token: administrator.access_token,body: { userId: aliceId } })).status,200);
    assert.notEqual((await identityDb.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,aliceId])).rows[0].membership_id,member);
    assert.equal((await request(issuerBase,'/oauth/access-state',{ token: pair.access_token })).body.active,false); assert.ok((await issueForApplication(client,'alice','openid groups')).access_token);
    const direct = await applicationGrant(client,manager.access_token,'user',aliceId); assert.equal(direct.status,201);
    await groupRequest(identityBase,`/api/groups/${groupId}/members/${aliceId}`,{ method: 'DELETE',token: administrator.access_token }); assert.ok((await issueForApplication(client,'alice','openid groups')).access_token);
  } finally { credentialGroupOverrides.delete('alice'); }
});
test('self-target aliases and current own group membership cannot manufacture an application grant', async () => {
  const administrator = await issue(); const metadataOperator = await issue('app-operator'); const manager = await issue('app-access-manager'); const managerId = canonicalSubjects.get('app-access-manager');
  const client = await registerApplication(metadataOperator.access_token,{ scopes: ['openid'] },false);
  assert.equal((await applicationGrant(client,manager.access_token,'user',managerId)).status,403);
  assert.equal((await applicationGrant(client,manager.access_token,'user',randomUUID())).status,403);
  assert.equal((await applicationGrant(client,manager.access_token,'user',canonicalSubjects.get('alice'),{ actor: 'forged' })).status,400);
  const group = await groupRequest(identityBase,'/api/groups',{ method: 'POST',token: administrator.access_token,body: { name: 'Self member group '+randomUUID() } }); assert.equal(group.status,201);
  await groupRequest(identityBase,`/api/groups/${group.body.id}/members`,{ method: 'POST',token: administrator.access_token,body: { userId: managerId } });
  assert.equal((await applicationGrant(client,manager.access_token,'group',group.body.id)).status,403);
});
test('application assignment store failure denies live access and refresh without consuming a still-valid refresh credential', async () => {
  const pair = await issue(); await issuerDb.query('ALTER TABLE oauth_application_assignments RENAME TO unavailable_application_assignments');
  try {
    for (const [base,path] of [[issuerBase,'/oauth/access-state'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/identity/subject'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']]) assert.equal((await request(base,path,{ token: pair.access_token })).status,503);
    assert.equal((await request(issuerBase,'/oauth/token',{ method: 'POST',body: { grant_type: 'refresh_token',client_id: clientId,client_secret: clientSecret,refresh_token: pair.refresh_token } })).status,503);
  } finally { await issuerDb.query('ALTER TABLE unavailable_application_assignments RENAME TO oauth_application_assignments'); }
  assert.equal((await request(issuerBase,'/oauth/token',{ method: 'POST',body: { grant_type: 'refresh_token',client_id: clientId,client_secret: clientSecret,refresh_token: pair.refresh_token } })).status,200);
});
test('withdrawal and a new application lease cannot revive pending code or already approved device checkpoints', async () => {
  const administrator = await issue(); const independent = await issue('second-admin'); const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
  const client = await registerApplication(administrator.access_token,{ grantTypes: ['authorization_code','refresh_token',deviceGrant] });
  const login = await request(issuerBase,'/oauth/authorize/login',{ method: 'POST',body: { client_id: client.clientId,redirect_uri: client.redirectUris[0],username: 'operator',password: 'disposable-password',scope: 'openid roles' } }); assert.equal(login.status,302);
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase,'/oauth/device/code',{ method: 'POST',body: { client_id: client.clientId,client_secret: client.clientSecret,scope: 'openid roles' } }); assert.equal(device.status,200);
  const approved = await fetch(issuerBase+'/oauth/device/approve',{ method: 'POST',headers: { 'Content-Type': 'application/json' },body: JSON.stringify({ user_code: device.body.user_code,username: 'operator',password: 'disposable-password' }) }); assert.equal(approved.status,200); assert.ok((await approved.text()).includes('Device authorized'));
  const assignments = await request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ token: independent.access_token }); const own = assignments.body.assignments.find(row => row.targetId === canonicalUser);
  assert.equal((await request(issuerBase,`/api/clients/${client.clientId}/assignments/${own.id}`,{ method: 'DELETE',token: independent.access_token })).status,200);
  assert.equal((await applicationGrant(client,independent.access_token,'user',canonicalUser)).status,201);
  for (const extra of [{ grant_type: 'authorization_code',code,redirect_uri: client.redirectUris[0] },{ grant_type: deviceGrant,device_code: device.body.device_code }]) assert.equal((await request(issuerBase,'/oauth/token',{ method: 'POST',body: { client_id: client.clientId,client_secret: client.clientSecret,...extra } })).body.error,'invalid_grant');
});
test('an expired application lease is denied by actual receivers and a new issuer process without waiting for JWT expiry', async () => {
  const administrator = await issue(); const independent = await issue('second-admin'); const client = await registerApplication(administrator.access_token); const pair = await issueForApplication(client);
  const assignments = await request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ token: independent.access_token }); const own = assignments.body.assignments.find(row => row.targetId === canonicalUser);
  await issuerDb.query('ALTER TABLE oauth_application_assignments DISABLE TRIGGER oauth_application_assignment_guard'); await issuerDb.query('ALTER TABLE oauth_application_assignments DISABLE TRIGGER oauth_application_assignment_record');
  try { await issuerDb.query("UPDATE oauth_application_assignments SET expires_at=clock_timestamp()+interval '0.15 seconds' WHERE id=$1",[own.id]); }
  finally { await issuerDb.query('ALTER TABLE oauth_application_assignments ENABLE TRIGGER oauth_application_assignment_guard'); await issuerDb.query('ALTER TABLE oauth_application_assignments ENABLE TRIGGER oauth_application_assignment_record'); }
  await new Promise(resolve => setTimeout(resolve,220));
  for (const [base,path] of [[gatewayBase,'/api/gateway/access'],[identityBase,'/api/identity/subject'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']]) assert.equal((await request(base,path,{ token: pair.access_token })).status,401);
  const fresh = await startFreshIssuer(); try { assert.equal((await request(fresh.base,'/oauth/access-state',{ token: pair.access_token })).body.active,false); } finally { await fresh.stop(); }
  assert.equal((await applicationGrant(client,independent.access_token,'user',canonicalUser)).status,201);
  assert.equal((await request(issuerBase,'/oauth/access-state',{ token: pair.access_token })).body.active,false); assert.ok((await issueForApplication(client)).access_token);
});
test('the actual protected offline bootstrap command grants only a bounded canonical app lease, not an administrative role', async () => {
  const operator = await issue('app-operator'); const client = await registerApplication(operator.access_token,{ scopes: ['openid'] },false);
  const child = spawn(process.execPath,['scripts/bootstrap-application-access.js',client.clientId,canonicalSubjects.get('alice'),'3600','Reviewed isolated CLI recovery access'],{
    cwd: path.join(__dirname,'../..'),stdio: ['ignore','pipe','pipe'],env: { ...process.env,OAUTH_BOOTSTRAP_DATABASE_URL: databaseUrl(schemas[0]),OAUTH_ISSUER: issuer,OAUTH_IDENTITY_AUTHORITY_URL: identityBase+'/internal/identity/authorization-state',OAUTH_SIGNING_KEY_FILE: firstKeyFile,OAUTH_EPHEMERAL_SIGNING_KEYS: 'false' } });
  let output = ''; let errors = ''; child.stdout.on('data',chunk => { output = (output+chunk).slice(-16000); }); child.stderr.on('data',chunk => { errors = (errors+chunk).slice(-4096); });
  const timer = setTimeout(() => child.kill('SIGTERM'),10000); const [status] = await once(child,'exit'); clearTimeout(timer); assert.equal(status,0,errors);
  const receipt = JSON.parse(output.split('\n').find(line => line.startsWith('{'))); assert.equal(receipt.assignment.targetId,canonicalSubjects.get('alice')); assert.equal(receipt.assignment.durationSeconds,3600);
  const row = (await issuerDb.query('SELECT created_actor FROM oauth_application_assignments WHERE id=$1',[receipt.assignment.id])).rows[0]; assert.equal(row.created_actor.type,'bootstrap');
  const pair = await issueForApplication(client,'alice','openid'); assert.equal(JSON.parse(Buffer.from(pair.access_token.split('.')[1],'base64url')).roles,undefined);
  assert.equal((await request(issuerBase,'/api/clients',{ token: pair.access_token })).status,403);
});

test('canonical application readers and managers have separate real issuer operations without privileged scope takeover', async () => {
  const reader = await issue('app-reader'); const manager = await issue('app-operator'); const admin = await issue();
  const access = await request(issuerBase, '/api/clients/access', { token: reader.access_token }); assert.deepEqual(access.body.permissions, ['applications.read']);
  assert.equal((await request(issuerBase, '/api/clients', { token: reader.access_token })).status, 200);
  const body = { name: 'Delegated registration', redirectUris: ['https://delegated.test/callback'] };
  assert.equal((await request(issuerBase, '/api/clients', { method: 'POST', token: reader.access_token, body })).status, 403);
  for (const scopes of [['roles'],['oauth.admin']]) assert.equal((await request(issuerBase, '/api/clients', { method: 'POST', token: manager.access_token, body: { ...body, scopes } })).status, 403);
  assert.equal((await request(issuerBase, '/api/clients', { method: 'POST', token: manager.access_token, body: { ...body, createdBy: 'forged' } })).status, 400);
  const created = await request(issuerBase, '/api/clients', { method: 'POST', token: manager.access_token, body }); assert.equal(created.status, 201); assert.equal(created.body.enabled, false);
  const audit = (await issuerDb.query('SELECT * FROM oauth_client_audit WHERE client_id=$1', [created.body.clientId])).rows[0];
  assert.equal(audit.actor_subject, 'app-operator-subject'); assert.equal(audit.actor_user_id, canonicalSubjects.get('app-operator'));
  const page = await request(issuerBase, '/api/clients', { token: reader.access_token }); assert.ok(!JSON.stringify(page.body).includes(created.body.clientSecret)); assert.ok(!JSON.stringify(page.body).includes('clientSecretHash'));
  const protectedApp = await registerApplication(admin.access_token);
  for (const [method, route, payload] of [['PUT', `/api/clients/${protectedApp.clientId}`, { name: 'Takeover' }], ['POST', `/api/clients/${protectedApp.clientId}/rotate-secret`, {}], ['DELETE', `/api/clients/${protectedApp.clientId}`, undefined]]) {
    assert.equal((await request(issuerBase, route, { method, token: manager.access_token, headers: clientCondition(protectedApp), body: payload })).status, 403);
  }
});

test('disabling a canonical OAuth application fences actual delegated license writes and every live receiver without reviving grants on enable', async () => {
  const administrator = await issue(); let client = await registerApplication(administrator.access_token); const secret = client.clientSecret;
  const pair = await issueForApplication(client); const token = pair.access_token;
  const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,3) RETURNING id', ['Application fence pool'])).rows[0];
  const recipient = randomUUID(); await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [recipient, recipient, recipient + '@test.invalid']);
  const route = `/api/licenses/${product.id}/assign`; const body = { assignee_type: 'user', assignee_id: recipient };
  assert.equal((await request(gatewayBase, route, { method: 'POST', token, body })).status, 201);
  const disabled = await request(issuerBase, `/api/clients/${client.clientId}`, { method: 'PUT', token: administrator.access_token, headers: clientCondition(client), body: { enabled: false } });
  assert.equal(disabled.status, 200); client = disabled.body;
  for (const [base, path] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access'], [quickBase, '/api/quick/access'], [issuerBase, '/oauth/userinfo']]) assert.equal((await request(base, path, { token })).status, 401);
  for (const base of [gatewayBase, policyBase]) assert.equal((await request(base, route, { method: 'POST', token, body })).status, 401);
  assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1', [product.id])).rows[0].count, 1);
  const enabled = await request(issuerBase, `/api/clients/${client.clientId}`, { method: 'PUT', token: administrator.access_token, headers: clientCondition(client), body: { enabled: true } }); assert.equal(enabled.status, 200);
  assert.equal((await request(issuerBase, '/oauth/access-state', { token })).body.active, false);
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', client_id: client.clientId, client_secret: secret, refresh_token: pair.refresh_token } })).body.error, 'invalid_grant');
  const fresh = await issueForApplication({ ...enabled.body, clientSecret: secret }); assert.equal((await request(gatewayBase, '/api/gateway/access', { token: fresh.access_token })).status, 200);
});

test('application secret rotation is visible to another actual issuer process and old workload tokens lose live access', async () => {
  const manager = await issue('app-operator'); const client = await registerApplication(manager.access_token, { scopes: ['openid'], grantTypes: ['client_credentials'], redirectUris: [] });
  const mint = (base, secret) => request(base, '/oauth/token', { method: 'POST', body: { grant_type: 'client_credentials', client_id: client.clientId, client_secret: secret, scope: 'openid' } });
  const issued = await mint(issuerBase, client.clientSecret); assert.equal(issued.status, 200);
  const other = await startFreshIssuer();
  try {
    assert.equal((await request(other.base, '/oauth/access-state', { token: issued.body.access_token })).body.active, true);
    const rotated = await request(issuerBase, `/api/clients/${client.clientId}/rotate-secret`, { method: 'POST', token: manager.access_token, headers: clientCondition(client), body: {} }); assert.equal(rotated.status, 200);
    for (const base of [issuerBase, other.base]) {
      assert.equal((await mint(base, client.clientSecret)).status, 401); assert.equal((await mint(base, rotated.body.clientSecret)).status, 200);
      assert.equal((await request(base, '/oauth/access-state', { token: issued.body.access_token })).body.active, false);
    }
    const state = (await issuerDb.query('SELECT secret,secret_hash FROM oauth_clients WHERE id=$1', [client.clientId])).rows[0];
    assert.equal(state.secret, null); assert.equal(state.secret_hash, createHash('sha256').update(rotated.body.clientSecret).digest('hex'));
  } finally { await other.stop(); }
});

test('a live application-authority outage denies all integrated receivers and refresh without consuming the credential', async () => {
  const pair = await issue(); await issuerDb.query('ALTER TABLE oauth_clients RENAME TO unavailable_oauth_clients');
  try {
    for (const [base, route] of [[issuerBase, '/oauth/access-state'], [gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access'], [quickBase, '/api/quick/access']]) assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', client_id: clientId, client_secret: clientSecret, refresh_token: pair.refresh_token } })).status, 503);
  } finally { await issuerDb.query('ALTER TABLE unavailable_oauth_clients RENAME TO oauth_clients'); }
  assert.equal((await request(issuerBase, '/oauth/access-state', { token: pair.access_token })).body.active, true);
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', client_id: clientId, client_secret: clientSecret, refresh_token: pair.refresh_token } })).status, 200);
});

test('client configuration changes fence pending authorization and approved device checkpoints, not just issued access', async () => {
  const administrator = await issue(); const deviceGrant = 'urn:ietf:params:oauth:grant-type:device_code';
  const client = await registerApplication(administrator.access_token, { grantTypes: ['authorization_code','refresh_token',deviceGrant] });
  const login = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: client.clientId, redirect_uri: client.redirectUris[0], username: 'operator', password: 'disposable-password', scope: 'openid roles' } }); assert.equal(login.status, 302);
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: client.clientId, client_secret: client.clientSecret, scope: 'openid roles' } }); assert.equal(device.status, 200);
  const approved = await fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username: 'operator', password: 'disposable-password' }) }); assert.equal(approved.status, 200); assert.ok((await approved.text()).includes('Device authorized'));
  const changed = await request(issuerBase, `/api/clients/${client.clientId}`, { method: 'PUT', token: administrator.access_token, headers: clientCondition(client), body: { name: 'Confirmed replacement metadata' } }); assert.equal(changed.status, 200);
  const common = { client_id: client.clientId, client_secret: client.clientSecret };
  for (const body of [{ ...common, grant_type: 'authorization_code', code, redirect_uri: client.redirectUris[0] }, { ...common, grant_type: deviceGrant, device_code: device.body.device_code }]) assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body })).body.error, 'invalid_grant');
});

after(async () => {
  if(inventoryFixture)await inventoryFixture.close();
  if (quickProcess && quickProcess.exitCode === null && quickProcess.signalCode === null) {
    const exited = once(quickProcess, 'exit'); quickProcess.kill('SIGTERM'); const timer = setTimeout(() => quickProcess.kill('SIGKILL'), 7000);
    try { await exited; } finally { clearTimeout(timer); }
  }
  if (gateway) { gateway.stop(); gateway.server.closeAllConnections(); }
  for (const server of [gateway?.server, receiverServer, policyServer, identityServer, issuerServer, credentialServer]) {
    if (server?.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  }
  if (Gateway) await Gateway.closeDatabase();
  if (policyDb) await policyDb.shutdown();
  if (identityDb) await identityDb.pool.end();
  if (issuerDb) await issuerDb.pool.end();
  for (const schema of schemas) await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
  await administration.end();
  if (keyDirectory) fs.rmSync(keyDirectory, { recursive: true, force: true });
});

test('a committed revocation denies an actual issuer token at the gateway and both direct resource servers', async () => {
  const pair = await issue();
  const routes = [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']];
  for (const [base, route] of routes) assert.equal((await request(base, route, { token: pair.access_token })).status, 200);
  const state = await request(issuerBase, '/oauth/access-state', { token: pair.access_token });
  assert.equal(state.status, 200); assert.equal(state.body.active, true); assert.equal(state.headers.get('cache-control'), 'no-store');
  assert.deepEqual(Object.keys(state.body).sort(), ['schemaVersion', 'active', 'issuer', 'subject', 'tokenId', 'expiresAt'].sort());
  assert.equal((await revoke(pair.access_token)).status, 200);
  for (const [base, route] of routes) assert.equal((await request(base, route, { token: pair.access_token })).status, 401);
  assert.deepEqual((await request(issuerBase, '/oauth/access-state', { token: pair.access_token })).body, { schemaVersion: 1, active: false });
});

test('a revoked operator cannot allocate another seat through the actual proxy or direct license API', async () => {
  const pair = await issue();
  const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,3) RETURNING id', ['Revocation pool'])).rows[0];
  const recipient = randomUUID();
  await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [recipient, recipient, `${recipient}@test.invalid`]);
  const route = `/api/licenses/${product.id}/assign`; const body = { assignee_type: 'user', assignee_id: recipient };
  assert.equal((await request(gatewayBase, route, { method: 'POST', token: pair.access_token, body })).status, 201);
  assert.equal((await revoke(pair.access_token)).status, 200);
  for (const base of [gatewayBase, policyBase]) assert.equal((await request(base, route, { method: 'POST', token: pair.access_token, body })).status, 401);
  assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1', [product.id])).rows[0].count, 1);
});

test('independent store instances observe persistent, idempotent revocations until actual signed expiry', async () => {
  const pair = await issue(); const payload = JSON.parse(Buffer.from(pair.access_token.split('.')[1], 'base64url'));
  const hash = createHash('sha256').update(pair.access_token).digest('hex');
  await revoke(pair.access_token); await revoke(pair.access_token);
  assert.equal(await new TokenRevocationStore(issuerDb).revoked(hash), true);
  const rows = (await issuerDb.query('SELECT token_hash,client_id,expires_at FROM oauth_token_revocations')).rows;
  assert.equal(rows.length, 1); assert.equal(rows[0].client_id, clientId); assert.equal(rows[0].expires_at.getTime(), payload.exp * 1000);
  assert.equal(JSON.stringify(rows).includes(pair.access_token), false);
  await issuerDb.query(fs.readFileSync(path.join(__dirname, '../../migrations/005_token_revocations.sql'), 'utf8'));
  assert.equal(await new TokenRevocationStore(issuerDb).revoked(hash), true);
});

test('another authenticated application cannot revoke the operator token', async () => {
  const pair = await issue();
  assert.equal((await revoke(pair.access_token, { client_id: 'grafana-od-client', client_secret: 'other-disposable-client' })).status, 200);
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 200);
  assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_token_revocations')).rows[0].count, 0);
});

test('actual signed user mutations enforce original tenant ownership at direct and gateway boundaries',async()=>{
 const first=await issue();const second=await issue('tenant-creation-admin');const username='mutation-owned-'+randomUUID();
 const created=await request(identityBase,'/api/users',{method:'POST',token:second.access_token,body:{username,email:username+'@test.invalid'}});assert.equal(created.status,201,JSON.stringify(created.body));const route='/api/users/'+created.body.id;const version=created.headers.get('etag');
 for(const base of[identityBase,gatewayBase]){
  assert.equal((await request(base,route,{method:'PUT',token:first.access_token,headers:{'If-Match':version},body:{title:'Foreign overwrite'}})).status,404);
  assert.equal((await request(base,route,{method:'DELETE',token:first.access_token,headers:{'If-Match':version}})).status,404);
  assert.equal((await request(base,route+'/authorization/invalidate',{method:'POST',token:first.access_token,body:{}})).status,404);
 }
 assert.equal((await identityDb.query('SELECT title,record_revision FROM users WHERE id=$1',[created.body.id])).rows[0].title,null);
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_user_events WHERE user_id=$1',[created.body.id])).rows[0].count,0);
 assert.equal((await request(identityBase,route+'?tenantId='+separateTenant,{method:'PUT',token:second.access_token,headers:{'If-Match':version},body:{title:'No caller scope'}})).status,400);
 const updated=await request(gatewayBase,route,{method:'PUT',token:second.access_token,headers:{'If-Match':version},body:{title:'Actual owner edit',enabled:true}});assert.equal(updated.status,200,JSON.stringify(updated.body));assert.equal(updated.body.enabled,true);assert.notEqual(updated.body.revision,created.body.revision);
 assert.equal((await request(identityBase,route,{method:'DELETE',token:second.access_token,headers:{'If-Match':version}})).status,412);
 assert.equal((await request(gatewayBase,route+'/authorization/invalidate',{method:'POST',token:second.access_token,body:{}})).status,200);
 const current=await request(identityBase,route,{token:second.access_token});assert.equal(current.status,200);assert.equal((await request(gatewayBase,route,{method:'DELETE',token:second.access_token,headers:{'If-Match':current.headers.get('etag')}})).status,204);
 const evidence=(await identityDb.query('SELECT action,tenant_id,actor FROM identity_directory_user_events WHERE user_id=$1 ORDER BY created_at',[created.body.id])).rows;assert.deepEqual(evidence.map(row=>row.action),['update','invalidate','delete']);for(const event of evidence){assert.equal(event.tenant_id,separateTenant);assert.equal(event.actor.userId,canonicalSubjects.get('tenant-creation-admin'));}
});

for(const action of['reset','disable','delete'])test('actual own '+action+' succeeds but immediately fences the original signed access and refresh tokens',async()=>{
 const name='mutation-self-'+action;const pair=await issue(name);const userId=canonicalSubjects.get(name);const route='/api/users/'+userId;const current=await request(identityBase,route,{token:pair.access_token});assert.equal(current.status,200);
 const result=action==='reset'?await request(identityBase,route+'/authorization/invalidate',{method:'POST',token:pair.access_token,body:{}}):await request(gatewayBase,route,{method:action==='delete'?'DELETE':'PUT',token:pair.access_token,headers:{'If-Match':current.headers.get('etag')},...(action==='disable'?{body:{enabled:false}}:{})});
 assert.equal(result.status,action==='delete'?204:200,JSON.stringify(result.body));assert.equal((await request(issuerBase,'/oauth/userinfo',{token:pair.access_token})).status,401);assert.equal((await request(gatewayBase,'/api/gateway/access',{token:pair.access_token})).status,401);assert.equal((await renew(pair.refresh_token)).status,400);
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_user_events WHERE user_id=$1',[userId])).rows[0].count,1);
 if(action==='delete')assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM users WHERE id=$1',[userId])).rows[0].count,0);
 if(action==='disable'){await identityDb.write('UPDATE users SET enabled=true WHERE id=$1',[userId],'Explicit disposable actor restoration');assert.equal((await request(issuerBase,'/oauth/userinfo',{token:pair.access_token})).status,401);}
 if(action!=='delete')assert.equal((await request(issuerBase,'/oauth/userinfo',{token:(await issue(name)).access_token})).status,200);
});

test('actual issuer revocation during own-reset audit SQL cannot be excused as the reset itself',async()=>{
 const pair=await issue('mutation-self-withdrawn');const userId=canonicalSubjects.get('mutation-self-withdrawn');const before=(await identityDb.query('SELECT * FROM users WHERE id=$1',[userId])).rows[0];const gate='mutation-final-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query(`CREATE FUNCTION pause_owned_user_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));RETURN NEW;END;$$;CREATE TRIGGER pause_owned_user_mutation BEFORE INSERT ON identity_directory_user_events FOR EACH ROW EXECUTE FUNCTION pause_owned_user_mutation()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(identityBase,'/api/users/'+userId+'/authorization/invalidate',{method:'POST',token:pair.access_token,body:{}});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true,'Actual own-reset SQL waiter required');assert.equal((await revoke(pair.access_token)).status,200);await blocker.query('COMMIT');const rejected=await pending;assert.equal(rejected.status,401,JSON.stringify(rejected.body));
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_owned_user_mutation ON identity_directory_user_events;DROP FUNCTION pause_owned_user_mutation()');}
 assert.deepEqual((await identityDb.query('SELECT * FROM users WHERE id=$1',[userId])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_user_events WHERE user_id=$1',[userId])).rows[0].count,0);
});

test('actual user mutations cannot report success without their mandatory receiving trigger and outbox receipt',async()=>{
 const pair=await issue();const route='/api/users/'+canonicalUser;const before=await request(identityBase,route,{token:pair.access_token});assert.equal(before.status,200);await identityDb.query('ALTER TABLE users DISABLE TRIGGER identity_directory_user_mutation_record');
 try{assert.equal((await request(identityBase,route,{method:'PUT',token:pair.access_token,headers:{'If-Match':before.headers.get('etag')},body:{title:'No unconfirmed mutation'}})).status,503);}
 finally{await identityDb.query('ALTER TABLE users ENABLE TRIGGER identity_directory_user_mutation_record');}assert.deepEqual((await request(identityBase,route,{token:pair.access_token})).body,before.body);
});

test('actual signed creators own new disabled users, empty groups and OUs in their original tenants without test-fixture adoption',async()=>{
 const first=await issue();const second=await issue('tenant-creation-admin');const source=new(require('../../../identity-service/src/AuthorizationState').AuthorizationState)(identityDb);const records=[];
 for(const pair of[first,second]){
  const claims=payload(pair.access_token);const tenant=(await source.state(issuer,claims.sub)).tenant;const username='runtime-created-'+randomUUID();
  const person=await request(identityBase,'/api/users',{method:'POST',token:pair.access_token,body:{username,email:username+'@test.invalid'}});assert.equal(person.status,201,JSON.stringify(person.body));assert.equal(person.body.enabled,false);
  const group=await groupRequest(identityBase,'/api/groups',{method:'POST',token:pair.access_token,body:{name:'Original tenant empty group'}});assert.equal(group.status,201,JSON.stringify(group.body));assert.deepEqual(group.body.members,[]);
  const root=await request(identityBase,'/api/ous',{method:'POST',token:pair.access_token,body:{name:'Original tenant OU'}});assert.equal(root.status,201,JSON.stringify(root.body));const child=await request(identityBase,'/api/ous',{method:'POST',token:pair.access_token,body:{name:'Original tenant child',parentId:root.body.id}});assert.equal(child.status,201);assert.equal(child.body.parentId,root.body.id);
  for(const[kind,record]of[['user',person.body],['group',group.body],['ou',root.body],['ou',child.body]]){
   const owned=(await identityDb.query('SELECT tenant_id,reason FROM identity_tenant_ownership WHERE resource_kind=$1 AND resource_id=$2',[kind,record.id])).rows[0];assert.equal(owned.tenant_id,tenant.id);assert.equal(owned.reason,'Original-token-bound new-resource creation');
   const evidence=(await identityDb.query("SELECT actor FROM identity_tenant_events WHERE action='resource-created' AND details->>'resourceId'=$1",[record.id])).rows;assert.equal(evidence.length,1);assert.equal(evidence[0].actor.userId,claims.identity_authorization.userId);
  }
  assert.equal((await request(identityBase,'/api/users/'+person.body.id,{token:pair.access_token})).status,200);assert.equal((await identityDb.query('SELECT identity_tenant_user_enabled($1) AS enabled',[person.body.id])).rows[0].enabled,false);
  records.push({pair,person:person.body,group:group.body,root:root.body,tenant});
 }
 for(const[reader,foreign]of[[records[0],records[1]],[records[1],records[0]]]){
  for(const path of['/api/users/'+foreign.person.id,'/api/groups/'+foreign.group.id,'/api/ous/'+foreign.root.id])assert.equal((await request(identityBase,path,{token:reader.pair.access_token})).status,404);
  assert.equal((await request(identityBase,'/api/ous',{method:'POST',token:reader.pair.access_token,body:{name:'Forbidden foreign parent',parentId:foreign.root.id}})).status,404);
  assert.equal((await groupRequest(identityBase,'/api/groups',{method:'POST',token:reader.pair.access_token,body:{name:'No caller owner',tenantId:foreign.tenant.id}})).status,400);
 }
});

test('actual signed group CRUD preserves strong versions and original tenant boundaries through the gateway',async()=>{
 const operator=await issue();const foreign=await issue('tenant-creation-admin');const created=await request(gatewayBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Actual original-tenant conditional group'}});assert.equal(created.status,201,JSON.stringify(created.body));const route='/api/groups/'+created.body.id;const tag=created.headers.get('etag');assert.equal(tag,`"group-${created.body.id}-${created.body.revision}"`);
 const metadata=await request(gatewayBase,'/api/identity/access',{token:operator.access_token});assert.equal(metadata.status,200);assert.equal(metadata.body.directoryGroupMutationProtocol,1);assert.equal(metadata.body.groupMembershipReviewProtocol,1);
 const separate=await request(identityBase,'/api/groups',{method:'POST',token:foreign.access_token,body:{name:'Actual coherent foreign group'}});assert.equal(separate.status,201);const foreignRoute='/api/groups/'+separate.body.id;const foreignUser=canonicalSubjects.get('tenant-session-user');const linked=await groupRequest(identityBase,foreignRoute+'/members',{method:'POST',token:foreign.access_token,body:{userId:foreignUser}});assert.equal(linked.status,200);
 for(const base of[identityBase,gatewayBase]){
  const headers={'If-Match':linked.headers.get('etag')};assert.equal((await request(base,foreignRoute,{token:operator.access_token})).status,404);
  for(const[method,path,body]of[['PUT',foreignRoute,{name:'Forbidden foreign overwrite'}],['POST',foreignRoute+'/members',{userId:canonicalSubjects.get('tenant-pending-user')}],['DELETE',foreignRoute+'/members/'+foreignUser],['DELETE',foreignRoute]])assert.equal((await request(base,path,{method,token:operator.access_token,headers,...(body?{body}:{})})).status,404);
  assert.equal((await request(base,route,{method:'PUT',token:operator.access_token,body:{description:'Missing version'}})).status,428);
  assert.equal((await request(base,route,{method:'PUT',token:operator.access_token,headers:{'If-Match':'W/'+tag},body:{description:'Weak version'}})).status,400);
 }
 assert.equal((await request(gatewayBase,route+'?tenantId='+separateTenant,{method:'PUT',token:operator.access_token,headers:{'If-Match':tag},body:{description:'No caller-selected scope'}})).status,400);
 assert.equal((await request(identityBase,route+'/members',{method:'POST',token:operator.access_token,headers:{'If-Match':tag},body:{userId:foreignUser}})).status,404);
 const updated=await request(gatewayBase,route,{method:'PUT',token:operator.access_token,headers:{'If-Match':tag},body:{name:'Actual conditional update',description:'No unrelated profile permission required'}});assert.equal(updated.status,200,JSON.stringify(updated.body));assert.notEqual(updated.headers.get('etag'),tag);
 assert.equal((await request(identityBase,route,{method:'DELETE',token:operator.access_token,headers:{'If-Match':tag}})).status,412);
 const memberId=canonicalSubjects.get('alice');const added=await request(gatewayBase,route+'/members',{method:'POST',token:operator.access_token,headers:{'If-Match':updated.headers.get('etag')},body:{userId:memberId}});assert.equal(added.status,200,JSON.stringify(added.body));assert.deepEqual(added.body.members,[memberId]);
 assert.equal((await request(identityBase,route+'/members',{method:'POST',token:operator.access_token,headers:{'If-Match':added.headers.get('etag')},body:{userId:memberId}})).status,409);
 const snapshot=await request(gatewayBase,'/api/license-groups/'+created.body.id+'/snapshot',{token:operator.access_token});assert.equal(snapshot.status,200);assert.deepEqual(snapshot.body.memberIds,[memberId]);
 const origin=(await identityDb.query('SELECT * FROM identity_membership_origins WHERE group_id=$1',[created.body.id])).rows[0];assert.equal(origin.created_by,canonicalUser);
 const removed=await request(gatewayBase,route+'/members/'+memberId,{method:'DELETE',token:operator.access_token,headers:{'If-Match':added.headers.get('etag')}});assert.equal(removed.status,200);assert.deepEqual(removed.body.members,[]);
 assert.equal((await request(gatewayBase,route,{method:'DELETE',token:operator.access_token,headers:{'If-Match':removed.headers.get('etag')}})).status,204);
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_membership_origins WHERE membership_id=$1',[origin.membership_id])).rows[0].count,1);
 const events=(await identityDb.query('SELECT action,actor,tenant_id FROM identity_directory_group_events WHERE group_id=$1 ORDER BY created_at',[created.body.id])).rows;assert.deepEqual(events.map(event=>event.action),['update','member-add','member-remove','delete']);for(const event of events){assert.equal(event.actor.userId,canonicalUser);assert.notEqual(event.tenant_id,separateTenant);}
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[separate.body.id])).rows[0].count,1);
});

test('actual signed group mutation cannot acknowledge a down-level receiver without its mandatory receiving guard',async()=>{
 const operator=await issue();const created=await request(identityBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Actual down-level group receiver'}});assert.equal(created.status,201);const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];await identityDb.query('ALTER TABLE groups DISABLE TRIGGER aaa_identity_directory_group_mutation');
 try{const response=await request(gatewayBase,'/api/groups/'+created.body.id,{method:'PUT',token:operator.access_token,headers:{'If-Match':created.headers.get('etag')},body:{name:'Not confirmed'}});assert.equal(response.status,403,JSON.stringify(response.body));assert.equal(response.body.id,undefined);}
 finally{await identityDb.query('ALTER TABLE groups ENABLE TRIGGER aaa_identity_directory_group_mutation');}assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,0);
});

async function groupApplicationFixture(username){
 const root=await issue();const independent=await issue('second-admin');const group=await request(identityBase,'/api/groups',{method:'POST',token:root.access_token,body:{name:'Actual group-only application admission '+randomUUID()}});assert.equal(group.status,201);
 assert.equal((await groupRequest(identityBase,'/api/groups/'+group.body.id+'/members',{method:'POST',token:root.access_token,body:{userId:canonicalSubjects.get(username)}})).status,200);
 const client=await registerApplication(root.access_token,{},false);const assignment=await applicationGrant(client,independent.access_token,'group',group.body.id);assert.equal(assignment.status,201,JSON.stringify(assignment.body));const pair=await issueForApplication(client,username);
 assert.equal((await issuerDb.query("SELECT count(*)::int AS count FROM oauth_application_assignments WHERE client_id=$1 AND target_type='user'",[client.clientId])).rows[0].count,0);return{root,group:group.body,client,pair};
}

for(const action of['remove','delete'])test('actual own group-derived application '+action+' commits with the original bearer and then closes its access and refresh',async()=>{
 const username='group-self-'+action;const fixture=await groupApplicationFixture(username);const route='/api/groups/'+fixture.group.id;const current=await request(gatewayBase,route,{token:fixture.pair.access_token});assert.equal(current.status,200);
 const path=action==='remove'?route+'/members/'+canonicalSubjects.get(username):route;const response=await request(gatewayBase,path,{method:'DELETE',token:fixture.pair.access_token,headers:{'If-Match':current.headers.get('etag')}});assert.equal(response.status,action==='remove'?200:204,JSON.stringify(response.body));
 assert.equal((await request(issuerBase,'/oauth/access-state',{token:fixture.pair.access_token})).body.active,false);assert.equal((await request(gatewayBase,'/api/gateway/access',{token:fixture.pair.access_token})).status,401);
 const refresh=await request(issuerBase,'/oauth/token',{method:'POST',body:{grant_type:'refresh_token',client_id:fixture.client.clientId,client_secret:fixture.client.clientSecret,refresh_token:fixture.pair.refresh_token}});assert.equal(refresh.status,400);
 const event=(await identityDb.query('SELECT actor FROM identity_directory_group_events WHERE group_id=$1 AND action=$2',[fixture.group.id,action==='remove'?'member-remove':'delete'])).rows;assert.equal(event.length,1);assert.equal(event[0].actor.userId,canonicalSubjects.get(username));
});

test('actual original issuer revocation during own group-reduction audit DML is not excused as the reduction itself',async()=>{
 const username='group-self-revoked';const fixture=await groupApplicationFixture(username);const groupId=fixture.group.id;const before=(await identityDb.query('SELECT * FROM group_members WHERE group_id=$1',[groupId])).rows;const previous=(await identityDb.query('SELECT revision FROM groups WHERE id=$1',[groupId])).rows[0].revision;const count=(await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[groupId])).rows[0].count;const gate='own-group-final-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query(`CREATE FUNCTION pause_owned_group_reduction() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='member-remove' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER pause_owned_group_reduction BEFORE INSERT ON identity_directory_group_events FOR EACH ROW EXECUTE FUNCTION pause_owned_group_reduction()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(gatewayBase,'/api/groups/'+groupId+'/members/'+canonicalSubjects.get(username),{method:'DELETE',token:fixture.pair.access_token,headers:{'If-Match':`"group-${groupId}-${previous}"`}});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'SELECT identity_directory_group_finish%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true,'Actual group-reduction evidence wait required');assert.equal((await revoke(fixture.pair.access_token,{client_id:fixture.client.clientId,client_secret:fixture.client.clientSecret})).status,200);await blocker.query('COMMIT');assert.equal((await pending).status,401);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_owned_group_reduction ON identity_directory_group_events;DROP FUNCTION pause_owned_group_reduction()');}
 assert.deepEqual((await identityDb.query('SELECT * FROM group_members WHERE group_id=$1',[groupId])).rows,before);assert.equal((await identityDb.query('SELECT revision FROM groups WHERE id=$1',[groupId])).rows[0].revision,previous);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[groupId])).rows[0].count,count);
});

test('actual signed protected membership reviewers cannot configure, discover or deny a coherent foreign tenant source',async()=>{
 const own=await membershipReviewFixture('membership-scope');const foreign=await membershipReviewFixture('tenant-group');const root=await issue();const base=foreign.base;const policy=(await request(gatewayBase,base+'/policies/groups/'+foreign.groupId,{token:foreign.config.access_token}));assert.equal(policy.status,200,JSON.stringify(policy.body));
 for(const receiver of[identityBase,gatewayBase]){
  assert.equal((await request(receiver,base+'/'+foreign.row.id,{token:root.access_token})).status,404);assert.equal((await request(receiver,base+'/'+foreign.row.id,{token:own.voter.access_token})).status,404);
  assert.equal((await request(receiver,base+'/policies/groups/'+foreign.groupId,{token:own.config.access_token})).status,404);
  assert.equal((await request(receiver,base+'/policies',{method:'POST',token:own.config.access_token,body:{groupId:foreign.groupId,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get('tenant-group-voter')],reason:'No coherent foreign tenant policy takeover',acknowledgeEffects:true}})).status,404);
  assert.equal((await request(receiver,base+'/'+foreign.row.id+'/decisions',{method:'POST',token:own.voter.access_token,headers:{'If-Match':`"od-membership-review:${foreign.row.id}:1:1"`},body:{decision:'deny',reason:'No foreign membership removal by a protected voter',acknowledgeScope:true}})).status,404);
 }
 const assigned=await request(gatewayBase,base+'/assigned',{token:own.voter.access_token});assert.equal(assigned.status,200);assert.deepEqual(assigned.body.reviews.map(review=>review.id),[own.row.id]);
 const attempt=await request(gatewayBase,base+'/policies',{method:'POST',token:own.config.access_token,body:{groupId:own.groupId,intervalSeconds:300,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get('tenant-group-voter')],reason:'No foreign voter reference on an owned group',acknowledgeEffects:true}});assert.equal(attempt.status,404);
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM group_members WHERE membership_id=$1',[foreign.row.membershipId])).rows[0].count,1);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_review_events WHERE group_id=$1',[foreign.groupId])).rows[0].count,1);
});

test('actual original issuer revocation while creation audit DML waits rolls back new row, owner and all receiving evidence',async()=>{
 const pair=await issue();const username='revoked-creation-'+randomUUID();const gate='creation-final-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 const tables=['users','identity_tenant_ownership','identity_tenant_events','identity_tenant_outbox','identity_user_audit','identity_user_outbox'];const counts=await Promise.all(tables.map(async table=>(await identityDb.query('SELECT count(*)::int AS count FROM '+table)).rows[0].count));
 await identityDb.query(`CREATE FUNCTION pause_owned_creation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='resource-created' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER pause_owned_creation_evidence BEFORE INSERT ON identity_tenant_events FOR EACH ROW EXECUTE FUNCTION pause_owned_creation_evidence()`);
 try{await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(identityBase,'/api/users',{method:'POST',token:pair.access_token,body:{username,email:username+'@test.invalid'}});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'INSERT INTO users(id,username,email,display_name,%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true,'Actual creation audit waiter required');
  assert.equal((await revoke(pair.access_token)).status,200);await blocker.query('COMMIT');assert.equal((await pending).status,401);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_owned_creation_evidence ON identity_tenant_events;DROP FUNCTION pause_owned_creation_evidence()');}
 for(let index=0;index<tables.length;index++)assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM '+tables[index])).rows[0].count,counts[index]);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM users WHERE username=$1',[username])).rows[0].count,0);
});

test('actual signed creation cannot report success when the receiving schema lacks runtime creation guards and evidence',async()=>{
 const pair=await issue();const username='downlevel-creation-'+randomUUID();await identityDb.query('ALTER TABLE users DISABLE TRIGGER aaa_identity_directory_creation;ALTER TABLE users DISABLE TRIGGER identity_directory_creation_commit');
 try{const result=await request(identityBase,'/api/users',{method:'POST',token:pair.access_token,body:{username,email:username+'@test.invalid'}});assert.equal(result.status,503);assert.equal(result.body.id,undefined);}
 finally{await identityDb.query('ALTER TABLE users ENABLE TRIGGER aaa_identity_directory_creation;ALTER TABLE users ENABLE TRIGGER identity_directory_creation_commit');}assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM users WHERE username=$1',[username])).rows[0].count,0);
});

test('actual signed directory reads scope collections, counts, details, search and role history to the original owner even for global administration',async()=>{
 const pair=await issue();const foreign=canonicalSubjects.get('tenant-session-user');const foreignGroup=randomUUID();const foreignOu=randomUUID();
 await identityDb.transaction(async client=>{
  await client.query("SELECT set_config('opendirectory.tenant_review','explicit-offline-owner-review',true),set_config('opendirectory.tenant_reason','Explicitly owned foreign directory fixture scope',true)");
  const version=(await client.query('SELECT version FROM identity_tenants WHERE id=$1',[separateTenant])).rows[0].version;
  await client.query('SELECT identity_tenant_adopt($1,$2,$3)',[separateTenant,version,JSON.stringify([{kind:'group',resourceId:foreignGroup},{kind:'ou',resourceId:foreignOu}])]);
  await client.query('INSERT INTO groups(id,name) VALUES($1,$2)',[foreignGroup,'Foreign directory group fixture']);await client.query('INSERT INTO ous(id,name) VALUES($1,$2)',[foreignOu,'Foreign directory OU fixture']);
 },{actor:'Explicit original-tenant fixture ownership review'});
 const tenant=(await new(require('../../../identity-service/src/AuthorizationState').AuthorizationState)(identityDb).state(issuer,payload(pair.access_token).sub)).tenant;
 const expected=(await identityDb.query("SELECT count(*)::int AS count FROM users WHERE identity_tenant_id('user',id)=$1",[tenant.id])).rows[0].count;
 const users=await request(identityBase,'/api/users?limit=100',{token:pair.access_token});assert.equal(users.status,200,JSON.stringify(users.body));assert.equal(users.body.total,expected);assert.equal(users.body.users.some(user=>user.id===foreign),false);
 for(const path of['/api/groups','/api/ous','/api/identity/search']){const result=await request(identityBase,path,{token:pair.access_token});assert.equal(result.status,200,JSON.stringify(result.body));for(const id of[foreign,foreignGroup,foreignOu])assert.equal(JSON.stringify(result.body).includes(id),false);}
 for(const path of['/api/users/'+foreign,'/api/groups/'+foreignGroup,'/api/ous/'+foreignOu,'/api/users/'+foreign+'/roles'])assert.equal((await request(identityBase,path,{token:pair.access_token})).status,404);
 assert.equal((await request(identityBase,'/api/users?tenantId='+separateTenant,{token:pair.access_token})).status,400);
 const original=await request(identityBase,'/api/users/'+canonicalUser,{token:pair.access_token,headers:{'X-Tenant-ID':separateTenant}});assert.equal(original.status,200);assert.equal(original.body.id,canonicalUser);
});

test('actual original issuer revocation during an observed directory read wait discards records after SQL',async()=>{
 const pair=await issue();const blocker=await identityDb.pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('LOCK TABLE ous IN ACCESS EXCLUSIVE MODE');pending=request(identityBase,'/api/ous',{token:pair.access_token});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<150;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id,name,description,parent_id,%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true,'An actual original-authorized OU read must be observed waiting');
  assert.equal((await revoke(pair.access_token)).status,200);await blocker.query('COMMIT');const result=await pending;assert.equal(result.status,401);assert.equal(result.body.ous,undefined);assert.equal(result.body.tree,undefined);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});

test('tenant-state binds only the actual signed human origin and loses authority with its original session',async()=>{
 const pair=await issue();const claims=payload(pair.access_token);const proof=await request(issuerBase,'/oauth/tenant-state',{token:pair.access_token});assert.equal(proof.status,200);assert.equal(proof.headers.get('cache-control'),'no-store');
 const tenant=(await new(require('../../../identity-service/src/AuthorizationState').AuthorizationState)(identityDb).state(issuer,claims.sub)).tenant;
 assert.deepEqual(proof.body,{schemaVersion:1,active:true,issuer,subject:claims.sub,tokenId:claims.jti,expiresAt:claims.exp,context:claims.identity_authorization,tenant});
 const verify=require('../../../../../packages/oidc-tenant-state').createTenantStateClient({endpoint:issuerBase+'/oauth/tenant-state'});assert.deepEqual(await verify('Bearer '+pair.access_token,claims),tenant);
 const foreign=await issue('tenant-session-user');const foreignProof=await request(issuerBase,'/oauth/tenant-state',{token:foreign.access_token});assert.equal(foreignProof.body.tenant.id,separateTenant);assert.notEqual(foreignProof.body.tenant.id,tenant.id);
 for(const route of['/oauth/tenant-state?tenantId='+separateTenant,'/oauth/tenant-state/'])assert.equal((await request(issuerBase,route,{token:pair.access_token})).status,401);
 assert.equal((await request(issuerBase,'/oauth/tenant-state',{token:pair.id_token})).status,401);
 assert.equal((await request(issuerBase,'/oauth/tenant-state',{token:pair.access_token,headers:{'X-API-Key':'forged'}})).status,401);
 await revoke(pair.access_token);assert.deepEqual((await request(issuerBase,'/oauth/tenant-state',{token:pair.access_token})).body,{schemaVersion:1,active:false});await assert.rejects(verify('Bearer '+pair.access_token,claims),error=>error.status===401);
});

test('actual signed link administration rejects foreign ownership and retained subject recycling without trusting body tenant aliases',async()=>{
 const pair=await issue();const target=randomUUID();const subject='tenant-link-'+randomUUID();await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[target,subject,subject+'@test.invalid']);
 const body={issuer,subject,userId:target};const create=await request(identityBase,'/api/identity/links',{method:'POST',token:pair.access_token,body});assert.equal(create.status,201,JSON.stringify(create.body));assert.equal(create.body.user_id,target);
 const foreign=canonicalSubjects.get('tenant-session-user');assert.equal((await request(identityBase,'/api/identity/links',{method:'POST',token:pair.access_token,body:{issuer,subject:'foreign-'+randomUUID(),userId:foreign}})).status,404);
 assert.equal((await request(identityBase,'/api/identity/links',{method:'DELETE',token:pair.access_token,body:{issuer,subject:'tenant-session-user-subject'}})).status,404);
 assert.equal((await request(identityBase,'/api/identity/links',{method:'DELETE',token:pair.access_token,body:{issuer,subject:payload(pair.access_token).sub}})).status,403);
 assert.equal((await request(identityBase,'/api/identity/links',{method:'POST',token:pair.access_token,body:{...body,tenantId:separateTenant}})).status,400);
 assert.equal((await request(identityBase,'/api/identity/links',{method:'DELETE',token:pair.access_token,body:{issuer,subject}})).status,204);
 await identityDb.query('DELETE FROM users WHERE id=$1',[target]);await assert.rejects(identityDb.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,foreign]),error=>error.code==='23514');
 await revoke(pair.access_token);assert.equal((await request(identityBase,'/api/identity/links',{method:'POST',token:pair.access_token,body:{issuer,subject:'revoked-'+randomUUID(),userId:foreign}})).status,401);
});

test('actual issuer revocation while subject-link audit DML waits rolls back link, namespace and evidence',async()=>{
 const pair=await issue();const target=randomUUID();const subject='waiting-link-'+randomUUID();const gate='subject-link-proof-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[target,subject,subject+'@test.invalid']);
 await identityDb.query(`CREATE FUNCTION pause_subject_link_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.details->>'subject'='${subject}' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));END IF;RETURN NEW;END;$$;CREATE TRIGGER pause_subject_link_evidence BEFORE INSERT ON identity_link_audit FOR EACH ROW EXECUTE FUNCTION pause_subject_link_evidence()`);
 try{
  await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(identityBase,'/api/identity/links',{method:'POST',token:pair.access_token,body:{issuer,subject,userId:target}});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true,'Actual link audit waiter must be observed');
  assert.equal((await revoke(pair.access_token)).status,200);await blocker.query('COMMIT');assert.equal((await pending).status,401);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_subject_link_evidence ON identity_link_audit;DROP FUNCTION pause_subject_link_evidence()');}
 for(const table of['identity_subject_links','identity_subject_tenant_bindings'])assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM '+table+' WHERE subject=$1',[subject])).rows[0].count,0);
 assert.equal((await identityDb.query("SELECT count(*)::int AS count FROM identity_tenant_events WHERE details->>'subject'=$1",[subject])).rows[0].count,0);assert.equal((await identityDb.query("SELECT count(*)::int AS count FROM identity_link_audit WHERE details->>'subject'=$1",[subject])).rows[0].count,0);await identityDb.query('DELETE FROM users WHERE id=$1',[target]);
});

test('access-state accepts only the original header access token, not identity tokens, API keys or query credentials', async () => {
  const pair = await issue();
  assert.equal((await request(issuerBase, '/oauth/access-state', { token: pair.id_token })).status, 401);
  assert.equal((await request(issuerBase, '/oauth/access-state?token=' + encodeURIComponent(pair.access_token))).status, 401);
  assert.equal((await request(issuerBase, '/oauth/access-state?subject=someone-else', { token: pair.access_token })).status, 401);
  const keyed = await fetch(issuerBase + '/oauth/access-state', { headers: { 'X-API-Key': 'untrusted', Authorization: `Bearer ${pair.access_token}` }, signal: AbortSignal.timeout(5000) });
  assert.equal(keyed.status, 401); await keyed.body.cancel();
});

test('expired records are inactive and concurrent upserts never shorten a live revocation', async () => {
  const store = new TokenRevocationStore(issuerDb);
  const expired = createHash('sha256').update('expired').digest('hex');
  await issuerDb.query("INSERT INTO oauth_token_revocations(token_hash,client_id,expires_at) VALUES($1,$2,clock_timestamp()-interval '1 second')", [expired, clientId]);
  assert.equal(await store.revoked(expired), false);
  const current = createHash('sha256').update('current').digest('hex'); const now = Date.now();
  await Promise.all([store.revoke(current, clientId, now + 600000), store.revoke(current, clientId, now + 100000)]);
  assert.equal(await store.revoked(current), true);
  assert.equal((await issuerDb.query('SELECT expires_at FROM oauth_token_revocations WHERE token_hash=$1', [current])).rows[0].expires_at.getTime(), now + 600000);
});

test('refresh revocation terminates the entire persisted session family', async () => {
  const pair = await issue(); assert.equal((await revoke(pair.refresh_token)).status, 200);
  const refreshed = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token',
    refresh_token: pair.refresh_token, client_id: clientId, client_secret: clientSecret } });
  assert.equal(refreshed.status, 400); assert.equal(refreshed.body.error, 'invalid_grant');
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
});

test('authority storage loss denies checks, issuance and revocations instead of pretending success', async () => {
  const pair = await issue();
  await issuerDb.query('ALTER TABLE oauth_token_revocations RENAME TO unavailable_revocations');
  try {
    for (const [base, route] of [[issuerBase, '/oauth/access-state'], [issuerBase, '/oauth/userinfo'], [gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']]) {
      assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    }
    assert.equal((await revoke(pair.access_token)).status, 503);
    const issuance = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'client_credentials', client_id: 'grafana-od-client', client_secret: 'other-disposable-client' } });
    assert.equal(issuance.status, 503);
  } finally { await issuerDb.query('ALTER TABLE unavailable_revocations RENAME TO oauth_token_revocations'); }
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 200);
});

test('idle native WebSockets close after revocation instead of retaining cached authentication', async () => {
  const pair = await issue();
  const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: `Bearer ${pair.access_token}` } });
  await once(socket, 'open');
  try {
    const closed = once(socket, 'close'); assert.equal((await revoke(pair.access_token)).status, 200);
    const [code] = await Promise.race([closed, new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Revoked socket remained open')), 9000); timer.unref();
    })]);
    assert.equal(code, 4401);
  } finally { socket.terminate(); }
});

test('idle native WebSockets fail closed when the revocation authority becomes unavailable', async () => {
  const pair = await issue();
  const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: `Bearer ${pair.access_token}` } });
  await once(socket, 'open');
  try {
    const closed = once(socket, 'close');
    await issuerDb.query('ALTER TABLE oauth_token_revocations RENAME TO unavailable_revocations');
    const [code] = await Promise.race([closed, new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Socket survived authority loss')), 9000); timer.unref();
    })]);
    assert.equal(code, 1013);
  } finally {
    socket.terminate();
    await issuerDb.query('ALTER TABLE unavailable_revocations RENAME TO oauth_token_revocations');
  }
});

function payload(token) { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); }

function renew(refreshToken, overrides = {}) {
  return request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: refreshToken,
    client_id: clientId, client_secret: clientSecret, ...overrides } });
}

test('owner-scoped session metadata contains no credentials and cannot be used to revoke another user', async () => {
  const scopes = 'openid sessions.self.read sessions.self.revoke';
  const alice = await issue('alice', scopes); const bob = await issue('bob', scopes);
  const listed = await request(issuerBase, '/oauth/sessions', { token: alice.access_token });
  assert.equal(listed.status, 200); assert.equal(listed.body.sessions.length, 1);
  assert.equal(listed.body.sessions[0].id, payload(alice.access_token).sid);
  assert.equal(listed.body.sessions[0].current, true);
  assert.equal(/token_hash|refresh_token|claims_snapshot|permissions/.test(JSON.stringify(listed.body)), false);
  assert.equal((await request(issuerBase, `/oauth/sessions/${payload(bob.access_token).sid}`, { method: 'DELETE', token: alice.access_token, body: { roles: ['admin'] } })).status, 404);
  assert.equal((await request(issuerBase, '/oauth/access-state', { token: bob.access_token })).body.active, true);
});

test('current-family revocation stops sibling access tokens at receiving services and rejects future refresh', async () => {
  const original = await issue(); const independent = await issue(); const rotated = await renew(original.refresh_token);
  assert.equal(rotated.status, 200);
  assert.equal(payload(rotated.body.access_token).sid, payload(original.access_token).sid);
  assert.equal(payload(rotated.body.access_token).auth_time, payload(original.access_token).auth_time);
  const ended = await request(issuerBase, '/oauth/sessions/current/revoke', { method: 'POST', token: rotated.body.access_token });
  assert.equal(ended.status, 200); assert.equal(ended.body.revoked, true);
  for (const token of [original.access_token, rotated.body.access_token]) {
    for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [policyBase, '/api/licenses/access'], [identityBase, '/api/identity/subject']]) assert.equal((await request(base, route, { token })).status, 401);
  }
  assert.equal((await renew(rotated.body.refresh_token)).status, 400);
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: independent.access_token })).status, 200);
});

test('a replayed consumed refresh credential revokes its whole family but another client cannot trigger that revocation', async () => {
  const original = await issue(); const rotated = await renew(original.refresh_token);
  assert.equal(rotated.status, 200);
  assert.equal((await renew(original.refresh_token, { client_id: 'grafana-od-client', client_secret: 'other-disposable-client' })).status, 400);
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: rotated.body.access_token })).status, 200);
  assert.equal((await renew(original.refresh_token)).status, 400);
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: rotated.body.access_token })).status, 401);
  assert.equal((await renew(rotated.body.refresh_token)).status, 400);
  const audit = (await issuerDb.query("SELECT action,actor_type,actor_subject FROM oauth_session_audit WHERE action='refresh_reuse'")).rows;
  assert.deepEqual(audit, [{ action: 'refresh_reuse', actor_type: 'application', actor_subject: clientId }]);
});

test('concurrent refresh requests use row locks, leave one rotation, and persist reuse-driven family revocation', async () => {
  const pair = await issue(); const results = await Promise.all([renew(pair.refresh_token), renew(pair.refresh_token)]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
  const winner = results.find(result => result.status === 200).body;
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: winner.access_token })).status, 401);
  const rows = (await issuerDb.query('SELECT * FROM oauth_session_refresh')).rows;
  assert.equal(rows.length, 2); assert.equal(rows.filter(row => row.consumed_at).length, 1);
  assert.equal(JSON.stringify(rows).includes(pair.refresh_token), false); assert.equal(JSON.stringify(rows).includes(winner.refresh_token), false);
});

test('rotation audit failure rolls back credential consumption and does not falsely acknowledge a replacement', async () => {
  const pair = await issue();
  await issuerDb.query(`CREATE FUNCTION reject_refresh_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.action='refreshed' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER reject_refresh_audit BEFORE INSERT ON oauth_session_audit FOR EACH ROW EXECUTE FUNCTION reject_refresh_audit()`);
  try {
    const attempted = await renew(pair.refresh_token); assert.equal(attempted.status, 503); assert.equal(attempted.body.access_token, undefined);
    assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh')).rows[0].consumed_at, null);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 200);
  } finally { await issuerDb.query('DROP TRIGGER reject_refresh_audit ON oauth_session_audit; DROP FUNCTION reject_refresh_audit()'); }
  assert.equal((await renew(pair.refresh_token)).status, 200);
});

test('actual delegated application reads and writes preserve the issuer actor at every HTTP receiver without service-token substitution', async () => {
  const reader = await issue('app-reader'); const read = await request(quickBase, '/api/quick/service-principals', { token: reader.access_token });
  assert.equal(read.status, 200); assert.equal(read.body.success, true); assert.equal(JSON.stringify(read.body).includes('fixture-secret'), false);
  assert.equal(receiverCalls[0].authorization, 'Bearer ' + reader.access_token);
  const operator = await issue('app-operator'); receiverCalls = [];
  const created = await request(gatewayBase, '/api/quick/service-principals', { method: 'POST', token: operator.access_token, body: { appName: 'DelegatedApp', createdBy: 'forged-admin', permissions: [] } });
  assert.equal(created.status, 201); assert.equal(created.body.success, true); assert.equal(receiverCalls.length, 3);
  for (const call of receiverCalls) { assert.equal(call.authorization, 'Bearer ' + operator.access_token); assert.equal(call.subject, 'app-operator-subject'); assert.equal(call.operationId, created.headers.get('x-od-operation-id')); }
  assert.equal(receiverCalls.find(call => call.path === '/api/service-accounts').createdBy, 'app-operator-subject');
  assert.equal(forbiddenServiceTokens, 0);
});
test('direct quick-actions cannot bypass ID-token purpose, retired service credentials, ordinary-user grants or revoked families', async () => {
  const ordinary = await issue('alice'); const operator = await issue('app-operator');
  assert.equal((await request(quickBase, '/api/quick/service-principals', { token: ordinary.access_token })).status, 403);
  for (const token of [operator.id_token, 'svc-retired-test-credential']) assert.equal((await request(quickBase, '/api/quick/service-principals', { token })).status, 401);
  assert.equal((await request(quickBase, '/api/quick/service-principals?access_token=ignored', { token: operator.access_token })).status, 401);
  assert.equal((await revoke(operator.refresh_token)).status, 200);
  assert.equal((await request(quickBase, '/api/quick/service-principals', { token: operator.access_token })).status, 401);
  assert.deepEqual(receiverCalls, []); assert.equal(forbiddenServiceTokens, 0);
});
test('a real PIM application lease governs orchestration before and after canonical revocation, including direct access', async () => {
  const fixture = await pimLeaseFixture('application-administrator');
  assert.equal((await request(quickBase, '/api/quick/service-principals', { token: fixture.owner.access_token })).status, 403);
  assert.equal((await pimDecision(fixture, 'approve', fixture.reviewer.access_token)).status, 200); assert.equal((await pimDecision(fixture, 'activate')).status, 200);
  const owner = await issue(fixture.username);
  const created = await request(quickBase, '/api/quick/service-principals', { method: 'POST', token: owner.access_token, body: { appName: 'PIMDelegatedApp', permissions: [] } });
  assert.equal(created.status, 201); const before = receiverCalls.length;
  assert.equal((await pimDecision(fixture, 'revoke', fixture.reviewer.access_token)).status, 200);
  for (const base of [quickBase, gatewayBase]) assert.equal((await request(base, '/api/quick/service-principals', { method: 'POST', token: owner.access_token, body: { appName: 'MustNotExist' } })).status, 401);
  assert.equal(receiverCalls.length, before); assert.equal(forbiddenServiceTokens, 0);
  assert.equal((await request(identityBase, `${pimBase}/eligibilities/${fixture.eligibility.id}`, { method: 'DELETE', token: fixture.manager.access_token })).status, 200);
});
test('an expired canonical application role cannot continue calling the direct orchestration receiver', async () => {
  const userId = canonicalSubjects.get('alice');
  await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'application-administrator','Disposable orchestration expiry fixture',clock_timestamp()+interval '2 seconds')", [userId], 'fixture');
  const owner = await issue('alice'); assert.equal((await request(quickBase, '/api/quick/service-principals', { token: owner.access_token })).status, 200); const count = receiverCalls.length;
  await new Promise(resolve => setTimeout(resolve, 2100));
  assert.equal((await request(quickBase, '/api/quick/service-principals', { token: owner.access_token })).status, 401); assert.equal(receiverCalls.length, count); assert.equal(forbiddenServiceTokens, 0);
});
function holdNextJoin(path = '/api/computers/join') {
  let entered; let release; const arrival = new Promise(resolve => { entered = resolve; }); const resume = new Promise(resolve => { release = resolve; });
  joinGate = { entered, resume, path };
  return { release, wait: async () => {
    let timer; try { await Promise.race([arrival, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Expected delegated AD fixture step was not reached')), 4000); })]); }
    finally { clearTimeout(timer); }
  } };
}
test('revocation during an accepted orchestration step blocks all later writes instead of continuing with ambient service credentials', async () => {
  const owner = await issue('app-operator'); const gate = holdNextJoin();
  const operation = request(quickBase, '/api/quick/service-principals', { method: 'POST', token: owner.access_token, body: { appName: 'InterruptedApp' } });
  try { await gate.wait(); assert.equal((await revoke(owner.access_token)).status, 200); }
  finally { gate.release(); }
  const result = await operation; assert.equal(result.status, 207); assert.equal(result.body.success, false); assert.equal(result.body.clientSecret, null);
  assert.deepEqual(receiverCalls.map(call => call.path), ['/api/computers/join']); assert.equal(forbiddenServiceTokens, 0);
});
test('an authority outage during orchestration latches failure and never resumes old work when storage recovers', async () => {
  const owner = await issue('app-operator'); const gate = holdNextJoin();
  const operation = request(quickBase, '/api/quick/service-principals', { method: 'POST', token: owner.access_token, body: { appName: 'UncertainApp' } });
  let unavailable = false;
  try {
    await gate.wait(); await issuerDb.query('ALTER TABLE oauth_token_revocations RENAME TO unavailable_revocations'); unavailable = true; gate.release();
    const result = await operation; assert.equal(result.status, 207); assert.equal(result.body.success, false); assert.equal(result.body.clientSecret, null);
    assert.deepEqual(receiverCalls.map(call => call.path), ['/api/computers/join']);
  } finally { gate.release(); if (unavailable) await issuerDb.query('ALTER TABLE unavailable_revocations RENAME TO oauth_token_revocations'); }
  await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(receiverCalls.length, 1); assert.equal(forbiddenServiceTokens, 0);
  assert.equal((await request(quickBase, '/api/quick/service-principals', { token: owner.access_token })).status, 200);
});
test('parallel real orchestrations cannot exchange operator credentials across asynchronous steps', async () => {
  const userId = canonicalSubjects.get('alice');
  const role = (await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'application-administrator','Disposable concurrent actor fixture',clock_timestamp()+interval '1 hour') RETURNING id", [userId], 'fixture')).rows[0];
  try {
    const pairs = await Promise.all(['app-operator', 'alice'].map(name => issue(name)));
    const results = await Promise.all(pairs.map((pair, index) => request(quickBase, '/api/quick/service-principals', { method: 'POST', token: pair.access_token, body: { appName: 'ConcurrentApp' + index } })));
    for (const [index, result] of results.entries()) {
      assert.equal(result.status, 201); const calls = receiverCalls.filter(call => call.operationId === result.headers.get('x-od-operation-id')); assert.equal(calls.length, 3);
      assert.ok(calls.every(call => call.authorization === 'Bearer ' + pairs[index].access_token));
    }
    assert.notEqual(results[0].headers.get('x-od-operation-id'), results[1].headers.get('x-od-operation-id')); assert.equal(forbiddenServiceTokens, 0);
  } finally { await identityDb.write('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE id=$1', [role.id], 'fixture-cleanup'); }
});

test('an operator revoked before credential delivery cannot receive a newly generated client secret', async () => {
  const owner = await issue('app-operator'); const gate = holdNextJoin('/api/service-accounts');
  const operation = request(quickBase, '/api/quick/service-principals', { method: 'POST', token: owner.access_token, body: { appName: 'LateCredentialFence' } });
  try { await gate.wait(); assert.equal((await revoke(owner.access_token)).status, 200); }
  finally { gate.release(); }
  const result = await operation; assert.equal(result.status, 401); assert.equal(result.body.success, false); assert.equal(result.body.clientSecret, undefined);
  assert.equal(receiverCalls.length, 3); assert.equal(forbiddenServiceTokens, 0);
});
test('a disconnected orchestration caller cannot leave detached follow-up writes running with their captured credential', async () => {
  const owner = await issue('app-operator'); const gate = holdNextJoin(); const controller = new AbortController();
  const operation = fetch(quickBase + '/api/quick/service-principals', { method: 'POST', headers: { Authorization: 'Bearer ' + owner.access_token, 'Content-Type': 'application/json' }, body: JSON.stringify({ appName: 'DisconnectedApp' }), signal: controller.signal });
  try { await gate.wait(); controller.abort(); await assert.rejects(operation); await new Promise(resolve => setTimeout(resolve, 50)); }
  finally { controller.abort(); gate.release(); }
  await new Promise(resolve => setTimeout(resolve, 50)); assert.deepEqual(receiverCalls.map(call => call.path), ['/api/computers/join']); assert.equal(forbiddenServiceTokens, 0);
  assert.equal((await request(quickBase, '/health')).status, 200);
});

const pimBase = '/api/identity/pim';
async function pimLeaseFixture(role = 'license-manager', withMfa = true) {
  const username = 'pim-owner-' + (++pimOwnerNumber);
  const manager = await issue('pim-manager'); const reviewer = await issue('pim-reviewer'); let owner = await issue(username);
  const eligibility = await request(identityBase, pimBase + '/eligibilities', { method: 'POST', token: manager.access_token,
    body: { userId: canonicalSubjects.get(username), role, maxDurationSeconds: 3600, validForSeconds: 86400, reason: 'Reviewed real canonical PIM eligibility' } });
  assert.equal(eligibility.status, 201);
  const pending = await request(identityBase, pimBase + '/requests', { method: 'POST', token: owner.access_token,
    body: { id: randomUUID(), eligibilityId: eligibility.body.id, durationSeconds: 3600, reason: 'Independent temporary license operation' } });
  assert.equal(pending.status, 200); assert.equal(pending.body.status, 'pending');
  if (withMfa) owner = await configureFactor(username, owner);
  return { username, manager, reviewer, owner, eligibility: eligibility.body, pending: pending.body };
}
async function configureFactor(username, pair) {
  const setup = await request(issuerBase, '/api/mfa/enroll', { method: 'POST', token: pair.access_token, body: { username, password: 'disposable-password' } });
  assert.equal(setup.status, 200); const counter = Math.floor(Date.now() / 30000) - 1;
  const confirmed = await request(issuerBase, '/api/mfa/confirm', { method: 'POST', token: pair.access_token, body: { code: totp(setup.body.secret, counter) } });
  assert.equal(confirmed.status, 200); rememberFactor(username, setup.body.secret, counter);
  return issue(username);
}
function pimDecision(fixture, action, token = fixture.owner.access_token) {
  return request(identityBase, `${pimBase}/requests/${fixture.pending.id}/${action}`, { method: 'POST', token, body: {} });
}
test('PIM self-request, independent approval and activation create actual license authority, not a parallel active label', async () => {
  const fixture = await pimLeaseFixture(); const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,2) RETURNING id', ['PIM actual license pool'])).rows[0];
  const route = `/api/licenses/${product.id}/assign`; const body = { assignee_type: 'user', assignee_id: canonicalSubjects.get('bob') };
  assert.equal((await request(policyBase, route, { method: 'POST', token: fixture.owner.access_token, body })).status, 403);
  assert.equal((await pimDecision(fixture, 'approve', fixture.manager.access_token)).status, 403);
  const approved = await pimDecision(fixture, 'approve', fixture.reviewer.access_token); assert.equal(approved.status, 200); assert.equal(approved.body.status, 'approved');
  assert.equal((await request(policyBase, route, { method: 'POST', token: fixture.owner.access_token, body })).status, 403);
  assert.equal((await pimDecision(fixture, 'activate', fixture.reviewer.access_token)).status, 404);
  const active = await pimDecision(fixture, 'activate'); assert.equal(active.status, 200); assert.equal(active.body.status, 'active');
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: fixture.owner.access_token })).status, 401);
  assert.equal((await renew(fixture.owner.refresh_token)).status, 400);
  const operator = await issue(fixture.username); assert.ok(payload(operator.access_token).roles.includes('license-manager'));
  assert.equal((await request(gatewayBase, route, { method: 'POST', token: operator.access_token, body })).status, 201);
  assert.equal((await pimDecision(fixture, 'revoke', fixture.reviewer.access_token)).body.status, 'revoked');
  for (const base of [gatewayBase, policyBase]) assert.equal((await request(base, route, { method: 'POST', token: operator.access_token, body })).status, 401);
  assert.equal((await renew(operator.refresh_token)).status, 400);
  assert.equal((await request(policyBase, route, { method: 'POST', token: (await issue(fixture.username)).access_token, body })).status, 403);
  const audit = (await identityDb.query('SELECT actor FROM identity_pim_audit WHERE entity_id=$1 ORDER BY created_at DESC LIMIT 1', [fixture.pending.id])).rows[0];
  assert.equal(JSON.parse(audit.actor).userId, canonicalSubjects.get('pim-reviewer'));
  assert.equal((await request(identityBase, `${pimBase}/eligibilities/${fixture.eligibility.id}`, { method: 'DELETE', token: fixture.manager.access_token })).status, 200);
});
test('a withdrawn reviewer authorization cannot be reused for PIM activation even with an otherwise valid owner session', async () => {
  const fixture = await pimLeaseFixture(); assert.equal((await pimDecision(fixture, 'approve', fixture.reviewer.access_token)).status, 200);
  await identityDb.write('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [canonicalSubjects.get('pim-reviewer')], 'reviewer-security-reset');
  assert.equal((await pimDecision(fixture, 'activate')).status, 409);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: fixture.owner.access_token })).status, 200);
  assert.equal((await identityDb.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [fixture.pending.id])).rows[0].count, 0);
  assert.equal((await request(identityBase, `${pimBase}/eligibilities/${fixture.eligibility.id}`, { method: 'DELETE', token: fixture.manager.access_token })).status, 200);
});
test('failed PIM audit cannot grant or fake activation, and eligibility withdrawal ends an already active canonical lease', async () => {
  const fixture = await pimLeaseFixture(); assert.equal((await pimDecision(fixture, 'approve', fixture.reviewer.access_token)).status, 200);
  await identityDb.query('ALTER TABLE identity_pim_audit RENAME TO unavailable_pim_audit');
  try {
    assert.equal((await pimDecision(fixture, 'activate')).status, 503);
    assert.equal((await request(issuerBase, '/oauth/userinfo', { token: fixture.owner.access_token })).status, 200);
    assert.equal((await identityDb.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [fixture.pending.id])).rows[0].count, 0);
  } finally { await identityDb.query('ALTER TABLE unavailable_pim_audit RENAME TO identity_pim_audit'); }
  assert.equal((await pimDecision(fixture, 'activate')).body.status, 'active'); const activated = await issue(fixture.username);
  assert.equal((await request(identityBase, `${pimBase}/eligibilities/${fixture.eligibility.id}`, { method: 'DELETE', token: fixture.manager.access_token })).status, 200);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: activated.access_token })).status, 401);
  assert.equal((await renew(activated.refresh_token)).status, 400);
  const own = await request(identityBase, pimBase + '/self', { token: (await issue(fixture.username)).access_token });
  assert.equal(own.body.requests.find(row => row.id === fixture.pending.id).status, 'revoked');
});

test('a fresh password, a posted MFA flag and independent PIM approval cannot replace a verified second factor', async () => {
  const fixture = await pimLeaseFixture('license-reader', false);
  assert.deepEqual(payload(fixture.owner.access_token).amr, ['pwd']);
  assert.equal((await pimDecision(fixture, 'approve', fixture.reviewer.access_token)).status, 200);
  const result = await pimDecision(fixture, 'activate'); assert.equal(result.status, 428); assert.equal(result.body.error, 'verified_mfa_required');
  assert.equal((await identityDb.query('SELECT COUNT(*)::int AS count FROM identity_role_assignments WHERE activation_request_id=$1', [fixture.pending.id])).rows[0].count, 0);
  assert.equal((await request(identityBase, `${pimBase}/eligibilities/${fixture.eligibility.id}`, { method: 'DELETE', token: fixture.manager.access_token })).status, 200);
});

test('real enrollment, replay protection, fresh process and refresh preserve verified MFA while fencing weaker checkpoints', async () => {
  const username = 'mfa-owner'; const pair = await issue(username); const other = await issue(username);
  const headers = { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username, password: 'disposable-password', scope: 'openid roles' };
  const pending = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: headers }); assert.equal(pending.status, 302);
  const code = new URL(pending.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid roles' } });
  assert.equal((await fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username, password: 'disposable-password' }) })).status, 200);
  assert.equal((await request(issuerBase, '/api/mfa?userId=' + canonicalSubjects.get('bob'), { token: pair.access_token })).status, 400);
  assert.equal((await request(issuerBase, '/api/mfa/enroll', { method: 'POST', token: pair.access_token, body: { username: 'bob', password: 'disposable-password' } })).status, 403);
  assert.equal((await request(issuerBase, '/api/mfa/enroll', { method: 'POST', token: pair.access_token, body: { username, password: 'disposable-password', userId: canonicalSubjects.get('bob') } })).status, 400);
  const setup = await request(issuerBase, '/api/mfa/enroll', { method: 'POST', token: pair.access_token, body: { username, password: 'disposable-password' } }); assert.equal(setup.status, 200);
  assert.equal(setup.headers.get('cache-control'), 'no-store'); const counter = Math.floor(Date.now() / 30000) - 1; const setupCode = totp(setup.body.secret, counter);
  assert.equal((await request(issuerBase, '/api/mfa/confirm', { method: 'POST', token: other.access_token, body: { code: setupCode } })).status, 409);
  assert.equal((await request(issuerBase, '/api/mfa/confirm', { method: 'POST', token: pair.access_token, body: { code: setupCode } })).status, 200);
  for (const [base, route] of [[issuerBase, '/oauth/userinfo'], [gatewayBase, '/api/gateway/access'], [identityBase, '/api/users'], [policyBase, '/api/licenses/access']]) assert.equal((await request(base, route, { token: pair.access_token })).status, 401);
  assert.equal((await renew(pair.refresh_token)).status, 400);
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: headers.redirect_uri } })).status, 400);
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.body.device_code, client_id: clientId, client_secret: clientSecret } })).status, 400);
  for (const extra of [{}, { amr: ['pwd', 'otp'], mfaEnabled: true }, { otpCode: setupCode }]) assert.equal((await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { ...headers, ...extra } })).status, 401);
  rememberFactor(username, setup.body.secret, counter); const stronger = await issue(username);
  assert.deepEqual(payload(stronger.access_token).amr, ['pwd', 'otp']); assert.deepEqual(payload(stronger.id_token).amr, ['pwd', 'otp']);
  const refreshed = await renew(stronger.refresh_token); assert.equal(refreshed.status, 200); assert.deepEqual(payload(refreshed.body.access_token).mfa_authorization, payload(stronger.access_token).mfa_authorization);
  const fresh = await startFreshIssuer();
  try { assert.equal((await request(fresh.base, '/oauth/userinfo', { token: refreshed.body.access_token })).status, 200); }
  finally { await fresh.stop(); }
  const unused = await nextOtp(username);
  const wrongPassword = await request(issuerBase, '/api/mfa/disable', { method: 'POST', token: refreshed.body.access_token, body: { username, password: 'wrong-password', code: unused } }); assert.equal(wrongPassword.status, 401);
  const disabled = await request(issuerBase, '/api/mfa/disable', { method: 'POST', token: refreshed.body.access_token, body: { username, password: 'disposable-password', code: unused } }); assert.equal(disabled.status, 200);
  for (const token of [pair.access_token, stronger.access_token, refreshed.body.access_token]) assert.equal((await request(issuerBase, '/oauth/userinfo', { token })).status, 401);
  assert.equal((await renew(refreshed.body.refresh_token)).status, 400);
});

test('a live MFA source outage fails closed at every receiver and cannot spend refresh or silently issue a weaker token', async () => {
  const pair = await issue('bob'); const hash = createHash('sha256').update(pair.refresh_token).digest('hex');
  await issuerDb.query('ALTER TABLE oauth_mfa_factors RENAME TO unavailable_mfa_factors');
  try {
    for (const [base, route] of [[issuerBase, '/oauth/userinfo'], [gatewayBase, '/api/gateway/access'], [identityBase, '/api/users'], [policyBase, '/api/licenses/access'], [quickBase, '/api/quick/access']]) assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    assert.equal((await renew(pair.refresh_token)).status, 503);
    assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1', [hash])).rows[0].consumed_at, null);
    assert.equal((await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: 'bob', password: 'disposable-password' } })).status, 503);
  } finally { await issuerDb.query('ALTER TABLE unavailable_mfa_factors RENAME TO oauth_mfa_factors'); }
  assert.equal((await renew(pair.refresh_token)).status, 200);
});

test('actual device approval needs its own unused canonical OTP and the resulting token carries only the verified methods', async () => {
  const username = 'mfa-device-owner'; const stronger = await configureFactor(username, await issue(username));
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid roles' } });
  const approve = extra => fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username, password: 'disposable-password', ...extra }) });
  assert.equal((await approve({ amr: ['pwd', 'otp'], mfaEnabled: true })).status, 401);
  const otpCode = await nextOtp(username); assert.equal((await approve({ otpCode })).status, 200);
  const polled = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.body.device_code, client_id: clientId, client_secret: clientSecret } });
  assert.equal(polled.status, 200); const claims = payload(polled.body.access_token);
  assert.deepEqual(claims.amr, ['pwd', 'otp']); assert.equal(claims.mfa_authorization.userId, canonicalSubjects.get(username)); assert.equal(claims.mfa_authorization.authTime, claims.auth_time);
  for (const token of [stronger.access_token, polled.body.access_token]) assert.equal((await request(issuerBase, '/oauth/userinfo', { token })).status, 200);
});

test('a stalled MFA source query is cancelled server-side and cannot consume a refresh credential', async () => {
  const pair = await issue('bob'); const hash = createHash('sha256').update(pair.refresh_token).digest('hex'); const lock = await issuerDb.pool.connect();
  await lock.query('BEGIN'); await lock.query('LOCK TABLE oauth_mfa_factors IN ACCESS EXCLUSIVE MODE');
  try {
    const started = Date.now(); assert.equal((await request(issuerBase, '/oauth/userinfo', { token: pair.access_token })).status, 503); assert.ok(Date.now() - started < 7000);
    assert.equal((await renew(pair.refresh_token)).status, 503); assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1', [hash])).rows[0].consumed_at, null);
    const waiting = await issuerDb.query("SELECT COUNT(*)::int AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%oauth_mfa_factors%'", ['od-native-' + schemas[0]]);
    assert.equal(waiting.rows[0].count, 0);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
  assert.equal((await renew(pair.refresh_token)).status, 200);
});

async function recoveryFixture(username) {
  const pair = await configureFactor(username, await issue(username)); const code = await nextOtp(username);
  const generated = await request(issuerBase, '/api/mfa/recovery-codes', { method: 'POST', token: pair.access_token, body: { username, password: 'disposable-password', code } });
  assert.equal(generated.status, 200); assert.equal(generated.body.recoveryCodes.length, 8); assert.equal(generated.headers.get('cache-control'), 'no-store');
  assert.deepEqual((await request(issuerBase, '/api/mfa/recovery-codes', { token: pair.access_token })).body, { remaining: 8 });
  return { pair, codes: generated.body.recoveryCodes, username };
}
for (const flow of ['code', 'device']) test('actual recovery replaces only its factor and fences strong ' + flow + ' checkpoints, refresh and receivers without granting license rights', async () => {
  const username = 'recovery-' + flow + '-owner'; const fixture = await recoveryFixture(username); let code; let device;
  const otpCode = await nextOtp(username);
  if (flow === 'code') {
    const pending = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username, password: 'disposable-password', otpCode, scope: 'openid roles' } });
    assert.equal(pending.status, 302); code = new URL(pending.headers.get('location')).searchParams.get('code');
  } else {
    device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid roles' } });
    assert.equal((await fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username, password: 'disposable-password', otpCode }) })).status, 200);
  }
  const body = { username, password: 'disposable-password', recoveryCode: fixture.codes[0] };
  assert.equal((await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body: { ...body, password: 'incorrect' } })).status, 401);
  assert.equal((await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body: { ...body, userId: canonicalSubjects.get('operator') } })).status, 400);
  const started = await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body }); assert.equal(started.status, 200); assert.deepEqual(Object.keys(started.body).sort(), ['challenge', 'expiresAt', 'otpauthUri', 'secret']);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: started.body.challenge })).status, 401);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: fixture.pair.access_token })).status, 200);
  assert.equal((await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body })).status, 401);
  const counter = Math.floor(Date.now() / 30000) - 1;
  const completed = await request(issuerBase, '/oauth/mfa/recovery/confirm', { method: 'POST', body: { challenge: started.body.challenge, code: totp(started.body.secret, counter) } });
  assert.equal(completed.status, 200); assert.deepEqual(completed.body, { enabled: true, reauthenticationRequired: true });
  for (const [base, route] of [[issuerBase, '/oauth/userinfo'], [gatewayBase, '/api/gateway/access'], [identityBase, '/api/users'], [policyBase, '/api/licenses/access'], [quickBase, '/api/quick/access']]) assert.equal((await request(base, route, { token: fixture.pair.access_token })).status, 401);
  assert.equal((await renew(fixture.pair.refresh_token)).status, 400);
  const grant = flow === 'code' ? { grant_type: 'authorization_code', code, redirect_uri: 'http://localhost:4000/callback' } : { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.body.device_code };
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { ...grant, client_id: clientId, client_secret: clientSecret } })).status, 400);
  rememberFactor(username, started.body.secret, counter); const fresh = await issue(username);
  assert.deepEqual(payload(fresh.access_token).roles, ['user']); assert.deepEqual(payload(fresh.access_token).amr, ['pwd', 'otp']);
  assert.equal((await request(policyBase, '/api/licenses', { method: 'POST', token: fresh.access_token, body: { name: 'No new license rights', total_seats: 2 } })).status, 403);
  assert.deepEqual((await request(issuerBase, '/api/mfa/recovery-codes', { token: fresh.access_token })).body, { remaining: 0 });
  const independent = await startFreshIssuer();
  try { assert.equal((await request(independent.base, '/oauth/userinfo', { token: fresh.access_token })).status, 200); assert.equal((await request(independent.base, '/oauth/userinfo', { token: fixture.pair.access_token })).status, 401); }
  finally { await independent.stop(); }
});

test('recovery is fenced by canonical disable/re-enable and source loss without consuming a challenge or offering administrator reset', async () => {
  const fixture = await recoveryFixture('recovery-identity-owner'); const { username } = fixture;
  const body = { username, password: 'disposable-password', recoveryCode: fixture.codes[0] };
  const administrator = await issue();
  assert.equal((await request(issuerBase, '/api/mfa/recovery-codes', { method: 'POST', token: administrator.access_token, body: { username, password: 'disposable-password', code: '123456' } })).status, 403);
  const started = await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body }); assert.equal(started.status, 200);
  const confirmation = { challenge: started.body.challenge, code: totp(started.body.secret, Math.floor(Date.now() / 30000)) };
  await identityDb.query('ALTER TABLE identity_subject_links RENAME TO unavailable_recovery_links');
  try { assert.equal((await request(issuerBase, '/oauth/mfa/recovery/confirm', { method: 'POST', body: confirmation })).status, 503); }
  finally { await identityDb.query('ALTER TABLE unavailable_recovery_links RENAME TO identity_subject_links'); }
  const identifier = started.body.challenge.split('.')[0]; assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_mfa_recovery_challenges WHERE id=$1', [identifier])).rows[0].consumed_at, null);
  await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [canonicalSubjects.get(username)], 'recovery-disable');
  assert.equal((await request(issuerBase, '/oauth/mfa/recovery/confirm', { method: 'POST', body: confirmation })).status, 403);
  await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [canonicalSubjects.get(username)], 'recovery-reactivate');
  assert.equal((await request(issuerBase, '/oauth/mfa/recovery/confirm', { method: 'POST', body: confirmation })).status, 401);
  const restored = await request(issuerBase, '/oauth/mfa/recovery/start', { method: 'POST', body: { ...body, recoveryCode: fixture.codes[1] } }); assert.equal(restored.status, 200);
  assert.equal((await issuerDb.query('SELECT superseded_at FROM oauth_mfa_recovery_challenges WHERE id=$1', [identifier])).rows[0].superseded_at instanceof Date, true);
});

test('backup codes generated by an in-flight operation are not disclosed after the actual owner is disabled', async () => {
  const username = 'recovery-redaction-owner'; const pair = await configureFactor(username, await issue(username)); const code = await nextOtp(username);
  const lock = await issuerDb.pool.connect(); await lock.query('BEGIN'); await lock.query('LOCK TABLE oauth_mfa_recovery_codes IN ACCESS EXCLUSIVE MODE');
  const operation = request(issuerBase, '/api/mfa/recovery-codes', { method: 'POST', token: pair.access_token, body: { username, password: 'disposable-password', code } });
  let outcome;
  try {
    let waiting = 0; const deadline = Date.now() + 900;
    do {
      waiting = (await issuerDb.query("SELECT COUNT(*)::int AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE 'UPDATE oauth_mfa_recovery_codes%'", ['od-native-' + schemas[0]])).rows[0].count;
      if (waiting) break; await new Promise(resolve => setTimeout(resolve, 10));
    } while (Date.now() < deadline);
    assert.equal(waiting, 1); await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [canonicalSubjects.get(username)], 'fixture-revoke-before-backup-disclosure');
  } finally { await lock.query('ROLLBACK'); lock.release(); outcome = await operation; }
  assert.equal(outcome.status, 401); assert.deepEqual(outcome.body, { error: 'authorization_changed_outcome_unknown' });
  assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_mfa_recovery_codes WHERE user_id=$1', [canonicalSubjects.get(username)])).rows[0].count, 8);
  await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [canonicalSubjects.get(username)], 'fixture-reactivate-after-redaction');
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: pair.access_token })).status, 401);
});

async function authenticationPolicyFixture(extra = {}) {
  const sequence = ++authenticationPolicyNumber; const username = 'auth-policy-user-' + sequence; const adminName = 'auth-policy-admin-' + sequence;
  const weakAdministrator = await issue(adminName); const administrator = await configureFactor(adminName, weakAdministrator);
  const client = await registerApplication(administrator.access_token, extra, false);
  const assigned = await request(issuerBase, `/api/clients/${client.clientId}/assignments`, { method: 'POST', token: administrator.access_token,
    body: { requestId: randomUUID(), targetType: 'user', targetId: canonicalSubjects.get(username), durationSeconds: 28800, reason: 'Independent assigned required-MFA user' } }); assert.equal(assigned.status, 201);
  return { username, client, administrator };
}
async function enforceAuthentication(client, administrator, required = true) {
  const result = await request(issuerBase, `/api/clients/${client.clientId}/authentication`, { method: 'PUT', token: administrator.access_token,
    headers: clientCondition(client), body: { required, maxAgeSeconds: 300, reason: 'Reviewed application MFA freshness rule' } });
  assert.equal(result.status, 200); assert.equal(result.body.required, required); return { ...client, version: result.body.version };
}
test('actual MFA policy fences weaker access and refresh, requires assigned public enrollment, then allows only a normal new two-factor login', async () => {
  const fixture = await authenticationPolicyFixture(); const { username, administrator } = fixture; let client = fixture.client;
  const weak = await issueForApplication(client, username); client = await enforceAuthentication(client, administrator);
  for (const [base, route] of [[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/users'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']]) assert.equal((await request(base,route,{ token: weak.access_token })).status,401);
  assert.equal((await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'refresh_token',client_id:client.clientId,client_secret:client.clientSecret,refresh_token:weak.refresh_token } })).status,400);
  const loginBody = { client_id: client.clientId, redirect_uri: client.redirectUris[0], username, password: 'disposable-password', scope: 'openid roles', amr: ['pwd','otp'] };
  const denied = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:loginBody }); assert.equal(denied.status,401); assert.equal(denied.body.error,'mfa_enrollment_required');
  assert.equal((await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId:client.clientId,username:'alice',password:'disposable-password' } })).status,403);
  assert.equal((await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId:client.clientId,username,password:'disposable-password',userId:canonicalUser } })).status,400);
  const before = (await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count;
  const started = await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId:client.clientId,username,password:'disposable-password' } }); assert.equal(started.status,200);
  assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:started.body.challenge })).status,401);
  assert.equal((await request(issuerBase,'/oauth/mfa/recovery/confirm',{ method:'POST',body:{ challenge:started.body.challenge,code:'123456' } })).status,401);
  const counter = Math.floor(Date.now()/30000)-1; const confirmed = await request(issuerBase,'/oauth/mfa/enrollment/confirm',{ method:'POST',body:{ challenge:started.body.challenge,code:totp(started.body.secret,counter) } });
  assert.equal(confirmed.status,200); assert.deepEqual(confirmed.body,{ enabled:true,reauthenticationRequired:true }); assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count,before);
  assert.equal((await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:loginBody })).status,401);
  const signedIn = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ ...loginBody,otpCode:totp(started.body.secret,counter+1) } }); assert.equal(signedIn.status,302);
  const code = new URL(signedIn.headers.get('location')).searchParams.get('code');
  const strong = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'authorization_code',client_id:client.clientId,client_secret:client.clientSecret,redirect_uri:client.redirectUris[0],code } }); assert.equal(strong.status,200);
  assert.deepEqual(payload(strong.body.access_token).amr,['pwd','otp']); assert.deepEqual(payload(strong.body.access_token).roles,['user']);
  assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:strong.body.access_token })).status,200);
  assert.equal((await request(policyBase,'/api/licenses',{ method:'POST',token:strong.body.access_token,body:{ name:'No new privilege',total_seats:1 } })).status,403);
  const renewed = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'refresh_token',client_id:client.clientId,client_secret:client.clientSecret,refresh_token:strong.body.refresh_token } }); assert.equal(renewed.status,200);
  assert.equal(payload(renewed.body.access_token).auth_time,payload(strong.body.access_token).auth_time);
  const independent = await startFreshIssuer(); try { assert.equal((await request(independent.base,'/oauth/userinfo',{ token:renewed.body.access_token })).status,200); } finally { await independent.stop(); }
});
test('policy MFA age denies a genuine signed historical session at every live receiver and refresh cannot rejuvenate it', async () => {
  const fixture = await authenticationPolicyFixture(); const { username, administrator } = fixture; const client = await enforceAuthentication(fixture.client,administrator);
  const setup = await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId:client.clientId,username,password:'disposable-password' } }); assert.equal(setup.status,200); const counter=Math.floor(Date.now()/30000)-1;
  assert.equal((await request(issuerBase,'/oauth/mfa/enrollment/confirm',{ method:'POST',body:{ challenge:setup.body.challenge,code:totp(setup.body.secret,counter) } })).status,200);
  const login = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:client.clientId,redirect_uri:client.redirectUris[0],username,password:'disposable-password',otpCode:totp(setup.body.secret,counter+1),scope:'openid roles' } }); assert.equal(login.status,302);
  const issued = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'authorization_code',client_id:client.clientId,client_secret:client.clientSecret,redirect_uri:client.redirectUris[0],code:new URL(login.headers.get('location')).searchParams.get('code') } }); assert.equal(issued.status,200);
  const { exp,iat,jti,aud,client_id,token_use,...original }=payload(issued.body.access_token); const authTime=Math.floor(Date.now()/1000)-301; const sid=randomUUID();
  const authorization={ ...original,aud:client.clientId,sid,auth_time:authTime,mfa_authorization:{ ...original.mfa_authorization,authTime },iat:Math.floor(Date.now()/1000) };
  const refreshToken=randomUUID()+randomUUID(); const expiresAt=Date.now()+86400000;
  await new SessionStore(issuerDb).create({ id:sid,issuer,subject:authorization.sub,principalType:'user',clientId:client.clientId,authTime,expiresAt },
    { hash:createHash('sha256').update(refreshToken).digest('hex'),scope:authorization.scope,authorization,expiresAt });
  const keys=new SigningKeys({ privateKeyFile:firstKeyFile,verificationJwksFile:null,ephemeral:false,production:true });
  const old=jwt.sign({ ...authorization,aud:'opendirectory-api',client_id:client.clientId,token_use:'access',jti:randomUUID() },keys.privateKey,{ algorithm:'RS256',keyid:keys.kid,expiresIn:3600 });
  for(const [base,route]of [[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/users'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']])assert.equal((await request(base,route,{ token:old })).status,401);
  assert.equal((await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'refresh_token',client_id:client.clientId,client_secret:client.clientSecret,refresh_token:refreshToken } })).status,400);
  assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1',[createHash('sha256').update(refreshToken).digest('hex')])).rows[0].consumed_at,null);
  assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:issued.body.access_token })).status,200);
});
test('authentication staff is independent from metadata and reads, protected-scope writes, weak proof and self-client policy are not bypasses', async () => {
  const fixture=await authenticationPolicyFixture({ scopes:['openid'] }); const {client}=fixture;
  const manager=await configureFactor('auth-policy-manager',await issue('auth-policy-manager')); const reader=await issue('auth-policy-reader'); const metadata=await issue('app-operator');
  const path=`/api/clients/${client.clientId}/authentication`; const body={ required:true,maxAgeSeconds:300,reason:'Reviewed delegated authentication policy' };
  assert.equal((await request(issuerBase,path,{ token:reader.access_token })).status,200);
  for(const pair of [reader,metadata])assert.equal((await request(issuerBase,path,{ method:'PUT',token:pair.access_token,headers:clientCondition(client),body })).status,403);
  assert.equal((await request(issuerBase,'/api/clients',{ token:manager.access_token })).status,403);
  assert.equal((await request(issuerBase,path,{ method:'PUT',token:manager.access_token,headers:clientCondition(client),body })).status,200);
  assert.equal((await request(issuerBase,'/api/clients/devportal-od-client/authentication',{ method:'PUT',token:manager.access_token,headers:{'If-Match':'"anything"'},body })).status,409);
  const protectedClient=await registerApplication(fixture.administrator.access_token,{},false);
  const protectedPolicy=await request(issuerBase,`/api/clients/${protectedClient.clientId}/authentication`,{ token:manager.access_token }); assert.equal(protectedPolicy.body.canManage,false);
  assert.equal((await request(issuerBase,`/api/clients/${protectedClient.clientId}/authentication`,{ method:'PUT',token:manager.access_token,headers:clientCondition(protectedClient),body })).status,403);
  const weakAdmin=await issue('operator'); const target=await request(issuerBase,`/api/clients/${client.clientId}`,{ token:fixture.administrator.access_token });
  assert.equal((await request(issuerBase,path,{ method:'PUT',token:weakAdmin.access_token,headers:clientCondition(target.body),body })).body.error,'fresh_mfa_required');
});
test('policy changes also fence pending code/device generations, never revive weaker grants and do not pretend workload credentials are MFA', async () => {
  const fixture=await authenticationPolicyFixture({ grantTypes:['authorization_code','refresh_token','client_credentials','urn:ietf:params:oauth:grant-type:device_code'] }); const {username,administrator}=fixture; let client=fixture.client;
  const login=await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:client.clientId,redirect_uri:client.redirectUris[0],username,password:'disposable-password',scope:'openid roles' } }); assert.equal(login.status,302); const code=new URL(login.headers.get('location')).searchParams.get('code');
  const device=await request(issuerBase,'/oauth/device/code',{ method:'POST',body:{ client_id:client.clientId,client_secret:client.clientSecret,scope:'openid roles' } });
  assert.equal((await fetch(issuerBase+'/oauth/device/approve',{ method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ user_code:device.body.user_code,username,password:'disposable-password' }) })).status,200);
  const machine=await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'client_credentials',client_id:client.clientId,client_secret:client.clientSecret,scope:'openid' } }); assert.equal(machine.status,200);
  client=await enforceAuthentication(client,administrator); assert.equal((await request(issuerBase,'/oauth/access-state',{ token:machine.body.access_token })).body.active,false);
  const next=await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'client_credentials',client_id:client.clientId,client_secret:client.clientSecret,scope:'openid' } }); assert.equal(next.status,200); assert.equal(payload(next.body.access_token).actor_type,'application'); assert.equal(payload(next.body.access_token).amr,undefined);
  client=await enforceAuthentication(client,administrator,false);
  for(const grant of [{ grant_type:'authorization_code',code,redirect_uri:client.redirectUris[0] },{ grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:device.body.device_code }])assert.equal((await request(issuerBase,'/oauth/token',{ method:'POST',body:{ ...grant,client_id:client.clientId,client_secret:client.clientSecret } })).status,400);
});

test('real enrollment is fenced by canonical membership incarnation changes even with an overlapping direct application lease', async () => {
  const fixture = await authenticationPolicyFixture(); const { username, administrator } = fixture; const client = await enforceAuthentication(fixture.client, administrator);
  const groupResponse = await groupRequest(identityBase, '/api/groups', { method: 'POST', token: administrator.access_token, body: { name: 'Required MFA enrollment group' } }); assert.equal(groupResponse.status, 201); const group = groupResponse.body.id;
  assert.equal((await groupRequest(identityBase, `/api/groups/${group}/members`, { method: 'POST', token: administrator.access_token, body: { userId: canonicalSubjects.get(username) } })).status, 200);
  const granted = await request(issuerBase, `/api/clients/${client.clientId}/assignments`, { method: 'POST', token: administrator.access_token,
    body: { requestId: randomUUID(), targetType: 'group', targetId: group, durationSeconds: 3600, reason: 'Reviewed overlapping enrollment membership' } }); assert.equal(granted.status, 201);
  const credentials = { clientId: client.clientId, username, password: 'disposable-password' };
  const started = await request(issuerBase, '/oauth/mfa/enrollment/start', { method: 'POST', body: credentials }); assert.equal(started.status, 200);
  assert.equal((await groupRequest(identityBase, `/api/groups/${group}/members/${canonicalSubjects.get(username)}`, { method: 'DELETE', token: administrator.access_token })).status, 200);
  const confirmation = { challenge: started.body.challenge, code: totp(started.body.secret, Math.floor(Date.now()/30000)) };
  assert.equal((await request(issuerBase, '/oauth/mfa/enrollment/confirm', { method: 'POST', body: confirmation })).status, 401);
  assert.equal((await groupRequest(identityBase, `/api/groups/${group}/members`, { method: 'POST', token: administrator.access_token, body: { userId: canonicalSubjects.get(username) } })).status, 200);
  assert.equal((await request(issuerBase, '/oauth/mfa/enrollment/confirm', { method: 'POST', body: confirmation })).status, 401);
  const fresh = await request(issuerBase, '/oauth/mfa/enrollment/start', { method: 'POST', body: credentials }); assert.equal(fresh.status, 200);
  assert.equal((await request(issuerBase, '/oauth/mfa/enrollment/confirm', { method: 'POST', body: { challenge: fresh.body.challenge, code: totp(fresh.body.secret, Math.floor(Date.now()/30000)) } })).status, 200);
});

test('credential-source administrator claims and permissions cannot create canonical human privileges', async () => {
  credentialRoleOverrides.set('alice', ['admin']);
  try {
    const pair = await issue('alice'); const claims = payload(pair.access_token);
    assert.deepEqual(claims.roles, ['user']); assert.deepEqual(claims.permissions, []);
    assert.equal((await request(identityBase, '/api/users', { token: pair.access_token })).status, 403);
    assert.equal((await request(identityBase, `/api/users/${canonicalUser}/roles`, { method: 'POST', token: pair.access_token,
      body: { role: 'admin', durationSeconds: 3600, reason: 'Must not trust credential roles' } })).status, 403);
    assert.equal((await request(issuerBase, '/api/clients', { token: pair.access_token })).status, 403);
  } finally { credentialRoleOverrides.delete('alice'); }
});

test('canonical delegated roles grant actual license authority and revocation removes it at proxy and direct boundaries', async () => {
  const administrator = await issue(); const aliceId = canonicalSubjects.get('alice'); const bobId = canonicalSubjects.get('bob');
  const roleBody = { role: 'role-administrator', durationSeconds: 3600, reason: 'Reviewed delegated role operator' };
  const aliceBefore = await issue('alice');
  const delegation = await request(identityBase, `/api/users/${aliceId}/roles`, { method: 'POST', token: administrator.access_token, body: roleBody });
  assert.equal(delegation.status, 201); assert.equal((await request(issuerBase, '/oauth/userinfo', { token: aliceBefore.access_token })).status, 401);
  const alice = await issue('alice');
  assert.equal((await request(identityBase, '/api/users', { token: alice.access_token })).status, 403);
  const protectedRoles = await request(identityBase, `/api/users/${canonicalUser}/roles`, { token: alice.access_token });
  assert.equal(protectedRoles.status, 200);
  const protectedId = protectedRoles.body.assignments.find(assignment => assignment.role === 'admin').id;
  assert.equal((await request(identityBase, `/api/users/${canonicalUser}/roles/${protectedId}`, { method: 'DELETE', token: alice.access_token })).status, 403);
  for (const target of [aliceId, bobId]) assert.equal((await request(identityBase, `/api/users/${target}/roles`, { method: 'POST', token: alice.access_token, body: { ...roleBody, role: 'admin' } })).status, 403);
  const grant = await request(identityBase, `/api/users/${bobId}/roles`, { method: 'POST', token: alice.access_token, body: { ...roleBody, role: 'license-manager' } });
  assert.equal(grant.status, 201); const bob = await issue('bob'); assert.deepEqual(payload(bob.access_token).roles, ['license-manager', 'user']);
  const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,2) RETURNING id', ['Canonical role pool'])).rows[0];
  const assignment = { assignee_type: 'user', assignee_id: aliceId };
  assert.equal((await request(gatewayBase, `/api/licenses/${product.id}/assign`, { method: 'POST', token: bob.access_token, body: assignment })).status, 201);
  const revoke = await request(identityBase, `/api/users/${bobId}/roles/${grant.body.id}`, { method: 'DELETE', token: alice.access_token }); assert.equal(revoke.status, 200);
  for (const base of [gatewayBase, policyBase]) assert.equal((await request(base, `/api/licenses/${product.id}/assign`, { method: 'POST', token: bob.access_token, body: assignment })).status, 401);
  assert.equal((await renew(bob.refresh_token)).status, 400); const fresh = await issue('bob');
  assert.equal((await request(policyBase, `/api/licenses/${product.id}/assign`, { method: 'POST', token: fresh.access_token, body: assignment })).status, 403);
  const audit = (await identityDb.query('SELECT actor FROM identity_role_audit WHERE assignment_id=$1 ORDER BY created_at DESC LIMIT 1', [grant.body.id])).rows[0];
  assert.equal(JSON.parse(audit.actor).userId, aliceId);
  assert.equal((await request(identityBase, `/api/users/${aliceId}/roles/${delegation.body.id}`, { method: 'DELETE', token: administrator.access_token })).status, 200);
});

test('role expiry changes the live fingerprint without a worker, closes idle WebSockets and cannot revive through later regrant', async () => {
  const userId = canonicalUser;
  const grant = (await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager','Disposable short-lived expiry fixture',clock_timestamp()+interval '2 seconds') RETURNING id", [userId], 'fixture')).rows[0];
  const pair = await issue(); const context = payload(pair.access_token).identity_authorization;
  const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: 'Bearer ' + pair.access_token } }); await once(socket, 'open');
  try {
    const [code] = await Promise.race([once(socket, 'close'), new Promise((_resolve, reject) => { const timer = setTimeout(() => reject(new Error('Expired-role socket remained open')), 9000); timer.unref(); })]);
    assert.equal(code, 4401);
  } finally { socket.terminate(); }
  assert.equal((await identityDb.query('SELECT authorization_revision FROM users WHERE id=$1', [userId])).rows[0].authorization_revision, context.revision);
  for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']]) assert.equal((await request(base, route, { token: pair.access_token })).status, 401);
  assert.equal((await renew(pair.refresh_token)).status, 400);
  assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1', [createHash('sha256').update(pair.refresh_token).digest('hex')])).rows[0].consumed_at, null);
  const fresh = await issue(); assert.notEqual(payload(fresh.access_token).identity_authorization.rolesRevision, context.rolesRevision);
  await assert.rejects(identityDb.query('UPDATE identity_role_assignments SET expires_at=NULL WHERE id=$1', [grant.id]), error => error.code === '23514');
  const replacement = (await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager','Reviewed new grant after expiry',clock_timestamp()+interval '1 hour') RETURNING id", [userId], 'fixture')).rows[0];
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: pair.access_token })).status, 401);
  assert.equal((await renew(pair.refresh_token)).status, 400);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: (await issue()).access_token })).status, 200);
  await identityDb.write('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE id=$1', [replacement.id], 'fixture-cleanup');
});

test('role-source loss fails closed without consuming refresh, and pending code/device grants cannot bypass a role change', async () => {
  const pair = await issue(); await identityDb.query('ALTER TABLE identity_role_assignments RENAME TO unavailable_role_assignments');
  try {
    for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']]) assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    assert.equal((await renew(pair.refresh_token)).status, 503);
  } finally { await identityDb.query('ALTER TABLE unavailable_role_assignments RENAME TO identity_role_assignments'); }
  assert.equal((await renew(pair.refresh_token)).status, 200);
  const login = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: 'alice', password: 'disposable-password', scope: 'openid roles' } });
  assert.equal(login.status, 302); const code = new URL(login.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid roles' } });
  assert.equal((await fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_code: device.body.user_code, username: 'alice', password: 'disposable-password' }) })).status, 200);
  const grant = (await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'directory-reader','Disposable pending grant change') RETURNING id", [canonicalSubjects.get('alice')], 'fixture')).rows[0];
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: 'http://localhost:4000/callback' } })).status, 403);
  assert.equal((await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.body.device_code, client_id: clientId, client_secret: clientSecret } })).status, 403);
  await identityDb.write('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE id=$1', [grant.id], 'fixture-cleanup');
});

test('role-free client scopes are still fenced by expiry and refresh cannot re-expand removed role claims', async () => {
  const grant = (await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,'license-manager','Disposable role-free expiry fixture',clock_timestamp()+interval '2 seconds') RETURNING id", [canonicalUser], 'fixture')).rows[0];
  const original = await issue(); const narrowed = await renew(original.refresh_token, { scope: 'openid' }); assert.equal(narrowed.status, 200);
  assert.equal(payload(narrowed.body.access_token).roles, undefined); assert.equal(payload(narrowed.body.access_token).permissions, undefined);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: narrowed.body.access_token })).status, 200);
  assert.equal((await renew(narrowed.body.refresh_token, { scope: 'openid roles' })).status, 400);
  await new Promise(resolve => setTimeout(resolve, 2100));
  assert.equal((await request(identityBase, '/api/identity/subject', { token: narrowed.body.access_token })).status, 401);
  assert.equal((await renew(narrowed.body.refresh_token)).status, 400);
  assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [grant.id])).rows[0].revoked_at, null);
});

test('self-service scope and narrow session administration cannot be obtained from body/scopes as global rights', async () => {
  const target = await issue('alice', 'openid sessions.self.read sessions.self.revoke'); const second = await issue('alice');
  const bob = await issue('bob', 'openid sessions.self.read sessions.self.revoke'); const administrator = await issue('session-operator');
  assert.equal((await request(issuerBase, '/oauth/users/alice-subject/sessions/revoke', { method: 'POST', token: bob.access_token, body: { permissions: ['sessions.revoke'] } })).status, 403);
  assert.equal((await request(issuerBase, '/api/clients', { token: administrator.access_token })).status, 403);
  assert.equal((await request(identityBase, '/api/users', { token: administrator.access_token })).status, 403);
  const ended = await request(issuerBase, '/oauth/users/alice-subject/sessions/revoke', { method: 'POST', token: administrator.access_token });
  assert.equal(ended.status, 200); assert.equal(ended.body.revoked, 2);
  for (const pair of [target, second]) assert.equal((await request(issuerBase, '/oauth/access-state', { token: pair.access_token })).body.active, false);
  assert.equal((await request(issuerBase, '/oauth/access-state', { token: bob.access_token })).body.active, true);
});

test('session revocation, immutable identity/lifetime, consumed-refresh fences and audit survive migration reapplication', async () => {
  const pair = await issue(); await renew(pair.refresh_token);
  const id = payload(pair.access_token).sid;
  await request(issuerBase, `/oauth/sessions/${id}`, { method: 'DELETE', token: pair.access_token });
  await assert.rejects(issuerDb.query('UPDATE oauth_sessions SET revoked_at=NULL WHERE id=$1', [id]), /cannot be reactivated/);
  await assert.rejects(issuerDb.query("UPDATE oauth_sessions SET subject='other' WHERE id=$1", [id]), /immutable/);
  await assert.rejects(issuerDb.query('UPDATE oauth_session_refresh SET consumed_at=NULL WHERE consumed_at IS NOT NULL'), /cannot be reused/);
  await assert.rejects(issuerDb.query("UPDATE oauth_session_audit SET action='changed'"), /append-only/);
  await issuerDb.query(fs.readFileSync(path.join(__dirname, '../../migrations/006_sessions.sql'), 'utf8'));
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
});

async function startFreshIssuer(overrides = {}) {
  const script = `const db=require('./src/db');let server;process.on('SIGTERM',async()=>{server?.closeAllConnections();if(server)await new Promise(resolve=>server.close(resolve));await db.pool.end();process.exit(0)});(async()=>{await db.initDb();if(!db.isAvailable())throw Error('database unavailable');const app=require('./src');await app.initializeClients();server=app.listen(0,'127.0.0.1',()=>process.stdout.write('ISSUER_PORT '+server.address().port+'\\n'))})().catch(error=>{process.stderr.write(error.message);process.exit(1)});`;
  const child = spawn(process.execPath, ['-e', script], { cwd: path.join(__dirname, '../..'),
    env: { ...process.env, DATABASE_URL: databaseUrl(schemas[0]), ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; let errors = '';
  child.stderr.on('data', chunk => { errors = (errors + chunk).slice(-4096); });
  const stop = async () => {
    if (child.pid && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit'); child.kill('SIGTERM'); await exited;
    }
  };
  try {
    const base = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Fresh issuer did not listen: ' + errors)), 10000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error('Fresh issuer exited ' + code + ': ' + errors)); });
      child.stdout.on('data', chunk => {
        output = (output + chunk).slice(-8192);
        const found = /ISSUER_PORT (\d+)/.exec(output);
        if (found) { clearTimeout(timer); resolve('http://127.0.0.1:' + found[1]); }
      });
    });
    return { base, stop };
  } catch (error) { await stop(); throw error; }
}

test('a fresh issuer process reuses protected signing material, accepts old access, and continues persisted refresh', async () => {
  const pair = await issue(); const fresh = await startFreshIssuer();
  try {
    const base = fresh.base;
    assert.equal((await request(base, '/oauth/access-state', { token: pair.access_token })).body.active, true);
    const rotated = await request(base, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret } });
    assert.equal(rotated.status, 200); assert.equal(payload(rotated.body.access_token).sid, payload(pair.access_token).sid);
    const firstHeader = JSON.parse(Buffer.from(pair.access_token.split('.')[0], 'base64url'));
    const nextHeader = JSON.parse(Buffer.from(rotated.body.access_token.split('.')[0], 'base64url'));
    assert.equal(firstHeader.kid, nextHeader.kid);
    assert.equal((await request(base, '/oauth/access-state', { token: rotated.body.access_token })).body.active, true);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: rotated.body.access_token })).status, 200);
    const continued = await renew(rotated.body.refresh_token);
    assert.equal(continued.status, 200);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: continued.body.access_token })).status, 200);
    assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_session_refresh')).rows[0].count, 3);
  } finally { await fresh.stop(); }
});

test('failed bulk-revocation audit leaves every family active and the committed retry ends all current owner sessions', async () => {
  const first = await issue('alice', 'openid sessions.self.revoke'); const second = await issue('alice');
  await issuerDb.query(`CREATE FUNCTION reject_bulk_session_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF NEW.action='revoked_all' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER reject_bulk_session_audit BEFORE INSERT ON oauth_session_audit FOR EACH ROW EXECUTE FUNCTION reject_bulk_session_audit()`);
  try {
    assert.equal((await request(issuerBase, '/oauth/sessions/revoke-all', { method: 'POST', token: first.access_token })).status, 503);
    for (const pair of [first, second]) assert.equal((await request(issuerBase, '/oauth/access-state', { token: pair.access_token })).body.active, true);
  } finally { await issuerDb.query('DROP TRIGGER reject_bulk_session_audit ON oauth_session_audit; DROP FUNCTION reject_bulk_session_audit()'); }
  assert.deepEqual((await request(issuerBase, '/oauth/sessions/revoke-all', { method: 'POST', token: first.access_token })).body, { revoked: 2 });
  for (const pair of [first, second]) assert.equal((await request(issuerBase, '/oauth/access-state', { token: pair.access_token })).body.active, false);
});

test('revoking a session family closes an already open sibling-token WebSocket', async () => {
  const pair = await issue(); const rotated = await renew(pair.refresh_token);
  assert.equal(rotated.status, 200);
  const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: `Bearer ${pair.access_token}` } });
  await once(socket, 'open');
  try {
    const closed = once(socket, 'close');
    assert.equal((await request(issuerBase, '/oauth/sessions/current/revoke', { method: 'POST', token: rotated.body.access_token })).status, 200);
    const [code] = await Promise.race([closed, new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Session family revocation did not close the socket')), 9000); timer.unref();
    })]);
    assert.equal(code, 4401);
  } finally { socket.terminate(); }
});

test('session authority loss denies existing access, refresh and management without losing the original family', async () => {
  const pair = await issue();
  await issuerDb.query('ALTER TABLE oauth_sessions RENAME TO unavailable_sessions');
  try {
    for (const [base, route] of [[issuerBase, '/oauth/access-state'], [issuerBase, '/oauth/sessions'], [gatewayBase, '/api/gateway/access'], [policyBase, '/api/licenses/access']]) {
      assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    }
    assert.equal((await renew(pair.refresh_token)).status, 503);
    assert.equal((await request(issuerBase, '/oauth/sessions/current/revoke', { method: 'POST', token: pair.access_token })).status, 503);
  } finally { await issuerDb.query('ALTER TABLE unavailable_sessions RENAME TO oauth_sessions'); }
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 200);
  assert.equal((await renew(pair.refresh_token)).status, 200);
});

test('prepublished public overlap keeps old and new signatures valid across rotation at the actual receiving services', async () => {
  const pair = await issue();
  const fresh = await startFreshIssuer({ OAUTH_SIGNING_KEY_FILE: secondKeyFile, OAUTH_VERIFICATION_JWKS_FILE: previousKeyFile });
  try {
    const rotated = await request(fresh.base, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret } });
    assert.equal(rotated.status, 200);
    const firstHeader = JSON.parse(Buffer.from(pair.access_token.split('.')[0], 'base64url'));
    const nextHeader = JSON.parse(Buffer.from(rotated.body.access_token.split('.')[0], 'base64url'));
    assert.notEqual(firstHeader.kid, nextHeader.kid);
    const published = await request(fresh.base, '/.well-known/jwks.json');
    assert.equal(published.body.keys.length, 2); assert.equal(/PRIVATE KEY|"d":|"p":/.test(JSON.stringify(published.body)), false);
    for (const token of [pair.access_token, rotated.body.access_token]) {
      for (const [base, route] of [[fresh.base, '/oauth/access-state'], [fresh.base, '/oauth/userinfo'], [fresh.base, '/oauth/sessions'],
        [gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']]) {
        assert.equal((await request(base, route, { token })).status, 200);
      }
    }
    assert.equal((await request(fresh.base, '/oauth/revoke', { method: 'POST', body: { token: pair.access_token, client_id: clientId, client_secret: clientSecret } })).status, 200);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: rotated.body.access_token })).status, 200);
  } finally { await fresh.stop(); }
});

test('removing a retired key from the live authority denies its signature even when a gateway verifier still trusts the old public JWKS', async () => {
  const pair = await issue();
  const fresh = await startFreshIssuer({ OAUTH_SIGNING_KEY_FILE: secondKeyFile, OAUTH_VERIFICATION_JWKS_FILE: '' });
  let boundary;
  try {
    const rotated = await request(fresh.base, '/oauth/token', { method: 'POST', body: { grant_type: 'refresh_token', refresh_token: pair.refresh_token,
      client_id: clientId, client_secret: clientSecret } });
    assert.equal(rotated.status, 200);
    assert.equal((await request(fresh.base, '/oauth/access-state', { token: pair.access_token })).status, 401);
    const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
    const { createAuthenticator } = require('../../../api-gateway/src/middleware/auth');
    const source = createAccessStateClient({ endpoint: fresh.base + '/oauth/access-state' });
    const verifiedLocally = [];
    const authentication = createAuthenticator({ issuer, audience: 'opendirectory-api', jwksUri: issuerBase + '/.well-known/jwks.json',
      accessState: async (authorization, claims) => { verifiedLocally.push(claims.jti); return source(authorization, claims); } });
    boundary = new Gateway({ authentication, discover: false, enabledModules: [] });
    boundary.server.listen(0, '127.0.0.1'); const base = await listening(boundary.server);
    assert.equal((await request(base, '/api/gateway/access', { token: pair.access_token })).status, 401);
    assert.equal(verifiedLocally.includes(payload(pair.access_token).jti), true);
    assert.equal((await request(base, '/api/gateway/access', { token: rotated.body.access_token })).status, 200);
    assert.equal((await issuerDb.query('SELECT revoked_at FROM oauth_sessions')).rows[0].revoked_at, null);
  } finally {
    if (boundary) { const closed = once(boundary.server, 'close'); boundary.stop(); boundary.server.closeAllConnections(); await closed; }
    await fresh.stop();
  }
});

test('committed account disablement denies existing access, refresh, fresh login and license allocation without resurrecting tokens on reactivation', async () => {
  const pair = await issue();
  const lifecycle = await issue('lifecycle');
  const product = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,1) RETURNING id', ['Disabled operator pool'])).rows[0];
  const recipient = randomUUID(); await identityDb.write('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [recipient, recipient, recipient + '@test.invalid'], 'fixture');
  try {
    const original = await request(identityBase, `/api/users/${canonicalUser}`, { token: lifecycle.access_token });
    assert.equal((await request(identityBase, `/api/users/${canonicalUser}`, { method: 'PUT', token: lifecycle.access_token, headers: { 'If-Match': original.headers.get('etag') }, body: { enabled: false } })).status, 200);
    for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access'], [issuerBase, '/oauth/userinfo']]) {
      assert.equal((await request(base, route, { token: pair.access_token })).status, 401);
    }
    assert.equal((await renew(pair.refresh_token)).status, 400);
    assert.equal((await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: 'operator', password: 'disposable-password' } })).status, 403);
    for (const base of [gatewayBase, policyBase]) assert.equal((await request(base, `/api/licenses/${product.id}/assign`, { method: 'POST', token: pair.access_token,
      body: { assignee_type: 'user', assignee_id: recipient } })).status, 401);
    assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1', [product.id])).rows[0].count, 0);
    assert.equal((await request(identityBase, `/api/users/${canonicalUser}`, { method: 'PUT', token: pair.access_token, body: { enabled: true } })).status, 401);
    const disabled = await request(identityBase, `/api/users/${canonicalUser}`, { token: lifecycle.access_token });
    assert.equal((await request(identityBase, `/api/users/${canonicalUser}`, { method: 'PUT', token: lifecycle.access_token, headers: { 'If-Match': disabled.headers.get('etag') }, body: { enabled: true } })).status, 200);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
    assert.equal((await renew(pair.refresh_token)).status, 400);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: (await issue()).access_token })).status, 200);
  } finally { await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [canonicalUser], 'fixture-cleanup'); }
});

test('unlink/relink to the same user is a new authorization generation rather than a revival of the previous grant', async () => {
  const pair = await issue();
  try {
    await identityDb.write('DELETE FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [issuer, 'operator-subject'], 'link-administrator');
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
    await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, 'operator-subject', canonicalUser], 'link-administrator');
    const next = await issue(); assert.notEqual(payload(next.access_token).identity_authorization.linkRevision, payload(pair.access_token).identity_authorization.linkRevision);
    assert.equal((await renew(pair.refresh_token)).status, 400);
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: next.access_token })).status, 200);
  } finally {
    await identityDb.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [issuer, 'operator-subject', canonicalUser]);
  }
});

test('actual tenant pause denies existing access and refresh at direct and gateway boundaries without reviving old tokens on re-enable',async()=>{
 const{enableTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');const pair=await issue('tenant-session-user');const other=await issue('alice');
 const paths=[[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/licenses/kiosk'],[identityBase,'/api/identity/subject'],[policyBase,'/api/licenses/access']];
 for(const[base,route]of paths)assert.equal((await request(base,route,{token:pair.access_token})).status,200);
 try{
  await enableTenant(identityDb,schemas[1],separateTenant,false);
  for(const[base,route]of paths)assert.equal((await request(base,route,{token:pair.access_token})).status,401);
  assert.equal((await renew(pair.refresh_token)).status,400);assert.equal((await request(issuerBase,'/oauth/userinfo',{token:other.access_token})).status,200);
  const forged=await request(issuerBase,'/oauth/authorize/login',{method:'POST',body:{client_id:clientId,redirect_uri:'http://localhost:4000/callback',username:'tenant-session-user',password:'disposable-password',scope:'openid roles',tenantId:randomUUID()}});assert.equal(forged.status,403);
  await enableTenant(identityDb,schemas[1],separateTenant,true);
  for(const[base,route]of paths)assert.equal((await request(base,route,{token:pair.access_token})).status,401);
  assert.equal((await renew(pair.refresh_token)).status,400);const fresh=await issue('tenant-session-user');assert.equal((await request(issuerBase,'/oauth/userinfo',{token:fresh.access_token})).status,200);
  assert.notEqual(payload(fresh.access_token).identity_authorization.revision,payload(pair.access_token).identity_authorization.revision);
  assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1',[canonicalSubjects.get('tenant-session-user')])).rows[0].enabled,true);
 }finally{if(!(await identityDb.query('SELECT enabled FROM identity_tenants WHERE id=$1',[separateTenant])).rows[0].enabled)await enableTenant(identityDb,schemas[1],separateTenant,true);}
});
test('actual tenant generations fence pending authorization codes and approved device grants across pause and re-enable',async()=>{
 const{enableTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');const name='tenant-pending-user';
 const login=await request(issuerBase,'/oauth/authorize/login',{method:'POST',body:{client_id:clientId,redirect_uri:'http://localhost:4000/callback',username:name,password:'disposable-password',scope:'openid roles'}});assert.equal(login.status,302);const code=new URL(login.headers.get('location')).searchParams.get('code');
 const device=await request(issuerBase,'/oauth/device/code',{method:'POST',body:{client_id:clientId,client_secret:clientSecret,scope:'openid'}});assert.equal(device.status,200);
 const approval=await fetch(issuerBase+'/oauth/device/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_code:device.body.user_code,username:name,password:'disposable-password'})});assert.equal(approval.status,200);
 const before=(await issuerDb.query('SELECT count(*)::int AS count FROM oauth_sessions')).rows[0].count;
 try{await enableTenant(identityDb,schemas[1],separateTenant,false);await enableTenant(identityDb,schemas[1],separateTenant,true);
  assert.equal((await request(issuerBase,'/oauth/token',{method:'POST',body:{grant_type:'authorization_code',code,client_id:clientId,client_secret:clientSecret,redirect_uri:'http://localhost:4000/callback'}})).status,403);
  assert.equal((await request(issuerBase,'/oauth/token',{method:'POST',body:{grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:device.body.device_code,client_id:clientId,client_secret:clientSecret}})).status,403);
  assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM oauth_sessions')).rows[0].count,before);
 }finally{if(!(await identityDb.query('SELECT enabled FROM identity_tenants WHERE id=$1',[separateTenant])).rows[0].enabled)await enableTenant(identityDb,schemas[1],separateTenant,true);}
});
test('a verified but unlinked subject receives no code, family, or guessed canonical UUID', async () => {
  const result = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: 'unlinked', password: 'disposable-password' } });
  assert.equal(result.status, 403); assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count, 0);
});

test('a consumed login checkpoint cannot issue a family after disable/reactivate, including already approved device grants', async () => {
  const login = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: 'operator', password: 'disposable-password' } });
  const code = new URL(login.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid' } });
  const approval = await fetch(issuerBase + '/oauth/device/approve', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username: 'operator', password: 'disposable-password' }) });
  assert.equal(approval.status, 200);
  await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [canonicalUser], 'lifecycle');
  await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [canonicalUser], 'lifecycle');
  const exchanged = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'authorization_code', code, client_id: clientId, client_secret: clientSecret, redirect_uri: 'http://localhost:4000/callback' } });
  assert.equal(exchanged.status, 403);
  const polled = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: device.body.device_code, client_id: clientId, client_secret: clientSecret } });
  assert.equal(polled.status, 403); assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count, 0);
});

test('narrow session administration can invalidate user authorization without user-write or link privileges', async () => {
  const alice = await issue('alice'); const operator = await issue('session-operator'); const userId = canonicalSubjects.get('alice');
  const route = `/api/users/${userId}/authorization/invalidate`;
  assert.equal((await request(identityBase, route, { method: 'POST', token: alice.access_token, body: { roles: ['admin'] } })).status, 403);
  assert.equal((await request(identityBase, '/api/users', { token: operator.access_token })).status, 403);
  assert.equal((await request(identityBase, `/api/users/${userId}`, { method: 'PUT', token: operator.access_token, body: { enabled: false } })).status, 403);
  assert.equal((await request(identityBase, route, { method: 'POST', token: operator.access_token, body: { userId: canonicalUser } })).status, 400);
  const invalidated = await request(identityBase, route, { method: 'POST', token: operator.access_token, body: {} }); assert.equal(invalidated.status, 200);
  assert.notEqual(invalidated.body.revision, payload(alice.access_token).identity_authorization.revision);
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: alice.access_token })).status, 401);
  assert.equal((await renew(alice.refresh_token)).status, 400);
  const audit = (await identityDb.query('SELECT actor,reason FROM identity_authorization_audit WHERE user_id=$1 ORDER BY revision DESC LIMIT 1', [userId])).rows[0];
  assert.deepEqual(audit, { actor: 'session-operator-subject', reason: 'security_reset' });
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: (await issue('alice')).access_token })).status, 200);
});

test('generation invalidation rolls back when its audit cannot commit', async () => {
  const alice = await issue('alice'); const operator = await issue('session-operator'); const userId = canonicalSubjects.get('alice');
  await identityDb.query('ALTER TABLE identity_authorization_audit RENAME TO unavailable_authorization_audit');
  try {
    assert.equal((await request(identityBase, `/api/users/${userId}/authorization/invalidate`, { method: 'POST', token: operator.access_token, body: {} })).status, 503);
    assert.equal(String((await identityDb.query('SELECT authorization_revision FROM users WHERE id=$1', [userId])).rows[0].authorization_revision), payload(alice.access_token).identity_authorization.revision);
    assert.equal((await request(issuerBase, '/oauth/userinfo', { token: alice.access_token })).status, 200);
  } finally { await identityDb.query('ALTER TABLE unavailable_authorization_audit RENAME TO identity_authorization_audit'); }
});

test('identity authority outage denies live access and refresh without spending the refresh credential', async () => {
  const pair = await issue(); const hash = createHash('sha256').update(pair.refresh_token).digest('hex');
  await identityDb.query('ALTER TABLE identity_subject_links RENAME TO unavailable_subject_links');
  try {
    for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/identity/subject'], [policyBase, '/api/licenses/access']]) {
      assert.equal((await request(base, route, { token: pair.access_token })).status, 503);
    }
    assert.equal((await renew(pair.refresh_token)).status, 503);
    assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1', [hash])).rows[0].consumed_at, null);
  } finally { await identityDb.query('ALTER TABLE unavailable_subject_links RENAME TO identity_subject_links'); }
  assert.equal((await renew(pair.refresh_token)).status, 200);
});

test('the authority assertion cannot be exchanged for access, used on ordinary APIs, or retargeted to another subject', async () => {
  const { IdentityAuthority } = require('../IdentityAuthority'); let authorization;
  const source = new IdentityAuthority({ issuer, signingKeys: new SigningKeys({ privateKeyFile: firstKeyFile, verificationJwksFile: null, ephemeral: false }),
    endpoint: identityBase + '/internal/identity/authorization-state', fetchImpl: (url, options) => { authorization = options.headers.Authorization; return fetch(url, options); } });
  const context = await source.context('operator-subject'); assert.equal(context.userId, canonicalUser);
  const token = authorization.slice(7);
  for (const [base, route] of [[gatewayBase, '/api/gateway/access'], [identityBase, '/api/users'], [policyBase, '/api/licenses/access'], [issuerBase, '/api/clients'], [issuerBase, '/oauth/userinfo']]) {
    assert.ok([401, 403].includes((await request(base, route, { token })).status));
  }
  assert.equal((await request(identityBase, '/internal/identity/authorization-state', { method: 'POST', token, body: { subject: 'alice-subject' } })).status, 401);
  assert.equal((await request(identityBase, '/internal/identity/authorization-state', { method: 'POST', token: (await issue()).access_token, body: { subject: 'operator-subject' } })).status, 401);
});

test('authorization revisions survive migration reapplication, preserve harmless profile edits, and cannot be reset to old values', async () => {
  const pair = await issue(); const context = payload(pair.access_token).identity_authorization;
  await identityDb.write('UPDATE users SET display_name=$1 WHERE id=$2', ['Renamed Operator', canonicalUser], 'profile-editor');
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/005_authorization_generation.sql'), 'utf8'));
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 200);
  await identityDb.write('UPDATE users SET authorization_revision=1 WHERE id=$1', [canonicalUser], 'security-operator');
  const current = String((await identityDb.query('SELECT authorization_revision FROM users WHERE id=$1', [canonicalUser])).rows[0].authorization_revision);
  assert.ok(BigInt(current) > BigInt(context.revision));
  assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 401);
  await assert.rejects(identityDb.query('UPDATE identity_authorization_audit SET actor=$1 WHERE user_id=$2', ['forged', canonicalUser]), /append-only/);
});

test('idle native WebSockets close after directory disablement, without waiting for token expiry', async () => {
  const pair = await issue(); const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: 'Bearer ' + pair.access_token } });
  await once(socket, 'open');
  try {
    const closed = once(socket, 'close'); await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [canonicalUser], 'lifecycle');
    const [code] = await Promise.race([closed, new Promise((_resolve, reject) => { const timer = setTimeout(() => reject(new Error('Disabled-user socket remained open')), 9000); timer.unref(); })]);
    assert.equal(code, 4401);
  } finally { socket.terminate(); await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [canonicalUser], 'fixture-cleanup'); }
});

test('deleted canonical users cannot sign in again or reuse their identity UUID', async () => {
  const userId = randomUUID(); await identityDb.write('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, 'gone', 'gone@test.invalid'], 'fixture');
  await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, 'gone-subject', userId], 'fixture');
  await bootstrapApplications(issuerDb,{ issuer,identityBase,signingKeyFile: firstKeyFile,clients: [clientId],users: [userId] });
  const pair = await issue('gone'); await identityDb.write('DELETE FROM users WHERE id=$1', [userId], 'lifecycle');
  assert.equal((await request(issuerBase, '/oauth/userinfo', { token: pair.access_token })).status, 401); assert.equal((await renew(pair.refresh_token)).status, 400);
  await assert.rejects(identityDb.write('INSERT INTO users(id,username,email) VALUES($1,$2,$3)', [userId, 'gone', 'gone@test.invalid'], 'fixture'), /cannot be reused/);
});

test('idle native WebSockets fail closed on identity-authority storage loss as well as issuer-store loss', async () => {
  const pair = await issue(); const WebSocket = createRequire(path.join(__dirname, '../../../api-gateway/package.json'))('ws');
  const socket = new WebSocket(gatewayBase.replace('http:', 'ws:') + '/ws', { headers: { Authorization: 'Bearer ' + pair.access_token } });
  await once(socket, 'open');
  await identityDb.query('ALTER TABLE identity_subject_links RENAME TO unavailable_subject_links');
  try {
    const [code] = await Promise.race([once(socket, 'close'), new Promise((_resolve, reject) => { const timer = setTimeout(() => reject(new Error('Socket survived identity authority loss')), 9000); timer.unref(); })]);
    assert.equal(code, 1013);
  } finally { socket.terminate(); await identityDb.query('ALTER TABLE unavailable_subject_links RENAME TO identity_subject_links'); }
});

test('parallel device approvals cannot replace an already approved user after asynchronous identity checks', async () => {
  const device = await request(issuerBase, '/oauth/device/code', { method: 'POST', body: { client_id: clientId, client_secret: clientSecret, scope: 'openid roles' } });
  const approvals = await Promise.all(['alice', 'bob'].map(username => fetch(issuerBase + '/oauth/device/approve', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_code: device.body.user_code, username, password: 'disposable-password' }) })));
  assert.deepEqual(approvals.map(response => response.status).sort(), [200, 400]);
  const result = await request(issuerBase, '/oauth/token', { method: 'POST', body: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: device.body.device_code, client_id: clientId, client_secret: clientSecret } });
  assert.equal(result.status, 200);
  assert.equal(payload(result.body.access_token).sub, approvals[0].status === 200 ? 'alice-subject' : 'bob-subject');
});

test('a stalled directory query is cancelled server-side and refresh recovers without replaying a consumed credential', async () => {
  const pair = await issue(); const lock = await identityDb.pool.connect();
  await lock.query('BEGIN'); await lock.query('LOCK TABLE identity_subject_links IN ACCESS EXCLUSIVE MODE');
  try {
    assert.equal((await request(gatewayBase, '/api/gateway/access', { token: pair.access_token })).status, 503);
    assert.equal((await renew(pair.refresh_token)).status, 503);
    const hash = createHash('sha256').update(pair.refresh_token).digest('hex');
    assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1', [hash])).rows[0].consumed_at, null);
    let pending; const deadline = Date.now() + 2500;
    do {
      pending = await identityDb.query("SELECT COUNT(*)::int AS count FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock' AND query LIKE '%JOIN users ON users.id=identity_subject_links.user_id%'", ['od-native-' + schemas[1]]);
      if (!pending.rows[0].count) break;
      await new Promise(resolve => setTimeout(resolve, 20));
    } while (Date.now() < deadline);
    assert.equal(pending.rows[0].count, 0);
  } finally { await lock.query('ROLLBACK'); lock.release(); }
  const recovered = await renew(pair.refresh_token);
  assert.equal(recovered.status, 200, JSON.stringify({ error: recovered.body?.error, identityRequests, identityRateDenials }));
});

async function firstRoleFactor(username) {
  const setup = await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId,username,password:'disposable-password' } });
  assert.equal(setup.status,200); const counter = Math.floor(Date.now()/30000)-1;
  const confirmed = await request(issuerBase,'/oauth/mfa/enrollment/confirm',{ method:'POST',body:{ challenge:setup.body.challenge,code:totp(setup.body.secret,counter) } });
  assert.equal(confirmed.status,200); assert.deepEqual(confirmed.body,{ enabled:true,reauthenticationRequired:true }); assert.equal(confirmed.headers.get('set-cookie'),null);
  rememberFactor(username,setup.body.secret,counter); return issue(username);
}
async function roleRule(token, required, maxAgeSeconds = 300) {
  const path = '/api/identity/authentication/roles/license-manager';
  const current = await request(identityBase,path,{ token }); assert.equal(current.status,200);
  const changed = await request(identityBase,path,{ method:'PUT',token,headers:{ 'If-Match':`"od-role-authentication:license-manager:${current.body.version}"` },
    body:{ required,maxAgeSeconds,reason:'Reviewed client-independent license role assurance' } });
  assert.equal(changed.status,200); return changed.body;
}
test('canonical role assurance closes alternate-client and omitted-scope MFA bypasses, fences pending grants and protects actual license allocation', async () => {
  const metadata = await issue('role-policy-admin');
  const deniedManager = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:clientId,redirect_uri:'http://localhost:4000/callback',username:'role-policy-manager',password:'disposable-password',scope:'openid roles' } });
  assert.equal(deniedManager.body.error,'mfa_enrollment_required');
  const manager = await firstRoleFactor('role-policy-manager'); const reader = await issue('role-policy-reader');
  const client = await registerApplication(metadata.access_token,{ grantTypes:['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:device_code'] },false);
  for (const username of ['role-policy-user','role-policy-pending']) {
    const assigned = await request(issuerBase,`/api/clients/${client.clientId}/assignments`,{ method:'POST',token:metadata.access_token,
      body:{ requestId:randomUUID(),targetType:'user',targetId:canonicalSubjects.get(username),durationSeconds:3600,reason:'Independent alternate-client role policy fixture' } }); assert.equal(assigned.status,201);
  }
  const weak = await issueForApplication(client,'role-policy-user'); const omitted = await issue('role-policy-user','openid');
  assert.equal(payload(omitted.access_token).roles,undefined); assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:omitted.access_token })).status,200);
  const login = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:client.clientId,redirect_uri:client.redirectUris[0],username:'role-policy-pending',password:'disposable-password',scope:'openid roles' } }); assert.equal(login.status,302);
  const pendingCode = new URL(login.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase,'/oauth/device/code',{ method:'POST',body:{ client_id:client.clientId,client_secret:client.clientSecret,scope:'openid roles' } }); assert.equal(device.status,200);
  assert.equal((await fetch(issuerBase+'/oauth/device/approve',{ method:'POST',headers:{ 'Content-Type':'application/json' },body:JSON.stringify({ user_code:device.body.user_code,username:'role-policy-pending',password:'disposable-password' }) })).status,200);
  const path = '/api/identity/authentication/roles/license-manager'; const before = await request(identityBase,path,{ token:reader.access_token }); assert.equal(before.status,200);
  for (const token of [reader.access_token,(await issue('app-operator')).access_token]) assert.equal((await request(identityBase,path,{ method:'PUT',token,headers:{ 'If-Match':before.headers.get('etag') },body:{ required:true,maxAgeSeconds:300,reason:'Unpermitted policy downgrade attempt' } })).status,403);
  assert.equal((await request(identityBase,'/api/users',{ token:manager.access_token })).status,403);
  assert.equal((await request(identityBase,'/api/identity/authentication/roles/admin',{ method:'PUT',token:manager.access_token,headers:{ 'If-Match':'"od-role-authentication:admin:1"' },body:{ required:true,maxAgeSeconds:300,reason:'Protected policy must stay global' } })).status,403);
  await roleRule(manager.access_token,true);
  try {
    const binding = await request(issuerBase,'/oauth/mfa/enrollment/start',{ method:'POST',body:{ clientId,username:'role-policy-pending',password:'disposable-password' } }); assert.equal(binding.status,200);
    for (const token of [weak.access_token,omitted.access_token]) for (const [base,route] of [[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/identity/subject'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']]) assert.equal((await request(base,route,{ token })).status,401);
    const refresh = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'refresh_token',client_id:client.clientId,client_secret:client.clientSecret,refresh_token:weak.refresh_token } }); assert.equal(refresh.status,400);
    const denied = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:client.clientId,redirect_uri:client.redirectUris[0],username:'role-policy-user',password:'disposable-password',scope:'openid',amr:['pwd','otp'] } }); assert.equal(denied.body.error,'mfa_enrollment_required');
    const pool = (await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,2) RETURNING id',['Client-independent role MFA license pool'])).rows[0];
    const route = `/api/licenses/${pool.id}/assign`; const body = { assignee_type:'user',assignee_id:canonicalSubjects.get('bob') };
    assert.equal((await request(policyBase,route,{ method:'POST',token:weak.access_token,body })).status,401);
    assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[pool.id])).rows[0].count,0);
    const strong = await firstRoleFactor('role-policy-user'); const alternate = await issueForApplication(client,'role-policy-user');
    assert.deepEqual(payload(alternate.access_token).amr,['pwd','otp']); assert.equal((await request(policyBase,route,{ method:'POST',token:alternate.access_token,body })).status,201);
    assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:strong.access_token })).status,200);
    const renewed = await renew(strong.refresh_token); assert.equal(renewed.status,200); assert.equal(payload(renewed.body.access_token).auth_time,payload(strong.access_token).auth_time);
    await roleRule(manager.access_token,false,before.body.maxAgeSeconds);
    const completeBinding = () => request(issuerBase,'/oauth/mfa/enrollment/confirm',{ method:'POST',body:{ challenge:binding.body.challenge,code:totp(binding.body.secret,Math.floor(Date.now()/30000)) } });
    assert.equal((await completeBinding()).body.error,'mfa_enrollment_not_allowed');
    await roleRule(manager.access_token,true); assert.equal((await completeBinding()).body.error,'enrollment_authorization_changed');
    await roleRule(manager.access_token,false,before.body.maxAgeSeconds);
    for (const token of [weak.access_token,omitted.access_token,strong.access_token]) assert.equal((await request(issuerBase,'/oauth/userinfo',{ token })).status,401);
    const code = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'authorization_code',client_id:client.clientId,client_secret:client.clientSecret,redirect_uri:client.redirectUris[0],code:pendingCode } }); assert.equal(code.status,403);
    const deviceToken = await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'urn:ietf:params:oauth:grant-type:device_code',client_id:client.clientId,client_secret:client.clientSecret,device_code:device.body.device_code } }); assert.equal(deviceToken.status,403);
  } finally { await roleRule(manager.access_token,false,before.body.maxAgeSeconds); }
});
test('role-wide original MFA age and policy source outages fail closed without spending refresh credentials', async () => {
  const administrator = await configureFactor('role-policy-admin',await issue('role-policy-admin'));
  const before = await request(identityBase,'/api/identity/authentication/roles/license-manager',{ token:administrator.access_token }); await roleRule(administrator.access_token,true);
  try {
    const strong = await firstRoleFactor('role-policy-age'); const original = payload(strong.access_token); const authTime = Math.floor(Date.now()/1000)-301; const sid = randomUUID();
    const { exp,iat,jti,aud,client_id,token_use,...base } = original;
    const authorization = { ...base,aud:clientId,sid,auth_time:authTime,mfa_authorization:{ ...original.mfa_authorization,authTime },iat:Math.floor(Date.now()/1000) };
    const refreshToken = randomUUID()+randomUUID(); const expiresAt = Date.now()+86400000; const hash = createHash('sha256').update(refreshToken).digest('hex');
    await new SessionStore(issuerDb).create({ id:sid,issuer,subject:authorization.sub,principalType:'user',clientId,authTime,expiresAt },{ hash,scope:authorization.scope,authorization,expiresAt });
    const keys = new SigningKeys({ privateKeyFile:firstKeyFile,verificationJwksFile:null,ephemeral:false,production:true });
    const old = jwt.sign({ ...authorization,aud:'opendirectory-api',client_id:clientId,token_use:'access',jti:randomUUID() },keys.privateKey,{ algorithm:'RS256',keyid:keys.kid,expiresIn:3600 });
    for (const [baseUrl,route] of [[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/identity/subject'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']]) assert.equal((await request(baseUrl,route,{ token:old })).status,401);
    assert.equal((await renew(refreshToken)).status,400); assert.equal((await issuerDb.query('SELECT consumed_at FROM oauth_session_refresh WHERE token_hash=$1',[hash])).rows[0].consumed_at,null);
    await identityDb.query('ALTER TABLE identity_role_authentication RENAME TO withheld_role_authentication');
    try {
      assert.equal((await request(policyBase,'/api/licenses/access',{ token:strong.access_token })).status,503);
      assert.equal((await renew(strong.refresh_token)).status,503);
    } finally { await identityDb.query('ALTER TABLE withheld_role_authentication RENAME TO identity_role_authentication'); }
    assert.equal((await request(policyBase,'/api/licenses/access',{ token:strong.access_token })).status,200); assert.equal((await renew(strong.refresh_token)).status,200);
  } finally { await roleRule(administrator.access_token,false,before.body.maxAgeSeconds); }
});
test('an explicitly registered eligibility workload receives no human role, profile read or license allocation and is fenced by client revocation',async()=>{
  const administrator=await issue('operator'); const client=await registerApplication(administrator.access_token,{ grantTypes:['client_credentials'],scopes:['licenses.users.read'] },false);
  const mint=()=>request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'client_credentials',client_id:client.clientId,client_secret:client.clientSecret,scope:'licenses.users.read' } });
  const issued=await mint(); assert.equal(issued.status,200); const decoded=payload(issued.body.access_token);
  assert.deepEqual(decoded.permissions,['licenses.users.read']); assert.equal(decoded.actor_type,'application'); assert.equal(decoded.roles,undefined); assert.equal(decoded.mfa_authorization,undefined);
  const beneficiary=canonicalSubjects.get('fulfillment-beneficiary');const homeTenant=(await identityDb.query("SELECT identity_tenant_id('user',$1) AS tenant_id",[beneficiary])).rows[0].tenant_id;
  const revision=(await issuerDb.query('SELECT revision FROM oauth_clients WHERE id=$1',[client.clientId])).rows[0].revision;assert.equal(decoded.client_revision,revision);
  const route=`/api/license-users/${beneficiary}/snapshot`;const foreignRoute=`/api/license-users/${canonicalSubjects.get('production-foreign-member')}/snapshot`;
  assert.equal((await request(identityBase,route,{token:issued.body.access_token})).status,403);
  const review={issuer,clientId:client.clientId,tenantId:homeTenant,clientRevision:revision,expectedVersion:'0',enabled:true,reason:'Explicit reviewed home tenant eligibility source fixture'};
  const binding=await changeSource(identityDb,review);assert.equal(binding.valid,true);assert.equal(binding.tenant_id,homeTenant);
  const snapshot=await request(identityBase,route,{ token:issued.body.access_token }); assert.equal(snapshot.status,200); assert.equal(Object.keys(snapshot.body).length,5);assert.equal(snapshot.body.userId,beneficiary);assert.equal(snapshot.headers.get('x-od-license-snapshot-protocol'),'1');
  assert.equal((await request(identityBase,foreignRoute,{token:issued.body.access_token})).status,404);
  assert.equal((await request(identityBase,'/api/users',{ token:issued.body.access_token })).status,403);
  assert.equal((await request(policyBase,'/api/licenses/fulfillment/connectors',{ method:'POST',token:issued.body.access_token,body:{ tenantId:randomUUID(),reason:'Machine cannot configure cloud bindings' } })).status,403);
  const disabled=await request(issuerBase,`/api/clients/${client.clientId}`,{ method:'PUT',token:administrator.access_token,headers:clientCondition(client),body:{ enabled:false } }); assert.equal(disabled.status,200);
  assert.equal((await request(identityBase,route,{ token:issued.body.access_token })).status,401);
  const enabled=await request(issuerBase,`/api/clients/${client.clientId}`,{ method:'PUT',token:administrator.access_token,headers:clientCondition(disabled.body),body:{ enabled:true } }); assert.equal(enabled.status,200);
  assert.equal((await request(identityBase,route,{ token:issued.body.access_token })).status,401);
  const renewed=await mint();assert.equal(renewed.status,200);const currentRevision=(await issuerDb.query('SELECT revision FROM oauth_clients WHERE id=$1',[client.clientId])).rows[0].revision;assert.equal(payload(renewed.body.access_token).client_revision,currentRevision);assert.ok(BigInt(currentRevision)>BigInt(revision));
  assert.equal((await request(identityBase,route,{token:renewed.body.access_token})).status,403);
  assert.deepEqual((await identityDb.query('SELECT client_revision,version FROM identity_license_user_sources WHERE issuer=$1 AND client_id=$2',[issuer,client.clientId])).rows[0],{client_revision:revision,version:binding.version});
  const rotated=await changeSource(identityDb,{...review,clientRevision:currentRevision,expectedVersion:binding.version,reason:'Explicit reviewed operator rotation after OAuth client reenablement'});assert.equal(rotated.id,binding.id);assert.equal(rotated.tenant_id,homeTenant);assert.equal(rotated.version,'2');
  const restored=await request(identityBase,route,{token:renewed.body.access_token});assert.equal(restored.status,200);assert.equal(restored.body.userId,beneficiary);assert.equal(restored.headers.get('x-od-license-snapshot-protocol'),'1');assert.equal((await request(identityBase,foreignRoute,{token:renewed.body.access_token})).status,404);assert.equal((await request(identityBase,route,{token:issued.body.access_token})).status,401);
});
test('real MFA-separated provider configuration and actual local entitlement drive a separately authenticated Graph worker without credential or success fabrication',async()=>{
  const administrator=await issue('operator'); const configurator=await firstRoleFactor('fulfillment-configurator'); const reader=await issue('fulfillment-reader'); const operatorActor=await firstRoleFactor('fulfillment-operator'); const licenseAdmin=await issue('fulfillment-license-admin');
  const base='/api/licenses/fulfillment'; const reason='Reviewed isolated exclusive Microsoft direct licensing';
  const pool=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Actual issuer to Graph fixture',2) RETURNING id")).rows[0];
  const create=(kind,body,token=configurator.access_token)=>request(policyBase,base+'/'+kind,{ method:'POST',token,body:{ ...body,reason } });
  for (const token of [reader.access_token,operatorActor.access_token,licenseAdmin.access_token]) assert.equal((await create('connectors',{ tenantId:randomUUID() },token)).status,403);
  assert.equal((await create('connectors',{ tenantId:randomUUID() },administrator.access_token)).body.error,'fresh_mfa_required');
  const connector=await create('connectors',{ tenantId:randomUUID() }); assert.equal(connector.status,201); assert.equal(connector.body.enabled,false);
  const product=await create('products',{ connectorId:connector.body.id,licenseId:pool.id,skuId:randomUUID(),disabledPlans:[],exclusiveDirectManagement:true }); assert.equal(product.status,201);
  const subject=await create('subjects',{ connectorId:connector.body.id,userId:canonicalSubjects.get('fulfillment-beneficiary'),objectId:randomUUID(),exclusiveDirectManagement:true }); assert.equal(subject.status,201);
  for (const [kind,result] of [['connectors',connector],['products',product],['subjects',subject]]) {
    const enabled=await request(policyBase,`${base}/${kind}/${result.body.id}`,{ method:'PUT',token:configurator.access_token,headers:{ 'If-Match':result.headers.get('etag') },body:{ enabled:true,reason } }); assert.equal(enabled.status,200);
  }
  const assignment={ assignee_type:'user',assignee_id:subject.body.userId };
  assert.equal((await request(policyBase,`/api/licenses/${pool.id}/assign`,{ method:'POST',token:configurator.access_token,body:assignment })).status,403);
  assert.equal((await request(policyBase,`/api/licenses/${pool.id}/assign`,{ method:'POST',token:administrator.access_token,body:assignment })).status,201);
  const statusPath=`${base}/targets/${pool.id}/${subject.body.userId}`; const pending=await request(policyBase,statusPath,{ token:reader.access_token }); assert.equal(pending.status,200); assert.equal(pending.body.status,'pending');
  const sourceClient=await registerApplication(administrator.access_token,{ scopes:['licenses.users.read'],grantTypes:['client_credentials'] },false);
  const mintSource=()=>request(issuerBase,'/oauth/token',{method:'POST',body:{grant_type:'client_credentials',client_id:sourceClient.clientId,client_secret:sourceClient.clientSecret,scope:'licenses.users.read'}});
  const originalSource=await mintSource();assert.equal(originalSource.status,200);const sourceRevision=(await issuerDb.query('SELECT revision FROM oauth_clients WHERE id=$1',[sourceClient.clientId])).rows[0].revision;assert.equal(payload(originalSource.body.access_token).client_revision,sourceRevision);
  const beneficiaryTenant=(await identityDb.query("SELECT identity_tenant_id('user',$1) AS tenant_id",[subject.body.userId])).rows[0].tenant_id;const sourceRoute=`/api/license-users/${subject.body.userId}/snapshot`;
  assert.equal((await request(identityBase,sourceRoute,{token:originalSource.body.access_token})).status,403);
  const sourceReview={issuer,clientId:sourceClient.clientId,tenantId:beneficiaryTenant,clientRevision:sourceRevision,expectedVersion:'0',enabled:true,reason:'Explicit reviewed beneficiary tenant binding for the isolated Graph worker'};
  const sourceBinding=await changeSource(identityDb,sourceReview);assert.equal(sourceBinding.valid,true);assert.equal(sourceBinding.tenant_id,beneficiaryTenant);
  const sourceSnapshot=await request(identityBase,sourceRoute,{token:originalSource.body.access_token});assert.equal(sourceSnapshot.status,200);assert.equal(sourceSnapshot.headers.get('x-od-license-snapshot-protocol'),'1');assert.equal((await request(identityBase,`/api/license-users/${canonicalSubjects.get('production-foreign-member')}/snapshot`,{token:originalSource.body.access_token})).status,404);
  const { WorkerIdentity }=require('../../../policy-service/src/licenses/fulfillment/WorkerConfiguration');
  const { LicenseAllocator }=require('../../../policy-service/src/licenses/LicenseAllocator'); const { ProviderStore }=require('../../../policy-service/src/licenses/fulfillment/ProviderStore');
  const { GraphLicenseClient }=require('../../../policy-service/src/licenses/fulfillment/GraphLicenseClient'); const { FulfillmentWorker }=require('../../../policy-service/src/licenses/fulfillment/FulfillmentWorker');
  let present=false; const graphCalls=[];let capacityFixture;
  const graphServer=http.createServer(async(incoming,outgoing)=>{
    const chunks=[]; for await(const chunk of incoming)chunks.push(chunk); const body=Buffer.concat(chunks).toString(); graphCalls.push({ path:incoming.url,method:incoming.method,body,authorization:incoming.headers.authorization }); outgoing.setHeader('Content-Type','application/json');
    if (incoming.url.endsWith('/token')) return outgoing.end(JSON.stringify({ token_type:'Bearer',access_token:new URLSearchParams(body).get('client_secret')==='owned-capacity-fixture-secret'?'owned-issuer-capacity-token':'owned-vendor-access-token',expires_in:3600 }));
    if(incoming.url.startsWith('/v1.0/subscribedSkus?')){assert.equal(incoming.method,'GET');assert.equal(incoming.headers.authorization,'Bearer owned-issuer-capacity-token');return outgoing.end(JSON.stringify({value:[{skuId:product.body.skuId,skuPartNumber:'OWNED_ISSUER_CAPACITY',appliesTo:'User',capabilityStatus:'Enabled',prepaidUnits:{enabled:2,warning:0,suspended:0,lockedOut:0},consumedUnits:0}]}));}
    assert.equal(incoming.headers.authorization,'Bearer owned-vendor-access-token');
    if (incoming.method==='POST') { const command=JSON.parse(body); assert.equal(command.addLicenses.length+command.removeLicenses.length,1); present=command.addLicenses.length>0; return outgoing.end(JSON.stringify({ id:subject.body.objectId })); }
    outgoing.end(JSON.stringify({ id:subject.body.objectId,accountEnabled:true,assignedLicenses:present?[{ skuId:product.body.skuId,disabledPlans:[] }]:[],licenseAssignmentStates:present?[{ skuId:product.body.skuId,disabledPlans:[],assignedByGroup:null,state:'Active',error:null }]:[] }));
  }).listen(0,'127.0.0.1'); const graphOrigin=await listening(graphServer);
  try {
    const identity=new WorkerIdentity({ sourceTokenUrl:issuerBase+'/oauth/token',sourceClientId:sourceClient.clientId,sourceClientSecret:sourceClient.clientSecret,identityUrl:identityBase+'/' });
    const graph=new GraphLicenseClient({ tenantId:connector.body.tenantId,clientId:randomUUID(),clientSecret:'isolated-vendor-secret',fetchImpl:(url,options)=>fetch(graphOrigin+new URL(url).pathname+new URL(url).search,options) });
    const store=new ProviderStore(new LicenseAllocator(policyDb)); const worker=new FulfillmentWorker({ store,identity,graph,connectorId:connector.body.id,tenantId:connector.body.tenantId,sourceClientId:sourceClient.clientId });
    await worker.target(pending.body.id);assert.equal((await request(policyBase,statusPath,{token:reader.access_token})).body.error,'capacity_budget_required');assert.equal(graphCalls.filter(call=>call.path.endsWith('/assignLicense')).length,0);
    const{capacityAdmissionFixture}=require('../../../../../scripts/lib/license-capacity-admission-fixture.cjs');
    capacityFixture=await capacityAdmissionFixture({database:policyDb,admin:administration,connectionString:process.env.OAUTH_TEST_DATABASE_URL,schema:schemas[2],connector:connector.body,product:product.body,fetchImpl:(url,options)=>fetch(graphOrigin+new URL(url).pathname+new URL(url).search,options)});
    await worker.target(pending.body.id); assert.equal((await request(policyBase,statusPath,{ token:reader.access_token })).body.status,'verifying');
    await worker.target(pending.body.id); const confirmed=await request(policyBase,statusPath,{ token:reader.access_token }); assert.equal(confirmed.body.status,'confirmed'); assert.equal(confirmed.body.owned,true); assert.equal(present,true);
    assert.equal(JSON.stringify(confirmed.body).includes('owned-vendor-access-token'),false);
    const capacityReport=await request(policyBase,`${base}/connectors/${connector.body.id}/capacity`,{token:reader.access_token});assert.equal(capacityReport.body.schemaVersion,2);assert.equal(capacityReport.body.products[0].admission.chargedUnits,1);assert.equal(capacityReport.body.products[0].admission.remainingUnits,1);
    const disabled=await request(issuerBase,`/api/clients/${sourceClient.clientId}`,{ method:'PUT',token:administrator.access_token,headers:clientCondition(sourceClient),body:{ enabled:false } }); assert.equal(disabled.status,200);
    assert.equal((await request(identityBase,sourceRoute,{token:originalSource.body.access_token})).status,401);
    assert.equal((await request(policyBase,`/api/licenses/${pool.id}/assignments/${subject.body.userId}?assignee_type=user`,{ method:'DELETE',token:administrator.access_token })).status,204);
    const before=graphCalls.length; await worker.target(pending.body.id); assert.equal(graphCalls.length,before); assert.equal((await request(policyBase,statusPath,{ token:reader.access_token })).body.error,'identity_source_unavailable');
    assert.equal((await request(issuerBase,`/api/clients/${sourceClient.clientId}`,{ method:'PUT',token:administrator.access_token,headers:clientCondition(disabled.body),body:{ enabled:true } })).status,200);
    assert.equal((await request(identityBase,sourceRoute,{token:originalSource.body.access_token})).status,401);
    const renewedSource=await mintSource();assert.equal(renewedSource.status,200);const renewedRevision=(await issuerDb.query('SELECT revision FROM oauth_clients WHERE id=$1',[sourceClient.clientId])).rows[0].revision;assert.equal(payload(renewedSource.body.access_token).client_revision,renewedRevision);assert.ok(BigInt(renewedRevision)>BigInt(sourceRevision));
    assert.equal((await request(identityBase,sourceRoute,{token:renewedSource.body.access_token})).status,403);
    await worker.target(pending.body.id);assert.equal(graphCalls.length,before);assert.equal((await request(policyBase,statusPath,{token:reader.access_token})).body.error,'identity_source_unavailable');
    assert.deepEqual((await identityDb.query('SELECT client_revision,version FROM identity_license_user_sources WHERE issuer=$1 AND client_id=$2',[issuer,sourceClient.clientId])).rows[0],{client_revision:sourceRevision,version:sourceBinding.version});
    const reviewedRotation=await changeSource(identityDb,{...sourceReview,clientRevision:renewedRevision,expectedVersion:sourceBinding.version,reason:'Explicit reviewed Graph source revision rotation after client reenablement'});assert.equal(reviewedRotation.id,sourceBinding.id);assert.equal(reviewedRotation.tenant_id,beneficiaryTenant);
    const reviewedSnapshot=await request(identityBase,sourceRoute,{token:renewedSource.body.access_token});assert.equal(reviewedSnapshot.status,200);assert.equal(reviewedSnapshot.headers.get('x-od-license-snapshot-protocol'),'1');
    await worker.target(pending.body.id); await worker.target(pending.body.id); const removed=await request(policyBase,statusPath,{ token:reader.access_token }); assert.equal(removed.body.status,'confirmed'); assert.equal(removed.body.desired,false); assert.equal(present,false);
    const secrets=JSON.stringify((await policyDb.query('SELECT details FROM license_fulfillment_events')).rows); assert.equal(secrets.includes('isolated-vendor-secret')||secrets.includes(sourceClient.clientSecret)||secrets.includes('owned-vendor-access-token'),false);
  } finally {await capacityFixture?.close(); graphServer.closeAllConnections(); await new Promise(resolve=>graphServer.close(resolve)); }
});
test('actual capacity reports deny ordinary license administration and recheck the original signed reader after the actual SQL read waits',async()=>{
 const owner=await firstRoleFactor('capacity-config');const reader=await issue('capacity-reader');const ordinary=await issue('capacity-license-manager');const created=await request(policyBase,'/api/licenses/fulfillment/connectors',{method:'POST',token:owner.access_token,body:{tenantId:randomUUID(),reason:'Explicitly reviewed capacity reporting connector'}});assert.equal(created.status,201,JSON.stringify(created.body));const path='/api/licenses/fulfillment/connectors/'+created.body.id+'/capacity';
 for(const base of [policyBase,gatewayBase]){const result=await request(base,path,{token:reader.access_token});assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.body.observation,null);assert.equal(result.body.allocationChanged,false);assert.equal(result.body.providerFulfillmentConfirmed,false);}
 assert.equal((await request(policyBase,path,{token:ordinary.access_token})).status,403);assert.equal((await request(policyBase,path+'?tenantId='+randomUUID(),{token:reader.access_token})).status,400);assert.equal((await request(policyBase,path,{method:'POST',token:reader.access_token,body:{refresh:true}})).status,404);
 const blocker=await policyDb.getClient();let pending;
 try{await blocker.query('BEGIN');await blocker.query('LOCK TABLE license_provider_products IN ACCESS EXCLUSIVE MODE');pending=request(policyBase,path,{token:reader.access_token});let waiting=false;
 for(let attempt=0;attempt<300;attempt++){waiting=(await policyDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT product.*,catalog.name,catalog.total_seats%'")).rows.length>0;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,10));}assert.equal(waiting,true);assert.equal((await revoke(reader.access_token)).status,200);await blocker.query('COMMIT');const result=await pending;assert.equal(result.status,401,JSON.stringify(result.body));assert.equal(Object.hasOwn(result.body,'products'),false);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
 assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_capacity_runs run JOIN license_capacity_sources source ON source.id=run.source_id WHERE source.connector_id=$1',[created.body.id])).rows[0].count,0);
});
test('a provider enablement admitted before a real SQL lock wait cannot commit after its canonical protected role was independently revoked',async()=>{
  const administrator=await issue('operator'); const owner=await firstRoleFactor('fulfillment-revoked-config'); const path='/api/licenses/fulfillment/connectors';
  const created=await request(policyBase,path,{ method:'POST',token:owner.access_token,body:{ tenantId:randomUUID(),reason:'Reviewed isolated pending provider enablement' } }); assert.equal(created.status,201);
  const license=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Blocked actor provider fixture',1) RETURNING id")).rows[0];
  const product=await request(policyBase,'/api/licenses/fulfillment/products',{ method:'POST',token:owner.access_token,body:{ connectorId:created.body.id,licenseId:license.id,skuId:randomUUID(),disabledPlans:[],exclusiveDirectManagement:true,reason:'Reviewed target for post-admission lock fence' } }); assert.equal(product.status,201);
  const subject=await request(policyBase,'/api/licenses/fulfillment/subjects',{ method:'POST',token:owner.access_token,body:{ connectorId:created.body.id,userId:canonicalSubjects.get('fulfillment-beneficiary'),objectId:randomUUID(),exclusiveDirectManagement:true,reason:'Reviewed target for post-admission lock fence' } }); assert.equal(subject.status,201);
  const target=(await policyDb.query('SELECT id,version FROM license_fulfillment_targets WHERE product_id=$1 AND subject_id=$2',[product.body.id,subject.body.id])).rows[0];
  const blocker=await policyDb.getClient(); let pending;
  try {
    await blocker.query('BEGIN'); await blocker.query('SELECT id FROM license_fulfillment_targets WHERE id=$1 FOR UPDATE',[target.id]);
    pending=request(policyBase,path+'/'+created.body.id,{ method:'PUT',token:owner.access_token,headers:{ 'If-Match':created.headers.get('etag') },body:{ enabled:true,reason:'This pending actor must remain currently authorized' } }); pending.catch(()=>{});
    let waiting=false; const deadline=Date.now()+2000;
    while(Date.now()<deadline) {
      waiting=(await policyDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'UPDATE license_provider_connectors%') AS waiting")).rows[0].waiting;
      if(waiting)break; await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.equal(waiting,true);
    const userId=canonicalSubjects.get('fulfillment-revoked-config'); const roles=await request(identityBase,`/api/users/${userId}/roles`,{ token:administrator.access_token }); assert.equal(roles.status,200);
    const grant=roles.body.assignments.find(row=>row.role==='license-provider-administrator');
    assert.equal((await request(identityBase,`/api/users/${userId}/roles/${grant.id}`,{ method:'DELETE',token:administrator.access_token })).status,200);
    await blocker.query('ROLLBACK'); assert.equal((await pending).status,401);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if(pending)await pending.catch(()=>{}); }
  const stored=(await policyDb.query('SELECT enabled,version FROM license_provider_connectors WHERE id=$1',[created.body.id])).rows[0]; assert.equal(stored.enabled,false); assert.equal(stored.version,'1');
  assert.equal((await policyDb.query('SELECT version FROM license_fulfillment_targets WHERE id=$1',[target.id])).rows[0].version,target.version);
});

async function changeActivationRule(token, required, maximum = 600) {
  const route = '/api/identity/pim/policies/license-manager';
  const before = await request(identityBase,route,{ token }); assert.equal(before.status,200);
  const changed = await request(identityBase,route,{ method:'PUT',token,headers:{ 'If-Match':`"od-role-activation:license-manager:${before.body.version}"` },
    body:{ required,maxDurationSeconds:maximum,reason:'Reviewed mandatory license management activation',acknowledgeInvalidation:true } });
  assert.equal(changed.status,200); return changed.body;
}
test('mandatory activation uses real MFA duties, revokes old cross-client authority and permits only a current approved bounded license operator', async () => {
  const manager = await firstRoleFactor('pim-policy-manager'); const reader = await issue('pim-policy-reader');
  const owner = await configureFactor('pim-policy-owner',await issue('pim-policy-owner')); const omitted = await issue('pim-policy-owner','openid');
  const policyRoute = '/api/identity/pim/policies/license-manager';
  assert.equal((await request(identityBase,'/api/users',{ token:manager.access_token })).status,403);
  assert.equal((await request(identityBase,pimBase+'/eligibilities',{ method:'POST',token:manager.access_token,body:{} })).status,403);
  assert.equal((await request(identityBase,policyRoute,{ token:reader.access_token })).body.canManage,false);
  assert.equal((await request(identityBase,policyRoute,{ method:'PUT',token:reader.access_token,body:{} })).status,403);
  const administrator = await issue(); const client = await registerApplication(administrator.access_token,{ grantTypes:['authorization_code','refresh_token','urn:ietf:params:oauth:grant-type:device_code'] },false);
  for (const username of ['pim-policy-owner','pim-policy-pending']) {
    assert.equal((await applicationGrant(client,administrator.access_token,'user',canonicalSubjects.get(username))).status,201);
  }
  const alternate = await issueForApplication(client,'pim-policy-owner');
  const pendingLogin = await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:client.clientId,redirect_uri:client.redirectUris[0],username:'pim-policy-pending',password:'disposable-password',scope:'openid roles' } });
  assert.equal(pendingLogin.status,302); const code = new URL(pendingLogin.headers.get('location')).searchParams.get('code');
  const device = await request(issuerBase,'/oauth/device/code',{ method:'POST',body:{ client_id:client.clientId,client_secret:client.clientSecret,scope:'openid roles' } }); assert.equal(device.status,200);
  assert.equal((await fetch(issuerBase+'/oauth/device/approve',{ method:'POST',headers:{ 'Content-Type':'application/json' },body:JSON.stringify({ user_code:device.body.user_code,username:'pim-policy-pending',password:'disposable-password' }) })).status,200);
  const eligibilityManager = await issue('pim-manager'); const reviewer = await issue('pim-reviewer');
  const eligibility = await request(identityBase,pimBase+'/eligibilities',{ method:'POST',token:eligibilityManager.access_token,
    body:{ userId:canonicalSubjects.get('pim-policy-owner'),role:'license-manager',maxDurationSeconds:3600,validForSeconds:86400,reason:'Independently approved eligible license operator' } }); assert.equal(eligibility.status,201);
  const prior = await request(identityBase,pimBase+'/requests',{ method:'POST',token:owner.access_token,body:{ id:randomUUID(),eligibilityId:eligibility.body.id,durationSeconds:3600,reason:'Prior independently reviewed license request' } }); assert.equal(prior.status,200);
  assert.equal((await request(identityBase,`${pimBase}/requests/${prior.body.id}/approve`,{ method:'POST',token:reviewer.access_token,body:{} })).body.status,'approved');
  const product = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Mandatory PIM actual pool',2) RETURNING id")).rows[0];
  const allocation = `/api/licenses/${product.id}/assign`; const body = { assignee_type:'user',assignee_id:canonicalSubjects.get('bob') };
  const before = payload(owner.access_token).identity_authorization;
  await changeActivationRule(manager.access_token,true);
  try {
    for (const token of [owner.access_token,omitted.access_token,alternate.access_token]) {
      for (const base of [issuerBase,gatewayBase,identityBase,policyBase,quickBase]) {
        const route = base===issuerBase?'/oauth/userinfo':base===gatewayBase?'/api/gateway/access':base===identityBase?'/api/identity/access':base===policyBase?'/api/licenses/access':'/api/quick/access';
        assert.equal((await request(base,route,{ token })).status,401);
      }
    }
    assert.equal((await renew(owner.refresh_token)).status,400);
    for(const grant of [{ grant_type:'authorization_code',code,redirect_uri:client.redirectUris[0] },{ grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:device.body.device_code }]) {
      const rejected=await request(issuerBase,'/oauth/token',{ method:'POST',body:{ ...grant,client_id:client.clientId,client_secret:client.clientSecret } });
      assert.equal(rejected.status,403); assert.equal(rejected.body.error,'identity_not_eligible'); assert.equal(rejected.body.access_token,undefined);
    }
    const current = await issue('pim-policy-owner'); const context = payload(current.access_token).identity_authorization;
    assert.equal(context.revision,before.revision); assert.notEqual(context.rolesRevision,before.rolesRevision); assert.ok(!payload(current.access_token).roles.includes('license-manager'));
    assert.equal((await request(gatewayBase,allocation,{ method:'POST',token:current.access_token,body })).status,403);
    assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[product.id])).rows[0].count,0);
    assert.equal((await request(identityBase,pimBase+'/self',{ token:current.access_token })).body.requests[0].status,'stale');
    const requestBody = { id:randomUUID(),eligibilityId:eligibility.body.id,durationSeconds:601,reason:'Current bounded license request' };
    assert.equal((await request(identityBase,pimBase+'/requests',{ method:'POST',token:current.access_token,body:requestBody })).status,409);
    requestBody.durationSeconds=600;
    const pending = await request(identityBase,pimBase+'/requests',{ method:'POST',token:current.access_token,body:requestBody }); assert.equal(pending.status,200);
    const activationRoute = `${pimBase}/requests/${pending.body.id}`;
    assert.equal((await request(identityBase,activationRoute+'/approve',{ method:'POST',token:current.access_token,body:{} })).status,403);
    assert.equal((await request(identityBase,activationRoute+'/approve',{ method:'POST',token:reviewer.access_token,body:{} })).body.status,'approved');
    const active = await request(identityBase,activationRoute+'/activate',{ method:'POST',token:current.access_token,body:{} }); assert.equal(active.body.status,'active');
    const operator = await issue('pim-policy-owner'); assert.ok(payload(operator.access_token).roles.includes('license-manager'));
    assert.equal((await request(gatewayBase,allocation,{ method:'POST',token:operator.access_token,body })).status,201);
    await changeActivationRule(manager.access_token,true,300);
    assert.equal((await request(policyBase,allocation,{ method:'POST',token:operator.access_token,body })).status,401);
    assert.equal((await renew(operator.refresh_token)).status,400);
  } finally { await changeActivationRule(manager.access_token,false,28800); }
  const after = await issue('pim-policy-owner'); assert.ok(!payload(after.access_token).roles.includes('license-manager'));
  assert.equal((await request(gatewayBase,allocation,{ method:'POST',token:after.access_token,body })).status,403);
});
test('a real issuer revocation inside policy audit DML rolls back a previously admitted policy write', async () => {
  const manager = await issue('pim-policy-manager'); const route='/api/identity/pim/policies/license-manager';
  const before = await request(identityBase,route,{ token:manager.access_token }); assert.equal(before.status,200);
  const gate = 'activation-final-authority-'+randomUUID(); const blocker=await identityDb.pool.connect(); let pending;
  await identityDb.query(`CREATE FUNCTION pause_activation_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); RETURN NEW; END $$`);
  await identityDb.query('CREATE TRIGGER pause_activation_evidence BEFORE INSERT ON identity_role_activation_audit FOR EACH ROW EXECUTE FUNCTION pause_activation_evidence()');
  await blocker.query('BEGIN'); await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
  try {
    pending=request(identityBase,route,{ method:'PUT',token:manager.access_token,headers:{ 'If-Match':`"od-role-activation:license-manager:${before.body.version}"` },
      body:{ required:true,maxDurationSeconds:600,reason:'Final actual issuer revocation must roll back',acknowledgeInvalidation:true } });
    for(let attempt=0;attempt<100;attempt++) {
      const waiting=await identityDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE identity_role_activation_policies SET activation_required=%'");
      if(waiting.rows.length)break;
      if(attempt===99)throw new Error('No live activation audit waiter observed');
      await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.equal((await revoke(manager.access_token)).status,200);
    await blocker.query('ROLLBACK'); assert.equal((await pending).status,401);
  } finally {
    await blocker.query('ROLLBACK'); blocker.release(); if(pending)await pending.catch(()=>{});
    await identityDb.query('DROP TRIGGER pause_activation_evidence ON identity_role_activation_audit');
  }
  const stored=(await identityDb.query("SELECT version,activation_required FROM identity_role_activation_policies WHERE role='license-manager'")).rows[0];
  assert.equal(stored.version,before.body.version); assert.equal(stored.activation_required,false);
});

test('named fresh-MFA PIM reviewers can independently activate a global administrator after mandatory policy removes every prior admin grant',async()=>{
  let administrator=await issue(); if(!provenMfa(payload(administrator.access_token)))administrator=await configureFactor('operator',administrator);
  let reviewer=await issue('pim-reviewer'); const owner=await issue('pim-policy-owner'); const stranger=await issue('pim-policy-foreign-reviewer');
  const eligibility=await request(identityBase,pimBase+'/eligibilities',{ method:'POST',token:administrator.access_token,
    body:{ userId:canonicalSubjects.get('pim-policy-owner'),role:'admin',maxDurationSeconds:600,validForSeconds:86400,reason:'Independent eligible global role before mandatory policy' } }); assert.equal(eligibility.status,201);
  const route='/api/identity/pim/policies/admin'; const before=await request(identityBase,route,{ token:administrator.access_token }); assert.equal(before.status,200);
  const changed=await request(identityBase,route,{ method:'PUT',token:administrator.access_token,headers:{ 'If-Match':`"od-role-activation:admin:${before.body.version}"` },
    body:{ required:true,maxDurationSeconds:600,reviewerUserIds:[canonicalSubjects.get('pim-reviewer')],reason:'Explicit independently reviewed global activation policy',acknowledgeInvalidation:true } }); assert.equal(changed.status,200);
  let currentAdmin;
  try {
    assert.equal((await request(identityBase,'/api/users',{ token:administrator.access_token })).status,401);
    const pending=await request(identityBase,pimBase+'/requests',{ method:'POST',token:owner.access_token,body:{ id:randomUUID(),eligibilityId:eligibility.body.id,durationSeconds:600,reason:'Current independently approved global role activation' } }); assert.equal(pending.status,200);
    const requestPath=`${pimBase}/requests/${pending.body.id}`;
    assert.equal((await request(identityBase,requestPath+'/approve',{ method:'POST',token:stranger.access_token,body:{} })).status,403);
    if(!provenMfa(payload(reviewer.access_token))) {
      assert.equal((await request(identityBase,requestPath+'/approve',{ method:'POST',token:reviewer.access_token,body:{} })).status,428);
      reviewer=await configureFactor('pim-reviewer',reviewer);
    }
    assert.equal((await request(identityBase,requestPath+'/approve',{ method:'POST',token:reviewer.access_token,body:{} })).body.status,'approved');
    assert.equal((await request(identityBase,requestPath+'/activate',{ method:'POST',token:owner.access_token,body:{} })).body.status,'active');
    currentAdmin=await issue('pim-policy-owner'); assert.ok(payload(currentAdmin.access_token).roles.includes('admin'));
    assert.equal((await request(identityBase,'/api/users',{ token:currentAdmin.access_token })).status,200);
    const decision=(await identityDb.query('SELECT decision_authority FROM identity_pim_requests WHERE id=$1',[pending.body.id])).rows[0].decision_authority;
    assert.equal(decision.reviewerAuthentication.authTime,payload(reviewer.access_token).auth_time);
    assert.ok(decision.reviewerAuthentication.factorRevision);
  } finally {
    if(currentAdmin) {
      const restored=await request(identityBase,route,{ method:'PUT',token:currentAdmin.access_token,headers:{ 'If-Match':`"od-role-activation:admin:${changed.body.version}"` },
        body:{ required:false,maxDurationSeconds:28800,reviewerUserIds:[],reason:'Reviewed isolated global policy restoration',acknowledgeInvalidation:true } }); assert.equal(restored.status,200);
    } else {
      await identityDb.transaction(async client=>{
        await client.query("SELECT set_config('opendirectory.activation_reason','Isolated test-owner recovery of global policy',true)");
        await client.query("UPDATE identity_role_activation_policies SET activation_required=false,max_duration_seconds=28800,reviewer_user_ids='{}',version=version+1 WHERE role='admin'");
      },{ actor:'isolated-test-owner' });
    }
  }
  assert.equal((await request(identityBase,'/api/users',{ token:currentAdmin.access_token })).status,401);
  assert.ok(!payload((await issue('operator')).access_token).roles.includes('admin'));
});

async function reviewCredential(name) {
  if(!reviewFactors.has(name)) { const pair=await firstRoleFactor(name); reviewFactors.add(name); return pair; }
  return issue(name);
}
async function reviewBootstrap(name,role) {
  return require('../../../identity-service/scripts/bootstrap-role').bootstrapRole(identityDb,{ userId:canonicalSubjects.get(name),role,duration:3600,reason:'Explicit owned fixture entitlement for actual review' });
}
async function cleanupReviewScope(role) {
  await identityDb.transaction(async client=>{
    await client.query("SELECT set_config('opendirectory.review_reason','Owned test review cleanup without resurrection',true)");
    await client.query('UPDATE identity_role_review_policies SET retired_at=identity_role_review_now(),version=version+1 WHERE role=$1 AND retired_at IS NULL',[role]);
    await client.query(`UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND id IN
      (SELECT lease.target_id FROM identity_role_review_leases lease JOIN identity_role_review_policies policy ON policy.id=lease.policy_id WHERE policy.role=$1 AND lease.target_kind='assignment')`,[role]);
    await client.query(`UPDATE identity_pim_eligibilities SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND id IN
      (SELECT lease.target_id FROM identity_role_review_leases lease JOIN identity_role_review_policies policy ON policy.id=lease.policy_id WHERE policy.role=$1 AND lease.target_kind='eligibility')`,[role]);
  },{ actor:'isolated-review-fixture-owner' });
  await identityDb.query('CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
}
test('real role review MFA, recurrence and unanswered cutoffs govern actual license administration at every receiver',async()=>{
  const manager=await reviewCredential('review-config'); const reviewer=await reviewCredential('review-voter'); const reader=await issue('review-reader');
  const grant=await reviewBootstrap('review-target','license-manager'); const original=await issue('review-target');
  const pending=await request(issuerBase,'/oauth/authorize/login',{ method:'POST',body:{ client_id:clientId,redirect_uri:'http://localhost:4000/callback',username:'review-target',password:'disposable-password',scope:'openid roles' } }); assert.equal(pending.status,302);
  const code=new URL(pending.headers.get('location')).searchParams.get('code'); const route='/api/identity/reviews';
  const configured=await request(identityBase,route+'/policies',{ method:'POST',token:manager.access_token,body:{ role:'license-manager',intervalSeconds:3600,windowSeconds:60,reviewerUserIds:[canonicalSubjects.get('review-voter')],reason:'Actual recurring license administrator recertification',acknowledgeDeadlines:true } }); assert.equal(configured.status,201);
  try {
    assert.equal((await request(identityBase,'/api/users',{ token:manager.access_token })).status,403);
    assert.equal((await request(identityBase,route+'/policies',{ method:'POST',token:reviewer.access_token,body:{} })).status,403);
    const old=await request(issuerBase,'/oauth/token',{ method:'POST',body:{ grant_type:'authorization_code',code,client_id:clientId,client_secret:clientSecret,redirect_uri:'http://localhost:4000/callback' } }); assert.equal(old.body.error,'identity_not_eligible'); assert.equal(old.body.access_token,undefined);
    assert.equal((await renew(original.refresh_token)).status,400);
    const queue=await request(identityBase,route+'/self',{ token:reviewer.access_token }); assert.equal(queue.status,200);
    const review=queue.body.reviews.find(row=>row.targetId===grant.id); assert.ok(review); assert.equal(review.canDecide,true);
    assert.equal((await request(identityBase,route+'/'+review.id,{ token:reader.access_token })).body.canDecide,false);
    assert.equal((await request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:reader.access_token,body:{} })).status,403);
    const current=await issue('review-target'); assert.ok(payload(current.access_token).roles.includes('license-manager'));
    const pool=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Review-governed actual license authority',2) RETURNING id")).rows[0];
    const allocation=`/api/licenses/${pool.id}/assign`; const body={ assignee_type:'user',assignee_id:canonicalSubjects.get('bob') };
    assert.equal((await request(gatewayBase,allocation,{ method:'POST',token:current.access_token,body })).status,201);
    const retain=await request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:reviewer.access_token,headers:{ 'If-Match':`"od-role-review:${review.id}:${review.version}:${review.policyVersion}"` },body:{ decision:'retain',reason:'Actual independent recurring access confirmation',acknowledgeScope:true } });
    assert.equal(retain.status,200); assert.equal(retain.body.state,'scheduled'); assert.equal(retain.body.cycle,'2');
    assert.equal((await identityDb.query('SELECT expires_at FROM identity_role_assignments WHERE id=$1',[grant.id])).rows[0].expires_at.toISOString(),new Date(grant.expires_at).toISOString());
    assert.equal((await request(issuerBase,'/oauth/userinfo',{ token:current.access_token })).status,401);
    const retained=await issue('review-target'); assert.equal((await request(policyBase,'/api/licenses/access',{ token:retained.access_token })).status,200);
    await identityDb.query("CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3661 seconds'; $$");
    for(const [base,path] of [[issuerBase,'/oauth/userinfo'],[gatewayBase,'/api/gateway/access'],[identityBase,'/api/identity/access'],[policyBase,'/api/licenses/access'],[quickBase,'/api/quick/access']])assert.equal((await request(base,path,{ token:retained.access_token })).status,401);
    assert.equal((await renew(retained.refresh_token)).status,400);
    const expired=await request(identityBase,route+'/'+review.id,{ token:reviewer.access_token }); assert.equal(expired.body.state,'expired');
    const without=await issue('review-target'); assert.ok(!payload(without.access_token).roles.includes('license-manager'));
    assert.equal((await request(policyBase,allocation,{ method:'POST',token:without.access_token,body })).status,403);
    assert.equal((await policyDb.query('SELECT COUNT(*)::int AS count FROM license_assignments WHERE license_id=$1',[pool.id])).rows[0].count,1);
    const retired=await request(identityBase,route+'/policies/'+configured.body.id+'/retire',{ method:'POST',token:manager.access_token,headers:{ 'If-Match':configured.headers.get('etag') },body:{ reason:'Retirement must not restore late administrator authority',acknowledgeDeadlines:true } }); assert.equal(retired.status,200);
    assert.ok(!payload((await issue('review-target')).access_token).roles.includes('license-manager'));
  } finally { await cleanupReviewScope('license-manager'); }
});
test('global administrators have no self-review bypass and only explicitly named real-MFA peers can retain protected grants',async()=>{
  const manager=await reviewCredential('review-config'); const voter=await reviewCredential('review-voter-two'); const outsider=await reviewCredential('review-voter');
  const grant=await reviewBootstrap('operator','admin'); let administrator=await issue(); if(!provenMfa(payload(administrator.access_token)))administrator=await configureFactor('operator',administrator);
  const route='/api/identity/reviews'; const input={ role:'admin',intervalSeconds:3600,windowSeconds:300,reviewerUserIds:[canonicalUser,canonicalSubjects.get('review-voter-two')].sort(),reason:'Independent named global administrator review',acknowledgeDeadlines:true };
  assert.equal((await request(identityBase,route+'/policies',{ method:'POST',token:manager.access_token,body:input })).status,403);
  const configured=await request(identityBase,route+'/policies',{ method:'POST',token:administrator.access_token,body:input }); assert.equal(configured.status,201);
  try {
    administrator=await issue(); const own=await request(identityBase,route+'/self',{ token:administrator.access_token }); const review=own.body.reviews.find(row=>row.targetId===grant.id); assert.ok(review); assert.equal(review.selfReview,true); assert.equal(review.canDecide,false);
    const decision={ decision:'retain',reason:'Actual independently reviewed global administration',acknowledgeScope:true }; const headers={ 'If-Match':`"od-role-review:${review.id}:${review.version}:${review.policyVersion}"` };
    assert.equal((await request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:administrator.access_token,headers,body:decision })).status,403);
    assert.equal((await request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:outsider.access_token,headers,body:decision })).status,404);
    const retained=await request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:voter.access_token,headers,body:decision }); assert.equal(retained.status,200); assert.equal(retained.body.state,'scheduled');
    assert.equal((await request(identityBase,'/api/users',{ token:administrator.access_token })).status,401);
    administrator=await issue(); assert.equal((await request(identityBase,'/api/users',{ token:administrator.access_token })).status,200);
  } finally { await cleanupReviewScope('admin'); }
});
test('a real issuer revocation during review audit DML rolls back its new cycle and decision evidence',async()=>{
  const manager=await reviewCredential('review-config'); const reviewer=await reviewCredential('review-voter'); const grant=await reviewBootstrap('review-directory-target','directory-reader');
  const route='/api/identity/reviews'; const policy=await request(identityBase,route+'/policies',{ method:'POST',token:manager.access_token,body:{ role:'directory-reader',intervalSeconds:3600,windowSeconds:300,reviewerUserIds:[canonicalSubjects.get('review-voter')],reason:'Final authority fence for accepted review evidence',acknowledgeDeadlines:true } }); assert.equal(policy.status,201);
  const queue=await request(identityBase,route+'/self',{ token:reviewer.access_token }); const review=queue.body.reviews.find(row=>row.targetId===grant.id); assert.ok(review);
  const gate='review-final-'+randomUUID(); const blocker=await identityDb.pool.connect(); let pending;
  await identityDb.query(`CREATE FUNCTION pause_role_review_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='retain' THEN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0)); END IF; RETURN NEW; END $$`);
  await identityDb.query('CREATE TRIGGER pause_role_review_audit BEFORE INSERT ON identity_role_review_audit FOR EACH ROW EXECUTE FUNCTION pause_role_review_audit()');
  await blocker.query('BEGIN'); await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
  try {
    pending=request(identityBase,route+'/'+review.id+'/decisions',{ method:'POST',token:reviewer.access_token,headers:{ 'If-Match':`"od-role-review:${review.id}:${review.version}:${review.policyVersion}"` },body:{ decision:'retain',reason:'A revoked live session cannot commit this review',acknowledgeScope:true } });
    for(let attempt=0;attempt<100;attempt++) {
      const waiting=await identityDb.query("SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'UPDATE identity_role_review_leases SET version=version+1,cycle=cycle+1,%'");
      if(waiting.rows.length)break; if(attempt===99)throw new Error('No live blocked review audit'); await new Promise(resolve=>setTimeout(resolve,10));
    }
    assert.equal((await revoke(reviewer.access_token)).status,200); await blocker.query('ROLLBACK'); assert.equal((await pending).status,401);
  } finally { await blocker.query('ROLLBACK'); blocker.release(); if(pending)await pending.catch(()=>{}); await identityDb.query('DROP TRIGGER pause_role_review_audit ON identity_role_review_audit'); await cleanupReviewScope('directory-reader'); }
  const stored=(await identityDb.query('SELECT version,cycle FROM identity_role_review_leases WHERE id=$1',[review.id])).rows[0]; assert.equal(stored.version,'1'); assert.equal(stored.cycle,'1');
  assert.equal((await identityDb.query("SELECT COUNT(*)::int AS count FROM identity_role_review_audit WHERE lease_id=$1 AND action='retain'",[review.id])).rows[0].count,0);
});

async function productionGlobalAdministrator(){await reviewBootstrap('production-global-admin','admin');let pair=await issue('production-global-admin');assert.ok(payload(pair.access_token).roles.includes('admin'),'The explicit new fixture grant must be genuinely active, not an old withdrawn administrator');if(!provenMfa(payload(pair.access_token)))pair=await configureFactor('production-global-admin',pair);return pair;}

async function withProductionGateway(operation) {
 const previousMode=process.env.NODE_ENV;const previousOrigins=process.env.CORS_ORIGIN;let production;
 try{
  process.env.NODE_ENV='production';process.env.CORS_ORIGIN='https://console.opendirectory.test, null, ';production=new Gateway({discover:false,enabledModules:['identity-service','policy-service','device-management']});production.server.listen(0,'127.0.0.1');return await operation(await listening(production.server));
 }finally{
  if(production){const closed=once(production.server,'close');production.stop();production.server.closeAllConnections();await closed;}
  if(previousMode===undefined)delete process.env.NODE_ENV;else process.env.NODE_ENV=previousMode;if(previousOrigins===undefined)delete process.env.CORS_ORIGIN;else process.env.CORS_ORIGIN=previousOrigins;
 }
}

test('production gateway isolates signed human UUID snapshots by canonical duty and tenant while ordinary users remain self only',async()=>{
 const duties=[['users','license-eligibility-reader'],['groups','license-group-reader'],['reviewers','license-review-administrator'],['scope-reviewers','license-delegation-review-administrator'],['delegates','license-scope-administrator'],['publication','policy-administrator']];
 const actors=new Map();
 for(const [name,role] of duties){
  const username='production-snapshot-'+name;const pair=await (MFA_LOCKED_ROLES.includes(role)?firstRoleFactor(username):issue(username));const claims=payload(pair.access_token);assert.equal(claims.actor_type,'user');assert.equal(claims.sub,username+'-subject');assert.equal(claims.identity_authorization.userId,canonicalSubjects.get(username));assert.ok(claims.roles.includes(role));assert.equal(claims.roles.includes('admin'),false);actors.set(name,pair);
 }
 const groupOperator=await issue('production-group-operator');const foreignOperator=await issue('production-foreign-group-operator');const member=canonicalSubjects.get('production-member');const foreign=canonicalSubjects.get('production-foreign-member');
 const homeTenant=(await identityDb.query("SELECT identity_tenant_id('user',$1) AS tenant_id",[member])).rows[0].tenant_id;assert.notEqual(homeTenant,separateTenant);assert.equal((await identityDb.query("SELECT identity_tenant_id('user',$1) AS tenant_id",[foreign])).rows[0].tenant_id,separateTenant);
 const ownGroup=await request(identityBase,'/api/groups',{method:'POST',token:groupOperator.access_token,body:{name:'Actual production home snapshot source'}});assert.equal(ownGroup.status,201,JSON.stringify(ownGroup.body));
 const foreignGroup=await request(identityBase,'/api/groups',{method:'POST',token:foreignOperator.access_token,body:{name:'Actual production foreign snapshot source'}});assert.equal(foreignGroup.status,201,JSON.stringify(foreignGroup.body));
 assert.equal((await groupRequest(identityBase,'/api/groups/'+ownGroup.body.id+'/members',{method:'POST',token:groupOperator.access_token,body:{userId:member}})).status,200);
 assert.equal((await groupRequest(identityBase,'/api/groups/'+foreignGroup.body.id+'/members',{method:'POST',token:foreignOperator.access_token,body:{userId:foreign}})).status,200);
 const ordinary=await issue('production-ordinary');const ordinaryId=canonicalSubjects.get('production-ordinary');assert.equal(payload(ordinary.access_token).identity_authorization.userId,ordinaryId);assert.deepEqual(payload(ordinary.access_token).roles,['user']);
 const administrator=await issue('operator');assert.equal(payload(administrator.access_token).identity_authorization.userId,canonicalUser);assert.ok(payload(administrator.access_token).roles.includes('admin'));
 const beforeRoles=(await identityDb.query('SELECT id,user_id,role,revoked_at FROM identity_role_assignments ORDER BY id')).rows;
 const frames=[
  {route:'license-users',duty:'users',own:member,foreign,fields:['schemaVersion','userId','revision','enabled','deleted']},
  {route:'license-groups',duty:'groups',own:ownGroup.body.id,foreign:foreignGroup.body.id},
  {route:'license-reviewers',duty:'reviewers',own:canonicalSubjects.get('license-review-voter'),foreign,fields:['schemaVersion','userId','enabled','linked','canReview']},
  {route:'license-scope-reviewers',duty:'scope-reviewers',own:canonicalSubjects.get('authority-review-voter'),foreign,fields:['schemaVersion','userId','enabled','linked','canReview']},
  {route:'license-activation-reviewers',duty:'delegates',own:canonicalSubjects.get('scope-pim-reviewer'),foreign,fields:['schemaVersion','userId','revision','enabled','linked','reviewRevision']},
  {route:'license-delegates',duty:'delegates',own:canonicalSubjects.get('pool-scope-operator'),foreign,fields:['schemaVersion','userId','revision','enabled','linked','delegationRevision']},
  {route:'policy-publication-actors',duty:'publication',own:canonicalSubjects.get('policy-config'),foreign,fields:['schemaVersion','userId','revision','enabled','linked','requestRevision','reviewRevision']},
 ];
 await withProductionGateway(async base=>{
  for(const frame of frames){
   const receiver=frame.route==='policy-publication-actors'?identityBase:base;const token=actors.get(frame.duty).access_token;const own=await request(receiver,'/api/'+frame.route+'/'+frame.own+'/snapshot',{token});assert.equal(own.status,200,frame.route+': '+JSON.stringify(own.body));assert.equal(own.headers.get('x-od-license-snapshot-protocol'),'1');assert.equal(own.headers.get('cache-control'),'no-store');
   if(frame.fields){assert.deepEqual(Object.keys(own.body).sort(),[...frame.fields].sort());assert.equal(own.body.userId,frame.own);assert.equal(own.body.enabled,true);}
   if(frame.route==='license-users'){assert.equal(own.body.schemaVersion,1);assert.equal(own.body.deleted,false);assert.equal(own.body.revision,(await identityDb.query('SELECT eligibility_revision FROM users WHERE id=$1',[frame.own])).rows[0].eligibility_revision);}
   if(frame.route==='license-groups'){assert.equal(own.body.schemaVersion,3);assert.equal(own.body.groupId,ownGroup.body.id);assert.deepEqual(own.body.memberIds,[member]);assert.equal(own.body.sourceAuthorization,null);assert.equal(own.body.viewerUserId,canonicalSubjects.get('production-snapshot-groups'));}
   if(frame.route==='license-reviewers'||frame.route==='license-scope-reviewers'){assert.equal(own.body.linked,true);assert.equal(own.body.canReview,true);}
   if(frame.route==='license-activation-reviewers')assert.match(own.body.reviewRevision,/^[a-f0-9]{64}$/);
   if(frame.route==='license-delegates')assert.match(own.body.delegationRevision,/^[a-f0-9]{64}$/);
   if(frame.route==='policy-publication-actors'){assert.match(own.body.requestRevision,/^[a-f0-9]{64}$/);assert.equal(own.body.reviewRevision,null);}
   for(const target of [frame.foreign,randomUUID()]){const hidden=await request(receiver,'/api/'+frame.route+'/'+target+'/snapshot',{token});assert.equal(hidden.status,404,frame.route+': '+JSON.stringify(hidden.body));assert.equal(hidden.body.userId,undefined);assert.equal(hidden.body.groupId,undefined);}
   assert.equal((await request(receiver,'/api/'+frame.route+'/'+frame.foreign+'/snapshot',{token:administrator.access_token})).status,404);
   for(const target of [frame.own,frame.foreign])assert.equal((await request(receiver,'/api/'+frame.route+'/'+target+'/snapshot',{token:ordinary.access_token})).status,403);
   assert.equal((await request(base,'/api/users',{token})).status,403);
  }
  for(const route of ['license-users','license-activation-reviewers','license-delegates']){
   const self=await request(base,'/api/'+route+'/'+ordinaryId+'/snapshot',{token:ordinary.access_token});assert.equal(self.status,200,JSON.stringify(self.body));assert.equal(self.body.userId,ordinaryId);assert.equal(self.body.enabled,true);assert.equal(self.headers.get('x-od-license-snapshot-protocol'),'1');
   if(route==='license-delegates')assert.equal(self.body.delegationRevision,null);if(route==='license-activation-reviewers')assert.equal(self.body.reviewRevision,null);
   assert.equal((await request(base,'/api/'+route+'/'+randomUUID()+'/snapshot',{token:ordinary.access_token})).status,403);
  }
  assert.equal((await request(base,'/api/users',{token:ordinary.access_token})).status,403);assert.equal((await request(base,'/api/identity/roles/catalog',{token:ordinary.access_token})).status,403);
 });
 assert.deepEqual((await identityDb.query('SELECT id,user_id,role,revoked_at FROM identity_role_assignments ORDER BY id')).rows,beforeRoles);
});

test('production gateway admits originless liveness and accurate bearer documentation without granting browser access',async()=>{
 await withProductionGateway(async base=>{
  const health=await request(base,'/health');assert.equal(health.status,200);assert.deepEqual(health.body,{status:'ok',service:'api-gateway'});assert.equal(health.headers.get('access-control-allow-origin'),null);assert.equal(health.headers.get('access-control-allow-credentials'),null);
  const docs=await request(base,'/docs');assert.equal(docs.status,200);assert.deepEqual(docs.body.authentication.types,['OIDC Bearer access token']);assert.equal(docs.body.authentication['api-key-example'],undefined);assert.equal(docs.body['rate-limits'].authenticated,'1000 requests per 15 minutes');
  assert.equal(docs.body.endpoints.public.services,undefined);assert.equal(docs.body.endpoints.protected.services,'/api/services');const spec=await request(base,'/docs/openapi.json');assert.equal(spec.status,200);assert.deepEqual(spec.body.components.securitySchemes,{BearerAuth:{type:'http',scheme:'bearer'}});assert.deepEqual(spec.body.security,[{BearerAuth:[]}]);assert.deepEqual(spec.body.paths['/health'].get.security,[]);assert.equal((await request(base,'/api/services')).status,401);
 });
});

test('production gateway originless group writes reach actual original-actor receivers with unchanged namespace and exact versions',async()=>{
 const operator=await issue('production-group-operator');await withProductionGateway(async base=>{
  const created=await request(base,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Production transport actual canonical group'}});assert.equal(created.status,201,JSON.stringify(created.body));const route='/api/groups/'+created.body.id;const version=created.headers.get('etag');assert.equal(version,`"group-${created.body.id}-${created.body.revision}"`);assert.equal(created.headers.get('access-control-allow-origin'),null);
  const found=await request(base,route,{token:operator.access_token});assert.equal(found.status,200);assert.equal(found.headers.get('etag'),version);assert.equal(found.headers.get('cache-control'),'no-store');
  assert.equal((await request(base,route,{method:'PUT',token:operator.access_token,body:{description:'No version'}})).status,428);
  const updated=await request(base,route,{method:'PUT',token:operator.access_token,headers:{'If-Match':version},body:{description:'Actual production-mode conditional write'}});assert.equal(updated.status,200,JSON.stringify(updated.body));assert.notEqual(updated.headers.get('etag'),version);
  assert.equal((await request(base,route,{method:'DELETE',token:operator.access_token,headers:{'If-Match':version}})).status,412);
  const member=canonicalSubjects.get('production-member');const added=await request(base,route+'/members',{method:'POST',token:operator.access_token,headers:{'If-Match':updated.headers.get('etag')},body:{userId:member}});assert.equal(added.status,200,JSON.stringify(added.body));assert.deepEqual(added.body.members,[member]);
  const removed=await request(base,route+'/members/'+member,{method:'DELETE',token:operator.access_token,headers:{'If-Match':added.headers.get('etag')}});assert.equal(removed.status,200);assert.deepEqual(removed.body.members,[]);
  assert.equal((await request(base,route,{method:'DELETE',token:operator.access_token,headers:{'If-Match':removed.headers.get('etag')}})).status,204);
  const evidence=(await identityDb.query('SELECT action,actor FROM identity_directory_group_events WHERE group_id=$1 ORDER BY created_at',[created.body.id])).rows;assert.deepEqual(evidence.map(event=>event.action),['update','member-add','member-remove','delete']);assert.equal(evidence.every(event=>event.actor.userId===canonicalSubjects.get('production-group-operator')),true);
 });
});

test('production gateway originless headers and retired credentials cannot replace canonical bearer purpose or receiving permissions',async()=>{
 const administrator=await issue('production-group-operator');const ordinary=await issue('production-ordinary');const created=await request(identityBase,'/api/groups',{method:'POST',token:administrator.access_token,body:{name:'Production admission negative group'}});assert.equal(created.status,201);const route='/api/groups/'+created.body.id;const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];
 await withProductionGateway(async base=>{
  for(const headers of[{}, {'X-Client-Type':'frontend','X-User-Roles':'admin'},{'X-Service-Auth':'legacy','X-Service-Name':'identity-service'},{'X-API-Key':'legacy'},{Authorization:'Bearer forged'},{Authorization:'Basic retired'},{Cookie:'token='+administrator.access_token},{Authorization:'Bearer '+administrator.id_token}]){
   const response=await request(base,route,{headers});assert.equal(response.status,401);assert.equal(response.headers.get('www-authenticate'),'Bearer');assert.equal(response.headers.get('access-control-allow-origin'),null);
  }
  assert.equal((await request(base,route,{token:administrator.access_token,headers:{'X-API-Key':'legacy'}})).status,401);
  assert.equal((await request(base,route,{method:'PUT',token:ordinary.access_token,headers:{'If-Match':created.headers.get('etag')},body:{description:'No receiving permission'}})).status,403);
 });
 assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,0);
});

test('production gateway browser origins retain exact CORS preflight and ETag exposure without cookie or origin authorization',async()=>{
 const operator=await issue('production-group-operator');const group=await request(identityBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Production browser ETag confirmation'}});assert.equal(group.status,201);await withProductionGateway(async base=>{
  const headers={Origin:'https://console.opendirectory.test'};const preflight=await fetch(base+'/api/groups',{method:'OPTIONS',headers:{...headers,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization,content-type,if-match'}});assert.equal(preflight.status,204);assert.equal(preflight.headers.get('access-control-allow-origin'),headers.Origin);assert.equal(preflight.headers.get('access-control-allow-credentials'),'true');assert.ok(preflight.headers.get('access-control-allow-headers').toLowerCase().includes('if-match'));
  const found=await request(base,'/api/groups/'+group.body.id,{token:operator.access_token,headers});assert.equal(found.status,200);assert.equal(found.headers.get('etag'),group.headers.get('etag'));assert.equal(found.headers.get('access-control-allow-origin'),headers.Origin);assert.ok(found.headers.get('access-control-expose-headers').toLowerCase().split(/,\s*/).includes('etag'));assert.ok(found.headers.get('vary').includes('Origin'));
  assert.equal((await request(base,'/api/groups',{headers:{...headers,Cookie:'token='+operator.access_token}})).status,401);
  for(const origin of['','null','https://console.opendirectory.test.evil.test','http://console.opendirectory.test','https://console.opendirectory.test:444']){
   const denied=await request(base,'/api/groups',{token:operator.access_token,headers:{Origin:origin}});assert.equal(denied.status,403);assert.equal(denied.headers.get('access-control-allow-origin'),null);
   const rejected=await fetch(base+'/api/groups',{method:'OPTIONS',headers:{Origin:origin,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization'}});assert.equal(rejected.status,403);assert.equal(rejected.headers.get('access-control-allow-origin'),null);
  }
 });
});

test('production gateway originless global administration still cannot read or mutate a coherent foreign tenant group',async()=>{
 const own=await productionGlobalAdministrator();const foreign=await issue('production-foreign-group-operator');const created=await request(identityBase,'/api/groups',{method:'POST',token:foreign.access_token,body:{name:'Production coherent foreign tenant group'}});assert.equal(created.status,201);const route='/api/groups/'+created.body.id;const member=canonicalSubjects.get('production-foreign-member');const linked=await groupRequest(identityBase,route+'/members',{method:'POST',token:foreign.access_token,body:{userId:member}});assert.equal(linked.status,200);const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];const evidence=(await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count;
 await withProductionGateway(async base=>{
  assert.equal((await request(base,route,{token:own.access_token})).status,404);const headers={'If-Match':linked.headers.get('etag')};for(const[method,path,body]of[['PUT',route,{description:'No foreign overwrite'}],['POST',route+'/members',{userId:canonicalSubjects.get('production-foreign-extra')}],['DELETE',route+'/members/'+member],['DELETE',route]])assert.equal((await request(base,path,{method,token:own.access_token,headers,...(body?{body}:{})})).status,404);
 });
 assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,evidence);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1 AND user_id=$2',[created.body.id,member])).rows[0].count,1);
});

test('production gateway originless original withdrawal and issuer outage fail closed without changing directory state',async()=>{
 const operator=await issue('production-group-operator');const created=await request(identityBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Production live state fence'}});assert.equal(created.status,201);const route='/api/groups/'+created.body.id;const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];
 await withProductionGateway(async base=>{
  await issuerDb.query('ALTER TABLE oauth_token_revocations RENAME TO unavailable_production_revocations');try{assert.equal((await request(base,route,{token:operator.access_token})).status,503);assert.equal((await request(base,route,{method:'PUT',token:operator.access_token,headers:{'If-Match':created.headers.get('etag')},body:{description:'Unavailable authority cannot admit a write'}})).status,503);}finally{await issuerDb.query('ALTER TABLE unavailable_production_revocations RENAME TO oauth_token_revocations');}
  assert.equal((await request(base,route,{token:operator.access_token})).status,200);assert.equal((await revoke(operator.access_token)).status,200);assert.equal((await request(base,route,{token:operator.access_token})).status,401);assert.equal((await request(base,route,{method:'PUT',token:operator.access_token,headers:{'If-Match':created.headers.get('etag')},body:{description:'Withdrawn bearer cannot admit a write'}})).status,401);
 });
 assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,0);
});

test('production gateway original revocation during actual group audit DML rolls back the admitted conditional write',async()=>{
 const operator=await issue('production-group-operator');const created=await request(identityBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Production final original-actor fence'}});assert.equal(created.status,201);const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];const gate='production-group-final-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;
 await identityDb.query(`CREATE FUNCTION pause_production_group_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));RETURN NEW;END;$$;CREATE TRIGGER pause_production_group_evidence BEFORE INSERT ON identity_directory_group_events FOR EACH ROW EXECUTE FUNCTION pause_production_group_evidence()`);
 try{await withProductionGateway(async base=>{
  await blocker.query('BEGIN');await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);pending=request(base,'/api/groups/'+created.body.id,{method:'PUT',token:operator.access_token,headers:{'If-Match':created.headers.get('etag')},body:{description:'Actual write must retain original authority'}});pending.catch(()=>{});let waiting=false;for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND query LIKE 'SELECT identity_directory_group_finish%') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true,'Actual production proxy receiving evidence wait required');assert.equal((await revoke(operator.access_token)).status,200);await blocker.query('COMMIT');assert.equal((await pending).status,401);
 });}finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});await identityDb.query('DROP TRIGGER pause_production_group_evidence ON identity_directory_group_events;DROP FUNCTION pause_production_group_evidence()');}
 assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,0);
});

test('production gateway cannot restore withdrawn group authority by issuing a new token or trusting original administrator labels',async()=>{
 const name='production-withdrawn-operator';const original=await issue(name);assert.ok(payload(original.access_token).roles.includes('group-administrator'));const userId=canonicalSubjects.get(name);await withProductionGateway(async base=>{
  const admitted=await request(base,'/api/groups',{method:'POST',token:original.access_token,body:{name:'Explicit current production group authority'}});assert.equal(admitted.status,201);
  await identityDb.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='group-administrator' AND revoked_at IS NULL",[userId],'Explicit independent production fixture authority withdrawal');
  assert.equal((await request(base,'/api/groups',{method:'POST',token:original.access_token,body:{name:'Old token cannot retain authority'}})).status,401);const fresh=await issue(name);assert.ok(!payload(fresh.access_token).roles.includes('group-administrator'));
  const denied=await request(base,'/api/groups',{method:'POST',token:fresh.access_token,headers:{'X-User-Roles':'admin','X-Client-Type':'frontend'},body:{name:'New token is not a new grant'}});assert.equal(denied.status,403);
 });assert.equal((await identityDb.query("SELECT count(*)::int AS count FROM groups WHERE name IN ('Old token cannot retain authority','New token is not a new grant')")).rows[0].count,0);
});

test('production gateway cannot fabricate a successful write when the actual group receiver guard is missing',async()=>{
 const operator=await issue('production-group-operator');const created=await request(identityBase,'/api/groups',{method:'POST',token:operator.access_token,body:{name:'Production missing receiver guard'}});assert.equal(created.status,201);const before=(await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0];await identityDb.query('ALTER TABLE groups DISABLE TRIGGER aaa_identity_directory_group_mutation');
 try{await withProductionGateway(async base=>{const response=await request(base,'/api/groups/'+created.body.id,{method:'PUT',token:operator.access_token,headers:{'If-Match':created.headers.get('etag')},body:{description:'Missing receiver admission cannot succeed'}});assert.equal(response.status,403);assert.equal(response.body.id,undefined);});}finally{await identityDb.query('ALTER TABLE groups ENABLE TRIGGER aaa_identity_directory_group_mutation');}
 assert.deepEqual((await identityDb.query('SELECT * FROM groups WHERE id=$1',[created.body.id])).rows[0],before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_group_events WHERE group_id=$1',[created.body.id])).rows[0].count,0);
});

test('production gateway fences actual foreign role and PIM sources even under global administration',async()=>{
 const administrator=await productionGlobalAdministrator();const operator=await issue('production-role-operator');const pimOperator=await issue('production-pim-operator');
 await reviewBootstrap('production-foreign-authority-admin','admin');const foreign=await issue('production-foreign-authority-admin');assert.ok(payload(foreign.access_token).roles.includes('admin'));
 const foreignUser=canonicalSubjects.get('production-foreign-member');const foreignPimUser=canonicalSubjects.get('production-foreign-extra');const ownUser=canonicalSubjects.get('production-member');
 const reason='Actual original signed authority target verification';const body={role:'license-manager',durationSeconds:300,reason};
 const grant=await request(identityBase,'/api/users/'+foreignUser+'/roles',{method:'POST',token:foreign.access_token,body});assert.equal(grant.status,201);
 const eligible=await request(identityBase,'/api/identity/pim/eligibilities',{method:'POST',token:foreign.access_token,body:{userId:foreignPimUser,role:'license-manager',maxDurationSeconds:300,validForSeconds:3600,reason}});assert.equal(eligible.status,201);
 const foreignOwner=await issue('production-foreign-extra');const pending=await request(identityBase,'/api/identity/pim/requests',{method:'POST',token:foreignOwner.access_token,body:{id:randomUUID(),eligibilityId:eligible.body.id,durationSeconds:300,reason}});assert.equal(pending.status,200);
 const before=(await identityDb.query(`SELECT (SELECT count(*)::int FROM identity_role_audit) AS roles,(SELECT count(*)::int FROM identity_pim_audit) AS pim`)).rows[0];
 await withProductionGateway(async base=>{
  for(const pair of [administrator,operator]){
   assert.equal((await request(base,'/api/users/'+foreignUser+'/roles',{method:'POST',token:pair.access_token,body})).status,404);
   assert.equal((await request(base,'/api/users/'+foreignUser+'/roles/'+grant.body.id,{method:'DELETE',token:pair.access_token})).status,404);
  }
  assert.equal((await request(base,'/api/identity/pim/eligibilities?userId='+foreignPimUser,{token:administrator.access_token})).status,404);
  for(const pair of [administrator,pimOperator]){
   assert.equal((await request(base,'/api/identity/pim/eligibilities',{method:'POST',token:pair.access_token,body:{userId:foreignPimUser,role:'license-manager',maxDurationSeconds:300,validForSeconds:3600,reason}})).status,404);
   assert.equal((await request(base,'/api/identity/pim/eligibilities/'+eligible.body.id,{method:'DELETE',token:pair.access_token})).status,404);
  }
  for(const action of ['approve','deny','activate','cancel','revoke'])assert.equal((await request(base,'/api/identity/pim/requests/'+pending.body.id+'/'+action,{method:'POST',token:administrator.access_token})).status,404);
  const queue=await request(base,'/api/identity/pim/requests',{token:administrator.access_token});assert.equal(queue.status,200);assert.ok(queue.body.requests.every(item=>item.userId!==foreignPimUser));
  assert.deepEqual((await identityDb.query(`SELECT (SELECT count(*)::int FROM identity_role_audit) AS roles,(SELECT count(*)::int FROM identity_pim_audit) AS pim`)).rows[0],before);
  const ownGrant=await request(base,'/api/users/'+ownUser+'/roles',{method:'POST',token:operator.access_token,body});assert.equal(ownGrant.status,201);
  const held=await issue('production-member');const access=await request(policyBase,'/api/licenses/access',{token:held.access_token});assert.equal(access.status,200);assert.ok(access.body.permissions.includes('licenses.assignments.manage'));
  assert.equal((await request(base,'/api/users/'+ownUser+'/roles/'+ownGrant.body.id,{method:'DELETE',token:operator.access_token})).status,200);
  assert.equal((await request(policyBase,'/api/licenses/access',{token:held.access_token})).status,401);const fresh=await issue('production-member');assert.ok(!(await request(policyBase,'/api/licenses/access',{token:fresh.access_token})).body.permissions.includes('licenses.assignments.manage'));
 });
 assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1',[grant.body.id])).rows[0].revoked_at,null);
 assert.equal((await identityDb.query('SELECT state FROM identity_pim_requests WHERE id=$1',[pending.body.id])).rows[0].state,'pending');
});

test('production gateway refuses a role mutation if any required authority target receiving guard is absent',async()=>{
 const operator=await issue('production-role-operator');const userId=canonicalSubjects.get('production-member');const before=(await identityDb.query('SELECT count(*)::int AS count FROM identity_role_audit WHERE user_id=$1',[userId])).rows[0].count;
 await identityDb.query('ALTER TABLE identity_pim_requests DISABLE TRIGGER aaa_identity_authority_target_tenant');
 try{await withProductionGateway(async base=>{
  const result=await request(base,'/api/users/'+userId+'/roles',{method:'POST',token:operator.access_token,body:{role:'license-manager',durationSeconds:300,reason:'Missing canonical authority receiving guard must fail closed'}});
  assert.equal(result.status,503);assert.equal(result.body.id,undefined);
 });}finally{await identityDb.query('ALTER TABLE identity_pim_requests ENABLE TRIGGER aaa_identity_authority_target_tenant');}
 assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_audit WHERE user_id=$1',[userId])).rows[0].count,before);
});

async function commandEvidence(){
 const result={};for(const[table,order]of [['users','id'],['identity_role_assignments','id'],['identity_role_audit','id'],['identity_pim_eligibilities','id'],['identity_pim_requests','id'],['identity_pim_audit','id'],['identity_role_authentication','role'],['identity_role_authentication_audit','id'],['identity_role_review_leases','id'],['identity_role_review_audit','id']])result[table]=(await identityDb.query('SELECT * FROM '+table+' ORDER BY '+order)).rows;return result;
}
async function prepareAuthorityCommand(kind){
 const username='production-command-'+kind;const target=canonicalSubjects.get(username);const reason='Actual original bearer must survive authority command DML';
 if(kind==='assurance'){
  const manager=await firstRoleFactor('production-command-assurance');const route='/api/identity/authentication/roles/operations-reader';const current=await request(identityBase,route,{token:manager.access_token});assert.equal(current.status,200);
  return{token:manager.access_token,table:'identity_role_authentication_audit',route,method:'PUT',headers:{'If-Match':`"od-role-authentication:operations-reader:${current.body.version}"`},body:{required:true,maxAgeSeconds:300,reason}};
 }
 let recipient=await issue(username);const roles=await issue('production-role-operator');const pim=await issue('production-pim-operator');const reviewer=await issue('production-command-reviewer');
 if(['grant','revoke','issuer-outage'].includes(kind)){
  const route='/api/users/'+target+'/roles';const body={role:'license-manager',durationSeconds:300,reason};
  if(kind!=='revoke')return{token:roles.access_token,table:'identity_role_audit',route,method:'POST',body};
  const grant=await request(identityBase,route,{method:'POST',token:roles.access_token,body});assert.equal(grant.status,201);return{token:roles.access_token,table:'identity_role_audit',route:route+'/'+grant.body.id,method:'DELETE'};
 }
 const eligibilityBody={userId:target,role:'license-manager',maxDurationSeconds:300,validForSeconds:3600,reason};const base='/api/identity/pim';
 if(kind==='eligibility-grant')return{token:pim.access_token,table:'identity_pim_audit',route:base+'/eligibilities',method:'POST',body:eligibilityBody};
 const eligible=await request(identityBase,base+'/eligibilities',{method:'POST',token:pim.access_token,body:eligibilityBody});assert.equal(eligible.status,201,JSON.stringify(eligible.body));
 if(kind==='eligibility-revoke')return{token:pim.access_token,table:'identity_pim_audit',route:base+'/eligibilities/'+eligible.body.id,method:'DELETE'};
 const requestBody={id:randomUUID(),eligibilityId:eligible.body.id,durationSeconds:300,reason};
 if(kind==='request')return{token:recipient.access_token,table:'identity_pim_audit',route:base+'/requests',method:'POST',body:requestBody};
 const pending=await request(identityBase,base+'/requests',{method:'POST',token:recipient.access_token,body:requestBody});assert.equal(pending.status,200,JSON.stringify(pending.body));
 const route=base+'/requests/'+pending.body.id;
 if(['approve','deny'].includes(kind))return{token:reviewer.access_token,table:'identity_pim_audit',route:route+'/'+kind,method:'POST'};
 if(kind==='cancel-pending')return{token:recipient.access_token,table:'identity_pim_audit',route:route+'/cancel',method:'POST'};
 assert.equal((await request(identityBase,route+'/approve',{method:'POST',token:reviewer.access_token})).status,200);recipient=await configureFactor(username,recipient);
 if(kind==='activate')return{token:recipient.access_token,table:'identity_role_audit',route:route+'/activate',method:'POST'};
 const active=await request(identityBase,route+'/activate',{method:'POST',token:recipient.access_token});assert.equal(active.status,200,JSON.stringify(active.body));assert.equal(active.body.status,'active');
 if(kind==='cancel-active')return{token:(await issue(username)).access_token,table:'identity_role_audit',route:route+'/cancel',method:'POST'};
 return{token:reviewer.access_token,table:'identity_role_audit',route:route+'/revoke',method:'POST'};
}
for(const kind of authorityCommandKinds)test('production gateway rolls back '+kind+' when original authority is withdrawn during actual authority audit DML',async()=>{
 const command=await prepareAuthorityCommand(kind);const before=await commandEvidence();const gate='original-authority-command-'+randomUUID();const blocker=await identityDb.pool.connect();let pending;let unavailable=false;
 await identityDb.query(`CREATE FUNCTION pause_original_authority_command() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('${gate}',0));RETURN NEW;END;$$;CREATE TRIGGER pause_original_authority_command BEFORE INSERT ON ${command.table} FOR EACH ROW EXECUTE FUNCTION pause_original_authority_command()`);
 try{await withProductionGateway(async base=>{
  await blocker.query('BEGIN');const backend=(await blocker.query('SELECT pg_backend_pid() AS id')).rows[0].id;await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[gate]);
  pending=request(base,command.route,{method:command.method,token:command.token,body:command.body,headers:command.headers});pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await identityDb.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event='advisory' AND $1=ANY(pg_blocking_pids(pid))) AS waiting",[backend])).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}
  assert.equal(waiting,true,'Actual authority audit DML lock wait required for '+kind);
  if(kind==='issuer-outage'){await issuerDb.query('ALTER TABLE oauth_token_revocations RENAME TO withheld_command_revocations');unavailable=true;}else assert.equal((await revoke(command.token)).status,200);
  await blocker.query('COMMIT');const response=await pending;assert.equal(response.status,kind==='issuer-outage'?503:401,JSON.stringify(response.body));assert.equal(response.body.id,undefined);
 });}finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});if(unavailable)await issuerDb.query('ALTER TABLE withheld_command_revocations RENAME TO oauth_token_revocations');await identityDb.query('DROP TRIGGER pause_original_authority_command ON '+command.table+';DROP FUNCTION pause_original_authority_command()');}
 assert.deepEqual(await commandEvidence(),before);
});

test('production gateway retains the original bearer through legitimate PIM self-activation and self-reduction without internal substitution',async()=>{
 const username='production-command-positive-self-change';const target=canonicalSubjects.get(username);const administrator=await issue('production-pim-operator');const reviewer=await issue('production-command-reviewer');let owner=await issue(username);
 const product=(await policyDb.query('INSERT INTO license_catalog(name,total_seats) VALUES($1,2) RETURNING id',['Original PIM bearer keeps existing business licenses'])).rows[0];const assign='/api/licenses/'+product.id+'/assign';const licenseBody={assignee_type:'user',assignee_id:canonicalSubjects.get('bob')};
 assert.equal((await request(policyBase,assign,{method:'POST',token:owner.access_token,body:licenseBody})).status,403);
 const eligible=await request(identityBase,'/api/identity/pim/eligibilities',{method:'POST',token:administrator.access_token,body:{userId:target,role:'license-manager',maxDurationSeconds:300,validForSeconds:3600,reason:'Actual source-to-license authority through the original PIM bearer'}});assert.equal(eligible.status,201);
 const pending=await request(identityBase,'/api/identity/pim/requests',{method:'POST',token:owner.access_token,body:{id:randomUUID(),eligibilityId:eligible.body.id,durationSeconds:300,reason:'Actual independently reviewed self activation and withdrawal'}});assert.equal(pending.status,200);
 const route='/api/identity/pim/requests/'+pending.body.id;assert.equal((await request(identityBase,route+'/approve',{method:'POST',token:reviewer.access_token})).status,200);owner=await configureFactor(username,owner);
 await withProductionGateway(async base=>{
  const active=await request(base,route+'/activate',{method:'POST',token:owner.access_token});assert.equal(active.status,200,JSON.stringify(active.body));assert.equal(active.body.status,'active');assert.equal((await request(policyBase,'/api/licenses/access',{token:owner.access_token})).status,401);
  const current=await issue(username);const allocation=await request(policyBase,'/api/licenses/access',{token:current.access_token});assert.equal(allocation.status,200);assert.ok(allocation.body.permissions.includes('licenses.assignments.manage'));
  assert.equal((await request(base,assign,{method:'POST',token:current.access_token,body:licenseBody})).status,201);
  const business=(await policyDb.query('SELECT * FROM license_assignments WHERE license_id=$1 ORDER BY id',[product.id])).rows;assert.equal(business.length,1);
  const cancelled=await request(base,route+'/cancel',{method:'POST',token:current.access_token});assert.equal(cancelled.status,200,JSON.stringify(cancelled.body));assert.equal(cancelled.body.status,'revoked');
  assert.equal((await request(policyBase,'/api/licenses/access',{token:current.access_token})).status,401);const fresh=await issue(username);const after=await request(policyBase,'/api/licenses/access',{token:fresh.access_token});assert.equal(after.status,200);assert.ok(!after.body.permissions.includes('licenses.assignments.manage'));
  assert.equal((await request(base,assign,{method:'POST',token:fresh.access_token,body:{...licenseBody,assignee_id:canonicalSubjects.get('alice')}})).status,403);assert.deepEqual((await policyDb.query('SELECT * FROM license_assignments WHERE license_id=$1 ORDER BY id',[product.id])).rows,business);
 });
 assert.equal(forbiddenServiceTokens,0);
});
test('production gateway commits a real original-token checkpoint and mandatory pending evidence without changing the public role response',async()=>{
 const operator=await issue('production-role-operator');const proof=payload(operator.access_token);const recipient=canonicalSubjects.get('production-member');let assignment;
 await withProductionGateway(async base=>{
  const response=await request(base,'/api/users/'+recipient+'/roles',{method:'POST',token:operator.access_token,body:{role:'license-reader',durationSeconds:300,reason:'Actual signed original-token SQL checkpoint receiving proof'}});assert.equal(response.status,201,JSON.stringify(response.body));assignment=response.body.id;assert.equal(response.body.checkpoint,undefined);
  const rows=(await identityDb.query(`SELECT checkpoint.*,event.actor,event.details,outbox.status FROM identity_authority_command_checkpoints checkpoint
   JOIN identity_authority_command_checkpoint_events event USING(id) JOIN identity_authority_command_checkpoint_outbox outbox USING(id)
   WHERE checkpoint.token_sha256=identity_authority_hash($1::jsonb) AND checkpoint.user_id=$2`,[JSON.stringify(proof.jti),proof.identity_authorization.userId])).rows;
  assert.equal(rows.length,1);assert.deepEqual(rows[0].original_context,proof.identity_authorization);assert.equal(rows[0].actor.userId,proof.identity_authorization.userId);assert.equal(rows[0].status,'pending');assert.ok(rows[0].valid_until.getTime()<=proof.exp*1000);assert.ok(rows[0].valid_until.getTime()>Date.now());assert.equal(rows[0].details.kind,'final-application-checkpoint');
  assert.equal((await request(base,'/api/users/'+recipient+'/roles/'+assignment,{method:'DELETE',token:operator.access_token})).status,200);
 });assert.equal(forbiddenServiceTokens,0);
});
test('production gateway refuses authority writes without the mandatory final SQL checkpoint receiver',async()=>{
 const operator=await issue('production-role-operator');const recipient=canonicalSubjects.get('production-member');const before=await commandEvidence();const evidence=(await identityDb.query('SELECT count(*)::int AS count FROM identity_authority_command_checkpoints')).rows[0].count;
 await identityDb.query('ALTER TABLE identity_authority_command_checkpoints DISABLE TRIGGER identity_authority_checkpoint_commit');
 try{await withProductionGateway(async base=>{
  const response=await request(base,'/api/users/'+recipient+'/roles',{method:'POST',token:operator.access_token,body:{role:'license-manager',durationSeconds:300,reason:'Missing mandatory final SQL checkpoint receiver must deny authority'}});assert.equal(response.status,403);assert.equal(response.body.id,undefined);
 });}finally{await identityDb.query('ALTER TABLE identity_authority_command_checkpoints ENABLE TRIGGER identity_authority_checkpoint_commit');}
 assert.deepEqual(await commandEvidence(),before);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_authority_command_checkpoints')).rows[0].count,evidence);
});
function organizationProfileFixture() {
  return { name: 'Actual Gateway Company', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Business Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'Europe/Zurich', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
}
test('production gateway persists only the original own-company profile and rejects foreign selectors and stale ETags', async () => {
  const administrator = await productionGlobalAdministrator(); await reviewBootstrap('production-foreign-authority-admin', 'admin'); let foreign = await issue('production-foreign-authority-admin'); if (!provenMfa(payload(foreign.access_token))) foreign = await configureFactor('production-foreign-authority-admin', foreign);
  const profile = organizationProfileFixture();
  const route = '/api/identity/organization';
  await withProductionGateway(async base => {
    const empty = await request(base, route, { token: administrator.access_token }); assert.equal(empty.status, 200, JSON.stringify(empty.body)); assert.equal(empty.body.organization, null); assert.equal(empty.headers.get('cache-control'), 'no-store');
    const created = await request(base, route, { method: 'PUT', token: administrator.access_token, headers: { 'If-Match': empty.body.etag }, body: { profile, reason: 'Actual signed company profile creation' } }); assert.equal(created.status, 200, JSON.stringify(created.body)); assert.equal(created.body.organization.version, '1'); assert.equal(created.headers.get('etag'), created.body.etag);
    const other = await request(base, route, { token: foreign.access_token }); assert.equal(other.status, 200); assert.notEqual(other.body.tenant.id, created.body.tenant.id); assert.equal(other.body.organization, null);
    assert.equal((await request(base, route, { method: 'PUT', token: foreign.access_token, headers: { 'If-Match': created.body.etag }, body: { profile, reason: 'Foreign known profile ETag cannot select another organization' } })).status, 412);
    assert.equal((await request(base, route + '?tenantId=' + other.body.tenant.id, { token: administrator.access_token })).status, 400);
    assert.equal((await request(base, route, { method: 'PUT', token: administrator.access_token, headers: { 'If-Match': empty.body.etag }, body: { profile, reason: 'Stale version cannot silently overwrite a real company' } })).status, 412);
    assert.equal((await request(base, route, { token: (await issue('production-ordinary')).access_token })).status, 403);
    const row = (await identityDb.query('SELECT event.actor,checkpoint.token_sha256,outbox.status FROM identity_organization_events event JOIN identity_organization_outbox outbox USING(id) JOIN identity_authority_command_checkpoints checkpoint ON checkpoint.transaction_id=event.transaction_id')).rows;
    assert.equal(row.length, 1); assert.equal(row[0].actor.userId, payload(administrator.access_token).identity_authorization.userId); assert.equal(row[0].status, 'pending');
  });
});
test('production gateway refuses an organization write when its mandatory receiving guard is absent', async () => {
  const administrator = await productionGlobalAdministrator(); const before = (await identityDb.query('SELECT count(*)::int AS count FROM identity_organization_events')).rows[0].count;
  const page = await request(identityBase, '/api/identity/organization', { token: administrator.access_token }); assert.equal(page.status, 200);
  await identityDb.query('ALTER TABLE identity_organization_outbox DISABLE TRIGGER identity_organization_guard');
  try { await withProductionGateway(async base => {
    assert.equal((await request(base, '/api/identity/organization', { token: administrator.access_token })).status, 503);
    assert.equal((await request(base, '/api/identity/organization', { method: 'PUT', token: administrator.access_token, headers: { 'If-Match': page.body.etag }, body: { profile: organizationProfileFixture(), reason: 'Actual missing receiver must reject a signed profile write' } })).status, 503);
  }); }
  finally { await identityDb.query('ALTER TABLE identity_organization_outbox ENABLE TRIGGER identity_organization_guard'); }
  assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_organization_events')).rows[0].count, before);
});
test('production gateway delegates only the own profile to an ordinary human and revokes the actual signed bearer without global role escalation', async () => {
  const administrator = await productionGlobalAdministrator(); const old = await issue('production-ordinary'); const userId = canonicalSubjects.get('production-ordinary'); const route = '/api/identity/organization'; const grantsRoute = route + '/delegations';
  await withProductionGateway(async base => {
    const granted = await request(base, grantsRoute, { method: 'POST', token: administrator.access_token, body: { userId, durationSeconds: 3600, reason: 'Actual scoped profile access, never a global role' } }); assert.equal(granted.status, 201, JSON.stringify(granted.body));
    assert.equal((await request(base, route, { token: old.access_token })).status, 401);
    let recipient = await issue('production-ordinary'); assert.equal(payload(recipient.access_token).roles.includes('admin'), false);
    if (!provenMfa(payload(recipient.access_token))) { assert.equal((await request(base, route, { token: recipient.access_token })).status, 428); recipient = await configureFactor('production-ordinary', recipient); }
    const access = await request(base, '/api/identity/access', { token: recipient.access_token }); assert.equal(access.status, 200); assert.deepEqual(access.body.permissions, ['organization.read', 'organization.manage']);
    assert.equal((await request(base, grantsRoute, { token: recipient.access_token })).status, 403);
    assert.equal((await request(base, '/api/users', { token: recipient.access_token })).status, 403);
    assert.equal((await request(base, '/api/identity/roles/catalog', { token: recipient.access_token })).status, 403);
    const current = await request(base, route, { token: recipient.access_token }); assert.equal(current.status, 200, JSON.stringify(current.body));
    const saved = await request(base, route, { method: 'PUT', token: recipient.access_token, headers: { 'If-Match': current.body.etag }, body: { profile: organizationProfileFixture(), reason: 'Actual ordinary human saves only the own delegated profile' } }); assert.equal(saved.status, 200, JSON.stringify(saved.body));
    assert.equal((await request(base, grantsRoute + '?tenantId=foreign', { token: administrator.access_token })).status, 400);
    const revoked = await request(base, grantsRoute + '/' + granted.body.grantId + '/revoke', { method: 'POST', token: administrator.access_token, body: { reason: 'Actual independent revocation of company profile access' } }); assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
    assert.equal((await request(base, route, { token: recipient.access_token })).status, 401);
    const renewed = await issue('production-ordinary'); assert.equal((await request(base, route, { token: renewed.access_token })).status, 403);
    const rows = (await identityDb.query('SELECT event.action,outbox.status,checkpoint.id FROM identity_organization_delegation_events event JOIN identity_organization_delegation_outbox outbox USING(id) JOIN identity_authority_command_checkpoints checkpoint ON checkpoint.transaction_id=event.transaction_id WHERE event.grant_id=$1 ORDER BY event.created_at', [granted.body.grantId])).rows;
    assert.deepEqual(rows.map(row => [row.action, row.status]), [['granted', 'pending'], ['revoked', 'pending']]);
  });
});
test('production gateway does not treat a real credential-bound pending company registration as an access grant', async () => {
  const previous = process.env.COMPANY_REGISTRATION_ENABLED; const previousActivation = process.env.COMPANY_ACTIVATION_ENABLED; const route = '/oauth/company-registration'; const registrationId = randomUUID();
  const body = { registrationId, username: 'company-registration-owner', password: 'disposable-password', mfaCode: '', confirm: true, profile: organizationProfileFixture() };
  try {
    process.env.COMPANY_REGISTRATION_ENABLED = 'false'; assert.equal((await request(issuerBase, route)).body.enabled, false); assert.equal((await request(issuerBase, route + '/submit', { method: 'POST', body })).status, 503);
    process.env.COMPANY_REGISTRATION_ENABLED = 'true'; assert.equal((await request(issuerBase, route)).body.enabled, true);
    assert.equal((await request(issuerBase, route + '/submit', { method: 'POST', body: { ...body, password: 'not-valid' } })).status, 401);
    assert.equal((await request(issuerBase, route + '/submit', { method: 'POST', body: { ...body, roles: ['admin'] } })).status, 400);
    const created = await request(issuerBase, route + '/submit', { method: 'POST', body }); assert.equal(created.status, 201, JSON.stringify(created.body)); assert.equal(created.body.status, 'pending-verification'); assert.equal(created.body.tenantEnabled, false); assert.equal(created.body.administratorEnabled, false); assert.equal(created.body.activationSupported, false); assert.equal(Object.hasOwn(created.body, 'access_token'), false);
    const repeated = await request(issuerBase, route + '/submit', { method: 'POST', body }); assert.equal(repeated.status, 200); assert.deepEqual(repeated.body, { ...created.body, replayed: true });
    const status = await request(issuerBase, route + '/status', { method: 'POST', body: { registrationId, username: body.username, password: body.password, mfaCode: '' } }); assert.equal(status.status, 200); assert.deepEqual(status.body, repeated.body);
    assert.equal((await request(issuerBase, route + '/submit', { method: 'POST', body: { ...body, profile: { ...body.profile, city: 'Retargeted' } } })).status, 409);
    const rejectedLogin = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: body.username, password: body.password, scope: 'openid roles' } }); assert.equal(rejectedLogin.status, 403); assert.equal(rejectedLogin.body.error, 'identity_not_eligible');
    const administrator = await productionGlobalAdministrator();
    const substitution = await request(identityBase, '/internal/identity/company-registrations/status', { method: 'POST', token: administrator.access_token, body: { registrationId, subject: body.username + '-subject' } }); assert.equal(substitution.status, 401);
    await withProductionGateway(async base => { assert.equal((await request(base, '/api/identity/organization', { token: registrationId })).status, 401); });
    const actual = (await identityDb.query('SELECT tenant.enabled AS tenant_enabled,account.enabled AS user_enabled,event.type,outbox.status FROM identity_company_registrations registration JOIN identity_tenants tenant ON tenant.id=registration.tenant_id JOIN users account ON account.id=registration.user_id JOIN identity_company_registration_events event ON event.id=registration.event_id JOIN identity_company_registration_outbox outbox ON outbox.id=event.id WHERE registration.id=$1', [registrationId])).rows;
    assert.deepEqual(actual, [{ tenant_enabled: false, user_enabled: false, type: 'company.registration.requested', status: 'pending' }]);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [created.body.administratorId])).rows[0].count, 0);
    const reviewsRoute = '/api/identity/company-registrations'; const reviewerName = 'production-ordinary'; const oldReviewer = await issue(reviewerName);
    const reviewerId = canonicalSubjects.get(reviewerName);
    await withProductionGateway(async base => {
      assert.equal((await request(base, reviewsRoute, { token: administrator.access_token })).status, 403);
      await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Explicit platform reviewer without a global role' });
      assert.equal((await request(base, reviewsRoute, { token: oldReviewer.access_token })).status, 401);
      let reviewer = await issue(reviewerName);
      if (!provenMfa(payload(reviewer.access_token))) { assert.equal((await request(base, reviewsRoute, { token: reviewer.access_token })).status, 428); reviewer = await configureFactor(reviewerName, reviewer); }
      const metadata = await request(base, '/api/identity/access', { token: reviewer.access_token }); assert.equal(metadata.status, 200); assert.deepEqual(metadata.body.permissions, ['company.registrations.review']);
      assert.equal((await request(base, '/api/users', { token: reviewer.access_token })).status, 403);
      const detail = await request(base, reviewsRoute + '/' + registrationId, { token: reviewer.access_token }); assert.equal(detail.status, 200, JSON.stringify(detail.body));
      const decision = await request(base, reviewsRoute + '/' + registrationId + '/review', { method: 'POST', token: reviewer.access_token, headers: { 'If-Match': detail.body.etag }, body: { decision: 'approved', reason: 'Actual signed independent company request review', confirm: true } }); assert.equal(decision.status, 200, JSON.stringify(decision.body)); assert.equal(decision.body.status, 'pending-activation');
      const observed = await request(issuerBase, route + '/status', { method: 'POST', body: { registrationId, username: body.username, password: body.password, mfaCode: '' } }); assert.equal(observed.status, 200); assert.equal(observed.body.status, 'pending-activation'); assert.equal(observed.body.administratorEnabled, false);
      const pendingLogin = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: body.username, password: body.password, scope: 'openid roles' } }); assert.equal(pendingLogin.status, 403); assert.equal(pendingLogin.body.error, 'identity_not_eligible');
      await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer, userId: reviewerId, version: '1', enabled: false, reason: 'Explicit platform review duty withdrawn after decision' });
      assert.equal((await request(base, reviewsRoute, { token: reviewer.access_token })).status, 401); const renewed = await issue(reviewerName); assert.equal((await request(base, reviewsRoute, { token: renewed.access_token })).status, 403);
    });
    const credentials = { registrationId, username: body.username, password: body.password, mfaCode: '' };
    assert.equal((await request(issuerBase, route + '/activate', { method: 'POST', body: { ...credentials, confirm: true } })).status, 503); process.env.COMPANY_ACTIVATION_ENABLED = 'true';
    const activated = await request(issuerBase, route + '/activate', { method: 'POST', body: { ...credentials, confirm: true } }); assert.equal(activated.status, 200, JSON.stringify(activated.body)); assert.equal(activated.body.status, 'active'); assert.equal(activated.body.mfaRequired, true);
    const notEnrolled = await request(issuerBase, '/oauth/authorize/login', { method: 'POST', body: { client_id: clientId, redirect_uri: 'http://localhost:4000/callback', username: body.username, password: body.password, scope: 'openid roles' } }); assert.equal(notEnrolled.status, 401); assert.equal(notEnrolled.body.error, 'mfa_enrollment_required');
    const companyOwner = await firstRoleFactor(body.username); assert.deepEqual(payload(companyOwner.access_token).roles, []);
    await withProductionGateway(async base => {
      const ownProfile = await request(base, '/api/identity/organization', { token: companyOwner.access_token }); assert.equal(ownProfile.status, 200, JSON.stringify(ownProfile.body)); assert.equal(ownProfile.body.organization.name, body.profile.name);
      const token = companyOwner.access_token; const metadata = await request(base, '/api/identity/access', { token }); assert.equal(metadata.status, 200);
      assert.equal(require('../../../identity-service/src/CompanyOwner').COMPANY_DIRECTORY_PERMISSIONS.length, 14);
      assert.deepEqual(metadata.body.permissions, ['organization.read', 'organization.manage', 'organization.delegations.manage', ...require('../../../identity-service/src/CompanyOwner').COMPANY_DIRECTORY_PERMISSIONS]);
      const people = await request(base, '/api/users', { token }); assert.equal(people.status, 200); assert.deepEqual(people.body.users.map(account => account.id), [activated.body.administratorId]);
      assert.equal((await request(base, '/api/users/' + canonicalSubjects.get('production-ordinary'), { token })).status, 404);
      assert.equal((await request(base, '/api/identity/company-registrations', { token })).status, 403); assert.equal((await request(base, '/api/identity/roles/catalog', { token })).status, 403);
      const root = await request(base, '/api/ous', { method: 'POST', token, body: { name: 'Company engineering' } }); assert.equal(root.status, 201, JSON.stringify(root.body));
      const child = await request(base, '/api/ous', { method: 'POST', token, body: { name: 'Company platform', parentId: root.body.id } }); assert.equal(child.status, 201); assert.equal(child.body.parentId, root.body.id);
      const created = await request(base, '/api/users', { method: 'POST', token, body: { username: 'signed-company-employee', email: 'signed-employee@example.invalid' } }); assert.equal(created.status, 201, JSON.stringify(created.body)); assert.equal(created.body.enabled, false);
      const inventoryCapabilities=await request(base,'/api/devices/capabilities',{token});assert.equal(inventoryCapabilities.status,200,JSON.stringify(inventoryCapabilities.body));assert.equal(inventoryCapabilities.body.tenantId,activated.body.tenantId);assert.deepEqual(inventoryCapabilities.body.supportedActions,[]);
      const registeredDevice=await request(base,'/api/devices',{method:'POST',token,body:{assetId:'SIGNED-LAPTOP-01',serialNumber:'SIGNED-SERIAL-01',manufacturer:'Example Manufacturer',model:'Corporate Laptop',deviceClass:'laptop',platform:'macos'}});
      assert.equal(registeredDevice.status,201,JSON.stringify(registeredDevice.body));assert.equal(registeredDevice.body.enrollmentStatus,'not-enrolled');assert.equal(registeredDevice.body.complianceStatus,'unknown');assert.equal(registeredDevice.body.lastSeen,null);
      const deviceRoute='/api/devices/'+registeredDevice.body.id;const deviceEtag=require('../../../../../packages/device-inventory-contract').deviceEtag;
      assert.equal((await request(base,deviceRoute+'/assignment',{method:'PUT',token,body:{userId:created.body.id}})).status,428);
      const deviceAssigned=await request(base,deviceRoute+'/assignment',{method:'PUT',token,headers:{'If-Match':deviceEtag(registeredDevice.body)},body:{userId:created.body.id}});assert.equal(deviceAssigned.status,200,JSON.stringify(deviceAssigned.body));assert.equal(deviceAssigned.body.assignedUserId,created.body.id);
      assert.equal((await request(base,deviceRoute+'/assignment',{method:'PUT',token,headers:{'If-Match':deviceEtag(registeredDevice.body)},body:{userId:null}})).status,412);
      assert.equal((await request(base,deviceRoute+'/assignment',{method:'PUT',token,headers:{'If-Match':deviceEtag(deviceAssigned.body)},body:{userId:canonicalSubjects.get('production-ordinary')}})).status,404);
      assert.equal((await request(base,deviceRoute+'/wipe',{method:'POST',token,body:{confirm:true}})).status,501);
      const deviceHistory=await request(base,deviceRoute+'/history',{token});assert.equal(deviceHistory.status,200,JSON.stringify(deviceHistory.body));assert.deepEqual(deviceHistory.body.events.map(event=>event.type),['device.assigned','device.registered']);assert.ok(deviceHistory.body.events.every(event=>event.deliveryStatus==='pending'));
      const inventoryForeign=await request(base,deviceRoute,{token:administrator.access_token});assert.equal(inventoryForeign.status,404,JSON.stringify(inventoryForeign.body));
      const deviceReleased=await request(base,deviceRoute+'/assignment',{method:'PUT',token,headers:{'If-Match':deviceEtag(deviceAssigned.body)},body:{userId:null}});assert.equal(deviceReleased.status,200,JSON.stringify(deviceReleased.body));assert.equal(deviceReleased.body.assignmentId,null);
      const actualDevice=(await inventoryFixture.db.query('SELECT tenant_id,assigned_user,status,compliance_status,last_seen,enrolled_at FROM devices WHERE id=$1',[registeredDevice.body.id])).rows[0];assert.deepEqual(actualDevice,{tenant_id:activated.body.tenantId,assigned_user:null,status:'inventory-only',compliance_status:'unknown',last_seen:null,enrolled_at:null});
      const group = await request(base, '/api/groups', { method: 'POST', token, body: { name: 'Own company group' } }); assert.equal(group.status, 201);
      const member = await request(base, '/api/groups/' + group.body.id + '/members', { method: 'POST', token, headers: { 'If-Match': require('../../../identity-service/src/GroupMutator').groupEtag(group.body) }, body: { userId: created.body.id } }); assert.equal(member.status, 200, JSON.stringify(member.body)); assert.deepEqual(member.body.members, [created.body.id]);
      const { ouEtag } = require('../../../identity-service/src/OuMutator'); assert.equal(metadata.body.directoryOuMutationProtocol, 1);
      assert.equal(metadata.body.directoryOuMembershipProtocol, 1);
      const memberRoute = '/api/ous/' + root.body.id + '/members';
      assert.equal((await request(base, memberRoute, { method: 'POST', token, body: { userId: created.body.id } })).status, 428);
      const ouLinked = await request(base, memberRoute, { method: 'POST', token, headers: { 'If-Match': ouEtag(root.body) }, body: { userId: created.body.id } }); assert.equal(ouLinked.status, 201, JSON.stringify(ouLinked.body)); assert.equal(ouLinked.body.unit.memberCount, 1);
      assert.equal((await request(base, memberRoute, { method: 'POST', token, headers: { 'If-Match': ouEtag(root.body) }, body: { userId: created.body.id } })).status, 412);
      const childLinked = await request(base, '/api/ous/' + child.body.id + '/members', { method: 'POST', token, headers: { 'If-Match': ouEtag(child.body) }, body: { userId: created.body.id } }); assert.equal(childLinked.status, 201, JSON.stringify(childLinked.body));
      const ownMembers = await request(base, memberRoute, { token }); assert.equal(ownMembers.status, 200, JSON.stringify(ownMembers.body)); assert.equal(ownMembers.body.profileAccess, true); assert.equal(ownMembers.body.actorUserId, activated.body.administratorId); assert.equal(ownMembers.body.total, 1); assert.equal(ownMembers.body.members[0].profile.username, 'signed-company-employee');
      assert.equal((await request(base, memberRoute, { method: 'POST', token, headers: { 'If-Match': ouEtag(ouLinked.body.unit) }, body: { userId: canonicalSubjects.get('production-ordinary') } })).status, 404);
      const ouUnlinked = await request(base, memberRoute + '/' + ouLinked.body.membership.id, { method: 'DELETE', token, headers: { 'If-Match': ouEtag(ouLinked.body.unit) } }); assert.equal(ouUnlinked.status, 200, JSON.stringify(ouUnlinked.body)); assert.equal(ouUnlinked.body.unit.memberCount, 0);
      assert.equal((await request(base, '/api/ous/' + child.body.id + '/members', { token })).body.total, 1);
      assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [created.body.id])).rows[0].enabled, false);
      assert.deepEqual((await identityDb.query('SELECT user_id FROM group_members WHERE group_id=$1', [group.body.id])).rows.map(link => link.user_id), [created.body.id]);
      assert.equal((await request(base, '/api/ous/' + root.body.id, { method: 'PUT', token, body: { name: 'Missing version' } })).status, 428);
      assert.equal((await request(base, '/api/ous/' + root.body.id, { method: 'DELETE', token, headers: { 'If-Match': ouEtag(ouUnlinked.body.unit) } })).status, 409);
      const moved = await request(base, '/api/ous/' + child.body.id, { method: 'PUT', token, headers: { 'If-Match': ouEtag(childLinked.body.unit) }, body: { name: 'Moved company platform', parentId: null } }); assert.equal(moved.status, 200, JSON.stringify(moved.body)); assert.equal(moved.body.parentId, undefined); assert.equal(moved.body.memberCount, 1);
      assert.equal((await request(base, '/api/ous/' + child.body.id, { method: 'PUT', token, headers: { 'If-Match': ouEtag(child.body) }, body: { name: 'Stale overwrite' } })).status, 412);
      assert.equal((await request(base, '/api/ous/' + root.body.id, { method: 'DELETE', token, headers: { 'If-Match': ouEtag(ouUnlinked.body.unit) } })).status, 204); assert.equal((await request(base, '/api/ous/' + root.body.id, { token })).status, 404);
      const foreignUnit = await request(base, '/api/ous', { method: 'POST', token: administrator.access_token, body: { name: 'Management tenant unit' } }); assert.equal(foreignUnit.status, 201, JSON.stringify(foreignUnit.body));
      for (const method of ['PUT', 'DELETE']) assert.equal((await request(base, '/api/ous/' + foreignUnit.body.id, { method, token, headers: { 'If-Match': ouEtag(foreignUnit.body) }, ...(method === 'PUT' ? { body: { name: 'No foreign overwrite' } } : {}) })).status, 404);
      assert.equal((await request(base, '/api/ous/' + foreignUnit.body.id + '/members', { token })).status, 404);
      assert.equal((await request(base, '/api/ous/' + foreignUnit.body.id + '/members', { method: 'POST', token, headers: { 'If-Match': ouEtag(foreignUnit.body) }, body: { userId: created.body.id } })).status, 404);
      for (const [method, path, body] of [['DELETE', '/api/users/' + created.body.id, undefined], ['POST', '/api/users/' + created.body.id + '/authorization/invalidate', {}]]) assert.equal((await request(base, path, { method, token, body })).status, 403);
      assert.deepEqual(payload(companyOwner.access_token).roles, []);
      const appBase = '/api/licenses/company'; const poolEtag = require('../../../../../packages/company-license-contract').poolEtag;
      const appCapabilities = await request(base, appBase + '/capabilities', { token }); assert.equal(appCapabilities.status, 200, JSON.stringify(appCapabilities.body));
      assert.equal(appCapabilities.body.companyLicenseProtocol, 1); assert.equal(appCapabilities.body.tenantId, activated.body.tenantId); assert.deepEqual(appCapabilities.body.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']);
      const poolInput = { name: 'Signed company local application', vendor: 'Reviewed Vendor', description: 'Actual inventory, no provider installation', totalSeats: 1, reason: 'Explicit signed own company pool creation' };
      assert.equal((await request(base, appBase + '/pools', { method: 'POST', token, body: { ...poolInput, tenantId: separateTenant } })).status, 400);
      assert.equal((await request(base, appBase + '/pools', { method: 'POST', token, body: { ...poolInput, totalSeats: 0 } })).status, 400);
      const companyPool = await request(base, appBase + '/pools', { method: 'POST', token, body: poolInput }); assert.equal(companyPool.status, 201, JSON.stringify(companyPool.body));
      assert.equal(companyPool.body.tenantId, activated.body.tenantId); assert.equal(companyPool.body.availableSeats, 1); assert.equal(companyPool.body.usedSeats, 0); assert.equal(companyPool.body.revision, '1'); assert.equal(companyPool.body.allocationMode, 'local-only');
      const poolRoute = appBase + '/pools/' + companyPool.body.id; const assignmentInput = { userId: created.body.id, reason: 'Explicit allocation to an actual own employee', confirm: true };
      assert.equal((await request(base, poolRoute, { token: administrator.access_token })).status, 404);
      for (const suffix of ['', '/assignments', '/audit']) assert.equal((await request(base, '/api/licenses/' + companyPool.body.id + suffix, { token: administrator.access_token })).status, 404);
      for (const route of ['/api/licenses', '/api/licenses/kiosk']) { const legacyCatalog = await request(base, route, { token: administrator.access_token }); assert.equal(legacyCatalog.status, 200); assert.equal(legacyCatalog.body.licenses.some(pool => pool.id === companyPool.body.id), false); }
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, body: assignmentInput })).status, 428);
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(companyPool.body) }, body: assignmentInput })).status, 403);
      assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_assignments WHERE license_id=$1', [companyPool.body.id])).rows[0].count, 0);
      const employeeRead = await request(base, '/api/users/' + created.body.id, { token }); assert.equal(employeeRead.status, 200);
      const employeeEnabled = await request(base, '/api/users/' + created.body.id, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(employeeRead.body) }, body: { enabled: true } }); assert.equal(employeeEnabled.status, 200, JSON.stringify(employeeEnabled.body));
      const assignedPool = await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(companyPool.body) }, body: assignmentInput }); assert.equal(assignedPool.status, 201, JSON.stringify(assignedPool.body));
      assert.equal(assignedPool.body.revision, '2'); assert.equal(assignedPool.body.usedSeats, 1); assert.equal(assignedPool.body.availableSeats, 0);
      const actualAllocation = (await policyDb.query(`SELECT assignment.assignee_id,source.source_type,catalog.business_tenant_id,subject.business_tenant_id AS subject_tenant,grants.kind
        FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
        JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id
        JOIN license_subjects subject ON subject.user_id=assignment.assignee_id JOIN license_grants grants ON grants.id=source.grant_id WHERE assignment.license_id=$1`, [companyPool.body.id])).rows;
      assert.deepEqual(actualAllocation, [{ assignee_id: created.body.id, source_type: 'direct', business_tenant_id: activated.body.tenantId, subject_tenant: activated.body.tenantId, kind: 'direct' }]);
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(companyPool.body) }, body: assignmentInput })).status, 412);
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(assignedPool.body) }, body: assignmentInput })).status, 409);
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(assignedPool.body) }, body: { ...assignmentInput, userId: canonicalSubjects.get('production-ordinary') } })).status, 404);
      const secondEmployee = await request(base, '/api/users', { method: 'POST', token, body: { username: 'signed-company-second-license-user', email: 'second-license-user@example.invalid' } }); assert.equal(secondEmployee.status, 201);
      const secondEnabled = await request(base, '/api/users/' + secondEmployee.body.id, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(secondEmployee.body) }, body: { enabled: true } }); assert.equal(secondEnabled.status, 200);
      assert.equal((await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(assignedPool.body) }, body: { ...assignmentInput, userId: secondEmployee.body.id } })).status, 409);
      assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_subjects WHERE user_id=$1', [secondEmployee.body.id])).rows[0].count, 0);
      const assignments = await request(base, poolRoute + '/assignments', { token }); assert.equal(assignments.status, 200); assert.equal(assignments.body.total, 1); assert.equal(assignments.body.assignments[0].userId, created.body.id);
      const employeeDisabled = await request(base, '/api/users/' + created.body.id, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(employeeEnabled.body) }, body: { enabled: false } }); assert.equal(employeeDisabled.status, 200);
      const releasedPool = await request(base, poolRoute + '/assignments/' + assignments.body.assignments[0].id + '/revoke', { method: 'POST', token, headers: { 'If-Match': poolEtag(assignedPool.body) }, body: assignmentInput }); assert.equal(releasedPool.status, 200, JSON.stringify(releasedPool.body));
      assert.equal(releasedPool.body.revision, '3'); assert.equal(releasedPool.body.usedSeats, 0); assert.equal(releasedPool.body.availableSeats, 1);
      const appHistory = await request(base, poolRoute + '/history', { token }); assert.equal(appHistory.status, 200); assert.deepEqual(appHistory.body.events.map(event => event.type), ['app.license.released', 'app.license.assigned', 'app.license.pool.created']); assert.ok(appHistory.body.events.every(event => event.deliveryStatus === 'pending'));
      const returnPool = await request(base, appBase + '/pools', { method: 'POST', token, body: { ...poolInput, name: 'Signed company second local application' } }); assert.equal(returnPool.status, 201, JSON.stringify(returnPool.body));
      const returnUserId = secondEmployee.body.id; const returnRoute = appBase + '/users/' + returnUserId + '/license-returns';
      for (const pool of [releasedPool.body, returnPool.body]) {
        const allocated = await request(base, appBase + '/pools/' + pool.id + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(pool) }, body: { ...assignmentInput, userId: returnUserId } });
        assert.equal(allocated.status, 201, JSON.stringify(allocated.body)); assert.equal(allocated.body.usedSeats, 1);
      }
      const providerTables = ['license_provider_connectors', 'license_provider_products', 'license_provider_subjects', 'license_provider_limits', 'license_fulfillment_targets', 'license_fulfillment_changes', 'license_fulfillment_events'];
      const returnState = async () => {
        const state = {};
        for (const table of ['license_catalog', 'license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_audit_events', 'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox', ...providerTables]) {
          state[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        }
        return state;
      };
      const beforeEditPool = await request(base, poolRoute, { token }); assert.equal(beforeEditPool.status, 200, JSON.stringify(beforeEditPool.body));
      const editCapabilities = await request(base, poolRoute + '/edit-capabilities', { token }); assert.equal(editCapabilities.status, 200, JSON.stringify(editCapabilities.body));
      assert.deepEqual(editCapabilities.body, { schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, poolId: companyPool.body.id, poolRevision: beforeEditPool.body.revision });
      assert.equal(editCapabilities.headers.get('cache-control'), 'no-store'); assert.equal(beforeEditPool.headers.get('etag'), poolEtag(beforeEditPool.body));
      const editInput = { name: 'Signed company renamed application', vendor: 'Updated Reviewed Vendor', description: 'Actual retained occupied company stock after metadata edit', totalSeats: 2, reason: 'Explicit signed metadata and occupied license stock correction', confirm: true };
      const beforeEdit = await returnState();
      assert.equal((await request(base, poolRoute, { method: 'PATCH', token, body: editInput })).status, 428);
      const invalidEditBodies = [
        {}, { ...editInput, confirm: false }, { ...editInput, confirm: 'true' }, { ...editInput, totalSeats: 0 }, { ...editInput, totalSeats: 10001 },
        { ...editInput, totalSeats: 1.5 }, { ...editInput, totalSeats: '2' }, { ...editInput, reason: 'too short' }, { ...editInput, name: '' },
        ...['tenantId', 'actorUserId', 'userId', 'poolId', 'poolRevision', 'usedSeats', 'permissions', 'providerId'].map(field => ({ ...editInput, [field]: field === 'usedSeats' ? 0 : activated.body.tenantId })),
        ...Object.keys(editInput).map(field => Object.fromEntries(Object.entries(editInput).filter(([key]) => key !== field))),
      ];
      for (const input of invalidEditBodies) assert.equal((await request(base, poolRoute, { method: 'PATCH', token, headers: { 'If-Match': beforeEditPool.headers.get('etag') }, body: input })).status, 400, JSON.stringify(input));
      for (const query of ['tenantId=' + activated.body.tenantId, 'actorUserId=' + activated.body.administratorId, 'poolId=' + companyPool.body.id]) {
        assert.equal((await request(base, poolRoute + '/edit-capabilities?' + query, { token })).status, 400);
        assert.equal((await request(base, poolRoute + '?' + query, { method: 'PATCH', token, headers: { 'If-Match': beforeEditPool.headers.get('etag') }, body: editInput })).status, 400);
      }
      for (const credential of [undefined, administrator.access_token]) {
        const status = credential ? 404 : 401;
        assert.equal((await request(base, poolRoute + '/edit-capabilities', { token: credential })).status, status);
        assert.equal((await request(base, poolRoute, { method: 'PATCH', token: credential, headers: { 'If-Match': beforeEditPool.headers.get('etag') }, body: editInput })).status, status);
      }
      assert.deepEqual(await returnState(), beforeEdit);
      const editedPool = await request(base, poolRoute, { method: 'PATCH', token, headers: { 'If-Match': beforeEditPool.headers.get('etag') }, body: editInput });
      assert.equal(editedPool.status, 200, JSON.stringify(editedPool.body));
      assert.deepEqual(editedPool.body, { ...beforeEditPool.body, name: editInput.name, vendor: editInput.vendor, description: editInput.description, totalSeats: 2, availableSeats: 1,
        revision: String(BigInt(beforeEditPool.body.revision) + 1n), updatedAt: editedPool.body.updatedAt });
      assert.equal(editedPool.body.usedSeats, 1); assert.equal(editedPool.headers.get('etag'), poolEtag(editedPool.body)); assert.equal(editedPool.headers.get('cache-control'), 'no-store');
      assert.deepEqual((await request(base, poolRoute, { token })).body, editedPool.body);
      const editedCapabilities = await request(base, poolRoute + '/edit-capabilities', { token }); assert.equal(editedCapabilities.status, 200);
      assert.deepEqual(editedCapabilities.body, { ...editCapabilities.body, poolRevision: editedPool.body.revision });
      const unchangedCapabilities = await request(base, appBase + '/capabilities', { token }); assert.equal(unchangedCapabilities.status, 200); assert.deepEqual(unchangedCapabilities.body, appCapabilities.body);
      const afterEdit = await returnState();
      for (const table of ['license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', ...providerTables]) assert.deepEqual(afterEdit[table], beforeEdit[table], table);
      assert.deepEqual(afterEdit.license_catalog.filter(record => record.row.id !== companyPool.body.id), beforeEdit.license_catalog.filter(record => record.row.id !== companyPool.body.id));
      for (const table of ['license_audit_events', 'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox']) {
        assert.deepEqual(afterEdit[table].filter(record => beforeEdit[table].some(previous => previous.row.id === record.row.id)), beforeEdit[table], table);
      }
      const editReceipts = (await policyDb.query(`SELECT event.*,outbox.status,license_company_event_valid(event) AS valid FROM license_company_events event
        JOIN license_company_outbox outbox USING(id) WHERE event.license_id=$1 AND event.type='app.license.pool.updated'`, [companyPool.body.id])).rows;
      assert.equal(editReceipts.length, 1); const editReceipt = editReceipts[0];
      assert.deepEqual([editReceipt.tenant_id, editReceipt.actor_user_id, editReceipt.target_user_id, editReceipt.version, String(editReceipt.before_revision), String(editReceipt.after_revision), editReceipt.status, editReceipt.valid],
        [activated.body.tenantId, activated.body.administratorId, null, 1, beforeEditPool.body.revision, editedPool.body.revision, 'pending', true]);
      assert.equal(editReceipt.proof.source.tokenId, payload(token).jti); assert.equal(editReceipt.proof.source.subject, payload(token).sub); assert.equal(editReceipt.proof.source.issuer, issuer);
      assert.deepEqual(editReceipt.proof.source.context, payload(token).identity_authorization);
      assert.deepEqual(editReceipt.proof.source.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']); assert.equal(editReceipt.proof.source.target, null);
      assert.deepEqual(editReceipt.proof.checkpoint, editReceipt.proof.source); assert.equal(editReceipt.proof.command.action, 'update'); assert.equal(editReceipt.proof.command.assignmentId, null);
      assert.deepEqual(editReceipt.proof.command.values, { name: editInput.name, vendor: editInput.vendor, description: editInput.description, totalSeats: 2 }); assert.equal(editReceipt.proof.command.reason, editInput.reason);
      assert.equal(provenMfa(payload(token)), true); assert.deepEqual(payload(token).roles, []);
      const editOrigins = (await policyDb.query('SELECT relation,operation,before_state,after_state FROM license_company_origins WHERE command_id=$1 ORDER BY ordinal', [editReceipt.id])).rows;
      assert.deepEqual(editOrigins.map(origin => origin.relation + ':' + origin.operation).sort(), ['license_audit_events:INSERT', 'license_catalog:UPDATE', 'license_catalog:UPDATE']);
      const catalogOrigins = editOrigins.filter(origin => origin.relation === 'license_catalog'); assert.equal(catalogOrigins.length, 2);
      assert.ok(catalogOrigins.every(origin => origin.operation === 'UPDATE' && origin.before_state.id === companyPool.body.id && origin.after_state.id === companyPool.body.id && origin.after_state.used_seats === origin.before_state.used_seats));
      assert.equal(catalogOrigins[0].before_state.name, beforeEditPool.body.name); assert.equal(catalogOrigins.at(-1).after_state.name, editInput.name); assert.equal(catalogOrigins.at(-1).after_state.total_seats, 2);
      assert.equal(editOrigins.some(origin => ['license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', ...providerTables].includes(origin.relation)), false);
      const editHistory = await request(base, poolRoute + '/history', { token }); assert.equal(editHistory.status, 200);
      assert.deepEqual(editHistory.body.events.filter(event => event.id === editReceipt.id).map(event => ({ type: event.type, userId: event.userId, beforeRevision: event.beforeRevision, afterRevision: event.afterRevision, deliveryStatus: event.deliveryStatus })),
        [{ type: 'app.license.pool.updated', userId: null, beforeRevision: beforeEditPool.body.revision, afterRevision: editedPool.body.revision, deliveryStatus: 'pending' }]);
      assert.equal((await request(base, poolRoute, { method: 'PATCH', token, headers: { 'If-Match': beforeEditPool.headers.get('etag') }, body: { ...editInput, name: 'Stale overwrite refused' } })).status, 412);
      assert.equal((await request(base, poolRoute, { method: 'PATCH', token, headers: { 'If-Match': editedPool.headers.get('etag') }, body: editInput })).status, 409);
      for (const statement of ['UPDATE license_company_events SET correlation_id=$2 WHERE id=$1', 'DELETE FROM license_company_events WHERE id=$1', 'UPDATE license_company_outbox SET status=$2 WHERE id=$1', 'DELETE FROM license_company_outbox WHERE id=$1']) {
        await assert.rejects(policyDb.query(statement, statement.includes('$2') ? [editReceipt.id, statement.includes('correlation_id') ? randomUUID() : 'pending'] : [editReceipt.id]), error => ['42501', '23514'].includes(error.code));
      }
      assert.deepEqual(await returnState(), afterEdit);
      const ownerAssignmentInput = { userId: activated.body.administratorId, reason: 'Actual second occupied seat to verify the allocation floor', confirm: true };
      const ownerAssigned = await request(base, poolRoute + '/assignments', { method: 'POST', token, headers: { 'If-Match': editedPool.headers.get('etag') }, body: ownerAssignmentInput }); assert.equal(ownerAssigned.status, 201, JSON.stringify(ownerAssigned.body)); assert.equal(ownerAssigned.body.usedSeats, 2);
      const fullyOccupied = await returnState();
      const belowUsed = await request(base, poolRoute, { method: 'PATCH', token, headers: { 'If-Match': ownerAssigned.headers.get('etag') }, body: { ...editInput, totalSeats: 1 } }); assert.equal(belowUsed.status, 409, JSON.stringify(belowUsed.body));
      assert.deepEqual(await returnState(), fullyOccupied);
      const ownerAssignments = await request(base, poolRoute + '/assignments', { token }); assert.equal(ownerAssignments.status, 200); const ownerAssignment = ownerAssignments.body.assignments.find(assignment => assignment.userId === activated.body.administratorId); assert.ok(ownerAssignment);
      const ownerReleased = await request(base, poolRoute + '/assignments/' + ownerAssignment.id + '/revoke', { method: 'POST', token, headers: { 'If-Match': ownerAssigned.headers.get('etag') }, body: ownerAssignmentInput }); assert.equal(ownerReleased.status, 200, JSON.stringify(ownerReleased.body)); assert.equal(ownerReleased.body.usedSeats, 1);
      const actualReturns = (await policyDb.query(`SELECT assignment.id,catalog.id AS pool_id,catalog.business_revision,catalog.name,catalog.vendor,source.grant_id,assignment.assigned_at
        FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
        JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
        WHERE assignment.assignee_id=$1 AND catalog.business_tenant_id=$2 ORDER BY catalog.name,catalog.id`, [returnUserId, activated.body.tenantId])).rows;
      assert.equal(actualReturns.length, 2);
      const returnRows = actualReturns.map(row => ({ id: row.id, poolId: row.pool_id, poolRevision: String(row.business_revision), name: row.name, vendor: row.vendor, grantId: row.grant_id, assignedAt: row.assigned_at.toISOString() }));
      const activeRevision = String((await identityDb.query('SELECT eligibility_revision FROM users WHERE id=$1', [returnUserId])).rows[0].eligibility_revision);
      const activeReturns = await request(base, returnRoute, { token }); assert.equal(activeReturns.status, 200, JSON.stringify(activeReturns.body));
      assert.deepEqual(activeReturns.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, userId: returnUserId,
        target: { enabled: true, deleted: false, eligibilityRevision: activeRevision }, assignments: returnRows, total: 2, page: 1, limit: 25 });
      assert.equal(activeReturns.headers.get('cache-control'), 'no-store');
      for (const page of [1, 2, 3]) {
        const paged = await request(base, returnRoute + '?page=' + page + '&limit=1', { token }); assert.equal(paged.status, 200, JSON.stringify(paged.body));
        assert.deepEqual(paged.body, { ...activeReturns.body, assignments: returnRows.slice(page - 1, page), page, limit: 1 });
      }
      const captured = returnRows.map(row => ({ poolId: row.poolId, assignmentId: row.id, poolRevision: row.poolRevision }));
      const returnInput = { reason: 'Controlled local license return after People disable', confirm: true, assignments: captured };
      const beforeReturns = await returnState();
      const enabledReturn = await request(base, returnRoute, { method: 'POST', token, body: returnInput }); assert.equal(enabledReturn.status, 403, JSON.stringify(enabledReturn.body));
      assert.equal((await request(base, returnRoute, { method: 'POST', token, body: { ...returnInput, reason: '1234567890', assignments: captured.slice(0, 1) } })).status, 403);
      assert.deepEqual(await returnState(), beforeReturns);
      const returnDisabled = await request(base, '/api/users/' + returnUserId, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(secondEnabled.body) }, body: { enabled: false } }); assert.equal(returnDisabled.status, 200, JSON.stringify(returnDisabled.body));
      assert.deepEqual(await returnState(), beforeReturns);
      const disabledAccount = (await identityDb.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1', [returnUserId])).rows[0];
      const disabledRevision = String(disabledAccount.eligibility_revision); assert.ok(BigInt(disabledRevision) > BigInt(activeRevision));
      const disabledReturns = await request(base, returnRoute + '?page=1&limit=25', { token }); assert.equal(disabledReturns.status, 200, JSON.stringify(disabledReturns.body));
      assert.deepEqual(disabledReturns.body, { ...activeReturns.body, target: { enabled: false, deleted: false, eligibilityRevision: disabledRevision } });
      for (const page of [1, 2, 3]) {
        const paged = await request(base, returnRoute + '?page=' + page + '&limit=1', { token }); assert.equal(paged.status, 200, JSON.stringify(paged.body));
        assert.deepEqual(paged.body, { ...disabledReturns.body, assignments: returnRows.slice(page - 1, page), page, limit: 1 });
      }
      for (const query of ['page=0', 'page=01', 'limit=0', 'limit=26', 'limit=101', 'limit=1&limit=2', 'search=employee', 'tenantId=' + separateTenant]) assert.equal((await request(base, returnRoute + '?' + query, { token })).status, 400, query);
      const foreignReturnRoute = appBase + '/users/' + canonicalSubjects.get('production-ordinary') + '/license-returns';
      assert.equal((await request(base, foreignReturnRoute, { token })).status, 404);
      for (const method of ['GET', 'POST']) {
        const foreign = await request(base, returnRoute, { method, token: administrator.access_token, ...(method === 'POST' ? { body: returnInput } : {}) }); assert.equal(foreign.status, 404, JSON.stringify(foreign.body));
        assert.equal((await request(base, returnRoute, { method, ...(method === 'POST' ? { body: returnInput } : {}) })).status, 401);
      }
      assert.deepEqual(await returnState(), beforeReturns);
      const invalidReturnBodies = [
        {}, { reason: returnInput.reason, assignments: captured }, { confirm: true, assignments: captured }, { reason: returnInput.reason, confirm: true },
        { ...returnInput, userId: returnUserId }, { ...returnInput, tenantId: activated.body.tenantId }, { ...returnInput, confirm: false }, { ...returnInput, confirm: 'true' },
        { ...returnInput, reason: '123456789' }, { ...returnInput, reason: 'a'.repeat(501) }, { ...returnInput, reason: 1234567890 },
        { ...returnInput, assignments: [] }, { ...returnInput, assignments: null }, { ...returnInput, assignments: {} },
        { ...returnInput, assignments: Array.from({ length: 26 }, () => ({ poolId: randomUUID(), assignmentId: randomUUID(), poolRevision: '1' })) },
        { ...returnInput, assignments: [captured[0], { ...captured[1], poolId: captured[0].poolId }] },
        { ...returnInput, assignments: [captured[0], { ...captured[1], assignmentId: captured[0].assignmentId }] },
        { ...returnInput, assignments: [{ ...captured[0], grantId: returnRows[0].grantId }] },
        { ...returnInput, assignments: [{ poolId: captured[0].poolId, assignmentId: captured[0].assignmentId }] },
        ...[0, 2, '0', '02', '9223372036854775808'].map(poolRevision => ({ ...returnInput, assignments: [{ ...captured[0], poolRevision }] })),
        { ...returnInput, assignments: [{ ...captured[0], poolId: 'not-a-pool' }] }, { ...returnInput, assignments: [{ ...captured[0], assignmentId: 'not-an-assignment' }] },
      ];
      for (const invalid of invalidReturnBodies) { const denied = await request(base, returnRoute, { method: 'POST', token, body: invalid }); assert.equal(denied.status, 400, JSON.stringify({ invalid, response: denied.body })); }
      assert.deepEqual(await returnState(), beforeReturns);
      await policyDb.query('CREATE SEQUENCE company_return_write_attempts');
      await policyDb.query("CREATE FUNCTION observe_company_return_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('company_return_write_attempts'); RETURN NEW; END $$");
      await policyDb.query('CREATE TRIGGER observe_company_return_write BEFORE INSERT ON license_company_commands FOR EACH ROW EXECUTE FUNCTION observe_company_return_write()');
      try {
        for (const [assignments, status] of [
          [[captured[0], { ...captured[1], poolRevision: String(BigInt(captured[1].poolRevision) - 1n) }], 412],
          [[captured[0], { ...captured[1], assignmentId: randomUUID() }], 404],
          [[captured[0], { ...captured[1], poolId: randomUUID() }], 404],
          [Array.from({ length: 25 }, () => ({ poolId: randomUUID(), assignmentId: randomUUID(), poolRevision: '1' })), 404],
        ]) {
          const rejected = await request(base, returnRoute, { method: 'POST', token, body: { ...returnInput, assignments } }); assert.equal(rejected.status, status, JSON.stringify(rejected.body));
          assert.equal((await policyDb.query('SELECT is_called FROM company_return_write_attempts')).rows[0].is_called, false);
          assert.deepEqual(await returnState(), beforeReturns);
        }
      } finally {
        await policyDb.query('DROP TRIGGER observe_company_return_write ON license_company_commands'); await policyDb.query('DROP FUNCTION observe_company_return_write()'); await policyDb.query('DROP SEQUENCE company_return_write_attempts');
      }
      await identityDb.query('ALTER TABLE identity_company_activation_outbox DISABLE TRIGGER identity_company_activation_guard');
      try {
        for (const method of ['GET', 'POST']) { const unavailable = await request(base, returnRoute, { method, token, ...(method === 'POST' ? { body: returnInput } : {}) }); assert.equal(unavailable.status, 503, JSON.stringify(unavailable.body)); }
      } finally { await identityDb.query('ALTER TABLE identity_company_activation_outbox ENABLE TRIGGER identity_company_activation_guard'); }
      assert.deepEqual(await returnState(), beforeReturns);
      const { exp: ownerExpiry, iat: ownerIssuedAt, jti: ownerTokenId, aud: ownerAudience, client_id: ownerClient, token_use: ownerUse, ...originalOwner } = payload(token);
      const historicalAuthTime = Math.floor(Date.now() / 1000) - 301; const historicalSession = randomUUID(); const historicalExpiry = Date.now() + 86400000;
      const historicalOwner = { ...originalOwner, aud: clientId, sid: historicalSession, auth_time: historicalAuthTime, mfa_authorization: { ...originalOwner.mfa_authorization, authTime: historicalAuthTime }, iat: Math.floor(Date.now() / 1000) };
      await new SessionStore(issuerDb).create({ id: historicalSession, issuer, subject: historicalOwner.sub, principalType: 'user', clientId, authTime: historicalAuthTime, expiresAt: historicalExpiry },
        { hash: createHash('sha256').update(randomUUID()).digest('hex'), scope: historicalOwner.scope, authorization: historicalOwner, expiresAt: historicalExpiry });
      const ownerKeys = new SigningKeys({ privateKeyFile: firstKeyFile, verificationJwksFile: null, ephemeral: false, production: true });
      const expiredMfaOwner = jwt.sign({ ...historicalOwner, aud: 'opendirectory-api', client_id: clientId, token_use: 'access', jti: randomUUID() }, ownerKeys.privateKey, { algorithm: 'RS256', keyid: ownerKeys.kid, expiresIn: 3600 });
      for (const method of ['GET', 'POST']) { const expired = await request(base, returnRoute, { method, token: expiredMfaOwner, ...(method === 'POST' ? { body: returnInput } : {}) }); assert.ok([401, 428].includes(expired.status), JSON.stringify(expired)); }
      assert.deepEqual(await returnState(), beforeReturns);
      const returned = await request(base, returnRoute, { method: 'POST', token, body: { ...returnInput, reason: 'r'.repeat(500) } }); assert.equal(returned.status, 200, JSON.stringify(returned.body));
      assert.match(returned.body.correlationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u); assert.equal(returned.headers.get('x-correlation-id'), returned.body.correlationId);
      assert.deepEqual(returned.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, userId: returnUserId, correlationId: returned.body.correlationId,
        results: captured.map(item => ({ poolId: item.poolId, assignmentId: item.assignmentId, status: 'released', code: 200 })) });
      for (const table of ['license_assignments', 'license_assignment_sources']) assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM ' + table + ' WHERE license_id=ANY($1::uuid[])', [captured.map(item => item.poolId)])).rows[0].count, 0);
      const grantStates = (await policyDb.query('SELECT DISTINCT ON (grant_id) grant_id,state FROM license_grant_events WHERE grant_id=ANY($1::uuid[]) ORDER BY grant_id,version DESC', [returnRows.map(row => row.grantId)])).rows;
      assert.equal(grantStates.length, 2); assert.ok(grantStates.every(grant => grant.state === 'revoked'));
      const returnReceipts = (await policyDb.query(`SELECT events.*,outbox.status,license_company_event_valid(events) AS valid FROM license_company_events events JOIN license_company_outbox outbox ON outbox.id=events.id
        WHERE events.correlation_id=$1 ORDER BY events.license_id`, [returned.body.correlationId])).rows;
      assert.equal(returnReceipts.length, 2);
      for (const receipt of returnReceipts) {
        const capturedItem = captured.find(item => item.poolId === receipt.license_id); assert.ok(capturedItem);
        assert.equal(receipt.type, 'app.license.released'); assert.equal(receipt.status, 'pending'); assert.equal(receipt.valid, true); assert.equal(receipt.version, 1);
        assert.equal(receipt.tenant_id, activated.body.tenantId); assert.equal(receipt.actor_user_id, activated.body.administratorId); assert.equal(receipt.target_user_id, returnUserId);
        assert.equal(receipt.correlation_id, returned.body.correlationId); assert.equal(String(receipt.before_revision), capturedItem.poolRevision); assert.equal(BigInt(receipt.after_revision), BigInt(capturedItem.poolRevision) + 1n);
        assert.equal(receipt.proof.source.tokenId, payload(token).jti); assert.equal(receipt.proof.source.subject, payload(token).sub); assert.equal(receipt.proof.source.issuer, issuer);
        assert.deepEqual(receipt.proof.source.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']); assert.deepEqual(receipt.proof.checkpoint, receipt.proof.source);
        assert.deepEqual(receipt.proof.source.target, { id: returnUserId, revision: String(disabledAccount.authorization_revision), enabled: false, deleted: false, eligibilityRevision: disabledRevision });
        assert.equal(receipt.proof.command.assignmentId, capturedItem.assignmentId); assert.equal(receipt.proof.command.reason, 'r'.repeat(500));
        for (const statement of ['UPDATE license_company_events SET correlation_id=$2 WHERE id=$1', 'DELETE FROM license_company_events WHERE id=$1', 'UPDATE license_company_outbox SET status=$2 WHERE id=$1', 'DELETE FROM license_company_outbox WHERE id=$1']) {
          await assert.rejects(policyDb.query(statement, statement.includes('$2') ? [receipt.id, statement.includes('correlation_id') ? randomUUID() : 'pending'] : [receipt.id]), error => ['42501', '23514'].includes(error.code));
        }
        const returnedPool = await request(base, appBase + '/pools/' + receipt.license_id, { token }); assert.equal(returnedPool.status, 200); assert.equal(returnedPool.body.usedSeats, 0); assert.equal(returnedPool.body.availableSeats, receipt.license_id === editedPool.body.id ? editedPool.body.totalSeats : 1);
        const returnedHistory = await request(base, appBase + '/pools/' + receipt.license_id + '/history', { token }); assert.equal(returnedHistory.status, 200);
        assert.deepEqual(returnedHistory.body.events.filter(event => event.correlationId === returned.body.correlationId).map(event => ({ type: event.type, deliveryStatus: event.deliveryStatus })), [{ type: 'app.license.released', deliveryStatus: 'pending' }]);
      }
      const emptyReturns = await request(base, returnRoute, { token }); assert.equal(emptyReturns.status, 200); assert.deepEqual(emptyReturns.body, { ...disabledReturns.body, assignments: [], total: 0 });
      const afterReturns = await returnState(); for (const table of providerTables) assert.deepEqual(afterReturns[table], beforeReturns[table]);
      const revokedOwner = await issue(body.username); assert.equal((await revoke(revokedOwner.access_token)).status, 200);
      for (const method of ['GET', 'POST']) assert.equal((await request(base, returnRoute, { method, token: revokedOwner.access_token, ...(method === 'POST' ? { body: returnInput } : {}) })).status, 401);
      assert.deepEqual(await returnState(), afterReturns);
      const workflowRoute = appBase + '/offboarding-workflows'; const previewRoute = appBase + '/users/' + returnUserId + '/offboarding-preview';
      const secondGroup = await request(base, '/api/groups', { method: 'POST', token, body: { name: 'Own company operations' } }); assert.equal(secondGroup.status, 201, JSON.stringify(secondGroup.body));
      for (const [groupId, userId] of [[group.body.id, returnUserId], [secondGroup.body.id, returnUserId], [secondGroup.body.id, created.body.id]]) {
        const linked = await groupRequest(base, '/api/groups/' + groupId + '/members', { method: 'POST', token, body: { userId } }); assert.equal(linked.status, 200, JSON.stringify(linked.body));
      }
      const foreignCleanupGroup = await request(base, '/api/groups', { method: 'POST', token: administrator.access_token, body: { name: 'Foreign company cleanup preflight boundary' } }); assert.equal(foreignCleanupGroup.status, 201, JSON.stringify(foreignCleanupGroup.body));
      const currentEmployee = await request(base, '/api/users/' + returnUserId, { token }); assert.equal(currentEmployee.status, 200);
      const restoredEmployee = await request(base, '/api/users/' + returnUserId, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(currentEmployee.body) }, body: { enabled: true } }); assert.equal(restoredEmployee.status, 200, JSON.stringify(restoredEmployee.body));
      const accessOperators = new Map();
      for (const [name, roles] of [['company-access-operator', ['role-administrator', 'pim-administrator']], ['company-access-reviewer', ['admin', 'pim-approver']], ['company-access-reader', ['role-reader']]]) {
        const account = await request(base, '/api/users', { method: 'POST', token, body: { username: name, email: name + '@example.invalid' } }); assert.equal(account.status, 201, JSON.stringify(account.body));
        const enabled = await request(base, '/api/users/' + account.body.id, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(account.body) }, body: { enabled: true } }); assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
        canonicalSubjects.set(name, account.body.id);
        await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, name + '-subject', account.body.id], 'fixture-bootstrap');
        for (const role of roles) await require('../../../identity-service/scripts/bootstrap-role').bootstrapRole(identityDb, { userId: account.body.id, role, duration: 3600, reason: 'Explicit isolated own-tenant Slice18 independent canonical operator fixture' });
        accessOperators.set(name, { id: account.body.id, roles });
      }
      const accessTargetName = 'company-access-target'; canonicalSubjects.set(accessTargetName, returnUserId);
      await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [issuer, accessTargetName + '-subject', returnUserId], 'fixture-bootstrap');
      await bootstrapApplications(issuerDb, { issuer, identityBase, signingKeyFile: firstKeyFile, clients: [clientId], users: [...accessOperators.values()].map(actor => actor.id).concat(returnUserId) });
      const publicAccessEnrollment = await request(issuerBase, '/oauth/mfa/enrollment/start', { method: 'POST', body: { clientId, username: 'company-access-operator', password: 'disposable-password' } });
      assert.equal(publicAccessEnrollment.status, 403, JSON.stringify(publicAccessEnrollment.body)); assert.deepEqual(publicAccessEnrollment.body, { error: 'mfa_enrollment_not_allowed' });
      process.stdout.write('Slice18 fixture public enrollment rejected truthfully: ' + JSON.stringify(publicAccessEnrollment.body) + '; using existing authenticated self-enrollment.\n');
      const accessOperator = await configureFactor('company-access-operator', await issue('company-access-operator')); const accessReviewer = await configureFactor('company-access-reviewer', await issue('company-access-reviewer')); const accessReader = await configureFactor('company-access-reader', await issue('company-access-reader'));
      const accessOperatorId = accessOperators.get('company-access-operator').id;
      assert.deepEqual(payload(accessOperator.access_token).roles, ['pim-administrator', 'role-administrator']);
      const accessOperatorMetadata = await request(base, '/api/identity/access', { token: accessOperator.access_token }); assert.equal(accessOperatorMetadata.status, 200);
      for (const forbidden of ['users.read', 'company.apps.read', 'company.apps.create', 'company.apps.assign']) assert.equal(accessOperatorMetadata.body.permissions.includes(forbidden), false);
      assert.equal((await request(base, '/api/users', { token: accessOperator.access_token })).status, 403);
      const accessRole = await request(base, '/api/users/' + returnUserId + '/roles', { method: 'POST', token: accessOperator.access_token, body: { role: 'group-administrator', durationSeconds: 3600, reason: 'Actual original canonical nonprotected role before offboarding' } }); assert.equal(accessRole.status, 201, JSON.stringify(accessRole.body));
      const accessProtectedRole = await request(base, '/api/users/' + returnUserId + '/roles', { method: 'POST', token: accessReviewer.access_token, body: { role: 'role-administrator', durationSeconds: 3600, reason: 'Protected canonical assignment remains restricted to a genuine administrator' } }); assert.equal(accessProtectedRole.status, 201, JSON.stringify(accessProtectedRole.body));
      const accessEligibilities = [];
      for (const role of ['license-manager', 'directory-reader']) {
        const eligibility = await request(base, '/api/identity/pim/eligibilities', { method: 'POST', token: accessOperator.access_token, body: { userId: returnUserId, role, maxDurationSeconds: 3600, validForSeconds: 7200, reason: 'Actual canonical eligibility before linked account offboarding' } }); assert.equal(eligibility.status, 201, JSON.stringify(eligibility.body)); accessEligibilities.push(eligibility.body);
      }
      let accessTarget = await configureFactor(accessTargetName, await issue(accessTargetName));
      const accessActiveRequest = await request(base, '/api/identity/pim/requests', { method: 'POST', token: accessTarget.access_token, body: { id: randomUUID(), eligibilityId: accessEligibilities[0].id, durationSeconds: 3600, reason: 'Actual beneficiary requests a later revocable active PIM assignment' } }); assert.equal(accessActiveRequest.status, 200, JSON.stringify(accessActiveRequest.body));
      assert.equal((await request(base, '/api/identity/pim/requests/' + accessActiveRequest.body.id + '/approve', { method: 'POST', token: accessReviewer.access_token })).status, 200);
      const accessActivated = await request(base, '/api/identity/pim/requests/' + accessActiveRequest.body.id + '/activate', { method: 'POST', token: accessTarget.access_token }); assert.equal(accessActivated.status, 200, JSON.stringify(accessActivated.body)); assert.equal(accessActivated.body.status, 'active');
      accessTarget = await issue(accessTargetName);
      const accessPendingRequest = await request(base, '/api/identity/pim/requests', { method: 'POST', token: accessTarget.access_token, body: { id: randomUUID(), eligibilityId: accessEligibilities[1].id, durationSeconds: 3600, reason: 'Actual pending request must be cancelled by the original eligibility kernel' } }); assert.equal(accessPendingRequest.status, 200, JSON.stringify(accessPendingRequest.body));
      const accessActiveAssignment = (await identityDb.query('SELECT id FROM identity_role_assignments WHERE activation_request_id=$1 AND revoked_at IS NULL', [accessActiveRequest.body.id])).rows[0]; assert.ok(accessActiveAssignment);
      assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [activated.body.administratorId])).rows[0].count, 0);
      for (const poolId of captured.map(item => item.poolId)) {
        const currentPool = await request(base, appBase + '/pools/' + poolId, { token }); assert.equal(currentPool.status, 200);
        const allocated = await request(base, appBase + '/pools/' + poolId + '/assignments', { method: 'POST', token, headers: { 'If-Match': poolEtag(currentPool.body) }, body: { ...assignmentInput, userId: returnUserId } });
        assert.equal(allocated.status, 201, JSON.stringify(allocated.body));
      }
      const workflowAssignments = (await policyDb.query(`SELECT assignment.id AS assignment_id,catalog.id AS pool_id,catalog.business_revision,source.grant_id
        FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
        JOIN license_assignment_sources source ON source.license_id=catalog.id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
        WHERE catalog.business_tenant_id=$1 AND assignment.assignee_id=$2 ORDER BY catalog.name,catalog.id`, [activated.body.tenantId, returnUserId])).rows;
      assert.equal(workflowAssignments.length, 2);
      const accountState = async () => (await identityDb.query('SELECT enabled,authorization_revision::text,eligibility_revision::text,record_revision::text FROM users WHERE id=$1', [returnUserId])).rows[0];
      const workflowState = async () => {
        const state = { policy: await returnState(), account: await accountState() };
        for (const table of ['company_offboarding_jobs', 'company_offboarding_events', 'company_offboarding_outbox']) state[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        for (const table of ['identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'identity_directory_user_events', 'identity_directory_user_outbox', 'identity_user_audit', 'identity_user_outbox']) state[table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        return state;
      };
      const returnDevices = [];
      for (const suffix of ['CANCEL', 'PHYSICAL', 'CHANGED']) {
        const registered = await request(base, '/api/devices', { method: 'POST', token, body: { assetId: 'SIGNED-RETURN-' + suffix, serialNumber: 'SIGNED-RETURN-SERIAL-' + suffix, manufacturer: 'Example Manufacturer', model: 'Actual return workflow laptop', deviceClass: 'laptop', platform: 'macos' } }); assert.equal(registered.status, 201, JSON.stringify(registered.body));
        const assigned = await request(base, '/api/devices/' + registered.body.id + '/assignment', { method: 'PUT', token, headers: { 'If-Match': deviceEtag(registered.body) }, body: { userId: returnUserId } }); assert.equal(assigned.status, 200, JSON.stringify(assigned.body)); returnDevices.push(assigned.body);
      }
      const devicesBefore = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM devices record ORDER BY id')).rows;
      const groupsBefore = (await identityDb.query('SELECT to_jsonb(record) AS row FROM group_members record ORDER BY to_jsonb(record)::text')).rows;
      const foreignBefore = (await identityDb.query('SELECT to_jsonb(record) AS row FROM users record WHERE identity_tenant_id(\'user\',id)<>$1 ORDER BY id', [activated.body.tenantId])).rows;
      const beforeWorkflow = await workflowState(); const beforeAccount = beforeWorkflow.account;
      const workflowCapabilities = await request(base, workflowRoute + '/capabilities', { token }); assert.equal(workflowCapabilities.status, 200, JSON.stringify(workflowCapabilities.body));
      assert.deepEqual(workflowCapabilities.body, { schemaVersion: 1, companyOffboardingProtocol: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, scope: 'account-and-local-licenses', requiresFreshMfa: true });
      const employeePreview = await request(base, previewRoute, { token }); assert.equal(employeePreview.status, 200, JSON.stringify(employeePreview.body));
      assert.deepEqual(employeePreview.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId,
        user: { id: returnUserId, name: restoredEmployee.body.displayName || restoredEmployee.body.username, userRevision: beforeAccount.record_revision, eligibilityRevision: beforeAccount.eligibility_revision, enabled: true }, licenseCount: 2 });
      const workflowInput = { workflowId: randomUUID(), userId: returnUserId, userRevision: employeePreview.body.user.userRevision, eligibilityRevision: employeePreview.body.user.eligibilityRevision, reason: 'Actual signed durable account and local license offboarding', confirm: true };
      assert.equal((await request(base, appBase + '/users/' + activated.body.administratorId + '/offboarding-preview', { token })).status, 403);
      assert.equal((await request(base, appBase + '/users/' + canonicalSubjects.get('production-ordinary') + '/offboarding-preview', { token })).status, 404);
      for (const route of [workflowRoute, workflowRoute + '/capabilities', previewRoute]) assert.equal((await request(base, route + '?tenantId=' + separateTenant, { token })).status, 400);
      for (const invalid of [{ ...workflowInput, confirm: false }, { ...workflowInput, confirm: 'true' }, { ...workflowInput, reason: 'too short' }, { ...workflowInput, tenantId: separateTenant }]) assert.equal((await request(base, workflowRoute, { method: 'POST', token, body: invalid })).status, 400);
      for (const field of ['userRevision', 'eligibilityRevision']) {
        const stale = await request(base, workflowRoute, { method: 'POST', token, body: { ...workflowInput, [field]: String(BigInt(workflowInput[field]) + 1n) } }); assert.equal(stale.status, 412, JSON.stringify(stale.body));
      }
      for (const rejectedToken of [expiredMfaOwner, revokedOwner.access_token]) {
        for (const route of [workflowRoute + '/capabilities', previewRoute]) { const denied = await request(base, route, { token: rejectedToken }); assert.ok([401, 428].includes(denied.status), JSON.stringify(denied.body)); }
        const denied = await request(base, workflowRoute, { method: 'POST', token: rejectedToken, body: workflowInput }); assert.ok([401, 428].includes(denied.status), JSON.stringify(denied.body));
      }
      assert.deepEqual(await workflowState(), beforeWorkflow);
      const workflowCreated = await request(base, workflowRoute, { method: 'POST', token, body: workflowInput, timeout: 60000 }); assert.equal(workflowCreated.status, 201, JSON.stringify(workflowCreated.body));
      const completedJob = workflowCreated.body; const workflow = completedJob.workflow;
      assert.deepEqual(Object.keys(completedJob).sort(), ['actorUserId', 'currentTarget', 'schemaVersion', 'tenantId', 'workflow']);
      assert.deepEqual([completedJob.schemaVersion, completedJob.actorUserId, completedJob.tenantId, workflow.id, workflow.userId, workflow.createdBy, workflow.reason, workflow.phase, workflow.totalLicenses, workflow.completedLicenses, workflow.failure],
        [1, activated.body.administratorId, activated.body.tenantId, workflowInput.workflowId, returnUserId, activated.body.administratorId, workflowInput.reason, 'completed_local', 2, 2, null]);
      assert.equal(workflow.requestedRevision, workflowInput.userRevision); assert.deepEqual(workflow.nextAssignments, []); assert.deepEqual(workflow.reviewAssignments, []);
      assert.ok(Number.isFinite(Date.parse(workflow.createdAt))); assert.ok(Date.parse(workflow.updatedAt) >= Date.parse(workflow.createdAt));
      const workflowEtag = '"company-offboarding-' + workflow.id + '-' + workflow.revision + '"'; assert.equal(workflowCreated.headers.get('etag'), workflowEtag); assert.equal(workflowCreated.headers.get('cache-control'), 'no-store');
      const afterAccount = await accountState(); assert.equal(afterAccount.enabled, false);
      for (const field of ['authorization_revision', 'eligibility_revision', 'record_revision']) assert.ok(BigInt(afterAccount[field]) > BigInt(beforeAccount[field]), field);
      assert.deepEqual(completedJob.currentTarget, { enabled: false, deleted: false, eligibilityRevision: afterAccount.eligibility_revision });
      const checkpoint = workflow.checkpoint; assert.deepEqual(Object.keys(checkpoint).sort(), ['schemaVersion', 'workflowId', 'tenantId', 'userId', 'actorUserId', 'operationId', 'action', 'beforeRevision', 'afterRevision', 'beforeEligibilityRevision', 'afterEligibilityRevision', 'createdAt', 'deliveryStatus'].sort());
      assert.match(checkpoint.operationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
      assert.deepEqual(checkpoint, { schemaVersion: 1, workflowId: workflow.id, tenantId: activated.body.tenantId, userId: returnUserId, actorUserId: activated.body.administratorId, operationId: checkpoint.operationId, action: 'disabled',
        beforeRevision: beforeAccount.record_revision, afterRevision: afterAccount.record_revision, beforeEligibilityRevision: beforeAccount.eligibility_revision, afterEligibilityRevision: afterAccount.eligibility_revision, createdAt: checkpoint.createdAt, deliveryStatus: 'pending' });
      const identityReceipt = (await identityDb.query(`SELECT receipt.*,outbox.status FROM identity_company_offboarding_receipts receipt JOIN identity_company_offboarding_outbox outbox USING(tenant_id,workflow_id) WHERE receipt.workflow_id=$1`, [workflow.id])).rows;
      assert.equal(identityReceipt.length, 1); assert.equal(identityReceipt[0].operation_id, checkpoint.operationId); assert.equal(identityReceipt[0].status, 'pending');
      assert.equal(identityReceipt[0].source.subject, payload(token).sub); assert.equal(identityReceipt[0].source.issuer, issuer); assert.deepEqual(identityReceipt[0].source.context, payload(token).identity_authorization);
      const mutationEvidence = (await identityDb.query(`SELECT event.id,event.action,event.actor,event.details,outbox.status FROM identity_directory_user_events event JOIN identity_directory_user_outbox outbox USING(id) WHERE event.id=$1 AND event.user_id=$2`, [checkpoint.operationId, returnUserId])).rows;
      assert.equal(mutationEvidence.length, 1); assert.equal(mutationEvidence[0].action, 'update'); assert.equal(mutationEvidence[0].status, 'pending');
      assert.deepEqual(mutationEvidence[0].actor, { issuer, subject: payload(token).sub, userId: activated.body.administratorId });
      assert.equal(mutationEvidence[0].details.beforeRevision, checkpoint.beforeRevision); assert.equal(mutationEvidence[0].details.afterRevision, checkpoint.afterRevision);
      assert.equal((await identityDb.query(`SELECT count(*)::integer AS count FROM identity_user_audit audit JOIN identity_user_outbox outbox USING(user_id,revision)
        WHERE audit.user_id=$1 AND audit.revision=$2 AND audit.actor=$3 AND audit.details->'enabled'='false'::jsonb AND outbox.payload->'enabled'='false'::jsonb`, [returnUserId, checkpoint.afterEligibilityRevision, payload(token).sub])).rows[0].count, 1);
      const durableJob = (await policyDb.query('SELECT job.*,company_offboarding_job_valid(job) AS valid FROM company_offboarding_jobs job WHERE id=$1 AND tenant_id=$2', [workflow.id, activated.body.tenantId])).rows[0];
      assert.equal(durableJob.valid, true); assert.deepEqual(durableJob.intent, workflowInput); assert.deepEqual(durableJob.state.checkpoint, checkpoint); assert.equal(durableJob.state.phase, 'completed_local'); assert.equal(String(durableJob.revision), workflow.revision);
      assert.equal(durableJob.state.items.length, 2); assert.ok(durableJob.state.items.every(item => item.status === 'released'));
      const childReceipts = (await policyDb.query(`SELECT events.*,outbox.status,license_company_event_valid(events) AS valid FROM license_company_events events JOIN license_company_outbox outbox ON outbox.id=events.id WHERE events.correlation_id=$1 ORDER BY events.license_id`, [workflow.id])).rows;
      assert.equal(childReceipts.length, 2);
      for (const receipt of childReceipts) {
        const assignment = workflowAssignments.find(item => item.pool_id === receipt.license_id); assert.ok(assignment);
        assert.deepEqual([receipt.type, receipt.tenant_id, receipt.actor_user_id, receipt.target_user_id, receipt.correlation_id, receipt.status, receipt.valid], ['app.license.released', activated.body.tenantId, activated.body.administratorId, returnUserId, workflow.id, 'pending', true]);
        assert.equal(receipt.before_state.assignment.id, assignment.assignment_id); assert.equal(receipt.before_state.source.grant_id, assignment.grant_id); assert.equal(String(receipt.before_revision), String(assignment.business_revision));
        assert.equal(receipt.proof.source.tokenId, payload(token).jti); assert.equal(receipt.proof.source.subject, payload(token).sub); assert.deepEqual(receipt.proof.source.context, payload(token).identity_authorization); assert.deepEqual(receipt.proof.checkpoint, receipt.proof.source);
        assert.equal(durableJob.state.items.find(item => item.assignmentId === assignment.assignment_id).eventId, receipt.id);
      }
      for (const table of ['license_assignments', 'license_assignment_sources']) assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM ' + table + ' WHERE license_id=ANY($1::uuid[])', [workflowAssignments.map(item => item.pool_id)])).rows[0].count, 0);
      const workflowGrants = (await policyDb.query('SELECT DISTINCT ON(grant_id) grant_id,state FROM license_grant_events WHERE grant_id=ANY($1::uuid[]) ORDER BY grant_id,version DESC', [workflowAssignments.map(item => item.grant_id)])).rows;
      assert.equal(workflowGrants.length, 2); assert.ok(workflowGrants.every(item => item.state === 'revoked'));
      const historyRows = (await policyDb.query(`SELECT event.*,outbox.status FROM company_offboarding_events event JOIN company_offboarding_outbox outbox USING(id,tenant_id) WHERE event.workflow_id=$1 ORDER BY event.revision DESC`, [workflow.id])).rows;
      assert.equal(historyRows.length, Number(workflow.revision)); assert.ok(historyRows.every(event => event.status === 'pending' && event.actor_user_id === activated.body.administratorId && event.authority.subject === payload(token).sub && event.authority.tenant.id === activated.body.tenantId));
      const history = await request(base, workflowRoute + '/' + workflow.id + '/history?page=1&limit=25', { token }); assert.equal(history.status, 200, JSON.stringify(history.body));
      assert.deepEqual(history.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, workflowId: workflow.id,
        events: historyRows.map(event => ({ id: event.id, revision: String(event.revision), phase: event.after_state.state.phase, actorUserId: event.actor_user_id, createdAt: event.created_at.toISOString(), deliveryStatus: 'pending', failure: event.after_state.state.failure,
          completedLicenses: event.after_state.state.items?.filter(item => item.status !== 'pending').length || 0, totalLicenses: event.after_state.state.items === null ? null : event.after_state.state.items.length })), total: historyRows.length, page: 1, limit: 25 });
      const afterWorkflow = await workflowState();
      const replay = await request(base, workflowRoute, { method: 'POST', token, body: workflowInput }); assert.equal(replay.status, 200, JSON.stringify(replay.body)); assert.deepEqual(replay.body, completedJob); assert.equal(replay.headers.get('etag'), workflowEtag);
      const reloaded = await request(base, workflowRoute + '/' + workflow.id, { token }); assert.equal(reloaded.status, 200, JSON.stringify(reloaded.body)); assert.deepEqual(reloaded.body, completedJob); assert.equal(reloaded.headers.get('etag'), workflowEtag);
      const listed = await request(base, workflowRoute, { token }); assert.equal(listed.status, 200, JSON.stringify(listed.body)); assert.deepEqual([listed.body.schemaVersion, listed.body.actorUserId, listed.body.tenantId, listed.body.total, listed.body.page, listed.body.limit], [1, activated.body.administratorId, activated.body.tenantId, 1, 1, 25]); assert.equal(listed.body.workflows[0].id, workflow.id);
      const staleContinue = await request(base, workflowRoute + '/' + workflow.id + '/continue', { method: 'POST', token, headers: { 'If-Match': '"company-offboarding-' + workflow.id + '-1"' }, body: { confirm: true, reason: workflowInput.reason, userRevision: workflowInput.userRevision, assignments: [] } }); assert.equal(staleContinue.status, 412, JSON.stringify(staleContinue.body));
      for (const suffix of ['', '/history']) assert.equal((await request(base, workflowRoute + '/' + workflow.id + suffix, { token: administrator.access_token })).status, 404);
      for (const route of [workflowRoute + '/' + workflow.id, workflowRoute + '/' + workflow.id + '/history']) assert.equal((await request(base, route + '?unknown=true', { token })).status, 400);
      assert.deepEqual(await workflowState(), afterWorkflow);
      for (const table of providerTables) assert.deepEqual(afterWorkflow.policy[table], beforeWorkflow.policy[table]);
      assert.deepEqual((await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM devices record ORDER BY id')).rows, devicesBefore);
      assert.deepEqual((await identityDb.query('SELECT to_jsonb(record) AS row FROM group_members record ORDER BY to_jsonb(record)::text')).rows, groupsBefore);
      assert.deepEqual((await identityDb.query('SELECT to_jsonb(record) AS row FROM users record WHERE identity_tenant_id(\'user\',id)<>$1 ORDER BY id', [activated.body.tenantId])).rows, foreignBefore);
      assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_assignments WHERE license_id=$1', [companyPool.body.id])).rows[0].count, 0);
      assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_provider_products WHERE license_id=$1', [companyPool.body.id])).rows[0].count, 0);
      assert.equal((await request(base, '/api/licenses/' + companyPool.body.id + '/assign', { method: 'POST', token: administrator.access_token, body: { assignee_type: 'user', assignee_id: canonicalSubjects.get('production-member') } })).status, 404);
      assert.equal((await request(base, '/api/identity/roles/catalog', { token })).status, 403); assert.deepEqual(payload(companyOwner.access_token).roles, []);
      const cleanupRoute = '/api/users/' + returnUserId + '/company-offboarding-groups';
      const cleanupQuery = '?workflowId=' + workflow.id + '&page=1&limit=25';
      const cleanupTarget = { enabled: false, eligibilityRevision: afterAccount.eligibility_revision };
      const cleanupEnvelope = { schemaVersion: 1, companyOffboardingGroupsProtocol: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, workflowId: workflow.id, userId: returnUserId, target: cleanupTarget };
      const { companyOffboardingGroupsProtocol, ...cleanupHistoryEnvelope } = cleanupEnvelope;
      const cleanupMemberships = (await identityDb.query(`SELECT collection.id AS "groupId",collection.name,collection.revision::text AS "groupRevision",member.membership_id AS "membershipId"
        FROM groups collection JOIN group_members member ON member.group_id=collection.id WHERE member.user_id=$1 ORDER BY collection.id`, [returnUserId])).rows;
      assert.equal(cleanupMemberships.length, 2); assert.deepEqual(new Set(cleanupMemberships.map(item => item.groupId)), new Set([group.body.id, secondGroup.body.id]));
      const cleanupInput = { workflowId: workflow.id, eligibilityRevision: cleanupTarget.eligibilityRevision, reason: 'Explicit signed removal of two captured own company group links', confirm: true,
        memberships: cleanupMemberships.map(({ name, ...membership }) => membership) };
      const cleanupState = async () => {
        const state = { workflow: await workflowState() };
        for (const table of ['users', 'groups', 'group_members', 'identity_group_audit', 'identity_group_outbox', 'identity_membership_origins', 'identity_membership_review_leases', 'identity_membership_review_audit', 'identity_directory_group_events', 'identity_directory_group_outbox', 'identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit']) {
          state[table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        }
        return state;
      };
      const beforeCleanup = await cleanupState();
      const groupPreview = await request(base, cleanupRoute + cleanupQuery, { token }); assert.equal(groupPreview.status, 200, JSON.stringify(groupPreview.body));
      assert.deepEqual(groupPreview.body, { ...cleanupEnvelope, groups: cleanupMemberships, total: 2, page: 1, limit: 25 }); assert.equal(groupPreview.headers.get('cache-control'), 'no-store');
      const emptyGroupHistory = await request(base, cleanupRoute + '/history' + cleanupQuery, { token }); assert.equal(emptyGroupHistory.status, 200, JSON.stringify(emptyGroupHistory.body));
      assert.deepEqual(emptyGroupHistory.body, { ...cleanupHistoryEnvelope, receipts: [], total: 0, page: 1, limit: 25 });
      const nextGroupPage = await request(base, cleanupRoute + '?workflowId=' + workflow.id + '&page=2', { token }); assert.equal(nextGroupPage.status, 200);
      assert.deepEqual(nextGroupPage.body, { ...cleanupEnvelope, groups: [], total: 2, page: 2, limit: 25 });
      for (const suffix of ['', '/history']) {
        for (const query of ['', '?workflowId=' + workflow.id + '&limit=24', '?workflowId=' + workflow.id + '&limit=26', '?workflowId=' + workflow.id + '&page=01', cleanupQuery + '&tenantId=' + separateTenant, cleanupQuery + '&unknown=true', cleanupQuery + '&workflowId=' + workflow.id]) {
          const invalid = await request(base, cleanupRoute + suffix + query, { token }); assert.equal(invalid.status, 400, JSON.stringify(invalid.body));
        }
        assert.equal((await request(base, cleanupRoute + suffix + cleanupQuery)).status, 401);
        assert.equal((await request(base, cleanupRoute + suffix + '?workflowId=' + randomUUID(), { token })).status, 409);
        assert.equal((await request(base, '/api/users/' + activated.body.administratorId + '/company-offboarding-groups' + suffix + cleanupQuery, { token })).status, 403);
        assert.equal((await request(base, '/api/users/' + canonicalSubjects.get('production-ordinary') + '/company-offboarding-groups' + suffix + cleanupQuery, { token })).status, 404);
        assert.equal((await request(base, '/api/users/' + created.body.id + '/company-offboarding-groups' + suffix + cleanupQuery, { token })).status, 409);
        assert.equal((await request(base, cleanupRoute + suffix + cleanupQuery, { token: administrator.access_token })).status, 404);
      }
      for (const [userId, status] of [[activated.body.administratorId, 403], [canonicalSubjects.get('production-ordinary'), 404], [created.body.id, 409]]) {
        const denied = await request(base, '/api/users/' + userId + '/company-offboarding-groups', { method: 'POST', token, body: cleanupInput }); assert.equal(denied.status, status, JSON.stringify(denied.body));
      }
      assert.equal((await request(base, cleanupRoute, { method: 'POST', token: administrator.access_token, body: cleanupInput })).status, 404);
      const invalidCleanupBodies = [{}, { ...cleanupInput, confirm: false }, { ...cleanupInput, confirm: 'true' }, { ...cleanupInput, reason: 'short' }, { ...cleanupInput, reason: 'x'.repeat(501) }, { ...cleanupInput, tenantId: separateTenant },
        { ...cleanupInput, eligibilityRevision: Number(cleanupTarget.eligibilityRevision) }, { ...cleanupInput, memberships: [] },
        { ...cleanupInput, memberships: Array.from({ length: 26 }, () => ({ groupId: randomUUID(), groupRevision: '1', membershipId: randomUUID() })) },
        { ...cleanupInput, memberships: [cleanupInput.memberships[0], cleanupInput.memberships[0]] },
        { ...cleanupInput, memberships: [{ ...cleanupInput.memberships[0], userId: returnUserId }] }];
      for (const invalid of invalidCleanupBodies) { const rejected = await request(base, cleanupRoute, { method: 'POST', token, body: invalid }); assert.equal(rejected.status, 400, JSON.stringify(rejected.body)); }
      assert.equal((await request(base, cleanupRoute + cleanupQuery, { method: 'POST', token, body: cleanupInput })).status, 400);
      assert.equal((await request(base, cleanupRoute, { method: 'POST', body: cleanupInput })).status, 401);
      for (const rejectedToken of [expiredMfaOwner, revokedOwner.access_token]) {
        for (const suffix of ['', '/history']) { const denied = await request(base, cleanupRoute + suffix + cleanupQuery, { token: rejectedToken }); assert.ok([401, 428].includes(denied.status), JSON.stringify(denied.body)); }
        const denied = await request(base, cleanupRoute, { method: 'POST', token: rejectedToken, body: cleanupInput }); assert.ok([401, 428].includes(denied.status), JSON.stringify(denied.body));
      }
      assert.deepEqual(await cleanupState(), beforeCleanup);
      await identityDb.query('CREATE SEQUENCE company_group_cleanup_write_attempts');
      await identityDb.query("CREATE FUNCTION observe_company_group_cleanup_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('company_group_cleanup_write_attempts'); RETURN OLD; END $$");
      await identityDb.query('CREATE TRIGGER observe_company_group_cleanup_write BEFORE DELETE ON group_members FOR EACH ROW EXECUTE FUNCTION observe_company_group_cleanup_write()');
      try {
        for (const [input, status] of [
          [{ ...cleanupInput, workflowId: randomUUID() }, 409],
          [{ ...cleanupInput, eligibilityRevision: String(BigInt(cleanupInput.eligibilityRevision) + 1n) }, 409],
          [{ ...cleanupInput, memberships: [cleanupInput.memberships[0], { ...cleanupInput.memberships[1], groupRevision: String(BigInt(cleanupInput.memberships[1].groupRevision) + 1n) }] }, 412],
          [{ ...cleanupInput, memberships: [cleanupInput.memberships[0], { ...cleanupInput.memberships[1], membershipId: randomUUID() }] }, 409],
          [{ ...cleanupInput, memberships: [cleanupInput.memberships[0], { groupId: foreignCleanupGroup.body.id, groupRevision: foreignCleanupGroup.body.revision, membershipId: randomUUID() }] }, 404],
          [{ ...cleanupInput, memberships: [cleanupInput.memberships[0], ...Array.from({ length: 24 }, () => ({ groupId: randomUUID(), groupRevision: '1', membershipId: randomUUID() }))] }, 404],
        ]) {
          const denied = await request(base, cleanupRoute, { method: 'POST', token, body: input }); assert.equal(denied.status, status, JSON.stringify(denied.body));
          assert.equal((await identityDb.query('SELECT is_called FROM company_group_cleanup_write_attempts')).rows[0].is_called, false);
          assert.deepEqual(await cleanupState(), beforeCleanup);
        }
      } finally {
        await identityDb.query('DROP TRIGGER observe_company_group_cleanup_write ON group_members'); await identityDb.query('DROP FUNCTION observe_company_group_cleanup_write()'); await identityDb.query('DROP SEQUENCE company_group_cleanup_write_attempts');
      }
      await identityDb.query("CREATE FUNCTION reject_company_group_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Explicit isolated first-child rollback oracle' USING ERRCODE='23514'; END $$");
      await identityDb.query('CREATE TRIGGER reject_company_group_cleanup BEFORE DELETE ON group_members FOR EACH ROW EXECUTE FUNCTION reject_company_group_cleanup()');
      try {
        const unconfirmed = await request(base, cleanupRoute, { method: 'POST', token, body: cleanupInput }); assert.equal(unconfirmed.status, 207, JSON.stringify(unconfirmed.body));
        assert.deepEqual(unconfirmed.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, workflowId: workflow.id, userId: returnUserId, correlationId: unconfirmed.body.correlationId,
          results: cleanupInput.memberships.map((member, index) => ({ groupId: member.groupId, membershipId: member.membershipId, status: index === 0 ? 'unconfirmed' : 'not_attempted', code: index === 0 ? 409 : null, operationId: null })) });
        assert.deepEqual(await cleanupState(), beforeCleanup);
      } finally { await identityDb.query('DROP TRIGGER reject_company_group_cleanup ON group_members'); await identityDb.query('DROP FUNCTION reject_company_group_cleanup()'); }
      const confirmedReadback = await request(base, cleanupRoute + cleanupQuery, { token }); assert.equal(confirmedReadback.status, 200); assert.deepEqual(confirmedReadback.body, groupPreview.body);
      const cleanedGroups = await request(base, cleanupRoute, { method: 'POST', token, body: cleanupInput }); assert.equal(cleanedGroups.status, 200, JSON.stringify(cleanedGroups.body));
      assert.match(cleanedGroups.body.correlationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
      assert.deepEqual(cleanedGroups.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, workflowId: workflow.id, userId: returnUserId, correlationId: cleanedGroups.body.correlationId,
        results: cleanupInput.memberships.map(item => ({ groupId: item.groupId, membershipId: item.membershipId, status: 'removed', code: 200, operationId: cleanedGroups.body.results.find(result => result.groupId === item.groupId)?.operationId })) });
      for (const result of cleanedGroups.body.results) assert.match(result.operationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
      const groupReceipts = (await identityDb.query(`SELECT receipt.*,outbox.status FROM identity_company_offboarding_group_receipts receipt JOIN identity_company_offboarding_group_outbox outbox USING(id)
        WHERE receipt.tenant_id=$1 AND receipt.workflow_id=$2 AND receipt.user_id=$3 ORDER BY receipt.created_at,receipt.id`, [activated.body.tenantId, workflow.id, returnUserId])).rows;
      assert.equal(groupReceipts.length, 2);
      for (const receipt of groupReceipts) {
        const captured = cleanupMemberships.find(item => item.groupId === receipt.group_id); const result = cleanedGroups.body.results.find(item => item.groupId === receipt.group_id); assert.ok(captured); assert.ok(result);
        assert.deepEqual([receipt.membership_id, receipt.operation_id, receipt.actor_user_id, receipt.status, receipt.reason], [captured.membershipId, result.operationId, activated.body.administratorId, 'pending', cleanupInput.reason]);
        assert.equal(String(receipt.before_group_revision), captured.groupRevision); assert.ok(BigInt(receipt.after_group_revision) > BigInt(captured.groupRevision));
        assert.equal((await identityDb.query('SELECT revision::text FROM groups WHERE id=$1', [receipt.group_id])).rows[0].revision, String(receipt.after_group_revision));
        assert.equal(receipt.source.tokenSha256, createHash('sha256').update('Bearer ' + token).digest('hex')); assert.equal(receipt.source.subject, payload(token).sub); assert.equal(receipt.source.issuer, issuer); assert.deepEqual(receipt.source.context, payload(token).identity_authorization);
        await identityDb.query('SELECT identity_company_offboarding_group_validate($1)', [receipt.id]);
        const canonical = (await identityDb.query('SELECT event.*,outbox.status FROM identity_directory_group_events event JOIN identity_directory_group_outbox outbox USING(id) WHERE event.id=$1', [receipt.operation_id])).rows;
        assert.equal(canonical.length, 1); assert.equal(canonical[0].action, 'member-remove'); assert.equal(canonical[0].group_id, receipt.group_id); assert.equal(canonical[0].tenant_id, activated.body.tenantId); assert.equal(canonical[0].status, 'pending');
        assert.deepEqual(canonical[0].actor, { issuer, subject: payload(token).sub, userId: activated.body.administratorId }); assert.equal(canonical[0].transaction_id, receipt.transaction_id);
        assert.equal(canonical[0].details.beforeRevision, String(receipt.before_group_revision)); assert.equal(canonical[0].details.afterRevision, String(receipt.after_group_revision));
        await assert.rejects(identityDb.query('UPDATE identity_company_offboarding_group_receipts SET reason=$2 WHERE id=$1', [receipt.id, 'No mutable cleanup history']), error => ['42501', '23514'].includes(error.code));
        await assert.rejects(identityDb.query('DELETE FROM identity_company_offboarding_group_outbox WHERE id=$1', [receipt.id]), error => ['42501', '23514'].includes(error.code));
      }
      const cleanupHistory = await request(base, cleanupRoute + '/history' + cleanupQuery, { token }); assert.equal(cleanupHistory.status, 200, JSON.stringify(cleanupHistory.body));
      assert.deepEqual(cleanupHistory.body, { ...cleanupHistoryEnvelope, receipts: groupReceipts.map(receipt => ({ id: receipt.id, groupId: receipt.group_id, name: receipt.name, membershipId: receipt.membership_id, operationId: receipt.operation_id,
        beforeGroupRevision: String(receipt.before_group_revision), afterGroupRevision: String(receipt.after_group_revision), actorUserId: receipt.actor_user_id, reason: receipt.reason, createdAt: receipt.created_at.toISOString(), deliveryStatus: 'pending' })), total: 2, page: 1, limit: 25 });
      const emptyCleanup = await request(base, cleanupRoute + cleanupQuery, { token }); assert.equal(emptyCleanup.status, 200); assert.deepEqual(emptyCleanup.body, { ...cleanupEnvelope, groups: [], total: 0, page: 1, limit: 25 });
      const afterCleanup = await cleanupState();
      assert.deepEqual(afterCleanup.workflow, beforeCleanup.workflow);
      for (const table of ['users', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit']) assert.deepEqual(afterCleanup[table], beforeCleanup[table]);
      assert.deepEqual(afterCleanup.group_members, beforeCleanup.group_members.filter(({ row }) => row.user_id !== returnUserId));
      const recoveredCleanup = await request(base, cleanupRoute, { method: 'POST', token, body: cleanupInput }); assert.equal(recoveredCleanup.status, 200, JSON.stringify(recoveredCleanup.body));
      assert.deepEqual(recoveredCleanup.body.results, cleanedGroups.body.results.map(result => ({ ...result, status: 'already_removed' }))); assert.deepEqual(await cleanupState(), afterCleanup);
      const futureGroupLink = await groupRequest(base, '/api/groups/' + cleanupMemberships[0].groupId + '/members', { method: 'POST', token, body: { userId: returnUserId } }); assert.equal(futureGroupLink.status, 200, JSON.stringify(futureGroupLink.body));
      const futureMember = (await identityDb.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2', [cleanupMemberships[0].groupId, returnUserId])).rows[0]; assert.notEqual(futureMember.membership_id, cleanupMemberships[0].membershipId);
      const beforeOldLinkRecovery = await cleanupState();
      const retainedRecovery = await request(base, cleanupRoute, { method: 'POST', token, body: cleanupInput }); assert.equal(retainedRecovery.status, 200, JSON.stringify(retainedRecovery.body));
      assert.deepEqual(retainedRecovery.body.results, recoveredCleanup.body.results); assert.deepEqual(await cleanupState(), beforeOldLinkRecovery);
      const accessRoute = '/api/users/' + returnUserId + '/company-offboarding-access';
      const accessQuery = kind => '?workflowId=' + workflow.id + '&kind=' + kind + '&page=1&limit=25';
      const accessEnvelope = { schemaVersion: 1, companyOffboardingAccessProtocol: 1, actorUserId: accessOperatorId, tenantId: activated.body.tenantId, workflowId: workflow.id, userId: returnUserId, target: cleanupTarget };
      const { companyOffboardingAccessProtocol, ...accessHistoryEnvelope } = accessEnvelope;
      const { target: accessTargetCheckpoint, ...accessCommandEnvelope } = accessHistoryEnvelope;
      assert.deepEqual(accessTargetCheckpoint, cleanupTarget);
      const accessState = async () => {
        const state = {};
        for (const table of ['users', 'identity_role_assignments', 'identity_role_audit', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit', 'identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'identity_company_offboarding_access_receipts', 'identity_company_offboarding_access_outbox', 'identity_authority_command_checkpoints', 'identity_authority_command_checkpoint_events', 'identity_authority_command_checkpoint_outbox']) state[table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        return state;
      };
      const capturedAccessState = await accessState();
      const accessCapabilities = await request(base, accessRoute + '/capabilities?workflowId=' + workflow.id, { token: accessOperator.access_token }); assert.equal(accessCapabilities.status, 200, JSON.stringify(accessCapabilities.body));
      assert.deepEqual(accessCapabilities.body, { ...accessEnvelope, permissions: ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['role', 'eligibility'] });
      for (const path of [accessRoute + '/capabilities?workflowId=' + workflow.id, accessRoute + accessQuery('role'), accessRoute + '/history' + accessQuery('eligibility')]) assert.equal((await request(base, path, { token })).status, 403);
      const onlyRoles = await request(base, accessRoute + '/capabilities?workflowId=' + workflow.id, { token: accessReader.access_token }); assert.equal(onlyRoles.status, 200, JSON.stringify(onlyRoles.body)); assert.deepEqual(onlyRoles.body.permissions, ['identities.roles.read']); assert.deepEqual(onlyRoles.body.supportedKinds, ['role']);
      assert.equal((await request(base, accessRoute + accessQuery('eligibility'), { token: accessReader.access_token })).status, 403);
      const accessPreviews = new Map();
      for (const kind of ['role', 'eligibility']) {
        const preview = await request(base, accessRoute + accessQuery(kind), { token: accessOperator.access_token }); assert.equal(preview.status, 200, JSON.stringify(preview.body)); assert.equal(preview.headers.get('cache-control'), 'no-store');
        const table = kind === 'role' ? 'identity_role_assignments' : 'identity_pim_eligibilities';
        const expected = await identityDb.transaction(async client => { await client.query("SET LOCAL timezone='UTC'"); return (await client.query(`SELECT id,role,encode(sha256(convert_to(to_jsonb(record)::text,'UTF8')),'hex') AS version,created_at,expires_at FROM ${table} record WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at,id`, [returnUserId])).rows; }, { readOnly: true });
        assert.deepEqual(new Set(preview.body.items.map(item => item.id)), new Set(expected.map(item => item.id)));
        assert.deepEqual({ ...preview.body, items: [] }, { ...accessEnvelope, kind, canRevoke: true, items: [], total: expected.length, page: 1, limit: 25 });
        for (const item of preview.body.items) {
          const row = expected.find(record => record.id === item.id); const protectedRole = require('../../../../../packages/directory-role-contract').PROTECTED.includes(row.role);
          assert.deepEqual(item, { id: row.id, role: row.role, version: row.version, createdAt: row.created_at.toISOString(), expiresAt: row.expires_at?.toISOString() || null, canRevoke: !protectedRole, blockedReason: protectedRole ? 'protected_role' : null });
        }
        accessPreviews.set(kind, preview.body);
        const empty = await request(base, accessRoute + '/history' + accessQuery(kind), { token: accessOperator.access_token }); assert.equal(empty.status, 200); assert.deepEqual(empty.body, { ...accessHistoryEnvelope, kind, receipts: [], total: 0, page: 1, limit: 25 });
        for (const suffix of ['', '/history']) for (const query of ['?workflowId=' + workflow.id, accessQuery(kind) + '&tenantId=' + separateTenant, accessQuery(kind) + '&workflowId=' + workflow.id, '?workflowId=' + workflow.id + '&kind=' + kind + '&limit=24']) assert.equal((await request(base, accessRoute + suffix + query, { token: accessOperator.access_token })).status, 400);
      }
      const directAccessItem = accessPreviews.get('role').items.find(item => item.id === accessRole.body.id); const protectedAccessItem = accessPreviews.get('role').items.find(item => item.id === accessProtectedRole.body.id); assert.ok(directAccessItem); assert.equal(protectedAccessItem.canRevoke, false);
      const accessInput = { workflowId: workflow.id, eligibilityRevision: cleanupTarget.eligibilityRevision, kind: 'role', reason: 'Explicit original canonical role cleanup after durable disabled account receipt', confirm: true, items: [{ id: directAccessItem.id, version: directAccessItem.version }] };
      assert.equal((await request(base, accessRoute, { method: 'POST', token, body: accessInput })).status, 403);
      assert.equal((await request(base, accessRoute, { method: 'POST', token: accessReader.access_token, body: accessInput })).status, 403);
      for (const invalid of [{ ...accessInput, confirm: false }, { ...accessInput, tenantId: activated.body.tenantId }, { ...accessInput, items: [] }, { ...accessInput, items: [accessInput.items[0], accessInput.items[0]] }, { ...accessInput, items: [{ ...accessInput.items[0], version: 'A'.repeat(64) }] }]) assert.equal((await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: invalid })).status, 400);
      assert.equal((await request(base, accessRoute + accessQuery('role'), { method: 'POST', token: accessOperator.access_token, body: accessInput })).status, 400);
      for (const [input, expectedStatus] of [[{ ...accessInput, workflowId: randomUUID() }, 409], [{ ...accessInput, eligibilityRevision: String(BigInt(accessInput.eligibilityRevision) + 1n) }, 409], [{ ...accessInput, items: [accessInput.items[0], { id: protectedAccessItem.id, version: protectedAccessItem.version }] }, 403], [{ ...accessInput, items: [accessInput.items[0], { id: accessActiveAssignment.id, version: '0'.repeat(64) }] }, 412]]) {
        const denied = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: input }); assert.equal(denied.status, expectedStatus, JSON.stringify(denied.body)); assert.deepEqual(await accessState(), capturedAccessState);
      }
      assert.equal((await request(base, accessRoute + '/capabilities?workflowId=' + workflow.id, { token: administrator.access_token })).status, 409);
      await identityDb.query("CREATE FUNCTION reject_company_access_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Explicit isolated original role-child rollback oracle' USING ERRCODE='23514'; END $$");
      await identityDb.query('CREATE TRIGGER reject_company_access_cleanup BEFORE UPDATE ON identity_role_assignments FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL) EXECUTE FUNCTION reject_company_access_cleanup()');
      try {
        const activeItem = accessPreviews.get('role').items.find(item => item.id === accessActiveAssignment.id); assert.ok(activeItem);
        const attempted = [accessInput.items[0], { id: activeItem.id, version: activeItem.version }];
        const rolledBack = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: { ...accessInput, items: attempted } }); assert.equal(rolledBack.status, 207, JSON.stringify(rolledBack.body));
        assert.deepEqual(rolledBack.body.results, attempted.map((item, index) => ({ id: item.id, status: index === 0 ? 'unconfirmed' : 'not_attempted', code: index === 0 ? 409 : null, checkpointId: null }))); assert.deepEqual(await accessState(), capturedAccessState);
      } finally { await identityDb.query('DROP TRIGGER reject_company_access_cleanup ON identity_role_assignments'); await identityDb.query('DROP FUNCTION reject_company_access_cleanup()'); }
      const roleRevoked = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: accessInput }); assert.equal(roleRevoked.status, 200, JSON.stringify(roleRevoked.body));
      assert.deepEqual(roleRevoked.body, { ...accessCommandEnvelope, kind: 'role', correlationId: roleRevoked.body.correlationId, results: [{ id: directAccessItem.id, status: 'revoked', code: 200, checkpointId: roleRevoked.body.results[0].checkpointId }] });
      const accessNewGrant = await request(base, '/api/users/' + returnUserId + '/roles', { method: 'POST', token: accessOperator.access_token, body: { role: directAccessItem.role, durationSeconds: 3600, reason: 'A later independent canonical regrant must survive original ID recovery' } }); assert.equal(accessNewGrant.status, 201, JSON.stringify(accessNewGrant.body)); assert.notEqual(accessNewGrant.body.id, directAccessItem.id);
      const beforeAccessRecovery = await accessState(); const accessRecovery = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: accessInput }); assert.equal(accessRecovery.status, 200, JSON.stringify(accessRecovery.body)); assert.deepEqual(accessRecovery.body.results, roleRevoked.body.results.map(result => ({ ...result, status: 'already_revoked' }))); assert.deepEqual(await accessState(), beforeAccessRecovery);
      const protectedAdminPreview = await request(base, accessRoute + accessQuery('role'), { token: accessReviewer.access_token }); assert.equal(protectedAdminPreview.status, 200); assert.equal(protectedAdminPreview.body.items.find(item => item.id === protectedAccessItem.id).canRevoke, true);
      const protectedRevoked = await request(base, accessRoute, { method: 'POST', token: accessReviewer.access_token, body: { ...accessInput, items: [{ id: protectedAccessItem.id, version: protectedAccessItem.version }] } }); assert.equal(protectedRevoked.status, 200, JSON.stringify(protectedRevoked.body)); assert.equal(protectedRevoked.body.results[0].status, 'revoked');
      const eligibilityInput = { ...accessInput, kind: 'eligibility', items: accessPreviews.get('eligibility').items.map(({ id, version }) => ({ id, version })) };
      const eligibleRevoked = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: eligibilityInput }); assert.equal(eligibleRevoked.status, 200, JSON.stringify(eligibleRevoked.body)); assert.equal(eligibleRevoked.body.results.length, 2); assert.ok(eligibleRevoked.body.results.every(result => result.status === 'revoked' && result.code === 200));
      assert.deepEqual((await identityDb.query('SELECT id,state FROM identity_pim_requests WHERE id=ANY($1::uuid[]) ORDER BY id', [[accessActiveRequest.body.id, accessPendingRequest.body.id]])).rows, [{ id: accessActiveRequest.body.id, state: 'revoked' }, { id: accessPendingRequest.body.id, state: 'cancelled' }].sort((left, right) => left.id.localeCompare(right.id)));
      assert.ok((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [accessActiveAssignment.id])).rows[0].revoked_at);
      assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [accessNewGrant.body.id])).rows[0].revoked_at, null);
      const accessReceipts = (await identityDb.query(`SELECT receipt.*,outbox.status,checkpoint.transaction_id AS checkpoint_transaction_id,checkpoint.user_id AS checkpoint_user_id,checkpoint.original_context,checkpoint.token_sha256,checkpoint.issuer AS checkpoint_issuer,checkpoint.subject AS checkpoint_subject,checkpoint.valid_until AS checkpoint_valid_until,checkpoint.created_at AS checkpoint_created_at,checkpoint_outbox.status AS checkpoint_status
        FROM identity_company_offboarding_access_receipts receipt JOIN identity_company_offboarding_access_outbox outbox USING(id) JOIN identity_authority_command_checkpoints checkpoint ON checkpoint.id=receipt.checkpoint_id JOIN identity_authority_command_checkpoint_outbox checkpoint_outbox ON checkpoint_outbox.id=checkpoint.id WHERE receipt.tenant_id=$1 AND receipt.workflow_id=$2 ORDER BY receipt.created_at,receipt.id`, [activated.body.tenantId, workflow.id])).rows;
      assert.equal(accessReceipts.length, 4);
      for (const record of accessReceipts) {
        const original = record.actor_user_id === accessOperatorId ? accessOperator.access_token : accessReviewer.access_token; const claims = payload(original);
        assert.equal(record.checkpoint_status, 'pending'); assert.equal(record.status, 'pending'); assert.equal(record.checkpoint_transaction_id, record.transaction_id); assert.equal(record.checkpoint_user_id, record.actor_user_id); assert.equal(record.checkpoint_issuer, issuer); assert.equal(record.checkpoint_subject, claims.sub); assert.deepEqual(record.original_context, claims.identity_authorization);
        assert.equal(record.token_sha256, createHash('sha256').update(JSON.stringify(claims.jti)).digest('hex')); assert.ok(record.valid_until.getTime() <= (claims.auth_time + 300) * 1000); assert.ok(record.valid_until > record.checkpoint_created_at);
        assert.equal(record.valid_until.getTime(), record.source.validUntil * 1000); assert.ok(record.created_at < record.valid_until); assert.ok(record.checkpoint_created_at >= record.created_at);
        assert.ok(record.checkpoint_valid_until.getTime() <= claims.exp * 1000); assert.ok(record.checkpoint_valid_until > record.checkpoint_created_at);
        assert.equal(record.source.tokenSha256, createHash('sha256').update('Bearer ' + original).digest('hex')); assert.deepEqual(record.source.context, claims.identity_authorization);
        await identityDb.query('SELECT identity_company_offboarding_access_validate($1)', [record.id]);
        await assert.rejects(identityDb.query('UPDATE identity_company_offboarding_access_receipts SET reason=$2 WHERE id=$1', [record.id, 'Cannot rewrite canonical offboarding evidence']), error => ['42501', '23514'].includes(error.code));
        await assert.rejects(identityDb.query('DELETE FROM identity_company_offboarding_access_outbox WHERE id=$1', [record.id]), error => ['42501', '23514'].includes(error.code));
      }
      const retainedAccessState = await accessState();
      const eligibleRecovery = await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: eligibilityInput }); assert.equal(eligibleRecovery.status, 200, JSON.stringify(eligibleRecovery.body)); assert.deepEqual(eligibleRecovery.body.results, eligibleRevoked.body.results.map(result => ({ ...result, status: 'already_revoked' }))); assert.deepEqual(await accessState(), retainedAccessState);
      for (const kind of ['role', 'eligibility']) {
        const history = await request(base, accessRoute + '/history' + accessQuery(kind), { token: accessOperator.access_token }); assert.equal(history.status, 200, JSON.stringify(history.body));
        assert.deepEqual(history.body, { ...accessHistoryEnvelope, kind, receipts: accessReceipts.filter(record => record.kind === kind).map(record => ({ id: record.id, resourceId: record.resource_id, role: record.role, version: record.version, kind: record.kind, checkpointId: record.checkpoint_id, actorUserId: record.actor_user_id, correlationId: record.correlation_id, reason: record.reason, createdAt: record.created_at.toISOString(), deliveryStatus: 'pending' })), total: 2, page: 1, limit: 25 });
      }
      assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [activated.body.administratorId])).rows[0].count, 0);
      process.stdout.write('Slice18 signed: genuine separate no-profile/no-company-apps canonical operator; roleless Owner denied; protected revocation needs actual admin; exact UTC row hashes; original checkpoint/outbox evidence; original-ID recovery preserves later role grant; actual PIM active/pending cascade verified.\n');
      const deviceReturnBase = '/api/devices/returns'; const deviceOffboardingRoute = '/api/devices/users/' + returnUserId + '/offboarding-returns';
      const deviceReturnEnvelope = { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId };
      const deviceOffboardingEnvelope = { ...deviceReturnEnvelope, deviceOffboardingReturnsProtocol: 1, workflowId: workflow.id, userId: returnUserId, target: cleanupTarget, permissions: require('../../../../../packages/device-inventory-contract').INVENTORY_PERMISSIONS, managementMode: 'inventory-only' };
      const deviceReturnQuery = '?workflowId=' + workflow.id + '&page=1&limit=25';
      const returnEtag = value => '"device-return-' + value.id + '-' + value.revision + '-' + value.currentDeviceRevision + '"';
      const returnFields = ['id', 'tenantId', 'workflowId', 'userId', 'deviceId', 'assignmentId', 'assetId', 'serialNumber', 'revision', 'deviceRevision', 'currentDeviceRevision', 'status', 'reason', 'actorUserId', 'requestedAt', 'eligibilityRevision', 'closedAt', 'closedByUserId', 'operationId', 'closingOperationId', 'inventoryOperationId', 'deliveryStatus'].sort();
      const verifyReturn = value => {
        assert.deepEqual(Object.keys(value).sort(), returnFields);
        for (const field of ['id', 'tenantId', 'workflowId', 'userId', 'deviceId', 'assignmentId', 'actorUserId', 'operationId']) assert.match(value[field], /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
        for (const field of ['revision', 'deviceRevision', 'currentDeviceRevision', 'eligibilityRevision']) { assert.equal(typeof value[field], 'string'); assert.match(value[field], /^[1-9][0-9]*$/u); assert.ok(BigInt(value[field]) <= 9223372036854775807n); }
        assert.ok(['requested', 'returned', 'cancelled', 'assignment_changed'].includes(value.status)); assert.equal(value.deliveryStatus, 'pending'); assert.ok(Number.isFinite(Date.parse(value.requestedAt)));
        const original = returnDevices.find(unit => unit.id === value.deviceId); assert.ok(original); assert.equal(value.assignmentId, original.assignmentId); assert.equal(value.deviceRevision, original.revision); assert.equal(value.assetId, original.assetId); assert.equal(value.serialNumber, original.serialNumber);
        assert.equal(value.tenantId, activated.body.tenantId); assert.equal(value.workflowId, workflow.id); assert.equal(value.userId, returnUserId); assert.equal(value.eligibilityRevision, cleanupTarget.eligibilityRevision);
        if (value.status === 'requested') { assert.equal(value.closedAt, null); assert.equal(value.closedByUserId, null); assert.equal(value.closingOperationId, null); assert.equal(value.inventoryOperationId, null); }
        else { assert.ok(Number.isFinite(Date.parse(value.closedAt))); assert.equal(value.closedByUserId, activated.body.administratorId); }
        return value;
      };
      const inventoryReturnState = async () => {
        const tables = (await inventoryFixture.db.query("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND (tablename='devices' OR tablename LIKE 'device_inventory_%' OR tablename LIKE 'device_return%') ORDER BY tablename")).rows;
        const state = {}; for (const { tablename } of tables) state[tablename] = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM ' + tablename + ' record ORDER BY to_jsonb(record)::text')).rows; return state;
      };
      const originalInventoryState = async () => {
        const state = {}; for (const table of ['devices', 'device_inventory_assignments', 'device_inventory_events', 'device_inventory_outbox']) state[table] = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM ' + table + ' record ORDER BY to_jsonb(record)::text')).rows; return state;
      };
      const offboardingSourceCalls = []; const inventorySourceCalls = []; let survivingReturn;
      const observeDeviceSource = incoming => { if (incoming.url === '/api/identity/device-offboarding') offboardingSourceCalls.push({ method: incoming.method, authorization: incoming.headers.authorization }); if (incoming.url === '/api/identity/device-inventory') inventorySourceCalls.push({ method: incoming.method, authorization: incoming.headers.authorization }); };
      identityServer.prependListener('request', observeDeviceSource);
      try {
        const inventorySource = await request(base, '/api/identity/device-inventory', { token }); assert.equal(inventorySource.status, 200, JSON.stringify(inventorySource.body)); assert.equal(Object.keys(inventorySource.body).length, 11);
        const disabledSource = await request(base, '/api/identity/device-offboarding', { method: 'POST', token, body: { workflowId: workflow.id, userId: returnUserId } }); assert.equal(disabledSource.status, 200, JSON.stringify(disabledSource.body));
        assert.deepEqual(Object.keys(disabledSource.body).sort(), [...Object.keys(inventorySource.body), 'deviceOffboardingReturnsProtocol', 'parent'].sort());
        assert.deepEqual(disabledSource.body, { ...inventorySource.body, deviceOffboardingReturnsProtocol: 1, target: { id: returnUserId, ...cleanupTarget }, parent: { workflowId: workflow.id, tenantId: activated.body.tenantId, userId: returnUserId, action: checkpoint.action, operationId: checkpoint.operationId, afterRevision: checkpoint.afterRevision, afterEligibilityRevision: checkpoint.afterEligibilityRevision, createdAt: checkpoint.createdAt, deliveryStatus: 'pending' } });
        const returnCapabilities = await request(base, deviceReturnBase + '/capabilities', { token }); assert.equal(returnCapabilities.status, 200, JSON.stringify(returnCapabilities.body)); assert.deepEqual(returnCapabilities.body, { ...deviceReturnEnvelope, deviceReturnsProtocol: 1, permissions: inventorySource.body.permissions, managementMode: 'inventory-only' });
        const offboardingReturnCapabilities = await request(base, deviceOffboardingRoute + '/capabilities?workflowId=' + workflow.id, { token }); assert.equal(offboardingReturnCapabilities.status, 200, JSON.stringify(offboardingReturnCapabilities.body)); assert.deepEqual(offboardingReturnCapabilities.body, deviceOffboardingEnvelope);
        const deviceReturnPreview = await request(base, deviceOffboardingRoute + deviceReturnQuery, { token }); assert.equal(deviceReturnPreview.status, 200, JSON.stringify(deviceReturnPreview.body));
        assert.deepEqual({ ...deviceReturnPreview.body, devices: [] }, { ...deviceOffboardingEnvelope, devices: [], total: 3, page: 1, limit: 25 });
        assert.deepEqual([...deviceReturnPreview.body.devices].sort((left, right) => left.deviceId.localeCompare(right.deviceId)), returnDevices.map(unit => ({ deviceId: unit.id, assetId: unit.assetId, serialNumber: unit.serialNumber, deviceRevision: unit.revision, assignmentId: unit.assignmentId, openRequestId: null })).sort((left, right) => left.deviceId.localeCompare(right.deviceId)));
        const deviceReturnInput = { workflowId: workflow.id, eligibilityRevision: cleanupTarget.eligibilityRevision, reason: 'Actual signed original inventory assignment return request after durable disabled parent', confirm: true, items: returnDevices.map(unit => ({ deviceId: unit.id, deviceRevision: unit.revision, assignmentId: unit.assignmentId, requestId: randomUUID() })) };
        const beforeDeviceRequests = await inventoryReturnState(); const beforeDeviceInventory = await originalInventoryState();
        for (const path of [deviceReturnBase, deviceOffboardingRoute + deviceReturnQuery]) assert.equal((await request(base, path)).status, 401);
        assert.equal((await request(base, deviceReturnBase + '/capabilities', { token: accessOperator.access_token })).status, 403);
        for (const invalid of [{ ...deviceReturnInput, confirm: false }, { ...deviceReturnInput, tenantId: activated.body.tenantId }, { ...deviceReturnInput, items: [] }, { ...deviceReturnInput, items: [deviceReturnInput.items[0], deviceReturnInput.items[0]] }, { ...deviceReturnInput, items: [{ ...deviceReturnInput.items[0], deviceRevision: 2 }] }]) assert.equal((await request(base, deviceOffboardingRoute, { method: 'POST', token, body: invalid })).status, 400);
        for (const query of ['?page=01', '?limit=24', '?status=unavailable', '?tenantId=' + activated.body.tenantId]) assert.equal((await request(base, deviceReturnBase + query, { token })).status, 400);
        await inventoryFixture.db.query('CREATE SEQUENCE signed_device_return_attempts');
        await inventoryFixture.db.query("CREATE FUNCTION observe_signed_device_return() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('signed_device_return_attempts'); RETURN NEW; END $$");
        await inventoryFixture.db.query('CREATE TRIGGER observe_signed_device_return BEFORE INSERT ON device_return_events FOR EACH ROW EXECUTE FUNCTION observe_signed_device_return()');
        try {
        for (const [items, expectedStatus] of [[deviceReturnInput.items.map((item, index) => index === 1 ? { ...item, deviceRevision: String(BigInt(item.deviceRevision) + 1n) } : item), 409], [deviceReturnInput.items.map((item, index) => index === 1 ? { ...item, assignmentId: randomUUID() } : item), 409]]) {
          const denied = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: { ...deviceReturnInput, items } }); assert.equal(denied.status, expectedStatus, JSON.stringify(denied.body)); assert.deepEqual(await inventoryReturnState(), beforeDeviceRequests);
          assert.equal((await inventoryFixture.db.query('SELECT is_called FROM signed_device_return_attempts')).rows[0].is_called, false);
        }
        } finally { await inventoryFixture.db.query('DROP TRIGGER observe_signed_device_return ON device_return_events'); await inventoryFixture.db.query('DROP FUNCTION observe_signed_device_return()'); await inventoryFixture.db.query('DROP SEQUENCE signed_device_return_attempts'); }
        await inventoryFixture.db.query("CREATE FUNCTION reject_signed_device_return() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Actual isolated child rollback without hiding earlier committed requests' USING ERRCODE='23514'; END $$");
        await inventoryFixture.db.query('CREATE TRIGGER reject_signed_device_return BEFORE INSERT ON device_return_events FOR EACH ROW EXECUTE FUNCTION reject_signed_device_return()');
        try {
          const rolledBack = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: deviceReturnInput }); assert.equal(rolledBack.status, 207, JSON.stringify(rolledBack.body)); assert.deepEqual(rolledBack.body.results, deviceReturnInput.items.map((item, index) => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: index === 0 ? 'unconfirmed' : 'not_attempted', code: index === 0 ? 409 : null, operationId: null }))); assert.deepEqual(await inventoryReturnState(), beforeDeviceRequests);
        } finally { await inventoryFixture.db.query('DROP TRIGGER reject_signed_device_return ON device_return_events'); await inventoryFixture.db.query('DROP FUNCTION reject_signed_device_return()'); }
        const createdRequests = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: deviceReturnInput }); assert.equal(createdRequests.status, 200, JSON.stringify(createdRequests.body));
        assert.deepEqual(createdRequests.body, { ...deviceReturnEnvelope, workflowId: workflow.id, userId: returnUserId, correlationId: createdRequests.body.correlationId, results: deviceReturnInput.items.map(item => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'requested', code: 200, operationId: createdRequests.body.results.find(result => result.requestId === item.requestId)?.operationId })) }); assert.deepEqual(await originalInventoryState(), beforeDeviceInventory);
        const pending = [];
        for (const item of deviceReturnInput.items) {
          const detail = await request(base, deviceReturnBase + '/' + item.requestId, { token }); assert.equal(detail.status, 200, JSON.stringify(detail.body)); const value = verifyReturn(detail.body); pending.push(value); assert.equal(detail.headers.get('etag'), returnEtag(value)); assert.equal(value.reason, deviceReturnInput.reason); assert.equal(value.status, 'requested'); assert.equal(value.revision, '1'); assert.equal(value.operationId, createdRequests.body.results.find(result => result.requestId === item.requestId).operationId);
          const events = await request(base, deviceReturnBase + '/' + item.requestId + '/history?page=1&limit=25', { token }); assert.equal(events.status, 200, JSON.stringify(events.body)); assert.equal(events.body.events.length, 1); assert.equal(events.body.events[0].id, value.operationId); assert.equal(events.body.events[0].type, 'device.return.requested'); assert.equal(events.body.events[0].version, 1); assert.equal(events.body.events[0].before, null); assert.deepEqual(events.body.events[0].after, { revision: '1', status: 'requested' }); assert.equal(events.body.events[0].inventoryOperationId, null); assert.equal(events.body.events[0].deliveryStatus, 'pending');
          const creation = (await inventoryFixture.db.query('SELECT event.*,outbox.status AS delivery_status FROM device_return_events event JOIN device_return_outbox outbox USING(id,tenant_id) WHERE event.id=$1', [value.operationId])).rows; assert.equal(creation.length, 1); const actual = creation[0]; assert.equal(actual.version, 1); assert.equal(actual.delivery_status, 'pending'); assert.equal(actual.request_id, item.requestId); assert.equal(actual.before_request, null); assert.equal(actual.after_request.operation_id, actual.id); assert.equal(actual.after_request.assignment_id, item.assignmentId); assert.equal(actual.after_request.device_revision, item.deviceRevision); assert.equal(actual.proof.source.tokenId, payload(token).jti); assert.equal(actual.proof.source.issuer, issuer); assert.deepEqual(actual.proof.source.context, payload(token).identity_authorization); assert.deepEqual(actual.proof.source.parent, disabledSource.body.parent); assert.deepEqual(actual.proof.item, item); assert.equal(actual.actor_user_id, activated.body.administratorId); assert.ok(actual.created_at < actual.valid_until); assert.equal(actual.valid_until.getTime(), actual.proof.source.validUntil * 1000); assert.ok(actual.valid_until.getTime() <= (payload(token).auth_time + 300) * 1000); assert.equal((await inventoryFixture.db.query('SELECT count(*)::int AS count FROM device_inventory_events WHERE transaction_id=$1', [actual.transaction_id])).rows[0].count, 0); await inventoryFixture.db.query('SELECT device_returns_validate($1)', [item.requestId]);
          assert.equal((await request(base, deviceReturnBase + '/' + item.requestId, { token: administrator.access_token })).status, 404);
        }
        const afterDeviceRequests = await inventoryReturnState(); const requestRecovery = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: deviceReturnInput }); assert.equal(requestRecovery.status, 200, JSON.stringify(requestRecovery.body)); assert.deepEqual(requestRecovery.body.results, createdRequests.body.results.map(result => ({ ...result, status: 'already_requested' }))); assert.deepEqual(await inventoryReturnState(), afterDeviceRequests);
        const cancellation = { action: 'cancelled', reason: 'Actual operator cancels the captured return task without changing the device', confirm: true }; const cancelPath = deviceReturnBase + '/' + pending[0].id + '/decision';
        assert.equal((await request(base, cancelPath, { method: 'POST', token, body: cancellation })).status, 428);
        assert.equal((await request(base, cancelPath, { method: 'POST', token, headers: { 'If-Match': returnEtag({ ...pending[0], currentDeviceRevision: '1' }) }, body: cancellation })).status, 412);
        const cancelled = await request(base, cancelPath, { method: 'POST', token, headers: { 'If-Match': returnEtag(pending[0]) }, body: cancellation }); assert.equal(cancelled.status, 200, JSON.stringify(cancelled.body)); assert.equal(cancelled.body.outcome, 'cancelled'); assert.equal(verifyReturn(cancelled.body.request).status, 'cancelled'); assert.equal(cancelled.body.request.revision, '2'); assert.equal(cancelled.body.request.reason, deviceReturnInput.reason); assert.equal(cancelled.body.request.inventoryOperationId, null); assert.equal(cancelled.headers.get('etag'), returnEtag(cancelled.body.request)); assert.deepEqual(await originalInventoryState(), beforeDeviceInventory);
        const physicalInput = { action: 'returned', reason: 'Actual physical laptop received and original assignment explicitly released', confirm: true }; const physicalPath = deviceReturnBase + '/' + pending[1].id + '/decision';
        const beforeAtomicDecision = await inventoryReturnState(); await inventoryFixture.db.query('CREATE SEQUENCE signed_inventory_release_attempts');
        await inventoryFixture.db.query("CREATE FUNCTION observe_signed_inventory_release() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('signed_inventory_release_attempts'); RETURN NEW; END $$"); await inventoryFixture.db.query("CREATE TRIGGER observe_signed_inventory_release BEFORE INSERT ON device_inventory_events FOR EACH ROW WHEN (NEW.action='release') EXECUTE FUNCTION observe_signed_inventory_release()");
        await inventoryFixture.db.query("CREATE FUNCTION reject_signed_return_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM device_return_events WHERE id=NEW.id AND type='device.return.confirmed') THEN RAISE EXCEPTION 'Actual missing return decision outbox must roll back the original inventory release' USING ERRCODE='23514'; END IF; RETURN NEW; END $$"); await inventoryFixture.db.query('CREATE TRIGGER reject_signed_return_outbox BEFORE INSERT ON device_return_outbox FOR EACH ROW EXECUTE FUNCTION reject_signed_return_outbox()');
        try {
          const atomicRollback = await request(base, physicalPath, { method: 'POST', token, headers: { 'If-Match': returnEtag(pending[1]) }, body: physicalInput }); assert.equal(atomicRollback.status, 409, JSON.stringify(atomicRollback.body)); assert.equal((await inventoryFixture.db.query('SELECT is_called FROM signed_inventory_release_attempts')).rows[0].is_called, true); assert.deepEqual(await inventoryReturnState(), beforeAtomicDecision);
        } finally { await inventoryFixture.db.query('DROP TRIGGER reject_signed_return_outbox ON device_return_outbox'); await inventoryFixture.db.query('DROP FUNCTION reject_signed_return_outbox()'); await inventoryFixture.db.query('DROP TRIGGER observe_signed_inventory_release ON device_inventory_events'); await inventoryFixture.db.query('DROP FUNCTION observe_signed_inventory_release()'); await inventoryFixture.db.query('DROP SEQUENCE signed_inventory_release_attempts'); }
        const physicallyReturned = await request(base, physicalPath, { method: 'POST', token, headers: { 'If-Match': returnEtag(pending[1]) }, body: physicalInput }); assert.equal(physicallyReturned.status, 200, JSON.stringify(physicallyReturned.body)); const actualReturn = verifyReturn(physicallyReturned.body.request); assert.equal(physicallyReturned.body.outcome, 'returned'); assert.equal(actualReturn.status, 'returned'); assert.equal(actualReturn.revision, '2'); assert.equal(actualReturn.closingOperationId, physicallyReturned.body.operationId); assert.match(actualReturn.inventoryOperationId, /^[a-f0-9-]{36}$/u); assert.equal(BigInt(actualReturn.currentDeviceRevision), BigInt(actualReturn.deviceRevision) + 1n); assert.equal(physicallyReturned.headers.get('etag'), returnEtag(actualReturn));
        const releasedEvidence = (await inventoryFixture.db.query('SELECT event.*,outbox.status FROM device_inventory_events event JOIN device_inventory_outbox outbox USING(id) WHERE event.id=$1', [actualReturn.inventoryOperationId])).rows; assert.equal(releasedEvidence.length, 1); assert.equal(releasedEvidence[0].type, 'device.assignment.released'); assert.equal(releasedEvidence[0].action, 'release'); assert.equal(releasedEvidence[0].before_assignment.id, actualReturn.assignmentId); assert.equal(releasedEvidence[0].after_assignment, null); assert.equal(releasedEvidence[0].status, 'pending'); assert.equal(releasedEvidence[0].proof.source.tokenId, payload(token).jti); assert.deepEqual(releasedEvidence[0].proof.source.context, payload(token).identity_authorization); assert.equal(releasedEvidence[0].actor_user_id, activated.body.administratorId);
        const actualDecision = (await inventoryFixture.db.query('SELECT event.*,outbox.status AS delivery_status FROM device_return_events event JOIN device_return_outbox outbox USING(id,tenant_id) WHERE event.id=$1', [physicallyReturned.body.operationId])).rows; assert.equal(actualDecision.length, 1); assert.equal(actualDecision[0].version, 1); assert.equal(actualDecision[0].delivery_status, 'pending'); assert.equal(actualDecision[0].type, 'device.return.confirmed'); assert.equal(actualDecision[0].transaction_id, releasedEvidence[0].transaction_id); assert.equal(actualDecision[0].inventory_operation_id, releasedEvidence[0].id); assert.deepEqual(actualDecision[0].proof.source, releasedEvidence[0].proof.source); assert.equal(Object.keys(actualDecision[0].proof.source).length, 11); assert.equal(actualDecision[0].proof.expected, returnEtag(pending[1])); assert.equal(actualDecision[0].proof.reason, physicalInput.reason); assert.deepEqual(actualDecision[0].before_state, { revision: '1', status: 'requested' }); assert.deepEqual(actualDecision[0].after_state, { revision: '2', status: 'returned' }); await inventoryFixture.db.query('SELECT device_returns_validate($1)', [pending[1].id]);
        const releasedDevice = await request(base, '/api/devices/' + actualReturn.deviceId, { token }); assert.equal(releasedDevice.status, 200); assert.equal(releasedDevice.body.assignedUserId, null); assert.equal(releasedDevice.body.lifecycle, 'available');
        const laterAssignment = await request(base, '/api/devices/' + actualReturn.deviceId + '/assignment', { method: 'PUT', token, headers: { 'If-Match': deviceEtag(releasedDevice.body) }, body: { userId: created.body.id } }); assert.equal(laterAssignment.status, 200, JSON.stringify(laterAssignment.body)); assert.notEqual(laterAssignment.body.assignmentId, actualReturn.assignmentId);
        const beforeDecisionRecovery = await inventoryReturnState(); const decisionRecovery = await request(base, physicalPath, { method: 'POST', token, headers: { 'If-Match': returnEtag(pending[1]) }, body: physicalInput }); assert.equal(decisionRecovery.status, 200, JSON.stringify(decisionRecovery.body)); assert.equal(decisionRecovery.body.outcome, 'already_returned'); assert.equal(decisionRecovery.body.operationId, physicallyReturned.body.operationId); assert.equal(decisionRecovery.body.request.currentDeviceRevision, laterAssignment.body.revision); assert.deepEqual(await inventoryReturnState(), beforeDecisionRecovery);
        const changedAssignment = await request(base, '/api/devices/' + pending[2].deviceId + '/assignment', { method: 'PUT', token, headers: { 'If-Match': deviceEtag(returnDevices[2]) }, body: { userId: created.body.id } }); assert.equal(changedAssignment.status, 200, JSON.stringify(changedAssignment.body)); assert.notEqual(changedAssignment.body.assignmentId, pending[2].assignmentId);
        const changedDetail = await request(base, deviceReturnBase + '/' + pending[2].id, { token }); assert.equal(changedDetail.status, 200); const changedReturn = verifyReturn(changedDetail.body); assert.equal(changedReturn.status, 'assignment_changed'); assert.equal(changedReturn.revision, '1'); assert.equal(changedReturn.closingOperationId, null); assert.equal(changedReturn.currentDeviceRevision, changedAssignment.body.revision);
        const actualReplacement = (await inventoryFixture.db.query('SELECT released_by_command_id,released_at FROM device_inventory_assignments WHERE id=$1', [pending[2].assignmentId])).rows[0]; assert.equal(changedReturn.inventoryOperationId, actualReplacement.released_by_command_id); assert.equal(changedReturn.closedAt, actualReplacement.released_at.toISOString());
        const beforeChangedDecision = await inventoryReturnState(); const changedDecision = await request(base, deviceReturnBase + '/' + pending[2].id + '/decision', { method: 'POST', token, headers: { 'If-Match': returnEtag(changedReturn) }, body: physicalInput }); assert.equal(changedDecision.status, 409, JSON.stringify(changedDecision.body)); assert.deepEqual(await inventoryReturnState(), beforeChangedDecision);
        const retainedCreation = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: deviceReturnInput }); assert.equal(retainedCreation.status, 200, JSON.stringify(retainedCreation.body)); assert.deepEqual(retainedCreation.body.results, requestRecovery.body.results); assert.deepEqual(await inventoryReturnState(), beforeChangedDecision);
        const generalList = await request(base, deviceReturnBase + '?page=1&limit=25', { token }); assert.equal(generalList.status, 200, JSON.stringify(generalList.body)); assert.deepEqual(Object.keys(generalList.body).sort(), ['schemaVersion', 'actorUserId', 'tenantId', 'requests', 'total', 'page', 'limit'].sort()); assert.equal(generalList.body.total, 3); assert.deepEqual(new Set(generalList.body.requests.map(item => verifyReturn(item).status)), new Set(['cancelled', 'returned', 'assignment_changed']));
        for (const value of generalList.body.requests) {
          const events = await request(base, deviceReturnBase + '/' + value.id + '/history?page=1&limit=25', { token }); assert.equal(events.status, 200); assert.equal(events.body.requestId, value.id); assert.equal(events.body.events.length, value.status === 'assignment_changed' ? 1 : 2);
          for (const event of events.body.events) { assert.deepEqual(Object.keys(event).sort(), ['id', 'tenantId', 'requestId', 'deviceId', 'assignmentId', 'type', 'version', 'actorUserId', 'correlationId', 'createdAt', 'before', 'after', 'inventoryOperationId', 'reason', 'deliveryStatus'].sort()); assert.equal(event.version, 1); assert.equal((await inventoryFixture.db.query('SELECT version FROM device_return_events WHERE id=$1', [event.id])).rows[0].version, 1); assert.equal(event.deliveryStatus, 'pending'); assert.equal(event.requestId, value.id); assert.ok(['requested', 'returned', 'cancelled'].includes(event.after.status)); if (event.type === 'device.return.confirmed') assert.equal(event.inventoryOperationId, value.inventoryOperationId); }
        }
        const replacementReturnId = randomUUID(); const replacementRequest = await request(base, deviceOffboardingRoute, { method: 'POST', token, body: { ...deviceReturnInput, items: [{ ...deviceReturnInput.items[0], requestId: replacementReturnId }] } }); assert.equal(replacementRequest.status, 200, JSON.stringify(replacementRequest.body)); assert.equal(replacementRequest.body.results[0].status, 'requested'); assert.equal(replacementRequest.body.results[0].requestId, replacementReturnId);
        const stillPending = await request(base, deviceReturnBase + '/' + replacementReturnId, { token }); assert.equal(stillPending.status, 200, JSON.stringify(stillPending.body)); survivingReturn = verifyReturn(stillPending.body); assert.equal(survivingReturn.status, 'requested'); assert.equal(survivingReturn.assignmentId, pending[0].assignmentId); assert.notEqual(survivingReturn.id, pending[0].id);
        assert.ok(offboardingSourceCalls.length > 3); assert.ok(offboardingSourceCalls.every(call => call.method === 'POST' && call.authorization === 'Bearer ' + token)); assert.ok(inventorySourceCalls.some(call => call.authorization === 'Bearer ' + token));
        assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [activated.body.administratorId])).rows[0].count, 0);
        process.stdout.write('Slice19 signed: original bearer through actual Identity13-field parent045 source and Device006; request leaves old005 assignments untouched; real cancel without inventory effect; physical return composes old005 release; original request/decision recovery preserves later assignments; ordinary reassign derives assignment_changed without fictitious return event.\n');
      } finally { identityServer.removeListener('request', observeDeviceSource); }
      const reactivation = await request(base, '/api/users/' + returnUserId, { token }); assert.equal(reactivation.status, 200);
      const reenabled = await request(base, '/api/users/' + returnUserId, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(reactivation.body) }, body: { enabled: true } }); assert.equal(reenabled.status, 200);
      assert.equal((await request(base, deviceOffboardingRoute + '/capabilities?workflowId=' + workflow.id, { token })).status, 409);
      const beforeReactivatedDecision = await originalInventoryState(); const afterReactivationDecision = await request(base, deviceReturnBase + '/' + survivingReturn.id + '/decision', { method: 'POST', token, headers: { 'If-Match': returnEtag(survivingReturn) }, body: { action: 'cancelled', reason: 'Actual inventory return task remains independently manageable after account reactivation', confirm: true } }); assert.equal(afterReactivationDecision.status, 200, JSON.stringify(afterReactivationDecision.body)); assert.equal(afterReactivationDecision.body.outcome, 'cancelled'); assert.equal((await accountState()).enabled, true); assert.deepEqual(await originalInventoryState(), beforeReactivatedDecision);
      for (const kind of ['role', 'eligibility']) { assert.equal((await request(base, accessRoute + accessQuery(kind), { token: accessOperator.access_token })).status, 409); assert.equal((await request(base, accessRoute, { method: 'POST', token: accessOperator.access_token, body: { ...accessInput, kind } })).status, 409); }
      const beforeReactivatedCleanup = await cleanupState();
      for (const suffix of ['', '/history']) assert.equal((await request(base, cleanupRoute + suffix + cleanupQuery, { token })).status, 409);
      assert.equal((await request(base, cleanupRoute, { method: 'POST', token, body: cleanupInput })).status, 409); assert.deepEqual(await cleanupState(), beforeReactivatedCleanup);
      const redisabled = await request(base, '/api/users/' + returnUserId, { method: 'PUT', token, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(reenabled.body) }, body: { enabled: false } }); assert.equal(redisabled.status, 200);
      const beforeChangedEpoch = await cleanupState();
      for (const suffix of ['', '/history']) assert.equal((await request(base, cleanupRoute + suffix + cleanupQuery, { token })).status, 409);
      assert.equal((await request(base, cleanupRoute, { method: 'POST', token, body: { ...cleanupInput, eligibilityRevision: String((await accountState()).eligibility_revision) } })).status, 409); assert.deepEqual(await cleanupState(), beforeChangedEpoch);
      process.stdout.write('Slice17 signed gates verified: exact parent045, fixed25 DTOs, effect-free later foreign/stale preflight, actual207 stop, two046/canonical pending receipts, original POST bearer SHA256, retained recovery without replay, later membership preserved, role/PIM unchanged, reactivation epoch fenced.\n');
    });
  } finally { if (previous === undefined) delete process.env.COMPANY_REGISTRATION_ENABLED; else process.env.COMPANY_REGISTRATION_ENABLED = previous; if (previousActivation === undefined) delete process.env.COMPANY_ACTIVATION_ENABLED; else process.env.COMPANY_ACTIVATION_ENABLED = previousActivation; }
});

test('production gateway registers an actual roleless company blueprint Owner and preserves immutable versions through recovery', async () => {
  const previousRegistration = process.env.COMPANY_REGISTRATION_ENABLED; const previousActivation = process.env.COMPANY_ACTIVATION_ENABLED;
  const body = { registrationId: randomUUID(), username: 'company-blueprint-owner', password: 'disposable-password', mfaCode: '', confirm: true, profile: { ...organizationProfileFixture(), name: 'Actual Signed Blueprint Company' } };
  try {
    process.env.COMPANY_REGISTRATION_ENABLED = 'true'; process.env.COMPANY_ACTIVATION_ENABLED = 'true';
    const submitted = await request(issuerBase, '/oauth/company-registration/submit', { method: 'POST', body }); assert.equal(submitted.status, 201, JSON.stringify(submitted.body)); assert.equal(submitted.body.tenantEnabled, false); assert.equal(submitted.body.administratorEnabled, false);
    const reviewerName = 'company-blueprint-reviewer'; const reviewerId = canonicalSubjects.get(reviewerName);
    await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Independent reviewer for the dedicated actual blueprint company' });
    let reviewer = await issue(reviewerName); if (!provenMfa(payload(reviewer.access_token))) reviewer = await configureFactor(reviewerName, reviewer);
    assert.deepEqual(payload(reviewer.access_token).roles, ['user']); assert.notEqual(reviewerId, submitted.body.administratorId);
    await withProductionGateway(async base => {
      const reviewPath = '/api/identity/company-registrations/' + body.registrationId;
      const pending = await request(base, reviewPath, { token: reviewer.access_token }); assert.equal(pending.status, 200, JSON.stringify(pending.body));
      const approved = await request(base, reviewPath + '/review', { method: 'POST', token: reviewer.access_token, headers: { 'If-Match': pending.body.etag }, body: { decision: 'approved', reason: 'Independent actual approval of the dedicated blueprint company', confirm: true } }); assert.equal(approved.status, 200, JSON.stringify(approved.body)); assert.equal(approved.body.status, 'pending-activation');
      const activated = await request(issuerBase, '/oauth/company-registration/activate', { method: 'POST', body: { registrationId: body.registrationId, username: body.username, password: body.password, mfaCode: '', confirm: true } }); assert.equal(activated.status, 200, JSON.stringify(activated.body)); assert.equal(activated.body.status, 'active');
      const companyOwner = await firstRoleFactor(body.username); const token = companyOwner.access_token; assert.deepEqual(payload(token).roles, []); assert.equal(provenMfa(payload(token)), true);
      const companyPool = await request(base, '/api/licenses/company/pools', { method: 'POST', token, body: { name: 'Signed Blueprint Desired Editor', vendor: 'Signed Blueprint Vendor', description: 'Actual own finite pool for desired blueprint references', totalSeats: 2, reason: 'Actual own application catalog setup for the dedicated blueprint journey' } }); assert.equal(companyPool.status, 201, JSON.stringify(companyPool.body)); assert.equal(companyPool.body.usedSeats, 0);
      const editedPool = companyPool;
      const registeredDevice = await request(base, '/api/devices', { method: 'POST', token, body: { assetId: 'SIGNED-BLUEPRINT-01', serialNumber: 'SIGNED-BLUEPRINT-SERIAL-01', manufacturer: 'Example Manufacturer', model: 'Blueprint Inventory Laptop', deviceClass: 'laptop', platform: 'macos' } }); assert.equal(registeredDevice.status, 201, JSON.stringify(registeredDevice.body));
      const administrator = await productionGlobalAdministrator();
      const blueprintRoute = '/api/company-blueprints';
      const blueprintOwner = Math.floor(Date.now() / 1000) - payload(token).auth_time >= 240 ? await issue(body.username) : companyOwner;
      const blueprintToken = blueprintOwner.access_token; const blueprintClaims = payload(blueprintToken);
      assert.deepEqual(blueprintClaims.roles, []); assert.equal(provenMfa(blueprintClaims), true); assert.equal(blueprintClaims.identity_authorization.userId, activated.body.administratorId);
      const blueprintTables = ['company_blueprints', 'company_blueprint_operations', 'company_blueprint_versions', 'company_blueprint_events', 'company_blueprint_outbox'];
      const blueprintRows = async () => {
        const result = {};
        for (const table of blueprintTables) result[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        return result;
      };
      const unrelatedBlueprintState = async () => {
        const result = {};
        const tables = (await policyDb.query('SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename')).rows;
        for (const { tablename } of tables) if (!blueprintTables.includes(tablename)) result[tablename] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM "${tablename}" record ORDER BY to_jsonb(record)::text`)).rows;
        for (const table of ['mdm_commands', 'policy_device_operations', 'policy_device_command_audit', 'policy_device_command_outbox', 'policy_device_cancellations']) result['issuer.' + table] = (await issuerDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        for (const table of ['users', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_company_activations']) result['identity.' + table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
        return result;
      };
      const beforeBlueprints = await blueprintRows(); const beforeBlueprintEffects = await unrelatedBlueprintState();
      const blueprintSource = await request(base, '/api/identity/company-blueprints', { token: blueprintToken }); assert.equal(blueprintSource.status, 200, JSON.stringify(blueprintSource.body));
      assert.equal(Object.keys(blueprintSource.body).length, 11); assert.equal(blueprintSource.body.companyBlueprintProtocol, 1);
      assert.deepEqual(blueprintSource.body.permissions, ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish']);
      assert.equal(blueprintSource.body.tokenId, blueprintClaims.jti); assert.equal(blueprintSource.body.actorUserId, activated.body.administratorId); assert.equal(blueprintSource.body.tenant.id, activated.body.tenantId);
      assert.deepEqual(blueprintSource.body.context, blueprintClaims.identity_authorization); assert.ok(blueprintSource.body.validUntil <= Math.min(blueprintClaims.exp, blueprintClaims.auth_time + 300));
      const blueprintCapabilities = await request(base, blueprintRoute + '/capabilities', { token: blueprintToken }); assert.equal(blueprintCapabilities.status, 200, JSON.stringify(blueprintCapabilities.body));
      assert.deepEqual(blueprintCapabilities.body, { schemaVersion: 1, actorUserId: activated.body.administratorId, tenantId: activated.body.tenantId, companyBlueprintProtocol: 1,
        permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'], configurationMode: 'local-only', maxConfigurations: 25, maxApplications: 25 });
      const ownBlueprintId = randomUUID(); const originalBlueprintDraft = { name: 'Signed own-company security plan', description: 'Desired local configuration only', platform: 'macos',
        configurations: [{ id: randomUUID(), type: 'screen_lock', name: 'Five minute screen lock', payloadJson: '{"minutes":5,"requirePassword":true}' }], appPoolIds: [companyPool.body.id] };
      const createBlueprintInput = { id: ownBlueprintId, draft: originalBlueprintDraft, reason: 'Actual roleless company owner creates the local security plan', confirm: true };
      const blueprintCreateKey = randomUUID();
      assert.equal((await request(base, blueprintRoute, { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': blueprintCreateKey, 'X-API-Key': 'untrusted' }, body: createBlueprintInput })).status, 401);
      assert.equal((await request(base, blueprintRoute, { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': blueprintCreateKey }, body: { ...createBlueprintInput, permissions: ['policies.deploy'] } })).status, 400);
      assert.deepEqual(await blueprintRows(), beforeBlueprints);
      const ownBlueprint = await request(base, blueprintRoute, { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': blueprintCreateKey }, body: createBlueprintInput });
      assert.equal(ownBlueprint.status, 201, JSON.stringify(ownBlueprint.body)); assert.equal(ownBlueprint.body.outcome, 'applied'); assert.equal(ownBlueprint.body.revision, '1'); assert.equal(ownBlueprint.body.publishedVersion, null);
      const ownBlueprintPath = blueprintRoute + '/' + ownBlueprintId;
      const originalBlueprint = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(originalBlueprint.status, 200, JSON.stringify(originalBlueprint.body));
      assert.ok(originalBlueprint.headers.get('etag')); assert.equal(originalBlueprint.body.blueprint.draftChanged, true);
      assert.equal(Object.hasOwn(originalBlueprint.body.blueprint, 'createdAtISO'), false); assert.equal(Object.hasOwn(originalBlueprint.body.blueprint, 'updatedAtISO'), false);
      assert.equal(new Date(originalBlueprint.body.blueprint.createdAt).toISOString(), originalBlueprint.body.blueprint.createdAt); assert.equal(new Date(originalBlueprint.body.blueprint.updatedAt).toISOString(), originalBlueprint.body.blueprint.updatedAt);
      const firstBlueprintDraft = originalBlueprint.body.blueprint.draft;
      assert.deepEqual(JSON.parse(firstBlueprintDraft.configurations[0].payloadJson), { minutes: 5, requirePassword: true }); assert.deepEqual(firstBlueprintDraft.appPoolIds, [companyPool.body.id]);
      const firstPublicationInput = { reason: 'First immutable local company blueprint release, not deployment approval', confirm: true };
      const firstPublicationHeaders = { 'Idempotency-Key': randomUUID(), 'If-Match': originalBlueprint.headers.get('etag') };
      const firstPublication = await request(base, ownBlueprintPath + '/publish', { method: 'POST', token: blueprintToken, headers: firstPublicationHeaders, body: firstPublicationInput });
      assert.equal(firstPublication.status, 200, JSON.stringify(firstPublication.body)); assert.equal(firstPublication.body.revision, '2'); assert.equal(firstPublication.body.publishedVersion, 1);
      const firstBlueprintVersion = await request(base, ownBlueprintPath + '/versions/1', { token: blueprintToken }); assert.equal(firstBlueprintVersion.status, 200, JSON.stringify(firstBlueprintVersion.body));
      assert.deepEqual(firstBlueprintVersion.body.version.draft, firstBlueprintDraft);
      assert.deepEqual(firstBlueprintVersion.body.version.apps, [{ id: companyPool.body.id, name: editedPool.body.name, vendor: editedPool.body.vendor, revision: editedPool.body.revision }]);
      const firstPublishedHead = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(firstPublishedHead.status, 200); assert.equal(firstPublishedHead.body.blueprint.draftChanged, false);
      const changedBlueprintDraft = { ...firstBlueprintDraft, configurations: [
        { ...firstBlueprintDraft.configurations[0], payloadJson: '{"minutes":10,"requirePassword":true}' },
        { id: randomUUID(), type: 'filevault', name: 'Desired disk encryption', payloadJson: '{"enabled":true}' },
        { id: randomUUID(), type: 'software_update', name: 'Desired automatic updates', payloadJson: '{"automatic":true,"deferralDays":7}' },
      ] };
      const updateBlueprintInput = { draft: changedBlueprintDraft, reason: 'Explicit own company security draft update before a separate release', confirm: true };
      const updatedBlueprint = await request(base, ownBlueprintPath, { method: 'PUT', token: blueprintToken, headers: { 'Idempotency-Key': randomUUID(), 'If-Match': firstPublishedHead.headers.get('etag') }, body: updateBlueprintInput });
      assert.equal(updatedBlueprint.status, 200, JSON.stringify(updatedBlueprint.body)); assert.equal(updatedBlueprint.body.revision, '3'); assert.equal(updatedBlueprint.body.publishedVersion, 1);
      const changedBlueprint = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(changedBlueprint.status, 200); assert.equal(changedBlueprint.body.blueprint.draftChanged, true);
      const secondPublication = await request(base, ownBlueprintPath + '/publish', { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': randomUUID(), 'If-Match': changedBlueprint.headers.get('etag') }, body: { reason: 'Second immutable local release includes encryption and update planning', confirm: true } });
      assert.equal(secondPublication.status, 200, JSON.stringify(secondPublication.body)); assert.equal(secondPublication.body.revision, '4'); assert.equal(secondPublication.body.publishedVersion, 2);
      const secondBlueprintVersion = await request(base, ownBlueprintPath + '/versions/2', { token: blueprintToken }); assert.equal(secondBlueprintVersion.status, 200);
      assert.deepEqual(secondBlueprintVersion.body.version.draft.configurations.map(config => [config.type, JSON.parse(config.payloadJson)]), [
        ['screen_lock', { minutes: 10, requirePassword: true }], ['filevault', { enabled: true }], ['software_update', { automatic: true, deferralDays: 7 }],
      ]);
      const secondPublishedHead = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(secondPublishedHead.status, 200);
      assert.equal((await request(base, ownBlueprintPath, { method: 'PUT', token: blueprintToken, headers: { 'Idempotency-Key': randomUUID(), 'If-Match': originalBlueprint.headers.get('etag') }, body: updateBlueprintInput })).status, 412);
      assert.deepEqual((await request(base, ownBlueprintPath + '/versions/1', { token: blueprintToken })).body, firstBlueprintVersion.body);
      const restoredBlueprint = await request(base, ownBlueprintPath + '/restore', { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': randomUUID(), 'If-Match': secondPublishedHead.headers.get('etag') }, body: { version: 1, reason: 'Explicitly restore historical version one into draft without changing released version two', confirm: true } });
      assert.equal(restoredBlueprint.status, 200, JSON.stringify(restoredBlueprint.body)); assert.equal(restoredBlueprint.body.revision, '5'); assert.equal(restoredBlueprint.body.publishedVersion, 2);
      const restoredBlueprintHead = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(restoredBlueprintHead.status, 200); assert.deepEqual(restoredBlueprintHead.body.blueprint.draft, firstBlueprintDraft); assert.equal(restoredBlueprintHead.body.blueprint.draftChanged, true);
      assert.equal((await request(base, ownBlueprintPath + '/versions', { token: blueprintToken })).body.total, 2);
      const thirdPublication = await request(base, ownBlueprintPath + '/publish', { method: 'POST', token: blueprintToken, headers: { 'Idempotency-Key': randomUUID(), 'If-Match': restoredBlueprintHead.headers.get('etag') }, body: { reason: 'Explicit third local release of the restored original company security plan', confirm: true } });
      assert.equal(thirdPublication.status, 200, JSON.stringify(thirdPublication.body)); assert.equal(thirdPublication.body.revision, '6'); assert.equal(thirdPublication.body.publishedVersion, 3);
      const thirdBlueprintVersion = await request(base, ownBlueprintPath + '/versions/3', { token: blueprintToken }); assert.equal(thirdBlueprintVersion.status, 200); assert.deepEqual(thirdBlueprintVersion.body.version.draft, firstBlueprintDraft);
      const newestBlueprint = await request(base, ownBlueprintPath, { token: blueprintToken }); assert.equal(newestBlueprint.status, 200);
      const beforeBlueprintReplay = await blueprintRows();
      const recoveredPublication = await request(base, ownBlueprintPath + '/publish', { method: 'POST', token: blueprintToken, headers: firstPublicationHeaders, body: firstPublicationInput });
      assert.equal(recoveredPublication.status, 200, JSON.stringify(recoveredPublication.body)); assert.deepEqual(recoveredPublication.body, { ...firstPublication.body, outcome: 'already_applied' });
      assert.deepEqual(await blueprintRows(), beforeBlueprintReplay); assert.deepEqual((await request(base, ownBlueprintPath, { token: blueprintToken })).body, newestBlueprint.body);
      assert.equal((await request(base, ownBlueprintPath + '/publish', { method: 'POST', token: blueprintToken, headers: firstPublicationHeaders, body: { ...firstPublicationInput, reason: 'Changed replay intent must never be accepted' } })).status, 409);
      assert.deepEqual(await blueprintRows(), beforeBlueprintReplay);
      assert.equal((await request(base, ownBlueprintPath, { token: administrator.access_token })).status, 404);
      const legacyBlueprints = await request(base, '/api/blueprints', { token: administrator.access_token }); assert.equal(legacyBlueprints.status, 200); assert.equal(JSON.stringify(legacyBlueprints.body).includes(ownBlueprintId), false);
      assert.equal((await request(base, '/api/blueprints/' + ownBlueprintId, { token: administrator.access_token })).status, 404);
      const legacyFrame = await request(base, '/api/policies/delivery/frame', { method: 'POST', token: administrator.access_token, body: { reference: { resourceKind: 'blueprint', resourceId: ownBlueprintId, resourceVersion: 1, publicationId: randomUUID(), configurationId: firstBlueprintDraft.configurations[0].id }, deviceId: registeredDevice.body.id, platform: 'macos', operationId: randomUUID() } }); assert.equal(legacyFrame.status, 404, JSON.stringify(legacyFrame.body));
      const finalBlueprintHistory = await request(base, ownBlueprintPath + '/history', { token: blueprintToken }); assert.equal(finalBlueprintHistory.status, 200); assert.equal(finalBlueprintHistory.body.total, 6);
      assert.deepEqual(finalBlueprintHistory.body.events.map(event => [event.type, event.afterRevision, event.releasedVersion, event.restoredFrom, event.deliveryStatus]), [
        ['blueprint.published', '6', 3, null, 'pending'], ['blueprint.draft.restored', '5', null, 1, 'pending'], ['blueprint.published', '4', 2, null, 'pending'],
        ['blueprint.draft.updated', '3', null, null, 'pending'], ['blueprint.published', '2', 1, null, 'pending'], ['blueprint.created', '1', null, null, 'pending'],
      ]);
      const retainedBlueprintOperations = (await policyDb.query('SELECT receipt.*,company_blueprint_evidence_valid(receipt) AS valid FROM company_blueprint_operations receipt WHERE blueprint_id=$1 ORDER BY (after_state->>\'revision\')::bigint', [ownBlueprintId])).rows;
      assert.equal(retainedBlueprintOperations.length, 6);
      for (const operation of retainedBlueprintOperations) {
        assert.equal(operation.valid, true); assert.equal(operation.actor_user_id, activated.body.administratorId); assert.equal(operation.tenant_id, activated.body.tenantId);
        assert.deepEqual(operation.source.permissions, blueprintSource.body.permissions); assert.equal(Object.keys(operation.source).length, 11); assert.equal(operation.source.tokenId, blueprintClaims.jti);
        assert.deepEqual(operation.application_source.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']); assert.equal(operation.application_source.tokenId, blueprintClaims.jti);
        assert.deepEqual(operation.application_source.tenant, operation.source.tenant); assert.deepEqual(operation.application_source.context, operation.source.context);
        assert.equal(operation.valid_until.getTime(), Math.min(operation.source.validUntil, operation.application_source.validUntil) * 1000);
      }
      const afterBlueprints = await blueprintRows();
      for (const [table, added] of [['company_blueprints', 1], ['company_blueprint_operations', 6], ['company_blueprint_versions', 3], ['company_blueprint_events', 6], ['company_blueprint_outbox', 6]]) assert.equal(afterBlueprints[table].length - beforeBlueprints[table].length, added);
      assert.deepEqual(await unrelatedBlueprintState(), beforeBlueprintEffects);
      assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [activated.body.administratorId])).rows[0].count, 0);
      process.stdout.write('Slice21 signed: roleless actual Owner source11/fixed3; typed own blueprint create/release1/update/release2/restore1/release3; exact historical-key recovery preserves revision6; six atomic receipts/pending outboxes; no allocator, legacy publication or MDM effects.\n');
      const poolAssigned = await request(base, '/api/licenses/company/pools/' + companyPool.body.id + '/assignments', { method: 'POST', token, headers: { 'If-Match': require('../../../../../packages/company-license-contract').poolEtag(companyPool.body) }, body: { userId: activated.body.administratorId, reason: 'Ordinary explicit allocation after the immutable blueprint effect window', confirm: true } });
      assert.equal(poolAssigned.status, 201, JSON.stringify(poolAssigned.body)); assert.equal(poolAssigned.body.usedSeats, 1); assert.notEqual(poolAssigned.body.revision, firstBlueprintVersion.body.version.apps[0].revision);
      assert.deepEqual((await request(base, ownBlueprintPath + '/versions/1', { token: blueprintToken })).body, firstBlueprintVersion.body);
      assert.deepEqual(await blueprintRows(), afterBlueprints);
    });
  } finally {
    if (previousRegistration === undefined) delete process.env.COMPANY_REGISTRATION_ENABLED; else process.env.COMPANY_REGISTRATION_ENABLED = previousRegistration;
    if (previousActivation === undefined) delete process.env.COMPANY_ACTIVATION_ENABLED; else process.env.COMPANY_ACTIVATION_ENABLED = previousActivation;
  }
});

test('production gateway applies actual roleless company blueprint license origins atomically and retires original offboarding captures', { timeout: 240000 }, async () => {
  const previousRegistration = process.env.COMPANY_REGISTRATION_ENABLED; const previousActivation = process.env.COMPANY_ACTIVATION_ENABLED;
  const registration = { registrationId: randomUUID(), username: 'company-assignment-owner', password: 'disposable-password', mfaCode: '', confirm: true, profile: { ...organizationProfileFixture(), name: 'Actual Signed Assignment Company' } };
  try {
    process.env.COMPANY_REGISTRATION_ENABLED = 'true'; process.env.COMPANY_ACTIVATION_ENABLED = 'true';
    const submitted = await request(issuerBase, '/oauth/company-registration/submit', { method: 'POST', body: registration });
    assert.equal(submitted.status, 201, JSON.stringify(submitted.body)); assert.equal(submitted.body.tenantEnabled, false); assert.equal(submitted.body.administratorEnabled, false);
    const reviewerName = 'company-assignment-reviewer'; const reviewerId = canonicalSubjects.get(reviewerName);
    await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer, userId: reviewerId, version: '0', enabled: true, reason: 'Independent review of the isolated actual assignment company' });
    const reviewer = await configureFactor(reviewerName, await issue(reviewerName)); assert.deepEqual(payload(reviewer.access_token).roles, ['user']); assert.notEqual(reviewerId, submitted.body.administratorId);
    await withProductionGateway(async base => {
      const reviewPath = '/api/identity/company-registrations/' + registration.registrationId;
      const pending = await request(base, reviewPath, { token: reviewer.access_token }); assert.equal(pending.status, 200, JSON.stringify(pending.body));
      const approved = await request(base, reviewPath + '/review', { method: 'POST', token: reviewer.access_token, headers: { 'If-Match': pending.body.etag }, body: { decision: 'approved', reason: 'Independently approve the company without granting global roles', confirm: true } }); assert.equal(approved.status, 200, JSON.stringify(approved.body));
      const activated = await request(issuerBase, '/oauth/company-registration/activate', { method: 'POST', body: { registrationId: registration.registrationId, username: registration.username, password: registration.password, mfaCode: '', confirm: true } }); assert.equal(activated.status, 200, JSON.stringify(activated.body));
      const owner = await firstRoleFactor(registration.username); const token = owner.access_token; const claims = payload(token); const startedAt = Date.now();
      assert.deepEqual(claims.roles, []); assert.equal(provenMfa(claims), true); assert.equal(claims.identity_authorization.userId, activated.body.administratorId);
      const call = (route, options = {}) => request(base, route, { ...options, token });
      const success = async (route, options = {}, status = 200) => { const response = await call(route, options); assert.equal(response.status, status, JSON.stringify({ route, response: response.body })); return response; };
      const sourceCalls = []; const observeSource = incoming => { if (incoming.url.split('?')[0] === '/api/identity/company-blueprint-assignments') sourceCalls.push({ method: incoming.method, authorization: incoming.headers.authorization }); };
      identityServer.on('request', observeSource);
      try {
        const assignmentBase = '/api/company-blueprint-assignments'; const appBase = '/api/licenses/company'; const appV2 = appBase + '/v2'; const blueprintBase = '/api/company-blueprints';
        const capabilities = await success(assignmentBase + '/capabilities'); assert.deepEqual(capabilities.body.permissions, ['company.blueprints.assignments.read', 'company.blueprints.assign']); assert.equal(capabilities.body.actorUserId, activated.body.administratorId); assert.equal(capabilities.body.tenantId, activated.body.tenantId);
        const actorSource = await success('/api/identity/company-blueprint-assignments'); assert.equal(Object.keys(actorSource.body).length, 12); assert.equal(actorSource.body.target, null); assert.equal(actorSource.body.tokenId, claims.jti); assert.deepEqual(actorSource.body.context, claims.identity_authorization);
        const createEmployee = async username => {
          const created = await success('/api/users', { method: 'POST', body: { username, email: username + '@example.invalid' } }, 201); assert.equal(created.body.enabled, false);
          return (await success('/api/users/' + created.body.id, { method: 'PUT', headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(created.body) }, body: { enabled: true } })).body;
        };
        const employee = await createEmployee('signed-assignment-employee'); const blocker = await createEmployee('signed-assignment-blocker'); const userId = employee.id;
        const createPool = async name => (await success(appBase + '/pools', { method: 'POST', body: { name, vendor: 'Actual Assignment Vendor', description: 'Finite local allocation without provider commands', totalSeats: 1, reason: 'Create an actual isolated finite application pool' } }, 201)).body;
        const sharedPool = await createPool('Signed overlapping blueprint app'); const emptyPool = await createPool('Signed atomic free app'); const scarcePool = await createPool('Signed atomic occupied app');
        const manualAssign = async (poolId, recipient) => {
          const preview = (await success(appV2 + '/pools/' + poolId + '/assignment-preview', { method: 'POST', body: { userId: recipient } })).body;
          const body = { userId: recipient, eligibilityRevision: preview.target.eligibilityRevision, assignmentId: preview.assignment?.id ?? null, sources: preview.assignment?.sources ?? [], reason: 'Explicit actual manual origin alongside independent blueprint origins', confirm: true };
          return success(appV2 + '/pools/' + poolId + '/assignments', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': '"company-pool-' + poolId + '-' + preview.poolRevision + '"' }, body }, 201);
        };
        await manualAssign(scarcePool.id, blocker.id); await manualAssign(sharedPool.id, userId);
        const release = async (name, appPoolIds, configurations) => {
          const id = randomUUID(); const draft = { name, description: 'Immutable actual company desired configuration', platform: 'macos', configurations, appPoolIds };
          await success(blueprintBase, { method: 'POST', headers: { 'Idempotency-Key': randomUUID() }, body: { id, draft, reason: 'Create a real released blueprint for actual assignment', confirm: true } }, 201);
          const current = await success(blueprintBase + '/' + id);
          await success(blueprintBase + '/' + id + '/publish', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': current.headers.get('etag') }, body: { reason: 'Explicitly release this immutable blueprint version for assignment', confirm: true } });
          return { id, draft };
        };
        const screenLock = minutes => [{ id: randomUUID(), type: 'screen_lock', name: 'Actual screen lock plan', payloadJson: JSON.stringify({ minutes, requirePassword: true }) }];
        const first = await release('Signed binding A', [sharedPool.id], screenLock(5)); const second = await release('Signed binding B', [sharedPool.id], screenLock(5));
        const configOnly = await release('Signed zero-app binding', [], [{ id: randomUUID(), type: 'filevault', name: 'Desired encryption only', payloadJson: '{"enabled":true}' }]);
        const conflicting = await release('Signed conflicting screen lock', [sharedPool.id], screenLock(10)); const shortage = await release('Signed all-or-nothing apps', [emptyPool.id, scarcePool.id], []);
        const capturePools = preview => preview.pools.map(({ poolId, poolRevision }) => ({ poolId, poolRevision }));
        const prepare = async blueprintId => {
          const preview = (await success(assignmentBase + '/preview', { method: 'POST', body: { userId, blueprintId, version: 1 } })).body;
          return { preview, headers: { 'Idempotency-Key': randomUUID() }, body: { id: randomUUID(), userId, blueprintId, version: 1, eligibilityRevision: preview.eligibilityRevision, pools: capturePools(preview), reason: 'Confirm the actual immutable blueprint and all captured pool versions', confirm: true } };
        };
        const assign = async blueprintId => { const intent = await prepare(blueprintId); const response = await success(assignmentBase, { method: 'POST', headers: intent.headers, body: intent.body }, 201); return { ...intent, response }; };
        const firstBinding = await assign(first.id); const secondBinding = await assign(second.id); const zeroBinding = await assign(configOnly.id);
        const ledger = async () => {
          const result = {};
          for (const table of ['license_catalog', 'license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_review_leases', 'license_audit_events', 'license_company_commands', 'license_company_origins', 'license_company_events', 'license_company_outbox', 'company_blueprint_user_assignments', 'company_blueprint_assignment_operations', 'company_blueprint_assignment_events', 'company_blueprint_assignment_outbox']) result[table] = (await policyDb.query('SELECT to_jsonb(record) AS row FROM ' + table + ' record ORDER BY to_jsonb(record)::text')).rows;
          return result;
        };
        const fullSources = (await success(appV2 + '/pools/' + sharedPool.id + '/assignments')).body;
        assert.equal(fullSources.schemaVersion, 2); assert.equal(fullSources.total, 1); assert.equal(fullSources.assignments.length, 1); assert.equal(fullSources.assignments[0].sources.length, 3);
        assert.deepEqual(fullSources.assignments[0].sources.map(source => [source.sourceType, source.sourceId]).sort(), [['blueprint', firstBinding.body.id], ['blueprint', secondBinding.body.id], ['direct', 'direct']].sort());
        assert.equal(new Set(fullSources.assignments[0].sources.map(source => source.grantId)).size, 3); assert.equal((await success(appBase + '/pools/' + sharedPool.id)).body.usedSeats, 1);
        const legacyMixed = await call(appBase + '/pools/' + sharedPool.id + '/assignments'); assert.equal(legacyMixed.status, 409, JSON.stringify(legacyMixed.body));
        const conflictingIntent = await prepare(conflicting.id); assert.equal(conflictingIntent.preview.hasConflicts, true); const beforeConflict = await ledger();
        const conflictDenied = await call(assignmentBase, { method: 'POST', headers: conflictingIntent.headers, body: conflictingIntent.body }); assert.equal(conflictDenied.status, 409, JSON.stringify(conflictDenied.body)); assert.deepEqual(await ledger(), beforeConflict);
        const shortageIntent = await prepare(shortage.id); assert.equal(shortageIntent.preview.hasConflicts, false); assert.equal(shortageIntent.preview.pools.find(pool => pool.poolId === scarcePool.id).availableSeats, 0); const beforeShortage = await ledger();
        const shortageDenied = await call(assignmentBase, { method: 'POST', headers: shortageIntent.headers, body: shortageIntent.body }); assert.equal(shortageDenied.status, 409, JSON.stringify(shortageDenied.body)); assert.deepEqual(await ledger(), beforeShortage);
        const firstVersion = (await success(blueprintBase + '/' + first.id + '/versions/1')).body;
        const firstHead = await success(blueprintBase + '/' + first.id); const changedDraft = { ...first.draft, configurations: screenLock(20) };
        await success(blueprintBase + '/' + first.id, { method: 'PUT', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': firstHead.headers.get('etag') }, body: { draft: changedDraft, reason: 'Later local draft must not mutate an already assigned immutable release', confirm: true } });
        const changedHead = await success(blueprintBase + '/' + first.id);
        await success(blueprintBase + '/' + first.id + '/publish', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': changedHead.headers.get('etag') }, body: { reason: 'Release a newer version without retargeting existing user assignments', confirm: true } });
        assert.deepEqual((await success(blueprintBase + '/' + first.id + '/versions/1')).body, firstVersion);
        const effective = (await success(assignmentBase + '/users/' + userId + '/effective')).body; assert.equal(effective.hasConflicts, false); assert.equal(effective.assignments.find(item => item.id === firstBinding.body.id).version, 1);
        assert.deepEqual(JSON.parse(effective.effectiveConfigurations.find(item => item.configType === 'screen_lock').payloadJson), { minutes: 5, requirePassword: true });
        const currentBinding = await success(assignmentBase + '/' + firstBinding.body.id); const currentPool = await success(appBase + '/pools/' + sharedPool.id);
        const removeBody = { userId, eligibilityRevision: firstBinding.body.eligibilityRevision, pools: [{ poolId: sharedPool.id, poolRevision: currentPool.body.revision }], reason: 'Remove only binding A while retaining the manual and binding B origins', confirm: true };
        const actualBindingEtag = currentBinding.headers.get('etag');
        assert.equal(actualBindingEtag, '"company-blueprint-assignment-' + firstBinding.body.id + '-' + currentBinding.body.assignment.revision + '"');
        const removeHeaders = { 'Idempotency-Key': randomUUID(), 'If-Match': actualBindingEtag };
        const removed = await success(assignmentBase + '/' + firstBinding.body.id + '/remove', { method: 'POST', headers: removeHeaders, body: removeBody });
        assert.equal(removed.body.pools[0].sourceRemoved, true); assert.equal(removed.body.pools[0].seatReleased, false); assert.equal(removed.body.pools[0].effectiveAssignmentRetained, true);
        assert.equal((await success(appV2 + '/pools/' + sharedPool.id + '/assignments')).body.assignments[0].sources.length, 2);
        const beforeRecovery = await ledger(); const recovered = await success(assignmentBase, { method: 'POST', headers: firstBinding.headers, body: firstBinding.body }); assert.deepEqual(recovered.body, { ...firstBinding.response.body, outcome: 'already_applied' }); assert.deepEqual(await ledger(), beforeRecovery);
        const replacementBinding = await assign(first.id); assert.notEqual(replacementBinding.body.id, firstBinding.body.id);
        const beforeOldRemoval = await ledger(); const removedRecovery = await success(assignmentBase + '/' + firstBinding.body.id + '/remove', { method: 'POST', headers: removeHeaders, body: removeBody }); assert.deepEqual(removedRecovery.body, { ...removed.body, outcome: 'already_applied' }); assert.deepEqual(await ledger(), beforeOldRemoval);
        const manualPreview = (await success(appV2 + '/pools/' + sharedPool.id + '/assignment-preview', { method: 'POST', body: { userId } })).body;
        const manualRemoved = await success(appV2 + '/pools/' + sharedPool.id + '/assignments/' + manualPreview.assignment.id + '/revoke', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': '"company-pool-' + sharedPool.id + '-' + manualPreview.poolRevision + '"' }, body: { userId, eligibilityRevision: manualPreview.target.eligibilityRevision, sources: manualPreview.assignment.sources, reason: 'Remove the manual origin without removing either actual blueprint source', confirm: true } });
        assert.equal(manualRemoved.body.sourceRemoved, true); assert.equal(manualRemoved.body.seatReleased, false); assert.equal(manualRemoved.body.effectiveAssignmentRetained, true);
        await manualAssign(sharedPool.id, userId);
        const beforeOffboardingSources = (await success(appV2 + '/pools/' + sharedPool.id + '/assignments')).body.assignments[0].sources; assert.equal(beforeOffboardingSources.length, 3);
        const offboardingPreview = (await success(appV2 + '/users/' + userId + '/offboarding-preview')).body; assert.equal(offboardingPreview.licenseCount, 1); assert.equal(offboardingPreview.bindingCount, 3);
        const workflowBody = { workflowId: randomUUID(), userId, userRevision: offboardingPreview.user.userRevision, eligibilityRevision: offboardingPreview.user.eligibilityRevision, reason: 'Original negative account workflow retires every origin and the zero-app binding', confirm: true };
        const workflowRoute = appV2 + '/offboarding-workflows'; const workflowResponse = await success(workflowRoute, { method: 'POST', headers: { 'Idempotency-Key': workflowBody.workflowId }, body: workflowBody, timeout: 60000 }, 201); const workflow = workflowResponse.body.workflow;
        assert.equal(workflow.phase, 'completed_local'); assert.equal(workflow.totalLicenses, 1); assert.equal(workflow.completedLicenses, 1); assert.equal(workflow.totalBindings, 3); assert.equal(workflow.completedBindings, 3); assert.equal(Object.keys(workflow.checkpoint).length, 13); assert.equal(workflow.checkpoint.action, 'disabled');
        const negativeReceipt = (await identityDb.query('SELECT receipt.*,outbox.status FROM identity_company_offboarding_receipts receipt JOIN identity_company_offboarding_outbox outbox USING(tenant_id,workflow_id) WHERE receipt.workflow_id=$1', [workflow.id])).rows;
        assert.equal(negativeReceipt.length, 1); assert.equal(negativeReceipt[0].operation_id, workflow.checkpoint.operationId); assert.equal(negativeReceipt[0].status, 'pending'); assert.equal(negativeReceipt[0].source.subject, claims.sub); assert.deepEqual(negativeReceipt[0].source.context, claims.identity_authorization);
        const retiredBindings = (await policyDb.query('SELECT id,status,version FROM company_blueprint_user_assignments WHERE user_id=$1 ORDER BY id', [userId])).rows;
        assert.equal(retiredBindings.length, 4); assert.ok(retiredBindings.every(item => item.status === 'removed')); assert.ok(retiredBindings.some(item => item.id === zeroBinding.body.id));
        const afterOffboarding = (await success(appV2 + '/pools/' + sharedPool.id + '/assignments')).body; assert.equal(afterOffboarding.total, 0); assert.equal((await success(appBase + '/pools/' + sharedPool.id)).body.usedSeats, 0);
        const retiredGrants = (await policyDb.query('SELECT DISTINCT ON(grant_id) grant_id,state FROM license_grant_events WHERE grant_id=ANY($1::uuid[]) ORDER BY grant_id,version DESC', [beforeOffboardingSources.map(item => item.grantId)])).rows; assert.equal(retiredGrants.length, 3); assert.ok(retiredGrants.every(item => item.state === 'revoked'));
        const disabled = await success('/api/users/' + userId); assert.equal(disabled.body.enabled, false);
        const reenabled = await success('/api/users/' + userId, { method: 'PUT', headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(disabled.body) }, body: { enabled: true } }); assert.equal(reenabled.body.enabled, true);
        await manualAssign(sharedPool.id, userId); const newBinding = await assign(second.id); assert.notEqual(newBinding.body.id, secondBinding.body.id);
        const beforeOldWorkflow = await ledger(); const oldWorkflow = await success(workflowRoute + '/' + workflow.id + '/continue', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': '"company-offboarding-' + workflow.id + '-' + workflow.revision + '"' }, body: { confirm: true, reason: workflowBody.reason, userRevision: workflowBody.userRevision, assignments: [], bindings: [] } }); assert.equal(oldWorkflow.body.workflow.phase, 'completed_local'); assert.equal(oldWorkflow.body.currentTarget.enabled, true); assert.deepEqual(oldWorkflow.body.workflow.checkpoint, workflow.checkpoint); assert.deepEqual(await ledger(), beforeOldWorkflow);
        const originalCheckpoint = (await identityDb.query('SELECT operation_id,after_eligibility_revision FROM identity_company_offboarding_receipts WHERE workflow_id=$1', [workflow.id])).rows[0]; assert.equal(originalCheckpoint.operation_id, workflow.checkpoint.operationId); assert.equal(String(originalCheckpoint.after_eligibility_revision), workflow.checkpoint.afterEligibilityRevision);
        const parents = (await policyDb.query('SELECT * FROM company_blueprint_assignment_operations WHERE tenant_id=$1 ORDER BY created_at,id', [activated.body.tenantId])).rows; assert.equal(parents.length, 12);
        for (const parent of parents) { assert.equal(parent.actor_user_id, activated.body.administratorId); if (parent.source) { assert.equal(parent.source.tokenId, claims.jti); assert.deepEqual(parent.source.context, claims.identity_authorization); } if (parent.application_source) assert.equal(parent.application_source.tokenId, claims.jti); }
        const parentDeliveries = (await policyDb.query('SELECT events.id,outbox.status FROM company_blueprint_assignment_events events JOIN company_blueprint_assignment_outbox outbox USING(id,tenant_id) WHERE events.tenant_id=$1', [activated.body.tenantId])).rows; assert.equal(parentDeliveries.length, parents.length); assert.ok(parentDeliveries.every(event => event.status === 'pending'));
        const canonicalChildren = (await policyDb.query('SELECT command.protocol,command.parent_operation_id,event.id,outbox.status,license_company_event_valid(event) AS valid FROM license_company_commands command JOIN license_company_events event ON event.id=command.id JOIN license_company_outbox outbox ON outbox.id=event.id WHERE command.protocol=2 AND command.tenant_id=$1', [activated.body.tenantId])).rows; assert.equal(canonicalChildren.length, 11); assert.ok(canonicalChildren.every(child => parents.some(parent => parent.id === child.parent_operation_id) && child.status === 'pending' && child.valid));
        assert.ok(sourceCalls.length > 10); assert.ok(sourceCalls.every(call => call.authorization === 'Bearer ' + token));
        assert.equal((await identityDb.query('SELECT count(*)::integer AS count FROM identity_role_assignments WHERE user_id=$1', [activated.body.administratorId])).rows[0].count, 0);
        for (const table of ['mdm_commands', 'policy_device_operations']) assert.equal((await issuerDb.query('SELECT count(*)::integer AS count FROM ' + table)).rows[0].count, 0);
        assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_provider_products WHERE license_id=ANY($1::uuid[])', [[sharedPool.id, emptyPool.id, scarcePool.id]])).rows[0].count, 0);
        assert.ok(Date.now() - startedAt < 240000, 'Actual independent journey stays comfortably within the unchanged 300-second original MFA proof');
        process.stdout.write('Slice22 signed: actual independently activated roleless Owner; source12 original bearer; manual+A+B one seat; source-only removal; all-app shortage and configuration conflict atomic; pinned immutable version; original-key recovery; original045 all-source plus zero-app retirement; reactivation fences old workflow and preserves new grants.\n');
      } finally { identityServer.removeListener('request', observeSource); }
    });
  } finally {
    if (previousRegistration === undefined) delete process.env.COMPANY_REGISTRATION_ENABLED; else process.env.COMPANY_REGISTRATION_ENABLED = previousRegistration;
    if (previousActivation === undefined) delete process.env.COMPANY_ACTIVATION_ENABLED; else process.env.COMPANY_ACTIVATION_ENABLED = previousActivation;
  }
});
