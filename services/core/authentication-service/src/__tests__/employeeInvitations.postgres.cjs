'use strict';
const {test,beforeEach,afterEach,after}=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {Pool}=require('pg');
const {activeCompany}=require('../../../../../scripts/lib/company-owner-fixture.cjs');const {DirectoryCreator}=require('../../../identity-service/src/DirectoryCreator');
const {AuthorizationState}=require('../../../identity-service/src/AuthorizationState');const {EmployeeInvitationAuthority}=require('../../../identity-service/src/EmployeeInvitationAuthority');
const {EmployeeInvitationObserver}=require('../../../identity-service/src/EmployeeInvitationObserver');const {EmployeeInvitations}=require('../EmployeeInvitations');
const contract=require('../../../../../packages/employee-invitation-contract');const {runMigrations}=require('../runMigrations');
const administration=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,max:1});const issuer='https://employee.native';const bearer='Bearer original-owner';
let authPool,identityPool,identity,owner,employee,store,schema,identitySchema;
function claims(operation,input,ownerBearer){const now=Math.floor(Date.now()/1000);return{iss:issuer,sub:'oauth-provider',aud:contract.AUDIENCE,actor_type:'workload',token_use:contract.PURPOSE,scope:'employees.invitations.'+operation,
 htm:'POST',htu:(['observe','complete'].includes(operation)?contract.IDENTITY_BASE:contract.AUTH_BASE)+'/'+operation,body_sha256:contract.digest(input),owner_sha256:ownerBearer?contract.digest(ownerBearer):null,jti:randomUUID(),iat:now,exp:now+30};}
beforeEach(async()=>{
 schema='auth_employee_'+randomUUID().replaceAll('-','');identitySchema='identity_employee_'+randomUUID().replaceAll('-','');await administration.query('CREATE SCHEMA '+schema);await administration.query('CREATE SCHEMA '+identitySchema);
 authPool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,options:'-c search_path='+schema+',public -c timezone=UTC'});identityPool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,options:'-c search_path='+identitySchema+',public -c timezone=UTC'});
 identity={isAvailable:()=>true,query:(...args)=>identityPool.query(...args),getClient:()=>identityPool.connect(),transaction:async(operation,options={})=>{const client=await identityPool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const result=await operation(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 const directory=path.join(__dirname,'../../../identity-service/migrations');for(const file of fs.readdirSync(directory).filter(file=>file.endsWith('.sql')).sort())await identityPool.query(fs.readFileSync(path.join(directory,file),'utf8'));
 await runMigrations(authPool);owner=await activeCompany(identity,identitySchema,issuer);const revalidate=async(_authorization,user)=>(await new AuthorizationState(identity).state(issuer,user.sub)).tenant;
 employee=await new DirectoryCreator(identity,{issuer,revalidate}).user({username:'actual-employee',email:randomUUID()+'@example.invalid'},owner.user,bearer);
 const authority=new EmployeeInvitationAuthority(identity,{issuer,revalidate});const observer=new EmployeeInvitationObserver(identity);
 store=new EmployeeInvitations({isAvailable:()=>true,getClient:()=>authPool.connect()},{authority:{owner:async(authorization,userId=null)=>{assert.equal(authorization,bearer);return authority.read(owner.user,authorization,{userId});}},observe:async witness=>{const input={witness};return observer.read(input,claims('observe',input));}});
});
afterEach(async()=>{await authPool.end();await identityPool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');await administration.query('DROP SCHEMA '+identitySchema+' CASCADE');});after(()=>administration.end());
function input(){return{id:randomUUID(),userId:employee.id,userRevision:employee.revision,loginName:'employee-'+randomUUID(),durationHours:24,reason:'Explicit own ordinary employee account invitation',confirm:true};}
async function invite(){const request=input();return{request,...await store.create(request,claims('create',request,bearer),bearer)};}
async function credentialed(){const created=await invite();const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 return{...created,credential:await store.credential(request,claims('credential',request)),password:request.password};}
function acceptance(created){return{invitationId:created.invitation.id,subjectId:created.credential.witness.subjectId,userId:employee.id,tenant:created.tenant,confirmed:true};}
function interceptQueries(intercept){store.database={isAvailable:()=>true,getClient:async()=>{const client=await authPool.connect();return{query:async(sql,values)=>{
 await intercept(sql,values,client);return client.query(sql,values);},release:()=>client.release()};}};}
test('a real own disabled directory entry receives a one-time invitation without credentials or directory activation',async()=>{
 const created=await invite();assert.equal(created.created,true);assert.equal(created.invitation.status,'pending');assert.equal(created.invitation.credentialCreated,false);assert.equal(created.invitation.identityConfirmed,false);assert.equal(created.invitationToken.length,80);
 const row=(await authPool.query('SELECT * FROM auth_employee_invitations')).rows[0];assert.notEqual(row.token_hash,created.invitationToken);assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'0');
 assert.equal((await identityPool.query('SELECT enabled FROM users WHERE id=$1',[employee.id])).rows[0].enabled,false);
 assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitation_events')).rows[0].n,'1');assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitation_outbox')).rows[0].n,'1');
});
test('recovery reads the original creation without another token and rejects a changed original intent',async()=>{
 const created=await invite();const replay=await store.create(created.request,claims('create',created.request,bearer),bearer);assert.equal(replay.created,false);assert.equal(replay.invitationToken,null);assert.equal(replay.invitation.id,created.invitation.id);
 const changed={...created.request,loginName:'changed-account'};await assert.rejects(store.create(changed,claims('create',changed,bearer),bearer),{status:409});assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitations')).rows[0].n,'1');
});
test('actual recipient possession creates one locked credential and preserves original pending recovery after owner MFA expires',async()=>{
 const created=await invite();owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;
 const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 const result=await store.credential(request,claims('credential',request));assert.equal(result.invitation.status,'credential_pending');assert.ok(result.witness.credential.eventId);
 const credential=(await authPool.query('SELECT * FROM users')).rows[0];assert.equal(credential.id,result.witness.subjectId);assert.equal(credential.is_locked,true);assert.deepEqual(credential.roles,['user']);assert.deepEqual(credential.permissions,[]);
 const policy=new(require('../policies/PasswordPolicyEnforcer'))(authPool);const reused=await policy.validatePassword(credential.id,request.password);assert.equal(reused.valid,false);assert.equal(reused.historyViolation,true);
 assert.equal((await authPool.query('SELECT count(*) AS n FROM password_history')).rows[0].n,'1');
 const replay=await store.credential(request,claims('credential',request));assert.deepEqual(replay,result);assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'1');
 const wrong={...request,password:'Unrelated-recipient-password-123!'};await assert.rejects(store.credential(wrong,claims('credential',wrong)),{status:401});
 assert.equal((await identityPool.query('SELECT enabled FROM users WHERE id=$1',[employee.id])).rows[0].enabled,false);
});
test('a changed actual directory revision prevents credential creation even with the original invitation secret',async()=>{
 const created=await invite();const {UserMutator}=require('../../../identity-service/src/UserMutator');const {userEtag}=require('../../../identity-service/src/DirectoryUsers');
 const revalidate=async(_auth,user)=>(await new AuthorizationState(identity).state(issuer,user.sub)).tenant;
 await new UserMutator(identity,{issuer,revalidate}).update(employee.id,{displayName:'Actual changed recipient'},userEtag(employee),owner.user,bearer);
 const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(request,claims('credential',request)),{status:409});assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'0');
});
test('the exact shared bcrypt byte boundary rejects truncation and cannot create credentials under the wrong token',async()=>{
 const created=await invite();const oversized={token:created.invitationToken,password:'A1!'+ 'ä'.repeat(35),observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(oversized,claims('credential',oversized)),{status:400});
 const wrong={token:randomUUID()+created.invitationToken.slice(36),password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(wrong,claims('credential',wrong)),{status:404});assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'0');
});
test('a confirmed revocation retains its original reason, releases the pending target and prevents token use',async()=>{
 const created=await invite();const request={id:created.invitation.id,revision:created.invitation.revision,reason:'The original employee invitation was withdrawn',confirm:true};
 const result=await store.revoke(request,claims('revoke',request,bearer),bearer);assert.equal(result.invitation.status,'revoked');
 const replay=await store.revoke(request,claims('revoke',request,bearer),bearer);assert.deepEqual(replay,result);
 const changed={...request,reason:'A different revocation reason cannot replace the original'};await assert.rejects(store.revoke(changed,claims('revoke',changed,bearer),bearer),{status:409});
 assert.equal((await authPool.query("SELECT reason FROM auth_employee_invitation_events WHERE action='revoked'")).rows[0].reason,request.reason);
 const inspection={token:created.invitationToken};await assert.rejects(store.inspect(inspection,claims('inspect',inspection)),{status:401});
 const next=await invite();assert.notEqual(next.invitation.id,created.invitation.id);assert.equal(next.invitation.status,'pending');
});
test('a foreign actual company owner cannot read or revoke an existing invitation',async()=>{
 const created=await invite();owner=await activeCompany(identity,identitySchema,issuer);
 const get={id:created.invitation.id};await assert.rejects(store.get(get,claims('get',get,bearer),bearer),{status:404});
 const revoke={id:created.invitation.id,revision:'1',reason:'Foreign company must not revoke this invitation',confirm:true};
 await assert.rejects(store.revoke(revoke,claims('revoke',revoke,bearer),bearer),{status:404});
 assert.equal((await authPool.query('SELECT status FROM auth_employee_invitations')).rows[0].status,'pending');
});
test('unfinished and revoked credentials cannot be reset, unlocked or deleted through ordinary credential writes',async()=>{
 const created=await credentialed();const subjectId=created.credential.witness.subjectId;
 for(const statement of ['UPDATE users SET is_locked=false WHERE id=$1',"UPDATE users SET password_hash='replaced' WHERE id=$1",'DELETE FROM users WHERE id=$1'])
  await assert.rejects(authPool.query(statement,[subjectId]),{code:'42501'});
 const revoke={id:created.invitation.id,revision:created.credential.invitation.revision,reason:'Withdraw the incomplete original employee credential',confirm:true};
 await store.revoke(revoke,claims('revoke',revoke,bearer),bearer);
 await assert.rejects(authPool.query('UPDATE users SET is_locked=false WHERE id=$1',[subjectId]),{code:'42501'});
 const state={invitationId:created.invitation.id,subjectId,userId:employee.id,tenantId:created.tenant.id};assert.equal((await store.state(state,claims('state',state))).ready,false);
 assert.equal((await authPool.query('SELECT is_locked FROM users WHERE id=$1',[subjectId])).rows[0].is_locked,true);
});
test('activation requires the current independent identity acceptance and only unlocks the original credential once',async()=>{
 const created=await credentialed();const request={id:created.invitation.id,receipt:acceptance(created)};const authorization='Bearer original-private-activation';
 store.accepted=async(input,original)=>{assert.deepEqual(input,request);assert.equal(original,authorization);return{active:false,receipt:input.receipt};};
 await assert.rejects(store.activate(request,claims('activate',request),authorization),{status:409});
 assert.equal((await authPool.query('SELECT is_locked FROM users')).rows[0].is_locked,true);
 store.accepted=async(input,original)=>{assert.equal(original,authorization);return{active:true,receipt:input.receipt};};
 const activated=await store.activate(request,claims('activate',request),authorization);assert.equal(activated.invitation.status,'accepted');assert.equal(activated.invitation.identityConfirmed,true);assert.equal(activated.replayed,false);
 const before=(await authPool.query('SELECT * FROM users')).rows[0];assert.equal(before.is_locked,false);assert.equal(before.record_revision,'2');assert.equal(before.security_revision,'2');
 assert.equal((await store.activate(request,claims('activate',request),authorization)).replayed,true);
 assert.deepEqual((await authPool.query('SELECT * FROM users')).rows[0],before);
 const changed={...request,receipt:{...request.receipt,userId:randomUUID()}};await assert.rejects(store.activate(changed,claims('activate',changed),authorization),{status:409});
 const revoke={id:created.invitation.id,revision:activated.invitation.revision,reason:'Completed employees require the normal offboarding workflow',confirm:true};
 await assert.rejects(store.revoke(revoke,claims('revoke',revoke,bearer),bearer),{status:409});
});
test('security revision tracks real credential changes without invalidation on ordinary login counters',async()=>{
 const created=await credentialed();const activate={id:created.invitation.id,receipt:acceptance(created)};store.accepted=async input=>({active:true,receipt:input.receipt});
 const state={invitationId:created.invitation.id,subjectId:created.credential.witness.subjectId,userId:employee.id,tenantId:created.tenant.id};
 assert.equal((await store.state(state,claims('state',state))).ready,false);
 await store.activate(activate,claims('activate',activate),'Bearer activation');const original=await store.state(state,claims('state',state));assert.equal(original.ready,true);
 await authPool.query('UPDATE users SET login_attempts=login_attempts+1 WHERE id=$1',[state.subjectId]);assert.deepEqual(await store.state(state,claims('state',state)),original);
 await authPool.query("UPDATE users SET password_hash='actual-password-changed' WHERE id=$1",[state.subjectId]);assert.equal((await store.state(state,claims('state',state))).securityRevision,String(BigInt(original.securityRevision)+1n));
 await authPool.query('UPDATE users SET is_locked=true WHERE id=$1',[state.subjectId]);assert.equal((await store.state(state,claims('state',state))).ready,false);
});
test('unrelated writes under the actual credential scope roll back the credential and invitation together',async()=>{
 const created=await invite();interceptQueries(async(sql,_values,client)=>{if(sql.startsWith('UPDATE auth_employee_invitations'))await client.query("INSERT INTO audit_events(event_type,message) VALUES('unrelated','Unexpected invitation side effect')");});
 const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(request,claims('credential',request)),{status:503});assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'0');
 assert.equal((await authPool.query('SELECT status FROM auth_employee_invitations')).rows[0].status,'pending');assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitation_events')).rows[0].n,'1');
});
test('a credential without its same-transaction invitation receipt cannot physically commit',async()=>{
 const created=await invite();interceptQueries(async(sql,_values,client)=>{if(sql.startsWith('UPDATE auth_employee_invitations'))await client.query('SET CONSTRAINTS ALL IMMEDIATE');});
 const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(request,claims('credential',request)),{status:503});assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'0');
 assert.equal((await authPool.query('SELECT status FROM auth_employee_invitations')).rows[0].status,'pending');
});
test('missing credential fencing fails closed before creating an invitation',async()=>{
 await authPool.query('DROP TRIGGER auth_employee_effect_commit ON users');const request=input();
 await assert.rejects(store.create(request,claims('create',request,bearer),bearer),{status:503});assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitations')).rows[0].n,'0');
});
test('a pending credential and its retained original evidence survive actual migration replay',async()=>{
 const created=await credentialed();await runMigrations(authPool);
 const read={id:created.invitation.id};const current=await store.get(read,claims('get',read,bearer),bearer);assert.deepEqual(current.invitation,created.credential.invitation);
 assert.equal((await authPool.query('SELECT is_locked FROM users')).rows[0].is_locked,true);
});
test('expiration at the physical commit rolls back an already inserted credential and its password history',async()=>{
 const created=await invite();const observe=store.observe;store.observe=async(...args)=>({...await observe(...args),validUntil:Math.floor(Date.now()/1000)+2});let inserted=false;
 interceptQueries(async(sql,_values,client)=>{if(sql==='COMMIT'){
  assert.equal((await client.query('SELECT count(*) AS n FROM users')).rows[0].n,'1');inserted=true;await client.query('SELECT pg_sleep(2.1)');
 }});
 const request={token:created.invitationToken,password:'Actual-Employee-Password-123!',observationAssertion:'actual-private-observation'};
 await assert.rejects(store.credential(request,claims('credential',request)),{status:503});assert.equal(inserted,true);
 for(const table of ['users','password_history'])assert.equal((await authPool.query('SELECT count(*) AS n FROM '+table)).rows[0].n,'0');
 assert.equal((await authPool.query('SELECT status FROM auth_employee_invitations')).rows[0].status,'pending');assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitation_events')).rows[0].n,'1');
});
test('retained invitation events and outbox fingerprints cannot be changed or removed',async()=>{
 const created=await invite();for(const statement of ["UPDATE auth_employee_invitation_events SET reason='Replaced original audit reason'",'DELETE FROM auth_employee_invitation_outbox','TRUNCATE auth_employee_invitation_events CASCADE'])await assert.rejects(authPool.query(statement),{code:'42501'});
 const read={id:created.invitation.id};assert.equal((await store.get(read,claims('get',read,bearer),bearer)).invitation.id,created.invitation.id);
});
