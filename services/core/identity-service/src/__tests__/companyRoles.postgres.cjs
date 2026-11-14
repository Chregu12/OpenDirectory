'use strict';
const {test,beforeEach,afterEach,after}=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');const {Pool}=require('pg');
const {activeCompany}=require('../../../../../scripts/lib/company-owner-fixture.cjs');const {adoptTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const {AuthorizationState}=require('../AuthorizationState');const {CompanyRoles}=require('../CompanyRoles');const C=require('../CompanyRoleContract');
const {DirectoryCreator}=require('../DirectoryCreator');const {DirectoryReader}=require('../DirectoryReader');const {UserMutator}=require('../UserMutator');const {GroupMutator,groupEtag}=require('../GroupMutator');const {OuMutator,ouEtag}=require('../OuMutator');const {userEtag}=require('../DirectoryUsers');
assert.ok(process.env.IDENTITY_TEST_DATABASE_URL);const admin=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});
const issuer='https://company-roles.native',bearer='Bearer original-company-roles-fixture';let schema,pool,db,owner,roles,creator,reader,options,beforeCommit;
const reason='Explicit independently reviewed company role decision';
const definition=(extra={})=>({name:'Scoped user operator',description:'Actual own company directory role',permissions:['users.read','users.update'],maxDurationSeconds:3600,reason,confirm:true,...extra});
beforeEach(async()=>{
 schema='cr_'+randomUUID().replaceAll('-','');await admin.query('CREATE SCHEMA '+schema);pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:8,options:`-c search_path=${schema},public -c timezone=UTC`});beforeCommit=null;
 db={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,settings={})=>{const client=await pool.connect();try{await client.query(settings.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');if(settings.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[settings.actor]);const result=await operation(client);if(!settings.readOnly&&beforeCommit)await beforeCommit(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 for(const file of fs.readdirSync(path.join(__dirname,'../../migrations')).filter(file=>file.endsWith('.sql')).sort())try{await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));}catch(error){throw new Error(file+': '+error.message+' '+error.where+' '+error.position);}
 owner=await activeCompany(db,schema,issuer);options={issuer,revalidate:async(_authorization,user)=>(await new AuthorizationState(db).state(issuer,user.sub)).tenant,revalidateAccess:async()=>{}};
 roles=new CompanyRoles(db,{revalidate:async(user)=>{const state=await new AuthorizationState(db).state(issuer,user.sub);assert.deepEqual(state.context,user.identity_authorization);}});creator=new DirectoryCreator(db,options);reader=new DirectoryReader(db,options);
});
afterEach(async()=>{beforeCommit=null;await pool?.end();if(schema)await admin.query('DROP SCHEMA '+schema+' CASCADE');});after(()=>admin.end());
async function person(label='employee'){
 const id=randomUUID(),subject=label+'-'+id;await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[id,subject,subject+'@test.invalid']);await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,id]);await adoptTenant(db,schema,owner.receipt.tenantId,[{kind:'user',resourceId:id}]);
 const source=await new AuthorizationState(db).state(issuer,subject),now=Math.floor(Date.now()/1000);return{id,user:{actor_type:'user',token_use:'access',iss:issuer,sub:subject,roles:source.roles,identity_authorization:source.context,auth_time:now,exp:now+3600,jti:randomUUID(),amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:id,revision:'1',authTime:now,methods:['pwd','otp']}}};
}
const createRole=async extra=>(await roles.create(definition(extra),owner.user,bearer)).role;
const assign=(role,target,extra={})=>roles.assign(role.id,{targetType:'user',targetId:target,scopeType:'tenant',ouId:null,durationSeconds:3600,reason,confirm:true,...extra},C.etag('role',role),owner.user,bearer);
test('actual custom role grants own directory read and profile updates without global token roles',async()=>{
 const delegate=await person('delegate'),target=await person('target');await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 const role=await createRole();const result=await assign(role,delegate.id);assert.equal(result.grant.status,'active');assert.deepEqual(delegate.user.roles,[]);
 const listing=await reader.users({},delegate.user,bearer);assert.ok(listing.users.some(row=>row.id===target.id));const current=await reader.user(target.id,{},delegate.user,bearer);
 const changed=await new UserMutator(db,options).update(target.id,{displayName:'Actual delegated profile update'},userEtag(current),delegate.user,bearer);assert.equal(changed.displayName,'Actual delegated profile update');
 const event=(await pool.query('SELECT proof FROM identity_company_role_uses WHERE resource_id=$1',[target.id])).rows[0];assert.equal(event.proof.companyRoles.grants[0].source.id,result.grant.id);
 const revoked=await roles.revoke(result.grant.id,{reason,confirm:true},C.etag('grant',result.grant),owner.user,bearer);assert.equal(revoked.grant.status,'revoked');await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('role definition edits invalidate old grants instead of expanding recipients rights',async()=>{
 const delegate=await person();const role=await createRole({permissions:['users.read']});const assigned=await assign(role,delegate.id);
 const updated=await roles.update(role.id,definition({permissions:['users.read','users.update'],enabled:true}),C.etag('role',role),owner.user,bearer);assert.equal(updated.role.revision,'2');
 await assert.rejects(reader.users({},delegate.user,bearer),{status:403});const detail=await roles.detail(role.id,{},owner.user,bearer);assert.equal(detail.grants[0].status,'definition-changed');
 await assign(updated.role,delegate.id);assert.ok((await reader.users({},delegate.user,bearer)).total>=2);await assert.rejects(roles.revoke(assigned.grant.id,{reason,confirm:true},'"company-grant-'+assigned.grant.id+'-9"',owner.user,bearer),{status:412});
});
test('only original own company managers may define or self-assign custom roles',async()=>{
 const delegate=await person();await assert.rejects(roles.create(definition(),delegate.user,bearer),{status:403});const role=await createRole();await assert.rejects(assign(role,owner.user.identity_authorization.userId));
 await assert.rejects(roles.create(definition({permissions:['identities.roles.manage']}),owner.user,bearer),{status:400});await assert.rejects(roles.update(role.id,definition({enabled:true}),undefined,owner.user,bearer),{status:428});
});
async function fixedOperator(roleName){const target=await person(roleName);await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[target.id,roleName,'Actual canonical separate duty native fixture']);const current=await new AuthorizationState(db).state(issuer,target.user.sub);target.user.roles=current.roles;target.user.identity_authorization=current.context;return target;}
test('OU scopes constrain counts, descendants, individual reads and writes, and survive no scope expansion by OU operators',async()=>{
 const delegate=await person('delegate'),inside=await person('inside'),outside=await person('outside');let root=await creator.ou({name:'Engineering'},owner.user,bearer);let child=await creator.ou({name:'Build systems',parentId:root.id},owner.user,bearer);const ous=new OuMutator(db,options);
 child=(await ous.addMember(child.id,{userId:inside.id},ouEtag(child),owner.user,bearer)).unit;
 const role=await createRole({permissions:['users.read','users.update','users.status.manage']});await assign(role,delegate.id,{scopeType:'ou',ouId:root.id});
 const listing=await reader.users({},delegate.user,bearer);assert.equal(listing.total,1);assert.equal(listing.users[0].id,inside.id);assert.equal((await reader.users({search:outside.user.sub},delegate.user,bearer)).total,0);
 await assert.rejects(reader.user(outside.id,{},delegate.user,bearer),{status:404});const current=await reader.user(inside.id,{},delegate.user,bearer);await new UserMutator(db,options).update(inside.id,{title:'Actual scoped user update'},userEtag(current),delegate.user,bearer);
 const foreign=await reader.user(outside.id,{},owner.user,bearer);await assert.rejects(new UserMutator(db,options).update(outside.id,{title:'Denied outside scope'},userEtag(foreign),delegate.user,bearer),{status:403});
 const manager=await fixedOperator('ou-administrator');const childNow=await reader.ou(child.id,{},owner.user,bearer);
 await assert.rejects(new OuMutator(db,options).addMember(child.id,{userId:outside.id},ouEtag(childNow),manager.user,bearer),{status:403});
 const ownerChanged=await ous.addMember(child.id,{userId:outside.id},ouEtag(childNow),owner.user,bearer);assert.equal(ownerChanged.membership.userId,outside.id);assert.equal((await reader.users({},delegate.user,bearer)).total,2);
});
test('only new explicitly protected static groups may carry roles; ordinary group administration cannot gain membership',async()=>{
 const delegate=await person('delegate'),target=await person('target');const created=await roles.createGroup({name:'Engineering operators',description:'Protected role group',reason,confirm:true},owner.user,bearer);const id=created.group.id;
 const group=await reader.group(id,{},owner.user,bearer);const member=await new GroupMutator(db,options).add(id,{userId:delegate.id},groupEtag(group),owner.user,bearer);
 const role=await createRole({permissions:['users.read']});await assign(role,id,{targetType:'group'});assert.ok((await reader.users({},delegate.user,bearer)).users.some(row=>row.id===target.id));
 const manager=await fixedOperator('group-administrator');await assert.rejects(new GroupMutator(db,options).add(id,{userId:manager.id},groupEtag(member),manager.user,bearer),{status:403});
 const normal=await creator.group({name:'Ordinary group'},owner.user,bearer);await assert.rejects(assign(role,normal.id,{targetType:'group'}),{status:404});
 const removed=await new GroupMutator(db,options).removeMember(id,delegate.id,groupEtag(member),owner.user,bearer);assert.ok(!removed.members.includes(delegate.id));await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('raw role writes, missing physical receivers and missing command/outbox evidence cannot commit',async()=>{
 const role=await createRole();await assert.rejects(pool.query('UPDATE identity_company_roles SET enabled=false'),{code:'42501'});
 await assert.rejects(pool.query('DELETE FROM identity_company_role_events'),{code:'42501'});await assert.rejects(pool.query('TRUNCATE identity_company_role_outbox'),{code:'42501'});
 await pool.query('ALTER TABLE identity_company_role_outbox DISABLE TRIGGER identity_company_role_guard');await assert.rejects(roles.list({},owner.user,bearer),{status:503});
});
test('custom grants cannot outlive the original MFA deadline at physical commit',async()=>{
 const delegate=await person('delegate'),target=await person('target');const role=await createRole();await assign(role,delegate.id);const current=await reader.user(target.id,{},owner.user,bearer);
 delegate.user.auth_time=Math.floor(Date.now()/1000)-299;delegate.user.mfa_authorization.authTime=delegate.user.auth_time;
 beforeCommit=async client=>client.query('SELECT pg_sleep(2.1)');await assert.rejects(new UserMutator(db,options).update(target.id,{title:'Must roll back after original assurance ends'},userEtag(current),delegate.user,bearer));beforeCommit=null;
 assert.equal((await reader.user(target.id,{},owner.user,bearer)).title,current.title);
});
test('canonical role readers can inspect own definitions and audit but cannot manage them',async()=>{
 const role=await createRole();const readOnly=await fixedOperator('role-reader');const result=await roles.list({},readOnly.user,bearer);assert.equal(result.roles[0].id,role.id);assert.equal(result.canManage,false);assert.deepEqual(await roles.permissions(readOnly.user),['company.roles.read']);await assert.rejects(roles.update(role.id,definition({enabled:false}),C.etag('role',role),readOnly.user,bearer),{status:403});assert.equal((await roles.history(role.id,{},readOnly.user,bearer)).total,1);
});
test('indirect OU profiles and global directory search retain scoped user boundaries',async()=>{
 const delegate=await person(),inside=await person('inside'),outside=await person('outside');let engineering=await creator.ou({name:'Engineering'},owner.user,bearer),sales=await creator.ou({name:'Sales'},owner.user,bearer);const mutator=new OuMutator(db,options);
 engineering=(await mutator.addMember(engineering.id,{userId:inside.id},ouEtag(engineering),owner.user,bearer)).unit;sales=(await mutator.addMember(sales.id,{userId:outside.id},ouEtag(sales),owner.user,bearer)).unit;
 const scoped=await createRole({permissions:['users.read']});await assign(scoped,delegate.id,{scopeType:'ou',ouId:engineering.id});const structures=await createRole({name:'Read own directory structure',permissions:['ous.read','groups.read']});await assign(structures,delegate.id);
 const own=await reader.ouMembers(engineering.id,{},delegate.user,bearer);assert.equal(own.profileAccess,true);assert.equal(own.members[0].profile.username,inside.user.sub);
 const other=await reader.ouMembers(sales.id,{},delegate.user,bearer);assert.equal(other.profileAccess,false);assert.equal(other.members[0].profile,undefined);
 const search=await reader.search({},delegate.user,bearer);assert.ok(search.entries.some(row=>row.id===inside.id));assert.ok(!search.entries.some(row=>row.id===outside.id));await assert.rejects(reader.userGroups(outside.id,{},delegate.user,bearer),{status:404});
});
test('the final SQL use fence rejects source drift after application checks and rolls back the whole write',async()=>{
 const delegate=await person(),target=await person();const role=await createRole();await assign(role,delegate.id);const current=await reader.user(target.id,{},owner.user,bearer);
 beforeCommit=async client=>{beforeCommit=null;
  // Privileged disposable corruption fixture: restore every guard before attempting commit.
  await client.query('ALTER TABLE identity_company_roles DISABLE TRIGGER USER');await client.query('UPDATE identity_company_roles SET enabled=false WHERE id=$1',[role.id]);await client.query('ALTER TABLE identity_company_roles ENABLE TRIGGER USER');
 };
 await assert.rejects(new UserMutator(db,options).update(target.id,{title:'Must not survive original source drift'},userEtag(current),delegate.user,bearer),{code:'42501'});
 assert.equal((await reader.user(target.id,{},owner.user,bearer)).title,current.title);assert.equal((await roles.detail(role.id,{},owner.user,bearer)).role.enabled,true);
});
test('a fabricated successful use admission without its retained record is rejected by the canonical kernel',async()=>{
 const delegate=await person(),target=await person();const role=await createRole();await assign(role,delegate.id);const current=await reader.user(target.id,{},owner.user,bearer);
 const missing={...db,transaction:(operation,settings)=>db.transaction(client=>operation({query:(sql,values)=>sql.startsWith('SELECT identity_company_role_admit_use')?Promise.resolve({rows:[]}):client.query(sql,values)}),settings)};
 await assert.rejects(new UserMutator(missing,options).update(target.id,{title:'Missing mandatory source use'},userEtag(current),delegate.user,bearer),{code:'42501'});assert.equal((await reader.user(target.id,{},owner.user,bearer)).title,current.title);
});
test('missing pending role outbox rolls back definition changes and preserves the original revision',async()=>{
 const role=await createRole();await pool.query('CREATE FUNCTION native_suppress_role_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');await pool.query('CREATE TRIGGER aaa_native_suppress_role_outbox BEFORE INSERT ON identity_company_role_outbox FOR EACH ROW EXECUTE FUNCTION native_suppress_role_outbox()');
 await assert.rejects(roles.update(role.id,definition({enabled:false}),C.etag('role',role),owner.user,bearer),{status:503});const current=await roles.detail(role.id,{},owner.user,bearer);assert.equal(current.role.revision,'1');assert.equal(current.role.enabled,true);
});
test('replaying the additive migration preserves grants, use receipts and every required guard',async()=>{
 const delegate=await person();const role=await createRole();await assign(role,delegate.id);await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/057_company_roles.sql'),'utf8'));assert.ok((await reader.users({},delegate.user,bearer)).users.some(row=>row.id===delegate.id));await pool.query('SELECT identity_company_role_receiving()');
});
test('a limited SQL login cannot read another actor role source through security-definer helpers',async()=>{
 const limited='cr_limited_'+randomUUID().replaceAll('-','');await pool.query('CREATE ROLE '+limited+' NOLOGIN');const client=await pool.connect();
 try{await pool.query('GRANT USAGE ON SCHEMA '+schema+' TO '+limited);await client.query('BEGIN');await client.query('SET LOCAL ROLE '+limited);
  await assert.rejects(client.query("SELECT identity_company_role_sources($1::uuid,$2::uuid,'users.read',NULL,NULL)",[owner.user.identity_authorization.userId,owner.receipt.tenantId]),{code:'42501'});
 }finally{await client.query('ROLLBACK');client.release();await pool.query('DROP OWNED BY '+limited);await pool.query('DROP ROLE '+limited);}
});
test('company managers cannot read or assign foreign definitions, users or OU scopes',async()=>{
 const ownRole=await createRole(),local=await person();const other=await activeCompany(db,schema,issuer);const foreignRole=(await roles.create(definition(),other.user,bearer)).role;const foreignOu=await creator.ou({name:'Foreign private OU'},other.user,bearer);
 await assert.rejects(roles.detail(foreignRole.id,{},owner.user,bearer),{status:404});await assert.rejects(assign(ownRole,other.user.identity_authorization.userId),{status:404});await assert.rejects(assign(ownRole,local.id,{scopeType:'ou',ouId:foreignOu.id}),{status:404});assert.deepEqual((await roles.list({},owner.user,bearer)).roles.map(row=>row.id),[ownRole.id]);
});
test('protected group authority and retained use proofs remain coherent in a non-UTC caller transaction',async()=>{
 const recipient=await person();const collection=(await roles.createGroup({name:'Timezone proof group',description:'Actual protected group',reason,confirm:true},owner.user,bearer)).group;const group=await reader.group(collection.id,{},owner.user,bearer);
 const local={...db,transaction:(operation,settings)=>db.transaction(async client=>{await client.query("SET LOCAL timezone='Pacific/Honolulu'");return operation(client);},settings)};
 const result=await new GroupMutator(local,options).add(collection.id,{userId:recipient.id},groupEtag(group),owner.user,bearer);assert.ok(result.members.includes(recipient.id));const proof=(await pool.query('SELECT proof FROM identity_company_role_uses WHERE resource_id=$1',[collection.id])).rows[0].proof;assert.equal(proof.companyGovernance.context.userId,owner.user.identity_authorization.userId);
});
test('a role manager cannot bypass self-grant restrictions by adding themselves after assigning a protected group',async()=>{
 const collection=(await roles.createGroup({name:'Independent protected membership',description:'No self elevation through group timing',reason,confirm:true},owner.user,bearer)).group;
 const role=await createRole({permissions:['users.read']});await assign(role,collection.id,{targetType:'group'});const group=await reader.group(collection.id,{},owner.user,bearer);
 await assert.rejects(new GroupMutator(db,options).add(group.id,{userId:owner.user.identity_authorization.userId},groupEtag(group),owner.user,bearer),{status:403});assert.deepEqual((await reader.group(group.id,{},owner.user,bearer)).members,[]);
});
