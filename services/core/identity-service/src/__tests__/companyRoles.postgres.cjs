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
test('directory work keeps its transaction budget after the independently bounded canonical authority lookup',async()=>{
 const delegate=await person('reader-budget');await assign(await createRole({permissions:['users.read']}),delegate.id);
 const tenant=await reader.read(['users.read'],delegate.user,bearer,async(client,tenantId)=>{await client.query('SELECT pg_sleep(1.1)');return tenantId;});
 assert.equal(tenant,owner.receipt.tenantId);
});
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
 const delegate=await person();const role=await createRole();await assign(role,delegate.id);await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/057_company_roles.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/058_company_pim.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/059_company_pim_approvals.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/061_company_pim_approver_groups.sql'),'utf8'));assert.ok((await reader.users({},delegate.user,bearer)).users.some(row=>row.id===delegate.id));await pool.query('SELECT identity_company_role_receiving()');
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
const {CompanyPim}=require('../CompanyPim');
const pim=()=>new CompanyPim(db,{revalidate:async user=>{const state=await new AuthorizationState(db).state(issuer,user.sub);assert.deepEqual(state.context,user.identity_authorization);}});
const makeEligible=(role,target,extra={})=>pim().assign(role.id,{targetType:'user',targetId:target,scopeType:'tenant',ouId:null,validForSeconds:30*86400,reason,confirm:true,...extra},C.etag('role',role),owner.user,bearer);
const activate=(eligible,user,durationSeconds=3600)=>pim().activate(eligible.id,{durationSeconds,reason,confirm:true},C.etag('eligibility',eligible),user,bearer);
test('own PIM eligibility grants no access until actual self activation and supports immediate self cancellation and retained history',async()=>{
 const delegate=await person(),target=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;assert.equal(eligible.status,'eligible');
 await assert.rejects(reader.users({},delegate.user,bearer),{status:403});const list=await pim().self({},delegate.user,bearer);assert.equal(list.total,1);assert.equal(list.items[0].role.id,role.id);assert.equal(list.items[0].activation,null);
 const current=(await activate(eligible,delegate.user)).activation;assert.equal(current.status,'active');assert.equal((await pim().self({tab:'active'},delegate.user,bearer)).items[0].activation.id,current.id);
 const before=await reader.user(target.id,{},delegate.user,bearer);await new UserMutator(db,options).update(target.id,{title:'Activated original custom role'},userEtag(before),delegate.user,bearer);
 const use=(await pool.query('SELECT proof FROM identity_company_role_uses WHERE resource_id=$1',[target.id])).rows[0].proof;assert.equal(use.companyRoles.grants[0].source.activationId,current.id);
 const ended=await pim().end(current.id,{reason,confirm:true},C.etag('activation',current),delegate.user,bearer);assert.equal(ended.activation.status,'ended');await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 assert.equal((await pim().history({},delegate.user,bearer)).total,2);assert.equal((await pim().history({},target.user,bearer)).total,0);assert.equal((await pim().eligibilities(role.id,{},owner.user,bearer)).eligibilities[0].id,eligible.id);
 const again=await activate(eligible,delegate.user);assert.notEqual(again.activation.id,current.id);assert.deepEqual(delegate.user.roles,[]);
});
test('own PIM activation stays usable beyond five-minute MFA freshness while stale direct grants do not expand its OU scope',async()=>{
 const delegate=await person(),inside=await person('inside'),outside=await person('outside');const ouMutator=new OuMutator(db,options);
 let a=await creator.ou({name:'PIM Engineering'},owner.user,bearer),b=await creator.ou({name:'Separate direct scope'},owner.user,bearer);
 a=(await ouMutator.addMember(a.id,{userId:inside.id},ouEtag(a),owner.user,bearer)).unit;b=(await ouMutator.addMember(b.id,{userId:outside.id},ouEtag(b),owner.user,bearer)).unit;
 const role=await createRole();await assign(role,delegate.id,{scopeType:'ou',ouId:b.id});const eligible=(await makeEligible(role,delegate.id,{scopeType:'ou',ouId:a.id})).eligibility;
 delegate.user.auth_time=Math.floor(Date.now()/1000)-298;delegate.user.mfa_authorization.authTime=delegate.user.auth_time;await activate(eligible,delegate.user);
 await pool.query('SELECT pg_sleep(3.2)');const list=await reader.users({},delegate.user,bearer);assert.equal(list.total,1);assert.equal(list.users[0].id,inside.id);await assert.rejects(reader.user(outside.id,{},delegate.user,bearer),{status:404});
 const before=await reader.user(inside.id,{},delegate.user,bearer);const changed=await new UserMutator(db,options).update(inside.id,{title:'Actual longer PIM lease'},userEtag(before),delegate.user,bearer);assert.equal(changed.title,'Actual longer PIM lease');
 await assert.rejects(activate(eligible,delegate.user),{status:428});
});
test('protected group eligibility binds the original membership incarnation and cannot revive after remove and re-add',async()=>{
 const delegate=await person();const collection=(await roles.createGroup({name:'Eligible Engineering group',description:'PIM delegation',reason,confirm:true},owner.user,bearer)).group;
 let group=await reader.group(collection.id,{},owner.user,bearer);group=await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);
 const role=await createRole();const eligible=(await makeEligible(role,group.id,{targetType:'group'})).eligibility;await activate(eligible,delegate.user);assert.ok((await reader.users({},delegate.user,bearer)).total>0);
 group=await new GroupMutator(db,options).removeMember(group.id,delegate.id,groupEtag(group),owner.user,bearer);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 group=await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 await activate(eligible,delegate.user);assert.ok((await reader.users({},delegate.user,bearer)).total>0);await pim().revokeEligibility(eligible.id,{reason,confirm:true},C.etag('eligibility',eligible),owner.user,bearer);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('role definition changes invalidate PIM eligibility and activations without silently expanding actions',async()=>{
 const delegate=await person();const role=await createRole({permissions:['users.read']});const eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user);
 await roles.update(role.id,definition({permissions:['users.read','users.update'],enabled:true}),C.etag('role',role),owner.user,bearer);
 await assert.rejects(reader.users({},delegate.user,bearer),{status:403});assert.equal((await pim().self({},delegate.user,bearer)).total,0);assert.equal((await pim().self({tab:'active'},delegate.user,bearer)).items[0].activation.status,'invalid');await assert.rejects(activate(eligible,delegate.user),{status:404});
});
test('PIM eligibility and activation reject self-assignment, other users, stale versions, absent confirmation and unbounded durations',async()=>{
 const delegate=await person(),other=await person();const role=await createRole();await assert.rejects(makeEligible(role,owner.user.identity_authorization.userId),{status:403});const eligible=(await makeEligible(role,delegate.id)).eligibility;
 await assert.rejects(activate(eligible,other.user),{status:404});await assert.rejects(activate(eligible,delegate.user,3601),{status:409});
 await assert.rejects(pim().activate(eligible.id,{durationSeconds:60,reason,confirm:true},'"company-eligibility-'+eligible.id+'-99"',delegate.user,bearer),{status:412});
 await assert.rejects(pim().activate(eligible.id,{durationSeconds:60,reason,confirm:false},C.etag('eligibility',eligible),delegate.user,bearer),{status:400});
 const actual=(await activate(eligible,delegate.user)).activation;await assert.rejects(activate(eligible,delegate.user),{status:409});await assert.rejects(pim().end(actual.id,{reason,confirm:true},C.etag('activation',actual),other.user,bearer),{status:404});
 await pim().end(actual.id,{reason,confirm:true},C.etag('activation',actual),owner.user,bearer,true);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('current PIM sources require the original MFA revision, subject and actor context',async()=>{
 const delegate=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user);
 const changed=structuredClone(delegate.user);changed.mfa_authorization.revision='2';await assert.rejects(reader.users({},changed,bearer),{status:403});assert.equal((await pim().self({tab:'active'},changed,bearer)).items[0].activation.status,'invalid');await activate(eligible,changed);assert.ok((await reader.users({},changed,bearer)).total>0);
 await pool.query('UPDATE users SET display_name=$2 WHERE id=$1',[delegate.id,'Unrelated profile keeps PIM']);assert.ok((await reader.users({},delegate.user,bearer)).total>0);
});
test('missing PIM event outbox or a fabricated positive admission cannot create effective activation',async()=>{
 const delegate=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;
 const missing={...db,transaction:(operation,settings)=>db.transaction(client=>operation({query:(sql,values)=>sql.startsWith('SELECT identity_company_role_pim_change')?Promise.resolve({rows:[{id:randomUUID()}]}):client.query(sql,values)}),settings)};
 await assert.rejects(new CompanyPim(missing,{revalidate:async()=>{}}).activate(eligible.id,{durationSeconds:60,reason,confirm:true},C.etag('eligibility',eligible),delegate.user,bearer),{status:503});
 await pool.query('CREATE FUNCTION suppress_pim_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');await pool.query('CREATE TRIGGER aaa_suppress_pim_outbox BEFORE INSERT ON identity_company_role_outbox FOR EACH ROW EXECUTE FUNCTION suppress_pim_outbox()');
 await assert.rejects(activate(eligible,delegate.user),{status:503});assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_role_activations')).rows[0].count,'0');await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('PIM activation final commit rechecks the real eligibility and unchanged original deadline',async()=>{
 const delegate=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;
 beforeCommit=async client=>{beforeCommit=null;await client.query('ALTER TABLE identity_company_role_eligibilities DISABLE TRIGGER USER');await client.query('UPDATE identity_company_role_eligibilities SET revoked_at=clock_timestamp() WHERE id=$1',[eligible.id]);await client.query('ALTER TABLE identity_company_role_eligibilities ENABLE TRIGGER USER');};
 await assert.rejects(activate(eligible,delegate.user));beforeCommit=null;assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_role_activations')).rows[0].count,'0');
 delegate.user.auth_time=Math.floor(Date.now()/1000)-299;delegate.user.mfa_authorization.authTime=delegate.user.auth_time;beforeCommit=client=>client.query('SELECT pg_sleep(2.1)');await assert.rejects(activate(eligible,delegate.user));beforeCommit=null;
 assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_role_activations')).rows[0].count,'0');
});
test('an activation that expires during a real pending directory write cannot commit its resource change',async()=>{
 const delegate=await person(),target=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user,60);const original=await reader.user(target.id,{},delegate.user,bearer);
 beforeCommit=async client=>{await client.query("SET LOCAL statement_timeout='70s'");await client.query('SELECT pg_sleep(60.5)');};await assert.rejects(new UserMutator(db,options).update(target.id,{title:'Must roll back after actual PIM expiry'},userEtag(original),delegate.user,bearer),{code:'42501'});beforeCommit=null;
 assert.equal((await reader.user(target.id,{},owner.user,bearer)).title,original.title);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('PIM eligibility and active leases do not revive when the original employee is disabled and reactivated',async()=>{
 const delegate=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user);
 let current=await reader.user(delegate.id,{},owner.user,bearer);current=await new UserMutator(db,options).update(delegate.id,{enabled:false},userEtag(current),owner.user,bearer);await new UserMutator(db,options).update(delegate.id,{enabled:true},userEtag(current),owner.user,bearer);
 const state=await new AuthorizationState(db).state(issuer,delegate.user.sub);delegate.user.identity_authorization=state.context;await assert.rejects(reader.users({},delegate.user,bearer),{status:403});assert.equal((await pim().self({},delegate.user,bearer)).total,0);
});
test('PIM raw rows, missing receiver manifests and public SQL helper calls fail closed',async()=>{
 const delegate=await person();const role=await createRole();const eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user);
 await assert.rejects(pool.query('UPDATE identity_company_role_activations SET ended_at=clock_timestamp(),ended_by=$1',[delegate.id]),{code:'42501'});await assert.rejects(pool.query('TRUNCATE identity_company_role_eligibilities CASCADE'),{code:'42501'});
 const limited='pim_limited_'+randomUUID().replaceAll('-','');await pool.query('CREATE ROLE '+limited+' NOLOGIN');const client=await pool.connect();try{await pool.query('GRANT USAGE ON SCHEMA '+schema+' TO '+limited);await client.query('BEGIN');await client.query('SET LOCAL ROLE '+limited);await assert.rejects(client.query('SELECT identity_company_role_pim_candidates($1::uuid,$2::uuid)',[delegate.id,owner.receipt.tenantId]),{code:'42501'});}finally{await client.query('ROLLBACK');client.release();await pool.query('DROP OWNED BY '+limited);await pool.query('DROP ROLE '+limited);}
 await pool.query('ALTER TABLE identity_company_role_pim_manifest DISABLE TRIGGER company_role_pim_manifest_guard');await assert.rejects(pim().self({},delegate.user,bearer),{status:503});
});
test('a real activated company lease reaches all four existing directory writers after the direct MFA window',async()=>{
 const delegate=await person(),target=await person();const role=await createRole({permissions:[...C.PERMISSIONS]});const eligible=(await makeEligible(role,delegate.id)).eligibility;delegate.user.auth_time=Math.floor(Date.now()/1000)-298;delegate.user.mfa_authorization.authTime=delegate.user.auth_time;await activate(eligible,delegate.user);await pool.query('SELECT pg_sleep(3.1)');
 const personCreated=await creator.user({username:'activated-new-account',email:'activated-new@test.invalid'},delegate.user,bearer);assert.equal(personCreated.enabled,false);
 let collection=await creator.group({name:'Activated new group'},delegate.user,bearer);const groups=new GroupMutator(db,options);collection=await groups.update(collection.id,{description:'Actual activated group update'},groupEtag(collection),delegate.user,bearer);collection=await groups.add(collection.id,{userId:target.id},groupEtag(collection),delegate.user,bearer);assert.ok(collection.members.includes(target.id));collection=await groups.removeMember(collection.id,target.id,groupEtag(collection),delegate.user,bearer);await groups.remove(collection.id,groupEtag(collection),delegate.user,bearer);
 let unit=await creator.ou({name:'Activated new OU'},delegate.user,bearer);const units=new OuMutator(db,options);unit=await units.update(unit.id,{description:'Actual activated OU update'},ouEtag(unit),delegate.user,bearer);const added=await units.addMember(unit.id,{userId:target.id},ouEtag(unit),delegate.user,bearer);const removed=await units.removeMember(unit.id,added.membership.id,ouEtag(added.unit),delegate.user,bearer);await units.remove(unit.id,ouEtag(removed.unit),delegate.user,bearer);
 const current=await reader.user(target.id,{},delegate.user,bearer);const changed=await new UserMutator(db,options).update(target.id,{title:'Actual activated user update'},userEtag(current),delegate.user,bearer);assert.equal(changed.title,'Actual activated user update');
 const kinds=(await pool.query('SELECT DISTINCT resource_kind FROM identity_company_role_uses ORDER BY resource_kind')).rows.map(row=>row.resource_kind);assert.deepEqual(kinds,['group','ou','user']);
});
const {CompanyPimApprovals}=require('../CompanyPimApprovals');const ApprovalContract=require('../CompanyPimApprovalContract');
const approvals=()=>new CompanyPimApprovals(db,{revalidate:async user=>{const state=await new AuthorizationState(db).state(issuer,user.sub);assert.deepEqual(state.context,user.identity_authorization);}});
async function approvalPolicy(role,extra={}){const current=await approvals().policy(role.id,owner.user,bearer);return(await approvals().updatePolicy(role.id,{approvalRequired:true,windowSeconds:300,reason,confirm:true,...extra},ApprovalContract.policyEtag(current),owner.user,bearer)).policy;}
const requested=(eligible,user,policy,durationSeconds=3600)=>approvals().create(eligible.id,{durationSeconds,policyRevision:policy.revision,reason,confirm:true},C.etag('eligibility',eligible),user,bearer);
const decision=(request,action,user=owner.user)=>approvals().decide(request.id,action,{reason,confirm:true},C.etag('request',request),user,bearer);
test('independent own-role approval produces no rights until the actual person consumes the exact approval',async()=>{
 const delegate=await person(),target=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility;const policy=await approvalPolicy(role);
 await assert.rejects(activate(eligible,delegate.user),{status:428});const available=await approvals().options(eligible.id,delegate.user,bearer);assert.equal(available.approvalRequired,true);assert.equal(available.existingRequest,null);
 const pending=(await requested(eligible,delegate.user,policy)).request;assert.equal(pending.status,'pending');assert.equal((await approvals().list({},delegate.user,bearer)).items[0].id,pending.id);assert.equal((await approvals().list({},target.user,bearer)).total,0);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 const queue=await approvals().list({},owner.user,bearer,true);assert.equal(queue.total,1);assert.equal(queue.canReview,true);
 const approved=(await decision(pending,'approve')).request;assert.equal(approved.status,'approved');await assert.rejects(activate(eligible,delegate.user),{status:428});
 const result=await approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer);assert.equal(result.activation.status,'active');
 const actual=(await pool.query('SELECT approval_policy_revision::text,approval_request_id FROM identity_company_role_activations WHERE id=$1',[result.activation.id])).rows[0];assert.equal(actual.approval_policy_revision,policy.revision);assert.equal(actual.approval_request_id,approved.id);
 const before=await reader.user(target.id,{},delegate.user,bearer);assert.equal((await new UserMutator(db,options).update(target.id,{title:'Actual independently approved write'},userEtag(before),delegate.user,bearer)).title,'Actual independently approved write');
 await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer),{status:412});
 await pim().end(result.activation.id,{reason,confirm:true},C.etag('activation',result.activation),delegate.user,bearer);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 assert.ok((await pim().history({},delegate.user,bearer)).events.some(event=>event.action==='pim-request-approve'));
});
test('an original canonical PIM approver can review own-tenant requests without receiving role-policy administration',async()=>{
 const delegate=await person(),reviewer=await fixedOperator('pim-approver');const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role);
 const pending=(await requested(eligible,delegate.user,policy)).request;assert.equal((await approvals().list({},reviewer.user,bearer,true)).canReview,true);const approved=(await decision(pending,'approve',reviewer.user)).request;assert.equal(approved.decidedBy,reviewer.id);
 await assert.rejects(approvals().policy(role.id,reviewer.user,bearer),{status:403});assert.equal((await approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer)).activation.status,'active');
});
test('even an actual role manager cannot approve their own request, and only the original person may activate or cancel',async()=>{
 const delegate=await fixedOperator('role-administrator'),other=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role);const pending=(await requested(eligible,delegate.user,policy)).request;
 await assert.rejects(decision(pending,'approve',delegate.user),{status:403});await assert.rejects(decision(pending,'deny',delegate.user),{status:403});await assert.rejects(decision(pending,'approve',other.user),{status:403});await assert.rejects(decision(pending,'cancel',other.user),{status:404});
 const approved=(await decision(pending,'approve')).request;await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),other.user,bearer),{status:404});
 const cancelled=(await decision(approved,'cancel',delegate.user)).request;assert.equal(cancelled.status,'cancelled');assert.equal(cancelled.decidedBy,owner.user.identity_authorization.userId);await assert.rejects(approvals().activate(cancelled.id,{reason,confirm:true},C.etag('request',cancelled),delegate.user,bearer),{status:409});
});
test('policy changes invalidate original active leases and requests instead of silently extending authority',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility;await activate(eligible,delegate.user);const policy=await approvalPolicy(role);await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
 const pending=(await requested(eligible,delegate.user,policy)).request;const changed=await approvals().updatePolicy(role.id,{approvalRequired:true,windowSeconds:600,reason,confirm:true},ApprovalContract.policyEtag(policy),owner.user,bearer);assert.equal(changed.policy.revision,'2');assert.equal((await approvals().list({},delegate.user,bearer)).items[0].status,'stale');await assert.rejects(decision(pending,'approve'),{status:409});await assert.rejects(requested(eligible,delegate.user,policy),{status:409});
 const next=(await requested(eligible,delegate.user,changed.policy)).request;assert.equal(next.status,'pending');await decision(next,'deny');assert.equal((await approvals().list({},delegate.user,bearer)).items.find(row=>row.id===next.id).status,'denied');
});
test('a current independent approval binds the original membership incarnation and cannot survive remove and re-add',async()=>{
 const delegate=await person();const collection=(await roles.createGroup({name:'Reviewed eligible role group',description:'Original static membership',reason,confirm:true},owner.user,bearer)).group;let group=await reader.group(collection.id,{},owner.user,bearer);group=await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);
 const role=await createRole(),eligible=(await makeEligible(role,group.id,{targetType:'group'})).eligibility,policy=await approvalPolicy(role);const pending=(await requested(eligible,delegate.user,policy)).request;const approved=(await decision(pending,'approve')).request;
 group=await new GroupMutator(db,options).removeMember(group.id,delegate.id,groupEtag(group),owner.user,bearer);await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);assert.equal((await approvals().list({},delegate.user,bearer)).items[0].status,'stale');await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer),{status:409});
});
test('approved activation requires a fresh original MFA and the same MFA revision while own cancellation needs no extra freshness',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role);const pending=(await requested(eligible,delegate.user,policy)).request,approved=(await decision(pending,'approve')).request;
 const older=structuredClone(delegate.user);older.auth_time-=301;older.mfa_authorization.authTime=older.auth_time;await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),older,bearer),{status:428});
 const reset=structuredClone(delegate.user);reset.mfa_authorization.revision='2';assert.equal((await approvals().list({},reset,bearer)).items[0].status,'stale');await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),reset,bearer),{status:409});const cancelled=await decision(approved,'cancel',older);assert.equal(cancelled.request.status,'cancelled');
});
test('competing independent decisions serialize on the real tenant lock and only one exact revision can commit',async()=>{
 const delegate=await person(),reviewer=await fixedOperator('pim-approver');const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role),pending=(await requested(eligible,delegate.user,policy)).request;
 const results=await Promise.allSettled([decision(pending,'approve'),decision(pending,'deny',reviewer.user)]);assert.equal(results.filter(value=>value.status==='fulfilled').length,1);assert.equal(results.filter(value=>value.status==='rejected'&&value.reason.status===412).length,1);
});
test('missing request outbox, fabricated positive admission, removed manifests and unbound raw writes cannot create or approve requests',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role);
 const missing={...db,transaction:(operation,settings)=>db.transaction(client=>operation({query:(sql,values)=>sql.startsWith('SELECT identity_company_pim_approval_change')?Promise.resolve({rows:[{id:randomUUID()}]}):client.query(sql,values)}),settings)};
 await assert.rejects(new CompanyPimApprovals(missing,{revalidate:async()=>{}}).create(eligible.id,{durationSeconds:60,policyRevision:policy.revision,reason,confirm:true},C.etag('eligibility',eligible),delegate.user,bearer),{status:503});
 await pool.query('CREATE FUNCTION suppress_approval_outbox() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');await pool.query('CREATE TRIGGER aaa_suppress_approval_outbox BEFORE INSERT ON identity_company_role_outbox FOR EACH ROW EXECUTE FUNCTION suppress_approval_outbox()');await assert.rejects(requested(eligible,delegate.user,policy),{status:503});assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_pim_requests')).rows[0].count,'0');
 await assert.rejects(pool.query('UPDATE identity_company_pim_policies SET approval_required=false'),{code:'42501'});await assert.rejects(pool.query('TRUNCATE identity_company_pim_requests CASCADE'),{code:'42501'});await pool.query('ALTER TABLE identity_company_pim_approval_manifest DISABLE TRIGGER company_pim_approval_manifest_guard');await assert.rejects(approvals().list({},delegate.user,bearer),{status:503});
});
test('approval source drift after admission is rechecked at physical commit and rolls the decision back',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role),pending=(await requested(eligible,delegate.user,policy)).request;
 beforeCommit=async client=>{beforeCommit=null;await client.query('ALTER TABLE identity_company_role_eligibilities DISABLE TRIGGER USER');await client.query('UPDATE identity_company_role_eligibilities SET revoked_at=clock_timestamp() WHERE id=$1',[eligible.id]);await client.query('ALTER TABLE identity_company_role_eligibilities ENABLE TRIGGER USER');};await assert.rejects(decision(pending,'approve'),{code:'42501'});beforeCommit=null;assert.equal((await approvals().list({},delegate.user,bearer)).items[0].state,'pending');
});
test('an approval that expires while activation is pending cannot be consumed at physical commit',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role,{windowSeconds:60}),pending=(await requested(eligible,delegate.user,policy)).request,approved=(await decision(pending,'approve')).request;
 beforeCommit=async client=>{await client.query("SET LOCAL statement_timeout='70s'");await client.query('SELECT pg_sleep(60.5)');};await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer),{code:'42501'});beforeCommit=null;assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_role_activations')).rows[0].count,'0');const current=(await approvals().list({},delegate.user,bearer)).items[0];assert.equal(current.state,'approved');assert.equal(current.status,'expired');await assert.rejects(reader.users({},delegate.user,bearer),{status:403});
});
test('own PIM review cannot cross tenants and new approval helpers are not public SQL authority',async()=>{
 const delegate=await person();const role=await createRole(),eligible=(await makeEligible(role,delegate.id)).eligibility,policy=await approvalPolicy(role),pending=(await requested(eligible,delegate.user,policy)).request;const foreign=await activeCompany(db,schema,issuer);
 await assert.rejects(approvals().options(eligible.id,foreign.user,bearer),{status:404});await assert.rejects(decision(pending,'approve',foreign.user),{status:404});assert.equal((await approvals().list({},foreign.user,bearer,true)).total,0);await assert.rejects(approvals().policy(role.id,foreign.user,bearer),{status:404});await assert.rejects(approvals().list({tenantId:owner.receipt.tenantId},foreign.user,bearer,true),{status:400});
 const name='approval_limited_'+randomUUID().replaceAll('-','');await pool.query('CREATE ROLE '+name+' NOLOGIN');const client=await pool.connect();try{await pool.query('GRANT USAGE ON SCHEMA '+schema+' TO '+name);await client.query('BEGIN');await client.query('SET LOCAL ROLE '+name);await assert.rejects(client.query('SELECT identity_company_pim_approval_policy($1::uuid)',[role.id]),{code:'42501'});}finally{await client.query('ROLLBACK');client.release();await pool.query('DROP OWNED BY '+name);await pool.query('DROP ROLE '+name);}
});

async function withDevices(operation,{scoped=false}={}){
 const {DeviceInventoryAuthority}=require('../DeviceInventoryAuthority');
 const source=new DeviceInventoryAuthority(db,options);
 const fixture=await require('../../../../../scripts/lib/device-inventory-fixture.cjs').deviceInventoryFixture(process.env.IDENTITY_TEST_DATABASE_URL,'http://127.0.0.1:1');
 const authority={scoped,read:(authorization,user,target,selected=null)=>source[scoped?'readScoped':'read'](user,authorization,selected?{userId:target||null,device:selected}:target?{userId:target}:null)};
 const inventory=new (require('../../../device-service/src/DeviceInventory').DeviceInventory)(fixture.db,{authority});
 try{return await operation({inventory,deviceDb:fixture.db,source});}finally{await fixture.close();}
}
const deviceValues=()=>({assetId:'NATIVE-'+randomUUID(),serialNumber:randomUUID(),manufacturer:'Actual native fixture',model:'Delegated inventory',deviceClass:'laptop',platform:'linux'});
const deviceUpdate=(device,changes={})=>({...Object.fromEntries(require('../../../../../packages/device-inventory-contract').DEVICE_FIELDS.map(field=>[field,device[field]])),...changes,reason,confirm:true});
async function deviceState(database){
 const state={};for(const table of ['devices','device_inventory_assignments','device_inventory_events','device_inventory_outbox','device_ou_assignments','device_ou_events','device_ou_outbox'])state[table]=(await database.query('SELECT to_jsonb(record)::text AS row FROM '+table+' record ORDER BY to_jsonb(record)::text')).rows;
 return state;
}
async function scopedDevices(operation,permissions=['devices.inventory.read','devices.compliance.read']){
 const delegate=await person(),root=await creator.ou({name:'Scoped device reads'},owner.user,bearer),child=await creator.ou({name:'Scoped device child',parentId:root.id},owner.user,bearer),outside=await creator.ou({name:'Other device scope'},owner.user,bearer);
 const role=await createRole({name:'Scoped device fixture duties',permissions}),grant=(await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).grant;
 return withDevices(async({inventory,deviceDb,source})=>{
  const originalOu=new(require('../DeviceOuAuthority').DeviceOuAuthority)(db,options);
  const client=user=>new(require('../../../device-service/src/DeviceOuSource').DeviceOuSource)({scoped:true,endpoint:'https://identity.native/api/identity/device-organizational-units',fetchImpl:async(url,request)=>{
   assert.equal(request.headers['X-OD-Device-Scope-Protocol'],'1');
   return Response.json(await(request.method==='GET'?originalOu.unitsScoped(Object.fromEntries(url.searchParams),user,request.headers.Authorization):url.pathname.endsWith('/status')?originalOu.status(JSON.parse(request.body),user,request.headers.Authorization,true):originalOu.resolveScoped(JSON.parse(request.body),user,request.headers.Authorization)));
  }});
  const units=new(require('../../../device-service/src/DeviceOrganizationalUnits').DeviceOrganizationalUnits)(deviceDb,{inventory,authority:{scoped:true,read:(authorization,user,ouId,resource=null)=>client(user).read(authorization,user,ouId,resource),units:(authorization,user,tenant,query,source)=>client(user).units(authorization,user,tenant,query,source),status:(authorization,user,selection)=>client(user).status(authorization,user,selection)}});
  const setUnit=async(device,unit)=>{const old=await units.get(device.id,{},owner.user,bearer),selected=unit?(await originalOu.resolve({ouId:unit.id},owner.user,bearer)).ou:null;return units.write(device.id,{ou:selected?{id:selected.id,generation:selected.generation,revision:selected.revision}:null,reason,confirm:true},require('../../../../../packages/device-ou-contract').etag(device.id,old.deviceRevision,old.revision),owner.user,bearer,randomUUID());};
  const inside=await inventory.create({...deviceValues(),assetId:'SCOPED-IN'},owner.user,bearer),nested=await inventory.create({...deviceValues(),assetId:'SCOPED-CHILD'},owner.user,bearer),hidden=await inventory.create({...deviceValues(),assetId:'SECRET-OUT',platform:'windows'},owner.user,bearer),unassigned=await inventory.create({...deviceValues(),assetId:'SECRET-NONE'},owner.user,bearer);
  await setUnit(inside,root);await setUnit(nested,child);await setUnit(hidden,outside);
  const agents=new(require('../../../device-service/src/DeviceAgents').DeviceAgents)(deviceDb,{inventory}),sync=new(require('../../../device-service/src/DeviceSync').DeviceSync)(deviceDb,{inventory}),compliance=new(require('../../../device-service/src/DeviceCompliance').DeviceCompliance)(deviceDb,{inventory,authority:{read:(authorization,user)=>source.readScoped(user,authorization,null,true)}});
  return operation({inventory,deviceDb,source,delegate,role,grant,root,child,outside,inside,nested,hidden,unassigned,units,setUnit,agents,sync,compliance});
 },{scoped:true});
}
test('device OU writes maintain assign and release actual scoped inventory with the original bound source',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,source,delegate,inside,nested,hidden})=>{
  const actualSource=await source.readScoped(delegate.user,bearer);await assert.rejects(source.read(delegate.user,bearer),{status:403});assert.equal((await deviceDb.query('SELECT device_scope_source_valid($1::jsonb) AS valid',[JSON.stringify(actualSource)])).rows[0].valid,true,'Actual original scoped Identity source must cross the physical receiver');
  const updated=await inventory.update(inside.id,deviceUpdate(inside,{model:'Actually scoped maintenance'}),contract.deviceEtag(inside),delegate.user,bearer,randomUUID());assert.equal(updated.model,'Actually scoped maintenance');assert.equal(BigInt(updated.revision),BigInt(inside.revision)+1n);
  const recipient=await person();const assigned=await inventory.assign(updated.id,{userId:recipient.id},contract.deviceEtag(updated),delegate.user,bearer,randomUUID());assert.equal(assigned.assignedUserId,recipient.id);
  const released=await inventory.assign(assigned.id,{userId:null},contract.deviceEtag(assigned),delegate.user,bearer,randomUUID());assert.equal(released.assignedUserId,null);assert.equal(released.lifecycle,'available');
  const maintained=await inventory.lifecycle(nested.id,{lifecycle:'maintenance',reason,confirm:true},contract.deviceEtag(nested),delegate.user,bearer,randomUUID());assert.equal(maintained.lifecycle,'maintenance');
  const events=(await deviceDb.query("SELECT event.*,outbox.status FROM device_inventory_events event JOIN device_inventory_outbox outbox USING(id) WHERE event.device_id=$1 AND event.action<>'create' ORDER BY event.created_at",[inside.id])).rows;
  assert.equal(events.length,3);for(const event of events){assert.equal(event.status,'pending');assert.equal(event.proof.source.schemaVersion,2);assert.equal(event.proof.source.scope.resource.deviceId,inside.id);assert.equal(event.proof.source.scope.resource.deviceRevision,event.before_state.inventory_revision);assert.equal(event.proof.source.scope.resource.ou.id,actualSource.scope.grants[0].source.ouId);assert.equal(event.proof.source.tokenId,delegate.user.jti);assert.deepEqual(event.proof.source.context,delegate.user.identity_authorization);}
  assert.equal(events[1].proof.source.target.id,recipient.id);assert.equal(events[2].proof.source.target,null);
  await assert.rejects(inventory.update(hidden.id,deviceUpdate(hidden,{model:'Must remain hidden'}),contract.deviceEtag(hidden),delegate.user,bearer,randomUUID()),{status:404});
 },['devices.inventory.read','devices.inventory.create','devices.inventory.assign']);
});
test('device OU writes hide outside and unassigned devices before versions or business-state conflicts',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,hidden,unassigned,inside})=>{
  const recipient=await person(),before=await deviceState(deviceDb);
  for(const device of [hidden,unassigned]){
   await assert.rejects(inventory.update(device.id,deviceUpdate(device),contract.deviceEtag(device),delegate.user,bearer),{status:404});
   await assert.rejects(inventory.lifecycle(device.id,{lifecycle:'available',reason,confirm:true},contract.deviceEtag(device),delegate.user,bearer),{status:404});
   await assert.rejects(inventory.assign(device.id,{userId:recipient.id},contract.deviceEtag({...device,revision:'999'}),delegate.user,bearer),{status:404});
   await assert.rejects(inventory.assign(device.id,{userId:null},contract.deviceEtag(device),delegate.user,bearer),{status:404});
  }
  await assert.rejects(inventory.create(deviceValues(),delegate.user,bearer),{status:403});
  await assert.rejects(inventory.assign(inside.id,{userId:randomUUID()},contract.deviceEtag(inside),delegate.user,bearer),{status:404});
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Expired factor'}),contract.deviceEtag(inside),{...delegate.user,auth_time:delegate.user.auth_time-301},bearer),{status:428});
  assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create','devices.inventory.assign']);
});
test('device OU writes preserve an independent tenant stock duty without binding unrelated scoped assignment rights',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,source,delegate,hidden})=>{
  await assign(await createRole({name:'Independent global stock duty',permissions:['devices.inventory.read','devices.inventory.create']}),delegate.id);
  const legacy=await source.read(delegate.user,bearer);assert.equal(legacy.schemaVersion,1);assert.deepEqual(legacy.permissions,['devices.inventory.read','devices.inventory.create']);assert.equal(Object.hasOwn(legacy,'scope'),false);
  await deviceDb.query('ALTER TABLE device_ou_assignments DISABLE TRIGGER device_ou_guard');
  const changed=await inventory.update(hidden.id,deviceUpdate(hidden,{model:'Actual independent tenant maintenance'}),contract.deviceEtag(hidden),delegate.user,bearer);assert.equal(changed.model,'Actual independent tenant maintenance');
  const added=await inventory.create(deviceValues(),delegate.user,bearer);assert.equal(added.assignedUserId,null);
  const proof=(await deviceDb.query("SELECT proof FROM device_inventory_events WHERE device_id=$1 AND action='update'",[hidden.id])).rows[0].proof;assert.equal(proof.source.schemaVersion,2);assert.equal(proof.source.scope.resource,null);
  await deviceDb.query('ALTER TABLE device_ou_assignments ENABLE TRIGGER device_ou_guard');
  const recipient=await person();await assert.rejects(inventory.assign(added.id,{userId:recipient.id},contract.deviceEtag(added),delegate.user,bearer),{status:404});
 },['devices.inventory.read','devices.inventory.assign']);
});
test('device OU writes reject a replacement grant at the final live checkpoint and roll back the entire effect',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,role,grant,root,inside})=>{
  const before=await deviceState(deviceDb),checkpoint=inventory.checkpoint.bind(inventory);let calls=0;
  inventory.checkpoint=async(...args)=>{if(++calls===2){await roles.revoke(grant.id,{reason,confirm:true},C.etag('grant',grant),owner.user,bearer);await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id});}return checkpoint(...args);};
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Old grant must not commit'}),contract.deviceEtag(inside),delegate.user,bearer),{status:401});assert.equal(calls,2);assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes lose a genuinely ended PIM activation before commit without inheriting another source',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,role,grant,root,inside})=>{
  await roles.revoke(grant.id,{reason,confirm:true},C.etag('grant',grant),owner.user,bearer);
  const eligible=(await makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).eligibility,current=(await activate(eligible,delegate.user,60)).activation;
  const before=await deviceState(deviceDb),checkpoint=inventory.checkpoint.bind(inventory);let calls=0;
  inventory.checkpoint=async(...args)=>{if(++calls===2)await pim().end(current.id,{reason,confirm:true},C.etag('activation',current),delegate.user,bearer);return checkpoint(...args);};
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Ended activation must not commit'}),contract.deviceEtag(inside),delegate.user,bearer),error=>[401,403].includes(error.status));assert.equal(calls,2);assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes keep the original recipient revision through the final independent Identity checkpoint',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  const recipient=await person(),before=await deviceState(deviceDb),checkpoint=inventory.checkpoint.bind(inventory);let calls=0;
  inventory.checkpoint=async(...args)=>{if(++calls===2){const current=await reader.user(recipient.id,{},owner.user,bearer);await new UserMutator(db,options).update(recipient.id,{enabled:false},userEtag(current),owner.user,bearer);}return checkpoint(...args);};
  await assert.rejects(inventory.assign(inside.id,{userId:recipient.id},contract.deviceEtag(inside),delegate.user,bearer),{status:401});assert.equal(calls,2);assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.assign']);
});
for(const destination of ['inside','outside'])test('device OU writes physically reject a late '+destination+' association move after the final Identity reply',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract'),ouContract=require('../../../../../packages/device-ou-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside,child,outside,units})=>{
  const before=await deviceState(deviceDb);let moved=false;
  inventory.database={...deviceDb,transaction:(operation,settings={})=>deviceDb.transaction(operation,{...settings,beforeCommit:async client=>{
   if(settings.beforeCommit)await settings.beforeCommit(client);if(settings.readOnly)return;
   const bound={...deviceDb,transaction:async(operation,options={})=>{const result=await operation(client);if(options.beforeCommit)await options.beforeCommit(client);return result;}};
   const stock=new(require('../../../device-service/src/DeviceInventory').DeviceInventory)(bound,{authority:inventory.authority});
   const metadata=new(require('../../../device-service/src/DeviceOrganizationalUnits').DeviceOrganizationalUnits)(bound,{inventory:stock,authority:units.authority});
   const current=await metadata.get(inside.id,{},owner.user,bearer),selected=(await units.authority.read(bearer,owner.user,destination==='inside'?child.id:outside.id)).ou;
   await metadata.write(inside.id,{ou:{id:selected.id,generation:selected.generation,revision:selected.revision},reason,confirm:true},ouContract.etag(inside.id,current.deviceRevision,current.revision),owner.user,bearer,randomUUID());moved=true;
  }})};
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Late association must not commit'}),contract.deviceEtag(inside),delegate.user,bearer),{code:'P0412'});assert.equal(moved,true);assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes cannot physically commit after a shortened original source expires past the last live checkpoint',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  const before=await deviceState(deviceDb),deadline=Math.floor(Date.now()/1000)+10,read=inventory.authority.read.bind(inventory.authority);let reachedFinalCheckpoint=false;
  inventory.authority.read=async(...args)=>{const source=await read(...args);assert.ok(deadline<=source.validUntil);return{...source,validUntil:deadline};};
  inventory.database={...deviceDb,transaction:(operation,settings={})=>deviceDb.transaction(operation,{...settings,beforeCommit:async client=>{
   if(settings.beforeCommit)await settings.beforeCommit(client);
   if(!settings.readOnly){reachedFinalCheckpoint=true;await client.query('SELECT pg_sleep($1)',[Math.max(0,(deadline*1000-Date.now()+100)/1000)]);}
  }})};
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Expired original deadline must not commit'}),contract.deviceEtag(inside),delegate.user,bearer),{code:'42501'});assert.equal(reachedFinalCheckpoint,true);assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes check exact physical resource versions even when called directly through the SQL kernel',async()=>{
 await scopedDevices(async({inventory,deviceDb,delegate,inside,units})=>{
  const current=await units.get(inside.id,{},delegate.user,bearer),selected={deviceId:inside.id,deviceRevision:inside.revision,revision:current.revision,ou:{id:current.ou.id,generation:current.ou.generation}},source=await inventory.authority.read(bearer,delegate.user,null,selected),before=await deviceState(deviceDb);
  for(const alter of [resource=>resource.deviceId=randomUUID(),resource=>resource.deviceRevision='99',resource=>resource.revision='99',resource=>resource.ou.generation='99',resource=>resource.ou.id=randomUUID()]){
   const changed=structuredClone(source);alter(changed.scope.resource);
   await assert.rejects(deviceDb.transaction(async client=>{const actual=await inventory.current(client,source.tenant.id,inside.id);return client.query('SELECT device_inventory_change($1::jsonb)',[JSON.stringify({id:randomUUID(),deviceId:inside.id,correlationId:randomUUID(),action:'update',source:changed,before:actual.row,values:deviceUpdate(inside,{model:'Wrong physical binding'}),assignmentId:null})]);}),{code:'P0412'});
   assert.deepEqual(await deviceState(deviceDb),before);
  }
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes preserve historical scoped receipts and all receiving guards through full device migration replay',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  const changed=await inventory.update(inside.id,deviceUpdate(inside,{model:'Retained original scoped receipt'}),contract.deviceEtag(inside),delegate.user,bearer),before=await deviceState(deviceDb);
  const directory=path.resolve(__dirname,'../../../device-service/migrations');for(const file of fs.readdirSync(directory).filter(file=>file.endsWith('.sql')).sort())await deviceDb.query(fs.readFileSync(path.join(directory,file),'utf8'));
  assert.deepEqual(await deviceState(deviceDb),before);await deviceDb.query('SELECT device_scope_receiving()');await deviceDb.query('SELECT device_ou_receiving()');
  const next=await inventory.lifecycle(changed.id,{lifecycle:'maintenance',reason,confirm:true},contract.deviceEtag(changed),delegate.user,bearer);assert.equal(next.lifecycle,'maintenance');assert.equal(BigInt(next.revision),BigInt(changed.revision)+1n);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes reject malformed private SQL scope sources without widening to a legacy tenant source',async()=>{
 await scopedDevices(async({inventory,deviceDb,delegate})=>{
  const source=await inventory.authority.read(bearer,delegate.user),contract=require('../../../../../packages/device-scope-contract');assert.equal(contract.validEnvelope(source,delegate.user),true);
  const alterations=[value=>value.schemaVersion=1,value=>value.extra=true,value=>value.context.revision=2,value=>value.scope.override=true,value=>value.scope.units.reverse(),value=>value.scope.units.push(value.scope.units[0]),value=>value.scope.units[0].roots.push(value.scope.units[0].roots[0]),value=>value.scope.units[0].generation='9223372036854775808',value=>value.scope.grants.push(value.scope.grants[0]),value=>value.scope.grants[0].source.scopeType='ou',value=>value.scope.grants[0].source.validUntil='9223372036854775807',value=>value.scope.grants[0].source.ouGeneration='999',value=>value.scope.grants[0].source.targetId=randomUUID(),value=>value.scope.grants[0].permission='devices.compliance.manage',value=>value.scope.resource={deviceId:randomUUID(),deviceRevision:'1',revision:'0',ou:{id:randomUUID(),generation:'1'}}];
  for(const change of alterations){const modified=structuredClone(source);change(modified);assert.equal(contract.validEnvelope(modified,delegate.user),false);assert.equal((await deviceDb.query('SELECT device_scope_source_valid($1::jsonb) AS valid',[JSON.stringify(modified)])).rows[0].valid,false);}
 },['devices.inventory.read','devices.inventory.create']);
});
for(const fault of ['scope manifest guard','scope validator','inventory guard','OU receiver'])test('device OU writes refuse a missing or replaced '+fault,async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  const before=await deviceState(deviceDb);
  if(fault==='scope manifest guard')await deviceDb.query('ALTER TABLE device_scope_manifest DISABLE TRIGGER device_scope_manifest_guard');
  else if(fault==='scope validator')await deviceDb.query('CREATE OR REPLACE FUNCTION device_scope_source_valid(source jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN RETURN true; END; $$');
  else if(fault==='inventory guard')await deviceDb.query('CREATE OR REPLACE FUNCTION device_inventory_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN NEW; END; $$');
  else await deviceDb.query('CREATE OR REPLACE FUNCTION device_ou_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN; END; $$');
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Missing receiver cannot authorize a write'}),contract.deviceEtag(inside),delegate.user,bearer),{status:503});assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU writes cannot acknowledge a scoped mutation without its actual pending inventory receipt',async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  const before=await deviceState(deviceDb);
  await deviceDb.query('CREATE FUNCTION suppress_scoped_inventory_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');await deviceDb.query('CREATE TRIGGER aaa_suppress_scoped_inventory_receipt BEFORE INSERT ON device_inventory_outbox FOR EACH ROW EXECUTE FUNCTION suppress_scoped_inventory_receipt()');
  await assert.rejects(inventory.update(inside.id,deviceUpdate(inside,{model:'Suppressed pending receipt'}),contract.deviceEtag(inside),delegate.user,bearer),{status:503});assert.deepEqual(await deviceState(deviceDb),before);
 },['devices.inventory.read','devices.inventory.create']);
});
for(const revision of ['9007199254740993','9223372036854775806'])test('device OU writes preserve the exact bound BIGINT device revision '+revision,async()=>{
 const contract=require('../../../../../packages/device-inventory-contract');
 await scopedDevices(async({inventory,deviceDb,delegate,inside})=>{
  await deviceDb.transaction(async client=>{await client.query('ALTER TABLE devices DISABLE TRIGGER ALL');await client.query('UPDATE devices SET inventory_revision=$2::bigint WHERE id=$1',[inside.id,revision]);await client.query('ALTER TABLE devices ENABLE TRIGGER ALL');await client.query('SELECT device_inventory_receiving()');});
  const current=await inventory.get(inside.id,delegate.user,bearer);assert.equal(current.revision,revision);
  const changed=await inventory.update(inside.id,deviceUpdate(current,{model:'Lossless scoped BIGINT mutation'}),contract.deviceEtag(current),delegate.user,bearer);assert.equal(changed.revision,String(BigInt(revision)+1n));
  const event=(await deviceDb.query("SELECT proof,before_state,after_state FROM device_inventory_events WHERE device_id=$1 AND action='update'",[inside.id])).rows[0];assert.equal(event.proof.source.scope.resource.deviceRevision,revision);assert.equal(event.before_state.inventory_revision,revision);assert.equal(event.after_state.inventory_revision,changed.revision);
 },['devices.inventory.read','devices.inventory.create']);
});
test('device OU reads filter actual inventory fleet counts searches CSV and retained metadata without hidden devices',async()=>{
 await scopedDevices(async({inventory,delegate,inside,nested,hidden,unassigned,agents,units})=>{
  const page=await inventory.list({},delegate.user,bearer);assert.equal(page.total,2);assert.deepEqual(page.devices.map(device=>device.id).sort(),[inside.id,nested.id].sort());assert.equal((await inventory.list({search:'SECRET'},delegate.user,bearer)).total,0);assert.equal((await inventory.list({platform:'windows'},delegate.user,bearer)).total,0);
  const csv=await inventory.exportCsv({},delegate.user,bearer);assert.equal(csv.count,2);assert.ok(!csv.csv.includes('SECRET-'));const fleet=await agents.fleet({},delegate.user,bearer);assert.equal(fleet.total,2);assert.equal(fleet.fleet.counts.total,2);assert.equal((await agents.fleet({},delegate.user,bearer,true)).count,2);
  assert.equal((await inventory.get(inside.id,delegate.user,bearer)).id,inside.id);assert.equal((await inventory.history(inside.id,{},delegate.user,bearer)).total,1);assert.equal((await units.get(inside.id,{},delegate.user,bearer)).ou.id,(await units.get(inside.id,{},owner.user,bearer)).ou.id);assert.equal((await units.history(inside.id,{},delegate.user,bearer)).total,1);
  for(const device of [hidden,unassigned]){await assert.rejects(inventory.get(device.id,delegate.user,bearer),{status:404});await assert.rejects(inventory.history(device.id,{},delegate.user,bearer),{status:404});await assert.rejects(units.get(device.id,{},delegate.user,bearer),{status:404});await assert.rejects(units.history(device.id,{},delegate.user,bearer),{status:404});}
  assert.ok(!Object.hasOwn(page,'scope'));assert.ok(!Object.hasOwn(page,'delegation'));
 });
});
test('device OU reads constrain agent hardware sync and independent compliance assessments and histories',async()=>{
 await scopedDevices(async({inventory,delegate,inside,hidden,agents,sync,compliance})=>{
  assert.equal((await agents.get(inside.id,{},delegate.user,bearer)).deviceId,inside.id);assert.equal((await agents.inventoryReport(inside.id,{},delegate.user,bearer)).status,'missing');
  const issued=await agents.manage(inside.id,'issue',{reason,confirm:true},`"agent-${inside.id}-0"`,owner.user,bearer,randomUUID());await agents.register({token:issued.enrollmentToken,report:{hostname:'scoped-device',platform:'linux',architecture:'x86_64',osVersion:'1.0',agentVersion:'1.0.0'}},randomUUID());
  const current=await sync.list(inside.id,{},owner.user,bearer),queued=await sync.write(inside.id,{reason,confirm:true},current.connectionEtag,owner.user,bearer,randomUUID());assert.equal((await sync.list(inside.id,{},delegate.user,bearer)).requests[0].id,queued.request.id);assert.equal((await sync.history(inside.id,queued.request.id,{},delegate.user,bearer)).events.length,1);
  for(const read of [()=>agents.get(hidden.id,{},delegate.user,bearer),()=>agents.inventoryReport(hidden.id,{},delegate.user,bearer),()=>sync.list(hidden.id,{},delegate.user,bearer),()=>sync.history(hidden.id,queued.request.id,{},delegate.user,bearer),()=>compliance.get(hidden.id,{},delegate.user,bearer),()=>compliance.history(hidden.id,{},delegate.user,bearer)])await assert.rejects(read,{status:404});
  const page=await compliance.list({},delegate.user,bearer);assert.equal(page.total,2);assert.equal(page.counts.total,2);assert.equal((await compliance.get(inside.id,{},delegate.user,bearer)).deviceId,inside.id);assert.equal((await compliance.history(inside.id,{},delegate.user,bearer)).total,0);await assert.rejects(compliance.policies({},delegate.user,bearer),{status:403});await assert.rejects(compliance.history('linux',{},delegate.user,bearer,true),{status:403});assert.equal((await inventory.list({},delegate.user,bearer)).total,2);
 });
});
test('device OU reads keep current OU status separate from the additional own directory read duty',async()=>{
 await scopedDevices(async({delegate,inside,hidden,units})=>{
  const C=require('../../../../../packages/device-ou-contract'),state=await units.get(inside.id,{},delegate.user,bearer),etag=C.etag(inside.id,state.deviceRevision,state.revision);await assert.rejects(units.status(inside.id,{},etag,delegate.user,bearer),{status:403,message:'device_ou_status_directory_read_required'});
  await assign(await createRole({name:'Independent own OU metadata reader',permissions:['ous.read']}),delegate.id);assert.equal((await units.status(inside.id,{},etag,delegate.user,bearer)).state,'current');
  const other=await units.get(hidden.id,{},owner.user,bearer);await assert.rejects(units.status(hidden.id,{},C.etag(hidden.id,other.deviceRevision,other.revision),delegate.user,bearer),{status:404});
 });
});
for(const destination of ['inside','outside'])test('device OU reads discard a late '+destination+' reassignment after the final Identity reply',async()=>{
 await scopedDevices(async({inventory,delegate,inside,child,outside,setUnit})=>{
  const read=inventory.authority.read;let calls=0;inventory.authority.read=async(...args)=>{const proof=await read(...args);if(args[1]===delegate.user&&++calls===2)await setUnit(inside,destination==='inside'?child:outside);return proof;};
  await assert.rejects(inventory.get(inside.id,delegate.user,bearer),{status:412});assert.equal((await inventory.get(inside.id,owner.user,bearer)).assetId,'SCOPED-IN');
 });
});
test('device OU reads fail closed without the complete local association receiver and retain independent tenant reads',async()=>{
 await scopedDevices(async({inventory,deviceDb,delegate})=>{
  await deviceDb.query('ALTER TABLE device_ou_assignments DISABLE TRIGGER device_ou_guard');await assert.rejects(inventory.list({},delegate.user,bearer),{status:503});assert.equal((await inventory.list({},owner.user,bearer)).total,4);
 });
});
test('device OU reads limit actual return tasks and their retained histories to current device associations',async()=>{
 await scopedDevices(async({inventory,deviceDb,delegate,inside,hidden})=>{
  const target=await person(),deviceEtag=require('../../../../../packages/device-inventory-contract').deviceEtag,assigned=[];
  for(const unit of [inside,hidden])assigned.push(await inventory.assign(unit.id,{userId:target.id},deviceEtag(unit),owner.user,bearer));
  const profile=await reader.user(target.id,{},owner.user,bearer),workflowId=randomUUID(),parent=await new(require('../CompanyOffboarding').CompanyOffboarding)(db,options).receive(target.id,{workflowId,expectedRevision:profile.revision,confirm:true},owner.user,bearer),negative=new(require('../DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db,options);
  const returns=new(require('../../../device-service/src/DeviceReturns').DeviceReturns)(deviceDb,{inventory,authority:{read:(authorization,user,id,userId)=>negative.read(user,authorization,{workflowId:id,userId})}}),items=assigned.map(unit=>({deviceId:unit.id,deviceRevision:unit.revision,assignmentId:unit.assignmentId,requestId:randomUUID()}));
  await returns.request(target.id,{workflowId,eligibilityRevision:parent.afterEligibilityRevision,reason,confirm:true,items},owner.user,bearer,randomUUID());const page=await returns.list({},delegate.user,bearer);assert.equal(page.total,1);assert.equal(page.requests[0].deviceId,inside.id);assert.equal((await returns.get(items[0].requestId,delegate.user,bearer)).deviceId,inside.id);assert.equal((await returns.history(items[0].requestId,{},delegate.user,bearer)).total,1);await assert.rejects(returns.get(items[1].requestId,delegate.user,bearer),{status:404});await assert.rejects(returns.history(items[1].requestId,{},delegate.user,bearer),{status:404});
 });
});
async function deviceOuSources(actor,permission='devices.inventory.read',unit=null,kind=unit?'device-ou':null){
 await pool.query('SELECT identity_company_role_receiving()');
 return (await pool.query('SELECT identity_company_role_sources($1,$2,$3,$4,$5) AS sources',[actor.id,owner.receipt.tenantId,permission,kind,unit])).rows[0].sources;
}
async function scopedReturns(operation) {
 return scopedDevices(async state => {
  const target = await person('scoped-return-target'), assigned = {};
  const { deviceEtag } = require('../../../../../packages/device-inventory-contract');
  for (const key of ['inside','nested','hidden','unassigned']) assigned[key] = await state.inventory.assign(state[key].id, { userId: target.id }, deviceEtag(state[key]), owner.user, bearer);
  const profile = await reader.user(target.id, {}, owner.user, bearer), workflowId = randomUUID();
  const parent = await new (require('../CompanyOffboarding').CompanyOffboarding)(db, options).receive(target.id, { workflowId, expectedRevision: profile.revision, confirm: true }, owner.user, bearer);
  const negative = new (require('../DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db, options);
  const authority = new (require('../../../device-service/src/DeviceReturnAuthority').DeviceReturnAuthority)({ scoped: true, endpoint: 'https://native.identity.test/api/identity/device-offboarding', fetchImpl: async (_url, request) => {
   assert.equal(request.headers['X-OD-Device-Scope-Protocol'], '1');
   return Response.json(await negative.readScoped(state.delegate.user, bearer, JSON.parse(request.body)));
  } });
  const returns = new (require('../../../device-service/src/DeviceReturns').DeviceReturns)(state.deviceDb, { inventory: state.inventory, authority });
  const requestBody = keys => ({ workflowId, eligibilityRevision: parent.afterEligibilityRevision, reason, confirm: true, items: keys.map(key => ({ deviceId: assigned[key].id, deviceRevision: assigned[key].revision, assignmentId: assigned[key].assignmentId, requestId: randomUUID() })) });
  return operation({ ...state, target, assigned, workflowId, parent, negative, authority, returns, requestBody });
 }, ['devices.inventory.read','devices.inventory.assign']);
}
test('device OU returns preserve scoped parent requests and real cancellation release history and recovery', async () => {
 await scopedReturns(async ({ inventory, deviceDb, delegate, assigned, workflowId, target, returns, requestBody }) => {
  const { deviceEtag, deviceReturnEtag } = require('../../../../../packages/device-inventory-contract');
  const preview = await returns.offboardingList(target.id, { workflowId }, delegate.user, bearer);
  assert.equal(preview.schemaVersion, 2); assert.equal(preview.deviceOffboardingReturnsProtocol, 2); assert.equal(preview.coverage, 'scope'); assert.equal(preview.total, 2);
  assert.deepEqual(preview.devices.map(row => row.deviceId).sort(), [assigned.inside.id, assigned.nested.id].sort());
  const body = requestBody(['inside','nested']), created = await returns.request(target.id, body, delegate.user, bearer, randomUUID());
  assert.equal(created.coverage, 'scope'); assert.ok(created.results.every(row => row.status === 'requested'));
  const proofs = (await deviceDb.query("SELECT proof FROM device_return_events WHERE type='device.return.requested'")).rows;
  for (const { proof } of proofs) { assert.equal(proof.source.schemaVersion, 2); assert.equal(proof.source.deviceOffboardingReturnsProtocol, 2); assert.equal(proof.source.inventory.scope.resource.deviceId, proof.item.deviceId); assert.equal(Object.hasOwn(proof.source, 'permissions'), false); }
  assert.equal((await returns.request(target.id, body, delegate.user, bearer, randomUUID())).results[0].status, 'already_requested');
  await inventory.update(assigned.inside.id, deviceUpdate(assigned.inside, { model: 'Updated before cancellation' }), deviceEtag(assigned.inside), owner.user, bearer, randomUUID());
  const cancelledTask = await returns.get(body.items[0].requestId, delegate.user, bearer);
  assert.notEqual(cancelledTask.deviceRevision, cancelledTask.currentDeviceRevision);
  const cancelled = await returns.decide(cancelledTask.id, { action: 'cancelled', reason, confirm: true }, deviceReturnEtag(cancelledTask), delegate.user, bearer, randomUUID());
  assert.equal(cancelled.request.status, 'cancelled'); assert.equal(cancelled.deviceReturnsProtocol, 2); assert.equal((await inventory.get(assigned.inside.id, delegate.user, bearer)).assignedUserId, target.id);
  const task = await returns.get(body.items[1].requestId, delegate.user, bearer), expected = deviceReturnEtag(task);
  const returned = await returns.decide(task.id, { action: 'returned', reason, confirm: true }, expected, delegate.user, bearer, randomUUID());
  assert.equal(returned.request.status, 'returned'); assert.equal(returned.coverage, 'scope'); assert.equal((await inventory.get(task.deviceId, delegate.user, bearer)).assignedUserId, null);
  const decision = (await deviceDb.query('SELECT proof FROM device_return_events WHERE id=$1', [returned.operationId])).rows[0].proof;
  const release = (await deviceDb.query('SELECT proof FROM device_inventory_events WHERE id=$1', [returned.request.inventoryOperationId])).rows[0].proof;
  assert.deepEqual(decision.source, release.source); assert.equal(decision.source.schemaVersion, 2); assert.equal(decision.source.scope.resource.deviceRevision, task.currentDeviceRevision);
  const other = await person(); const current = await inventory.get(task.deviceId, owner.user, bearer); const later = await inventory.assign(task.deviceId, { userId: other.id }, deviceEtag(current), owner.user, bearer, randomUUID());
  assert.equal((await returns.decide(task.id, { action: 'returned', reason, confirm: true }, expected, delegate.user, bearer, randomUUID())).outcome, 'already_returned');
  assert.equal((await inventory.get(task.deviceId, delegate.user, bearer)).assignmentId, later.assignmentId);
  assert.equal((await returns.list({}, delegate.user, bearer)).total, 2); assert.equal((await returns.offboardingHistory(target.id, { workflowId }, delegate.user, bearer)).total, 2);
  assert.equal((await returns.history(task.id, {}, delegate.user, bearer)).events.length, 2);
 });
});
async function returnState(database) {
 const state = await deviceState(database);
 for (const table of ['device_return_requests','device_return_events','device_return_outbox']) state[table] = (await database.query('SELECT to_jsonb(record)::text AS row FROM '+table+' record ORDER BY to_jsonb(record)::text')).rows;
 return state;
}
async function prepareReturn(fixture, kind) {
 const body = fixture.requestBody(['inside']);
 if (kind === 'requested') return { body };
 const result = await fixture.returns.request(fixture.target.id, body, fixture.delegate.user, bearer, randomUUID());
 assert.equal(result.results[0].status, 'requested');
 const task = await fixture.returns.get(body.items[0].requestId, fixture.delegate.user, bearer);
 return { body, task, expected: require('../../../../../packages/device-inventory-contract').deviceReturnEtag(task) };
}
async function changeReturn(fixture, kind, prepared, errorCode) {
 if (kind === 'requested') {
  const result = await fixture.returns.request(fixture.target.id, prepared.body, fixture.delegate.user, bearer, randomUUID());
  if (errorCode) { assert.equal(result.results[0].status, 'unconfirmed'); assert.ok([].concat(errorCode).includes(result.results[0].code), JSON.stringify(result)); }
  return result;
 }
 const operation = fixture.returns.decide(prepared.task.id, { action: kind, reason, confirm: true }, prepared.expected, fixture.delegate.user, bearer, randomUUID());
 if (errorCode) return assert.rejects(operation, error => [].concat(errorCode).includes(error.status || ({ P0412: 412, '42501': 503, '23514': 409 }[error.code])), 'Original return boundary must reject the effect');
 return operation;
}
function ownerReturns(fixture) {
 return new (require('../../../device-service/src/DeviceReturns').DeviceReturns)(fixture.deviceDb, { inventory: fixture.inventory,
  authority: { read: (authorization, user, workflowId, userId, selected = null) => fixture.negative.readScoped(user, authorization, { workflowId, userId, ...(selected ? { device: selected } : {}) }) } });
}
test('device OU returns hide outside corrupted tasks before state ETag recovery and history disclosure', async () => {
 await scopedReturns(async fixture => {
  const body = fixture.requestBody(['hidden','unassigned']), ownerService = ownerReturns(fixture);
  assert.ok((await ownerService.request(fixture.target.id, body, owner.user, bearer, randomUUID())).results.every(row => row.status === 'requested'));
  await fixture.deviceDb.query('ALTER TABLE device_return_outbox DISABLE TRIGGER USER');
  await fixture.deviceDb.query('DELETE FROM device_return_outbox');
  await fixture.deviceDb.query('ALTER TABLE device_return_outbox ENABLE TRIGGER USER');
  for (const item of body.items) {
   await assert.rejects(fixture.returns.get(item.requestId, fixture.delegate.user, bearer), { status: 404 });
   await assert.rejects(fixture.returns.history(item.requestId, {}, fixture.delegate.user, bearer), { status: 404 });
   await assert.rejects(fixture.returns.decide(item.requestId, { action: 'cancelled', reason, confirm: true }, `"device-return-${item.requestId}-99-99"`, fixture.delegate.user, bearer), { status: 404 });
   await assert.rejects(fixture.returns.request(fixture.target.id, { ...body, items: [{ ...item, deviceRevision: '99' }] }, fixture.delegate.user, bearer), { status: 404 });
  }
  assert.equal((await fixture.returns.list({}, fixture.delegate.user, bearer)).total, 0);
  assert.equal((await fixture.returns.offboardingHistory(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer)).total, 0);
 });
});
test('device OU returns intersect global read authority with the actual scoped assignment duty', async () => {
 await scopedReturns(async fixture => {
  await assign(await createRole({ name: 'Tenant return history reader', permissions: ['devices.inventory.read'] }), fixture.delegate.id);
  const ownerService = ownerReturns(fixture), body = fixture.requestBody(['inside','hidden']);
  assert.ok((await ownerService.request(fixture.target.id, body, owner.user, bearer, randomUUID())).results.every(row => row.status === 'requested'));
  const listing = await fixture.returns.list({}, fixture.delegate.user, bearer); assert.equal(listing.coverage, 'tenant'); assert.equal(listing.total, 2);
  const preview = await fixture.returns.offboardingList(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer);
  assert.equal(preview.coverage, 'scope'); assert.equal(preview.total, 2); assert.ok(!preview.devices.some(row => row.deviceId === fixture.assigned.hidden.id));
  const history = await fixture.returns.offboardingHistory(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer); assert.equal(history.total, 1); assert.equal(history.coverage, 'scope');
  const hidden = await fixture.returns.get(body.items[1].requestId, fixture.delegate.user, bearer);
  await assert.rejects(fixture.returns.decide(hidden.id, { action: 'cancelled', reason, confirm: true }, require('../../../../../packages/device-inventory-contract').deviceReturnEtag(hidden), fixture.delegate.user, bearer), { status: 404 });
 });
});
for (const kind of ['requested','cancelled','returned']) for (const destination of ['inside','outside']) test(`device OU returns physically reject a late ${destination} move after the final ${kind} checkpoint`, async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, kind), before = await returnState(fixture.deviceDb); let moved = false;
  afterControlCheckpoint(fixture, async client => { await moveControlUnit(fixture, client, destination === 'inside' ? fixture.child : fixture.outside); moved = true; });
  await changeReturn(fixture, kind, prepared, 412); assert.equal(moved, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
for (const kind of ['requested','cancelled']) test(`device OU returns bind the actual inventory version through physical ${kind} commit`, async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, kind), before = await returnState(fixture.deviceDb); let edited = false;
  afterControlCheckpoint(fixture, async client => {
   // Privileged disposable corruption fixture; every guard is restored before physical commit.
   await client.query('ALTER TABLE devices DISABLE TRIGGER USER');
   await client.query('UPDATE devices SET inventory_revision=inventory_revision+1 WHERE id=$1', [fixture.assigned.inside.id]);
   await client.query('ALTER TABLE devices ENABLE TRIGGER USER'); edited = true;
  });
  await changeReturn(fixture, kind, prepared, 412); assert.equal(edited, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
for (const kind of ['requested','cancelled','returned']) for (const mode of ['grant','PIM']) test(`device OU returns reject a changed original ${mode} at the final ${kind} checkpoint`, async () => {
 await scopedReturns(async fixture => {
  let active;
  if (mode === 'PIM') { await roles.revoke(fixture.grant.id, { reason, confirm: true }, C.etag('grant', fixture.grant), owner.user, bearer); active = (await activate((await makeEligible(fixture.role, fixture.delegate.id, { scopeType: 'device-ou', ouId: fixture.root.id })).eligibility, fixture.delegate.user)).activation; }
  const prepared = await prepareReturn(fixture, kind), before = await returnState(fixture.deviceDb), checkpoint = fixture.returns.checkpoint.bind(fixture.returns); let calls = 0, changed = false;
  fixture.returns.checkpoint = async (...args) => {
   const actor = require('../../../../../packages/device-return-scope-contract').actorSource(args[0]);
   if (actor.scope?.resource && ++calls === (kind === 'requested' ? 1 : 2)) {
    if (mode === 'PIM') await pim().end(active.id, { reason, confirm: true }, C.etag('activation', active), fixture.delegate.user, bearer);
    else { await roles.revoke(fixture.grant.id, { reason, confirm: true }, C.etag('grant', fixture.grant), owner.user, bearer); await assign(fixture.role, fixture.delegate.id, { scopeType: 'device-ou', ouId: fixture.root.id }); }
    changed = true;
   }
   return checkpoint(...args);
  };
  await changeReturn(fixture, kind, prepared, [401,403]); assert.equal(changed, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
for (const again of [false,true]) test(`device OU returns reject an account ${again ? 'disabled again' : 'reactivated'} before request commit`, async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, 'requested'), before = await returnState(fixture.deviceDb), checkpoint = fixture.returns.checkpoint.bind(fixture.returns); let changed = false;
  fixture.returns.checkpoint = async (...args) => {
   if (args[0].inventory?.scope.resource && !changed) {
    let profile = await reader.user(fixture.target.id, {}, owner.user, bearer);
    await new UserMutator(db, options).update(fixture.target.id, { enabled: true }, userEtag(profile), owner.user, bearer);
    if (again) { profile = await reader.user(fixture.target.id, {}, owner.user, bearer); await new UserMutator(db, options).update(fixture.target.id, { enabled: false }, userEtag(profile), owner.user, bearer); }
    changed = true;
   }
   return checkpoint(...args);
  };
  await changeReturn(fixture, 'requested', prepared, 409); assert.equal(changed, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
for (const kind of ['requested','cancelled']) test(`device OU returns cannot commit an expired original ${kind} source after final revalidation`, async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, kind), before = await returnState(fixture.deviceDb), deadline = Math.floor(Date.now()/1000)+10;
  const read = fixture.inventory.authority.read.bind(fixture.inventory.authority), transport = fixture.authority.fetchImpl;
  fixture.inventory.authority.read = async (...args) => ({ ...await read(...args), validUntil: deadline });
  fixture.authority.fetchImpl = async (...args) => { const response = await transport(...args), value = await response.json(); value.inventory.validUntil = deadline; return Response.json(value); };
  let checked = false;
  afterControlCheckpoint(fixture, async client => { checked = true; await client.query('SELECT pg_sleep($1)', [Math.max(0, (deadline*1000-Date.now()+100)/1000)]); });
  await changeReturn(fixture, kind, prepared, 503); assert.equal(checked, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
test('device OU returns reject unbound or substituted original resources at the SQL admission boundary', async () => {
 await scopedReturns(async fixture => {
  const body = fixture.requestBody(['inside']);
  const source = await fixture.returns.initial(fixture.delegate.user, bearer, fixture.workflowId, fixture.target.id);
  const bound = await fixture.deviceDb.transaction(client => fixture.returns.bind(client, source, fixture.delegate.user, bearer, fixture.assigned.inside.id, fixture.assigned.inside.revision));
  const before = await returnState(fixture.deviceDb);
  for (const alter of [value => value.inventory.scope.resource = null, value => value.inventory.scope.resource.deviceId = randomUUID(), value => value.inventory.scope.resource.deviceRevision = '99', value => value.inventory.scope.resource.revision = '99', value => value.inventory.scope.resource.ou.generation = '99']) {
   const changed = structuredClone(bound); alter(changed);
   const proof = { id: randomUUID(), action: 'requested', requestId: body.items[0].requestId, correlationId: randomUUID(), source: changed, item: body.items[0], reason, eligibilityRevision: body.eligibilityRevision };
   await assert.rejects(fixture.deviceDb.transaction(client => client.query('SELECT device_returns_change($1::jsonb)', [JSON.stringify(proof)])), { code: 'P0412' });
   assert.deepEqual(await returnState(fixture.deviceDb), before);
  }
 });
});
for (const fault of ['change','commit','source','actor','manifest guard']) test(`device OU returns refuse a replaced ${fault} receiver`, async () => {
 await scopedReturns(async fixture => {
  if (fault === 'manifest guard') await fixture.deviceDb.query('ALTER TABLE device_return_scope_manifest DISABLE TRIGGER device_return_scope_manifest_guard');
  else {
   const name = 'device_returns_'+fault;
   const signature = fault === 'change' ? 'proof jsonb' : fault === 'source' ? 'source jsonb,offboarding boolean,live boolean DEFAULT true' : fault === 'actor' ? 'source jsonb' : '';
   const type = fault === 'change' ? 'uuid' : fault === 'source' ? 'void' : fault === 'actor' ? 'jsonb' : 'trigger';
   const result = type === 'trigger' ? 'RETURN NEW;' : type === 'void' ? 'RETURN;' : 'RETURN NULL;';
   await fixture.deviceDb.query(`CREATE OR REPLACE FUNCTION ${name}(${signature}) RETURNS ${type} LANGUAGE plpgsql AS $$ BEGIN ${result} END; $$`);
  }
  await assert.rejects(fixture.returns.capabilities(fixture.delegate.user, bearer), { status: 503 });
 });
});
for (const kind of ['requested','returned']) test(`device OU returns roll back ${kind} when a required pending receipt is suppressed`, async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, kind), before = await returnState(fixture.deviceDb);
  const table = kind === 'requested' ? 'device_return_outbox' : 'device_inventory_outbox';
  await fixture.deviceDb.query('CREATE FUNCTION suppress_scoped_return_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$');
  await fixture.deviceDb.query('CREATE TRIGGER aaa_suppress_scoped_return_receipt BEFORE INSERT ON '+table+' FOR EACH ROW EXECUTE FUNCTION suppress_scoped_return_receipt()');
  await changeReturn(fixture, kind, prepared, [409,503]); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
test('device OU returns retain independent tenant duties without requiring an unrelated OU association receiver', async () => {
 await scopedReturns(async fixture => {
  await assign(await createRole({ name: 'Independent tenant handback', permissions: ['devices.inventory.read','devices.inventory.assign'] }), fixture.delegate.id);
  await assign(await createRole({ name: 'Unrelated limited stock duty', permissions: ['devices.inventory.read','devices.inventory.create'] }), fixture.delegate.id, { scopeType: 'device-ou', ouId: fixture.root.id });
  await fixture.deviceDb.query('ALTER TABLE device_ou_assignments DISABLE TRIGGER device_ou_guard');
  const preview = await fixture.returns.offboardingList(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer);
  assert.equal(preview.schemaVersion, 2); assert.equal(preview.coverage, 'tenant'); assert.equal(preview.total, 4);
  const result = await fixture.returns.request(fixture.target.id, fixture.requestBody(['hidden','unassigned']), fixture.delegate.user, bearer, randomUUID());
  assert.equal(result.coverage, 'tenant'); assert.ok(result.results.every(row => row.status === 'requested'));
  await fixture.deviceDb.query('ALTER TABLE device_ou_assignments ENABLE TRIGGER device_ou_guard');
 });
});
test('device OU returns preserve original scoped receipts through complete forward replay and reject a partial old receiver', async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, 'cancelled'); await changeReturn(fixture, 'cancelled', prepared);
  const before = await returnState(fixture.deviceDb), migrations = path.resolve(__dirname, '../../../device-service/migrations');
  await fixture.deviceDb.query(fs.readFileSync(path.join(migrations, '006_device_returns.sql'), 'utf8'));
  await assert.rejects(fixture.returns.capabilities(fixture.delegate.user, bearer), { status: 503 });
  for (const file of fs.readdirSync(migrations).filter(file => file.endsWith('.sql')).sort()) await fixture.deviceDb.query(fs.readFileSync(path.join(migrations, file), 'utf8'));
  assert.deepEqual(await returnState(fixture.deviceDb), before);
  assert.equal((await fixture.returns.history(prepared.task.id, {}, fixture.delegate.user, bearer)).events.length, 2);
  assert.equal((await fixture.returns.offboardingCapabilities(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer)).deviceOffboardingReturnsProtocol, 2);
 });
});
for (const mode of ['preview','history']) test(`device OU returns withhold a mixed-duty ${mode} after the final local assignment changes`, async () => {
 await scopedReturns(async fixture => {
  await assign(await createRole({ name: 'Independent tenant return reader', permissions: ['devices.inventory.read'] }), fixture.delegate.id);
  if (mode === 'history') await prepareReturn(fixture, 'cancelled');
  const checkpoint = fixture.returns.checkpoint.bind(fixture.returns); let moved = false;
  fixture.returns.checkpoint = async (...args) => {
   await checkpoint(...args);
   if (!moved) { await fixture.setUnit(fixture.assigned.inside, fixture.outside); moved = true; }
  };
  await assert.rejects(mode === 'preview'
   ? fixture.returns.offboardingList(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer)
   : fixture.returns.offboardingHistory(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer), { status: 412 });
  assert.equal(moved, true);
 });
});
test('device OU returns withhold idempotent recovery after a late scope move without adding a return event', async () => {
 await scopedReturns(async fixture => {
  const body = fixture.requestBody(['inside']); await fixture.returns.request(fixture.target.id, body, fixture.delegate.user, bearer, randomUUID());
  const before = (await fixture.deviceDb.query('SELECT count(*) AS count FROM device_return_events')).rows[0].count;
  afterControlCheckpoint(fixture, client => moveControlUnit(fixture, client, fixture.outside));
  const result = await fixture.returns.request(fixture.target.id, body, fixture.delegate.user, bearer, randomUUID());
  assert.equal(result.results[0].status, 'unconfirmed'); assert.equal(result.results[0].code, 412);
  assert.equal((await fixture.deviceDb.query('SELECT count(*) AS count FROM device_return_events')).rows[0].count, before);
 });
});
test('device OU returns reject replacement of an original scoped receipt after its row guard ran', async () => {
 await scopedReturns(async fixture => {
  const prepared = await prepareReturn(fixture, 'requested'), before = await returnState(fixture.deviceDb); let replaced = false;
  await fixture.deviceDb.query(`CREATE FUNCTION poison_return_source() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.proof=jsonb_set(NEW.proof,'{source,inventory,scope,resource,deviceRevision}','"99"'::jsonb);RETURN NEW;END; $$;CREATE TRIGGER z_poison_return_source BEFORE INSERT ON device_return_events FOR EACH ROW EXECUTE FUNCTION poison_return_source()`);
  afterControlCheckpoint(fixture, async client => {
   const row = (await client.query("SELECT proof#>>'{source,inventory,scope,resource,deviceRevision}' AS revision FROM device_return_events WHERE transaction_id=txid_current()")).rows[0];
   assert.equal(row.revision, '99'); replaced = true;
  });
  await changeReturn(fixture, 'requested', prepared, 412); assert.equal(replaced, true); assert.deepEqual(await returnState(fixture.deviceDb), before);
 });
});
test('device OU returns refuse protocol two capabilities against an actual previous SQL receiver', async () => {
 await scopedReturns(async fixture => {
  const directory = path.resolve(__dirname, '../../../device-service/migrations');
  for (const file of ['006_device_returns.sql','012_delegated_device_returns.sql','015_device_scope_controls.sql']) await fixture.deviceDb.query(fs.readFileSync(path.join(directory, file), 'utf8'));
  await fixture.deviceDb.query('DROP FUNCTION device_returns_receiving(integer)');
  await fixture.deviceDb.query('SELECT device_returns_receiving()');
  await assert.rejects(fixture.returns.capabilities(fixture.delegate.user, bearer), { status: 503 });
  await assert.rejects(fixture.returns.offboardingCapabilities(fixture.target.id, { workflowId: fixture.workflowId }, fixture.delegate.user, bearer), { status: 503 });
 });
});
function scopedAuthority(revalidate=options.revalidate){return new(require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,{...options,revalidate});}
for (const mode of ['direct', 'PIM']) {
 test(`device OU offboarding source retains an actual ${mode} grant and negative parent across the private HTTP boundary`, async () => {
  const delegate = await person(), target = await person(), root = await creator.ou({ name: 'Scoped handback source' }, owner.user, bearer);
  const role = await createRole({ permissions: ['devices.inventory.read', 'devices.inventory.assign'] });
  if (mode === 'PIM') await activate((await makeEligible(role, delegate.id, { scopeType: 'device-ou', ouId: root.id })).eligibility, delegate.user);
  else await assign(role, delegate.id, { scopeType: 'device-ou', ouId: root.id });
  const profile = await reader.user(target.id, {}, owner.user, bearer), workflowId = randomUUID();
  const parent = await new (require('../CompanyOffboarding').CompanyOffboarding)(db, options).receive(target.id, { workflowId, expectedRevision: profile.revision, confirm: true }, owner.user, bearer);
  const authority = new (require('../DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db, options);
  const generation = (await deviceOuSources(delegate))[0].ouGeneration;
  const selected = { deviceId: randomUUID(), deviceRevision: '9007199254740993', revision: '5', ou: { id: root.id, generation } }, calls = [];
  const server = require('node:http').createServer(async (req, res) => {
   try {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    calls.push({ path: req.url, authorization: req.headers.authorization, protocol: req.headers['x-od-device-scope-protocol'], body });
    const result = await authority[req.headers['x-od-device-scope-protocol'] === '1' ? 'readScoped' : 'read'](delegate.user, req.headers.authorization, body);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(result));
   } catch (error) { res.writeHead(error.status || 503, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
   const { DeviceReturnAuthority } = require('../../../device-service/src/DeviceReturnAuthority');
   const endpoint = `http://127.0.0.1:${server.address().port}/api/identity/device-offboarding`;
   const result = await new DeviceReturnAuthority({ scoped: true, endpoint }).read(bearer, delegate.user, workflowId, target.id, selected);
   assert.equal(require('../../../../../packages/device-return-scope-contract').validSource(result, delegate.user, workflowId, target.id, selected), true);
   assert.equal(result.schemaVersion, 2); assert.equal(result.deviceOffboardingReturnsProtocol, 2); assert.equal(Object.hasOwn(result, 'permissions'), false);
   assert.deepEqual(result.inventory.permissions, ['devices.inventory.read', 'devices.inventory.assign']);
   assert.deepEqual(result.inventory.scope.resource, selected, 'Identity echoes the requested binding; it does not attest Device storage');
   assert.equal(result.target.eligibilityRevision, parent.afterEligibilityRevision); assert.equal(result.parent.afterRevision, parent.afterRevision);
   const account = (await pool.query('SELECT authorization_revision,eligibility_revision FROM users WHERE id=$1', [target.id])).rows[0];
   assert.equal(result.inventory.target.revision, String(account.authorization_revision)); assert.equal(result.target.eligibilityRevision, String(account.eligibility_revision));
   assert.equal(Object.hasOwn(result.inventory.scope.grants[0].source, 'activationId'), mode === 'PIM');
   assert.deepEqual(calls, [{ path: '/api/identity/device-offboarding', authorization: bearer, protocol: '1', body: { workflowId, userId: target.id, device: selected } }]);
   await assert.rejects(new DeviceReturnAuthority({ endpoint }).read(bearer, delegate.user, workflowId, target.id), { status: 403 });
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
 });
 test(`device OU offboarding source rejects an equivalent replacement ${mode} source after the original checkpoint`, async () => {
  const delegate = await person(), target = await person(), root = await creator.ou({ name: 'Held handback source' }, owner.user, bearer);
  const role = await createRole({ permissions: ['devices.inventory.read', 'devices.inventory.assign'] });
  let grant, eligible, active;
  if (mode === 'PIM') { eligible = (await makeEligible(role, delegate.id, { scopeType: 'device-ou', ouId: root.id })).eligibility; active = (await activate(eligible, delegate.user)).activation; }
  else grant = (await assign(role, delegate.id, { scopeType: 'device-ou', ouId: root.id })).grant;
  const profile = await reader.user(target.id, {}, owner.user, bearer), workflowId = randomUUID();
  await new (require('../CompanyOffboarding').CompanyOffboarding)(db, options).receive(target.id, { workflowId, expectedRevision: profile.revision, confirm: true }, owner.user, bearer);
  let calls = 0;
  const authority = new (require('../DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db, { ...options, revalidate: async (authorization, user) => {
   if (++calls === 3) {
    if (mode === 'PIM') { await pim().end(active.id, { reason, confirm: true }, C.etag('activation', active), delegate.user, bearer); await activate(eligible, delegate.user); }
    else { await roles.revoke(grant.id, { reason, confirm: true }, C.etag('grant', grant), owner.user, bearer); await assign(role, delegate.id, { scopeType: 'device-ou', ouId: root.id }); }
   }
   return options.revalidate(authorization, user);
  } });
  await assert.rejects(authority.readScoped(delegate.user, bearer, { workflowId, userId: target.id }), { status: 401 });
  assert.equal((await deviceOuSources(delegate, 'devices.inventory.assign')).length, 1, 'Equivalent replacement rights are still not the original source');
 });
}
test('device OU source returns only current own descendant generations and independently bounded duties',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Private scoped source'},owner.user,bearer),child=await creator.ou({name:'Current own child',parentId:root.id},owner.user,bearer),outside=await creator.ou({name:'Outside own area'},owner.user,bearer),foreign=await activeCompany(db,schema,issuer),foreignOu=await creator.ou({name:'Foreign private child'},foreign.user,bearer);
 await assign(await createRole({permissions:[...C.DEVICE_OU_PERMISSIONS]}),delegate.id,{scopeType:'device-ou',ouId:root.id});
 const authority=scopedAuthority(),result=await authority.readScoped(delegate.user,bearer),contract=require('../../../../../packages/device-scope-contract');assert.equal(result.schemaVersion,2);assert.deepEqual(result.permissions,['devices.inventory.read','devices.inventory.create','devices.inventory.assign']);assert.equal(contract.validEnvelope(result,delegate.user),true);
 assert.deepEqual(result.scope.units.map(unit=>unit.id).sort(),[root.id,child.id].sort());assert.ok(!result.scope.units.some(unit=>[outside.id,foreignOu.id].includes(unit.id)));assert.ok(result.scope.units.every(unit=>unit.roots.length===1&&unit.roots[0]===root.id&&/^\d+$/.test(unit.generation)));
 assert.equal(contract.permits(result,'devices.inventory.read',null),false);assert.equal(contract.permits(result,'devices.inventory.create',{id:child.id,generation:result.scope.units.find(unit=>unit.id===child.id).generation}),true);
 const compliance=await authority.readScoped(delegate.user,bearer,null,true);assert.deepEqual(compliance.permissions,['devices.compliance.read']);assert.equal(contract.validEnvelope(compliance,delegate.user,null,true),true);assert.equal(contract.permits(compliance,'devices.compliance.manage',null),false);
 assert.equal((await authority.readScoped(owner.user,bearer)).schemaVersion,1);await assert.rejects(authority.read(delegate.user,bearer),{status:403});
});
test('device OU source crosses the real HTTP client with the original bearer recipient and requested device versions',async()=>{
 const delegate=await person(),recipient=await person(),root=await creator.ou({name:'HTTP scoped source'},owner.user,bearer);await assign(await createRole({permissions:['devices.inventory.read','devices.inventory.assign']}),delegate.id,{scopeType:'device-ou',ouId:root.id});
 const authority=scopedAuthority(),generation=(await deviceOuSources(delegate))[0].ouGeneration,selected={deviceId:randomUUID(),deviceRevision:'9007199254740993',revision:'5',ou:{id:root.id,generation}},calls=[];
 const server=require('node:http').createServer(async(req,res)=>{try{
  const chunks=[];for await(const chunk of req)chunks.push(chunk);const input=chunks.length?JSON.parse(Buffer.concat(chunks).toString()):null;calls.push({method:req.method,authorization:req.headers.authorization,protocol:req.headers['x-od-device-scope-protocol'],input});
  const result=await authority.readScoped(delegate.user,req.headers.authorization,input);res.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(result));
 }catch(error){res.writeHead(error.status||503,{'Content-Type':'application/json'});res.end(JSON.stringify({error:error.message}));}});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{
  const client=new(require('../../../device-service/src/InventoryAuthority').InventoryAuthority)({scoped:true,endpoint:`http://127.0.0.1:${server.address().port}/api/identity/device-inventory`});
  const result=await client.read(bearer,delegate.user,recipient.id,selected);assert.deepEqual(result.scope.resource,selected);assert.equal(result.target.id,recipient.id);assert.equal(result.schemaVersion,2);assert.deepEqual(calls,[{method:'POST',authorization:bearer,protocol:'1',input:{userId:recipient.id,device:selected}}]);
  assert.equal(require('../../../device-service/src/InventoryAuthority').inventorySourceMatches(result,delegate.user,recipient.id),false);
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('device OU source preserves independent tenant rights while limiting each additional scope duty',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Combined duty source'},owner.user,bearer),outside=await creator.ou({name:'Outside combined stock scope'},owner.user,bearer);
 await assign(await createRole({name:'Tenant handback source',permissions:['devices.inventory.read','devices.inventory.assign']}),delegate.id);await assign(await createRole({name:'Scoped stock source',permissions:['devices.inventory.read','devices.inventory.create']}),delegate.id,{scopeType:'device-ou',ouId:root.id});
 const result=await scopedAuthority().readScoped(delegate.user,bearer),contract=require('../../../../../packages/device-scope-contract');assert.deepEqual(result.permissions,['devices.inventory.read','devices.inventory.create','devices.inventory.assign']);assert.equal(contract.validEnvelope(result,delegate.user),true);
 assert.equal(contract.permits(result,'devices.inventory.assign',null),true);assert.equal(contract.permits(result,'devices.inventory.read',null),true);assert.equal(contract.permits(result,'devices.inventory.create',null),false);assert.equal(contract.permits(result,'devices.inventory.create',{id:outside.id,generation:'1'}),false);
 assert.equal(contract.permits(result,'devices.inventory.create',{id:root.id,generation:result.scope.units.find(unit=>unit.id===root.id).generation}),true);
});
test('device OU source refuses a replacement grant after its original snapshot',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Original held device grant'},owner.user,bearer),role=await createRole({permissions:['devices.inventory.read']}),grant=(await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).grant;let calls=0;
 const authority=scopedAuthority(async(authorization,user)=>{if(++calls===2){await roles.revoke(grant.id,{reason,confirm:true},C.etag('grant',grant),owner.user,bearer);await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id});}return options.revalidate(authorization,user);});
 await assert.rejects(authority.readScoped(delegate.user,bearer),{status:401});assert.equal((await deviceOuSources(delegate)).length,1);
});
test('device OU source rejects current hierarchy drift after the original proof was captured',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Held hierarchy root'},owner.user,bearer),outside=await creator.ou({name:'Later parent'},owner.user,bearer),child=await creator.ou({name:'Held scoped child',parentId:root.id},owner.user,bearer);await assign(await createRole({permissions:['devices.inventory.read']}),delegate.id,{scopeType:'device-ou',ouId:root.id});let calls=0;
 const authority=scopedAuthority(async(authorization,user)=>{if(++calls===2)await new OuMutator(db,options).update(child.id,{name:child.name,parentId:outside.id},ouEtag(child),owner.user,bearer);return options.revalidate(authorization,user);});
 await assert.rejects(authority.readScoped(delegate.user,bearer),{status:401});assert.deepEqual(await deviceOuSources(delegate,'devices.inventory.read',child.id),[]);
});
test('device OU source drops the original PIM activation when it ends during source revalidation',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Held PIM source'},owner.user,bearer),role=await createRole({permissions:['devices.inventory.read']}),eligible=(await makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).eligibility,active=(await activate(eligible,delegate.user)).activation;let calls=0;
 const authority=scopedAuthority(async(authorization,user)=>{if(++calls===2)await pim().end(active.id,{reason,confirm:true},C.etag('activation',active),delegate.user,bearer);return options.revalidate(authorization,user);});
 await assert.rejects(authority.readScoped(delegate.user,bearer),{status:401});assert.deepEqual(await deviceOuSources(delegate),[]);
});
test('device OU source refuses stale MFA foreign recipients and unsupported context before releasing metadata',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Bound source inputs'},owner.user,bearer);await assign(await createRole({permissions:['devices.inventory.read']}),delegate.id,{scopeType:'device-ou',ouId:root.id});const authority=scopedAuthority();
 await assert.rejects(authority.readScoped({...delegate.user,auth_time:delegate.user.auth_time-301},bearer),{status:428});await assert.rejects(authority.readScoped(delegate.user,bearer,{userId:randomUUID()}),{status:404});
 await assert.rejects(authority.readScoped(delegate.user,bearer,{userId:null,device:{deviceId:randomUUID(),deviceRevision:'1',revision:'0',ou:{id:root.id,generation:'1'}}}),{status:400});await assert.rejects(authority.readScoped(delegate.user,bearer,{userId:null,device:null,permissions:['admin']}),{status:400});
});
test('device OU scope kernel binds direct duties to own OU generation and descendants without tenant authority',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Device Engineering'},owner.user,bearer),child=await creator.ou({name:'Device Platform',parentId:root.id},owner.user,bearer),outside=await creator.ou({name:'Other device area'},owner.user,bearer);
 const role=await createRole({permissions:[...C.DEVICE_OU_PERMISSIONS]});const assigned=(await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).grant;
 const stored=(await pool.query('SELECT ou_generation::text FROM identity_company_role_grants WHERE id=$1',[assigned.id])).rows[0];
 for(const permission of C.DEVICE_OU_PERMISSIONS){
  const sources=await deviceOuSources(delegate,permission,child.id);assert.equal(sources.length,1);assert.equal(sources[0].id,assigned.id);assert.equal(sources[0].scopeType,'device-ou');assert.equal(sources[0].ouId,root.id);assert.equal(sources[0].ouGeneration,stored.ou_generation);
  assert.equal((await deviceOuSources(delegate,permission,root.id)).length,1);assert.deepEqual(await deviceOuSources(delegate,permission,outside.id),[]);assert.deepEqual(await deviceOuSources(delegate,permission,child.id,'user'),[]);
 }
 assert.deepEqual(await deviceOuSources(delegate,'users.read',child.id),[]);assert.deepEqual(await deviceOuSources(delegate,'devices.compliance.manage',child.id),[]);
 assert.equal((await roles.detail(role.id,{},owner.user,bearer)).grants[0].status,'active');
 await assert.rejects(new (require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,options).read(delegate.user,bearer),{status:403});
 assert.deepEqual(delegate.user.roles,[]);
});
test('device OU scope kernel refuses user actions mixed roles tenant policy writes and foreign roots',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Strictly typed scopes'},owner.user,bearer);
 for(const permissions of [['users.read'],['users.read','devices.inventory.read'],['devices.compliance.read','devices.compliance.manage']]){
  const role=await createRole({name:'Rejected scope '+permissions.join(' '),permissions});await assert.rejects(assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id}),{status:409});await assert.rejects(makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:root.id}),{status:409});
 }
 const role=await createRole({permissions:['devices.inventory.read']}),foreign=await activeCompany(db,schema,issuer),foreignOu=await creator.ou({name:'Foreign device scope'},foreign.user,bearer);
 await assert.rejects(assign(role,delegate.id,{scopeType:'device-ou',ouId:foreignOu.id}),{status:404});await assert.rejects(makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:foreignOu.id}),{status:404});
 assert.equal((await pool.query("SELECT count(*)::int AS count FROM identity_company_role_grants WHERE scope_type='device-ou'")).rows[0].count,0);
});
test('device OU scope kernel neither widens nor withdraws independent tenant device duties',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Additional limited stock duty'},owner.user,bearer);
 const globalRole=await createRole({name:'Actual tenant assignment duty',permissions:['devices.inventory.read','devices.inventory.assign']}),scopedRole=await createRole({name:'Scoped stock changes only',permissions:['devices.inventory.read','devices.inventory.create']});
 await assign(globalRole,delegate.id);await assign(scopedRole,delegate.id,{scopeType:'device-ou',ouId:root.id});
 const source=await new (require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,options).read(delegate.user,bearer);assert.deepEqual(source.permissions,['devices.inventory.read','devices.inventory.assign']);assert.ok(source.delegation.grants.every(grant=>grant.source.id&&grant.source.scopeType==='tenant'));assert.equal(source.delegation.grants.length,2);
});
test('device OU scope kernel PIM eligibility needs actual self activation and retains original generation and lease',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Eligible device area'},owner.user,bearer),child=await creator.ou({name:'Eligible devices',parentId:root.id},owner.user,bearer);
 const role=await createRole({permissions:['devices.inventory.read']}),eligible=(await makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).eligibility;
 assert.deepEqual(await deviceOuSources(delegate),[]);assert.equal((await pim().self({},delegate.user,bearer)).items[0].eligibility.scopeType,'device-ou');
 const active=(await activate(eligible,delegate.user)).activation;const actual=await deviceOuSources(delegate,'devices.inventory.read',child.id);assert.equal(actual.length,1);assert.equal(actual[0].activationId,active.id);assert.equal(actual[0].id,eligible.id);assert.ok(actual[0].ouGeneration);assert.ok(Number(actual[0].validUntil)<=Date.parse(active.expiresAt)/1000);
 await assert.rejects(new (require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,options).read(delegate.user,bearer),{status:403});
 await pim().end(active.id,{reason,confirm:true},C.etag('activation',active),delegate.user,bearer);assert.deepEqual(await deviceOuSources(delegate),[]);
});
test('device OU scope kernel protected group membership cannot revive an earlier PIM activation',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Grouped device area'},owner.user,bearer),collection=(await roles.createGroup({name:'Device scope operators',description:'Protected eligibility recipients',reason,confirm:true},owner.user,bearer)).group;
 let group=await reader.group(collection.id,{},owner.user,bearer);group=await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);
 const role=await createRole({permissions:['devices.inventory.read']}),eligible=(await makeEligible(role,collection.id,{targetType:'group',scopeType:'device-ou',ouId:root.id})).eligibility;const active=(await activate(eligible,delegate.user)).activation;
 const original=(await deviceOuSources(delegate))[0];assert.equal(original.activationId,active.id);assert.ok(original.membershipId);
 group=await new GroupMutator(db,options).removeMember(group.id,delegate.id,groupEtag(group),owner.user,bearer);assert.deepEqual(await deviceOuSources(delegate),[]);
 await new GroupMutator(db,options).add(group.id,{userId:delegate.id},groupEtag(group),owner.user,bearer);assert.deepEqual(await deviceOuSources(delegate),[]);
 const again=(await activate(eligible,delegate.user)).activation;const replacement=(await deviceOuSources(delegate))[0];assert.equal(replacement.activationId,again.id);assert.notEqual(replacement.membershipId,original.membershipId);
});
test('device OU scope kernel independent approval is consumed once and never makes tenant inventory available',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Reviewed device access'},owner.user,bearer),role=await createRole({permissions:['devices.inventory.read']}),eligible=(await makeEligible(role,delegate.id,{scopeType:'device-ou',ouId:root.id})).eligibility,policy=await approvalPolicy(role);
 await assert.rejects(activate(eligible,delegate.user),{status:428});const pending=(await requested(eligible,delegate.user,policy)).request;assert.deepEqual(await deviceOuSources(delegate),[]);
 const approved=(await decision(pending,'approve')).request;assert.deepEqual(await deviceOuSources(delegate),[]);
 const current=await approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer);assert.equal((await deviceOuSources(delegate))[0].activationId,current.activation.id);
 await assert.rejects(approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),delegate.user,bearer),{status:412});await assert.rejects(new (require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,options).read(delegate.user,bearer),{status:403});
});
test('device OU scope kernel follows live reparenting and drops a replaced root generation',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Original device root'},owner.user,bearer),outside=await creator.ou({name:'Separate device root'},owner.user,bearer),child=await creator.ou({name:'Movable device area',parentId:root.id},owner.user,bearer),role=await createRole({permissions:['devices.inventory.read']});await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id});
 assert.equal((await deviceOuSources(delegate,'devices.inventory.read',child.id)).length,1);await new OuMutator(db,options).update(child.id,{name:child.name,parentId:outside.id},ouEtag(child),owner.user,bearer);assert.deepEqual(await deviceOuSources(delegate,'devices.inventory.read',child.id),[]);
 assert.equal((await deviceOuSources(delegate,'devices.inventory.read',root.id)).length,1);
 await pool.query('ALTER TABLE identity_tenant_ownership DISABLE TRIGGER USER');await pool.query("UPDATE identity_tenant_ownership SET generation=generation+1 WHERE resource_kind='ou' AND resource_id=$1",[root.id]);await pool.query('ALTER TABLE identity_tenant_ownership ENABLE TRIGGER USER');assert.deepEqual(await deviceOuSources(delegate),[]);
});
test('device OU scope kernel full migration replay retains sources receipts and all original sealed receivers',async()=>{
 const delegate=await person(),root=await creator.ou({name:'Retained device scope'},owner.user,bearer),role=await createRole({permissions:['devices.inventory.read']});await assign(role,delegate.id,{scopeType:'device-ou',ouId:root.id});const before=await deviceOuSources(delegate);
 const evidence=async()=>(await pool.query('SELECT to_jsonb(event) AS event,to_jsonb(outbox) AS outbox FROM identity_company_role_events event JOIN identity_company_role_outbox outbox USING(id) ORDER BY event.id')).rows;const original=await evidence();
 for(const file of fs.readdirSync(path.join(__dirname,'../../migrations')).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));
 assert.deepEqual(await deviceOuSources(delegate),before);assert.deepEqual(await evidence(),original);await pool.query('SELECT identity_company_role_receiving(),identity_company_role_pim_receiving(),identity_company_pim_approval_receiving()');
});
test('custom device read and assignment duties reach real device storage without profile, create or compliance authority',async()=>{
 const delegate=await person('device-reader'),target=await person('device-recipient');
 const readRole=await createRole({name:'Actual device reader',permissions:['devices.inventory.read']});const readGrant=(await assign(readRole,delegate.id)).grant;
 await withDevices(async({inventory,deviceDb,source})=>{
  const unit=await inventory.create(deviceValues(),owner.user,bearer);assert.equal((await inventory.list({},delegate.user,bearer)).devices[0].id,unit.id);
  assert.deepEqual((await inventory.capabilities(delegate.user,bearer)).permissions,['devices.inventory.read']);
  await assert.rejects(inventory.create(deviceValues(),delegate.user,bearer),{status:403});await assert.rejects(inventory.assign(unit.id,{userId:target.id},require('../../../../../packages/device-inventory-contract').deviceEtag(unit),delegate.user,bearer),{status:403});
  await assert.rejects(reader.users({},delegate.user,bearer),{status:403});await assert.rejects(source.read(delegate.user,bearer,null,true),{status:403});
  const role=await createRole({name:'Actual device assignment operator',permissions:['devices.inventory.read','devices.inventory.assign']});const granted=(await assign(role,delegate.id)).grant;
  const changed=await inventory.assign(unit.id,{userId:target.id},require('../../../../../packages/device-inventory-contract').deviceEtag(unit),delegate.user,bearer);assert.equal(changed.assignedUserId,target.id);
  const retained=(await deviceDb.query("SELECT proof FROM device_inventory_events WHERE device_id=$1 AND action='assign'",[unit.id])).rows[0].proof;
  assert.equal(retained.source.delegation.grants.find(item=>item.permission==='devices.inventory.assign').source.id,granted.id);
  assert.ok(retained.source.validUntil<=delegate.user.auth_time+300);assert.deepEqual(delegate.user.roles,[]);
  await roles.revoke(granted.id,{reason,confirm:true},C.etag('grant',granted),owner.user,bearer);
  await assert.rejects(inventory.assign(unit.id,{userId:null},require('../../../../../packages/device-inventory-contract').deviceEtag(changed),delegate.user,bearer),{status:403});
  assert.equal((await inventory.get(unit.id,delegate.user,bearer)).assignedUserId,target.id);
  await roles.revoke(readGrant.id,{reason,confirm:true},C.etag('grant',readGrant),owner.user,bearer);await assert.rejects(inventory.get(unit.id,delegate.user,bearer),{status:403});
 });
});
test('actual custom device PIM activation binds retained device changes and immediately ends without changing token roles',async()=>{
 const delegate=await person('device-pim');const role=await createRole({name:'Activated native device stock management',permissions:['devices.inventory.read','devices.inventory.create']});const eligible=(await makeEligible(role,delegate.id)).eligibility;
 await withDevices(async({inventory,deviceDb,source})=>{
  await assert.rejects(inventory.list({},delegate.user,bearer),{status:403});const current=(await activate(eligible,delegate.user)).activation;
  const unit=await inventory.create(deviceValues(),delegate.user,bearer);const event=(await deviceDb.query('SELECT proof FROM device_inventory_events WHERE device_id=$1',[unit.id])).rows[0].proof;
  assert.equal(event.source.delegation.grants.find(item=>item.permission==='devices.inventory.create').source.activationId,current.id);
  const agents=new (require('../../../device-service/src/DeviceAgents').DeviceAgents)(deviceDb,{inventory});
  const issued=await agents.manage(unit.id,'issue',{reason,confirm:true},`"agent-${unit.id}-0"`,delegate.user,bearer,randomUUID());assert.match(issued.enrollmentToken,/^odae_/);
  assert.equal((await deviceDb.query("SELECT source FROM device_agent_events WHERE action='issue'")).rows[0].source.delegation.grants[1].source.activationId,current.id);
  await agents.manage(unit.id,'revoke',{reason,confirm:true},`"agent-${unit.id}-${issued.connection.revision}"`,delegate.user,bearer,randomUUID());
  const values=Object.fromEntries(require('../../../../../packages/device-inventory-contract').DEVICE_FIELDS.map(field=>[field,unit[field]]));
  const changed=await inventory.update(unit.id,{...values,model:'Actually updated through custom PIM',reason,confirm:true},require('../../../../../packages/device-inventory-contract').deviceEtag(unit),delegate.user,bearer);assert.equal(changed.revision,'2');
  await assert.rejects(source.read({...delegate.user,auth_time:delegate.user.auth_time-301},bearer),{status:428});
  const interrupted={...deviceDb,transaction:(operation,settings={})=>deviceDb.transaction(operation,{...settings,beforeCommit:async client=>{await pim().end(current.id,{reason,confirm:true},C.etag('activation',current),delegate.user,bearer);if(settings.beforeCommit)await settings.beforeCommit(client);}})};
  const revokedDuringWrite=new (require('../../../device-service/src/DeviceInventory').DeviceInventory)(interrupted,{authority:inventory.authority});
  await assert.rejects(revokedDuringWrite.update(unit.id,{...values,model:'Must roll back after PIM ends',reason,confirm:true},require('../../../../../packages/device-inventory-contract').deviceEtag(changed),delegate.user,bearer),{status:403});
  assert.equal((await inventory.get(unit.id,owner.user,bearer)).model,changed.model);assert.equal((await deviceDb.query('SELECT count(*) AS count FROM device_inventory_events WHERE device_id=$1',[unit.id])).rows[0].count,'2');
  await assert.rejects(inventory.get(unit.id,delegate.user,bearer),{status:403});
  assert.deepEqual(delegate.user.roles,[]);assert.equal((await pim().history({},delegate.user,bearer)).total,2);
 });
});
test('device duties reject OU scope instead of widening a user OU grant and preserve the original permission whitelist on replay',async()=>{
 const delegate=await person(),unit=await creator.ou({name:'User scope cannot become a device scope'},owner.user,bearer);
 const role=await createRole({permissions:['devices.inventory.read']});await assert.rejects(assign(role,delegate.id,{scopeType:'ou',ouId:unit.id}));await assert.rejects(makeEligible(role,delegate.id,{scopeType:'ou',ouId:unit.id}));
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/060_device_company_roles.sql'),'utf8'));await assign(role,delegate.id);
 assert.deepEqual((await new (require('../DeviceInventoryAuthority').DeviceInventoryAuthority)(db,options).read(delegate.user,bearer)).permissions,['devices.inventory.read']);
 await assert.rejects(createRole({permissions:['devices.wipe']}),{status:400});
});
test('custom compliance duties independently reach actual policies with retained provenance and no implicit inventory access',async()=>{
 const delegate=await person('compliance-delegate');const role=await createRole({name:'Actual own company compliance management',permissions:['devices.compliance.read','devices.compliance.manage']});const granted=(await assign(role,delegate.id)).grant;
 await withDevices(async({deviceDb,source,inventory})=>{
  const compliance=new (require('../../../device-service/src/DeviceCompliance').DeviceCompliance)(deviceDb,{authority:{read:(authorization,user)=>source.read(user,authorization,null,true)}});
  assert.deepEqual((await compliance.capabilities(delegate.user,bearer)).permissions,['devices.compliance.read','devices.compliance.manage']);
  await assert.rejects(inventory.list({},delegate.user,bearer),{status:403});
  const values={settings:{enabled:true,maxReportAgeSeconds:3600,minimumOsVersion:'0',requireDiskEncryption:false,requireFirewall:false,minimumDiskFreePercent:null},reason,confirm:true};
  const saved=await compliance.save('linux',values,`"device-compliance-${owner.receipt.tenantId}-linux-0"`,delegate.user,bearer,randomUUID());assert.equal(saved.policy.revision,'1');
  const event=(await deviceDb.query('SELECT source FROM device_compliance_policy_events')).rows[0];assert.equal(event.source.delegation.grants.find(item=>item.permission==='devices.compliance.manage').source.id,granted.id);
  await roles.revoke(granted.id,{reason,confirm:true},C.etag('grant',granted),owner.user,bearer);await assert.rejects(compliance.capabilities(delegate.user,bearer),{status:403});
 });
});
test('delegated device assignment roles execute real offboarding return requests and handback without stock management',async()=>{
 const delegate=await person('return-delegate'),target=await person('return-target');const role=await createRole({name:'Device handback without stock authority',permissions:['devices.inventory.read','devices.inventory.assign']});const grant=(await assign(role,delegate.id)).grant;
 await withDevices(async({inventory,deviceDb})=>{
  const {deviceEtag,deviceReturnEtag}=require('../../../../../packages/device-inventory-contract');
  let unit=await inventory.create(deviceValues(),owner.user,bearer);unit=await inventory.assign(unit.id,{userId:target.id},deviceEtag(unit),owner.user,bearer);
  const profile=await reader.user(target.id,{},owner.user,bearer),workflowId=randomUUID();const parent=await new (require('../CompanyOffboarding').CompanyOffboarding)(db,options).receive(target.id,{workflowId,expectedRevision:profile.revision,confirm:true},owner.user,bearer);
  const negative=new (require('../DeviceOffboardingAuthority').DeviceOffboardingAuthority)(db,options);
  const returns=new (require('../../../device-service/src/DeviceReturns').DeviceReturns)(deviceDb,{inventory,authority:new (require('../../../device-service/src/DeviceReturnAuthority').DeviceReturnAuthority)({endpoint:'https://native.identity.test/api/identity/device-offboarding',fetchImpl:async(url,request)=>{assert.equal(url.pathname,'/api/identity/device-offboarding');assert.equal(request.headers.Authorization,bearer);return Response.json(await negative.read(delegate.user,bearer,JSON.parse(request.body)));}})});
  const body={workflowId,eligibilityRevision:parent.afterEligibilityRevision,reason,confirm:true,items:[{deviceId:unit.id,deviceRevision:unit.revision,assignmentId:unit.assignmentId,requestId:randomUUID()}]};
  const requested=await returns.request(target.id,body,delegate.user,bearer,randomUUID());assert.equal(requested.results[0].status,'requested');
  const task=await returns.get(body.items[0].requestId,delegate.user,bearer);assert.equal(task.status,'requested');
  const returned=await returns.decide(task.id,{action:'returned',reason,confirm:true},deviceReturnEtag(task),delegate.user,bearer,randomUUID());assert.equal(returned.request.status,'returned');assert.equal((await inventory.get(unit.id,delegate.user,bearer)).assignedUserId,null);
  const retained=(await deviceDb.query('SELECT proof FROM device_return_events WHERE id=$1',[returned.operationId])).rows[0].proof;assert.equal(retained.source.delegation.grants.find(item=>item.permission==='devices.inventory.assign').source.id,grant.id);
  const readRole=await createRole({name:'Handback history reader',permissions:['devices.inventory.read']});await assign(readRole,delegate.id);await roles.revoke(grant.id,{reason,confirm:true},C.etag('grant',grant),owner.user,bearer);
  assert.equal((await returns.list({},delegate.user,bearer)).requests[0].status,'returned');
  await assert.rejects(returns.decide(task.id,{action:'returned',reason,confirm:true},deviceReturnEtag(task),delegate.user,bearer,randomUUID()),{status:403});
 });
});

async function reviewerGroup(memberIds=[]){const created=(await roles.createGroup({name:'Explicit PIM approvers '+randomUUID(),description:'Protected role-specific independent review',reason,confirm:true},owner.user,bearer)).group;let group=await reader.group(created.id,{},owner.user,bearer);for(const userId of memberIds)group=await new GroupMutator(db,options).add(group.id,{userId},groupEtag(group),owner.user,bearer);return group;}
test('protected PIM approver groups delegate only their actual role queue without canonical roles or an owner bypass',async()=>{
 const recipient=await person(),reviewer=await person('group-reviewer');const group=await reviewerGroup([reviewer.id]),role=await createRole(),otherRole=await createRole({name:'Unrelated role'}),eligible=(await makeEligible(role,recipient.id)).eligibility,other=(await makeEligible(otherRole,recipient.id)).eligibility;
 const policy=await approvalPolicy(role,{reviewerGroupId:group.id}),otherPolicy=await approvalPolicy(otherRole);assert.equal(policy.reviewerGroupId,group.id);
 const pending=(await requested(eligible,recipient.user,policy)).request;await requested(other,recipient.user,otherPolicy);
 assert.deepEqual(reviewer.user.roles,[]);assert.deepEqual(await approvals().permissions(reviewer.user),['company.pim.requests.review']);assert.deepEqual(await roles.permissions(reviewer.user),[]);
 const queue=await approvals().list({},reviewer.user,bearer,true);assert.equal(queue.total,1);assert.equal(queue.items[0].id,pending.id);assert.equal(queue.canReview,true);
 await assert.rejects(decision(pending,'approve'),{status:403});await assert.rejects(approvals().policy(role.id,reviewer.user,bearer),{status:403});
 const approved=(await decision(pending,'approve',reviewer.user)).request;const event=(await pool.query('SELECT actor FROM identity_company_role_events WHERE id=(SELECT decision_event_id FROM identity_company_pim_requests WHERE id=$1)',[pending.id])).rows[0];
 assert.equal(event.actor.reviewerSource.kind,'group');assert.equal(event.actor.reviewerSource.groupId,group.id);assert.equal(event.actor.reviewerSource.membershipId,(await pool.query('SELECT membership_id FROM group_members WHERE group_id=$1 AND user_id=$2',[group.id,reviewer.id])).rows[0].membership_id);
 await approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),recipient.user,bearer);assert.ok((await reader.users({},recipient.user,bearer)).total>0);
 await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/061_company_pim_approver_groups.sql'),'utf8'));assert.equal((await approvals().policy(role.id,owner.user,bearer)).reviewerGroupId,group.id);assert.ok((await reader.users({},recipient.user,bearer)).total>0);
});
test('protected PIM approver groups reject ordinary, empty, foreign and approval-disabled group policies',async()=>{
 const member=await person(),role=await createRole(),normal=await creator.group({name:'Ordinary unprotected review group'},owner.user,bearer),empty=await reviewerGroup();
 await assert.rejects(approvalPolicy(role,{reviewerGroupId:normal.id}),{status:409});await assert.rejects(approvalPolicy(role,{reviewerGroupId:empty.id}),{status:409});
 const group=await reviewerGroup([member.id]);await assert.rejects(approvalPolicy(role,{approvalRequired:false,reviewerGroupId:group.id}),{status:400});
 const foreign=await activeCompany(db,schema,issuer),foreignGroup=(await roles.createGroup({name:'Foreign protected reviewers',description:'Separate tenant authority',reason,confirm:true},foreign.user,bearer)).group;
 await assert.rejects(approvalPolicy(role,{reviewerGroupId:foreignGroup.id}),{status:409});assert.equal((await approvals().policy(role.id,owner.user,bearer)).revision,'0');
});
test('protected PIM approver membership removal takes effect immediately and an in-flight incarnation change rolls back',async()=>{
 const recipient=await person(),reviewer=await person();let group=await reviewerGroup([reviewer.id]);const role=await createRole(),eligible=(await makeEligible(role,recipient.id)).eligibility,policy=await approvalPolicy(role,{reviewerGroupId:group.id}),pending=(await requested(eligible,recipient.user,policy)).request;
 beforeCommit=async client=>{beforeCommit=null;await client.query('ALTER TABLE group_members DISABLE TRIGGER USER');await client.query('UPDATE group_members SET membership_id=gen_random_uuid() WHERE group_id=$1 AND user_id=$2',[group.id,reviewer.id]);await client.query('ALTER TABLE group_members ENABLE TRIGGER USER');};
 await assert.rejects(decision(pending,'approve',reviewer.user),{code:'42501'});assert.equal((await approvals().list({},recipient.user,bearer)).items[0].state,'pending');
 group=await new GroupMutator(db,options).removeMember(group.id,reviewer.id,groupEtag(group),owner.user,bearer);assert.deepEqual(await approvals().permissions(reviewer.user),[]);await assert.rejects(approvals().list({},reviewer.user,bearer,true),{status:403});await assert.rejects(decision(pending,'approve',reviewer.user),{status:403});
 await new GroupMutator(db,options).add(group.id,{userId:reviewer.id},groupEtag(group),owner.user,bearer);assert.equal((await decision(pending,'approve',reviewer.user)).request.status,'approved');
});
test('protected PIM approver groups retain fresh MFA and independent identity requirements',async()=>{
 const recipient=await person(),reviewer=await person(),group=await reviewerGroup([recipient.id,reviewer.id]),role=await createRole(),eligible=(await makeEligible(role,recipient.id)).eligibility,policy=await approvalPolicy(role,{reviewerGroupId:group.id}),pending=(await requested(eligible,recipient.user,policy)).request;
 await assert.rejects(decision(pending,'approve',recipient.user),{status:403});await assert.rejects(decision(pending,'deny',recipient.user),{status:403});const older=structuredClone(reviewer.user);older.auth_time-=301;older.mfa_authorization.authTime=older.auth_time;
 assert.equal((await approvals().list({},older,bearer,true)).canReview,false);await assert.rejects(decision(pending,'approve',older),{status:428});
});
test('protected PIM approver policies require an explicit group decision and changing reviewers invalidates old approvals and activations',async()=>{
 const recipient=await person(),reviewer=await person(),group=await reviewerGroup([reviewer.id]),role=await createRole(),eligible=(await makeEligible(role,recipient.id)).eligibility,policy=await approvalPolicy(role,{reviewerGroupId:group.id}),pending=(await requested(eligible,recipient.user,policy)).request,approved=(await decision(pending,'approve',reviewer.user)).request;
 const active=await approvals().activate(approved.id,{reason,confirm:true},C.etag('request',approved),recipient.user,bearer);assert.equal(active.activation.status,'active');
 await assert.rejects(approvalPolicy(role),{status:409});assert.equal((await approvals().policy(role.id,owner.user,bearer)).revision,policy.revision);
 const next=await approvalPolicy(role,{reviewerGroupId:null});assert.equal(next.reviewerGroupId,null);assert.equal(next.revision,'2');await assert.rejects(reader.users({},recipient.user,bearer),{status:403});assert.deepEqual(await approvals().permissions(reviewer.user),[]);
 await assert.rejects(approvals().updatePolicy(role.id,{approvalRequired:true,windowSeconds:300,reviewerGroupId:group.id,reason,confirm:true},ApprovalContract.policyEtag(policy),owner.user,bearer),{status:412});
});
test('protected PIM approver group helpers are private SQL authority',async()=>{
 const role=await createRole(),name='pim_group_limited_'+randomUUID().replaceAll('-','');await pool.query('CREATE ROLE '+name+' NOLOGIN');const client=await pool.connect();
 try{await pool.query('GRANT USAGE ON SCHEMA '+schema+' TO '+name);for(const query of ["SELECT identity_company_pim_approver_group_current(NULL::uuid,$1::uuid,NULL::bigint)","SELECT identity_company_pim_reviewer_source('{}'::jsonb,$1::uuid)"]){await client.query('BEGIN');await client.query('SET LOCAL ROLE '+name);await assert.rejects(client.query(query,[role.id]),{code:'42501'});await client.query('ROLLBACK');}}
 finally{await client.query('ROLLBACK');client.release();await pool.query('DROP OWNED BY '+name);await pool.query('DROP ROLE '+name);}
});
test('protected PIM approver queue reads revalidate original group sources after external actor revalidation',async()=>{
 const recipient=await person(),reviewer=await person(),group=await reviewerGroup([reviewer.id]),role=await createRole(),eligible=(await makeEligible(role,recipient.id)).eligibility,policy=await approvalPolicy(role,{reviewerGroupId:group.id});await requested(eligible,recipient.user,policy);let calls=0;
 const racing=new CompanyPimApprovals(db,{revalidate:async()=>{if(++calls===2)await new GroupMutator(db,options).removeMember(group.id,reviewer.id,groupEtag(group),owner.user,bearer);}});
 await assert.rejects(racing.list({},reviewer.user,bearer,true),{status:403});assert.equal(calls,2);
});
test('protected PIM approver queues retain scoped history of disabled roles without allowing another decision',async()=>{
 const recipient=await person(),reviewer=await person(),group=await reviewerGroup([reviewer.id]),scoped=await createRole(),canonical=await createRole({name:'Canonical disabled role'});
 const eligible=(await makeEligible(scoped,recipient.id)).eligibility,other=(await makeEligible(canonical,recipient.id)).eligibility,policy=await approvalPolicy(scoped,{reviewerGroupId:group.id}),otherPolicy=await approvalPolicy(canonical),pending=(await requested(eligible,recipient.user,policy)).request,otherRequest=(await requested(other,recipient.user,otherPolicy)).request;
 for(const role of [scoped,canonical])await roles.update(role.id,definition({name:role.name,enabled:false}),C.etag('role',role),owner.user,bearer);
 const groupQueue=await approvals().list({status:'all'},reviewer.user,bearer,true);assert.equal(groupQueue.total,1);assert.equal(groupQueue.items[0].id,pending.id);assert.equal(groupQueue.items[0].status,'stale');
 const ownerQueue=await approvals().list({status:'all'},owner.user,bearer,true);assert.equal(ownerQueue.total,1);assert.equal(ownerQueue.items[0].id,otherRequest.id);assert.equal(ownerQueue.items[0].status,'stale');
 await assert.rejects(decision(pending,'approve',reviewer.user),{status:409});await assert.rejects(decision(otherRequest,'approve'),{status:409});
});

const controlReport = device => ({hostname:'native-scoped-device',platform:device.platform,architecture:'arm64',osVersion:'24.04',agentVersion:'1.5.0'});
const controlDecision = {reason,confirm:true};
const controlPermissions = ['devices.inventory.read','devices.inventory.create'];
async function controlState(database) {
 const state=await deviceState(database);
 for(const table of ['device_agent_connections','device_agent_events','device_sync_requests','device_sync_events','device_compliance_events'])state[table]=(await database.query('SELECT to_jsonb(record)::text AS row FROM '+table+' record ORDER BY to_jsonb(record)::text')).rows;
 return state;
}
async function enrollControl(fixture,user=owner.user) {
 const {agents,inside}=fixture,etag=require('../../../device-service/src/DeviceAgents').agentEtag;
 const state=await agents.get(inside.id,{},user,bearer);
 const issued=await agents.manage(inside.id,'issue',controlDecision,etag(inside.id,state.revision),user,bearer,randomUUID());
 const registered=await agents.register({token:issued.enrollmentToken,report:controlReport(inside)},randomUUID());
 return {issued,registered};
}
async function queueControl(fixture,user=fixture.delegate.user) {
 const current=await fixture.sync.list(fixture.inside.id,{},user,bearer);
 return fixture.sync.write(fixture.inside.id,controlDecision,current.connectionEtag,user,bearer,randomUUID());
}
async function controlChange(fixture,kind,request=null) {
 const {inside,agents,sync,delegate}=fixture;
 if(kind==='agent')return agents.manage(inside.id,'issue',controlDecision,require('../../../device-service/src/DeviceAgents').agentEtag(inside.id,(await agents.get(inside.id,{},delegate.user,bearer)).revision),delegate.user,bearer,randomUUID());
 if(kind==='queue')return queueControl(fixture);
 return sync.write(inside.id,controlDecision,require('../../../device-service/src/DeviceSync').syncRequestEtag(request),delegate.user,bearer,randomUUID(),request.id);
}
function afterControlCheckpoint(fixture,check) {
 const database={...fixture.deviceDb,transaction:(operation,settings={})=>fixture.deviceDb.transaction(operation,{...settings,beforeCommit:async client=>{
  if(settings.beforeCommit)await settings.beforeCommit(client);
  if(!settings.readOnly)await check(client);
 }})};
 fixture.agents.database=database;fixture.sync.database=database;if(fixture.returns)fixture.returns.database=database;
}
async function moveControlUnit(fixture,client,destination) {
 const bound={...fixture.deviceDb,transaction:async(operation,settings={})=>{const result=await operation(client);if(settings.beforeCommit)await settings.beforeCommit(client);return result;}};
 const inventory=new(require('../../../device-service/src/DeviceInventory').DeviceInventory)(bound,{authority:fixture.inventory.authority});
 const units=new(require('../../../device-service/src/DeviceOrganizationalUnits').DeviceOrganizationalUnits)(bound,{inventory,authority:fixture.units.authority});
 const current=await units.get(fixture.inside.id,{},owner.user,bearer),selected=(await fixture.units.authority.read(bearer,owner.user,destination.id)).ou;
 return units.write(fixture.inside.id,{ou:{id:selected.id,generation:selected.generation,revision:selected.revision},reason,confirm:true},require('../../../../../packages/device-ou-contract').etag(fixture.inside.id,current.deviceRevision,current.revision),owner.user,bearer,randomUUID());
}

test('device OU controls enroll an actual scoped agent and complete a scoped sync with device credentials',async()=>{
 await scopedDevices(async fixture=>{
  const {inside,agents,sync,deviceDb,delegate}=fixture;
  const {registered}=await enrollControl(fixture,delegate.user);
  const queued=await queueControl(fixture);
  const claim=await sync.claim({deviceId:inside.id},'Bearer '+registered.deviceToken,randomUUID());assert.equal(claim.command.id,queued.request.id);
  const inventory={schemaVersion:1,cpu:{model:'Actual fixture CPU',logicalProcessors:4},memory:{totalBytes:'9007199254740993',availableBytes:'4000000000'},systemDisk:{totalBytes:'1000000000000',availableBytes:'200000000000'},uptimeSeconds:'86461'};
  const security={schemaVersion:1,osVersion:'24.04',diskEncryption:{state:'enabled',reason:'checked'},firewall:{state:'enabled',reason:'checked'}};
  await agents.heartbeat({deviceId:inside.id,report:controlReport(inside),inventory,security,sync:{id:claim.command.id,leaseToken:claim.command.leaseToken}},'Bearer '+registered.deviceToken,randomUUID());
  const actual=(await sync.list(inside.id,{},delegate.user,bearer)).requests[0];assert.equal(actual.status,'completed');assert.equal(actual.result.inventory.facts.memory.totalBytes,'9007199254740993');
  const agentEvent=(await deviceDb.query("SELECT * FROM device_agent_events WHERE device_id=$1 AND action='issue'",[inside.id])).rows[0];
  const syncEvents=(await deviceDb.query('SELECT * FROM device_sync_events WHERE request_id=$1 ORDER BY created_at',[queued.request.id])).rows;assert.deepEqual(syncEvents.map(event=>event.action),['queued','claimed','completed']);
  for(const source of [agentEvent.source,syncEvents[0].source]){assert.equal(source.schemaVersion,2);assert.equal(source.tokenId,delegate.user.jti);assert.deepEqual(source.context,delegate.user.identity_authorization);assert.equal(source.scope.resource.deviceId,inside.id);assert.equal(source.scope.resource.deviceRevision,inside.revision);assert.equal(source.scope.resource.ou.id,fixture.root.id);assert.equal(source.target,null);}
  for(const event of syncEvents.slice(1)){assert.equal(event.actor_user_id,null);assert.equal(event.source,null);}
  assert.equal((await deviceDb.query("SELECT source FROM device_agent_events WHERE device_id=$1 AND action='register'",[inside.id])).rows[0].source,null);
  const current=await agents.get(inside.id,{},delegate.user,bearer);
  await agents.manage(inside.id,'revoke',controlDecision,require('../../../device-service/src/DeviceAgents').agentEtag(inside.id,current.revision),delegate.user,bearer,randomUUID());
  await assert.rejects(agents.heartbeat({deviceId:inside.id,report:controlReport(inside)},'Bearer '+registered.deviceToken,randomUUID()),{status:401});
 },controlPermissions);
});

test('device OU controls retain a cancellation actors own source without replacing the original queue authority',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const queued=await queueControl(fixture),canceller=await person();await assign(fixture.role,canceller.id,{scopeType:'device-ou',ouId:fixture.root.id});
  const cancelled=await fixture.sync.write(fixture.inside.id,controlDecision,require('../../../device-service/src/DeviceSync').syncRequestEtag(queued.request),canceller.user,bearer,randomUUID(),queued.request.id);assert.equal(cancelled.request.status,'cancelled');
  const actual=(await fixture.deviceDb.query('SELECT source FROM device_sync_requests WHERE id=$1',[queued.request.id])).rows[0];assert.equal(actual.source.tokenId,fixture.delegate.user.jti);
  const event=(await fixture.deviceDb.query("SELECT * FROM device_sync_events WHERE request_id=$1 AND action='cancelled'",[queued.request.id])).rows[0];assert.equal(event.actor_user_id,canceller.id);assert.equal(event.source.tokenId,canceller.user.jti);assert.deepEqual(event.source.context,canceller.user.identity_authorization);assert.equal(event.source.scope.resource.deviceId,fixture.inside.id);
 },controlPermissions);
});

test('device OU controls conceal outside and unassigned devices before agent or sync state errors',async()=>{
 await scopedDevices(async fixture=>{
  const before=await controlState(fixture.deviceDb);
  for(const device of [fixture.hidden,fixture.unassigned]){
   for(const action of ['issue','revoke'])await assert.rejects(fixture.agents.manage(device.id,action,controlDecision,require('../../../device-service/src/DeviceAgents').agentEtag(device.id,'99'),fixture.delegate.user,bearer,randomUUID()),{status:404});
   await assert.rejects(fixture.sync.write(device.id,controlDecision,'"unknown-connection"',fixture.delegate.user,bearer,randomUUID()),{status:404});
   await assert.rejects(fixture.sync.write(device.id,controlDecision,'"unknown-request"',fixture.delegate.user,bearer,randomUUID(),randomUUID()),{status:404});
  }
  assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

for(const kind of ['agent','queue','cancel'])test('device OU controls reject a replaced original grant at the final '+kind+' checkpoint',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const queued=kind==='cancel'?await queueControl(fixture,owner.user):null,before=await controlState(fixture.deviceDb);
  const expected=kind==='agent'?require('../../../device-service/src/DeviceAgents').agentEtag(fixture.inside.id,(await fixture.agents.get(fixture.inside.id,{},fixture.delegate.user,bearer)).revision):kind==='queue'?(await fixture.sync.list(fixture.inside.id,{},fixture.delegate.user,bearer)).connectionEtag:require('../../../device-service/src/DeviceSync').syncRequestEtag(queued.request);
  const checkpoint=fixture.inventory.checkpoint.bind(fixture.inventory);let calls=0,replaced=false;
  fixture.inventory.checkpoint=async(...args)=>{if(++calls===2){await roles.revoke(fixture.grant.id,{reason,confirm:true},C.etag('grant',fixture.grant),owner.user,bearer);await assign(fixture.role,fixture.delegate.id,{scopeType:'device-ou',ouId:fixture.root.id});replaced=true;}return checkpoint(...args);};
  await assert.rejects(kind==='agent'?fixture.agents.manage(fixture.inside.id,'issue',controlDecision,expected,fixture.delegate.user,bearer,randomUUID()):fixture.sync.write(fixture.inside.id,controlDecision,expected,fixture.delegate.user,bearer,randomUUID(),queued?.request.id),{status:401});
  assert.equal(replaced,true);assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

for(const kind of ['agent','queue','cancel'])for(const destination of ['inside','outside'])test('device OU controls physically fence a late '+destination+' OU move after the final '+kind+' reply',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const queued=kind==='cancel'?await queueControl(fixture,owner.user):null,before=await controlState(fixture.deviceDb);let moved=false;
  afterControlCheckpoint(fixture,async client=>{await moveControlUnit(fixture,client,destination==='inside'?fixture.child:fixture.outside);moved=true;});
  await assert.rejects(controlChange(fixture,kind,queued?.request),{code:'P0412'});assert.equal(moved,true);assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

for(const kind of ['agent','queue'])test('device OU controls keep the original inventory revision through physical '+kind+' commit',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const before=await controlState(fixture.deviceDb);let edited=false;
  afterControlCheckpoint(fixture,async client=>{
   const bound={...fixture.deviceDb,transaction:async(operation,settings={})=>{const result=await operation(client);if(settings.beforeCommit)await settings.beforeCommit(client);return result;}};
   const inventory=new(require('../../../device-service/src/DeviceInventory').DeviceInventory)(bound,{authority:fixture.inventory.authority});
   const current=await inventory.get(fixture.inside.id,owner.user,bearer);
   await inventory.update(current.id,deviceUpdate(current,{model:'Late actual inventory edit'}),require('../../../../../packages/device-inventory-contract').deviceEtag(current),owner.user,bearer,randomUUID());edited=true;
  });
  await assert.rejects(controlChange(fixture,kind),{code:'P0412'});assert.equal(edited,true);assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

for(const kind of ['agent','queue'])test('device OU controls cannot commit an expired original '+kind+' source after the final checkpoint',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const before=await controlState(fixture.deviceDb),deadline=Math.floor(Date.now()/1000)+10,read=fixture.inventory.authority.read.bind(fixture.inventory.authority);let checked=false;
  fixture.inventory.authority.read=async(...args)=>{const source=await read(...args);assert.ok(deadline<=source.validUntil);return{...source,validUntil:deadline};};
  afterControlCheckpoint(fixture,async client=>{checked=true;await client.query('SELECT pg_sleep($1)',[Math.max(0,(deadline*1000-Date.now()+100)/1000)]);});
  await assert.rejects(controlChange(fixture,kind),{code:'42501'});assert.equal(checked,true);assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

test('device OU controls reject direct SQL commands with a mismatched original device resource',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const current=await fixture.units.get(fixture.inside.id,{},fixture.delegate.user,bearer),resource={deviceId:fixture.inside.id,deviceRevision:fixture.inside.revision,revision:current.revision,ou:{id:current.ou.id,generation:current.ou.generation}};
  const source=await fixture.inventory.authority.read(bearer,fixture.delegate.user,null,resource),connection=(await fixture.deviceDb.query('SELECT device_sync_generation(connection) AS generation FROM device_agent_connections connection WHERE device_id=$1',[fixture.inside.id])).rows[0],before=await controlState(fixture.deviceDb);
  for(const alter of [value=>value.scope.resource=null,value=>value.scope.resource.deviceId=randomUUID(),value=>value.scope.resource.deviceRevision='99',value=>value.scope.resource.revision='99',value=>value.scope.resource.ou.id=randomUUID(),value=>value.scope.resource.ou.generation='99'])for(const kind of ['agent','queue']){
   const changed=structuredClone(source);alter(changed);
   const command={deviceId:fixture.inside.id,source:changed,reason,eventId:randomUUID(),correlationId:randomUUID(),...(kind==='agent'?{action:'issue',expectedRevision:'2',newHash:'a'.repeat(64)}:{action:'queued',id:randomUUID(),generation:connection.generation})};
   await assert.rejects(fixture.deviceDb.transaction(client=>client.query('SELECT '+(kind==='agent'?'device_agent_change':'device_sync_change')+'($1::jsonb)',[JSON.stringify(command)])),{code:'P0412'});assert.deepEqual(await controlState(fixture.deviceDb),before);
  }
 },controlPermissions);
});

for(const fault of ['agent change','agent commit','sync change','sync commit','control manifest guard'])test('device OU controls refuse a missing or replaced '+fault,async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const before=await controlState(fixture.deviceDb);
  if(fault==='control manifest guard')await fixture.deviceDb.query('ALTER TABLE device_control_manifest DISABLE TRIGGER device_control_manifest_guard');
  else{
   const name='device_'+fault.replace(' ','_'),type=fault.endsWith('commit')?'trigger':fault.startsWith('agent')?'void':'uuid',arguments_=fault.endsWith('commit')?'':'command jsonb';
   await fixture.deviceDb.query('CREATE OR REPLACE FUNCTION '+name+'('+arguments_+') RETURNS '+type+' LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN '+(type==='trigger'?'RETURN NEW;':type==='uuid'?'RETURN NULL;':'RETURN;')+' END; $$;');
  }
  await assert.rejects(controlChange(fixture,fault.startsWith('sync')?'queue':'agent'),{code:'42501'});assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

test('device OU controls preserve original queue cancellation and agent receipts through every migration replay',async()=>{
 await scopedDevices(async fixture=>{
  const {registered}=await enrollControl(fixture,fixture.delegate.user),queued=await queueControl(fixture);await controlChange(fixture,'cancel',queued.request);const before=await controlState(fixture.deviceDb);
  const directory=path.resolve(__dirname,'../../../device-service/migrations');for(const file of fs.readdirSync(directory).filter(file=>file.endsWith('.sql')).sort())await fixture.deviceDb.query(fs.readFileSync(path.join(directory,file),'utf8'));
  assert.deepEqual(await controlState(fixture.deviceDb),before);await fixture.deviceDb.query('SELECT device_scope_receiving()');await fixture.deviceDb.query('SELECT device_sync_receiving()');
  await fixture.agents.heartbeat({deviceId:fixture.inside.id,report:controlReport(fixture.inside)},'Bearer '+registered.deviceToken,randomUUID());assert.equal((await fixture.agents.get(fixture.inside.id,{},fixture.delegate.user,bearer)).status,'connected');
  assert.equal((await queueControl(fixture)).request.status,'queued');
 },controlPermissions);
});

test('device OU controls preserve independent tenant stock authority despite an unrelated limited duty',async()=>{
 await scopedDevices(async fixture=>{
  await assign(await createRole({name:'Independent tenant control operator',permissions:controlPermissions}),fixture.delegate.id);
  await fixture.deviceDb.query('ALTER TABLE device_ou_assignments DISABLE TRIGGER device_ou_guard');
  await enrollControl(fixture,fixture.delegate.user);const queued=await queueControl(fixture);
  const agent=(await fixture.deviceDb.query("SELECT source FROM device_agent_events WHERE device_id=$1 AND action='issue'",[fixture.inside.id])).rows[0];
  const request=(await fixture.deviceDb.query('SELECT source FROM device_sync_requests WHERE id=$1',[queued.request.id])).rows[0];
  assert.equal(agent.source.scope.resource,null);assert.equal(request.source.scope.resource,null);assert.equal(agent.source.schemaVersion,2);assert.ok(agent.source.scope.grants.some(grant=>grant.source.scopeType==='device-ou'));
 },['devices.inventory.read','devices.inventory.assign']);
});

test('device OU controls reject a substituted cancellation source after its row guard already ran',async()=>{
 await scopedDevices(async fixture=>{
  await enrollControl(fixture);const queued=await queueControl(fixture,owner.user),before=await controlState(fixture.deviceDb);
  await fixture.deviceDb.query("CREATE FUNCTION poison_control_source() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='cancelled' THEN SELECT source INTO NEW.source FROM device_sync_requests WHERE id=NEW.request_id;END IF;RETURN NEW;END; $$;CREATE TRIGGER z_poison_control_source BEFORE INSERT ON device_sync_events FOR EACH ROW EXECUTE FUNCTION poison_control_source()");
  await assert.rejects(controlChange(fixture,'cancel',queued.request),{code:'42501'});assert.deepEqual(await controlState(fixture.deviceDb),before);
 },controlPermissions);
});

const ouStockPermissions=['devices.inventory.read','devices.inventory.create'];
async function ouDirectory(fixture) { return (await assign(await createRole({name:'Independent OU metadata reader '+randomUUID(),permissions:['ous.read']}),fixture.delegate.id)).grant; }
async function moveScopedOu(fixture,destination=fixture.child,user=fixture.delegate.user,previous=null) {
 const OU=require('../../../../../packages/device-ou-contract');
 const current=previous||await fixture.units.get(fixture.inside.id,{},user,bearer);
 const selected=destination===null?null:(await pool.query("SELECT unit.id,unit.revision::text,ownership.generation::text FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id WHERE unit.id=$1",[destination.id])).rows[0];
 return fixture.units.write(fixture.inside.id,{ou:selected,reason,confirm:true},OU.etag(fixture.inside.id,current.deviceRevision,current.revision),user,bearer,randomUUID());
}
function afterOuCheckpoint(fixture,check) {
 fixture.units.database={...fixture.deviceDb,transaction:(operation,settings={})=>fixture.deviceDb.transaction(operation,{...settings,beforeCommit:async client=>{
  if(settings.beforeCommit)await settings.beforeCommit(client);if(!settings.readOnly)await check(client);
 }})};
}

test('device OU metadata moves only within actual stock scope and retains original inventory and directory evidence',async()=>{
 await scopedDevices(async fixture=>{
  const directory=await ouDirectory(fixture),original=await fixture.inventory.get(fixture.inside.id,owner.user,bearer);
  const result=await moveScopedOu(fixture);assert.equal(result.schemaVersion,2);assert.equal(result.deviceOuProtocol,2);assert.equal(result.coverage,'scope');assert.equal(result.revision,'2');assert.equal(result.ou.id,fixture.child.id);assert.equal(result.deliveryStatus,'pending');
  assert.deepEqual(await fixture.inventory.get(fixture.inside.id,owner.user,bearer),original);
  const retained=(await fixture.deviceDb.query('SELECT source FROM device_ou_events WHERE id=$1',[result.operationId])).rows[0].source;
  assert.equal(retained.inventory.schemaVersion,2);assert.equal(retained.inventory.scope.resource.revision,'1');assert.equal(retained.inventory.scope.resource.ou.id,fixture.root.id);assert.equal(retained.inventory.scope.resource.deviceRevision,original.revision);assert.equal(retained.directoryGrant.id,directory.id);assert.equal(retained.inventory.target,null);
  assert.equal((await moveScopedOu(fixture,fixture.root)).revision,'3');
  const history=await fixture.units.history(fixture.inside.id,{},fixture.delegate.user,bearer);assert.equal(history.total,3);assert.equal(history.events[0].actorUserId,fixture.delegate.id);assert.ok(!JSON.stringify(result).includes('tokenId'));assert.ok(!JSON.stringify(history).includes('directoryGrant'));
  await roles.revoke(fixture.grant.id,{reason,confirm:true},C.etag('grant',fixture.grant),owner.user,bearer);
  assert.equal((await fixture.units.history(fixture.inside.id,{},owner.user,bearer)).total,3,'Historical scoped proofs survive actual grant withdrawal');
 },ouStockPermissions);
});
test('device OU metadata choices apply the read and stock intersection to counts search and every page',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);
  for(let index=0;index<25;index++)await creator.ou({name:'Scoped target '+String(index).padStart(2,'0'),parentId:fixture.root.id},owner.user,bearer);
  const first=await fixture.units.units({},fixture.delegate.user,bearer),second=await fixture.units.units({page:'2'},fixture.delegate.user,bearer);
  assert.equal(first.schemaVersion,2);assert.equal(first.coverage,'scope');assert.equal(first.total,27);assert.equal(first.units.length,25);assert.equal(second.units.length,2);assert.equal(new Set([...first.units,...second.units].map(unit=>unit.id)).size,27);
  assert.ok(![...first.units,...second.units].some(unit=>unit.id===fixture.outside.id));assert.equal((await fixture.units.units({search:'Other device'},fixture.delegate.user,bearer)).total,0);assert.equal((await fixture.units.units({page:'9'},fixture.delegate.user,bearer)).units.length,0);
  assert.ok(!JSON.stringify(first).includes('directoryGrant'));assert.ok(!JSON.stringify(first).includes('tokenId'));assert.ok(!Object.hasOwn(first,'inventory'));assert.ok(first.validUntil<=fixture.delegate.user.auth_time+300);
 },ouStockPermissions);
});
test('device OU metadata keeps independent OU reading and denies out of scope devices before target lookup or versions',async()=>{
 await scopedDevices(async fixture=>{
  const before=await deviceState(fixture.deviceDb);
  await assert.rejects(fixture.units.units({},fixture.delegate.user,bearer),{status:403});await assert.rejects(moveScopedOu(fixture),{status:403});
  const OU=require('../../../../../packages/device-ou-contract');
  for(const device of [fixture.hidden,fixture.unassigned])await assert.rejects(fixture.units.write(device.id,{ou:{id:randomUUID(),generation:'1',revision:'1'},reason,confirm:true},OU.etag(device.id,'99','99'),fixture.delegate.user,bearer),{status:404});
  assert.deepEqual(await deviceState(fixture.deviceDb),before);await ouDirectory(fixture);
  await assert.rejects(moveScopedOu(fixture,null),{status:403});await assert.rejects(moveScopedOu(fixture,fixture.outside),{status:404});await assert.rejects(moveScopedOu(fixture,fixture.root),{status:409});
  const original=await fixture.units.get(fixture.inside.id,{},fixture.delegate.user,bearer);await moveScopedOu(fixture);await assert.rejects(moveScopedOu(fixture,fixture.root,fixture.delegate.user,original),{status:412});
 },ouStockPermissions);
});
test('device OU metadata global reading cannot widen scoped stock choices or pull an outside device into scope',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);await assign(await createRole({name:'Independent global inventory reader',permissions:['devices.inventory.read']}),fixture.delegate.id);
  assert.equal((await fixture.inventory.get(fixture.hidden.id,fixture.delegate.user,bearer)).id,fixture.hidden.id);
  const choices=await fixture.units.units({},fixture.delegate.user,bearer);assert.equal(choices.coverage,'scope');assert.equal(choices.total,2);
  const OU=require('../../../../../packages/device-ou-contract'),current=await fixture.units.get(fixture.hidden.id,{},fixture.delegate.user,bearer),target=(await fixture.units.units({},owner.user,bearer)).units.find(unit=>unit.id===fixture.root.id);
  await assert.rejects(fixture.units.write(fixture.hidden.id,{ou:{id:target.id,generation:target.generation,revision:target.revision},reason,confirm:true},OU.etag(fixture.hidden.id,current.deviceRevision,current.revision),fixture.delegate.user,bearer),{status:404});
 },ouStockPermissions);
});
test('device OU metadata independent tenant stock rights can move and clear while preserving an unrelated scoped source',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);await assign(await createRole({name:'Independent tenant stock operator',permissions:ouStockPermissions}),fixture.delegate.id);
  const source=await fixture.source.readScoped(fixture.delegate.user,bearer);assert.equal(source.schemaVersion,2);assert.equal(source.scope.resource,null);
  const choices=await fixture.units.units({},fixture.delegate.user,bearer);assert.equal(choices.coverage,'tenant');assert.equal(choices.total,3);
  const moved=await moveScopedOu(fixture,fixture.outside);assert.equal(moved.coverage,'tenant');assert.equal((await moveScopedOu(fixture,null)).ou,null);
  const proof=(await fixture.deviceDb.query('SELECT source FROM device_ou_events WHERE id=$1',[moved.operationId])).rows[0].source;assert.equal(proof.inventory.schemaVersion,2);assert.equal(proof.inventory.scope.resource,null);
 },['devices.inventory.read','devices.inventory.create','devices.inventory.assign']);
});
for(const replace of ['stock grant','directory grant','PIM activation'])test('device OU metadata cannot acknowledge a replaced '+replace+' at its final original source checkpoint',async()=>{
 await scopedDevices(async fixture=>{
  const directory=await ouDirectory(fixture);let activation;
  if(replace==='PIM activation'){
   await roles.revoke(fixture.grant.id,{reason,confirm:true},C.etag('grant',fixture.grant),owner.user,bearer);
   const eligible=(await makeEligible(fixture.role,fixture.delegate.id,{scopeType:'device-ou',ouId:fixture.root.id})).eligibility;activation=(await activate(eligible,fixture.delegate.user)).activation;
  }
  const before=await deviceState(fixture.deviceDb),read=fixture.units.authority.read.bind(fixture.units.authority);let calls=0;
  fixture.units.authority.read=async(...args)=>{
   if(++calls===3){
    if(replace==='PIM activation')await pim().end(activation.id,{reason,confirm:true},C.etag('activation',activation),fixture.delegate.user,bearer);
    else{const grant=replace==='stock grant'?fixture.grant:directory;await roles.revoke(grant.id,{reason,confirm:true},C.etag('grant',grant),owner.user,bearer);if(replace==='stock grant')await assign(fixture.role,fixture.delegate.id,{scopeType:'device-ou',ouId:fixture.root.id});else await ouDirectory(fixture);}
   }
   return read(...args);
  };
  await assert.rejects(moveScopedOu(fixture),error=>[401,403].includes(error.status));assert.equal(calls,3);assert.deepEqual(await deviceState(fixture.deviceDb),before);
 },ouStockPermissions);
});
for(const corruption of ['inside association','outside association','inventory revision'])test('device OU metadata physically rejects late '+corruption+' after its final successful checkpoint',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);const before=await deviceState(fixture.deviceDb);let reached=false;
  afterOuCheckpoint(fixture,async client=>{
   reached=true;await client.query("SET LOCAL session_replication_role='replica'");
   try{
    if(corruption==='inventory revision')await client.query('UPDATE devices SET inventory_revision=inventory_revision+1 WHERE id=$1',[fixture.inside.id]);
    else{const target=corruption==='inside association'?fixture.root:fixture.outside,unit=(await fixture.units.authority.read(bearer,owner.user,target.id)).ou;await client.query('UPDATE device_ou_assignments SET revision=revision+1,ou=$2::jsonb WHERE device_id=$1',[fixture.inside.id,JSON.stringify(unit)]);}
   }finally{await client.query("SET LOCAL session_replication_role='origin'");}
  });
  await assert.rejects(moveScopedOu(fixture),{code:'P0412'});assert.equal(reached,true);assert.deepEqual(await deviceState(fixture.deviceDb),before);
 },ouStockPermissions);
});
test('device OU metadata original deadline remains mandatory at physical commit after a successful final reply',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);const before=await deviceState(fixture.deviceDb);let reached=false;
  const authTime=Math.floor(Date.now()/1000)-293;fixture.delegate.user.auth_time=authTime;fixture.delegate.user.mfa_authorization.authTime=authTime;
  afterOuCheckpoint(fixture,async client=>{reached=true;const until=Number((await client.query("SELECT current_setting('opendirectory.device_ou')::jsonb#>>'{source,validUntil}' AS until")).rows[0].until);await client.query('SELECT pg_sleep($1)',[Math.max(0,until-Date.now()/1000)+0.15]);});
  await assert.rejects(moveScopedOu(fixture),{code:'42501'});assert.equal(reached,true);assert.deepEqual(await deviceState(fixture.deviceDb),before);
 },ouStockPermissions);
});
test('device OU metadata SQL refuses substituted original resources and legacy wrappers around scoped proofs',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);const current=await fixture.units.get(fixture.inside.id,{},fixture.delegate.user,bearer),resource={deviceId:fixture.inside.id,deviceRevision:current.deviceRevision,revision:current.revision,ou:{id:current.ou.id,generation:current.ou.generation}},source=await fixture.units.authority.read(bearer,fixture.delegate.user,fixture.child.id,resource),before=await deviceState(fixture.deviceDb);
  const selectedOu={id:source.ou.id,generation:source.ou.generation,revision:source.ou.revision};
  for(const change of [value=>value.inventory.scope.resource=null,value=>value.inventory.scope.resource.deviceId=randomUUID(),value=>value.inventory.scope.resource.deviceRevision='99',value=>value.inventory.scope.resource.revision='99',value=>value.inventory.scope.resource.ou.generation='99']){
   const bad=structuredClone(source);change(bad);assert.equal((await fixture.deviceDb.query('SELECT device_scope_source_valid($1::jsonb) AS valid',[JSON.stringify(bad.inventory)])).rows[0].valid,true);
   const command={id:randomUUID(),deviceId:fixture.inside.id,deviceRevision:current.deviceRevision,revision:current.revision,selectedOu,source:bad,reason,confirm:true,correlationId:randomUUID()};
   await assert.rejects(fixture.deviceDb.transaction(client=>client.query('SELECT device_ou_change($1::jsonb)',[JSON.stringify(command)])),{code:bad.inventory.scope.resource===null?'42501':'P0412'});assert.deepEqual(await deviceState(fixture.deviceDb),before);
  }
  const downgraded={...source,schemaVersion:1,deviceOuProtocol:1};await assert.rejects(fixture.deviceDb.query('SELECT device_ou_source($1::jsonb)',[JSON.stringify(downgraded)]),{code:'42501'});
 },ouStockPermissions);
});
for(const fault of ['change','commit','manifest guard','pending receipt'])test('device OU metadata fails closed on a replaced '+fault,async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);const before=await deviceState(fixture.deviceDb);
  if(fault==='manifest guard')await fixture.deviceDb.query('ALTER TABLE device_ou_scope_manifest DISABLE TRIGGER device_ou_scope_manifest_guard');
  else if(fault==='pending receipt')await fixture.deviceDb.query('CREATE FUNCTION omit_scoped_ou_pending() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL;END;$$;CREATE TRIGGER zz_omit_scoped_ou_pending BEFORE INSERT ON device_ou_outbox FOR EACH ROW EXECUTE FUNCTION omit_scoped_ou_pending()');
  else await fixture.deviceDb.query('CREATE OR REPLACE FUNCTION device_ou_'+fault+'('+(fault==='change'?'command jsonb':'')+') RETURNS '+(fault==='change'?'uuid':'trigger')+' LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN '+(fault==='change'?'RETURN NULL;':'RETURN NEW;')+' END;$$;');
  await assert.rejects(moveScopedOu(fixture),error=>error.status===503||error.code==='42501');assert.deepEqual(await deviceState(fixture.deviceDb),before);
 },ouStockPermissions);
});
test('device OU metadata complete forward replay retains scoped history and a partial old receiver cannot advertise protocol two',async()=>{
 await scopedDevices(async fixture=>{
  await ouDirectory(fixture);await moveScopedOu(fixture);const before=await deviceState(fixture.deviceDb),folder=path.join(__dirname,'../../../device-service/migrations');
  await fixture.deviceDb.query(fs.readFileSync(path.join(folder,'013_device_organizational_units.sql'),'utf8'));
  await assert.rejects(fixture.units.units({},fixture.delegate.user,bearer),{status:503});
  for(const name of fs.readdirSync(folder).filter(name=>name.endsWith('.sql')).sort())await fixture.deviceDb.query(fs.readFileSync(path.join(folder,name),'utf8'));
  await fixture.deviceDb.query('SELECT device_ou_receiving(2)');assert.deepEqual(await deviceState(fixture.deviceDb),before);assert.equal((await fixture.units.history(fixture.inside.id,{},fixture.delegate.user,bearer)).total,2);
  assert.equal((await fixture.deviceDb.query('SELECT count(*)::int AS count FROM device_ou_scope_manifest')).rows[0].count,10);
  assert.equal((await fixture.deviceDb.query("SELECT has_function_privilege('public','device_ou_change(jsonb)','EXECUTE') AS allowed")).rows[0].allowed,false);
 },ouStockPermissions);
});
for(const change of ['directory grant','target metadata'])test('device OU metadata choices cannot acknowledge changed '+change+' after the first Identity reply',async()=>{
 await scopedDevices(async fixture=>{
  const directory=await ouDirectory(fixture),units=fixture.units.authority.units.bind(fixture.units.authority);let calls=0;
  fixture.units.authority.units=async(...args)=>{
   if(++calls===2){if(change==='directory grant'){await roles.revoke(directory.id,{reason,confirm:true},C.etag('grant',directory),owner.user,bearer);await ouDirectory(fixture);}else await new OuMutator(db,options).update(fixture.child.id,{name:'Changed after original choices'},ouEtag(fixture.child),owner.user,bearer);}
   return units(...args);
  };
  await assert.rejects(fixture.units.units({},fixture.delegate.user,bearer),{status:401});assert.equal(calls,2);
 },ouStockPermissions);
});

async function deviceOuGovernor() {
 const operator=await fixedOperator('ou-administrator');
 await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)',[operator.id,'role-administrator','Independent protected OU governance fixture']);
 const state=await new AuthorizationState(db).state(issuer,operator.user.sub);operator.user.roles=state.roles;operator.user.identity_authorization=state.context;return operator;
}
async function ouGovernanceState() {
 const result={};for(const table of ['ous','identity_directory_ou_events','identity_directory_ou_outbox','identity_company_role_uses'])result[table]=(await pool.query('SELECT to_jsonb(record)::text AS row FROM '+table+' record ORDER BY to_jsonb(record)::text')).rows;
 return result;
}
test('device OU governance refuses ordinary and claimed administrators at both boundaries of the protected subtree',async()=>{
 await scopedDevices(async fixture=>{
  const operator=await fixedOperator('ou-administrator'),mutator=new OuMutator(db,options),before=await ouGovernanceState(),devices=await deviceState(fixture.deviceDb);
  for(const user of [operator.user,{...operator.user,roles:['admin']}]){
   await assert.rejects(mutator.update(fixture.outside.id,{parentId:fixture.root.id},ouEtag(fixture.outside),user,bearer),{status:403});
   await assert.rejects(mutator.update(fixture.child.id,{parentId:null},ouEtag(fixture.child),user,bearer),{status:403});
   await assert.rejects(mutator.update(fixture.root.id,{name:'An ordinary OU editor cannot control a device grant root'},ouEtag(fixture.root),user,bearer),{status:403});
   await assert.rejects(mutator.remove(fixture.child.id,ouEtag(fixture.child),user,bearer),{status:403});
  }
  assert.deepEqual(await ouGovernanceState(),before);assert.deepEqual(await deviceState(fixture.deviceDb),devices);assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,2);
 },['devices.inventory.read']);
});
test('device OU governance an independent role and OU manager changes live scope only through an actual audited hierarchy mutation',async()=>{
 await scopedDevices(async fixture=>{
  const operator=await deviceOuGovernor(),devices=await deviceState(fixture.deviceDb),prior=await fixture.source.readScoped(fixture.delegate.user,bearer);
  await assert.rejects(fixture.inventory.list({},operator.user,bearer),{status:403});
  const changed=await new OuMutator(db,options).update(fixture.outside.id,{parentId:fixture.root.id},ouEtag(fixture.outside),operator.user,bearer);assert.equal(changed.parentId,fixture.root.id);
  const current=await fixture.source.readScoped(fixture.delegate.user,bearer);assert.deepEqual(current.context,prior.context);assert.deepEqual(current.scope.grants,prior.scope.grants);assert.notDeepEqual(current.scope.units,prior.scope.units);
  assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,3);assert.equal((await fixture.inventory.get(fixture.hidden.id,fixture.delegate.user,bearer)).id,fixture.hidden.id);assert.deepEqual(await deviceState(fixture.deviceDb),devices);
  const events=(await pool.query("SELECT event.*,outbox.status FROM identity_directory_ou_events event JOIN identity_directory_ou_outbox outbox USING(id) WHERE event.ou_id=$1 AND event.action='update'",[fixture.outside.id])).rows;
  assert.equal(events.length,1);assert.equal(events[0].status,'pending');assert.equal(events[0].actor.userId,operator.id);assert.equal(events[0].proof.companyGovernance.context.userId,operator.id);assert.equal(events[0].proof.companyGovernance.mfa.userId,operator.id);assert.equal(events[0].before_state.parent_id,null);assert.equal(events[0].after_state.parent_id,fixture.root.id);
  await assert.rejects(fixture.inventory.checkpoint(prior,fixture.delegate.user,bearer),{status:401});
 },['devices.inventory.read']);
});
test('device OU governance an eligible device PIM root is protected before activation and after eligibility withdrawal',async()=>{
 await scopedDevices(async fixture=>{
  const root=await creator.ou({name:'Device PIM-only protected root'},owner.user,bearer),role=await createRole({name:'PIM-only device root role',permissions:['devices.inventory.read']}),eligible=(await makeEligible(role,fixture.delegate.id,{scopeType:'device-ou',ouId:root.id})).eligibility,operator=await fixedOperator('ou-administrator'),mutator=new OuMutator(db,options);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_role_grants WHERE ou_id=$1',[root.id])).rows[0].count,0);
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_role_activations WHERE eligibility_id=$1',[eligible.id])).rows[0].count,0);
  await assert.rejects(mutator.update(fixture.outside.id,{parentId:root.id},ouEtag(fixture.outside),operator.user,bearer),{status:403});
  await pim().revokeEligibility(eligible.id,{reason,confirm:true},C.etag('eligibility',eligible),owner.user,bearer);
  await assert.rejects(mutator.update(fixture.outside.id,{parentId:root.id},ouEtag(fixture.outside),operator.user,bearer),{status:403});
  assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,2);
 },['devices.inventory.read']);
});
test('device OU governance withdrawing the last grant does not silently release the protected namespace to OU administrators',async()=>{
 await scopedDevices(async fixture=>{
  const operator=await fixedOperator('ou-administrator');await roles.revoke(fixture.grant.id,{reason,confirm:true},C.etag('grant',fixture.grant),owner.user,bearer);
  await assert.rejects(fixture.inventory.list({},fixture.delegate.user,bearer),{status:403});
  await assert.rejects(new OuMutator(db,options).update(fixture.outside.id,{parentId:fixture.root.id},ouEtag(fixture.outside),operator.user,bearer),{status:403});
  assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_company_role_ous WHERE ou_id=$1',[fixture.root.id])).rows[0].count,1);
  const replacement=(await assign(fixture.role,fixture.delegate.id,{scopeType:'device-ou',ouId:fixture.root.id})).grant;assert.notEqual(replacement.id,fixture.grant.id);assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,2);
 },['devices.inventory.read']);
});
test('device OU governance an active directory PIM editor cannot substitute its lease for independent role governance',async()=>{
 await scopedDevices(async fixture=>{
  const operator=await person('PIM-directory-editor'),role=await createRole({name:'Activated directory metadata editor',permissions:['ous.read','ous.update','ous.delete']}),eligible=(await makeEligible(role,operator.id)).eligibility;
  await activate(eligible,operator.user,3600);assert.deepEqual(operator.user.roles,[]);assert.ok((await reader.ous({},operator.user,bearer)).ous.some(unit=>unit.id===fixture.outside.id));
  await assert.rejects(new OuMutator(db,options).update(fixture.outside.id,{parentId:fixture.root.id},ouEtag(fixture.outside),operator.user,bearer),{status:403});assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,2);
 },['devices.inventory.read']);
});
test('device OU governance physical commit retains the independent managers original fresh MFA deadline',async()=>{
 await scopedDevices(async fixture=>{
  const operator=await deviceOuGovernor(),before=await ouGovernanceState(),devices=await deviceState(fixture.deviceDb),authTime=Math.floor(Date.now()/1000)-292;operator.user.auth_time=authTime;operator.user.mfa_authorization.authTime=authTime;let reached=false;
  beforeCommit=async client=>{reached=true;const until=Number((await client.query("SELECT current_setting('opendirectory.ou_mutation')::jsonb#>>'{proof,validUntil}' AS until")).rows[0].until);assert.ok(Number.isSafeInteger(until));await client.query('SELECT pg_sleep($1)',[Math.max(0,until-Date.now()/1000)+0.15]);};
  await assert.rejects(new OuMutator(db,options).update(fixture.outside.id,{parentId:fixture.root.id},ouEtag(fixture.outside),operator.user,bearer),{code:'42501'});beforeCommit=null;assert.equal(reached,true);assert.deepEqual(await ouGovernanceState(),before);assert.deepEqual(await deviceState(fixture.deviceDb),devices);assert.equal((await fixture.inventory.list({},fixture.delegate.user,bearer)).total,2);
 },['devices.inventory.read']);
});
