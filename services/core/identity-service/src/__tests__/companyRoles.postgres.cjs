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
 const delegate=await person();const role=await createRole();await assign(role,delegate.id);await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/057_company_roles.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/058_company_pim.sql'),'utf8'));await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations/059_company_pim_approvals.sql'),'utf8'));assert.ok((await reader.users({},delegate.user,bearer)).users.some(row=>row.id===delegate.id));await pool.query('SELECT identity_company_role_receiving()');
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

async function withDevices(operation){
 const {DeviceInventoryAuthority}=require('../DeviceInventoryAuthority');
 const source=new DeviceInventoryAuthority(db,options);
 const fixture=await require('../../../../../scripts/lib/device-inventory-fixture.cjs').deviceInventoryFixture(process.env.IDENTITY_TEST_DATABASE_URL,'http://127.0.0.1:1');
 const authority={read:(authorization,user,target)=>source.read(user,authorization,target?{userId:target}:null)};
 const inventory=new (require('../../../device-service/src/DeviceInventory').DeviceInventory)(fixture.db,{authority});
 try{return await operation({inventory,deviceDb:fixture.db,source});}finally{await fixture.close();}
}
const deviceValues=()=>({assetId:'NATIVE-'+randomUUID(),serialNumber:randomUUID(),manufacturer:'Actual native fixture',model:'Delegated inventory',deviceClass:'laptop',platform:'linux'});
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
