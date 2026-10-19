'use strict';

const {test,before,beforeEach,after}=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {Pool}=require('pg');
const {UserMutator}=require('../UserMutator');const {DirectoryCreator}=require('../DirectoryCreator');
const {DirectoryUsers,userEtag}=require('../DirectoryUsers');const {AuthorizationState}=require('../AuthorizationState');
const {sameContext}=require('../../../../../packages/identity-authorization-contract');
const {provisionTenant,adoptTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
const schema='mutations_'+randomUUID().replaceAll('-','');const administration=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});
const issuer='https://mutation.test';const migrations=path.join(__dirname,'../../migrations');let pool;let database;
before(async()=>{
 await administration.query('CREATE SCHEMA '+schema);pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:10,options:`-c search_path=${schema},public`});
 database={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,options={})=>{
  const client=await pool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');await client.query("SET LOCAL lock_timeout='5s';SET LOCAL statement_timeout='15s'");if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const result=await operation(client);await client.query('COMMIT');return result;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
 }};
 for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
});
beforeEach(async()=>{await pool.query('TRUNCATE identity_tenants,users,groups,ous,identity_deleted_users,identity_deleted_groups,identity_user_audit,identity_user_outbox,identity_authorization_audit,identity_group_audit,identity_group_outbox CASCADE');});
after(async()=>{await pool.end();await administration.query('DROP SCHEMA '+schema+' CASCADE');await administration.end();});
async function actor(role='admin',tenant,expiresSeconds){
 tenant=tenant||await provisionTenant(database,schema,{enabled:true});const userId=randomUUID();const subject='mutator-'+randomUUID();
 await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[userId,subject,subject+'@test.invalid']);await pool.query('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)',[issuer,subject,userId]);
 await adoptTenant(database,schema,tenant,[{kind:'user',resourceId:userId}]);await pool.query('INSERT INTO identity_role_assignments(user_id,role,reason,expires_at) VALUES($1,$2,$3,$4)',[userId,role,'Explicit owned user mutation operator',expiresSeconds?new Date(Date.now()+expiresSeconds*1000):null]);
 const state=await new AuthorizationState(database).state(issuer,subject);const user={iss:issuer,sub:subject,actor_type:'user',roles:state.roles,identity_authorization:state.context,exp:Math.floor(Date.now()/1000)+300};
 const live={checks:0,revoked:false,onCheck:null};const revalidate=async(_authorization,original)=>{
  live.checks++;if(live.onCheck)await live.onCheck(live.checks);const current=await new AuthorizationState(database).state(issuer,original.sub);
  if(live.revoked||!current.active||!sameContext(current.context,original.identity_authorization))throw Object.assign(new Error('Original user mutation authority revoked'),{status:401});return current.tenant;
 };
 return{tenant,user,userId,live,revalidate,mutator:new UserMutator(database,{issuer,revalidate}),creator:new DirectoryCreator(database,{issuer,revalidate})};
}
const load=identity=>new DirectoryUsers(database).get(identity);
async function target(fixture){return fixture.creator.user({username:'target-'+randomUUID(),email:randomUUID()+'@test.invalid'},fixture.user,'Bearer original');}
const events=async identity=>(await pool.query('SELECT event.*,outbox.action AS outbox_action FROM identity_directory_user_events event JOIN identity_directory_user_outbox outbox USING(id) WHERE event.user_id=$1',[identity])).rows;
function wrapped(operation){return{...database,transaction:(callback,options)=>database.transaction(async client=>{const result=await callback(client);await operation(client,result);return result;},options)};}
async function call(fixture,action,person){return action==='update'?fixture.mutator.update(person.id,{title:'Updated owned profile'},userEtag(person),fixture.user,'Bearer original'):action==='delete'?fixture.mutator.remove(person.id,userEtag(person),fixture.user,'Bearer original'):fixture.mutator.invalidate(person.id,fixture.user,'Bearer original');}

test('owned profile and status changes commit exact ETags and immutable original-actor evidence without bearer or profile disclosure',async()=>{
 const fixture=await actor();const person=await target(fixture);const updated=await fixture.mutator.update(person.id,{displayName:'New owned display',enabled:true},userEtag(person),fixture.user,'Bearer original');
 assert.equal(updated.enabled,true);assert.equal(updated.displayName,'New owned display');assert.notEqual(updated.revision,person.revision);assert.deepEqual(await load(person.id),updated);
 const evidence=await events(person.id);assert.equal(evidence.length,1);assert.equal(evidence[0].action,'update');assert.equal(evidence[0].outbox_action,'update');assert.equal(evidence[0].actor.userId,fixture.userId);assert.equal(evidence[0].details.beforeRevision,person.revision);assert.equal(evidence[0].details.afterRevision,updated.revision);
 assert.match(evidence[0].scope_sha256,/^[a-f0-9]{64}$/);assert.match(evidence[0].details.afterSha256,/^[a-f0-9]{64}$/);assert.equal(JSON.stringify(evidence).includes('Bearer'),false);assert.equal(JSON.stringify(evidence).includes(person.email),false);assert.equal(JSON.stringify(evidence).includes('New owned display'),false);
 for(const source of['identity_directory_user_events','identity_directory_user_outbox'])for(const sql of['UPDATE '+source+" SET action='delete'",'DELETE FROM '+source])await assert.rejects(pool.query(sql),error=>error.code==='42501');
});
for(const action of['update','delete','invalidate'])test(action+' hides foreign, unowned and missing UUIDs without changing target or evidence',async()=>{
 const first=await actor();const foreign=await actor();const owned=await target(foreign);const unowned=randomUUID();await pool.query('INSERT INTO users(id,username,email) VALUES($1,$2,$3)',[unowned,'unowned',unowned+'@test.invalid']);
 for(const identity of[owned.id,unowned,randomUUID()]){const person=identity===owned.id?owned:identity===unowned?await load(unowned):{id:identity,revision:'1'};await assert.rejects(call(first,action,person),error=>error.status===404);assert.equal((await events(identity)).length,0);}
 assert.deepEqual(await load(owned.id),owned);assert.equal((await load(unowned)).enabled,true);
});
test('foreign target locks are never acquired even when another transaction holds that user exclusively',async()=>{
 const fixture=await actor();const foreign=await actor();const person=await target(foreign);const blocker=await pool.connect();
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[person.id]);const started=Date.now();await assert.rejects(call(fixture,'update',person),error=>error.status===404);assert.ok(Date.now()-started<2000);}finally{await blocker.query('ROLLBACK');blocker.release();}
});
test('missing, malformed, mismatched and stale user ETags fail before a visible owned write',async()=>{
 const fixture=await actor();const person=await target(fixture);
 for(const[expected,status]of[[undefined,428],['*',400],['W/'+userEtag(person),400],[userEtag({...person,revision:'9223372036854775808'}),400],[userEtag({...person,id:randomUUID()}),412],[userEtag({...person,revision:'1'}),412]])for(const action of['update','delete'])await assert.rejects(action==='update'?fixture.mutator.update(person.id,{title:'Rejected'},expected,fixture.user,'Bearer original'):fixture.mutator.remove(person.id,expected,fixture.user,'Bearer original'),error=>error.status===status);
 assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('unknown fields cannot smuggle tenant, credentials, generation, owner, roles or an admission bypass into a user mutation',async()=>{
 const fixture=await actor();const person=await target(fixture);for(const change of[{tenantId:fixture.tenant},{id:person.id},{selfReduction:true},{authorization_revision:'1'},{roles:['admin']},{password:'ignored'},{enabled:'false'}])await assert.rejects(fixture.mutator.update(person.id,change,userEtag(person),fixture.user,'Bearer original'),error=>error.status===400);
});
test('readers, workloads and unbound legacy actors cannot reuse an owned tenant as mutation authority',async()=>{
 const fixture=await actor('directory-reader');const person=await new DirectoryUsers(database).get(fixture.userId);
 for(const user of[fixture.user,{...fixture.user,roles:['admin'],actor_type:'application'},{...fixture.user,roles:['admin'],identity_authorization:undefined},{...fixture.user,roles:['admin'],iss:'https://foreign.test'}])await assert.rejects(fixture.mutator.invalidate(person.id,user,'Bearer original'),error=>error.status===403);assert.equal(fixture.live.checks,0);
});
for(const action of['update','delete','invalidate'])test('own '+action+' remains possible without admitting any foreign user or a revoked original session',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);fixture.live.checks=0;
 const result=action==='update'?await fixture.mutator.update(person.id,{enabled:false},userEtag(person),fixture.user,'Bearer original'):await call(fixture,action,person);
 assert.equal(fixture.live.checks,3);assert.equal((await events(person.id)).length,1);const state=await new AuthorizationState(database).state(issuer,fixture.user.sub);
 if(action==='delete'){await assert.rejects(load(person.id),error=>error.status===404);assert.equal(state.active,false);assert.equal((await pool.query('SELECT count(*)::int AS count FROM identity_subject_tenant_bindings WHERE issuer=$1 AND subject=$2',[issuer,fixture.user.sub])).rows[0].count,1);}
 else if(action==='update'){assert.equal(result.enabled,false);assert.equal(state.active,false);}
 else{assert.equal(result.userId,person.id);assert.notEqual(result.revision,fixture.user.identity_authorization.revision);assert.equal(state.active,true);assert.equal(sameContext(state.context,fixture.user.identity_authorization),false);}
 await assert.rejects(fixture.mutator.invalidate(person.id,fixture.user,'Bearer original'),error=>error.status===401);
});
test('own ordinary profile editing preserves original authorization and is not treated as a self-reduction',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);await fixture.mutator.update(person.id,{title:'Same-authority own edit'},userEtag(person),fixture.user,'Bearer original');assert.equal(sameContext((await new AuthorizationState(database).state(issuer,fixture.user.sub)).context,fixture.user.identity_authorization),true);
});
for(const action of['update','delete','invalidate'])test('external original-token withdrawal after own '+action+' DML rolls back the entire self-reduction',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);fixture.live.onCheck=async number=>{if(number===3)fixture.live.revoked=true;};
 await assert.rejects(action==='update'?fixture.mutator.update(person.id,{enabled:false},userEtag(person),fixture.user,'Bearer original'):call(fixture,action,person),error=>error.status===401);
 assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);assert.equal(sameContext((await new AuthorizationState(database).state(issuer,fixture.user.sub)).context,fixture.user.identity_authorization),true);
});
test('session reset is monotonic without a client ETag and preserves public profile, eligibility and tenant generations',async()=>{
 const fixture=await actor();const person=await target(fixture);const before=(await pool.query('SELECT * FROM users WHERE id=$1',[person.id])).rows[0];const reset=await fixture.mutator.invalidate(person.id,fixture.user,'Bearer original');const after=(await pool.query('SELECT * FROM users WHERE id=$1',[person.id])).rows[0];
 assert.equal(reset.revision,String(after.authorization_revision));assert.ok(BigInt(after.authorization_revision)>BigInt(before.authorization_revision));assert.ok(BigInt(after.record_revision)>BigInt(before.record_revision));assert.equal(after.eligibility_revision,before.eligibility_revision);assert.equal(after.tenant_generation,before.tenant_generation);assert.equal(after.email,before.email);assert.equal(after.enabled,false);
});
test('deletion retains ownership, retirement, negative eligibility, record audit and outbox even after user and links disappear',async()=>{
 const fixture=await actor();const person=await target(fixture);await call(fixture,'delete',person);
 for(const source of['identity_tenant_retirements','identity_deleted_users'])assert.equal((await pool.query('SELECT count(*)::int AS count FROM '+source+' WHERE '+(source==='identity_tenant_retirements'?'resource_id':'user_id')+'=$1',[person.id])).rows[0].count,1);
 const evidence=await events(person.id);assert.equal(evidence[0].details.afterSha256,null);assert.equal(evidence[0].details.afterRevision,null);assert.equal((await pool.query("SELECT identity_tenant_id('user',$1) AS owner",[person.id])).rows[0].owner,fixture.tenant);
});
for(const action of['update','delete','invalidate'])test('role withdrawal after '+action+' checkpoints rolls back even a legitimate self-reduction',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);const changed=wrapped(client=>client.query('UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1',[fixture.userId]));fixture.mutator=new UserMutator(changed,{issuer,revalidate:fixture.revalidate});
 await assert.rejects(action==='update'?fixture.mutator.update(person.id,{enabled:false},userEtag(person),fixture.user,'Bearer original'):call(fixture,action,person),error=>['42501','23514'].includes(error.code));assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('physical role expiry is detected by the deferred raw role snapshot without any SQL withdrawal',async()=>{
 const fixture=await actor('admin',undefined,2);const person=await load(fixture.userId);fixture.mutator=new UserMutator(wrapped(client=>client.query('SELECT pg_sleep(2.1)')),{issuer,revalidate:fixture.revalidate});
 await assert.rejects(call(fixture,'invalidate',person),error=>error.code==='42501');assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('physical token expiry at deferred commit cannot preserve a positive last checkpoint',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);fixture.user.exp=Math.floor(Date.now()/1000)+2;fixture.mutator=new UserMutator(wrapped(client=>client.query('SELECT pg_sleep(2.1)')),{issuer,revalidate:fixture.revalidate});
 await assert.rejects(call(fixture,'invalidate',person),error=>error.code==='42501');assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('a second DML transition cannot drift user content after its exact original-token checkpoint',async()=>{
 const fixture=await actor();const person=await target(fixture);fixture.mutator=new UserMutator(wrapped(client=>client.query('UPDATE users SET title=$2 WHERE id=$1',[person.id,'Unconfirmed extra edit'])),{issuer,revalidate:fixture.revalidate});
 await assert.rejects(call(fixture,'update',person),error=>error.code==='23514');assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('clearing the receiving scope before deferred commit cannot turn off admission',async()=>{
 const fixture=await actor();const person=await target(fixture);fixture.mutator=new UserMutator(wrapped(client=>client.query("SELECT set_config('opendirectory.user_mutation','',true)")),{issuer,revalidate:fixture.revalidate});
 await assert.rejects(call(fixture,'update',person),error=>error.code==='42501');assert.deepEqual(await load(person.id),person);
});
test('a missing receiving trigger or mandatory outbox cannot fabricate a successful owned update',async()=>{
 const fixture=await actor();const person=await target(fixture);await pool.query('ALTER TABLE users DISABLE TRIGGER identity_directory_user_mutation_record');
 try{await assert.rejects(call(fixture,'update',person),error=>error.status===503);}finally{await pool.query('ALTER TABLE users ENABLE TRIGGER identity_directory_user_mutation_record');}assert.deepEqual(await load(person.id),person);
 await pool.query('ALTER TABLE identity_directory_user_outbox RENAME TO withheld_user_outbox');try{await assert.rejects(call(fixture,'update',person));}finally{await pool.query('ALTER TABLE withheld_user_outbox RENAME TO identity_directory_user_outbox');}assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('actor and target locks use the same UUID order so two same-tenant operators can edit each other without deadlock',async()=>{
 const first=await actor();const second=await actor('admin',first.tenant);const firstPerson=await load(first.userId);const secondPerson=await load(second.userId);const result=await Promise.all([call(first,'update',secondPerson),call(second,'update',firstPerson)]);assert.equal(result.length,2);assert.equal((await events(first.userId)).length,1);assert.equal((await events(second.userId)).length,1);
});
test('original-token withdrawal during an observed target lock wait is checked after the lock resolves',async()=>{
 const fixture=await actor();const person=await target(fixture);fixture.live.checks=0;const blocker=await pool.connect();let pending;
 try{await blocker.query('BEGIN');await blocker.query('SELECT id FROM users WHERE id=$1 FOR UPDATE',[person.id]);pending=call(fixture,'update',person);pending.catch(()=>{});let waiting=false;
  for(let attempt=0;attempt<200;attempt++){waiting=(await pool.query("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE 'SELECT id FROM users WHERE id=ANY(%ORDER BY id FOR UPDATE') AS waiting")).rows[0].waiting;if(waiting)break;await new Promise(resolve=>setTimeout(resolve,5));}assert.equal(waiting,true);fixture.live.revoked=true;await blocker.query('COMMIT');await assert.rejects(pending,error=>error.status===401);assert.deepEqual(await load(person.id),person);
 }finally{await blocker.query('ROLLBACK');blocker.release();if(pending)await pending.catch(()=>{});}
});
test('revision values above JavaScript safe integer precision are captured and compared losslessly',async()=>{
 const fixture=await actor();const person=await target(fixture);await pool.query("SELECT setval('identity_user_record_revision_seq',9007199254740993)");await pool.query('UPDATE users SET title=title WHERE id=$1',[person.id]);const current=await load(person.id);assert.ok(BigInt(current.revision)>9007199254740991n);const changed=await call(fixture,'update',current);assert.ok(BigInt(changed.revision)>BigInt(current.revision));assert.equal((await events(person.id))[0].details.beforeRevision,current.revision);
});
test('replaying migration preserves mutation receipts, resource versions and ownership',async()=>{
 const fixture=await actor();const person=await target(fixture);await call(fixture,'update',person);const before=await load(person.id);const evidence=await events(person.id);await pool.query(fs.readFileSync(path.join(migrations,'027_directory_user_mutations.sql'),'utf8'));assert.deepEqual(await load(person.id),before);assert.deepEqual(await events(person.id),evidence);await call(fixture,'invalidate',before);
});
async function captureProof(fixture,person){
 let proof;const capture={...database,transaction:(callback,options)=>database.transaction(client=>callback({query:async(sql,values)=>{if(sql.startsWith("SELECT set_config('opendirectory.user_mutation'")){proof=JSON.parse(values[0]);throw new Error('Explicit user mutation proof capture');}return client.query(sql,values);}}),options)};
 await assert.rejects(new UserMutator(capture,{issuer,revalidate:fixture.revalidate}).update(person.id,{title:'Captured exact intent'},userEtag(person),fixture.user,'Bearer original'),/Explicit user mutation proof capture/);return proof;
}
test('a complete captured proof cannot mutate another target or substitute different intent at the actual SQL receiver',async()=>{
 const fixture=await actor();const person=await target(fixture);const other=await target(fixture);const proof=await captureProof(fixture,person);
 for(const[identity,title]of[[other.id,'Captured exact intent'],[person.id,'Unrequested replacement']])await assert.rejects(database.transaction(async client=>{await client.query("SELECT set_config('opendirectory.user_mutation',$1,true)",[JSON.stringify(proof)]);await client.query('UPDATE users SET title=$2 WHERE id=$1',[identity,title]);},{actor:fixture.user.sub}),error=>error.code==='23514');
 assert.deepEqual(await load(person.id),person);assert.deepEqual(await load(other.id),other);assert.equal((await events(person.id)).length,0);
});
test('a limited actual SQL login or assumed role cannot launder a complete proof through security-definer user mutation guards',async()=>{
 const fixture=await actor();const person=await target(fixture);const proof=await captureProof(fixture,person);const role='mutation_limited_'+randomUUID().replaceAll('-','');const password='owned-'+randomUUID();let limited;
 await administration.query(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '${password}'`);
 try{
  await pool.query(`GRANT USAGE ON SCHEMA ${schema} TO ${role};GRANT SELECT,UPDATE ON users TO ${role};GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO ${role}`);const address=new URL(process.env.IDENTITY_TEST_DATABASE_URL);address.username=role;address.password=password;limited=new Pool({connectionString:address.toString(),max:1,options:`-c search_path=${schema},public`});
  for(const assumed of[false,true]){const client=await(assumed?pool:limited).connect();try{await client.query('BEGIN');if(assumed)await client.query('SET LOCAL ROLE '+role);await client.query("SELECT set_config('opendirectory.user_mutation',$1,true)",[JSON.stringify(proof)]);
   await assert.rejects(client.query('UPDATE users SET title=$2 WHERE id=$1',[person.id,'Captured exact intent']),error=>error.code==='42501'&&error.message==='Actual database owner required for original-actor user mutation');
  }finally{await client.query('ROLLBACK');client.release();}}
  assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
 }finally{await limited?.end();await pool.query('DROP OWNED BY '+role);await administration.query('DROP ROLE '+role);}
});
test('late receiving triggers cannot silently change immutable user metadata behind the initial whitelist',async()=>{
 const fixture=await actor();const person=await target(fixture);await pool.query("CREATE FUNCTION mutate_unrequested_user_metadata() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.created_at=clock_timestamp();RETURN NEW;END;$$;CREATE TRIGGER aab_mutate_unrequested_user_metadata BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION mutate_unrequested_user_metadata()");
 try{await assert.rejects(call(fixture,'update',person),error=>error.code==='23514');}finally{await pool.query('DROP TRIGGER aab_mutate_unrequested_user_metadata ON users;DROP FUNCTION mutate_unrequested_user_metadata()');}assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
});
test('missing core record, authorization or eligibility evidence cannot be masked by a user-mutation receipt',async()=>{
 const fixture=await actor();const person=await target(fixture);
 for(const trigger of['identity_user_record_changed','identity_authorization_user_record','identity_user_eligibility_record']){
  await pool.query('ALTER TABLE users DISABLE TRIGGER '+trigger);try{await assert.rejects(fixture.mutator.update(person.id,{enabled:true},userEtag(person),fixture.user,'Bearer original'),error=>error.code==='23514');}finally{await pool.query('ALTER TABLE users ENABLE TRIGGER '+trigger);}assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
 }
});
test('held-role MFA age is a physical commit deadline rather than only a pre-DML boolean',async()=>{
 const fixture=await actor();const person=await load(fixture.userId);const original=(await pool.query("SELECT * FROM identity_role_authentication WHERE role='admin'")).rows[0];
 const configure=(required,age)=>database.transaction(async client=>{await client.query("SELECT set_config('opendirectory.authentication_reason','Explicit owned role assurance deadline fixture',true)");await client.query("UPDATE identity_role_authentication SET mfa_required=$1,max_age_seconds=$2,version=version+1 WHERE role='admin'",[required,age]);},{actor:fixture.user.sub});
 try{await configure(true,300);fixture.user.identity_authorization=(await new AuthorizationState(database).state(issuer,fixture.user.sub)).context;fixture.user.auth_time=Math.floor(Date.now()/1000)-298;fixture.user.amr=['pwd','otp'];fixture.user.mfa_authorization={schemaVersion:1,userId:fixture.userId,revision:'1',methods:fixture.user.amr,authTime:fixture.user.auth_time};
  fixture.mutator=new UserMutator(wrapped(client=>client.query('SELECT pg_sleep(2.1)')),{issuer,revalidate:fixture.revalidate});await assert.rejects(call(fixture,'invalidate',person),error=>error.code==='42501');assert.deepEqual(await load(person.id),person);assert.equal((await events(person.id)).length,0);
 }finally{await configure(original.mfa_required,original.max_age_seconds);}
});
