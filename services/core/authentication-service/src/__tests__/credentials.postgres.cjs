'use strict';
const {test,beforeEach,afterEach,after}=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');
const {Pool}=require('pg');
const PostgresUserRepository=require('../infrastructure/repositories/PostgresUserRepository');
const UserService=require('../services/userService');const AuthApplicationService=require('../application/AuthApplicationService');
const AuthenticationManager=require('../services/authenticationManager');const UserAggregate=require('../domain/aggregates/UserAggregate');
const {runMigrations}=require('../runMigrations');const {localAuthentication}=require('../localAuthentication');
const pool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL});
const migrationDirectory=path.join(__dirname,'../../migrations');
let connection,schema,scopedPool;
beforeEach(async()=>{assert.ok(process.env.AUTH_TEST_DATABASE_URL,'Disposable AUTH_TEST_DATABASE_URL required');schema='auth_'+randomUUID().replaceAll('-','');await pool.query('CREATE SCHEMA '+schema);scopedPool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,options:'-c search_path='+schema+',pg_catalog'});connection=await scopedPool.connect();});
afterEach(async()=>{await connection.query('ROLLBACK');connection.release();await scopedPool.end();await pool.query('DROP SCHEMA '+schema+' CASCADE');});
after(()=>pool.end());
async function migrate(){await runMigrations(scopedPool);}
const log={info(){},warn(){},error(){}};const password='Actual-disposable-password-321!';
async function account(){await migrate();const repo=new PostgresUserRepository(scopedPool);const users=new UserService({userRepository:repo,logger:log});const user=await users.createUser({username:'actual-employee',email:'employee@example.test',password});return{repo,users,user};}
const application=repo=>new AuthApplicationService({userRepository:repo,config:{jwtSecret:'actual-disposable-native-test-signing-key'},logger:log});
test('all shipped authentication migrations apply to a fresh actual PostgreSQL schema',async()=>{await migrate();});
test('a real existing credential suspension remains locked when read through the production repository',async()=>{
 await connection.query(fs.readFileSync(path.join(migrationDirectory,'005_users.sql'),'utf8'));
 const id=randomUUID();await connection.query("INSERT INTO users(id,username,password_hash,is_locked) VALUES($1,'original-suspended','retained-hash',true)",[id]);
 const user=await new PostgresUserRepository(connection).findById(id);assert.equal(user.isLocked(),true);
});
test('a real new password account is stored once and authenticates through a fresh repository instance',async()=>{
 const{repo,user}=await account();assert.equal(user.password_hash,undefined);assert.equal(user.passwordHash,undefined);
 const before=(await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0];assert.match(before.password_hash,/^\$2/);assert.notEqual(before.password_hash,password);
 const result=await application(new PostgresUserRepository(scopedPool)).login({username:user.username,password});assert.equal(result.user.id,user.id);assert.equal(result.user.passwordHash,undefined);
 assert.equal((await repo.findById(user.id)).recordRevision,'2');
});
test('failed password attempts and the resulting lock survive new application instances',async()=>{
 const{repo,user}=await account();
 for(let attempt=0;attempt<5;attempt++)await assert.rejects(application(new PostgresUserRepository(scopedPool)).login({username:user.username,password:'incorrect'}),error=>error.status===401);
 const locked=await repo.findById(user.id);assert.equal(locked.loginAttempts,5);assert.equal(locked.isLocked(),true);
 await assert.rejects(application(new PostgresUserRepository(scopedPool)).login({username:user.username,password}),error=>error.status===403);
});
test('a real persisted scrypt password replacement works through both production verifiers without restoring the old bcrypt secret',async()=>{
 const{repo,user,users}=await account();const Password=require('../domain/value-objects/Password');const replacement='Actual-scrypt-replacement-987!';
 const credential=await repo.findById(user.id);credential.changePassword((await Password.fromPlaintext(replacement)).hash);await repo.save(credential);
 await assert.rejects(application(new PostgresUserRepository(scopedPool)).login({username:user.username,password}),error=>error.status===401);
 assert.equal((await application(new PostgresUserRepository(scopedPool)).login({username:user.username,password:replacement})).user.id,user.id);
 assert.equal((await new AuthenticationManager({userRepository:new PostgresUserRepository(scopedPool),logger:log}).authenticateLocal(user.username,replacement)).id,user.id);
 assert.equal(await users.verifyCurrentPassword(user.id,replacement),true);assert.equal(await users.verifyCurrentPassword(user.id,password),false);
});
test('existing canonical permanent and timed suspensions deny actual password authentication',async()=>{
 const{repo,user,users}=await account();const auth=new AuthenticationManager({userRepository:repo,logger:log});
 for(const deadline of [null,new Date(Date.now()+60000)]){await users.lockUser(user.id,'Actual retained suspension',deadline?60000:null);assert.equal(await auth.authenticateLocal(user.username,password),null);}
 await users.unlockUser(user.id);assert.equal((await auth.authenticateLocal(user.username,password)).id,user.id);
});
test('a stale successful login cannot erase a later real password change or account suspension',async()=>{
 const{repo,user,users}=await account();const stale=await repo.findById(user.id);stale.recordLoginSuccess();
 await users.changePassword(user.id,'Actual-replacement-password-987!');const replaced=(await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0];
 await assert.rejects(repo.save(stale),error=>error.status===409);assert.deepEqual((await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0],replaced);
 const suspended=await repo.findById(user.id);suspended.recordLoginSuccess();await users.lockUser(user.id,'Actual later suspension');
 await assert.rejects(repo.save(suspended),error=>error.status===409);assert.equal((await repo.findById(user.id)).isLocked(),true);
});
test('two actual concurrent credential writers cannot overwrite the winning original revision',async()=>{
 const{repo,user}=await account();const first=await repo.findById(user.id);const second=await repo.findById(user.id);first.assignRole('first-native-role');second.assignRole('second-native-role');
 const results=await Promise.allSettled([repo.save(first),repo.save(second)]);assert.equal(results.filter(result=>result.status==='fulfilled').length,1);assert.equal(results.find(result=>result.status==='rejected').reason.status,409);
 assert.equal((await repo.findById(user.id)).roles.length,2);
});
test('a self password change cannot reuse an older password confirmation after another real change',async()=>{
 const{users,user}=await account();assert.equal(await users.verifyCurrentPassword(user.id,password),true);
 await users.changePassword(user.id,'Actual-newer-password-432!');const before=(await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0];
 await assert.rejects(users.changePassword(user.id,'Must-not-become-current-888!',password),error=>error.status===401);
 assert.deepEqual((await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0],before);
});
test('an unknown in-memory account cannot replace a missing or unavailable repository credential',async()=>{
 const{repo,user}=await account();const auth=new AuthenticationManager({userRepository:repo,logger:log});const stored=(await connection.query('SELECT * FROM users WHERE id=$1',[user.id])).rows[0];
 auth._users.set('memory-shadow',{...stored,username:'memory-shadow'});assert.equal(await auth.authenticateLocal('memory-shadow',password),null);
 auth._users.set(user.username,stored);await connection.query('ALTER TABLE users RENAME TO unavailable_credentials');
 await assert.rejects(auth.authenticateLocal(user.username,password),error=>error.status===503);
});
test('credential lookup, password confirmation and listing do not fall back to cached identities on SQL failure',async()=>{
 const{users,user}=await account();users._users.set(user.id,{id:user.id,username:user.username,password_hash:'cached'});await connection.query('ALTER TABLE users RENAME TO unavailable_credentials');
 for(const read of [()=>users.getUserById(user.id),()=>users.getUserByUsername(user.username),()=>users.getUserByEmail(user.email),()=>users.listUsers(),()=>users.verifyCurrentPassword(user.id,password)])await assert.rejects(read(),error=>error.status===503);
});
test('the real local strategy does not turn SQL loss or revision conflicts into a legacy login',async()=>{
 const{repo,user}=await account();let legacyCalls=0;const services={authAppService:application(repo),authManager:{authenticateLocal(){legacyCalls++;return user;}},zeroTrust:{evaluateTrust:async()=>100},auditService:{logFailedAuth:async()=>{}}};
 await connection.query('ALTER TABLE users RENAME TO unavailable_credentials');
 const result=await new Promise(resolve=>localAuthentication(services)({ip:'127.0.0.1',headers:{}},user.username,password,(error,value)=>resolve({error,value})));
 assert.equal(result.error.status,503);assert.equal(result.value,undefined);assert.equal(legacyCalls,0);
 services.authAppService={login:async()=>{throw Object.assign(new Error('Actual conflict'),{status:409});}};
 const conflict=await new Promise(resolve=>localAuthentication(services)({ip:'127.0.0.1',headers:{}},user.username,password,(error,value)=>resolve({error,value})));
 assert.equal(conflict.error.status,409);assert.equal(legacyCalls,0);
});
test('migration replay preserves existing credentials, suspension and original password history timestamps',async()=>{
 await connection.query(fs.readFileSync(path.join(migrationDirectory,'002_password_history.sql'),'utf8'));
 await connection.query("INSERT INTO password_history(user_id,password_hash,created_at) VALUES('original-employee','retained-historical-hash','2007-01-02T03:04:05Z')");
 await migrate();assert.equal((await connection.query('SELECT changed_at FROM password_history')).rows[0].changed_at.toISOString(),'2007-01-02T03:04:05.000Z');
 const repo=new PostgresUserRepository(scopedPool);const original=UserAggregate.create({id:randomUUID(),username:'retained',passwordHash:'retained-hash',locked:true});await repo.save(original);
 const before=(await connection.query('SELECT * FROM users')).rows;const history=(await connection.query('SELECT * FROM password_history')).rows;await migrate();
 assert.deepEqual((await connection.query('SELECT * FROM users')).rows,before);assert.deepEqual((await connection.query('SELECT * FROM password_history')).rows,history);
});
test('a migration error rolls the actual partial schema back instead of reporting readiness',async()=>{
 const os=require('node:os');const directory=fs.mkdtempSync(path.join(os.tmpdir(),'auth-migration-'));
 try{fs.writeFileSync(path.join(directory,'001.sql'),'CREATE TABLE must_roll_back(id INTEGER)');fs.writeFileSync(path.join(directory,'002.sql'),'SELECT missing_original_authentication_function()');
  await assert.rejects(runMigrations(scopedPool,directory),error=>error.code==='42883');assert.equal((await connection.query("SELECT to_regclass('must_roll_back') AS relation")).rows[0].relation,null);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
test('the actual production service cold-starts and authenticates through the OAuth password adapter after a real restart', {timeout:45000},async()=>{
 const{user,users}=await account();const {startAuthenticationService}=require('./fixtures/server.cjs');const {authenticateUser}=require('../../../oauth-provider/src/authenticateUser');
 const databaseUrl=new URL(process.env.AUTH_TEST_DATABASE_URL);databaseUrl.searchParams.set('options','-c search_path='+schema+',pg_catalog');
 const previous=process.env.AUTH_SERVICE_URL;let server;
 try{
  for(let boot=0;boot<2;boot++){
   server=await startAuthenticationService(databaseUrl.href,boot===0);process.env.AUTH_SERVICE_URL=server.url;
   const authenticated=await authenticateUser({username:user.username,password});assert.equal(authenticated.error,undefined,authenticated.error);assert.equal(authenticated.user.id,user.id);
   assert.equal(Object.hasOwn(authenticated.user,'passwordHash'),false);assert.equal(Object.hasOwn(authenticated.user,'password_hash'),false);
   assert.ok((await server.redis.keys('auth:session:*')).length>0,'Actual REDIS_URL stores the returned provider session');
   const evidence=(await connection.query("SELECT * FROM audit_events WHERE event_type='auth_success' AND user_id=$1",[user.id])).rows;assert.equal(evidence.length,boot+1);assert.ok(evidence.every(event=>event.message==='auth_success'&&event.id>0));
   for(const target of ['/.well-known/openid-configuration','/authorize','/token','/jwks','/interaction/old-login']){
    const retired=await fetch(server.url+target,{method:target==='/token'?'POST':'GET'});assert.equal(retired.status,410,target);assert.equal((await retired.json()).error,'legacy_oidc_retired');
   }
   if(boot===0){await server.stop();server=null;}
  }
  await connection.query('ALTER TABLE audit_events RENAME TO unavailable_audit');const missingAudit=await authenticateUser({username:user.username,password});assert.equal(missingAudit.status,503);assert.equal(missingAudit.user,undefined);await connection.query('ALTER TABLE unavailable_audit RENAME TO audit_events');
  await users.lockUser(user.id,'Actual provider suspension after the last login');const denied=await authenticateUser({username:user.username,password});assert.equal(denied.status,401);assert.equal(denied.user,undefined);
  await connection.query('ALTER TABLE users RENAME TO unavailable_credentials');
  const unavailable=await authenticateUser({username:user.username,password});assert.equal(unavailable.status,503);assert.equal(unavailable.user,undefined);
  assert.equal((await fetch(server.url+'/health')).status,503);
 }finally{if(server)await server.stop();if(previous===undefined)delete process.env.AUTH_SERVICE_URL;else process.env.AUTH_SERVICE_URL=previous;}
});
test('the actual service exits without listening when its real migration cannot apply', {timeout:20000},async()=>{
 await connection.query('CREATE TABLE password_history(incompatible_column INTEGER)');const {startAuthenticationService}=require('./fixtures/server.cjs');
 const databaseUrl=new URL(process.env.AUTH_TEST_DATABASE_URL);databaseUrl.searchParams.set('options','-c search_path='+schema+',pg_catalog');
 await assert.rejects(startAuthenticationService(databaseUrl.href),error=>error.message.includes('exited before readiness')&&error.message.includes('Authentication database initialization failed'));
 assert.equal((await connection.query("SELECT to_regclass('audit_events') AS relation")).rows[0].relation,null,'Earlier successful migration effects actually rolled back');
});
