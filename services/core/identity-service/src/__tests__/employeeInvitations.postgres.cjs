'use strict';
const {test,beforeEach,afterEach,after}=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const fs=require('node:fs');const path=require('node:path');const {Pool}=require('pg');
const {activeCompany}=require('../../../../../scripts/lib/company-owner-fixture.cjs');const {DirectoryCreator}=require('../DirectoryCreator');
const {EmployeeInvitationAuthority}=require('../EmployeeInvitationAuthority');const {AuthorizationState}=require('../AuthorizationState');
const admin=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});const issuer='https://employee-invitation.native';
let pool,schema,database,owner,authority,creator;
beforeEach(async()=>{
 schema='employee_'+randomUUID().replaceAll('-','');await admin.query('CREATE SCHEMA '+schema);
 pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,options:'-c search_path='+schema+',public -c timezone=UTC'});
 database={isAvailable:()=>true,query:(...args)=>pool.query(...args),getClient:()=>pool.connect(),transaction:async(operation,options={})=>{const client=await pool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const value=await operation(client);await client.query('COMMIT');return value;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 const directory=path.join(__dirname,'../../migrations');for(const file of fs.readdirSync(directory).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(directory,file),'utf8'));
 owner=await activeCompany(database,schema,issuer);const revalidate=async(_authorization,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant;
 authority=new EmployeeInvitationAuthority(database,{issuer,revalidate});creator=new DirectoryCreator(database,{issuer,revalidate});
});
afterEach(async()=>{await pool.end();await admin.query('DROP SCHEMA '+schema+' CASCADE');});after(()=>admin.end());
test('actual roleless ownership exposes only the original invitation authority and its own disabled unlinked recipient',async()=>{
 const employee=await creator.user({username:'employee',email:'employee@example.invalid'},owner.user,'Bearer original');
 const source=await authority.read(owner.user,'Bearer original',{userId:employee.id});assert.equal(source.actorUserId,owner.receipt.administratorId);assert.equal(source.target.id,employee.id);
 assert.equal(source.target.enabled,false);assert.equal(source.target.unlinked,true);assert.equal(source.target.ordinary,true);assert.equal(source.consoleClientId,'web-app');assert.deepEqual(owner.user.roles,[]);
 assert.equal(Object.hasOwn(source.target,'password'),false);assert.equal(Object.hasOwn(source.target,'password_hash'),false);
 assert.equal((await authority.read(owner.user,'Bearer original',{userId:null})).target,null);
});
test('a second real company cannot select another company employee or substitute global roles for ownership',async()=>{
 const employee=await creator.user({username:'employee',email:'employee@example.invalid'},owner.user,'Bearer original');const foreign=await activeCompany(database,schema,issuer);
 await assert.rejects(authority.read(foreign.user,'Bearer foreign',{userId:employee.id}),{status:404});
 const ordinary=await creator.user({username:'unbound',email:'unbound@example.invalid'},owner.user,'Bearer original');
 await assert.rejects(authority.read({...owner.user,sub:'unbound',roles:['admin'],identity_authorization:{...owner.user.identity_authorization,userId:ordinary.id}},'Bearer fabricated',{userId:null}));
});
test('invitation management requires original independently proven recent MFA even for listing',async()=>{
 owner.user.auth_time-=301;owner.user.mfa_authorization.authTime-=301;await assert.rejects(authority.read(owner.user,'Bearer original',{userId:null}),{status:428});
});
test('own-company ownership is not itself an invitation target',async()=>{
 const source=await authority.read(owner.user,'Bearer original',{userId:owner.receipt.administratorId});assert.equal(source.target.enabled,true);assert.equal(source.target.unlinked,false);assert.equal(source.target.ordinary,false);
});
