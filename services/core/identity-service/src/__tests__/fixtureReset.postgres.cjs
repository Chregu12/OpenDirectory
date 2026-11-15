'use strict';
const {test,after}=require('node:test');const assert=require('node:assert/strict');const {randomUUID}=require('node:crypto');
const fs=require('node:fs'),path=require('node:path');const {Pool}=require('pg');
const {resetDirectoryFixture}=require('../../../../../scripts/lib/reset-directory-fixture.cjs');
const {activeCompany}=require('../../../../../scripts/lib/company-owner-fixture.cjs');
const {CompanyRoles}=require('../CompanyRoles');
assert.ok(process.env.IDENTITY_TEST_DATABASE_URL);const admin=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:1});after(()=>admin.end());
async function fixture(prefix,full,operation){
 const schema=prefix+'_'+randomUUID().replaceAll('-','');await admin.query('CREATE SCHEMA '+schema);
 const pool=new Pool({connectionString:process.env.IDENTITY_TEST_DATABASE_URL,max:2,options:`-c search_path=${schema},public`});
 const db={getClient:()=>pool.connect(),isAvailable:()=>true,query:(...args)=>pool.query(...args),transaction:async(callback,settings={})=>{const client=await pool.connect();try{await client.query('BEGIN');if(settings.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[settings.actor]);const value=await callback(client);await client.query('COMMIT');return value;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 try{
  if(full)for(const file of fs.readdirSync(path.join(__dirname,'../../migrations')).filter(file=>file.endsWith('.sql')).sort())await pool.query(fs.readFileSync(path.join(__dirname,'../../migrations',file),'utf8'));
  else await pool.query('CREATE TABLE users(id integer)');
  return await operation(pool,db,schema);
 }finally{await pool.end();await admin.query('DROP SCHEMA '+schema+' CASCADE');}
}
test('legacy reset can clear ordinary fixture users only while new role storage is empty and all guards are restored',async()=>fixture('group_mutations',true,async pool=>{
 await pool.query("INSERT INTO users(id,username,email) VALUES($1,'reset-fixture-user','reset@test.invalid')",[randomUUID()]);
 await resetDirectoryFixture(pool,'TRUNCATE users CASCADE');assert.equal((await pool.query('SELECT count(*) AS count FROM users')).rows[0].count,'0');
 await assert.rejects(resetDirectoryFixture(pool,'TRUNCATE missing_fixture_table CASCADE'),{code:'42P01'});
 await pool.query('SELECT identity_company_role_receiving()');await assert.rejects(pool.query('TRUNCATE identity_company_role_events CASCADE'),{code:'42501'});
}));
test('nonempty actual role history prevents fixture reset and remains protected after rollback',async()=>fixture('group_mutations',true,async(pool,db,schema)=>{
 const owner=await activeCompany(db,schema,'https://fixture-reset.native');const roles=new CompanyRoles(db,{revalidate:async()=>{}});
 await roles.create({name:'Retained native role',description:'Real owner decision',permissions:['users.read'],maxDurationSeconds:3600,reason:'Preserve original role history across any fixture reset',confirm:true},owner.user,'Bearer original-fixture');
 const before=(await pool.query('SELECT count(*) AS count FROM users')).rows[0].count;
 await assert.rejects(resetDirectoryFixture(pool,'TRUNCATE users CASCADE'),/Role history must stay isolated/);
 assert.equal((await pool.query('SELECT count(*) AS count FROM users')).rows[0].count,before);assert.equal((await pool.query('SELECT count(*) AS count FROM identity_company_role_events')).rows[0].count,'1');await pool.query('SELECT identity_company_role_receiving()');
 await assert.rejects(pool.query('TRUNCATE identity_company_role_events CASCADE'),{code:'42501'});
}));
test('unrecognized schemas and non-truncate commands are refused before fixture data changes',async()=>{
 await fixture('forbidden_reset',false,async pool=>{await pool.query('INSERT INTO users VALUES(1)');await assert.rejects(resetDirectoryFixture(pool,'TRUNCATE users CASCADE'),/disposable directory/);assert.equal((await pool.query('SELECT count(*) AS count FROM users')).rows[0].count,'1');});
 await fixture('mutations',false,async pool=>{await pool.query('INSERT INTO users VALUES(1)');await assert.rejects(resetDirectoryFixture(pool,'DELETE FROM users'),/explicit fixture truncate/);assert.equal((await pool.query('SELECT count(*) AS count FROM users')).rows[0].count,'1');});
});
test('pre-role historical fixture storage is supported without claiming installed role receivers',async()=>fixture('ou_mutations',false,async pool=>{
 await pool.query('INSERT INTO users VALUES(1)');await resetDirectoryFixture(pool,'TRUNCATE users CASCADE');assert.equal((await pool.query('SELECT count(*) AS count FROM users')).rows[0].count,'0');
}));
test('license group fixture resets the new empty reviewer FK cascade and restores every role truncate guard',async()=>fixture('identity_groups',true,async pool=>{
 await pool.query("INSERT INTO groups(id,name) VALUES($1,'Explicit empty role FK fixture')",[randomUUID()]);
 await resetDirectoryFixture(pool,'TRUNCATE groups CASCADE');assert.equal((await pool.query('SELECT count(*) AS count FROM groups')).rows[0].count,'0');await pool.query('SELECT identity_company_role_receiving()');
 await assert.rejects(pool.query('TRUNCATE identity_company_pim_policies CASCADE'),{code:'42501'});
}));
