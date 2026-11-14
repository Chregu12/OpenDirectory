'use strict';
const assert=require('node:assert/strict');
async function resetDirectoryFixture(pool,statement){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');const schema=(await client.query('SELECT current_schema() AS name')).rows[0].name;
  assert.match(schema,/^(group|ou)_mutations_[a-f0-9]{32}$/,'Only a disposable directory kernel fixture may reset storage');
  const tables=['identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox','identity_company_role_uses'];
  for(const table of tables)assert.equal((await client.query('SELECT count(*) AS count FROM '+table)).rows[0].count,'0','Role history must stay isolated in its own schema');
  // Only empty new tables participate in these old fixtures; production guards stay unconditional.
  for(const table of tables)await client.query('ALTER TABLE '+table+' DISABLE TRIGGER '+(table==='identity_company_role_uses'?'identity_company_role_usage_truncate':'identity_company_role_truncate'));
  await client.query(statement);
  for(const table of tables)await client.query('ALTER TABLE '+table+' ENABLE TRIGGER '+(table==='identity_company_role_uses'?'identity_company_role_usage_truncate':'identity_company_role_truncate'));
  await client.query('SELECT identity_company_role_receiving()');await client.query('COMMIT');
 }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
module.exports={resetDirectoryFixture};
