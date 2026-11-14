'use strict';
const assert=require('node:assert/strict');
async function resetDirectoryFixture(pool,statement){
 const client=await pool.connect();
 try{
  await client.query('BEGIN');const schema=(await client.query('SELECT current_schema() AS name')).rows[0].name;
  assert.match(schema,/^(group_mutations|ou_mutations|offboarding_groups|authority_candidates|authority_checkpoints|authority_targets|company_offboarding|company_registration|creations|group_reviews|license_users|mutations|organization|ou_memberships|owned_policies|identity_test|source_consent_tenant|tenants)_[a-f0-9]{32}$/,'Only a disposable directory kernel fixture may reset storage');
  assert.match(statement,/^TRUNCATE [a-z_, ]+ CASCADE$/,'Only an explicit fixture truncate may be executed');
  const configured=(await client.query("SELECT to_regclass('identity_company_roles') IS NOT NULL AS present")).rows[0].present;
  const tables=['identity_company_pim_policies','identity_company_pim_requests','identity_company_role_eligibilities','identity_company_role_activations','identity_company_roles','identity_company_role_grants','identity_company_role_groups','identity_company_role_ous','identity_company_role_events','identity_company_role_outbox','identity_company_role_uses'];
  if(configured)for(const table of tables)assert.equal((await client.query('SELECT count(*) AS count FROM '+table)).rows[0].count,'0','Role history must stay isolated in its own schema');
  // Only empty new tables participate in these old fixtures; production guards stay unconditional.
  if(configured)for(const table of tables)await client.query('ALTER TABLE '+table+' DISABLE TRIGGER '+(table==='identity_company_role_uses'?'identity_company_role_usage_truncate':'identity_company_role_truncate'));
  await client.query(statement);
  if(configured){for(const table of tables)await client.query('ALTER TABLE '+table+' ENABLE TRIGGER '+(table==='identity_company_role_uses'?'identity_company_role_usage_truncate':'identity_company_role_truncate'));
  await client.query('SELECT identity_company_role_receiving()');}await client.query('COMMIT');
 }catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}
}
module.exports={resetDirectoryFixture};
