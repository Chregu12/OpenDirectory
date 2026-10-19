'use strict';

const { validUuid } = require('../../../../packages/identity-authorization-contract');
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
async function authorityTenant(client, proof, { write = false } = {}) {
  let tenant;
  try { tenant = (await client.query('SELECT identity_authority_actor_home($1::jsonb) AS tenant_id', [JSON.stringify(proof)])).rows[0]?.tenant_id; }
  catch (error) { if (error.code === '42501') fail(401, 'authority_actor_changed'); throw error; }
  if (!validUuid(tenant) || tenant !== tenant.toLowerCase()) fail(503, 'authority_tenant_unavailable');
  if (write && !(await client.query('SELECT id FROM identity_tenants WHERE id=$1 AND enabled FOR SHARE', [tenant])).rows.length) fail(401, 'authority_actor_changed');
  return tenant;
}
async function lockAuthorityUsers(client, identifiers, tenant) {
  const selected = [...new Set(identifiers.filter(Boolean))].sort();
  const rows = (await client.query("SELECT id,enabled,authorization_revision FROM users WHERE id=ANY($1::uuid[]) AND identity_tenant_id('user',id)=$2 ORDER BY id FOR UPDATE", [selected, tenant])).rows;
  if (rows.length !== selected.length || rows.some(row => !selected.includes(row.id))) fail(404, 'authority_target_not_found');
  return rows;
}
async function requireAuthorityReceiver(client) {
  const required = ['identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_role_review_leases'];
  const rows = (await client.query(`SELECT relation.relname FROM pg_catalog.pg_class relation JOIN pg_catalog.pg_trigger guard ON guard.tgrelid=relation.oid
    WHERE relation.relnamespace=current_schema()::regnamespace AND relation.relname=ANY($1::text[]) AND guard.tgname='aaa_identity_authority_target_tenant'
    AND guard.tgenabled='O' AND guard.tgtype=31 AND guard.tgfoid='identity_authority_target_tenant_guard()'::regprocedure`, [required])).rows;
  if (rows.length !== required.length || new Set(rows.map(row => row.relname)).size !== required.length || rows.some(row => !required.includes(row.relname))) fail(503, 'authority_tenant_receiver_unavailable');
}
async function requireOuReceiver(client) {
  try { await client.query('SELECT identity_directory_ou_receiving()'); }
  catch (error) { throw Object.assign(new Error('Canonical OU receiver unavailable'), { status: 503, cause: error }); }
}
module.exports = { authorityTenant, lockAuthorityUsers, requireAuthorityReceiver, requireOuReceiver };
