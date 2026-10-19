'use strict';

const { validContext } = require('../../../../packages/identity-authorization-contract');
const { authorityTenant, requireOuReceiver } = require('./AuthorityTenant');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const COMPANY_DIRECTORY_PERMISSIONS = Object.freeze([
  'users.read', 'users.create', 'users.update', 'users.status.manage',
  'groups.read', 'groups.create', 'groups.update', 'groups.delete', 'groups.members.manage',
  'ous.read', 'ous.create', 'ous.update', 'ous.delete', 'ous.members.manage',
]);
async function ownerState(client, userId) {
  const row = (await client.query('SELECT owner.*,identity_company_activation_valid(owner.registration_id) AS valid,identity_company_owner_active(owner) AS active FROM identity_company_activations owner WHERE user_id=$1', [userId])).rows[0];
  if (row) await client.query('SELECT identity_company_activation_receiving()');
  if (row && !row.valid) throw Object.assign(new Error('company_owner_evidence_unavailable'), { status: 503 }); return row || null;
}
async function companyOwner(client, user) {
  if (user?.actor_type !== 'user' || !validContext(user.identity_authorization)) return null;
  const home = await authorityTenant(client, { ...user.identity_authorization, issuer: user.iss, subject: user.sub });
  const owner = await ownerState(client, user.identity_authorization.userId);
  return owner?.active && owner.tenant_id === home && owner.issuer === user.iss && owner.subject === user.sub ? owner : null;
}
async function companyDirectoryPermissions(client, user) {
  if (!acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) return [];
  if (!await companyOwner(client, user)) return [];
  await requireOuReceiver(client); return [...COMPANY_DIRECTORY_PERMISSIONS];
}
module.exports = { companyOwner, ownerState, companyDirectoryPermissions, COMPANY_DIRECTORY_PERMISSIONS };
