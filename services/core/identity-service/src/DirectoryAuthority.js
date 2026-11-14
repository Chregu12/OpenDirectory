'use strict';

const { getIdentityPermissions } = require('./middleware/identityAccess');
const { companyDirectoryPermissions, companyOwner, COMPANY_DIRECTORY_PERMISSIONS } = require('./CompanyOwner');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');

function mayUseDirectory(user, required) {
  const held = getIdentityPermissions(user);
  const missing = required.filter(permission => !held.includes(permission));
  return !missing.length || missing.every(permission => COMPANY_DIRECTORY_PERMISSIONS.includes(permission))
    && acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user);
}

async function requireDirectoryPermissions(client, user, required, resource = null) {
  const held = getIdentityPermissions(user);
  const missing = required.filter(permission => !held.includes(permission));
  if (!missing.length) return undefined;
  if (missing.every(permission => COMPANY_DIRECTORY_PERMISSIONS.includes(permission))) {
    if (await companyOwner(client, user) && acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)) { await require('./AuthorityTenant').requireOuReceiver(client); return undefined; }
    if (!await require('./CompanyRoleAuthority').configured(client)) throw Object.assign(new Error('Canonical directory permission required'), { status: 403 });
    const captured = await require('./CompanyRoleAuthority').capture(client, user, missing, resource);
    return captured;
  }
  throw Object.assign(new Error('Canonical directory permission required'), { status: 403 });
}

module.exports = { mayUseDirectory, requireDirectoryPermissions };
