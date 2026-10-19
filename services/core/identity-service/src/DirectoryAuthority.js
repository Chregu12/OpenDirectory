'use strict';

const { getIdentityPermissions } = require('./middleware/identityAccess');
const { companyDirectoryPermissions, COMPANY_DIRECTORY_PERMISSIONS } = require('./CompanyOwner');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');

function mayUseDirectory(user, required) {
  const held = getIdentityPermissions(user);
  const missing = required.filter(permission => !held.includes(permission));
  return !missing.length || missing.every(permission => COMPANY_DIRECTORY_PERMISSIONS.includes(permission))
    && acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user);
}

async function requireDirectoryPermissions(client, user, required) {
  const held = getIdentityPermissions(user);
  const missing = required.filter(permission => !held.includes(permission));
  if (!missing.length) return;
  if (missing.every(permission => COMPANY_DIRECTORY_PERMISSIONS.includes(permission))) {
    const owned = await companyDirectoryPermissions(client, user);
    if (missing.every(permission => owned.includes(permission))) return;
  }
  throw Object.assign(new Error('Canonical directory permission required'), { status: 403 });
}

module.exports = { mayUseDirectory, requireDirectoryPermissions };
