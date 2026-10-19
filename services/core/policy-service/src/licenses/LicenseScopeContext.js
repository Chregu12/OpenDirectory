'use strict';

const { AsyncLocalStorage } = require('async_hooks');
const scopeContext = new AsyncLocalStorage();
const { LicenseError } = require('./LicenseError');
function requireScopedOperation(licenseId, permissions) {
  const scope = scopeContext.getStore();
  if (scope && (scope.licenseId !== licenseId || !permissions.includes(scope.permission))) throw new LicenseError(403, 'License operation exceeds the captured resource scope');
}
function scopedPermission(user, principal, licenseId, permission) {
  const scope = scopeContext.getStore();
  return !!scope && scope.licenseId === licenseId && scope.permission === permission && scope.userId === principal?.userId
    && scope.user.iss === user?.iss && scope.user.sub === user?.sub;
}
module.exports = { scopeContext, scopedPermission, requireScopedOperation };
