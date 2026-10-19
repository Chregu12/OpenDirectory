'use strict';

const { AsyncLocalStorage } = require('async_hooks');
const { LicenseError } = require('./LicenseError');
const principalContext = new AsyncLocalStorage();
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

function requirePrincipal(principal, userId) {
  if (!principal || typeof principal.issuer !== 'string' || !principal.issuer.trim() || typeof principal.subject !== 'string' || !principal.subject.trim()
    || principal.subject.length > 255 || typeof principal.userId !== 'string' || !UUID.test(principal.userId) || principal.enabled !== true || (userId !== undefined && principal.userId !== userId)) {
    throw new LicenseError(403, 'A linked, enabled canonical license identity is required');
  }
  return principal;
}

function validateRequestIdentity(request) {
  if (request.identity_bound !== true || !UUID.test(request.requester_id) || !request.requester_issuer || !request.requester_subject
    || (request.assignee_type === 'user' && !UUID.test(request.assignee_id))) throw new LicenseError(409, 'Legacy request identity is unresolved; recreate it with canonical identities');
}

module.exports = { principalContext, requirePrincipal, validateRequestIdentity, UUID };
