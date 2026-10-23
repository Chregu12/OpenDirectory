'use strict';
const { exact, identifier, text } = require('./company-license-contract');
const { validRevision } = require('./identity-authorization-contract');
const {validTenantContext}=require('./tenant-authorization-contract');
const SCOPE = 'company.automation';
const LICENSE_ACTION = 'licenses.groups.reconcile';
const GROUP_ACTION = 'directory.groups.reconcile';
const reconciliation = action => [LICENSE_ACTION, GROUP_ACTION].includes(action);
const ACTIONS = Object.freeze(['directory.users.export', 'directory.groups.export', 'directory.ous.export', LICENSE_ACTION, GROUP_ACTION]);
const CLIENT_ID = /^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/;
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function actions(value) {
  if (!Array.isArray(value) || !value.length || value.length > ACTIONS.length || new Set(value).size !== value.length || value.some(action => !ACTIONS.includes(action))) fail(400, 'Explicit supported automation actions required');
  return [...value].sort();
}
function workload(user, issuer, now = Date.now()) {
  if (user?.actor_type !== 'application' || user.token_use !== 'access' || user.iss !== issuer || typeof user.client_id !== 'string' || !CLIENT_ID.test(user.client_id) || user.sub !== user.client_id
    || !validRevision(user.client_revision) || user.scope !== SCOPE || JSON.stringify(user.permissions) !== JSON.stringify([SCOPE]) || user.roles !== undefined || user.realm_access !== undefined
    || user.identity_authorization !== undefined || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp) || user.exp * 1000 <= now) fail(403, 'Dedicated current company automation app required');
  if(user.company_tenant!==undefined&&!validTenantContext(user.company_tenant))fail(403,'Original company app tenant required');
  return { kind: 'application', issuer: user.iss, clientId: user.client_id, clientRevision: user.client_revision, tokenId: user.jti, validUntil: user.exp,...(user.company_tenant?{companyTenant:user.company_tenant}:{}) };
}
function grantInput(body) {
  exact(body, ['id', 'enrollmentId', 'clientId', 'clientRevision', 'actions', 'expiresAt', 'reason', 'confirm']);
  identifier(body.id); identifier(body.enrollmentId);
  if (typeof body.clientId !== 'string' || !CLIENT_ID.test(body.clientId) || !validRevision(body.clientRevision) || body.confirm !== true || typeof body.expiresAt !== 'string'
    || !Number.isFinite(Date.parse(body.expiresAt)) || new Date(body.expiresAt).toISOString() !== body.expiresAt
    || Date.parse(body.expiresAt) - Date.now() < 60000 || Date.parse(body.expiresAt) - Date.now() > 30 * 86400000) fail(400, 'Confirmed bounded automation grant required');
  return { ...body, actions: actions(body.actions), reason: text(body.reason, 10, 500) };
}
function jobInput(body, scheduled = false) {
  exact(body, ['id', 'grantId', 'action', 'format', ...(reconciliation(body?.action) ? ['ruleId'] : []), ...(scheduled ? body?.onChange === true ? ['onChange'] : ['intervalSeconds'] : [])]); identifier(body.id); identifier(body.grantId);
  if (!ACTIONS.includes(body.action) || !['csv', 'json'].includes(body.format) || scheduled && body.onChange !== true && (!Number.isInteger(body.intervalSeconds) || body.intervalSeconds < 60 || body.intervalSeconds > 2592000)) fail(400, 'Supported bounded automation job required');
  if (scheduled && body.onChange === true && !reconciliation(body.action)) fail(400, 'Only delegated group reconciliation supports change subscriptions');
  if (reconciliation(body.action)) { identifier(body.ruleId); if (body.format !== 'json') fail(400, 'Structured reconciliation result required'); }
  return { ...body };
}
module.exports = { SCOPE, ACTIONS, LICENSE_ACTION, GROUP_ACTION, reconciliation, CLIENT_ID, fail, exact, identifier, text, actions, workload, grantInput, jobInput };
