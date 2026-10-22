'use strict';

const IDENTITY_SCOPES = new Set(['openid', 'profile', 'email', 'groups', 'roles', 'offline_access', 'sessions.self.read', 'sessions.self.revoke']);

function stringList(value) {
  return Array.isArray(value) ? [...new Set(value.filter(item => typeof item === 'string' && item.length > 0))] : [];
}

function resolveScopes(client, requested, defaults = [], maximum) {
  const allowed = new Set(stringList(client.scopes));
  if (requested !== undefined && (typeof requested !== 'string' || requested.length > 4096
    || (requested !== '' && !/^[\x21\x23-\x5B\x5D-\x7E]+(?: +[\x21\x23-\x5B\x5D-\x7E]+)*$/.test(requested)))) return null;
  const scopes = requested === undefined ? defaults.filter(scope => allowed.has(scope)) : requested.split(' ').filter(Boolean);
  const ceiling = maximum === undefined ? null : new Set(maximum.split(' ').filter(Boolean));
  if (scopes.some(scope => !allowed.has(scope) || (ceiling && !ceiling.has(scope)))) return null;
  return [...new Set(scopes)].join(' ');
}

function userCanDelegateScopes(user, scope) {
  const permissions = new Set(stringList(user.permissions));
  const admin = stringList(user.roles).includes('admin');
  return scope.split(' ').filter(Boolean).every(item => IDENTITY_SCOPES.has(item) || admin || permissions.has(item));
}

function userAuthorizationClaims(user, scope) {
  if (!scope.split(' ').includes('roles')) return {};
  return { roles: stringList(user.roles), permissions: stringList(user.permissions) };
}
function workloadAuthorizationClaims(scope) {
  const permissions = ['licenses.users.read','licenses.groups.derive','company.automation'].filter(permission => scope.split(' ').includes(permission));
  return permissions.length ? { permissions } : {};
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function validPkceRequest(client, challenge, method) {
  if (client.publicClient) return method === 'S256' && typeof challenge === 'string' && /^[A-Za-z0-9_-]{43}$/.test(challenge);
  if (!challenge) return !method;
  return typeof challenge === 'string' && (!method || method === 'S256' || method === 'plain');
}

module.exports = { resolveScopes, userCanDelegateScopes, userAuthorizationClaims, workloadAuthorizationClaims, escapeHtml, validPkceRequest };
