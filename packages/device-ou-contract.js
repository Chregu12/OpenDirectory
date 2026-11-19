'use strict';

const { validUuid, validRevision } = require('./identity-authorization-contract');
const { validDelegation } = require('./device-delegation-contract');
function exact(value, keys) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function identifier(value) { if (!validUuid(value) || value !== value.toLowerCase()) fail(400, 'Canonical device OU identifier required'); return value; }
function text(value, minimum, maximum) { return typeof value === 'string' && !/[\u0000-\u001f\u007f-\u009f]/u.test(value) && [...value.trim()].length >= minimum && [...value.trim()].length <= maximum; }
function input(value) {
  if (!exact(value, ['ou', 'reason', 'confirm']) || value.confirm !== true || !text(value.reason, 10, 500)
    || value.ou !== null && (!exact(value.ou, ['id', 'generation', 'revision']) || !validUuid(value.ou.id) || !validRevision(value.ou.generation) || !validRevision(value.ou.revision))) fail(400, 'Explicit device OU confirmation and reason required');
  return { ou: value.ou === null ? null : { ...value.ou, id: identifier(value.ou.id) }, reason: value.reason.trim(), confirm: true };
}
function validUnit(value) {
  return exact(value, ['id', 'generation', 'revision', 'name', 'parentId']) && validUuid(value.id) && validRevision(value.generation) && validRevision(value.revision)
    && text(value.name, 1, 255) && (value.parentId === null || validUuid(value.parentId) && value.parentId !== value.id);
}
function validProof(value, user) {
  if (!exact(value, ['schemaVersion', 'deviceOuProtocol', 'inventory', 'ou', 'directoryGrant', 'validUntil']) || value.schemaVersion !== 1 || value.deviceOuProtocol !== 1
    || !Number.isSafeInteger(value.validUntil) || value.validUntil * 1000 <= Date.now() || value.validUntil > value.inventory?.validUntil
    || !value.inventory?.permissions?.includes('devices.inventory.create') || value.ou !== null && !validUnit(value.ou)
    || value.ou === null && value.directoryGrant !== null) return false;
  if (value.directoryGrant === null) return true;
  return validDelegation({ ...value.inventory, validUntil: value.validUntil, permissions: ['ous.read'],
    delegation: { grants: [{ permission: 'ous.read', source: value.directoryGrant }] } }, user);
}
function etag(deviceId, deviceRevision, revision) {
  identifier(deviceId); if (!validRevision(deviceRevision) || revision !== '0' && !validRevision(revision)) fail(503, 'Device OU versions unavailable');
  return `"device-ou-${deviceId}-${deviceRevision}-${revision}"`;
}
function expected(value, deviceId) {
  if (!value) fail(428, 'Current device OU If-Match required');
  const match = typeof value === 'string' && /^"device-ou-([a-f0-9-]{36})-([1-9][0-9]{0,18})-(0|[1-9][0-9]{0,18})"$/.exec(value);
  if (!match || match[0] !== value || match[1] !== identifier(deviceId) || !validRevision(match[2]) || match[3] !== '0' && !validRevision(match[3])) fail(400, 'Exact device OU If-Match required');
  return { deviceRevision: match[2], revision: match[3] };
}
function page(query = {}, searchable = false) {
  if (Object.keys(query).some(key => !['page', ...(searchable ? ['search'] : [])].includes(key)) || query.page !== undefined && (typeof query.page !== 'string' || !/^[1-9][0-9]*$/.test(query.page) || Number(query.page) > 1000000)
    || query.search !== undefined && !text(query.search, 0, 255)) fail(400, 'Exact device OU selectors required');
  return { page: Number(query.page || 1), limit: 25, search: query.search?.trim() || '' };
}
module.exports = { exact, identifier, input, validUnit, validProof, etag, expected, page, fail };
