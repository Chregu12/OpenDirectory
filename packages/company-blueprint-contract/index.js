'use strict';

const { validUuid, validRevision, sameContext } = require('../identity-authorization-contract');
const { validTenantContext } = require('../tenant-authorization-contract');
const { acceptsRoleAuthentication } = require('../role-authentication-contract');
const COMPANY_BLUEPRINT_PERMISSIONS = Object.freeze(['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish']);
const PLATFORMS = Object.freeze(['all', 'windows', 'macos', 'linux']);
const CONFIGURATION_TYPES = Object.freeze(['screen_lock', 'filevault', 'software_update']);
const ACTIONS = Object.freeze(['created', 'updated', 'published', 'restored']);
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(400, 'exact_company_blueprint_fields_required');
  return value;
}
function identifier(value) { if (!validUuid(value) || value !== value.toLowerCase()) fail(400, 'canonical_company_blueprint_id_required'); return value; }
function revision(value, zero = false) { if (!(zero && value === '0') && !validRevision(value)) fail(400, 'company_blueprint_revision_required'); return value; }
function text(value, minimum, maximum) {
  if (typeof value !== 'string' || value !== value.trim() || Array.from(value).length < minimum || Array.from(value).length > maximum || /[\u0000-\u001f\u007f-\u009f]/.test(value)) fail(400, 'bounded_company_blueprint_text_required');
  return value;
}
function versionNumber(value) {
  if (typeof value === 'string' && /^[1-9][0-9]{0,9}$/.test(value)) value = Number(value);
  if (!Number.isInteger(value) || value < 1 || value > 2147483647) fail(400, 'company_blueprint_version_required');
  return value;
}
function payloadValues(type, value) {
  if (!CONFIGURATION_TYPES.includes(type) || typeof value !== 'string' || Buffer.byteLength(value) > 65536 || /[0-9][.eE]/.test(value)) fail(400, 'safe_company_blueprint_configuration_required');
  let payload;
  try { payload = JSON.parse(value); } catch { fail(400, 'safe_company_blueprint_configuration_required'); }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || (value.match(/"\s*:/g) || []).length !== Object.keys(payload).length) fail(400, 'safe_company_blueprint_configuration_required');
  if (type === 'screen_lock') {
    exact(payload, ['minutes', 'requirePassword']);
    if (!Number.isInteger(payload.minutes) || payload.minutes < 1 || payload.minutes > 1440 || typeof payload.requirePassword !== 'boolean') fail(400, 'safe_company_blueprint_configuration_required');
  } else if (type === 'filevault') {
    exact(payload, ['enabled']);
    if (typeof payload.enabled !== 'boolean') fail(400, 'safe_company_blueprint_configuration_required');
  } else {
    exact(payload, ['automatic', 'deferralDays']);
    if (typeof payload.automatic !== 'boolean' || !Number.isInteger(payload.deferralDays) || payload.deferralDays < 0 || payload.deferralDays > 365) fail(400, 'safe_company_blueprint_configuration_required');
  }
  return value;
}
function draftValues(input) {
  exact(input, ['name', 'description', 'platform', 'configurations', 'appPoolIds']);
  const name = text(input.name, 1, 160); const description = text(input.description, 0, 2000);
  if (!PLATFORMS.includes(input.platform) || !Array.isArray(input.configurations) || input.configurations.length > 25 || !Array.isArray(input.appPoolIds) || input.appPoolIds.length > 25) fail(400, 'bounded_company_blueprint_draft_required');
  const configurations = input.configurations.map(item => {
    exact(item, ['id', 'type', 'name', 'payloadJson']);
    return { id: identifier(item.id), type: item.type, name: text(item.name, 1, 160), payloadJson: payloadValues(item.type, item.payloadJson) };
  });
  const appPoolIds = input.appPoolIds.map(identifier);
  if (new Set(configurations.map(item => item.id)).size !== configurations.length || new Set(appPoolIds).size !== appPoolIds.length
    || configurations.reduce((total, item) => total + Buffer.byteLength(item.payloadJson), 0) > 262144) fail(400, 'unique_bounded_company_blueprint_items_required');
  return { name, description, platform: input.platform, configurations, appPoolIds };
}
function writeValues(action, input) {
  if (!ACTIONS.includes(action)) fail(400, 'company_blueprint_action_required');
  exact(input, [...(action === 'created' ? ['id', 'draft'] : action === 'updated' ? ['draft'] : action === 'restored' ? ['version'] : []), 'reason', 'confirm']);
  if (input.confirm !== true) fail(400, 'company_blueprint_confirmation_required');
  const result = { reason: text(input.reason, 10, 500), confirm: true };
  if (action === 'created') result.id = identifier(input.id);
  if (['created', 'updated'].includes(action)) result.draft = draftValues(input.draft);
  if (action === 'restored') {
    if (typeof input.version !== 'number') fail(400, 'company_blueprint_version_required');
    result.version = versionNumber(input.version);
  }
  return result;
}
function commandValues(input) {
  exact(input, ['id', 'correlationId', 'blueprintId', 'action', 'expectedRevision', 'reason', 'draft', 'version']);
  identifier(input.id); identifier(input.correlationId); identifier(input.blueprintId);
  if (!ACTIONS.includes(input.action)) fail(400, 'company_blueprint_action_required');
  revision(input.expectedRevision, input.action === 'created');
  if (input.action === 'created' && input.expectedRevision !== '0') fail(400, 'company_blueprint_revision_required');
  const values = writeValues(input.action, { ...(input.action === 'created' ? { id: input.blueprintId, draft: input.draft } : input.action === 'updated' ? { draft: input.draft } : input.action === 'restored' ? { version: input.version } : {}), reason: input.reason, confirm: true });
  if (!['created', 'updated'].includes(input.action) && input.draft !== null || input.action !== 'restored' && input.version !== null) fail(400, 'exact_company_blueprint_command_required');
  return { id: input.id, correlationId: input.correlationId, blueprintId: input.blueprintId, action: input.action, expectedRevision: input.expectedRevision, reason: values.reason, draft: values.draft || null, version: values.version || null };
}
function etag(row) { return `"company-blueprint-${identifier(row.id)}-${revision(row.revision)}"`; }
function expectedRevision(id, value) {
  identifier(id);
  if (value === undefined || value === null || value === '') fail(428, 'company_blueprint_version_required');
  if (typeof value !== 'string' || !value.startsWith(`"company-blueprint-${id}-`) || !value.endsWith('"')) fail(400, 'exact_company_blueprint_etag_required');
  const captured = value.slice(`"company-blueprint-${id}-`.length, -1); revision(captured); return captured;
}
function pagination(query, searchAllowed = false) {
  if (!query || typeof query !== 'object' || Array.isArray(query) || Object.keys(query).some(key => !['page', 'limit', ...(searchAllowed ? ['search'] : [])].includes(key))) fail(400, 'exact_company_blueprint_query_required');
  if (query.page !== undefined && (typeof query.page !== 'string' || !/^[1-9][0-9]{0,6}$/.test(query.page) || Number(query.page) > 1000000)
    || query.limit !== undefined && query.limit !== '25') fail(400, 'bounded_company_blueprint_page_required');
  const search = query.search === undefined ? '' : text(query.search, 0, 100);
  return { page: query.page === undefined ? 1 : Number(query.page), limit: 25, search };
}
function validSource(source, user, now = Date.now()) {
  try {
    exact(source, ['schemaVersion', 'companyBlueprintProtocol', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil']);
    text(source.issuer, 1, 2048); text(source.subject, 1, 255); text(source.tokenId, 1, 255);
    identifier(source.actorUserId); identifier(source.context?.userId); identifier(source.tenant?.id);
    return source.schemaVersion === 1 && source.companyBlueprintProtocol === 1 && user?.actor_type === 'user' && user.token_use === 'access'
      && source.issuer === user.iss && source.subject === user.sub && source.tokenId === user.jti && source.expiresAt === user.exp
      && typeof source.issuer === 'string' && source.issuer.length > 0 && source.issuer.length <= 2048 && typeof source.subject === 'string' && source.subject.length > 0
      && typeof source.tokenId === 'string' && source.tokenId.length > 0 && Number.isSafeInteger(source.expiresAt) && Number.isSafeInteger(user.auth_time)
      && sameContext(source.context, user.identity_authorization) && source.actorUserId === source.context.userId && validTenantContext(source.tenant)
      && JSON.stringify(source.permissions) === JSON.stringify(COMPANY_BLUEPRINT_PERMISSIONS) && acceptsRoleAuthentication({ required: true, maxAgeSeconds: 300 }, user)
      && Number.isSafeInteger(source.validUntil) && source.validUntil * 1000 > now && source.validUntil <= Math.min(user.exp, user.auth_time + 300, Math.floor(now / 1000) + 300);
  } catch { return false; }
}

module.exports = { COMPANY_BLUEPRINT_PERMISSIONS, PLATFORMS, CONFIGURATION_TYPES, ACTIONS, fail, exact, identifier, revision, text, versionNumber, payloadValues, draftValues, writeValues, commandValues, etag, expectedRevision, pagination, validSource };
