'use strict';

const { validUuid, sameContext } = require('./identity-authorization-contract');
const { validTenantContext, sameTenantContext } = require('./tenant-authorization-contract');
const { provenMfa } = require('./mfa-authorization-contract');
const DURATIONS = Object.freeze([900, 3600, 7200, 14400, 28800, 36000]);
const PATH = '/api/mfa/company-license-activation';
const ELIGIBILITY_PATH = '/api/identity/company-license-eligibility';
function exact(value, keys) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function validClaim(value) {
  return exact(value, ['schemaVersion', 'scope', 'id', 'tenant', 'expiresAt']) && value.schemaVersion === 1 && value.scope === 'company-licenses'
    && validUuid(value.id) && validTenantContext(value.tenant) && Number.isSafeInteger(value.expiresAt) && value.expiresAt > 0;
}
function deadline(user) {
  const claim = user?.company_license_activation;
  return validClaim(claim) && provenMfa(user) && Number.isSafeInteger(user.iat) && Number.isSafeInteger(user.exp)
    && user.iat <= Math.floor(Date.now() / 1000) + 5 && user.exp > user.iat && user.exp <= user.iat + 300
    ? Math.min(user.exp, claim.expiresAt) : user.auth_time + 300;
}
function binding(user) {
  return { issuer: user.iss, subject: user.sub, sessionId: user.sid, clientId: user.client_id || user.aud, clientRevision: user.client_revision,
    context: user.identity_authorization, authTime: user.auth_time, mfaRevision: user.mfa_authorization?.revision };
}
function matches(first, second) {
  return !!first && !!second && ['issuer', 'subject', 'sessionId', 'clientId', 'clientRevision', 'authTime', 'mfaRevision'].every(key => first[key] === second[key]) && sameContext(first.context, second.context);
}
async function request(base, path, authorization, user, fetchImpl = global.fetch) {
  const url = new URL(base);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== path) throw new Error('Invalid company license activation authority URL');
  if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) throw Object.assign(new Error('Original bearer required'), { status: 401 });
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
  try {
    const response = await fetchImpl(url, { headers: { Authorization: authorization, Accept: 'application/json' }, redirect: 'error', cache: 'no-store', signal: controller.signal });
    if ([401, 403, 428].includes(response.status)) throw Object.assign(new Error('Company license activation authority rejected'), { status: response.status });
    if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Unavailable activation authority');
    const chunks = []; let size = 0;
    for await (const chunk of response.body) { size += chunk.length; if (size > 8192) throw new Error('Oversized activation authority'); chunks.push(Buffer.from(chunk)); }
    const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (result?.schemaVersion !== 1 || result.issuer !== user.iss || result.subject !== user.sub || result.tokenId !== user.jti || result.expiresAt !== user.exp
      || !sameContext(result.context, user.identity_authorization) || !validTenantContext(result.tenant)) throw new Error('Mismatched activation authority');
    if (path === ELIGIBILITY_PATH && (!exact(result, ['schemaVersion', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target'])
      || result.actorUserId !== user.identity_authorization.userId || JSON.stringify(result.permissions) !== JSON.stringify(['company.apps.read', 'company.apps.create', 'company.apps.assign'])
      || result.target !== null || !Number.isSafeInteger(result.validUntil) || result.validUntil > user.exp || result.validUntil * 1000 <= Date.now())) throw new Error('Invalid activation eligibility');
    return result;
  } catch (error) { if (error.status) throw error; throw Object.assign(new Error('Company license activation authority unavailable', { cause: error }), { status: 503, code: 'company_license_activation_authority_unavailable' }); }
  finally { clearTimeout(timer); controller.abort(); }
}
module.exports = { DURATIONS, PATH, ELIGIBILITY_PATH, exact, validClaim, deadline, binding, matches, request, sameTenantContext };
