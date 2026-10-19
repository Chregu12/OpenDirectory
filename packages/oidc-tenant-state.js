'use strict';

const { validContext, sameContext } = require('./identity-authorization-contract');
const { TENANT_STATE_PATH, validTenantContext } = require('./tenant-authorization-contract');
const { AccessStateError } = require('./oidc-access-state');

function createTenantStateClient({ endpoint = process.env.OIDC_TENANT_STATE_URL || 'http://oauth-provider:3010' + TENANT_STATE_PATH,
  fetchImpl = (...args) => global.fetch(...args), timeoutMs = 2500 } = {}) {
  const url = new URL(endpoint);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== TENANT_STATE_PATH) throw new Error('Invalid tenant-state authority URL');
  return async (authorization, expected) => {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)
      || expected?.actor_type !== 'user' || !validContext(expected.identity_authorization)
      || typeof expected.iss !== 'string' || !expected.iss || typeof expected.sub !== 'string' || !expected.sub
      || typeof expected.jti !== 'string' || !expected.jti || !Number.isFinite(expected.exp)) throw new AccessStateError(401, 'Tenant-bound human token required');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { method: 'GET', headers: { Authorization: authorization, Accept: 'application/json' },
        redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([401, 403].includes(response.status)) throw new AccessStateError(401, 'Tenant authority rejected the original token');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Unavailable tenant authority');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length; if (length > 4096) throw new Error('Oversized tenant authority'); chunks.push(Buffer.from(chunk));
      }
      const state = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (state?.schemaVersion !== 1 || typeof state.active !== 'boolean') throw new Error('Invalid tenant authority');
      if (!state.active) throw new AccessStateError(401, 'Tenant authority rejected the original token');
      if (Object.keys(state).length !== 8 || state.issuer !== expected.iss || state.subject !== expected.sub || state.tokenId !== expected.jti
        || state.expiresAt !== expected.exp || expected.exp * 1000 <= Date.now() || !sameContext(state.context, expected.identity_authorization)
        || !validTenantContext(state.tenant)) throw new Error('Mismatched tenant authority');
      return state.tenant;
    } catch (error) {
      if (error instanceof AccessStateError) throw error;
      throw new AccessStateError(503, 'Tenant authority unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  };
}

module.exports = { createTenantStateClient };
