'use strict';

class AccessStateError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function createAccessStateClient({ endpoint = process.env.OIDC_ACCESS_STATE_URL || 'http://oauth-provider:3010/oauth/access-state', fetchImpl = (...args) => global.fetch(...args), timeoutMs = 2500 } = {}) {
  const url = new URL(endpoint);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/oauth/access-state') throw new Error('Invalid access-state authority URL');
  return async (authorization, expected) => {
    if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)
      || typeof expected?.jti !== 'string' || !expected.jti || typeof expected.sub !== 'string' || !expected.sub
      || !Number.isFinite(expected.exp)) throw new AccessStateError(401, 'Invalid access-token state claims');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(url, { headers: { Authorization: authorization, Accept: 'application/json' }, method: 'GET',
        redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([401, 403].includes(response.status)) throw new AccessStateError(401, 'Access token is revoked or invalid');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new AccessStateError(503, 'Token state authority unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length;
        if (length > 4096) { controller.abort(); throw new Error('Oversized state response'); }
        chunks.push(Buffer.from(chunk));
      }
      const state = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (state?.schemaVersion !== 1 || typeof state.active !== 'boolean') throw new Error('Invalid state response');
      if (!state.active) throw new AccessStateError(401, 'Access token is revoked or invalid');
      if (state.issuer !== expected.iss || state.subject !== expected.sub || state.tokenId !== expected.jti || state.expiresAt !== expected.exp
        || expected.exp * 1000 <= Date.now()) throw new Error('Mismatched state response');
    } catch (error) {
      if (error instanceof AccessStateError) throw error;
      throw new AccessStateError(503, 'Token state authority unavailable');
    } finally { clearTimeout(timer); controller.abort(); }
  };
}

module.exports = { createAccessStateClient, AccessStateError };
