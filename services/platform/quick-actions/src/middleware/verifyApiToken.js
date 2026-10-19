'use strict';

const issuer = process.env.OIDC_ISSUER || 'https://opendirectory.local';
const audience = process.env.OIDC_AUDIENCE || 'opendirectory-api';
const uri = new URL(process.env.JWKS_URI || 'http://oauth-provider:3010/.well-known/jwks.json');
if (!issuer || !audience || !['http:', 'https:'].includes(uri.protocol) || uri.username || uri.password || uri.hash || uri.search) throw new Error('Invalid quick-actions verification configuration');
let verifier;
async function verifyToken(token) {
  if (!verifier) verifier = import('jose').then(({ createRemoteJWKSet, jwtVerify }) => {
    const keys = createRemoteJWKSet(uri, { timeoutDuration: 1500, cooldownDuration: 1000, cacheMaxAge: 30000 });
    return async credential => (await jwtVerify(credential, keys, { issuer, audience, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'] })).payload;
  });
  try { return await (await verifier)(token); }
  catch (error) {
    const unavailable = ['ERR_JWKS_TIMEOUT', 'ERR_JWKS_INVALID', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN'].includes(error.code)
      || error instanceof TypeError || /Expected 200 OK/.test(error.message);
    throw Object.assign(new Error(unavailable ? 'Verification source unavailable' : 'Invalid access token'), { status: unavailable ? 503 : 401 });
  }
}
module.exports = { verifyToken };
