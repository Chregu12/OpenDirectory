const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createAccessStateClient } = require('../../../../../packages/oidc-access-state');
const { workload } = require('../../../../../packages/company-automation-contract');
const accessState = createAccessStateClient();

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

let JWKS = null;

function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

function oidcAuth({ skipPaths = [] } = {}) {
  return async (req, res, next) => {
    if (skipPaths.some(p => req.path === p || req.path.startsWith(p))) return next();
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    try {
      const { payload } = await jwtVerify(auth.slice(7), getJWKS(), { issuer: ISSUER, audience: process.env.OIDC_AUDIENCE || 'opendirectory-api', algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'jti'] });
      if (payload.token_use !== 'access') return res.status(403).json({ error: 'invalid_token_purpose' });
      await accessState(auth, payload);
      if (payload.actor_type === 'application') {
        if (req.method !== 'POST' || !['/api/licenses/automation/groups/step','/api/licenses/automation/groups/observe'].includes(req.path)) return res.status(403).json({ error: 'workload_policy_administration_forbidden' });
        workload(payload, ISSUER);
      }
      req.user = payload;
      req.verifiedAccess = Object.freeze({ authorization: auth, claims: structuredClone(payload) });
      next();
    } catch (err) {
      const status = err.status || (err.code === 'ERR_JWT_EXPIRED' || err.claim === 'sub' ? 401 : 403);
      res.status(status).json({ error: 'invalid_token', message: err.message });
    }
  };
}

module.exports = { oidcAuth };
