const { createRemoteJWKSet, jwtVerify } = require('jose');

const JWKS_URI = process.env.JWKS_URI || 'http://localhost:3001/jwks';
const ISSUER = process.env.OIDC_ISSUER || 'http://localhost:3001';

// Cache JWKS — jose handles caching internally with createRemoteJWKSet
let JWKS = null;
function getJWKS() {
  if (!JWKS) JWKS = createRemoteJWKSet(new URL(JWKS_URI), { cacheMaxAge: 3600000 });
  return JWKS;
}

async function verifyToken(token) {
  const { payload } = await jwtVerify(token, getJWKS(), { issuer: ISSUER });
  return payload;
}

function oidcAuthMiddleware({ scopes = [], skipPaths = [] } = {}) {
  return async (req, res, next) => {
    // Skip public paths
    if (skipPaths.some(p => req.path === p || req.path.startsWith(p))) return next();

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'unauthorized', error_description: 'Bearer token required' });
    }

    try {
      const token = authHeader.slice(7);
      const payload = await verifyToken(token);
      req.user = payload;

      // Scope check
      if (scopes.length > 0) {
        const tokenScopes = (payload.scope || '').split(' ');
        const hasScope = scopes.some(s => tokenScopes.includes(s));
        if (!hasScope) return res.status(403).json({ error: 'insufficient_scope' });
      }

      next();
    } catch (err) {
      if (err.code === 'ERR_JWT_EXPIRED') return res.status(401).json({ error: 'token_expired' });
      return res.status(403).json({ error: 'invalid_token', error_description: err.message });
    }
  };
}

module.exports = { oidcAuthMiddleware, verifyToken };
