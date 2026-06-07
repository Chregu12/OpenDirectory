const { verifyToken } = require('../../../../shared/oidcAuth');

// Paths that do not require authentication
const PUBLIC_PATHS = [
  '/health',
  '/api/health',
];

// Service-account token for backwards-compatible service-to-service calls
// Format: "svc-<SERVICE_TOKEN>" — bypass JWKS verification during migration
const SERVICE_TOKEN = process.env.SERVICE_TOKEN;

async function authMiddleware(req, res, next) {
  // Skip public paths
  if (PUBLIC_PATHS.some(p => req.path === p || req.path.startsWith(p + '/'))) {
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Bearer token required' });
  }

  const token = authHeader.slice(7);

  // Service-account bypass for backwards compatibility during migration
  if (SERVICE_TOKEN && token === `svc-${SERVICE_TOKEN}`) {
    req.user = { sub: 'service-account', scope: 'openid roles' };
    return next();
  }

  try {
    const payload = await verifyToken(token);
    req.user = payload;
    next();
  } catch (err) {
    if (err.code === 'ERR_JWT_EXPIRED') {
      return res.status(401).json({ error: 'token_expired' });
    }
    return res.status(403).json({ error: 'invalid_token', error_description: err.message });
  }
}

module.exports = authMiddleware;
