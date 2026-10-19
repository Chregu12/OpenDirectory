'use strict';

const { verifyToken } = require('./verifyApiToken');
const { validate, runWithOperator } = require('../utils/delegation');
const { validContext } = require('../../../../../packages/identity-authorization-contract');

function validClaims(payload) {
  const now = Date.now() / 1000;
  return payload?.token_use === 'access' && typeof payload.iss === 'string' && !!payload.iss
    && typeof payload.sub === 'string' && !!payload.sub.trim() && payload.sub.length <= 255
    && typeof payload.jti === 'string' && !!payload.jti && payload.jti.length <= 255
    && Number.isInteger(payload.exp) && Number.isInteger(payload.iat) && payload.exp > now && payload.exp > payload.iat && payload.iat <= now + 30
    && ['user', 'application'].includes(payload.actor_type) && Number.isInteger(payload.auth_time)
    && typeof payload.sid === 'string' && payload.sid.length === 36 && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(payload.sid)
    && typeof payload.client_id === 'string' && !!payload.client_id && payload.client_id.length <= 255
    && (payload.actor_type !== 'user' || validContext(payload.identity_authorization));
}
async function authMiddleware(req, res, next) {
  if (['GET', 'HEAD'].includes(req.method) && req.path === '/health') return next();
  res.set('Cache-Control', 'no-store');
  const authorization = req.headers.authorization;
  const duplicate = (req.rawHeaders || []).filter((value, index) => index % 2 === 0 && value.toLowerCase() === 'authorization').length > 1;
  if (duplicate || req.headers['x-api-key'] || ['token', 'access_token', 'api_key', 'service_token'].some(key => Object.hasOwn(req.query || {}, key))
    || typeof authorization !== 'string' || authorization.length > 8192 || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization)) {
    res.set('WWW-Authenticate', 'Bearer'); return res.status(401).json({ error: 'invalid_token' });
  }
  try {
    const payload = await verifyToken(authorization.slice(7));
    if (!validClaims(payload)) throw Object.assign(new Error('Invalid access-token claims'), { status: 401 });
    await validate(authorization, payload);
    if (req.aborted || res.destroyed) return;
    return runWithOperator(authorization, payload, context => {
      req.user = context.claims;
      res.set('X-OD-Operation-Id', context.operationId);
      res.once('finish', context.close); res.once('close', context.close); req.once('aborted', context.close);
      next();
    });
  } catch (error) {
    const status = error.status === 503 ? 503 : 401;
    if (status === 401) res.set('WWW-Authenticate', 'Bearer');
    return res.status(status).json({ error: status === 503 ? 'authorization_unavailable' : 'invalid_token' });
  }
}
module.exports = authMiddleware;
module.exports.validClaims = validClaims;
