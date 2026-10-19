'use strict';

const rateLimit = require('express-rate-limit');

function authorityAdmission({ windowMs = 60000, ingressMax = 6000, verifiedMax = 5000 } = {}) {
  for (const value of [windowMs, ingressMax, verifiedMax]) if (!Number.isSafeInteger(value) || value < 1) throw new Error('Invalid authority admission limit');
  const options = { windowMs, standardHeaders: true, legacyHeaders: false, message: { error: 'identity_authority_rate_limited' } };
  const ingressLimit = rateLimit({ ...options, max: ingressMax });
  const ingress = (req, res, next) => { res.set('Cache-Control', 'no-store'); return ingressLimit(req, res, next); };
  const verifiedLimit = rateLimit({ ...options, max: verifiedMax, keyGenerator: req => req.authorityIssuer });
  const verified = (req, res, next) => {
    if (typeof req.authorityIssuer !== 'string' || !req.authorityIssuer) return res.status(401).json({ error: 'invalid_authority_request' });
    return verifiedLimit(req, res, next);
  };
  return { ingress, verified };
}

module.exports = { authorityAdmission };
