'use strict';

const rateLimit = require('express-rate-limit');

function authRateLimit({ skipSuccessfulRequests = false } = {}) {
  const options = {
    windowMs: 15 * 60 * 1000,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    message: { error: 'authentication_rate_limited' },
  };
  return [
    rateLimit({ ...options, max: 20 }),
    rateLimit({ ...options, max: 5,
      skip: req => typeof req.body?.username !== 'string' || !req.body.username.trim(),
      keyGenerator: req => req.body.username.trim().toLowerCase(),
    }),
  ];
}

module.exports = { authRateLimit };
