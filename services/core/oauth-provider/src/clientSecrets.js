'use strict';

const { createHash, timingSafeEqual } = require('node:crypto');
function hashSecret(secret) { return createHash('sha256').update(secret, 'utf8').digest('hex'); }
function secretMatches(hash, secret) {
  return typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash) && typeof secret === 'string' && secret.length > 0 && secret.length <= 4096
    && timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(hashSecret(secret), 'hex'));
}
module.exports = { hashSecret, secretMatches };
