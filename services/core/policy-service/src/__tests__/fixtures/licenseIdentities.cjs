'use strict';

const { createHash } = require('crypto');
const issuer = 'https://license-fixture.test';
function userId(name) {
  const value = createHash('sha256').update(name).digest('hex').slice(0, 32);
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}
function principal(subject, identityIssuer = issuer) { return { issuer: identityIssuer, subject, userId: userId(subject), enabled: true }; }
module.exports = { userId, principal, issuer };
