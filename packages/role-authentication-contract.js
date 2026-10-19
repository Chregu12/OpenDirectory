'use strict';

const { provenMfa } = require('./mfa-authorization-contract');
function validAuthentication(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 2
    && typeof value.required === 'boolean' && Number.isInteger(value.maxAgeSeconds) && value.maxAgeSeconds >= 300 && value.maxAgeSeconds <= 86400;
}
function acceptsRoleAuthentication(policy, payload, now = Math.floor(Date.now() / 1000)) {
  return validAuthentication(policy) && (!policy.required || provenMfa(payload) && payload.auth_time <= now + 5 && now - payload.auth_time <= policy.maxAgeSeconds);
}
module.exports = { validAuthentication, acceptsRoleAuthentication };
