'use strict';

const { provenMfa } = require('../../../../packages/mfa-authorization-contract');
function freshMfa(payload, maximumAge = 300, now = Math.floor(Date.now() / 1000)) {
  return provenMfa(payload) && payload.auth_time <= now + 5 && now - payload.auth_time <= maximumAge;
}
function acceptsAuthentication(client, payload, now) {
  if (!['user', 'application'].includes(payload?.actor_type)) return false;
  if (payload.actor_type === 'application') return true;
  return !client.mfaRequired || freshMfa(payload, client.mfaMaxAgeSeconds, now);
}
module.exports = { freshMfa, acceptsAuthentication };
