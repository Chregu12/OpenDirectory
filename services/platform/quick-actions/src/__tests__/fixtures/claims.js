'use strict';
function accessClaims(patch = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: 'https://quick-actions.unit.test', sub: 'operator', aud: 'opendirectory-api', jti: 'unit-token', iat: now, exp: now + 3600,
    token_use: 'access', actor_type: 'user', auth_time: now, sid: '11111111-1111-4111-8111-111111111111', client_id: 'unit-client',
    identity_authorization: { userId: '22222222-2222-4222-8222-222222222222', revision: '1', linkRevision: '2', rolesRevision: 'a'.repeat(64) }, ...patch };
}
module.exports = { accessClaims };
