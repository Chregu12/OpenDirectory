'use strict';
const contract = require('../../../../packages/company-license-activation');
const { validUuid } = require('../../../../packages/identity-authorization-contract');
module.exports = async function activationState(user, authorization) {
  if (!validUuid(user.sid)) return { known: false, activation: null };
  const path = contract.PATH + '/source';
  const result = await contract.request(new URL(path, process.env.OIDC_TENANT_STATE_URL || process.env.OAUTH_PROVIDER_URL || 'http://oauth-provider:3010').href, path, authorization, user);
  if (!contract.exact(result, ['schemaVersion', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'known', 'activation'])
    || typeof result.known !== 'boolean' || (result.activation !== null && (!result.known || !contract.validClaim(result.activation)
      || !contract.sameTenantContext(result.activation.tenant, result.tenant)))) throw Object.assign(new Error('Invalid license activation source'), { status: 503 });
  return { known: result.known, activation: result.activation };
};
