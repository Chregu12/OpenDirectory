'use strict';

const { validContext, sameContext, validUuid } = require('../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { INVENTORY_PERMISSIONS } = require('../../../../packages/device-inventory-contract');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class InventoryAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/device-inventory', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/device-inventory') throw new Error('Invalid inventory identity authority URL');
  }
  async read(authorization, user, userId = null) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || user?.actor_type !== 'user' || !validContext(user.identity_authorization)
      || typeof user.jti !== 'string' || !user.jti || !Number.isFinite(user.exp) || userId !== null && !validUuid(userId)) fail(401, 'Original inventory human required');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: userId ? 'POST' : 'GET', headers: { Authorization: authorization, Accept: 'application/json', ...(userId ? { 'Content-Type': 'application/json' } : {}) }, ...(userId ? { body: JSON.stringify({ userId }) } : {}), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400,401,403,404,428].includes(response.status)) fail(response.status, 'Inventory identity authority rejected the original request');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Inventory source unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 8192) throw new Error('Oversized inventory source'); chunks.push(Buffer.from(chunk)); }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (Object.keys(source).length !== 11 || source.schemaVersion !== 1 || source.issuer !== user.iss || source.subject !== user.sub || source.tokenId !== user.jti || source.expiresAt !== user.exp
        || !sameContext(source.context, user.identity_authorization) || source.actorUserId !== source.context.userId || !validTenantContext(source.tenant)
        || JSON.stringify(source.permissions) !== JSON.stringify(INVENTORY_PERMISSIONS) || !Number.isSafeInteger(source.validUntil) || source.validUntil > Math.min(user.exp, user.auth_time + 300) || source.validUntil * 1000 <= Date.now()
        || (userId === null ? source.target !== null : source.target?.id !== userId || Object.keys(source.target).length !== 3 || typeof source.target.enabled !== 'boolean' || !/^[1-9][0-9]*$/.test(source.target.revision))) throw new Error('Mismatched inventory source');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Inventory identity authority unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { InventoryAuthority };
