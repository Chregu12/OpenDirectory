'use strict';

const { validContext, sameContext, validRevision } = require('../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { INVENTORY_PERMISSIONS, deviceOffboardingValues } = require('../../../../packages/device-inventory-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
function uuid(value) { return typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value); }
function exact(value, keys) { return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)); }
function timestamp(value) { return typeof value === 'string' && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value; }

class DeviceReturnAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/device-offboarding', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/device-offboarding') throw new Error('Invalid device offboarding identity authority URL');
  }

  async read(authorization, user, workflowId, userId) {
    const values = deviceOffboardingValues({ workflowId, userId });
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)
      || user?.actor_type !== 'user' || !validContext(user.identity_authorization) || !uuid(user.identity_authorization.userId)
      || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp) || !Number.isSafeInteger(user.auth_time)) fail(401, 'Original offboarding inventory human required');
    if (userId === user.identity_authorization.userId) fail(403, 'Self offboarding is forbidden');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: 'POST', headers: { Authorization: authorization, Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(values), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404, 409, 428].includes(response.status)) fail(response.status, 'Device offboarding authority rejected the original request');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Device offboarding source unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 12288) throw new Error('Oversized device offboarding source'); chunks.push(Buffer.from(chunk)); }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8')); const parent = source?.parent;
      if (!exact(source, ['schemaVersion', 'issuer', 'subject', 'tokenId', 'expiresAt', 'context', 'tenant', 'actorUserId', 'permissions', 'validUntil', 'target', 'deviceOffboardingReturnsProtocol', 'parent'])
        || source.schemaVersion !== 1 || source.deviceOffboardingReturnsProtocol !== 1 || source.issuer !== user.iss || source.subject !== user.sub || source.tokenId !== user.jti || source.expiresAt !== user.exp
        || !sameContext(source.context, user.identity_authorization) || source.actorUserId !== source.context.userId || !validTenantContext(source.tenant) || !uuid(source.tenant.id)
        || JSON.stringify(source.permissions) !== JSON.stringify(INVENTORY_PERMISSIONS) || !Number.isSafeInteger(source.validUntil) || source.validUntil > Math.min(user.exp, user.auth_time + 300) || source.validUntil * 1000 <= Date.now()
        || !exact(source.target, ['id', 'enabled', 'eligibilityRevision']) || source.target.id !== userId || source.target.enabled !== false || !validRevision(source.target.eligibilityRevision)
        || !exact(parent, ['workflowId', 'tenantId', 'userId', 'action', 'operationId', 'afterRevision', 'afterEligibilityRevision', 'createdAt', 'deliveryStatus'])
        || parent.workflowId !== workflowId || parent.tenantId !== source.tenant.id || parent.userId !== userId || !['disabled', 'already_disabled'].includes(parent.action)
        || (parent.action === 'disabled' ? !uuid(parent.operationId) : parent.operationId !== null) || !validRevision(parent.afterRevision) || parent.afterEligibilityRevision !== source.target.eligibilityRevision
        || !timestamp(parent.createdAt) || Date.parse(parent.createdAt) > Date.now() || parent.deliveryStatus !== 'pending') throw new Error('Mismatched original device offboarding source');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Device offboarding identity authority unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}

module.exports = { DeviceReturnAuthority };
