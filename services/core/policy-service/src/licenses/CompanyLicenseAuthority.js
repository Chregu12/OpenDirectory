'use strict';

const { validContext, sameContext, validRevision } = require('../../../../../packages/identity-authorization-contract');
const { validTenantContext } = require('../../../../../packages/tenant-authorization-contract');
const { COMPANY_LICENSE_PERMISSIONS, identifier } = require('../../../../../packages/company-license-contract');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyLicenseAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/company-licenses', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/company-licenses') throw new Error('Invalid company license identity source URL');
  }
  async read(authorization, user, userId = null) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || user?.actor_type !== 'user' || !validContext(user.identity_authorization)
      || typeof user.jti !== 'string' || !user.jti || !Number.isFinite(user.exp) || !Number.isSafeInteger(user.auth_time)) fail(401, 'Original company license human required');
    if (userId !== null) identifier(userId);
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: userId ? 'POST' : 'GET', headers: { Authorization: authorization, Accept: 'application/json', ...(userId ? { 'Content-Type': 'application/json' } : {}) }, ...(userId ? { body: JSON.stringify({ userId }) } : {}), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404, 428].includes(response.status)) fail(response.status, 'Company license identity rejected the original request');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Company license identity unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 8192) throw new Error('Oversized company license source'); chunks.push(Buffer.from(chunk)); }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!source || Object.keys(source).length !== 11 || source.schemaVersion !== 1 || source.issuer !== user.iss || source.subject !== user.sub || source.tokenId !== user.jti || source.expiresAt !== user.exp
        || !sameContext(source.context, user.identity_authorization) || source.actorUserId !== source.context.userId || !validTenantContext(source.tenant)
        || JSON.stringify(source.permissions) !== JSON.stringify(COMPANY_LICENSE_PERMISSIONS) || !Number.isSafeInteger(source.validUntil) || source.validUntil > Math.min(user.exp, user.auth_time + 300) || source.validUntil * 1000 <= Date.now()
        || (userId === null ? source.target !== null : !source.target || Object.keys(source.target).length !== 5 || source.target.id !== userId || !validRevision(source.target.eligibilityRevision)
          || typeof source.target.enabled !== 'boolean' || typeof source.target.deleted !== 'boolean' || (source.target.deleted ? source.target.revision !== null || source.target.enabled : !validRevision(source.target.revision)))) throw new Error('Mismatched company license source');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Company license identity source unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyLicenseAuthority };
