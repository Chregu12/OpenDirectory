'use strict';

const { validUuid, validRevision } = require('../../../../../packages/identity-authorization-contract');
const { identifier } = require('../../../../../packages/company-license-contract');
function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyOffboardingIdentity {
  constructor({ origin = process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.origin = new URL(origin); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.origin.protocol) || this.origin.username || this.origin.password || this.origin.search || this.origin.hash || this.origin.pathname !== '/') throw new Error('Exact Identity origin required');
  }
  async request(path, authorization, body = null) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/u.test(authorization)) fail(401, 'Original offboarding bearer required');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await this.fetchImpl(new URL(path, this.origin), { method: body === null ? 'GET' : 'POST',
        headers: { Authorization: authorization, Accept: 'application/json', ...(body === null ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === null ? {} : { body: JSON.stringify(body) }), cache: 'no-store', redirect: 'error', signal: controller.signal });
      if ([400, 401, 403, 404, 409, 412, 428].includes(response.status)) fail(response.status, 'Identity rejected the original offboarding request');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Identity offboarding unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 65536) throw new Error('Oversized Identity response'); chunks.push(Buffer.from(chunk)); }
      return { body: JSON.parse(Buffer.concat(chunks).toString('utf8')), etag: response.headers.get('etag') };
    } catch (error) { if (error.status) throw error; fail(503, 'Identity offboarding result unconfirmed'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
  async user(userId, authorization, source) {
    identifier(userId); const { body, etag } = await this.request('/api/users/' + userId, authorization);
    const name = typeof body?.displayName === 'string' && body.displayName.trim() ? body.displayName : body?.username;
    if (body?.id !== userId || !validRevision(body.revision) || typeof body.enabled !== 'boolean' || body.enabled !== source.target.enabled
      || etag !== `"user-${userId}-${body.revision}"` || typeof name !== 'string' || !name.trim() || [...name].length > 255 || /[\u0000-\u001f\u007f-\u009f]/u.test(name)) fail(503, 'Own employee record not confirmed');
    return { id: userId, name, userRevision: body.revision, eligibilityRevision: source.target.eligibilityRevision, enabled: body.enabled };
  }
  async disable(job, authorization, source) {
    const expected = job.state.requestedRevision;
    const { body } = await this.request('/api/users/' + identifier(job.userId) + '/company-offboarding', authorization, { workflowId: identifier(job.id), expectedRevision: expected, confirm: true });
    if (!body || typeof body !== 'object' || Object.keys(body).length !== 13 || body.schemaVersion !== 1 || body.workflowId !== job.id || body.tenantId !== source.tenant.id || body.userId !== job.userId
      || !validUuid(body.actorUserId) || !['disabled', 'already_disabled'].includes(body.action) || body.beforeRevision !== expected
      || ![body.beforeRevision, body.afterRevision, body.beforeEligibilityRevision, body.afterEligibilityRevision].every(validRevision)
      || typeof body.createdAt !== 'string' || !Number.isFinite(Date.parse(body.createdAt)) || body.deliveryStatus !== 'pending'
      || (body.action === 'disabled' ? !validUuid(body.operationId) || BigInt(body.afterRevision) <= BigInt(body.beforeRevision) || BigInt(body.afterEligibilityRevision) <= BigInt(body.beforeEligibilityRevision)
        : body.operationId !== null || body.beforeRevision !== body.afterRevision || body.beforeEligibilityRevision !== body.afterEligibilityRevision)) fail(503, 'Persistent Identity offboarding receipt not confirmed');
    return body;
  }
}
module.exports = { CompanyOffboardingIdentity };
