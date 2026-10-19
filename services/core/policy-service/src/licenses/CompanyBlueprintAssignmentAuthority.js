'use strict';

const { validContext } = require('../../../../../packages/identity-authorization-contract');
const { identifier, validSource } = require('../../../../../packages/company-blueprint-assignment-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyBlueprintAssignmentAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/company-blueprint-assignments', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/company-blueprint-assignments') throw new Error('Invalid company blueprint assignment identity source URL');
  }
  async read(authorization, user, userId = null) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || user?.actor_type !== 'user'
      || user.token_use !== 'access' || !validContext(user.identity_authorization) || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp) || !Number.isSafeInteger(user.auth_time)) fail(401, 'Original company blueprint assignment human required');
    if (userId !== null) identifier(userId);
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: userId === null ? 'GET' : 'POST', headers: { Authorization: authorization, Accept: 'application/json', ...(userId === null ? {} : { 'Content-Type': 'application/json' }) },
        ...(userId === null ? {} : { body: JSON.stringify({ userId }) }), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (controller.signal.aborted) throw new Error('Expired source request');
      if ([400, 401, 403, 404, 428].includes(response.status)) fail(response.status, 'Company blueprint assignment identity rejected the original request');
      if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Identity unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        if (controller.signal.aborted) throw new Error('Expired source request');
        const bytes = Buffer.from(chunk); length += bytes.length;
        if (length > 8192) throw new Error('Oversized source'); chunks.push(bytes);
      }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (controller.signal.aborted || !validSource(source, user, userId)) throw new Error('Mismatched source');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Company blueprint assignment identity source unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyBlueprintAssignmentAuthority };
