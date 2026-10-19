'use strict';

const { validContext } = require('../../../../packages/identity-authorization-contract');
const { validSource } = require('../../../../packages/company-blueprint-contract');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class CompanyBlueprintAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/company-blueprints', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/company-blueprints') throw new Error('Invalid company blueprint identity source URL');
  }
  async read(authorization, user) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || user?.actor_type !== 'user'
      || !validContext(user.identity_authorization) || typeof user.jti !== 'string' || !user.jti || !Number.isSafeInteger(user.exp) || !Number.isSafeInteger(user.auth_time)) fail(401, 'Original company blueprint human required');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: 'GET', headers: { Authorization: authorization, Accept: 'application/json' }, redirect: 'error', cache: 'no-store', signal: controller.signal });
      if (controller.signal.aborted) throw new Error('Expired source request');
      if ([401, 403, 428].includes(response.status)) fail(response.status, 'Company blueprint identity rejected the original request');
      if (response.status !== 200 || !response.headers.get('content-type')?.includes('application/json')) throw new Error('Identity unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 8192) throw new Error('Oversized source'); chunks.push(Buffer.from(chunk)); }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (controller.signal.aborted || !validSource(source, user)) throw new Error('Mismatched source');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Company blueprint identity source unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyBlueprintAuthority };
