'use strict';
const { validContext } = require('../../../../packages/identity-authorization-contract');
const C = require('../../../../packages/device-ou-retirement-contract');
const { fail } = require('../../../../packages/device-ou-contract');

class DeviceOuRetirementAuthority {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/device-ou-retirement', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/device-ou-retirement') throw new Error('Invalid OU retirement authority URL');
  }
  read(authorization, user, body) { return this.request(authorization, user, body, false); }
  check(authorization, user, body) { return this.request(authorization, user, body, true); }
  async request(authorization, user, body, check) {
    const selected = structuredClone(C.input(body));
    if (user?.actor_type !== 'user' || !validContext(user.identity_authorization) || typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization)) fail(401, 'Original OU retirement human required');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 5000);
    try {
      const endpoint = new URL(this.endpoint); if (check) endpoint.pathname += '/check';
      const response = await this.fetchImpl(endpoint, { method: 'POST', headers: { Authorization: authorization, Accept: 'application/json', 'Content-Type': 'application/json', 'X-OD-Device-Ou-Retirement-Protocol': '1' }, body: JSON.stringify(selected), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404, 412, 428].includes(response.status)) fail(response.status, 'Original OU retirement authority rejected the request');
      if (response.status !== 200 || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Unconfirmed retirement authority');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) { size += chunk.length; if (size > 65536) throw new Error('Oversized retirement source'); chunks.push(Buffer.from(chunk)); }
      const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!C.validSource(result, user, selected)) throw new Error('Unconfirmed original retirement source');
      return result;
    } catch (error) { if (error.status) throw error; fail(503, 'Original OU retirement source unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { DeviceOuRetirementAuthority };
