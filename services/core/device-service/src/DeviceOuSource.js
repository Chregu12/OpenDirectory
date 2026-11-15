'use strict';

const { validContext } = require('../../../../packages/identity-authorization-contract');
const C = require('../../../../packages/device-ou-contract');
const { inventorySourceMatches } = require('./InventoryAuthority');

class DeviceOuSource {
  constructor({ endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + '/api/identity/device-organizational-units', fetchImpl = (...args) => global.fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash || this.endpoint.pathname !== '/api/identity/device-organizational-units') throw new Error('Invalid device OU authority URL');
  }
  async request(authorization, user, method, values) {
    if (typeof authorization !== 'string' || authorization.length > 16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || user?.actor_type !== 'user' || !validContext(user.identity_authorization)) C.fail(401, 'Original device OU human required');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 5000);
    try {
      const endpoint = new URL(this.endpoint);
      if (method === 'GET') for (const [key, value] of Object.entries(values)) endpoint.searchParams.set(key, String(value));
      const response = await this.fetchImpl(endpoint, { method, headers: { Authorization: authorization, Accept: 'application/json', ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
        ...(method === 'POST' ? { body: JSON.stringify(values) } : {}), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404, 428].includes(response.status)) C.fail(response.status, 'Device OU identity authority rejected the request');
      if (response.status !== 200 || !/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Unconfirmed device OU authority');
      const chunks = []; let size = 0;
      for await (const chunk of response.body) { size += chunk.length; if (size > 32768) throw new Error('Oversized device OU source'); chunks.push(Buffer.from(chunk)); }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) { if (error.status) throw error; C.fail(503, 'Device OU identity authority unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
  async read(authorization, user, ouId) {
    if (ouId !== null) C.identifier(ouId);
    const result = await this.request(authorization, user, 'POST', { ouId });
    if (!inventorySourceMatches(result?.inventory, user) || !C.validProof(result, user) || (ouId === null ? result.ou !== null : result.ou?.id !== ouId)) C.fail(503, 'Original selected device OU source unavailable');
    return result;
  }
  async units(authorization, user, tenantId, query) {
    const selected = C.page(query, true), result = await this.request(authorization, user, 'GET', { page: selected.page, search: selected.search });
    if (!C.exact(result, ['schemaVersion', 'deviceOuProtocol', 'actorUserId', 'tenantId', 'units', 'total', 'page', 'limit']) || result.schemaVersion !== 1 || result.deviceOuProtocol !== 1 || result.actorUserId !== user.identity_authorization.userId || result.tenantId !== tenantId
      || result.page !== selected.page || result.limit !== 25 || !Number.isSafeInteger(result.total) || result.total < 0 || !Array.isArray(result.units) || result.units.length !== Math.min(25, Math.max(0, result.total - (selected.page - 1) * 25))
      || result.units.some(unit => !C.validUnit(unit)) || new Set(result.units.map(unit => unit.id)).size !== result.units.length) C.fail(503, 'Own device OU choices unavailable');
    return result;
  }
}
module.exports = { DeviceOuSource };
