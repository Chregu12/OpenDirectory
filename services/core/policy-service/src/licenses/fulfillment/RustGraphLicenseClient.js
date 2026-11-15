'use strict';

const { GraphLicenseClient } = require('./GraphLicenseClient');
const { uuid, plans } = require('./contracts');
const { ProviderError, bearer } = require('./transport');
const { runConnector } = require('./rustConnector');

// Reads and explicitly selected writes share the existing observation/worker contracts.
class RustGraphLicenseClient extends GraphLicenseClient {
  constructor(options) {
    super(options);
    this.binary = options.binary || '/usr/local/bin/opendirectory-connectors';
    this.spawnImpl = options.spawnImpl;
    this.writeEngine = options.writeEngine ?? 'javascript';
    if (!['javascript', 'rust'].includes(this.writeEngine)) throw new Error('Unknown fulfillment write connector engine');
  }

  async readUser(objectId) {
    uuid(objectId);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const accessToken = await this.tokens.get(controller.signal);
      return await runConnector({ binary: this.binary, spawnImpl: this.spawnImpl,
        request: { operation: 'microsoft.user', accessToken, objectId }, signal: controller.signal, stage: 'graph_read', field: 'user' });
    } catch (error) { this.tokens.clear(); throw error; }
    finally { clearTimeout(timer); }
  }

  async mutate(objectId, skuId, disabledPlans, desired, token, attemptId) {
    if (this.writeEngine === 'javascript') return super.mutate(objectId, skuId, disabledPlans, desired, token, attemptId);
    uuid(objectId); uuid(skuId); plans(disabledPlans); uuid(attemptId);
    if (typeof desired !== 'boolean' || !bearer(token)) throw new ProviderError('graph_write_invalid_request');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const result = await runConnector({ binary: this.binary, spawnImpl: this.spawnImpl,
        request: { operation: 'microsoft.assignLicense', accessToken: token, objectId, skuId, disabledPlans, desired, attemptId },
        signal: controller.signal, stage: 'graph_write', field: 'result' });
      if (Object.keys(result).join(',') !== 'id' || result.id !== objectId) throw new ProviderError('graph_write_invalid_response', { uncertain: true });
    } finally { clearTimeout(timer); }
  }
}

function fulfillmentClient(options, engine = process.env.LICENSE_FULFILLMENT_READ_ENGINE || 'javascript', writeEngine = process.env.LICENSE_FULFILLMENT_WRITE_ENGINE || 'javascript') {
  if (!['javascript', 'rust'].includes(engine)) throw new Error('Unknown fulfillment read connector engine');
  if (!['javascript', 'rust'].includes(writeEngine)) throw new Error('Unknown fulfillment write connector engine');
  if (writeEngine === 'rust' && engine !== 'rust') throw new Error('Rust writes require the Rust read connector');
  return new (engine === 'rust' ? RustGraphLicenseClient : GraphLicenseClient)({ ...options, writeEngine });
}

module.exports = { RustGraphLicenseClient, fulfillmentClient };
