'use strict';

const { GraphLicenseClient } = require('./GraphLicenseClient');
const { uuid } = require('./contracts');
const { runConnector } = require('./rustConnector');

// Only the read transport changes. Observation and reviewed writes stay shared.
class RustGraphLicenseClient extends GraphLicenseClient {
  constructor(options) {
    super(options);
    this.binary = options.binary || '/usr/local/bin/opendirectory-connectors';
    this.spawnImpl = options.spawnImpl;
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
}

function fulfillmentClient(options, engine = process.env.LICENSE_FULFILLMENT_READ_ENGINE || 'javascript') {
  if (!['javascript', 'rust'].includes(engine)) throw new Error('Unknown fulfillment read connector engine');
  return new (engine === 'rust' ? RustGraphLicenseClient : GraphLicenseClient)(options);
}

module.exports = { RustGraphLicenseClient, fulfillmentClient };
