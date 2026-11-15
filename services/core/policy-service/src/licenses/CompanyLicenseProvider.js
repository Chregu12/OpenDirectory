'use strict';

const { isDeepStrictEqual } = require('node:util');
const { identifier } = require('../../../../../packages/company-license-contract');
const { configuration } = require('./providers/ReadConfiguration');
const { ProviderReadClient } = require('./providers/ProviderReadClient');
const { ProviderError } = require('./fulfillment/transport');

class CompanyLicenseProvider {
  constructor(store, { tenantId = process.env.LICENSE_COMPANY_PROVIDER_TENANT_ID,
    filename = process.env.LICENSE_COMPANY_PROVIDER_CONFIG_FILE, load = configuration,
    createClient = config => new ProviderReadClient(config) } = {}) {
    this.store = store; this.tenantId = tenantId; this.filename = filename; this.load = load; this.createClient = createClient;
  }

  async inspect(user, authorization, signal) {
    return this.store.read(user, authorization, async (_client, source) => {
      const envelope = { schemaVersion: 1, companyLicenseProviderProtocol: 1, actorUserId: source.actorUserId,
        tenantId: source.tenant.id, provider: 'microsoft-365' };
      if (!this.tenantId && !this.filename) return { ...envelope, state: 'not_configured' };
      if (!this.tenantId || !this.filename) throw Object.assign(new Error('Incomplete company provider configuration'), { status: 503 });
      try { identifier(this.tenantId); } catch { throw Object.assign(new Error('Invalid company provider binding'), { status: 503 }); }
      if (this.tenantId !== source.tenant.id) return { ...envelope, state: 'not_configured' };
      const currentConfiguration = () => {
        try {
          const config = this.load(this.filename);
          if (config.provider !== 'microsoft-365') throw new Error();
          return config;
        } catch { throw Object.assign(new Error('Company provider configuration unavailable'), { status: 503 }); }
      };
      const config = currentConfiguration(); let result;
      try {
        const products = await this.createClient(config).inspect(signal);
        result = { ...envelope, state: 'connected', microsoftTenantId: config.tenantId, checkedAt: new Date().toISOString(), products };
      } catch (error) {
        if (!(error instanceof ProviderError) || !/^graph_capacity_[a-z0-9_]{1,80}$/.test(error.code)) throw error;
        result = { ...envelope, state: 'failed', errorCode: error.code,
          ...(Number.isInteger(error.retryAfter) && error.retryAfter >= 1 && error.retryAfter <= 3600 ? { retryAfter: error.retryAfter } : {}) };
      }
      if (!isDeepStrictEqual(config, currentConfiguration())) throw Object.assign(new Error('Company provider configuration changed'), { status: 503 });
      return result;
    });
  }
}

module.exports = { CompanyLicenseProvider };
