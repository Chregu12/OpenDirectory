'use strict';

const { uuid } = require('../src/licenses/fulfillment/contracts');
const { ProviderError } = require('../src/licenses/fulfillment/transport');

// A separate read-only command: no worker sweep, write intent or mutate call.
async function probe({ store, config, graph, targetId }) {
  uuid(targetId);
  const connector = await store.get('connectors', config.connectorId);
  const row = await store.row(targetId);
  if (connector.tenantId !== config.tenantId || !row?.enabled || row.business_tenant_id != null
    || row.connector_id !== config.connectorId || row.tenant_id !== config.tenantId || graph.tenantId !== row.tenant_id) {
    throw new ProviderError('graph_probe_binding_rejected');
  }
  if (!await store.available(config.connectorId)) throw new ProviderError('graph_probe_backoff_active');
  return { targetId, tenantId: config.tenantId, observation: await graph.inspect(row.object_id, row.sku_id, row.disabled_plans) };
}

async function main() {
  if (process.argv.length !== 3) throw new Error('One bound target UUID is required');
  const targetId = uuid(process.argv[2]);
  const { configuration } = require('../src/licenses/fulfillment/WorkerConfiguration');
  const config = configuration(process.env.LICENSE_FULFILLMENT_CONFIG_FILE);
  if (!process.env.DATABASE_URL) throw new Error('Explicit worker database required');
  const database = require('../src/db/postgres');
  try {
    await require('../src/licenses/fulfillment/databasePrivileges').assertWorkerDatabase(database);
    const { LicenseAllocator } = require('../src/licenses/LicenseAllocator');
    const { ProviderStore } = require('../src/licenses/fulfillment/ProviderStore');
    const { fulfillmentClient } = require('../src/licenses/fulfillment/RustGraphLicenseClient');
    const graph = fulfillmentClient({ tenantId: config.tenantId, clientId: config.graphClientId, clientSecret: config.graphClientSecret }, 'rust');
    const result = await probe({ store: new ProviderStore(new LicenseAllocator(database)), config, graph, targetId });
    process.stdout.write(JSON.stringify(result) + '\n');
  } finally { await database.shutdown(); }
}

if (require.main === module) main().catch(error => {
  const code = error instanceof ProviderError && /^graph_[a-z0-9_]{1,100}$/.test(error.code) ? error.code : 'probe_configuration_rejected';
  process.stderr.write(JSON.stringify({ ok: false, code, ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}) }) + '\n');
  process.exitCode = 1;
});

module.exports = { probe };
