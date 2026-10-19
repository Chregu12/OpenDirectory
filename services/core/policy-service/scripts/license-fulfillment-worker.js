'use strict';

const database=require('../src/db/postgres');
const { LicenseAllocator }=require('../src/licenses/LicenseAllocator');
const { ProviderStore }=require('../src/licenses/fulfillment/ProviderStore');
const { GraphLicenseClient }=require('../src/licenses/fulfillment/GraphLicenseClient');
const { configuration,WorkerIdentity }=require('../src/licenses/fulfillment/WorkerConfiguration');
const { FulfillmentWorker }=require('../src/licenses/fulfillment/FulfillmentWorker');
const { assertWorkerDatabase }=require('../src/licenses/fulfillment/databasePrivileges');
async function main() {
  const config=configuration(process.env.LICENSE_FULFILLMENT_CONFIG_FILE);
  if (!process.env.DATABASE_URL) throw new Error('An explicitly provisioned fulfillment database identity is required');
  const poolLimit=process.env.PG_POOL_MAX||'20';
  if (!/^[1-9][0-9]?$/.test(poolLimit) || Number(poolLimit)<3 || Number(poolLimit)>20) throw new Error('Fulfillment requires a database pool of three to twenty connections');
  await database.query('SELECT id FROM license_fulfillment_targets LIMIT 0');
  await assertWorkerDatabase(database);
  const store=new ProviderStore(new LicenseAllocator(database));
  const connector=await store.get('connectors',config.connectorId);
  if (connector.tenantId!==config.tenantId) throw new Error('Worker configuration must match its immutable connector tenant');
  const identity=new WorkerIdentity(config);
  const graph=new GraphLicenseClient({ tenantId:config.tenantId,clientId:config.graphClientId,clientSecret:config.graphClientSecret });
  const worker=new FulfillmentWorker({ store,identity,graph,connectorId:config.connectorId,tenantId:config.tenantId,sourceClientId:config.sourceClientId });
  let stopped=false; let wake=null;
  const stop=()=>{ stopped=true; worker.stop(); if (wake) wake(); };
  process.once('SIGTERM',stop); process.once('SIGINT',stop);
  while (!stopped) {
    try { await worker.sweep(); } catch { process.stderr.write('License fulfillment sweep failed; no success was acknowledged.\n'); }
    if (!stopped) await new Promise(resolve=>{ const timer=setTimeout(resolve,30000); wake=()=>{ clearTimeout(timer); resolve(); }; });
  }
  await database.shutdown();
}
if (require.main===module) main().catch(async()=>{ process.stderr.write('License fulfillment startup rejected. Check protected configuration and migrated storage.\n'); await database.shutdown(); process.exitCode=1; });
module.exports = { main };
