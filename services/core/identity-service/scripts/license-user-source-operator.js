'use strict';

const { CLIENT_ID } = require('../src/LicenseSourceClients');
const { validUuid } = require('../../../../packages/identity-authorization-contract');

function validateInput(input) {
  const keys = ['issuer', 'clientId', 'tenantId', 'clientRevision', 'expectedVersion', 'enabled', 'reason'];
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== keys.length
    || keys.some(key => !Object.hasOwn(input, key) || typeof input[key] !== (key === 'enabled' ? 'boolean' : 'string'))
    || !CLIENT_ID.test(input.clientId) || !validUuid(input.tenantId) || input.tenantId !== input.tenantId.toLowerCase()
    || !/^[1-9][0-9]{0,18}$/.test(input.clientRevision) || !/^(0|[1-9][0-9]{0,18})$/.test(input.expectedVersion)
    || BigInt(input.clientRevision) > 9223372036854775807n || BigInt(input.expectedVersion) >= 9223372036854775807n
    || input.issuer.length > 2048 || input.issuer !== input.issuer.trim() || /[\s\u0000-\u001f\u007f]/.test(input.issuer)
    || input.reason.length < 10 || input.reason.length > 500 || input.reason !== input.reason.trim() || /[\u0000-\u001f\u007f]/.test(input.reason)) {
    throw new Error('Exact canonical offline license user source review required');
  }
  const authority = new URL(input.issuer);
  if (!['http:', 'https:'].includes(authority.protocol) || !authority.hostname || authority.username || authority.password || authority.search || authority.hash) {
    throw new Error('Explicit bounded HTTP issuer without credentials, query or fragment required');
  }
  return { ...input };
}

function argumentsForOperator(args) {
  const [issuer, clientId, tenantId, clientRevision, expectedVersion, action, reason, ...extra] = args;
  if (extra.length || !['enable', 'disable'].includes(action)) {
    throw new Error('Usage: license-user-source-operator.js ISSUER CLIENT_ID TENANT_UUID CLIENT_REVISION EXPECTED_VERSION enable|disable "reviewed reason (10–500 characters)"');
  }
  return validateInput({ issuer, clientId, tenantId, clientRevision, expectedVersion, enabled: action === 'enable', reason });
}

async function changeSource(database, input) {
  const review = validateInput(input);
  return database.transaction(async client => {
    await client.query("SET LOCAL timezone='UTC'");
    const eventId = (await client.query('SELECT identity_license_user_source_change($1::jsonb) AS event_id', [JSON.stringify(review)])).rows[0]?.event_id;
    const row = (await client.query('SELECT binding.*, identity_license_user_source_valid(binding) AS valid FROM identity_license_user_sources binding WHERE issuer=$1 AND client_id=$2', [review.issuer, review.clientId])).rows[0];
    if (!row?.valid || row.event_id !== eventId || row.tenant_id !== review.tenantId || row.client_revision !== review.clientRevision
      || row.enabled !== review.enabled || BigInt(row.version) !== BigInt(review.expectedVersion) + 1n) throw new Error('Configured license user source change not confirmed');
    return row;
  }, { actor: JSON.stringify({ kind: 'offline-license-user-source', reason: review.reason }) });
}

if (require.main === module) {
  (async () => {
    const input = argumentsForOperator(process.argv.slice(2));
    if (!process.env.IDENTITY_OPERATOR_DATABASE_URL) throw new Error('Explicit IDENTITY_OPERATOR_DATABASE_URL required; no fallback');
    process.env.DATABASE_URL = process.env.IDENTITY_OPERATOR_DATABASE_URL;
    const database = require('../src/db');
    try {
      if (!await database.initDb()) throw new Error('Migrated persistent identity database required');
      process.stdout.write(JSON.stringify(await changeSource(database, input)) + '\n');
    } finally { await database.pool.end(); }
  })().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}

module.exports = { argumentsForOperator, changeSource };
