'use strict';

const { identifier } = require('../../../../packages/company-registration-contract');
function argumentsForOperator(args) {
  const [issuer, userId, version, action, reason, ...extra] = args;
  if (extra.length || typeof issuer !== 'string' || issuer.trim() !== issuer || !/^https?:\/\//.test(issuer) || issuer.length > 2048 || !identifier(userId)
    || !/^(0|[1-9][0-9]{0,17})$/.test(version || '') || !['enable', 'disable'].includes(action) || typeof reason !== 'string' || reason.trim().length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(issuer + reason)) {
    throw new Error('Usage: company-review-operator.js ISSUER USER_UUID EXPECTED_VERSION enable|disable "reviewed reason (10–500 characters)"');
  }
  return { issuer, userId, version, enabled: action === 'enable', reason: reason.trim() };
}
async function changeOperator(database, options) {
  if (typeof options?.enabled !== 'boolean') throw new Error('Explicit boolean reviewer state required');
  const value = argumentsForOperator([options.issuer, options.userId, options.version, options.enabled ? 'enable' : 'disable', options.reason]);
  return database.transaction(async client => {
    await client.query("SET LOCAL timezone='UTC'");
    const result = await client.query('SELECT identity_company_review_operator_change($1,$2,$3::bigint,$4,$5) AS event_id', [value.issuer, value.userId, value.version, value.enabled, value.reason]);
    const row = (await client.query('SELECT *,identity_company_review_operator_valid(operator) AS valid FROM identity_company_review_operators operator WHERE command_id=$1', [result.rows[0]?.event_id])).rows[0];
    if (!row?.valid || row.enabled !== value.enabled || BigInt(row.version) !== BigInt(value.version) + 1n) throw new Error('Reviewer change not confirmed'); return row;
  }, { actor: JSON.stringify({ kind: 'offline-company-review-operator', reason: value.reason }) });
}
if (require.main === module) {
  (async () => {
    const options = argumentsForOperator(process.argv.slice(2));
    if (!process.env.IDENTITY_OPERATOR_DATABASE_URL) throw new Error('Explicit IDENTITY_OPERATOR_DATABASE_URL required; no fallback');
    process.env.DATABASE_URL = process.env.IDENTITY_OPERATOR_DATABASE_URL; const database = require('../src/db');
    try { if (!await database.initDb()) throw new Error('Migrated persistent identity database required'); process.stdout.write(JSON.stringify(await changeOperator(database, options)) + '\n'); }
    finally { await database.pool.end(); }
  })().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
module.exports = { argumentsForOperator, changeOperator };
