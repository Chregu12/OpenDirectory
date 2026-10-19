'use strict';

const { validUuid } = require('../../../../packages/identity-authorization-contract');
function argumentsForBootstrap(args) {
  const [clientId,userId,lifetime,reason,...extra] = args; const durationSeconds = Number(lifetime);
  if (extra.length || typeof clientId !== 'string' || !/^[A-Za-z0-9._~-]{1,255}$/.test(clientId) || clientId.trim() !== clientId || !validUuid(userId)
    || !Number.isInteger(durationSeconds) || durationSeconds < 60 || durationSeconds > 28800
    || typeof reason !== 'string' || reason.trim().length < 10 || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) {
    throw new Error('Usage: bootstrap-application-access.js CLIENT_ID CANONICAL_USER_UUID SECONDS "reviewed reason (10–500 characters)"; 60–28800 seconds, no permanent or group bootstrap');
  }
  return { clientId,userId: userId.toLowerCase(),durationSeconds,reason: reason.trim() };
}
async function bootstrapApplication(access, options, issuer) {
  const validated = argumentsForBootstrap([options.clientId,options.userId,String(options.durationSeconds),options.reason]);
  if (typeof issuer !== 'string' || !issuer.trim()) throw new Error('Explicit OAUTH_ISSUER is required');
  return access.bootstrap(validated.clientId,validated.userId,validated.durationSeconds,validated.reason,issuer);
}
if (require.main === module) {
  (async () => {
    const options = argumentsForBootstrap(process.argv.slice(2));
    if (!process.env.OAUTH_BOOTSTRAP_DATABASE_URL || !process.env.OAUTH_ISSUER || !process.env.OAUTH_IDENTITY_AUTHORITY_URL) throw new Error('Explicit OAUTH_BOOTSTRAP_DATABASE_URL, OAUTH_ISSUER and OAUTH_IDENTITY_AUTHORITY_URL are required');
    process.env.DATABASE_URL = process.env.OAUTH_BOOTSTRAP_DATABASE_URL;
    const database = require('../src/db'); const { SigningKeys } = require('../src/SigningKeys');
    const { IdentityAuthority } = require('../src/IdentityAuthority'); const { ApplicationAccess } = require('../src/ApplicationAccess');
    try {
      const signingKeys = new SigningKeys({ production: true, ephemeral: false });
      await database.initDb(); if (!database.isAvailable()) throw new Error('Migrated persistent OAuth storage is required');
      const identity = new IdentityAuthority({ signingKeys,issuer: process.env.OAUTH_ISSUER,production: true,demo: false });
      const access = new ApplicationAccess(database,{ identity,production: true,demo: false });
      process.stdout.write(JSON.stringify(await bootstrapApplication(access,options,process.env.OAUTH_ISSUER)) + '\n');
    } finally { await database.pool.end(); }
  })().catch(error => { process.stderr.write(error.message + '\n'); process.exitCode = 1; });
}
module.exports = { argumentsForBootstrap, bootstrapApplication };
