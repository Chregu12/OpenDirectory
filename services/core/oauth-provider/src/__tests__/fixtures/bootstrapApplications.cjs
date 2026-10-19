'use strict';
const { SigningKeys } = require('../../SigningKeys');
const { IdentityAuthority } = require('../../IdentityAuthority');
const { ApplicationAccess } = require('../../ApplicationAccess');
const { bootstrapApplication } = require('../../../scripts/bootstrap-application-access');
async function bootstrapApplications(database, { issuer,identityBase,signingKeyFile,clients,users }) {
  const keys = new SigningKeys({ privateKeyFile: signingKeyFile,verificationJwksFile: null,production: true,ephemeral: false });
  const identity = new IdentityAuthority({ signingKeys: keys,issuer,endpoint: identityBase + '/internal/identity/authorization-state',production: true,demo: false });
  const access = new ApplicationAccess(database,{ identity,production: true,demo: false });
  for (const clientId of clients) for (const userId of users) await bootstrapApplication(access,{ clientId,userId,durationSeconds: 28800,reason: 'Reviewed disposable application-access fixture bootstrap' },issuer);
}
module.exports = { bootstrapApplications };
