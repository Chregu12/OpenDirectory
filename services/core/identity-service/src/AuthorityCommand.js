'use strict';

const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { beginAuthorityCheckpoint, checkpointError } = require('./AuthorityCheckpoint');

class AuthorityCommand {
  constructor(database, { revalidate } = {}) {
    this.database = database;
    const accessState = createAccessStateClient();
    this.revalidate = revalidate || ((user, authorization) => accessState(authorization, user));
  }

  async run(user, authorization, operation, options, assurance) {
    const original = structuredClone(user);
    await this.revalidate(original, authorization);
    return this.database.transaction(async client => {
      const checkpoint = await beginAuthorityCheckpoint(client, original);
      const result = await operation(client);
      await this.revalidate(original, authorization);
      const required = typeof assurance === 'function' ? assurance(result) : assurance;
      if (required && !acceptsRoleAuthentication(required, original)) {
        throw Object.assign(new Error('fresh_mfa_required'), { status: 428, code: 'fresh_mfa_required' });
      }
      await checkpoint(required);
      return result;
    }, options).catch(checkpointError);
  }
}

module.exports = { AuthorityCommand };
