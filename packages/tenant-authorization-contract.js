'use strict';

const { validUuid, validRevision } = require('./identity-authorization-contract');
const TENANT_STATE_PATH = '/oauth/tenant-state';

function validTenantContext(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 3
    && validUuid(value.id) && validRevision(value.version) && validRevision(value.generation);
}

function sameTenantContext(first, second) {
  return validTenantContext(first) && validTenantContext(second) && first.id === second.id
    && first.version === second.version && first.generation === second.generation;
}

module.exports = { TENANT_STATE_PATH, validTenantContext, sameTenantContext };
