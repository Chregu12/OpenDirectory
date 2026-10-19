'use strict';

const { deviceOffboardingValues } = require('../../../../packages/device-inventory-contract');
const { sameContext } = require('../../../../packages/identity-authorization-contract');
const { sameTenantContext } = require('../../../../packages/tenant-authorization-contract');
const { DeviceInventoryAuthority } = require('./DeviceInventoryAuthority');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class DeviceOffboardingAuthority {
  constructor(database, options = {}) { this.database = database; this.options = options; }
  async read(user, authorization, body) {
    const { workflowId, userId } = deviceOffboardingValues(body);
    if (userId === user?.identity_authorization?.userId) fail(403, 'Self offboarding device returns are forbidden');
    const original = await new DeviceInventoryAuthority(this.database, this.options).read(user, authorization, { userId });
    if (original.target?.enabled !== false) fail(409, 'Original disabled offboarding target required');
    const validate = async client => {
      const bound = { isAvailable: () => true, transaction: operation => operation(client) };
      const source = await new DeviceInventoryAuthority(bound, this.options).read(user, authorization, { userId });
      if (!sameContext(original.context, source.context) || !sameTenantContext(original.tenant, source.tenant)
        || original.issuer !== source.issuer || original.subject !== source.subject || original.actorUserId !== source.actorUserId
        || original.tokenId !== source.tokenId || original.expiresAt !== source.expiresAt || original.validUntil !== source.validUntil
        || JSON.stringify(original.permissions) !== JSON.stringify(source.permissions)) fail(401, 'Original offboarding inventory authority changed');
      if (source.target?.id !== userId || source.target.enabled !== false) fail(409, 'Original disabled offboarding target required');
      const row = (await client.query(`SELECT parent.*,account.eligibility_revision AS current_eligibility_revision
        FROM identity_company_offboarding_receipts parent JOIN users account ON account.id=parent.user_id
        WHERE parent.tenant_id=$1 AND parent.workflow_id=$2 AND parent.user_id=$3 AND account.enabled=false
        AND identity_tenant_id('user',account.id)=$1`, [original.tenant.id, workflowId, userId])).rows[0];
      if (!row || String(row.after_eligibility_revision) !== String(row.current_eligibility_revision)) fail(409, 'Exact original negative account checkpoint required');
      await client.query('SELECT identity_company_offboarding_validate($1,$2,$3)', [original.tenant.id, workflowId, userId]);
      return row;
    };
    let row;
    try {
      row = await this.database.transaction(validate, { readOnly: true, beforeCommit: validate });
      await this.database.transaction(validate, { readOnly: true });
    } catch (error) {
      if (Number.isInteger(error.status)) throw error;
      fail(503, 'Retained offboarding device authority unavailable');
    }
    return { ...original, deviceOffboardingReturnsProtocol: 1,
      target: { id: userId, enabled: false, eligibilityRevision: String(row.after_eligibility_revision) },
      parent: { workflowId: row.workflow_id, tenantId: row.tenant_id, userId: row.user_id, action: row.action, operationId: row.operation_id,
        afterRevision: String(row.after_revision), afterEligibilityRevision: String(row.after_eligibility_revision),
        createdAt: new Date(row.created_at).toISOString(), deliveryStatus: 'pending' } };
  }
}

module.exports = { DeviceOffboardingAuthority };
