'use strict';

const { deviceOffboardingValues } = require('../../../../packages/device-inventory-contract');
const { isDeepStrictEqual } = require('node:util');
const Scope = require('../../../../packages/device-scope-contract');
const { DeviceInventoryAuthority } = require('./DeviceInventoryAuthority');

function fail(status, message) { throw Object.assign(new Error(message), { status }); }
class DeviceOffboardingAuthority {
  constructor(database, options = {}) { this.database = database; this.options = options; }
  async readScoped(user, authorization, body) { return this.read(user, authorization, body, true); }
  async read(user, authorization, body, scoped = false) {
    if(!body || typeof body!=='object' || Array.isArray(body))fail(400,'Exact offboarding device source required');
    const values={...body},selected=scoped && Object.hasOwn(values,'device')?values.device:null;
    if(scoped)delete values.device;
    const { workflowId, userId } = deviceOffboardingValues(values);
    if(!Scope.resource(selected))fail(400,'Exact scoped device resource required');
    const target=scoped && selected!==null?{userId,device:selected}:{userId};
    const method=scoped?'readScoped':'read';
    if (userId === user?.identity_authorization?.userId) fail(403, 'Self offboarding device returns are forbidden');
    const original = await new DeviceInventoryAuthority(this.database, this.options)[method](user, authorization, target);
    if(!original.permissions.includes('devices.inventory.read')||!original.permissions.includes('devices.inventory.assign'))fail(403,'Device return management required');
    if (original.target?.enabled !== false) fail(409, 'Original disabled offboarding target required');
    const validate = async client => {
      const bound = { isAvailable: () => true, transaction: operation => operation(client) };
      const source = await new DeviceInventoryAuthority(bound, this.options)[method](user, authorization, target);
      // Target role cleanup may advance authorization; the retained negative eligibility is checked separately.
      if (!isDeepStrictEqual({ ...original, target: null }, { ...source, target: null })) fail(401, 'Original offboarding inventory authority changed');
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
    return { ...(original.schemaVersion===2?{schemaVersion:2,deviceOffboardingReturnsProtocol:2,inventory:original}:{...original,deviceOffboardingReturnsProtocol:1}),
      target: { id: userId, enabled: false, eligibilityRevision: String(row.after_eligibility_revision) },
      parent: { workflowId: row.workflow_id, tenantId: row.tenant_id, userId: row.user_id, action: row.action, operationId: row.operation_id,
        afterRevision: String(row.after_revision), afterEligibilityRevision: String(row.after_eligibility_revision),
        createdAt: new Date(row.created_at).toISOString(), deliveryStatus: 'pending' } };
  }
}

module.exports = { DeviceOffboardingAuthority };
