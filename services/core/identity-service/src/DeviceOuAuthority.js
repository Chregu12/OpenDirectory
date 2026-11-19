'use strict';

const { DeviceInventoryAuthority } = require('./DeviceInventoryAuthority');
const { DirectoryReader } = require('./DirectoryReader');
const { requireOuReceiver } = require('./AuthorityTenant');
const { deadline } = require('./CompanyRoleAuthority');
const C = require('../../../../packages/device-ou-contract');

class DeviceOuAuthority {
  constructor(database, options = {}) {
    this.database = database;
    this.inventory = new DeviceInventoryAuthority(database, options);
    this.directory = new DirectoryReader(database, options);
  }
  async base(user, authorization) {
    const source = await this.inventory.read(user, authorization);
    if (!source.permissions.includes('devices.inventory.create')) C.fail(403, 'Tenant-wide inventory maintenance required');
    return source;
  }
  async units(query, user, authorization) {
    const selected = C.page(query, true), source = await this.base(user, authorization);
    const result = await this.directory.read(['ous.read'], user, authorization, async (client, tenant) => {
      if (tenant !== source.tenant.id) C.fail(401, 'Original device OU tenant changed');
      await requireOuReceiver(client);
      const where = "FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id AND ownership.tenant_id=$1 WHERE identity_tenant_id('ou',unit.id)=$1 AND ($2='' OR strpos(lower(unit.name),lower($2))>0)";
      const total = Number((await client.query('SELECT count(*) AS count ' + where, [tenant, selected.search])).rows[0].count);
      const units = (await client.query('SELECT unit.id,unit.name,unit.parent_id AS "parentId",unit.revision::text,ownership.generation::text ' + where + ' ORDER BY lower(unit.name),unit.id LIMIT 25 OFFSET $3', [tenant, selected.search, (selected.page - 1) * 25])).rows;
      if (units.some(unit => !C.validUnit(unit))) C.fail(503, 'Canonical OU metadata unavailable');
      return { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: source.actorUserId, tenantId: tenant, units, total, page: selected.page, limit: 25 };
    });
    if (JSON.stringify(source) !== JSON.stringify(await this.base(user, authorization))) C.fail(401, 'Original device OU authority changed');
    return result;
  }
  async target(ouId, source, user, authorization) {
    if (ouId === null) return { ou: null, directoryGrant: null, validUntil: source.validUntil };
    return this.directory.read(['ous.read'], user, authorization, async (client, tenant, captured) => {
      if (tenant !== source.tenant.id) C.fail(401, 'Original device OU tenant changed');
      await requireOuReceiver(client);
      const ou = (await client.query("SELECT unit.id,unit.name,unit.parent_id AS \"parentId\",unit.revision::text,ownership.generation::text FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id AND ownership.tenant_id=$2 WHERE unit.id=$1 AND identity_tenant_id('ou',unit.id)=$2", [ouId, tenant])).rows[0];
      if (!ou) C.fail(404, 'Own organizational unit not found');
      if (!C.validUnit(ou)) C.fail(503, 'Canonical OU metadata unavailable');
      const grants = (captured?.grants || []).filter(grant => grant.permission === 'ous.read').sort((a, b) => deadline(user, { grants: [b] }) - deadline(user, { grants: [a] }) || a.source.id.localeCompare(b.source.id));
      const selected = grants[0];
      return { ou, directoryGrant: selected?.source || null, validUntil: Math.min(source.validUntil, selected ? deadline(user, { grants: [selected] }) : user.exp) };
    });
  }
  async resolve(body, user, authorization) {
    if (!C.exact(body, ['ouId'])) C.fail(400, 'Exact original OU selection required');
    const id = body.ouId === null ? null : C.identifier(body.ouId), inventory = await this.base(user, authorization);
    const target = await this.target(id, inventory, user, authorization);
    if (JSON.stringify(inventory) !== JSON.stringify(await this.base(user, authorization)) || JSON.stringify(target) !== JSON.stringify(await this.target(id, inventory, user, authorization))) C.fail(401, 'Original organizational unit or source changed');
    const result = { schemaVersion: 1, deviceOuProtocol: 1, inventory, ...target };
    if (!C.validProof(result, user)) C.fail(503, 'Original device OU proof unavailable');
    return result;
  }
}
module.exports = { DeviceOuAuthority };
