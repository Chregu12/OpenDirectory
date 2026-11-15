'use strict';

const { DeviceInventoryAuthority } = require('./DeviceInventoryAuthority');
const { DirectoryReader } = require('./DirectoryReader');
const { requireOuReceiver } = require('./AuthorityTenant');
const { deadline } = require('./CompanyRoleAuthority');
const C = require('../../../../packages/device-ou-contract');
const Scope = require('../../../../packages/device-scope-contract');
function directoryEvidence(captured, user, source) {
  const grants = (captured?.grants || []).filter(grant => grant.permission === 'ous.read').sort((a, b) => deadline(user, { grants: [b] }) - deadline(user, { grants: [a] }) || a.source.id.localeCompare(b.source.id));
  const selected = grants[0];
  return { directoryGrant: selected?.source || null, validUntil: Math.min(source.validUntil, selected ? deadline(user, { grants: [selected] }) : user.exp) };
}

class DeviceOuAuthority {
  constructor(database, options = {}) {
    this.database = database;
    this.inventory = new DeviceInventoryAuthority(database, options);
    this.directory = new DirectoryReader(database, options);
  }
  async base(user, authorization, permission = 'devices.inventory.create', scoped = false, device = null) {
    const source = await this.inventory[scoped?'readScoped':'read'](user, authorization, device === null ? null : { userId: null, device });
    if (!source.permissions.includes(permission)) C.fail(403, 'Required tenant inventory duty unavailable');
    return source;
  }
  unitsScoped(query, user, authorization) { return this.units(query, user, authorization, true); }
  async units(query, user, authorization, scoped = false) {
    const selected = C.page(query, true), source = await this.base(user, authorization, 'devices.inventory.create', scoped);
    const allowed = source.schemaVersion === 2 && !C.permitsOu(source, null) ? source.scope.units.filter(unit => C.permitsOu(source, unit)).map(({id, generation}) => ({id, generation})) : null;
    const result = await this.directory.read(['ous.read'], user, authorization, async (client, tenant, captured) => {
      if (tenant !== source.tenant.id) C.fail(401, 'Original device OU tenant changed');
      await requireOuReceiver(client);
      const where = "FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id AND ownership.tenant_id=$1 WHERE identity_tenant_id('ou',unit.id)=$1 AND ($2='' OR strpos(lower(unit.name),lower($2))>0) AND ($3::jsonb IS NULL OR EXISTS(SELECT 1 FROM jsonb_to_recordset($3::jsonb) AS permitted(id uuid,generation text) WHERE permitted.id=unit.id AND permitted.generation=ownership.generation::text))";
      const parameters = [tenant, selected.search, allowed === null ? null : JSON.stringify(allowed)];
      const total = Number((await client.query('SELECT count(*) AS count ' + where, parameters)).rows[0].count);
      const units = (await client.query('SELECT unit.id,unit.name,unit.parent_id AS "parentId",unit.revision::text,ownership.generation::text ' + where + ' ORDER BY lower(unit.name),unit.id LIMIT 25 OFFSET $4', [...parameters, (selected.page - 1) * 25])).rows;
      if (units.some(unit => !C.validUnit(unit))) C.fail(503, 'Canonical OU metadata unavailable');
      return source.schemaVersion === 2 ? { schemaVersion: 2, deviceOuProtocol: 2, inventory: source, ...directoryEvidence(captured, user, source), coverage: C.coverage(source), units, total, page: selected.page, limit: 25 }
        : { schemaVersion: 1, deviceOuProtocol: 1, actorUserId: source.actorUserId, tenantId: tenant, units, total, page: selected.page, limit: 25 };
    });
    if (JSON.stringify(source) !== JSON.stringify(await this.base(user, authorization, 'devices.inventory.create', scoped))) C.fail(401, 'Original device OU authority changed');
    if (source.schemaVersion === 2 && !C.validChoices(result, user)) C.fail(503, 'Original scoped OU choices unavailable');
    return result;
  }
  async target(ouId, source, user, authorization) {
    if (source.schemaVersion === 2 && (ouId === null ? !C.permitsOu(source, null) : !C.permitsOu(source, null) && !source.scope.units.some(unit => unit.id === ouId && C.permitsOu(source, unit)))) C.fail(ouId === null ? 403 : 404, 'Organizational unit outside original device scope');
    if (ouId === null) return { ou: null, directoryGrant: null, validUntil: source.validUntil };
    return this.directory.read(['ous.read'], user, authorization, async (client, tenant, captured) => {
      if (tenant !== source.tenant.id) C.fail(401, 'Original device OU tenant changed');
      await requireOuReceiver(client);
      const ou = (await client.query("SELECT unit.id,unit.name,unit.parent_id AS \"parentId\",unit.revision::text,ownership.generation::text FROM ous unit JOIN identity_tenant_ownership ownership ON ownership.resource_kind='ou' AND ownership.resource_id=unit.id AND ownership.tenant_id=$2 WHERE unit.id=$1 AND identity_tenant_id('ou',unit.id)=$2", [ouId, tenant])).rows[0];
      if (!ou) C.fail(404, 'Own organizational unit not found');
      if (!C.validUnit(ou)) C.fail(503, 'Canonical OU metadata unavailable');
      if (!C.permitsOu(source, ou)) C.fail(404, 'Organizational unit outside original device scope');
      return { ou, ...directoryEvidence(captured, user, source) };
    });
  }
  resolveScoped(body, user, authorization) { return this.resolve(body, user, authorization, true); }
  async resolve(body, user, authorization, scoped = false) {
    if (!C.exact(body, ['ouId']) && !(scoped && C.exact(body, ['ouId', 'device']) && Scope.resource(body.device))) C.fail(400, 'Exact original OU selection required');
    const device = body.device ?? null;
    const id = body.ouId === null ? null : C.identifier(body.ouId), inventory = await this.base(user, authorization, 'devices.inventory.create', scoped, device);
    const target = await this.target(id, inventory, user, authorization);
    if (JSON.stringify(inventory) !== JSON.stringify(await this.base(user, authorization, 'devices.inventory.create', scoped, device)) || JSON.stringify(target) !== JSON.stringify(await this.target(id, inventory, user, authorization))) C.fail(401, 'Original organizational unit or source changed');
    const result = { schemaVersion: inventory.schemaVersion, deviceOuProtocol: inventory.schemaVersion, inventory, ...target };
    if (!C.validProof(result, user)) C.fail(503, 'Original device OU proof unavailable');
    return result;
  }
  async status(body, user, authorization, scoped = false) {
    if (!C.exact(body, ['selection']) || body.selection !== null && !C.validReference(body.selection)) C.fail(400, 'Exact original OU reference required');
    const selection = body.selection, inventory = await this.base(user, authorization, 'devices.inventory.read',scoped);
    const target = async () => {
      if (selection === null) return { currentOu: null, directoryGrant: null, validUntil: inventory.validUntil };
      return this.directory.read(['ous.read'], user, authorization, async (client, tenant, captured) => {
        if (tenant !== inventory.tenant.id) C.fail(401, 'Original device OU tenant changed');
        await requireOuReceiver(client);
        const unit = (await this.directory.readOus(client, tenant, selection.id))[0];
        const owned = unit && (await client.query("SELECT generation::text FROM identity_tenant_ownership WHERE resource_kind='ou' AND resource_id=$1 AND tenant_id=$2 AND generation=$3::bigint", [selection.id, tenant, selection.generation])).rows[0];
        const currentOu = owned ? { id: unit.id, generation: owned.generation, revision: unit.revision, name: unit.name, parentId: unit.parentId ?? null } : null;
        if (currentOu && !C.validUnit(currentOu)) C.fail(503, 'Canonical current OU unavailable');
        return { currentOu, ...directoryEvidence(captured, user, inventory) };
      });
    };
    const captured = await target();
    if (JSON.stringify(inventory) !== JSON.stringify(await this.base(user, authorization, 'devices.inventory.read',scoped)) || JSON.stringify(captured) !== JSON.stringify(await target())) C.fail(401, 'Original current OU or source changed');
    const result = { schemaVersion: 1, deviceOuStatusProtocol: 1, inventory, selection, ...captured };
    if (!C.validStatusProof(result, user)) C.fail(503, 'Original current OU proof unavailable');
    return result;
  }
}
module.exports = { DeviceOuAuthority };
