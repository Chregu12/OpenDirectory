'use strict';

const { MAX_GRANTS, MAX_UNITS } = require('../../../../packages/device-scope-contract');
const { INVENTORY_PERMISSIONS } = require('../../../../packages/device-inventory-contract');
const { PERMISSIONS: COMPLIANCE_PERMISSIONS } = require('../../../../packages/device-compliance-contract');

const header = { name: 'X-OD-Device-Scope-Protocol', in: 'header', required: false, schema: { const: '1' },
  description: 'Private upgraded receiver opt-in. Absent retains the legacy tenant source; unknown versions return 400. Public device clients do not enable this protocol yet.' };
const description = 'With the explicit private protocol header, Identity may return source schema 2 when a duty depends on device-ou grants. The original bearer, independent MFA age of at most 300 seconds, current original root generations, hierarchy, grant/PIM provenance and earliest expiry remain mandatory. Tenant and inherent duties remain independent. The source is not a reusable credential. Device must independently check actual local association versions and generations; the echoed resource is only a requested binding. Read receivers are implemented behind explicit opt-in; scoped writes, public capabilities and GUI activation are not released.';
function schemas(legacy) {
  const ref = name => ({ $ref: '#/components/schemas/' + name });
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const nullable = value => ({ oneOf: [value, { type: 'null' }] });
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$', description: 'Canonical positive BIGINT decimal, at most 9223372036854775807.' };
  const available = [...INVENTORY_PERMISSIONS, ...COMPLIANCE_PERMISSIONS];
  const base = { id: uuid, roleId: uuid, roleRevision: revision, targetType: { enum: ['user', 'group'] }, targetId: uuid,
    membershipId: nullable(uuid), validUntil: { type: 'string', pattern: '^[1-9][0-9]*$', description: 'Original expiry, no earlier than the source deadline.' } };
  const pim = { activationId: uuid, mfaRevision: revision, authTime: revision, issuer: { type: 'string' }, subject: { type: 'string' }, actorContext: structuredClone(legacy.properties.context) };
  const tenant = { ...base, scopeType: { const: 'tenant' }, ouId: { type: 'null' } };
  const scoped = { ...base, scopeType: { const: 'device-ou' }, ouId: uuid, ouGeneration: revision };
  const source = structuredClone(legacy);
  delete source.properties.delegation;
  source.required.push('scope'); source.properties.schemaVersion = { const: 2 };
  source.properties.scope = ref('DeviceScopeDescriptor');
  source.description = description;
  const compliance = structuredClone(source);
  compliance.properties.permissions = { oneOf: [{ const: [COMPLIANCE_PERMISSIONS[0]] }, { const: [...COMPLIANCE_PERMISSIONS] }] };
  compliance.properties.target = { type: 'null' };
  return {
    DeviceScopeResource: object({ deviceId: uuid, deviceRevision: revision,
      revision: { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$', description: 'Original local association revision, at most BIGINT max. Zero requires ou=null.' }, ou: nullable(ref('DeviceOuReference')) }),
    DeviceScopeDescriptor: { ...object({ protocol: { const: 1 }, inherent: { type: 'array', uniqueItems: true, maxItems: 3, items: { enum: available } },
      grants: { type: 'array', minItems: 1, maxItems: MAX_GRANTS, uniqueItems: true,
        items: object({ permission: { enum: available }, source: { oneOf: [object(tenant), object({ ...tenant, ...pim }), object(scoped), object({ ...scoped, ...pim })] } }) },
      units: { type: 'array', minItems: 1, maxItems: MAX_UNITS, uniqueItems: true,
        items: object({ id: uuid, generation: revision, roots: { type: 'array', minItems: 1, maxItems: MAX_GRANTS, uniqueItems: true, items: uuid } }) },
      resource: nullable(ref('DeviceScopeResource')) }),
    description: 'Canonical permission/source ordering and UUID-sorted current own units/roots. At least one device-ou source; each original root must occur with its original generation. No compliance.manage in scoped grants. Duties equal the inherent/grant union; source expiry cannot exceed any selected original grant/PIM expiry. PIM sources retain the same actor context and independently bound MFA. No private provenance is included in public device DTOs.' },
    InventoryScopedAuthoritySource: source,
    DeviceComplianceScopedAuthoritySource: compliance,
  };
}
module.exports = { header, description, schemas };
