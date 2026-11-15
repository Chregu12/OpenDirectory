'use strict';
function deviceOuOpenApi() {
  const id = { type: 'string', format: 'uuid' }, revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$', description: 'Positive PostgreSQL BIGINT string, at most 9223372036854775807.' }, time = { type: 'string', format: 'date-time' };
  const ref = name => ({ $ref: '#/components/schemas/' + name }), nullable = value => ({ oneOf: [value, { type: 'null' }] });
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const context = { schemaVersion: { const: 1 }, deviceOuProtocol: { const: 1 }, actorUserId: id, tenantId: id };
  const snapshot = { revision: { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$' }, ou: nullable(ref('DeviceOrganizationalUnit')), updatedAt: nullable(time), updatedBy: nullable(id) };
  const current = { ...context, deviceId: id, deviceRevision: revision, ...snapshot };
  const inventory = require('./inventory-openapi').deviceInventoryOpenApi().components.schemas;
  const schemas = {
    DeviceOrganizationalUnit: object({ id, generation: revision, revision, name: { type: 'string', minLength: 1, maxLength: 255 }, parentId: nullable(id) }),
    DeviceOuSelection: object({ id, generation: revision, revision }),
    DeviceOuAssignment: object(current),
    DeviceOuReceipt: object({ ...current, operationId: id, deliveryStatus: { const: 'pending' } }),
    DeviceOuChoices: object({ ...context, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 }, total: { type: 'integer', minimum: 0 }, units: { type: 'array', maxItems: 25, items: ref('DeviceOrganizationalUnit') } }),
    DeviceOuHistory: object({ ...context, deviceId: id, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 }, total: { type: 'integer', minimum: 0 }, events: { type: 'array', maxItems: 25, items: object({ id, actorUserId: id, correlationId: id, reason: { type: 'string', minLength: 10, maxLength: 500 }, createdAt: time, before: nullable(object(snapshot)), after: object(snapshot), deliveryStatus: { const: 'pending' } }) } }),
    DeviceOuAuthority: object({ schemaVersion: { const: 1 }, deviceOuProtocol: { const: 1 }, inventory: ref('InventoryAuthoritySource'), ou: nullable(ref('DeviceOrganizationalUnit')), directoryGrant: nullable(structuredClone(inventory.DeviceRoleDelegation.properties.grants.items.properties.source)), validUntil: { type: 'integer', description: 'No later than the original inventory, selected directory grant, token and fresh MFA deadlines.' } }),
  };
  const response = (schema, description) => ({ description, headers: { 'Cache-Control': { schema: { const: 'no-store' } } }, content: { 'application/json': { schema } } });
  const error = { type: 'object', additionalProperties: false, required: ['error'], properties: { error: { type: 'string' }, correlationId: id } };
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 413, 428, 503].map(status => [status, response(error, ({ 400: 'Exact input/selectors required', 401: 'Original actor or source changed', 403: 'Separate actual inventory/OU duties required', 404: 'Own device or selected OU absent', 409: 'Unchanged or conflicting assignment', 412: 'Original device, assignment or selected OU version changed; reload, never automatically retry', 413: 'Bounded JSON body required', 428: 'Fresh MFA and exact strong If-Match required', 503: 'Original source or physical receiving evidence unavailable' })[status])]));
  const description = 'Own canonical human bearer and unchanged original source, tenant and MFA deadline are required. Read requires devices.inventory.read; changes require devices.inventory.create and selecting an OU additionally requires independent ous.read. An explicitly upgraded scoped receiver requires both read and stock duties over the before and selected OU; removal requires independent tenant-wide read and stock rights. Outside devices are hidden before metadata, integrity, ETag or state checks. The selected OU UUID, ownership generation and revision must match the explicit confirmation. Original resource bindings retain the inventory revision and before association even after a legitimate OU change. Source/grant replacement, rename or expiry before commit rejects the entire change. Immutable actual effect, event and local pending outbox are checked at physical commit. OU snapshot names and versions describe the assignment time; this metadata does not grant device or PIM access. Default scoped reception remains disabled until hierarchy, GUI and signed scoped browser acceptance. Separate Identity/Device databases do not provide instantaneous distributed revocation.';
  const device = [{ name: 'id', in: 'path', required: true, schema: id }], page = [{ name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 1000000, default: 1 } }];
  const operation = (operationId, summary, schema, parameters = []) => ({ operationId, summary, description, security: [{ bearerAuth: [] }], parameters, responses: { 200: response(schema, summary), ...errors } });
  schemas.DeviceOuReference = object({ id, generation: revision });
  schemas.DeviceOuCurrentStatus = object({ schemaVersion: { const: 1 }, deviceOuStatusProtocol: { const: 1 }, actorUserId: id, tenantId: id, deviceId: id, deviceRevision: revision,
    revision: snapshot.revision, selection: nullable(ref('DeviceOuReference')), state: { enum: ['unassigned', 'current', 'changed', 'not-current'] }, currentOu: nullable(ref('DeviceOrganizationalUnit')), checkedAt: time, validUntil: { type: 'integer', description: 'Original read/source deadline; the displayed check must expire at this time.' } });
  schemas.DeviceOuStatusAuthority = object({ schemaVersion: { const: 1 }, deviceOuStatusProtocol: { const: 1 }, inventory: ref('InventoryAuthoritySource'), selection: nullable(ref('DeviceOuReference')),
    currentOu: nullable(ref('DeviceOrganizationalUnit')), directoryGrant: schemas.DeviceOuAuthority.properties.directoryGrant, validUntil: schemas.DeviceOuAuthority.properties.validUntil });
  const currentStatus = operation('readCurrentOwnDeviceOrganizationalUnitStatus', 'Read the live own OU status for one exact retained device association', ref('DeviceOuCurrentStatus'), [...device, { name: 'If-Match', in: 'header', required: true, schema: { type: 'string' }, description: 'Exact strong ETag of the underlying retained device OU association; both device and assignment versions are checked.' }]);
  currentStatus.description = 'Read-only current OU lookup requires original devices.inventory.read and, for an assigned OU, separate ous.read. No create or assignment right is granted. The server selects the original OU UUID and ownership generation from the actual owned device association. Retired, foreign or replaced-generation resources return not-current without current metadata. Rename, revision and parent changes return changed; current means the saved and live snapshots match. Original inventory/OU grants and the actual local association are revalidated before response; source replacement and concurrent changes reject the read. No device rows, audit events or pending outbox are changed. The reply expires at validUntil. Identity and Device remain separate databases, not an instantaneous distributed revocation transaction.';
  const statusAuthority = operation('resolveOriginalDeviceOuCurrentStatus', 'Resolve original read duties and current own OU metadata for one original reference', ref('DeviceOuStatusAuthority'));
  const scope = require('./device-scope-openapi');
  statusAuthority.parameters.push(structuredClone(scope.header));
  schemas.DeviceOuStatusAuthority.properties.inventory = { oneOf: [ref('InventoryAuthoritySource'), ref('InventoryScopedAuthoritySource')] };
  statusAuthority.description = currentStatus.description + ' ' + scope.description;
  statusAuthority.requestBody = { required: true, content: { 'application/json': { schema: object({ selection: nullable(ref('DeviceOuReference')) }) } } };
  const write = operation('changeOwnDeviceOrganizationalUnit', 'Confirm one current own device OU assignment, move or removal', ref('DeviceOuReceipt'), [...device, { name: 'If-Match', in: 'header', required: true, schema: { type: 'string', pattern: '^"device-ou-[a-f0-9-]{36}-[1-9][0-9]*-(0|[1-9][0-9]*)"$' }, description: 'Exact current device-ou-DEVICE-DEVICE_REVISION-ASSIGNMENT_REVISION ETag.' }]);
  const read = operation('readOwnDeviceOrganizationalUnit', 'Read retained own device OU metadata and exact current versions', ref('DeviceOuAssignment'), device);
  for (const endpoint of [read, write]) endpoint.responses[200].headers.ETag = { schema: { type: 'string' }, description: 'Exact strong device-ou-DEVICE-DEVICE_REVISION-ASSIGNMENT_REVISION version.' };
  write.requestBody = { required: true, content: { 'application/json': { schema: object({ ou: nullable(ref('DeviceOuSelection')), reason: { type: 'string', minLength: 10, maxLength: 500 }, confirm: { const: true } }) } } };
  const privateResolve = operation('resolveOriginalDeviceOuAuthority', 'Resolve the actual original human inventory and selected own OU source', ref('DeviceOuAuthority'));
  const scoped = properties => ({ ...structuredClone(properties), schemaVersion: { const: 2 }, deviceOuProtocol: { const: 2 } });
  const coverage = { enum: ['scope', 'tenant'], description: 'Read and stock intersection; scoped counts cover only permitted target OUs.' };
  schemas.DeviceOuScopedAuthority = object(scoped({ ...schemas.DeviceOuAuthority.properties, inventory: ref('InventoryScopedAuthoritySource') }));
  schemas.DeviceOuScopedReceipt = object({ ...scoped(schemas.DeviceOuReceipt.properties), coverage });
  schemas.DeviceOuScopedChoices = object({ ...scoped(schemas.DeviceOuChoices.properties), coverage, validUntil: schemas.DeviceOuAuthority.properties.validUntil });
  schemas.DeviceOuScopedChoicesAuthority = object({ schemaVersion: { const: 2 }, deviceOuProtocol: { const: 2 }, inventory: ref('InventoryScopedAuthoritySource'), directoryGrant: schemas.DeviceOuAuthority.properties.directoryGrant,
    validUntil: schemas.DeviceOuAuthority.properties.validUntil, coverage, units: schemas.DeviceOuChoices.properties.units, total: schemas.DeviceOuChoices.properties.total, page: schemas.DeviceOuChoices.properties.page, limit: schemas.DeviceOuChoices.properties.limit });
  const either = (first, second) => ({ oneOf: [ref(first), ref(second)] });
  write.responses[200].content['application/json'].schema = either('DeviceOuReceipt', 'DeviceOuScopedReceipt');
  privateResolve.parameters.push(structuredClone(scope.header));
  privateResolve.responses[200].content['application/json'].schema = either('DeviceOuAuthority', 'DeviceOuScopedAuthority');
  privateResolve.requestBody = { required: true, content: { 'application/json': { schema: { oneOf: [object({ ouId: nullable(id) }), object({ ouId: nullable(id), device: nullable(ref('DeviceScopeResource')) })] } } } };
  const choices = operation('readOwnDeviceOrganizationalUnitChoices', 'Read own OU choices with server pagination and search', either('DeviceOuChoices', 'DeviceOuScopedChoices'), [...page, { name: 'search', in: 'query', schema: { type: 'string', maxLength: 255 } }]);
  const privateChoices = operation('readOriginalDeviceOuChoices', 'Read original allowed OU metadata and independent directory evidence for device selection', either('DeviceOuChoices', 'DeviceOuScopedChoicesAuthority'), [...page, { name: 'search', in: 'query', schema: { type: 'string', maxLength: 255 } }, structuredClone(scope.header)]);
  privateChoices.description += ' The private scoped frame retains the original normal inventory source and independent directory grant; Device validates both and removes these fields from its public reply. Server pagination, count and literal name search use the read/stock intersection and current ownership generations.';
  return { paths: {
    '/api/devices/organizational-units': { get: choices },
    '/api/devices/{id}/organizational-unit': { get: read, put: write },
    '/api/devices/{id}/organizational-unit/history': { get: operation('readOwnDeviceOrganizationalUnitHistory', 'Read retained own device OU changes without source tokens', ref('DeviceOuHistory'), [...device, ...page]) },
    '/api/devices/{id}/organizational-unit/status': { get: currentStatus },
    '/api/identity/device-organizational-units/status': { post: statusAuthority },
    '/api/identity/device-organizational-units': { get: privateChoices, post: privateResolve },
  }, components: { schemas } };
}
module.exports = { deviceOuOpenApi };
