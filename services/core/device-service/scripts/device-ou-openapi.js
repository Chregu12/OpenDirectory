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
  const description = 'Own canonical human bearer and unchanged original source, tenant and MFA deadline are required. Read requires devices.inventory.read; changes require tenant-wide devices.inventory.create and selecting an OU additionally requires ous.read. The selected OU UUID, ownership generation and revision must match the explicit confirmation. Source/grant replacement, rename or expiry before commit rejects the entire change. Immutable actual effect, event and local pending outbox are checked at physical commit. OU snapshot names and versions describe the assignment time; this metadata does not grant device or PIM access. Device OU/group access scopes remain separate work. Separate Identity/Device databases do not provide instantaneous distributed revocation.';
  const device = [{ name: 'id', in: 'path', required: true, schema: id }], page = [{ name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 1000000, default: 1 } }];
  const operation = (operationId, summary, schema, parameters = []) => ({ operationId, summary, description, security: [{ bearerAuth: [] }], parameters, responses: { 200: response(schema, summary), ...errors } });
  const write = operation('changeOwnDeviceOrganizationalUnit', 'Confirm one current own device OU assignment, move or removal', ref('DeviceOuReceipt'), [...device, { name: 'If-Match', in: 'header', required: true, schema: { type: 'string', pattern: '^"device-ou-[a-f0-9-]{36}-[1-9][0-9]*-(0|[1-9][0-9]*)"$' }, description: 'Exact current device-ou-DEVICE-DEVICE_REVISION-ASSIGNMENT_REVISION ETag.' }]);
  const read = operation('readOwnDeviceOrganizationalUnit', 'Read retained own device OU metadata and exact current versions', ref('DeviceOuAssignment'), device);
  for (const endpoint of [read, write]) endpoint.responses[200].headers.ETag = { schema: { type: 'string' }, description: 'Exact strong device-ou-DEVICE-DEVICE_REVISION-ASSIGNMENT_REVISION version.' };
  write.requestBody = { required: true, content: { 'application/json': { schema: object({ ou: nullable(ref('DeviceOuSelection')), reason: { type: 'string', minLength: 10, maxLength: 500 }, confirm: { const: true } }) } } };
  const privateResolve = operation('resolveOriginalDeviceOuAuthority', 'Resolve the actual original human inventory and selected own OU source', ref('DeviceOuAuthority'));
  privateResolve.requestBody = { required: true, content: { 'application/json': { schema: object({ ouId: nullable(id) }) } } };
  return { paths: {
    '/api/devices/organizational-units': { get: operation('readOwnDeviceOrganizationalUnitChoices', 'Read own OU choices with server pagination and search', ref('DeviceOuChoices'), [...page, { name: 'search', in: 'query', schema: { type: 'string', maxLength: 255 } }]) },
    '/api/devices/{id}/organizational-unit': { get: read, put: write },
    '/api/devices/{id}/organizational-unit/history': { get: operation('readOwnDeviceOrganizationalUnitHistory', 'Read retained own device OU changes without source tokens', ref('DeviceOuHistory'), [...device, ...page]) },
    '/api/identity/device-organizational-units': { get: operation('readOriginalDeviceOuChoices', 'Read original own-tenant OU metadata for device selection', ref('DeviceOuChoices'), [...page, { name: 'search', in: 'query', schema: { type: 'string', maxLength: 255 } }]), post: privateResolve },
  }, components: { schemas } };
}
module.exports = { deviceOuOpenApi };
