'use strict';

function blueprintPreviewOpenApi() {
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const reference = name => ({ $ref: '#/components/schemas/' + name });
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const version = { type: 'integer', minimum: 1, maximum: 2147483647 };
  const platform = { enum: ['windows', 'macos', 'linux'] };
  const selection = object({ id: uuid, version });
  const source = object({ blueprintId: uuid, configurationId: uuid });
  const variant = { payloadJson: { type: 'string', minLength: 2, maxLength: 1048576, description: 'Exact PostgreSQL JSONB object text. Display as opaque text; do not parse and reserialize numbers for equality or delivery. JSONB equality is computed in PostgreSQL, not JavaScript.' }, sources: { type: 'array', minItems: 1, maxItems: 1000, items: source } };
  const configType = { type: 'string', minLength: 1, maxLength: 100 };
  const schemas = {
    BlueprintPreviewRequest: object({ platform, blueprints: { type: 'array', minItems: 1, maxItems: 25, items: selection, description: 'Unique Blueprint IDs, each with its explicitly captured current version. No target, tenant selector, priorities, permissions or desired payloads are accepted.' } }),
    BlueprintPreviewResult: object({ schemaVersion: { const: 1 }, scope: { const: 'selected-blueprint-versions' }, comparison: { const: 'whole-config-type' }, platform,
      previewOnly: { const: true }, enforcementConfirmed: { const: false }, licenseReservations: { const: 0 },
      blueprints: { type: 'array', minItems: 1, maxItems: 25, items: object({ id: uuid, name: { type: 'string', minLength: 1, maxLength: 255 }, platform: { enum: ['all', 'windows', 'macos', 'linux'] }, version }) },
      configurationCount: { type: 'integer', minimum: 0, maximum: 1000 }, hasConflicts: { type: 'boolean' },
      effectiveConfigurations: { type: 'array', maxItems: 1000, items: object({ configType, ...variant }), description: 'Only types with one distinct JSONB payload. Conflicting types have no winner; identical payloads retain every original source.' },
      conflicts: { type: 'array', maxItems: 500, items: object({ configType, variants: { type: 'array', minItems: 2, maxItems: 1000, items: object(variant) } }) } }),
  };
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 503].map(status => [status, { description: ({
    400: 'Exact bounded request required', 401: 'Original human session or authority no longer valid', 403: 'Canonical human policies.preview permission required',
    404: 'Selected current Blueprint no longer exists', 409: 'Selected platform mismatch or aggregate limit exceeded; no partial preview',
    412: 'Selected current version changed; explicitly reload and select again', 503: 'Canonical database, authority or stored evidence unavailable',
  })[status], content: { 'application/json': { schema: object({ error: { type: 'string' } }) } } }]));
  return { paths: { '/api/blueprints/preview': { post: { operationId: 'previewSelectedBlueprintVersions', summary: 'Compare actual selected Blueprint versions without effects',
    description: 'Existing explicit platform-policy authority only, not implicit company-owner rights. One repeatable-read/read-only PostgreSQL snapshot with original authority checks. Limits: 25 unique Blueprints, 1000 original configurations and 1 MiB aggregate original UTF-8 JSONB payload text; never truncates. Same config_type and database-equal payloads deduplicate; different payloads conflict with no priority or deep merge. Conservative one-profile-per-type comparison, including Wi-Fi/VPN; not Apple validation, target/group applicability, immutable historical versions, publication approval, deployment or license reservation. Results are point-in-time observations, never authorization tokens. Internal conflicts also block single-Blueprint /apply before delivery and canonical receiver admission; conflicts across other assigned Blueprints are not automatically checked.',
    security: [{ bearerAuth: [] }], requestBody: { required: true, content: { 'application/json': { schema: reference('BlueprintPreviewRequest') } } },
    responses: { 200: { description: 'Complete bounded comparison of exact current versions in input order', headers: { 'Cache-Control': { schema: { type: 'string', const: 'no-store' } } }, content: { 'application/json': { schema: reference('BlueprintPreviewResult') } } }, ...errors } } } }, components: { schemas } };
}

module.exports = { blueprintPreviewOpenApi };
