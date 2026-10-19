'use strict';

const { COMPANY_BLUEPRINT_PERMISSIONS, PLATFORMS, CONFIGURATION_TYPES } = require('../../../../packages/company-blueprint-contract');
function companyBlueprintOpenApi() {
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const reference = name => ({ $ref: '#/components/schemas/' + name });
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$', description: 'Canonical positive PostgreSQL int8, at most 9223372036854775807; never converted to a JSON number.' };
  const version = { type: 'integer', minimum: 1, maximum: 2147483647 };
  const timestamp = { type: 'string', format: 'date-time', description: 'Canonical UTC ISO timestamp.' };
  const nullable = schema => ({ anyOf: [schema, { type: 'null' }] });
  const text = (minimum, maximum) => ({ type: 'string', minLength: minimum, maxLength: maximum, description: 'Already trimmed, no C0/C1 control characters; lengths count Unicode code points.' });
  const actor = { schemaVersion: { const: 1 }, actorUserId: uuid, tenantId: uuid };
  const page = { total: { type: 'integer', minimum: 0 }, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 } };
  const draft = object({ name: text(1, 160), description: text(0, 2000), platform: { enum: [...PLATFORMS] },
    configurations: { type: 'array', maxItems: 25, items: object({ id: uuid, type: { enum: [...CONFIGURATION_TYPES] }, name: text(1, 160),
      payloadJson: { type: 'string', minLength: 2, maxLength: 65536, description: 'Exactly one supported non-secret JSON object: screen_lock {minutes:integer 1..1440,requirePassword:boolean}; filevault {enabled:boolean}; software_update {automatic:boolean,deferralDays:integer 0..365}. No extra or duplicate keys, decimal/exponent number literals, strings, nested data, credentials or secret references. Maximum 64 KiB UTF-8 each and 256 KiB aggregate; no provider validation or device action is implied.' } }) },
    appPoolIds: { type: 'array', maxItems: 25, uniqueItems: true, items: uuid, description: 'Desired own-company application pool references only. No seat reservation, allocation, installation or provider execution.' } });
  const summary = { id: uuid, tenantId: uuid, name: text(1, 160), platform: { enum: [...PLATFORMS] }, revision, publishedVersion: nullable(version), draftChanged: { type: 'boolean' }, configurationCount: { type: 'integer', minimum: 0, maximum: 25 }, appCount: { type: 'integer', minimum: 0, maximum: 25 }, createdAt: timestamp, updatedAt: timestamp };
  const versionMetadata = { version, sourceRevision: revision, publishedRevision: revision, actorUserId: uuid, operationId: uuid, createdAt: timestamp };
  const previewSource = object({ blueprintId: uuid, configurationId: uuid });
  const variant = { payloadJson: { type: 'string' }, sources: { type: 'array', minItems: 1, maxItems: 25, items: previewSource } };
  const preview = object({ configurationCount: { type: 'integer', minimum: 0, maximum: 25 }, hasConflicts: { type: 'boolean' },
    effectiveConfigurations: { type: 'array', maxItems: 3, items: object({ configType: { enum: [...CONFIGURATION_TYPES] }, ...variant }) },
    conflicts: { type: 'array', maxItems: 3, items: object({ configType: { enum: [...CONFIGURATION_TYPES] }, variants: { type: 'array', minItems: 2, maxItems: 25, items: object(variant) } }) } });
  const schemas = {
    CompanyBlueprintDraft: draft,
    CompanyBlueprintCapabilities: object({ ...actor, companyBlueprintProtocol: { const: 1 }, permissions: { type: 'array', const: [...COMPANY_BLUEPRINT_PERMISSIONS] }, configurationMode: { const: 'local-only' }, maxConfigurations: { const: 25 }, maxApplications: { const: 25 } }),
    CompanyBlueprintSummary: object(summary),
    CompanyBlueprintRecord: object({ id: uuid, tenantId: uuid, revision, publishedVersion: nullable(version), draftChanged: { type: 'boolean' }, draft: reference('CompanyBlueprintDraft'), createdAt: timestamp, updatedAt: timestamp, preview }),
    CompanyBlueprintPage: object({ ...actor, blueprints: { type: 'array', maxItems: 25, items: reference('CompanyBlueprintSummary') }, ...page }),
    CompanyBlueprintDetail: object({ ...actor, blueprint: reference('CompanyBlueprintRecord') }),
    CompanyBlueprintReceipt: object({ ...actor, operationId: uuid, blueprintId: uuid, revision, publishedVersion: nullable(version), action: { enum: ['created', 'updated', 'published', 'restored'] }, outcome: { enum: ['applied', 'already_applied'] }, deliveryStatus: { const: 'pending' } }),
    CompanyBlueprintVersionMetadata: object(versionMetadata),
    CompanyBlueprintVersion: object({ ...versionMetadata, draft: reference('CompanyBlueprintDraft'), apps: { type: 'array', maxItems: 25, items: object({ id: uuid, name: text(1, 160), vendor: text(1, 160), revision }), description: 'Immutable actual own-catalog metadata at release. Captured pool revision is provenance, not a validity lease; later allocation or stock changes do not invalidate this version.' } }),
    CompanyBlueprintVersionPage: object({ ...actor, blueprintId: uuid, versions: { type: 'array', maxItems: 25, items: reference('CompanyBlueprintVersionMetadata') }, ...page }),
    CompanyBlueprintVersionDetail: object({ ...actor, blueprintId: uuid, version: reference('CompanyBlueprintVersion') }),
    CompanyBlueprintEvent: object({ id: uuid, tenantId: uuid, type: { enum: ['blueprint.created', 'blueprint.draft.updated', 'blueprint.published', 'blueprint.draft.restored'] }, version: { const: 1 }, blueprintId: uuid, actorUserId: uuid, correlationId: uuid, createdAt: timestamp, beforeRevision: nullable(revision), afterRevision: revision, releasedVersion: nullable(version), restoredFrom: nullable(version), reason: text(10, 500), deliveryStatus: { const: 'pending' } }),
    CompanyBlueprintHistory: object({ ...actor, blueprintId: uuid, events: { type: 'array', maxItems: 25, items: reference('CompanyBlueprintEvent') }, ...page }),
    CompanyBlueprintSource: object({ schemaVersion: { const: 1 }, companyBlueprintProtocol: { const: 1 }, issuer: text(1, 2048), subject: text(1, 255), tokenId: text(1, 255), expiresAt: { type: 'integer', minimum: 1 },
      context: object({ userId: uuid, revision, linkRevision: revision, rolesRevision: { type: 'string', pattern: '^[a-f0-9]{64}$' } }), tenant: object({ id: uuid, version: revision, generation: revision }), actorUserId: uuid,
      permissions: { type: 'array', const: [...COMPANY_BLUEPRINT_PERMISSIONS] }, validUntil: { type: 'integer', minimum: 1, description: 'No later than original token expiry, original verified MFA deadline, or observed now+300. No refresh extends the original MFA proof.' } }),
  };
  const json = schema => ({ content: { 'application/json': { schema } } });
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 428, 503].map(status => [status, { description: ({
    400: 'Exact request, canonical Idempotency-Key or safe typed values required', 401: 'Original human or tenant authority changed', 403: 'Actual current own-company owner or canonical home-administration required',
    404: 'Own resource or application reference unavailable; foreign identifiers reveal no resource', 409: 'Conflict, empty release, unchanged draft, immutable intent mismatch or concurrent operation',
    412: 'Captured parent revision changed; explicitly reload, never silently retry with a refreshed ETag', 428: 'Fresh independently verified MFA within 300 seconds and required If-Match missing', 503: 'Canonical source, retained evidence or supported receiving unavailable',
  })[status], ...json(object({ error: { type: 'string' }, correlationId: uuid })) }]));
  const parameters = [{ name: 'id', in: 'path', required: true, schema: uuid }];
  const paging = [{ name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 1000000, default: 1 } }, { name: 'limit', in: 'query', schema: { type: 'integer', const: 25, default: 25 } }];
  const reply = (schema, description, detail = false) => ({ description, ...json(reference(schema)), headers: { 'Cache-Control': { schema: { type: 'string', const: 'no-store' } }, 'X-Correlation-ID': { schema: uuid }, ...(detail ? { ETag: { schema: { type: 'string', pattern: '^"company-blueprint-[a-f0-9-]{36}-[1-9][0-9]{0,18}"$' } } } : {}) } });
  const domain = 'Only the actual current own-company owner or canonical home-administration, original verified human bearer and fresh independent MFA <=300s. Tenant always comes from canonical authority, never body/query. New purpose-specific rights do not activate source036, grant global Policy/Licensing roles or replace independent deployment approval. Separate own-company tables, never the legacy global Blueprint tables.';
  const read = (operationId, summaryText, schema, extra = [], detail = false) => ({ operationId, summary: summaryText, description: domain + ' Complete bounded read-only snapshot; original authority is rechecked. No device, allocation or external publication effect.', parameters: extra, responses: { 200: reply(schema, 'Confirmed own-company observation', detail), ...errors } });
  const mutation = (operationId, summaryText, properties, create = false) => ({ operationId, summary: summaryText,
    description: domain + ' Original sources checked before/after locked DML; head, immutable version when relevant, operation, metadata-only audit and pending outbox commit atomically. App references additionally require independently revalidated existing company-app authority and actual same-tenant pool evidence. Idempotency is actor/tenant/issuer/subject plus exact original action/resource/revision/body/reason. Exact historical recovery is effect-free and returns its old revision, never the current head; it does not overwrite later edits. Local release freezes an artifact, not deployment approval. Restore changes only the draft; a separate release creates the next version.',
    parameters: [...(create ? [] : parameters), { name: 'Idempotency-Key', in: 'header', required: true, schema: uuid }, ...(create ? [] : [{ name: 'If-Match', in: 'header', required: true, schema: { type: 'string' }, description: 'Exact original current-head ETag. Retain the same key, body and ETag for explicitly requested recovery after uncertain acknowledgement.' }])],
    requestBody: { required: true, ...json(object({ ...properties, reason: text(10, 500), confirm: { const: true } })) },
    responses: { ...(create ? { 201: reply('CompanyBlueprintReceipt', 'New actual draft committed') } : {}), 200: reply('CompanyBlueprintReceipt', create ? 'Effect-free original creation recovery' : 'Applied change or effect-free historical recovery; not a current-head assertion'), ...errors } });
  const paths = {
    '/api/company-blueprints/capabilities': { get: read('getOwnCompanyBlueprintCapabilities', 'Read supported own-company Blueprint rights', 'CompanyBlueprintCapabilities') },
    '/api/company-blueprints': {
      get: read('listOwnCompanyBlueprints', 'List own-company draft summaries', 'CompanyBlueprintPage', [...paging, { name: 'search', in: 'query', schema: text(0, 100) }]),
      post: mutation('createOwnCompanyBlueprint', 'Create an actual own-company draft', { id: uuid, draft: reference('CompanyBlueprintDraft') }, true),
    },
    '/api/company-blueprints/{id}': { get: read('getOwnCompanyBlueprint', 'Read current draft and actual conservative conflict preview', 'CompanyBlueprintDetail', parameters, true), put: mutation('updateOwnCompanyBlueprint', 'Replace exactly the captured own draft', { draft: reference('CompanyBlueprintDraft') }) },
    '/api/company-blueprints/{id}/publish': { post: mutation('publishOwnCompanyBlueprintVersion', 'Freeze a nonempty conflict-free local version', {}) },
    '/api/company-blueprints/{id}/restore': { post: mutation('restoreOwnCompanyBlueprintDraft', 'Restore an immutable prior version into the draft only', { version }) },
    '/api/company-blueprints/{id}/versions': { get: read('listOwnCompanyBlueprintVersions', 'List immutable local release metadata', 'CompanyBlueprintVersionPage', [...parameters, ...paging]) },
    '/api/company-blueprints/{id}/versions/{version}': { get: read('getOwnCompanyBlueprintVersion', 'Read an immutable local release including original app metadata', 'CompanyBlueprintVersionDetail', [...parameters, { name: 'version', in: 'path', required: true, schema: version }]) },
    '/api/company-blueprints/{id}/history': { get: read('getOwnCompanyBlueprintHistory', 'Read actual metadata audit and pending delivery history', 'CompanyBlueprintHistory', [...parameters, ...paging]) },
    '/api/identity/company-blueprints': { get: { operationId: 'getOwnCompanyBlueprintAuthoritySource', summary: 'Read the original minimal own-company Blueprint authority', description: domain + ' Exact GET with no body/query/API key. Private receiving source, not a user-assignment endpoint or deployment credential.', responses: { 200: reply('CompanyBlueprintSource', 'Original current human source with independent MFA cutoff'), ...Object.fromEntries(Object.entries(errors).map(([status, error]) => [status, { ...error, ...json(object({ error: { type: 'string' } })) }])) } } },
  };
  return { paths, components: { schemas } };
}

module.exports = { companyBlueprintOpenApi };
