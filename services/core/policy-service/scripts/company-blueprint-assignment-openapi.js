'use strict';

const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS } = require('../../../../packages/company-blueprint-assignment-contract');

function companyBlueprintAssignmentOpenApi() {
  const oldBlueprint = require('./company-blueprint-openapi').companyBlueprintOpenApi().components.schemas;
  const oldLicense = require('./company-license-openapi').companyLicenseOpenApi().components.schemas;
  const oldOffboarding = require('./company-offboarding-openapi').companyOffboardingOpenApi().components.schemas;
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const reference = name => ({ $ref: '#/components/schemas/' + name });
  const nullable = schema => ({ anyOf: [schema, { type: 'null' }] });
  const array = (items, maximum = 25) => ({ type: 'array', maxItems: maximum, items });
  const uuid = oldBlueprint.CompanyBlueprintSummary.properties.id;
  const revision = oldBlueprint.CompanyBlueprintSummary.properties.revision;
  const timestamp = oldBlueprint.CompanyBlueprintSummary.properties.createdAt;
  const version = oldBlueprint.CompanyBlueprintVersion.properties.version;
  const count = { type: 'integer', minimum: 0 };
  const flag = { type: 'boolean' };
  const reason = { type: 'string', minLength: 10, maxLength: 500, description: 'Already trimmed, no control characters or credentials.' };
  const actor = { schemaVersion: { const: 1 }, actorUserId: uuid, tenantId: uuid };
  const actorV2 = { ...actor, schemaVersion: { const: 2 }, companyLicenseProtocol: { const: 2 } };
  const page = { total: count, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 } };
  const outcome = { enum: ['applied', 'already_applied'] };
  const configuration = oldBlueprint.CompanyBlueprintRecord.properties.preview.properties;
  const effectiveConfigurations = structuredClone(configuration.effectiveConfigurations);
  const conflicts = structuredClone(configuration.conflicts);
  effectiveConfigurations.items.properties.sources.maxItems = 1000;
  conflicts.items.properties.variants.maxItems = 1000;
  conflicts.items.properties.variants.items.properties.sources.maxItems = 1000;
  const applicationPage = { ...page, limit: { type: 'integer', minimum: 1, maximum: 100 } };
  const returnPage = { ...page, limit: { type: 'integer', minimum: 1, maximum: 25 } };
  const source = object({ sourceType: { enum: ['direct', 'blueprint'] }, sourceId: { type: 'string', description: 'direct for a manual origin; otherwise the immutable blueprint user-assignment UUID.' }, grantId: uuid });
  const sources = array(source, 10000);
  const capturedPool = object({ poolId: uuid, poolRevision: revision });
  const binding = object({ id: uuid, tenantId: uuid, userId: uuid, blueprintId: uuid, version, eligibilityRevision: revision, revision, status: { enum: ['active', 'removed'] },
    actorUserId: uuid, operationId: uuid, removalOperationId: nullable(uuid), createdAt: timestamp, removedAt: nullable(timestamp), appPoolIds: array(uuid) });
  const negativeBinding = object({ id: uuid, revision, blueprintId: uuid, version, eligibilityRevision: revision, poolIds: array(uuid) });
  const target = oldLicense.CompanyLicenseAuthoritySource.properties.target.oneOf.find(item => item.type === 'object');
  const assignment = object({ id: uuid, userId: uuid, assignedAt: timestamp, assignedBy: uuid, eligibilityRevision: revision, sources });
  const previewAssignment = object({ id: uuid, poolId: uuid, poolRevision: revision, name: oldLicense.CompanyLicensePool.properties.name, vendor: oldLicense.CompanyLicensePool.properties.vendor, eligibilityRevision: revision, assignedAt: timestamp, sources });
  const capturedAssignment = object({ poolId: uuid, poolRevision: revision, assignmentId: uuid, sources });
  const bindingCapture = object({ id: uuid, revision });
  const confirmation = { reason, confirm: { const: true } };
  const manual = { userId: uuid, eligibilityRevision: revision, sources, ...confirmation };
  const { companyBlueprintProtocol, ...sourceFields } = oldBlueprint.CompanyBlueprintSource.properties;
  const schemas = {
    CompanyBlueprintAssignmentSource: object({ ...sourceFields, companyBlueprintAssignmentsProtocol: { const: 1 }, permissions: { const: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS] }, target: nullable(target) }),
    CompanyBlueprintAssignmentCapability: object({ ...actor, companyBlueprintAssignmentsProtocol: { const: 1 }, permissions: { const: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS] }, configurationMode: { const: 'local-only' }, allocationMode: { const: 'local-only' }, supportedTargets: { const: ['user'] }, maxApplications: { const: 25 } }),
    CompanyBlueprintUserAssignment: binding,
    CompanyBlueprintUserAssignmentPage: object({ ...actor, userId: uuid, assignments: array(reference('CompanyBlueprintUserAssignment')), ...page }),
    CompanyBlueprintUserAssignmentDetail: object({ ...actor, assignment: reference('CompanyBlueprintUserAssignment') }),
    CompanyBlueprintAssignmentRemovalPreview: object({ ...actor, assignment: reference('CompanyBlueprintUserAssignment'), eligibilityRevision: revision, pools: array(capturedPool) }),
    CompanyBlueprintAssignmentPreview: object({ ...actor, userId: uuid, blueprintId: uuid, version, eligibilityRevision: revision,
      pools: array(object({ poolId: uuid, poolRevision: revision, totalSeats: count, usedSeats: count, availableSeats: count, additionalSeats: { type: 'integer', minimum: 0, maximum: 1 } })),
      effectiveConfigurations, conflicts, hasConflicts: flag }),
    CompanyBlueprintUserEffective: object({ ...actor, userId: uuid, assignments: array(reference('CompanyBlueprintUserAssignment'), 1000),
      effectiveConfigurations, conflicts, hasConflicts: flag, applications: array(object({ poolId: uuid, sources }), 10000) }),
    CompanyBlueprintAssignmentReceipt: object({ ...actor, operationId: uuid, assignmentId: nullable(uuid), action: { enum: ['assigned', 'removed'] }, outcome, revision: nullable(revision), deliveryStatus: { const: 'pending' },
      pools: array(object({ poolId: uuid, eventId: uuid, beforeRevision: revision, afterRevision: revision, sourceAdded: flag, sourceRemoved: flag, seatAllocated: flag, seatReleased: flag, effectiveAssignmentRetained: flag })) }),
    CompanyLicenseV2Capability: object({ ...actorV2, permissions: { const: ['company.apps.read', 'company.apps.create', 'company.apps.assign'] }, allocationMode: { const: 'local-only' }, supportedTargets: { const: ['user'] } }),
    CompanyLicenseV2AssignmentPage: object({ ...actorV2, poolId: uuid, poolRevision: revision, assignments: array(assignment, 100), ...applicationPage }),
    CompanyLicenseV2AssignmentPreview: object({ ...actorV2, poolId: uuid, poolRevision: revision, target, assignment: nullable(assignment) }),
    CompanyLicenseV2ManualReceipt: object({ ...actorV2, operationId: uuid, outcome, action: { enum: ['manual_assign', 'manual_revoke'] }, poolId: uuid, userId: uuid, assignmentId: nullable(uuid),
      sourceAdded: flag, sourceRemoved: flag, seatAllocated: flag, seatReleased: flag, effectiveAssignmentRetained: flag, eventId: uuid, poolRevision: revision, deliveryStatus: { const: 'pending' } }),
    CompanyLicenseV2ReturnPreview: object({ ...actorV2, userId: uuid, target: oldOffboarding.CompanyOffboardingEnvelope.properties.currentTarget,
      assignments: array(previewAssignment), bindings: array(negativeBinding, 10000), totalBindings: count, workflowRequired: flag, ...returnPage }),
    CompanyLicenseV2ReturnReceipt: object({ ...actorV2, operationId: uuid, outcome, userId: uuid, workflowId: nullable(uuid),
      results: array(object({ poolId: uuid, assignmentId: uuid, status: { const: 'released' }, eventId: uuid, poolRevision: revision }), 10000), retiredBindings: array(uuid, 10000), deliveryStatus: { const: 'pending' } }),
    CompanyOffboardingV2Capability: object({ ...actorV2, companyOffboardingProtocol: { const: 2 }, scope: { const: 'account-local-licenses-and-blueprint-bindings' }, requiresFreshMfa: { const: true } }),
    CompanyOffboardingV2Preview: object({ ...actorV2, user: oldOffboarding.CompanyOffboardingPreview.properties.user, licenseCount: count, bindingCount: count }),
    CompanyOffboardingV2Summary: object({ ...oldOffboarding.CompanyOffboardingSummary.properties, totalBindings: nullable(count), completedBindings: count }),
  };
  schemas.CompanyOffboardingV2Workflow = object({ ...schemas.CompanyOffboardingV2Summary.properties, requestedRevision: revision, checkpoint: nullable(reference('CompanyOffboardingAccountReceipt')),
    nextAssignments: array(previewAssignment, 10000), reviewAssignments: array(previewAssignment, 10000), nextBindings: array(negativeBinding, 10000) });
  schemas.CompanyOffboardingV2Envelope = object({ ...actorV2, workflow: reference('CompanyOffboardingV2Workflow'), currentTarget: oldOffboarding.CompanyOffboardingEnvelope.properties.currentTarget });
  schemas.CompanyOffboardingV2Page = object({ ...actorV2, ...applicationPage, workflows: array(reference('CompanyOffboardingV2Summary'), 100) });
  schemas.CompanyOffboardingV2History = object({ ...actorV2, workflowId: uuid, ...applicationPage, events: array(object({ ...oldOffboarding.CompanyOffboardingHistoryEvent.properties, totalBindings: nullable(count), completedBindings: count }), 100) });
  const json = schema => ({ content: { 'application/json': { schema } } });
  const reply = name => ({ description: 'Confirmed local observation or immutable historical receipt; inspect actual outcome and phase.', ...json(reference(name)), headers: { 'Cache-Control': { schema: { const: 'no-store' } }, 'X-Correlation-ID': { schema: uuid } } });
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 413, 428, 503].map(status => [status, { description: 'Exact source, tenant, scope, captured incarnation/version, capacity and mandatory receiver checks apply. No fallback or automatic replay.', ...json({ ...object({ error: { type: 'string' }, correlationId: uuid }), required: ['error'] }) }]));
  const domain = 'Original canonical human, actual current own-company Owner or home administration and independently bound MFA no older than 300 seconds. Separate Blueprint-assignment duties never grant global roles or widen the Blueprint authoring source. Independent App authority is required for actual app resources; the same actor, tenant and original bearer must match. Immutable pinned releases and grant incarnations; one effective seat per user/pool across all origins. Source deadline limits admission, not license lifetime. No MDM, purchase, installation or provider success. Events/outbox remain pending. SQL/DDL-owner is an explicit trust boundary.';
  const parameter = name => ({ name, in: 'path', required: true, schema: uuid });
  const pages = [{ name: 'page', in: 'query', schema: page.page }, { name: 'limit', in: 'query', schema: { const: 25 } }];
  const applicationPages = [{ name: 'page', in: 'query', schema: page.page }, { name: 'limit', in: 'query', schema: applicationPage.limit }];
  const returnPages = [{ name: 'page', in: 'query', schema: page.page }, { name: 'limit', in: 'query', schema: returnPage.limit }];
  const key = { name: 'Idempotency-Key', in: 'header', required: true, schema: uuid };
  const conditional = { name: 'If-Match', in: 'header', required: true, schema: { type: 'string' }, description: 'Exact captured pool, binding or workflow ETag; original key/body/ETag for explicit historical recovery before current-version checks.' };
  const read = (operationId, schema, parameters = []) => ({ operationId, description: domain, parameters, responses: { 200: reply(schema), ...errors } });
  const write = (operationId, schema, properties, parameters = [], created = false) => ({ ...read(operationId, schema, parameters), requestBody: { required: true, ...json(object(properties)) },
    description: domain + ' Fully captured intent. A historical already_applied receipt has no new effects and does not assert current state. No silent ETag, target eligibility or grant refresh.', responses: { 200: reply(schema), ...(created ? { 201: reply(schema) } : {}), ...errors } });
  const base = '/api/company-blueprint-assignments'; const apps = '/api/licenses/company/v2'; const jobs = apps + '/offboarding-workflows';
  const paths = {
    [base + '/capabilities']: { get: read('readOwnBlueprintAssignmentCapability', 'CompanyBlueprintAssignmentCapability') },
    [base]: { get: read('listOwnBlueprintUserAssignments', 'CompanyBlueprintUserAssignmentPage', [{ name: 'userId', in: 'query', required: true, schema: uuid }, ...pages]),
      post: write('assignOwnBlueprintToUser', 'CompanyBlueprintAssignmentReceipt', { id: uuid, userId: uuid, blueprintId: uuid, version, eligibilityRevision: revision, pools: array(capturedPool), ...confirmation }, [key], true) },
    [base + '/preview']: { post: write('previewOwnBlueprintUserAssignment', 'CompanyBlueprintAssignmentPreview', { userId: uuid, blueprintId: uuid, version }) },
    [base + '/{id}']: { get: read('readOwnBlueprintUserAssignment', 'CompanyBlueprintUserAssignmentDetail', [parameter('id')]) },
    [base + '/{id}/removal-preview']: { get: read('previewOwnBlueprintAssignmentRemoval', 'CompanyBlueprintAssignmentRemovalPreview', [parameter('id')]) },
    [base + '/{id}/remove']: { post: write('removeOwnBlueprintUserAssignment', 'CompanyBlueprintAssignmentReceipt', { userId: uuid, eligibilityRevision: revision, pools: array(capturedPool), ...confirmation }, [parameter('id'), key, conditional]) },
    [base + '/users/{userId}/effective']: { get: read('readOwnUserEffectiveBlueprints', 'CompanyBlueprintUserEffective', [parameter('userId')]) },
    '/api/identity/company-blueprint-assignments': { get: read('readOriginalBlueprintAssignmentAuthority', 'CompanyBlueprintAssignmentSource'), post: write('readOriginalBlueprintAssignmentRecipient', 'CompanyBlueprintAssignmentSource', { userId: uuid }) },
    [apps + '/capabilities']: { get: read('readOwnCompanyLicenseV2Capability', 'CompanyLicenseV2Capability') },
    [apps + '/pools/{id}/assignments']: { get: read('listOwnCompanyLicenseV2Assignments', 'CompanyLicenseV2AssignmentPage', [parameter('id'), ...applicationPages]),
      post: write('assignOwnCompanyManualLicenseV2', 'CompanyLicenseV2ManualReceipt', { ...manual, assignmentId: nullable(uuid) }, [parameter('id'), key, conditional], true) },
    [apps + '/pools/{id}/assignment-preview']: { post: write('previewOwnCompanyLicenseV2Recipient', 'CompanyLicenseV2AssignmentPreview', { userId: uuid }, [parameter('id')]) },
    [apps + '/pools/{id}/assignments/{assignmentId}/revoke']: { post: write('removeOwnCompanyManualLicenseSourceV2', 'CompanyLicenseV2ManualReceipt', manual, [parameter('id'), parameter('assignmentId'), key, conditional]) },
    [apps + '/users/{userId}/license-returns']: { get: read('previewOwnCompanyLicenseV2Returns', 'CompanyLicenseV2ReturnPreview', [parameter('userId'), ...returnPages]),
      post: write('returnOwnCompanyCapturedLicenseSourcesV2', 'CompanyLicenseV2ReturnReceipt', { workflowId: nullable(uuid), eligibilityRevision: revision, assignments: array(capturedAssignment, 10000), bindings: array(bindingCapture, 10000), ...confirmation }, [parameter('userId'), key]) },
    [jobs + '/capabilities']: { get: read('readOwnCompanyOffboardingV2Capability', 'CompanyOffboardingV2Capability') },
    [apps + '/users/{userId}/offboarding-preview']: { get: read('previewOwnCompanyOffboardingV2', 'CompanyOffboardingV2Preview', [parameter('userId')]) },
    [jobs]: { get: read('listOwnCompanyOffboardingV2Workflows', 'CompanyOffboardingV2Page', applicationPages),
      post: write('startOwnCompanyOffboardingV2', 'CompanyOffboardingV2Envelope', { workflowId: uuid, userId: uuid, userRevision: revision, eligibilityRevision: revision, ...confirmation }, [key], true) },
    [jobs + '/{id}']: { get: read('readOwnCompanyOffboardingV2Workflow', 'CompanyOffboardingV2Envelope', [parameter('id')]) },
    [jobs + '/{id}/history']: { get: read('readOwnCompanyOffboardingV2History', 'CompanyOffboardingV2History', [parameter('id'), ...applicationPages]) },
    [jobs + '/{id}/continue']: { post: write('continueOwnCompanyOffboardingV2', 'CompanyOffboardingV2Envelope', { confirm: { const: true }, reason, userRevision: revision, assignments: array(capturedAssignment, 10000), bindings: array(bindingCapture, 10000) }, [parameter('id'), key, conditional]) },
  };
  for (const path of [base + '/{id}', base + '/{id}/removal-preview', jobs + '/{id}']) paths[path].get.responses[200].headers.ETag = { schema: { type: 'string' }, description: 'Exact current binding/workflow revision, never an allocation-receipt assertion.' };
  for (const operation of Object.values(paths['/api/identity/company-blueprint-assignments'])) delete operation.responses[200].headers['X-Correlation-ID'];
  for (const path of [base + '/preview', apps + '/pools/{id}/assignment-preview', '/api/identity/company-blueprint-assignments']) paths[path].post.description = domain + ' Read-only original observation; no allocation, account mutation, idempotent write or provider execution.';
  paths[jobs].post.description += ' Identity045 account blocking and Policy cleanup have separate commits; partial failures remain visible. Complete immutable source/grant and binding manifests include zero-app bindings. All captured policy sources and bindings retire in one transaction, at most 10000 pools, bindings and aggregate sources; excess fails explicitly without truncation. Original negative eligibility is never refreshed after reactivation.';
  return { paths, components: { schemas } };
}
module.exports = { companyBlueprintAssignmentOpenApi };
