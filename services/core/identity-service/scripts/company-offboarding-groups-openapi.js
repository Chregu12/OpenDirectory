'use strict';

function companyOffboardingGroupsOpenApi() {
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$', description: 'Exact positive PostgreSQL BIGINT string, at most 9223372036854775807.' };
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const reference = name => ({ $ref: '#/components/schemas/' + name });
  const json = schema => ({ content: { 'application/json': { schema } } });
  const reason = { type: 'string', minLength: 10, maxLength: 500, description: 'Trimmed explicit reason without control characters.' };
  const target = object({ enabled: { const: false }, eligibilityRevision: revision });
  const envelope = { schemaVersion: { const: 1 }, actorUserId: uuid, tenantId: uuid, workflowId: uuid, userId: uuid };
  const page = { target, total: { type: 'integer', minimum: 0 }, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 } };
  const membership = object({ groupId: uuid, name: { type: 'string', minLength: 1, maxLength: 255 }, groupRevision: revision, membershipId: uuid });
  const resultIdentity = { groupId: uuid, membershipId: uuid };
  const schemas = {
    CompanyOffboardingGroupsPreview: object({ ...envelope, companyOffboardingGroupsProtocol: { const: 1 }, ...page, groups: { type: 'array', maxItems: 25, items: membership } }),
    CompanyOffboardingGroupsHistory: object({ ...envelope, ...page, receipts: { type: 'array', maxItems: 25, items: object({ id: uuid, groupId: uuid, name: membership.properties.name, membershipId: uuid, operationId: uuid, beforeGroupRevision: revision, afterGroupRevision: revision, actorUserId: uuid, reason, createdAt: { type: 'string', format: 'date-time' }, deliveryStatus: { const: 'pending' } }) } }),
    CompanyOffboardingGroupsResult: object({ ...envelope, correlationId: uuid, results: { type: 'array', minItems: 1, maxItems: 25, items: { oneOf: [
      object({ ...resultIdentity, status: { enum: ['removed', 'already_removed'] }, code: { const: 200 }, operationId: uuid }),
      object({ ...resultIdentity, status: { const: 'unconfirmed' }, code: { type: 'integer', minimum: 400, maximum: 599 }, operationId: { type: 'null' } }),
      object({ ...resultIdentity, status: { const: 'not_attempted' }, code: { type: 'null' }, operationId: { type: 'null' } }),
    ] } } }),
  };
  const description = 'Original live own-company Owner or canonical home admin and independently bound fresh MFA within 300 seconds required; actual directory permissions remain independently enforced. The exact retained Identity account-offboarding receipt must belong to this tenant, workflow and user, whose current account must still be disabled in the original negative eligibility generation. Self, deleted, foreign or reactivated targets cannot borrow the old checkpoint. Body/JWT tenant hints, global role aliases, service credentials or a workflow UUID grant no authority. Each group removal uses the existing canonical GroupMutator and immutable original membership incarnation. Roles, PIM, OU membership, sessions, devices and external providers are NOT removed; this is not full WF-004.';
  const parameters = [{ name: 'id', in: 'path', required: true, schema: uuid }];
  const query = [{ name: 'workflowId', in: 'query', required: true, schema: uuid }, { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 1000000, default: 1 } }, { name: 'limit', in: 'query', schema: { const: 25, default: 25 } }];
  const reply = (name, description) => ({ description, ...json(reference(name)), headers: { 'Cache-Control': { schema: { const: 'no-store' } } } });
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 428, 503].map(status => [status, { description: ({ 400: 'Exact canonical fields, fixed pagination and captured membership manifest required', 401: 'Original human, tenant or token context changed', 403: 'Actual own-company directory duty or self-target boundary rejected', 404: 'Own retained checkpoint, group or captured membership unavailable', 409: 'Original disabled generation or retained group evidence changed', 412: 'Captured group version changed; explicit readback required', 428: 'Fresh independently verified MFA required', 503: 'Canonical receiver, retained proof or persistent storage unavailable; no fallback' })[status], ...json({ type: 'object', required: ['error'], properties: { error: { type: 'string' } } }) }]));
  const base = '/api/users/{id}/company-offboarding-groups';
  return { components: { schemas }, paths: {
    [base]: {
      get: { operationId: 'previewOwnEmployeeOffboardingGroups', summary: 'Read an actual captured page of current own employee group links after canonical offboarding', description: description + ' Requires actual groups.read. No mutation or silent group/role cleanup; at most 25 current links per page.', parameters: [...parameters, ...query], responses: { 200: reply('CompanyOffboardingGroupsPreview', 'Actual own-tenant consistent group page and protocol 1'), ...errors } },
      post: { operationId: 'removeOwnEmployeeOffboardingGroups', summary: 'Explicitly remove precisely the displayed own employee group membership incarnations', description: description + ' Requires actual groups.read and groups.members.manage. Preflight the full manifest before any mutation. Each item commits its own canonical group event, linked receipt and pending outbox; previous child commits remain if a later item fails. Lost response may recover a valid original membership receipt, never delete a new regrant. One uncertain result stops subsequent items. Re-read preview/history instead of automatic write retries.', parameters, requestBody: { required: true, ...json(object({ workflowId: uuid, eligibilityRevision: revision, reason, confirm: { const: true }, memberships: { type: 'array', minItems: 1, maxItems: 25, description: 'Unique group IDs and membership IDs captured from the exact displayed preview.', items: object({ groupId: uuid, groupRevision: revision, membershipId: uuid }) } })) }, responses: { 200: reply('CompanyOffboardingGroupsResult', 'All requested old membership incarnations have confirmed original removal receipts; not all employee access removed'), 207: reply('CompanyOffboardingGroupsResult', 'Stopped on one uncertain child; earlier commits remain and later items were not attempted'), ...errors } },
    },
    [base + '/history']: { get: { operationId: 'readOwnEmployeeOffboardingGroupHistory', summary: 'Read actual retained canonical group-removal receipts linked to the original account checkpoint', description: description + ' Requires actual groups.read. Original group names, actors, versions and pending delivery are retained, even after a later group deletion; current own checkpoint eligibility remains mandatory.', parameters: [...parameters, ...query], responses: { 200: reply('CompanyOffboardingGroupsHistory', 'Actual retained own receipts, not externally delivered messages or full access cleanup'), ...errors } } },
  } };
}

module.exports = { companyOffboardingGroupsOpenApi };
