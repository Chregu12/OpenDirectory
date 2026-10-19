'use strict';

function companyOffboardingAccessOpenApi() {
  const { ROLES } = require('../../../../packages/directory-role-contract');
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$', description: 'Exact positive PostgreSQL BIGINT string, at most 9223372036854775807.' };
  const version = { type: 'string', pattern: '^[a-f0-9]{64}$', description: 'Captured canonical grant-row SHA256 under UTC, not a numeric revision or mutable role name.' };
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const reference = name => ({ $ref: '#/components/schemas/' + name });
  const json = schema => ({ content: { 'application/json': { schema } } });
  const kind = { enum: ['role', 'eligibility'] };
  const role = { enum: ROLES };
  const reason = { type: 'string', minLength: 10, maxLength: 500, description: 'Trimmed explicit reason without control characters.' };
  const timestamp = { type: 'string', format: 'date-time' };
  const target = object({ enabled: { const: false }, eligibilityRevision: revision });
  const envelope = { schemaVersion: { const: 1 }, actorUserId: uuid, tenantId: uuid, workflowId: uuid, userId: uuid };
  const protocol = { companyOffboardingAccessProtocol: { const: 1 } };
  const page = { target, kind, total: { type: 'integer', minimum: 0 }, page: { type: 'integer', minimum: 1, maximum: 1000000 }, limit: { const: 25 } };
  const permissions = ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'];
  const schemas = {
    CompanyOffboardingAccessCapabilities: object({ ...envelope, ...protocol, target, permissions: { type: 'array', minItems: 1, maxItems: 4, uniqueItems: true, items: { enum: permissions } }, supportedKinds: { type: 'array', minItems: 1, maxItems: 2, uniqueItems: true, items: kind } }),
    CompanyOffboardingAccessPreview: object({ ...envelope, ...protocol, ...page, canRevoke: { type: 'boolean' }, items: { type: 'array', maxItems: 25, items: object({ id: uuid, role, version, createdAt: timestamp, expiresAt: { oneOf: [timestamp, { type: 'null' }] }, canRevoke: { type: 'boolean' }, blockedReason: { enum: [null, 'permission_required', 'protected_role'] } }) } }),
    CompanyOffboardingAccessHistory: object({ ...envelope, ...page, receipts: { type: 'array', maxItems: 25, items: object({ id: uuid, resourceId: uuid, role, version, kind, checkpointId: uuid, actorUserId: uuid, correlationId: uuid, reason, createdAt: timestamp, deliveryStatus: { const: 'pending' } }) } }),
    CompanyOffboardingAccessResult: object({ ...envelope, kind, correlationId: uuid, results: { type: 'array', minItems: 1, maxItems: 25, items: { oneOf: [
      object({ id: uuid, status: { enum: ['revoked', 'already_revoked'] }, code: { const: 200 }, checkpointId: uuid }),
      object({ id: uuid, status: { const: 'unconfirmed' }, code: { type: 'integer', minimum: 400, maximum: 599 }, checkpointId: { type: 'null' } }),
      object({ id: uuid, status: { const: 'not_attempted' }, code: { type: 'null' }, checkpointId: { type: 'null' } }),
    ] } } }),
  };
  const description = 'Original current human authority in the same home tenant and independently verified MFA within 300 seconds are mandatory. The target must still be disabled in the exact original negative eligibility generation of its retained Identity 045 account checkpoint. No self, deleted, foreign or reactivated targets. Ownership, company.apps permissions, token role aliases and a workflow UUID do not grant role or PIM authority. Corresponding actual canonical read/manage permissions are enforced separately for each kind. Protected grants additionally require actual canonical admin under the existing kernels; no global privilege is granted. This explicit segment is not complete WF-004 and removes no OU memberships, devices, external credentials or all sessions.';
  const path = [{ name: 'id', in: 'path', required: true, schema: uuid }];
  const workflow = { name: 'workflowId', in: 'query', required: true, schema: uuid };
  const query = [workflow, { name: 'kind', in: 'query', required: true, schema: kind }, { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 1000000, default: 1 } }, { name: 'limit', in: 'query', schema: { const: 25, default: 25 } }];
  const reply = (name, description) => ({ description, ...json(reference(name)), headers: { 'Cache-Control': { schema: { const: 'no-store' } } } });
  const errors = Object.fromEntries([400, 401, 403, 404, 409, 412, 428, 503].map(status => [status, { description: ({ 400: 'Exact selectors, explicit kind, confirmation and canonical captured manifest required', 401: 'Original actor, token or live authority changed', 403: 'Independent canonical permission, home tenant, self or protected-role boundary rejected', 404: 'Own original account checkpoint or captured grant unavailable', 409: 'Disabled account generation or retained grant evidence changed', 412: 'Captured exact grant-row version changed; explicit readback required', 428: 'Independent fresh MFA within 300 seconds required', 503: 'Canonical source, receiver, checkpoint, proof or persistent storage unavailable; no fallback' })[status], ...json({ type: 'object', required: ['error'], properties: { error: { type: 'string' } } }) }]));
  const base = '/api/users/{id}/company-offboarding-access';
  return { components: { schemas }, paths: {
    [base + '/capabilities']: { get: { operationId: 'readEmployeeOffboardingAccessCapabilities', summary: 'Read actual independent role and PIM cleanup capabilities for an original disabled account checkpoint', description: description + ' Requires at least one actual identities.roles.read or pim.eligibilities.read duty; supports only the corresponding readable kinds. No global users.read or CompanyOwner role is required.', parameters: [...path, workflow], responses: { 200: reply('CompanyOffboardingAccessCapabilities', 'Actual permissions, supported kinds and original disabled target generation'), ...errors } } },
    [base]: {
      get: { operationId: 'previewEmployeeOffboardingAccess', summary: 'Read a real captured page of unrevoked role assignments or PIM eligibilities', description: description + ' Requires identities.roles.read for role or pim.eligibilities.read for eligibility. Includes stored unrevoked expired grants; not all rows are presently effective. Read-only actors and protected grants remain visibly blocked. No mutation or implicit cascade is performed by preview.', parameters: [...path, ...query], responses: { 200: reply('CompanyOffboardingAccessPreview', 'At most 25 exact own-target grants and their actual revocation eligibility'), ...errors } },
      post: { operationId: 'revokeEmployeeOffboardingAccess', summary: 'Explicitly revoke exactly the captured old role assignments or PIM eligibilities', description: description + ' Requires corresponding read and manage duties. Full read-only preflight precedes the first effect. Each child uses the existing DirectoryRoles.revoke or PrivilegedActivation.revokeEligibility with its real command checkpoint, audit and pending outbox plus a linked immutable receipt. Existing PIM eligibility revocation may cancel related pending requests and revoke linked active assignments. Each child commits independently; previous successes remain after a later failure. One unconfirmed result stops later items. Explicit recovery uses only valid original ID/version receipts and never revokes a new grant. No automatic write retry or silent version refresh.', parameters: path, requestBody: { required: true, ...json(object({ workflowId: uuid, eligibilityRevision: revision, kind, reason, confirm: { const: true }, items: { type: 'array', minItems: 1, maxItems: 25, description: 'Unique exact IDs and row hashes captured from the explicit preview; protected or unsupported grants cannot be silently skipped.', items: object({ id: uuid, version }) } })) }, responses: { 200: reply('CompanyOffboardingAccessResult', 'All requested old grants have confirmed original checkpoints; not all access removed'), 207: reply('CompanyOffboardingAccessResult', 'Stopped after one unconfirmed child, retaining earlier commits; later items not attempted'), ...errors } },
    },
    [base + '/history']: { get: { operationId: 'readEmployeeOffboardingAccessHistory', summary: 'Read actual retained role or PIM cleanup receipts linked to the original account checkpoint', description: description + ' Requires corresponding read duty. Pending delivery is not a successful external notification or provider revocation.', parameters: [...path, ...query], responses: { 200: reply('CompanyOffboardingAccessHistory', 'Original actual child receipts, actors, row versions and command checkpoints'), ...errors } } },
  } };
}

module.exports = { companyOffboardingAccessOpenApi };
