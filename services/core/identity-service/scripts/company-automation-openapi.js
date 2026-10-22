'use strict';
const { ACTIONS, SCOPE, LICENSE_ACTION } = require('../../../../packages/company-automation-contract');
function companyAutomationOpenApi() {
  const uuid = { type: 'string', format: 'uuid', pattern: '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' };
  const revision = { type: 'string', pattern: '^[1-9][0-9]{0,18}$' }; const date = { type: 'string', format: 'date-time' };
  const object = properties => ({ type: 'object', additionalProperties: false, required: Object.keys(properties), properties });
  const ref = name => ({ $ref: '#/components/schemas/' + name }); const json = schema => ({ content: { 'application/json': { schema } } });
  const nullable = schema => ({ oneOf: [schema, { type: 'null' }] }); const action = { enum: [...ACTIONS] }; const format = { enum: ['json', 'csv'] };
  const principal = { oneOf: [object({ kind: { const: 'owner' }, userId: uuid, tenantId: uuid }), object({ kind: { const: 'application' }, clientId: { type: 'string', minLength: 1, maxLength: 255 }, clientRevision: revision })] };
  const base = { schemaVersion: { const: 1 }, companyAutomationProtocol: { const: 1 }, principal };
  const schemas = {
    CompanyAutomationEnrollment: object({ ...base, id: uuid, clientId: { type: 'string' }, clientRevision: revision, name: { type: 'string', minLength: 1, maxLength: 160 }, expiresAt: date, requestedScope: { const: SCOPE } }),
    CompanyAutomationGrant: object({ id: uuid, enrollmentId: uuid, tenantId: uuid, clientId: { type: 'string' }, clientRevision: revision, actions: { type: 'array', minItems: 1, maxItems: ACTIONS.length, uniqueItems: true, items: action }, expiresAt: date, status: { enum: ['active', 'revoked'] }, revision: { enum: ['1', '2'] }, createdAt: date }),
    CompanyAutomationJob: object({ id: uuid, grantId: uuid, tenantId: uuid, scheduleId: nullable(uuid), action, format, status: { enum: ['queued', 'running', 'retry_wait', 'succeeded', 'partial', 'failed', 'cancelled'] }, revision,
      attemptCount: { type: 'integer', minimum: 0, maximum: 5 }, retryCount: { type: 'integer', minimum: 0 }, availableAt: date, leaseUntil: nullable(date), errorCode: nullable({ type: 'string' }), rowCount: nullable({ type: 'integer', minimum: 0, maximum: 10000 }), artifactSha256: nullable({ type: 'string', pattern: '^[a-f0-9]{64}$' }), createdAt: date, updatedAt: date }),
    CompanyAutomationSchedule: object({ id: uuid, grantId: uuid, tenantId: uuid, action, format, intervalSeconds: { type: 'integer', minimum: 60, maximum: 2592000 }, enabled: { type: 'boolean' }, nextRunAt: date, revision, createdAt: date }),
  };
  const exports = { enum: ACTIONS.filter(value => value !== LICENSE_ACTION) };
  const progress = object({ runId: uuid, retryCount: { type: 'integer', minimum: 0 }, cycle: { type: 'integer', minimum: 1, maximum: 5 }, ...Object.fromEntries(['completed','total','blocked'].map(key => [key, { type: 'integer', minimum: 0, maximum: 10000 }])) });
  schemas.CompanyLicenseAutomationProgress = progress;
  const appActor = object({ kind: { const: 'application' }, id: uuid, clientId: { type: 'string', minLength: 1, maxLength: 255 }, clientRevision: revision });
  schemas.CompanyLicenseAutomationActor = appActor;
  for (const [name, extra] of [['CompanyAutomationJob', { ruleId: uuid, progress: nullable(ref('CompanyLicenseAutomationProgress')) }], ['CompanyAutomationSchedule', { ruleId: uuid }]]) {
    const schema = schemas[name]; Object.assign(schema.properties, extra);
    schema.allOf = [{ if: { properties: { action: { const: LICENSE_ACTION } }, required: ['action'] },
      then: { required: Object.keys(extra), properties: { format: { const: 'json' } } },
      else: { properties: { action: exports, ...(name === 'CompanyAutomationJob' ? { status: { enum: schema.properties.status.enum.filter(value => value !== 'partial') } } : {}) }, not: { anyOf: Object.keys(extra).map(key => ({ required: [key] })) } } }];
  }
  const memberResult = { oneOf: [object({ userId: uuid, status: { enum: ['assigned','retained','removed'] }, code: { type: 'null' } }), object({ userId: uuid, status: { const: 'blocked' }, code: { enum: [403,404,409] } })] };
  schemas.CompanyLicenseAutomationStep = object({ schemaVersion: { const: 1 }, companyLicenseAutomationProtocol: { const: 1 }, grantId: uuid, jobId: uuid, ruleId: uuid,
    actor: ref('CompanyLicenseAutomationActor'), progress: ref('CompanyLicenseAutomationProgress'), finished: { type: 'boolean' }, hasBlocked: { type: 'boolean' }, results: { type: 'array', maxItems: 10000, items: memberResult } });
  schemas.CompanyLicenseAutomationStep.allOf = [{ if: { properties: { finished: { const: false } } }, then: { properties: { results: { maxItems: 0 } } } }];
  const ids = { type: 'array', maxItems: 10000, uniqueItems: true, items: uuid };
  const membership = object({ userId: uuid, membershipId: uuid, eligibilityRevision: revision, reviewDeadlineAt: nullable(date) });
  const group = object({ schemaVersion: { const: 3 }, groupId: uuid, name: nullable({ type: 'string', maxLength: 255 }), revision, deleted: { type: 'boolean' }, memberIds: ids, inactiveMemberIds: ids,
    unresolvedMemberIds: { type: 'array', maxItems: 10000, uniqueItems: true, items: { type: 'string', minLength: 1, maxLength: 255 } }, memberships: { type: 'array', maxItems: 10000, items: membership } });
  const target = object({ id: uuid, revision: nullable(revision), eligibilityRevision: revision, enabled: { type: 'boolean' }, deleted: { type: 'boolean' } });
  schemas.CompanyLicenseAutomationSource = object({ schemaVersion: { const: 1 }, companyLicenseAutomationProtocol: { const: 1 }, kind: { const: 'application' }, issuer: { type: 'string' }, subject: { type: 'string' }, tokenId: { type: 'string' }, expiresAt: { type: 'integer' }, clientRevision: revision,
    tenant: object({ id: uuid, version: revision, generation: revision }), grantId: uuid, jobId: uuid, leaseToken: uuid, ruleId: uuid, retryCount: { type: 'integer', minimum: 0 }, validUntil: { type: 'integer' }, permissions: { const: [LICENSE_ACTION] }, target: nullable(target), group: nullable(group) });
  const page = { page: { type: 'integer', minimum: 1 }, limit: { const: 25 }, total: { type: 'integer', minimum: 0 } };
  schemas.CompanyAutomationGrantReceipt = object({ ...base, grant: ref('CompanyAutomationGrant') }); schemas.CompanyAutomationJobReceipt = object({ ...base, job: ref('CompanyAutomationJob') }); schemas.CompanyAutomationScheduleReceipt = object({ ...base, schedule: ref('CompanyAutomationSchedule') });
  schemas.CompanyAutomationGrants = object({ ...base, ...page, grants: { type: 'array', maxItems: 25, items: ref('CompanyAutomationGrant') }, supportedActions: { type: 'array', const: [...ACTIONS] } });
  schemas.CompanyAutomationJobs = object({ ...base, ...page, grantId: uuid, tenantId: uuid, jobs: { type: 'array', maxItems: 25, items: ref('CompanyAutomationJob') } });
  schemas.CompanyAutomationSchedules = object({ ...base, ...page, grantId: uuid, tenantId: uuid, schedules: { type: 'array', maxItems: 25, items: ref('CompanyAutomationSchedule') } });
  schemas.CompanyAutomationArtifact = object({ ...base, jobId: uuid, grantId: uuid, tenantId: uuid, rowCount: { type: 'integer', minimum: 0, maximum: 10000 }, sha256: { type: 'string', pattern: '^[a-f0-9]{64}$' }, contentType: { enum: ['application/json', 'text/csv;charset=utf-8'] }, filename: { type: 'string' }, content: { type: 'string', maxLength: 4194304 } });
  schemas.CompanyAutomationHistory = object({ ...base, ...page, jobId: uuid, tenantId: uuid, events: { type: 'array', maxItems: 25, items: object({ revision, actor: principal, status: schemas.CompanyAutomationJob.properties.status, attemptCount: { type: 'integer', minimum: 0, maximum: 5 }, errorCode: nullable({ type: 'string' }), createdAt: date }) } });
  // Event actors contain only provenance; owner tenant is the enclosing history's tenantId.
  schemas.CompanyAutomationHistory.properties.events.items.properties.actor = { oneOf: [object({ kind: { const: 'owner' }, userId: uuid }), object({ kind: { const: 'application' }, clientId: { type: 'string' }, clientRevision: revision })] };
  const description = 'Tenant-bound durable app automation. Enrollment requires an issuer-verified, live exact company.automation client-credentials token and grants no tenant access. Only the actual company owner with original fresh MFA (at most 300 seconds) may approve fixed actions for its own tenant for at most 30 days. Each grant pins issuer, client ID and client generation; rotation, revocation, expiration, tenant incarnation or loss of original ownership denies runtime use. Workers use their own current app token, never a retained or fabricated human session. Jobs and schedules require an explicit live grant; no arbitrary scripts or caller tenant selectors. Exported data is personal data covered by the explicit delegation. Immutable events and pending outbox are local evidence, not external delivery.';
  const errors = Object.fromEntries([400,401,403,404,409,412,428,429,503].map(status => [status, { description: 'Rejected or unconfirmed. Read durable grant/job state before retrying an uncertain write.' }]));
  const resource = { name: 'id', in: 'path', required: true, schema: uuid }; const pageParameter = { name: 'page', in: 'query', schema: { type: 'integer', minimum: 1, maximum: 999999, default: 1 } };
  const conditional = kind => ({ name: 'If-Match', in: 'header', required: true, schema: { type: 'string', pattern: '^"company-automation-' + kind + '-[a-f0-9-]{36}-[1-9][0-9]{0,18}"$' } });
  const read = (operationId, name, parameters=[]) => ({ operationId, description, security: [{ bearerAuth: [] }], parameters, responses: { 200: { description: 'Actual authorized persistent state', ...json(ref(name)), headers: { 'Cache-Control': { schema: { const: 'no-store' } } } }, ...errors } });
  const write = (operationId, name, input, parameters=[], status=200) => ({ ...read(operationId,name,parameters), requestBody: { required: true, ...json(object(input)) }, responses: { [status]: { description: 'Actual local commit; a queued job is not completed execution', ...json(ref(name)), headers: { 'Cache-Control': { schema: { const: 'no-store' } }, ETag: { schema: { type: 'string' } } } }, ...errors } });
  const basePath = '/api/identity/automation'; const input = { id: uuid, grantId: uuid, action, format }; const confirm = { confirm: { const: true } };
  const paths = {
    [basePath+'/enrollments']: { post: write('enrollCompanyAutomationApp','CompanyAutomationEnrollment',{ id:uuid,name:{type:'string',minLength:1,maxLength:160} },[],201) },
    [basePath+'/enrollments/{id}']: { get: read('readPendingCompanyAutomationEnrollment','CompanyAutomationEnrollment',[resource]) },
    [basePath+'/grants']: { get: read('listCompanyAutomationGrants','CompanyAutomationGrants',[pageParameter]), post: write('approveCompanyAutomationApp','CompanyAutomationGrantReceipt',{ id:uuid,enrollmentId:uuid,clientId:{type:'string',minLength:1,maxLength:255},clientRevision:revision,actions:{type:'array',minItems:1,maxItems:ACTIONS.length,uniqueItems:true,items:action},expiresAt:date,reason:{type:'string',minLength:10,maxLength:500},...confirm },[],201) },
    [basePath+'/grants/{id}/revoke']: { post: write('revokeCompanyAutomationApp','CompanyAutomationGrantReceipt',confirm,[resource,conditional('grant')]) },
    [basePath+'/jobs']: { get: read('listCompanyAutomationJobs','CompanyAutomationJobs',[{name:'grantId',in:'query',required:true,schema:uuid},pageParameter]), post: write('queueCompanyAutomationJob','CompanyAutomationJobReceipt',input,[],201) },
    [basePath+'/schedules']: { get: read('listCompanyAutomationSchedules','CompanyAutomationSchedules',[{name:'grantId',in:'query',required:true,schema:uuid},pageParameter]), post: write('scheduleCompanyAutomationJob','CompanyAutomationScheduleReceipt',{...input,intervalSeconds:{type:'integer',minimum:60,maximum:2592000}},[],201) },
    [basePath+'/run']: { post: write('runGrantedCompanyAutomationJob','CompanyAutomationJobReceipt',{grantId:uuid}) },
    [basePath+'/jobs/{id}/result']: { get: read('downloadCompanyAutomationArtifact','CompanyAutomationArtifact',[resource]) },
    [basePath+'/jobs/{id}/history']: { get: read('readCompanyAutomationJobHistory','CompanyAutomationHistory',[resource,pageParameter]) },
    [basePath+'/jobs/{id}/cancel']: { post: write('cancelCompanyAutomationJob','CompanyAutomationJobReceipt',confirm,[resource,conditional('job')]) },
    [basePath+'/jobs/{id}/retry']: { post: write('retryFailedCompanyAutomationJob','CompanyAutomationJobReceipt',confirm,[resource,conditional('job')]) },
    [basePath+'/schedules/{id}/disable']: { post: write('disableCompanyAutomationSchedule','CompanyAutomationScheduleReceipt',confirm,[resource,conditional('schedule')]) },
  };
  for (const [path, scheduled] of [[basePath+'/jobs',false],[basePath+'/schedules',true]]) {
    const timing = scheduled ? { intervalSeconds: { type: 'integer', minimum: 60, maximum: 2592000 } } : {};
    paths[path].post.requestBody.content['application/json'].schema = { oneOf: [object({ ...input, action: exports, ...timing }), object({ ...input, action: { const: LICENSE_ACTION }, format: { const: 'json' }, ruleId: uuid, ...timing })] };
  }
  paths[basePath+'/license-source'] = { post: write('readOriginalCompanyLicenseAutomationSource','CompanyLicenseAutomationSource',{ grantId:uuid,jobId:uuid,leaseToken:uuid,groupId:nullable(uuid),userId:nullable(uuid) }) };
  paths[basePath+'/license-source'].post.description = description + ' Private receiver source. Requires the actual running license job, exact grant and current lease. A base lookup has groupId=userId=null; a recipient requires the captured own group. Returns canonical current eligibility and review deadlines without human identity/MFA fields. Source lifetime is at most the original job lease (45 seconds), current app token, grant and membership review deadline. This source is not a reusable bearer.';
  paths['/api/licenses/automation/groups/step'] = { post: write('stepGrantedCompanyLicenseGroupReconciliation','CompanyLicenseAutomationStep',{ grantId:uuid,jobId:uuid,leaseToken:uuid,ruleId:uuid }) };
  paths['/api/licenses/automation/groups/step'].post.description = description + ' Private Policy receiver for the original live app JWT and the exact current running Identity job. Processes at most 25 captured canonical users per step through the existing finite allocator. Immutable cycles/pages and original receipts support recovery after lost acknowledgements. At most five bounded rescans per retry epoch, no invented human authority. Partial results report blocked users; assigned/removed confirm only local group origins, never provider provisioning. No arbitrary pool, group, Blueprint, tenant or URL selector. An unfinished response contains progress and no complete results; the Identity job remains queued. Missing/corrupt evidence fails closed.';
  paths[basePath+'/run'].post.responses[204]={description:'No due job; schedules remain persistent.'};
  paths[basePath+'/run'].post.description += ' Only the pinned app may execute. Claims use an expiring lease, up to five attempts and bounded exponential backoff; an expired worker cannot acknowledge another claim. Schedules skip missed bursts. Local exports are read-only. Explicitly delegated license reconciliation uses the existing source-aware allocator and durable per-member receipts. Incomplete pages requeue the same job; a completed pass with blocked members is partial, not succeeded. These handlers do not perform external mutations.';
  return { paths, components: { schemas } };
}
module.exports = { companyAutomationOpenApi };
