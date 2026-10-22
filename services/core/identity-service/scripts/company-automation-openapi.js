'use strict';
const { ACTIONS, SCOPE } = require('../../../../packages/company-automation-contract');
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
    CompanyAutomationJob: object({ id: uuid, grantId: uuid, tenantId: uuid, scheduleId: nullable(uuid), action, format, status: { enum: ['queued', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled'] }, revision,
      attemptCount: { type: 'integer', minimum: 0, maximum: 5 }, retryCount: { type: 'integer', minimum: 0 }, availableAt: date, leaseUntil: nullable(date), errorCode: nullable({ type: 'string' }), rowCount: nullable({ type: 'integer', minimum: 0, maximum: 10000 }), artifactSha256: nullable({ type: 'string', pattern: '^[a-f0-9]{64}$' }), createdAt: date, updatedAt: date }),
    CompanyAutomationSchedule: object({ id: uuid, grantId: uuid, tenantId: uuid, action, format, intervalSeconds: { type: 'integer', minimum: 60, maximum: 2592000 }, enabled: { type: 'boolean' }, nextRunAt: date, revision, createdAt: date }),
  };
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
  paths[basePath+'/run'].post.responses[204]={description:'No due job; schedules remain persistent.'};
  paths[basePath+'/run'].post.description += ' Only the pinned app may execute. Claims use an expiring lease, up to five attempts and bounded exponential backoff; an expired worker cannot acknowledge another claim. Schedules skip missed bursts. All currently supported handlers are read-only directory exports, so retry cannot duplicate an external mutation.';
  return { paths, components: { schemas } };
}
module.exports = { companyAutomationOpenApi };
