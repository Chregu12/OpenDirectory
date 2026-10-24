import { z } from 'zod';
import { api } from './api';
import { companyUuid as uuid, companyRevision as revision, companyReason, CompanyWire } from './companyAssignmentProtocol';
const base = '/api/identity/automation';
export const automationActions = ['directory.users.export', 'directory.groups.export', 'directory.ous.export', 'licenses.groups.reconcile', 'directory.groups.reconcile'] as const;
export const licenseAutomationAction = 'licenses.groups.reconcile';
export const groupRuleAutomationAction = 'directory.groups.reconcile';
export const isReconciliationAction = (value: string) => [licenseAutomationAction, groupRuleAutomationAction].includes(value);
const action = z.enum(automationActions); const timestamp = z.string().datetime({ offset: true });
const principalSchema = z.object({ kind: z.literal('owner'), userId: uuid, tenantId: uuid }).strict();
const envelope = { schemaVersion: z.literal(1), companyAutomationProtocol: z.literal(1), principal: principalSchema };
const grantSchema = z.object({ id: uuid, enrollmentId: uuid, tenantId: uuid, clientId: z.string().min(1).max(255), clientRevision: revision, actions: z.array(action).min(1).max(5),
  expiresAt: timestamp, status: z.enum(['active', 'revoked']), revision: z.enum(['1', '2']), createdAt: timestamp }).strict()
  .refine(value => new Set(value.actions).size === value.actions.length && (value.status === 'active' ? value.revision === '1' : value.revision === '2'));
const progressSchema = z.object({ runId: uuid, retryCount: z.number().int().nonnegative(), cycle: z.number().int().min(1).max(5), completed: z.number().int().min(0).max(10000), total: z.number().int().min(0).max(10000), blocked: z.number().int().min(0).max(10000) }).strict().refine(value => value.blocked <= value.completed && value.completed <= value.total);
const counter=z.string().regex(/^(0|[1-9][0-9]{0,18})$/).refine(value=>BigInt(value)<=BigInt('9223372036854775807'));
const triggerSchema=z.object({kind:z.literal('change'),groupId:uuid,sourceRevision:revision,deadlineRevision:counter,poolId:uuid.optional(),poolRevision:revision.optional(),availableSeats:z.number().int().min(0).max(10000).optional()}).strict();
const jobSchema = z.object({ id: uuid, grantId: uuid, tenantId: uuid, scheduleId: uuid.nullable(), action, format: z.enum(['csv', 'json']),
  status: z.enum(['queued', 'running', 'retry_wait', 'succeeded', 'partial', 'failed', 'cancelled']), revision, attemptCount: z.number().int().min(0).max(5), retryCount: z.number().int().nonnegative(),
  availableAt: timestamp, leaseUntil: timestamp.nullable(), errorCode: z.string().nullable(), rowCount: z.number().int().min(0).max(10000).nullable(), artifactSha256: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
  createdAt: timestamp, updatedAt: timestamp, trigger:triggerSchema.optional(), ruleId: uuid.optional(), progress: progressSchema.nullable().optional() }).strict().refine(value => (value.status === 'running') === (value.leaseUntil !== null)
    && (['succeeded','partial'].includes(value.status) ? value.rowCount !== null && value.artifactSha256 !== null : value.rowCount === null && value.artifactSha256 === null)
    && (!value.trigger || isReconciliationAction(value.action) && value.scheduleId!==null && (value.action===licenseAutomationAction ? value.trigger.poolId!==undefined&&value.trigger.poolRevision!==undefined&&value.trigger.availableSeats!==undefined : value.trigger.poolId===undefined&&value.trigger.poolRevision===undefined&&value.trigger.availableSeats===undefined))
    && (isReconciliationAction(value.action) ? value.ruleId !== undefined && value.progress !== undefined && value.format === 'json'
      && (!value.progress || value.progress.runId === value.id && value.progress.retryCount <= value.retryCount)
      && (!['succeeded','partial'].includes(value.status) || !!value.progress && value.progress.retryCount === value.retryCount && value.progress.completed === value.progress.total && value.rowCount === value.progress.total && (value.status === 'partial') === (value.progress.blocked > 0))
      : value.ruleId === undefined && value.progress === undefined && value.status !== 'partial'));
const scheduleSchema = z.object({ id: uuid, grantId: uuid, tenantId: uuid, action, format: z.enum(['csv', 'json']), intervalSeconds: z.number().int().min(60).max(2592000).nullable(),onChange:z.literal(true).optional(),lastSourceRevision:revision.nullable().optional(),lastDeadlineRevision:counter.nullable().optional(),
  enabled: z.boolean(), nextRunAt: timestamp, revision, createdAt: timestamp, ruleId: uuid.optional() }).strict().refine(value => (value.onChange ? isReconciliationAction(value.action)&&value.intervalSeconds===null&&value.lastSourceRevision!==undefined&&value.lastDeadlineRevision!==undefined : value.intervalSeconds!==null&&value.lastSourceRevision===undefined&&value.lastDeadlineRevision===undefined) && (isReconciliationAction(value.action) ? value.ruleId !== undefined && value.format === 'json' : value.ruleId === undefined));
const grantsSchema = z.object({ ...envelope, grants: z.array(grantSchema).max(25), page: z.number().int().positive(), limit: z.literal(25), total: z.number().int().nonnegative(), supportedActions: z.array(action).length(5) }).strict();
const enrollmentSchema = z.object({ ...envelope, id: uuid, clientId: z.string().min(1).max(255), clientRevision: revision, name: z.string().min(1).max(160), expiresAt: timestamp, requestedScope: z.literal('company.automation'),companyTenant:z.object({id:uuid,version:revision,generation:revision}).strict().optional() }).strict().refine(row=>!row.companyTenant||row.companyTenant.id===row.principal.tenantId);
const grantReceipt = z.object({ ...envelope, grant: grantSchema }).strict();
const jobReceipt = z.object({ ...envelope, job: jobSchema }).strict(); const scheduleReceipt = z.object({ ...envelope, schedule: scheduleSchema }).strict();
const page = { ...envelope, grantId: uuid, tenantId: uuid, page: z.number().int().positive(), limit: z.literal(25), total: z.number().int().nonnegative() };
const jobsSchema = z.object({ ...page, jobs: z.array(jobSchema).max(25) }).strict(); const schedulesSchema = z.object({ ...page, schedules: z.array(scheduleSchema).max(25) }).strict();
const historySchema = z.object({ ...envelope, jobId: uuid, tenantId: uuid, page: z.number().int().positive(), limit: z.literal(25), total: z.number().int().nonnegative(), events: z.array(z.object({ revision, actor: z.union([
  z.object({ kind: z.literal('owner'), userId: uuid }).strict(), z.object({ kind: z.literal('application'), clientId: z.string().min(1).max(255), clientRevision: revision }).strict(),
]), status: z.enum(['queued', 'running', 'retry_wait', 'succeeded', 'partial', 'failed', 'cancelled']), attemptCount: z.number().int().min(0).max(5), errorCode: z.string().nullable(), createdAt: timestamp }).strict()).max(25) }).strict();
const licenseReportSchema = z.object({ schemaVersion: z.literal(1), companyLicenseAutomationProtocol: z.literal(1), grantId: uuid, jobId: uuid, ruleId: uuid,
  actor: z.object({ kind: z.literal('application'), id: uuid, clientId: z.string().min(1).max(255), clientRevision: revision }).strict(), progress: progressSchema,
  finished: z.literal(true), hasBlocked: z.boolean(), results: z.array(z.object({ userId: uuid, status: z.enum(['assigned','retained','removed','blocked']), code: z.union([z.literal(403),z.literal(404),z.literal(409)]).nullable() }).strict()
    .refine(value => value.status === 'blocked' ? value.code !== null : value.code === null)).max(10000) }).strict();
export type AutomationGrant = CompanyWire<z.infer<typeof grantSchema>>;
export type AutomationJob = Omit<CompanyWire<z.infer<typeof jobSchema>>, 'ruleId' | 'progress'> & { ruleId?: string; progress?: CompanyWire<z.infer<typeof progressSchema>> | null };
export type AutomationSchedule = Omit<CompanyWire<z.infer<typeof scheduleSchema>>, 'ruleId'> & { ruleId?: string };
export type AutomationEnrollment = Omit<CompanyWire<z.infer<typeof enrollmentSchema>>, 'companyTenant'> & { companyTenant?: { id: string; version: string; generation: string } };
export type AutomationPrincipal = CompanyWire<z.infer<typeof principalSchema>>;
export type AutomationHistory = CompanyWire<z.infer<typeof historySchema>>;
export type AutomationLicenseReport = CompanyWire<z.infer<typeof licenseReportSchema>>;
const groupReportSchema = licenseReportSchema.omit({companyLicenseAutomationProtocol:true,results:true}).extend({companyGroupRuleAutomationProtocol:z.literal(1),
 results:z.array(z.object({userId:uuid,status:z.enum(['added','retained','manual-retained','removed','awaiting-review','blocked']),code:z.union([z.literal(403),z.literal(404),z.literal(409),z.literal(428)]).nullable()}).strict().refine(row=>row.status==='blocked'?row.code!==null:row.code===null)).max(10000)}).strict();
export type AutomationGroupReport = CompanyWire<z.infer<typeof groupReportSchema>>;
function parse<S extends z.ZodType>(schema: S, value: unknown): CompanyWire<z.output<S>> { return schema.parse(value) as unknown as CompanyWire<z.output<S>>; }
function fail(): never { throw new Error('Automationsstand nicht bestätigt. Freigaben und gespeicherte Jobs neu laden; frühere Schritte können bereits gespeichert sein.'); }
function checked<T extends { principal: AutomationPrincipal }>(value: T, expected: AutomationPrincipal) {
  if (value.principal.userId !== expected.userId || value.principal.tenantId !== expected.tenantId) fail(); return value;
}
const etag = (kind: string, row: { id: string; revision: string }) => `"company-automation-${kind}-${row.id}-${row.revision}"`;
export const companyAutomation = {
  async grants(userId: string, number = 1) {
    uuid.parse(userId); const response = await api.get(base + '/grants', { params: { page: number } }); if (response.status !== 200) fail(); const value = parse(grantsSchema, response.data);
    if (value.principal.userId !== userId || value.grants.some(row => row.tenantId !== value.principal.tenantId) || new Set(value.grants.map(row => row.id)).size !== value.grants.length
      || new Set(value.supportedActions).size !== 5 || value.page !== number || value.grants.length > value.total) fail(); return value;
  },
  async enrollment(id: string, expected: AutomationPrincipal) {
    uuid.parse(id); const response = await api.get(base + '/enrollments/' + id); if (response.status !== 200) fail();
    const value = checked(parse(enrollmentSchema, response.data), expected); if (value.id !== id || Date.parse(value.expiresAt) <= Date.now()) fail(); return value;
  },
  async approve(enrollment: AutomationEnrollment, actions: string[], durationHours: number, reason: string, expected: AutomationPrincipal) {
    checked(enrollment, expected); if (!Number.isInteger(durationHours) || durationHours < 1 || durationHours > 720 || !actions.length || new Set(actions).size !== actions.length) fail();
    actions.forEach(value => action.parse(value)); const id = crypto.randomUUID(); const expiresAt = new Date(Date.now() + durationHours * 3600000).toISOString();
    const response = await api.post(base + '/grants', { id, enrollmentId: enrollment.id, clientId: enrollment.clientId, clientRevision: enrollment.clientRevision, actions: [...actions].sort(), expiresAt, reason: companyReason(reason), confirm: true });
    if (response.status !== 201) fail(); const value = checked(parse(grantReceipt, response.data), expected); const grant = value.grant;
    if (grant.id !== id || grant.tenantId !== expected.tenantId || grant.enrollmentId !== enrollment.id || grant.clientId !== enrollment.clientId || grant.clientRevision !== enrollment.clientRevision
      || grant.status !== 'active' || grant.expiresAt !== expiresAt || JSON.stringify(grant.actions) !== JSON.stringify([...actions].sort())) fail(); return grant;
  },
  async jobs(grant: AutomationGrant, expected: AutomationPrincipal, number = 1) {
    const response = await api.get(base + '/jobs', { params: { grantId: grant.id, page: number } }); if (response.status !== 200) fail();
    const value = checked(parse(jobsSchema, response.data), expected);
    if (value.grantId !== grant.id || value.tenantId !== expected.tenantId || value.page !== number || value.jobs.some(row => row.grantId !== grant.id || row.tenantId !== expected.tenantId)
      || new Set(value.jobs.map(row => row.id)).size !== value.jobs.length || value.jobs.length > value.total) fail(); return value;
  },
  async schedules(grant: AutomationGrant, expected: AutomationPrincipal, number = 1) {
    const response = await api.get(base + '/schedules', { params: { grantId: grant.id, page: number } }); if (response.status !== 200) fail();
    const value = checked(parse(schedulesSchema, response.data), expected);
    if (value.grantId !== grant.id || value.tenantId !== expected.tenantId || value.page !== number || value.schedules.some(row => row.grantId !== grant.id || row.tenantId !== expected.tenantId)) fail(); return value;
  },
  async queue(grant: AutomationGrant, selectedAction: string, format: 'json' | 'csv', expected: AutomationPrincipal, intervalSeconds?: number, ruleId?: string, onChange = false) {
    if (grant.tenantId !== expected.tenantId || grant.status !== 'active' || !grant.actions.includes(action.parse(selectedAction))) fail();
    const scheduled = intervalSeconds !== undefined || onChange; if (onChange && (!isReconciliationAction(selectedAction) || intervalSeconds !== undefined)) fail(); if (intervalSeconds !== undefined && (!Number.isInteger(intervalSeconds) || intervalSeconds < 60 || intervalSeconds > 2592000)) fail();
    if (isReconciliationAction(selectedAction) ? !uuid.safeParse(ruleId).success || format !== 'json' : ruleId !== undefined) fail();
    const id = crypto.randomUUID(); const response = await api.post(base + (scheduled ? '/schedules' : '/jobs'), { id, grantId: grant.id, action: selectedAction, format, ...(isReconciliationAction(selectedAction) ? { ruleId } : {}), ...(onChange ? {onChange:true} : scheduled ? { intervalSeconds } : {}) });
    if (response.status !== 201) fail(); const value = scheduled ? checked(parse(scheduleReceipt, response.data), expected).schedule : checked(parse(jobReceipt, response.data), expected).job;
    if (value.id !== id || value.grantId !== grant.id || value.tenantId !== expected.tenantId || value.action !== selectedAction || value.format !== format || value.ruleId !== ruleId || scheduled && 'intervalSeconds' in value && (value.intervalSeconds !== (onChange ? null : intervalSeconds) || !!value.onChange !== onChange)) fail(); return value;
  },
  async revoke(grant: AutomationGrant, expected: AutomationPrincipal) {
    if (grant.tenantId !== expected.tenantId || grant.status !== 'active') fail();
    const response = await api.post(base + '/grants/' + grant.id + '/revoke', { confirm: true }, { headers: { 'If-Match': etag('grant', grant) } });
    if (response.status !== 200) fail(); const value = checked(parse(grantReceipt, response.data), expected).grant;
    if (value.id !== grant.id || value.tenantId !== expected.tenantId || value.status !== 'revoked' || value.revision !== '2') fail(); return value;
  },
  async changeJob(job: AutomationJob, operation: 'cancel' | 'retry', expected: AutomationPrincipal) {
    if (job.tenantId !== expected.tenantId) fail(); const response = await api.post(base + '/jobs/' + job.id + '/' + operation, { confirm: true }, { headers: { 'If-Match': etag('job', job) } });
    if (response.status !== 200) fail(); const value = checked(parse(jobReceipt, response.data), expected).job;
    if (value.id !== job.id || value.tenantId !== expected.tenantId || value.grantId !== job.grantId || BigInt(value.revision) <= BigInt(job.revision) || value.status !== (operation === 'cancel' ? 'cancelled' : 'queued')) fail(); return value;
  },
  async disable(schedule: AutomationSchedule, expected: AutomationPrincipal) {
    if (schedule.tenantId !== expected.tenantId) fail(); const response = await api.post(base + '/schedules/' + schedule.id + '/disable', { confirm: true }, { headers: { 'If-Match': etag('schedule', schedule) } });
    if (response.status !== 200) fail(); const value = checked(parse(scheduleReceipt, response.data), expected).schedule;
    if (value.id !== schedule.id || value.tenantId !== expected.tenantId || value.enabled || BigInt(value.revision) <= BigInt(schedule.revision)) fail(); return value;
  },
  async artifact(job: AutomationJob, expected: AutomationPrincipal) {
    const schema = z.object({ ...envelope, jobId: uuid, grantId: uuid, tenantId: uuid, rowCount: z.number().int().nonnegative(), sha256: z.string().regex(/^[a-f0-9]{64}$/),
      contentType: z.enum(['application/json', 'text/csv;charset=utf-8']), filename: z.string().regex(/^[a-z0-9.-]+\.(csv|json)$/), content: z.string().max(4194304) }).strict();
    const response = await api.get(base + '/jobs/' + job.id + '/result'); if (response.status !== 200) fail(); const value = checked(parse(schema, response.data), expected);
    if (!['succeeded','partial'].includes(job.status) || job.tenantId !== expected.tenantId || value.jobId !== job.id || value.grantId !== job.grantId || value.tenantId !== expected.tenantId || value.sha256 !== job.artifactSha256 || value.rowCount !== job.rowCount) fail();
    const actual = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value.content))), byte => byte.toString(16).padStart(2, '0')).join('');
    if (actual !== value.sha256) fail(); return value;
  },
  async licenseReport(job: AutomationJob, grant: AutomationGrant, expected: AutomationPrincipal) {
    if (job.action !== licenseAutomationAction || job.grantId !== grant.id || !job.progress) fail();
    const artifact = await this.artifact(job, expected); if (artifact.contentType !== 'application/json') fail();
    const report = parse(licenseReportSchema, JSON.parse(artifact.content));
    if (report.jobId !== job.id || report.grantId !== grant.id || report.ruleId !== job.ruleId || report.actor.id !== grant.id || report.actor.clientId !== grant.clientId || report.actor.clientRevision !== grant.clientRevision
      || report.progress.runId !== job.id || report.progress.retryCount !== job.retryCount || Object.keys(report.progress).some(key => report.progress[key as keyof typeof report.progress] !== job.progress?.[key as keyof typeof report.progress]) || report.progress.completed !== report.progress.total
      || report.results.length !== report.progress.total || report.results.length !== job.rowCount || report.progress.blocked !== report.results.filter(row => row.status === 'blocked').length
      || report.hasBlocked !== (job.status === 'partial') || report.hasBlocked !== (report.progress.blocked > 0) || new Set(report.results.map(row => row.userId)).size !== report.results.length) fail(); return report;
  },
  async history(job: AutomationJob, expected: AutomationPrincipal, number = 1) {
    const response = await api.get(base + '/jobs/' + job.id + '/history', { params: { page: number } }); if (response.status !== 200) fail(); const value = checked(parse(historySchema, response.data), expected);
    if (job.tenantId !== expected.tenantId || value.tenantId !== expected.tenantId || value.jobId !== job.id || value.page !== number || value.events.length > value.total || value.events.some((row, index) => index && BigInt(row.revision) <= BigInt(value.events[index - 1].revision))) fail(); return value;
  },
  async groupReport(job: AutomationJob, grant: AutomationGrant, expected: AutomationPrincipal) {
    if(job.action!==groupRuleAutomationAction||job.grantId!==grant.id||!job.progress)fail();
    const artifact=await this.artifact(job,expected);if(artifact.contentType!=='application/json')fail();const report=parse(groupReportSchema,JSON.parse(artifact.content));
    if(report.jobId!==job.id||report.grantId!==grant.id||report.ruleId!==job.ruleId||report.actor.id!==grant.id||report.actor.clientId!==grant.clientId||report.actor.clientRevision!==grant.clientRevision
      || report.progress.runId!==job.id||report.progress.retryCount!==job.retryCount||Object.keys(report.progress).some(key=>report.progress[key as keyof typeof report.progress]!==job.progress?.[key as keyof typeof report.progress])
      || report.progress.completed!==report.progress.total||report.results.length!==report.progress.total||report.results.length!==job.rowCount
      || report.progress.blocked!==report.results.filter(row=>['blocked','awaiting-review'].includes(row.status)).length||report.hasBlocked!==(job.status==='partial')||report.hasBlocked!==(report.progress.blocked>0)||new Set(report.results.map(row=>row.userId)).size!==report.results.length)fail();return report;
  },
};
