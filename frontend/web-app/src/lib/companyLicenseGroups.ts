import { z } from 'zod';
import { api } from './api';
import { companyUuid as uuid, companyRevision, companyReason, CompanyWire } from './companyAssignmentProtocol';
const base = '/api/licenses/company/groups';
const context = { schemaVersion: z.literal(1), companyLicenseGroupsProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, allocationMode: z.literal('local-only') };
const ruleSchema = z.object({ id: uuid, tenantId: uuid, groupId: uuid, poolId: uuid, blueprintId: uuid, status: z.enum(['active', 'unlinked']), revision: z.enum(['1', '2']),
  createdAt: z.string().datetime({ offset: true }), updatedAt: z.string().datetime({ offset: true }) }).strict().refine(rule => rule.status === 'active' ? rule.revision === '1' : rule.revision === '2');
const listSchema = z.object({ ...context, rules: z.array(ruleSchema).max(100), truncated: z.boolean() }).strict();
const receiptSchema = z.object({ ...context, rule: ruleSchema }).strict();
const previewSchema = receiptSchema.extend({ groupRevision: companyRevision.nullable(), groupName: z.string().nullable(),
  eligibleMembers: z.number().int().nonnegative(), assignedMembers: z.number().int().nonnegative(), pendingMembers: z.number().int().nonnegative(), removalMembers: z.number().int().nonnegative() }).strict();
const rowSchema = z.object({ userId: uuid, status: z.enum(['assigned', 'removed', 'retained', 'blocked']), code: z.number().int().min(400).max(499).nullable() }).strict()
  .refine(row => row.status === 'blocked' ? row.code !== null : row.code === null);
const syncSchema = receiptSchema.extend({ groupRevision: companyRevision.nullable(), results: z.array(rowSchema).max(25), nextCursor: uuid.nullable(), hasBlocked: z.boolean() }).strict();
export type CompanyLicenseGroup = Required<z.infer<typeof ruleSchema>>;
export type LicenseGroupContext = { actorUserId: string; tenantId: string };
export type LicenseGroupResult = Required<z.infer<typeof rowSchema>>;
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): CompanyWire<z.infer<S>> { return schema.parse(value); }
function reject(): never { throw new Error('Lizenzgruppen-Ergebnis nicht bestätigt. Gruppen-, Pool- und Zuweisungsstand prüfen; frühere Mitglieder können bereits verarbeitet sein.'); }
function checked<T extends LicenseGroupContext>(result: T, expected: LicenseGroupContext) { if (result.actorUserId !== expected.actorUserId || result.tenantId !== expected.tenantId) reject(); return result; }
function sameRule(left: CompanyLicenseGroup, right: CompanyLicenseGroup) { if (['id', 'tenantId', 'groupId', 'poolId', 'blueprintId', 'revision', 'status'].some(key => left[key as keyof CompanyLicenseGroup] !== right[key as keyof CompanyLicenseGroup])) reject(); }
export const companyLicenseGroups = {
  async inspect(ruleId: string, expected: LicenseGroupContext) {
    uuid.parse(ruleId); const response = await api.get(base + '/' + ruleId + '/preview');
    if (response.status !== 200) reject(); const result = checked(parse(previewSchema, response.data), expected);
    if (result.rule.id !== ruleId || result.rule.tenantId !== expected.tenantId) reject(); return result;
  },
  async list(groupId: string, actorUserId: string, signal?: AbortSignal) {
    uuid.parse(groupId); uuid.parse(actorUserId); const response = await api.get(base, { params: { groupId }, signal });
    if (response.status !== 200) reject(); const result = parse(listSchema, response.data);
    if (result.actorUserId !== actorUserId || result.rules.some(rule => rule.groupId !== groupId || rule.tenantId !== result.tenantId)
      || new Set(result.rules.map(rule => rule.id)).size !== result.rules.length) reject(); return result;
  },
  async link(groupId: string, poolId: string, reason: string, expected: LicenseGroupContext) {
    uuid.parse(groupId); uuid.parse(poolId);
    const current = await this.list(groupId, expected.actorUserId); checked(current, expected);
    const response = await api.post(base, { groupId, poolId, reason: companyReason(reason), confirm: true }, { headers: { 'Idempotency-Key': crypto.randomUUID() } });
    if (response.status !== 201) reject(); const result = checked(parse(receiptSchema, response.data), expected);
    if (result.rule.groupId !== groupId || result.rule.poolId !== poolId || result.rule.tenantId !== expected.tenantId || result.rule.status !== 'active') reject(); return result.rule;
  },
  async unlink(rule: CompanyLicenseGroup, reason: string, expected: LicenseGroupContext) {
    uuid.parse(rule.id); if (rule.status !== 'active' || rule.tenantId !== expected.tenantId) reject();
    checked(await this.list(rule.groupId, expected.actorUserId), expected);
    const response = await api.post(base + '/' + rule.id + '/unlink', { reason: companyReason(reason), confirm: true }, { headers: { 'Idempotency-Key': crypto.randomUUID(), 'If-Match': `"company-license-group-${rule.id}-${rule.revision}"` } });
    if (response.status !== 200) reject(); const result = checked(parse(receiptSchema, response.data), expected);
    sameRule({ ...rule, status: 'unlinked', revision: '2' }, result.rule); return result.rule;
  },
  async sync(rule: CompanyLicenseGroup, reason: string, expected: LicenseGroupContext, alive: () => boolean = () => true): Promise<LicenseGroupResult[]> {
    uuid.parse(rule.id); if (!alive()) reject();
    const preview = await api.get(base + '/' + rule.id + '/preview'); if (!alive() || preview.status !== 200) reject();
    const captured = checked(parse(previewSchema, preview.data), expected); sameRule(rule, captured.rule);
    let cursor: string | null = null; const results: LicenseGroupResult[] = [];
    do {
      if (!alive() || results.length >= 20000) reject();
      const response = await api.post(base + '/' + rule.id + '/sync', { groupRevision: captured.groupRevision, cursor, reason: companyReason(reason), confirm: true });
      if (!alive() || response.status !== 200) reject(); const page = checked(parse(syncSchema, response.data), expected); sameRule(rule, page.rule);
      if (page.groupRevision !== captured.groupRevision || page.hasBlocked !== page.results.some(row => row.status === 'blocked')
        || page.results.some((row, index) => row.userId <= (index ? page.results[index - 1].userId : cursor || ''))
        || page.nextCursor !== null && page.nextCursor !== page.results.at(-1)?.userId) reject();
      results.push(...page.results as LicenseGroupResult[]); cursor = page.nextCursor;
    } while (cursor !== null);
    return results;
  },
};
