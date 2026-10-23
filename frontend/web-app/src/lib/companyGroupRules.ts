import { z } from 'zod';
import { api } from './api';
import { companyUuid as uuid, companyRevision as revision, companyReason, CompanyWire } from './companyAssignmentProtocol';
export const groupRuleAttributes = ['department','title','email','username','displayName'] as const;
export const groupRuleOperators = ['equals','startsWith','endsWith'] as const;
const condition = z.object({ attribute: z.enum(groupRuleAttributes), operator: z.enum(groupRuleOperators), value: z.string().min(1).max(160).refine(value => value.trim() === value && !/[\u0000-\u001f\u007f-\u009f]/.test(value)) }).strict();
const ids = (maximum: number) => z.array(uuid).max(maximum).refine(values => new Set(values).size === values.length);
const draftSchema = z.object({ dynamic: z.object({ all: z.array(condition).min(1).max(8) }).strict().nullable(), childGroupIds: ids(25), excludedUserIds: ids(10000) }).strict().refine(value => !!value.dynamic || value.childGroupIds.length > 0);
const stamp = z.string().datetime({ offset: true }); const sha = z.string().regex(/^[a-f0-9]{64}$/);
const ruleSchema = z.object({ groupId: uuid, tenantId: uuid, revision, enabled: z.boolean(), draft: draftSchema, createdBy: uuid, createdAt: stamp, updatedAt: stamp }).strict();
const envelope = { schemaVersion: z.literal(1), companyGroupRuleProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid };
const pageSchema = z.object({ ...envelope, groupId: uuid, rule: ruleSchema.nullable(), etag: z.string(), executionMode: z.literal('manual') }).strict();
const previewSchema = z.object({ ...envelope, groupId: uuid, groupName: z.string().max(255), groupRevision: revision, ruleRevision: revision, enabled: z.boolean(), observation: sha, executionMode: z.literal('manual'),
 desired: z.array(z.object({ userId: uuid, eligibilityRevision: revision }).strict()).max(10000), existing: z.array(z.object({ userId: uuid, membershipId: uuid, managed: z.boolean(), effective: z.boolean(), validUntil: stamp.nullable() }).strict()).max(10000), additions: z.number().int().min(0).max(10000) }).strict();
const resultSchema = z.object({ userId: uuid, status: z.enum(['added','retained','manual-retained','removed','awaiting-review','blocked']), code: z.union([z.literal(403),z.literal(404),z.literal(409),z.literal(428)]).nullable() }).strict().refine(row => row.status === 'blocked' ? row.code !== null : row.code === null);
const receiptSchema = z.object({ ...envelope, outcome: z.enum(['applied','already_applied']), rule: ruleSchema }).strict();
const syncSchema = z.object({ ...envelope, groupId: uuid, ruleRevision: revision, observation: sha, results: z.array(resultSchema).max(25), nextCursor: uuid.nullable(), hasBlocked: z.boolean() }).strict();
const historySchema = z.object({ ...envelope, groupId: uuid, page: z.number().int().positive(), limit: z.literal(25), total: z.number().int().nonnegative(), events: z.array(z.object({ id: uuid, kind: z.enum(['configuration','membership']), action: z.enum(['configured','member-add','member-remove']), userId: uuid.nullable(), membershipId: uuid.nullable(), ruleRevision: revision, actorUserId: uuid.nullable(), application: z.object({grantId:uuid,clientId:z.string().min(1).max(255),clientRevision:revision}).strict().optional(), reason: z.string().min(10).max(500), createdAt: stamp, deliveryStatus: z.literal('pending') }).strict()).max(25) }).strict();
export type CompanyGroupRuleDraft = CompanyWire<z.infer<typeof draftSchema>>;
export type CompanyGroupRulePage = CompanyWire<z.infer<typeof pageSchema>>;
export type CompanyGroupRulePreview = CompanyWire<z.infer<typeof previewSchema>>;
export type CompanyGroupRuleResult = CompanyWire<z.infer<typeof resultSchema>>;
export type CompanyGroupRuleHistory = CompanyWire<z.infer<typeof historySchema>>;
const base = (id: string) => '/api/groups/' + uuid.parse(id) + '/rule';
const etag = (id: string, version: string | null) => `"group-rule-${id}-${version === null ? 'absent' : version}"`;
function fail(): never { throw new Error('Gruppenregel oder Ergebnis nicht bestätigt. Neu laden; frühere Mitgliedsschritte können bereits gespeichert sein.'); }
function checked(value: { actorUserId: string; tenantId: string; groupId: string }, groupId: string, actorUserId: string, tenantId?: string) { if (value.groupId !== groupId || value.actorUserId !== actorUserId || tenantId && value.tenantId !== tenantId) fail(); }
export const companyGroupRules = {
 async get(groupId: string, actorUserId: string): Promise<CompanyGroupRulePage> {
  const response = await api.get(base(groupId)); if (response.status !== 200) fail(); const value = pageSchema.parse(response.data); checked(value as CompanyGroupRulePage, groupId, actorUserId);
  if (value.etag !== etag(groupId, value.rule?.revision || null) || value.rule && (value.rule.groupId !== groupId || value.rule.tenantId !== value.tenantId)) fail(); return value as CompanyGroupRulePage;
 },
 async save(page: CompanyGroupRulePage, draft: CompanyGroupRuleDraft, enabled: boolean, reason: string) {
  const normalized = draftSchema.parse(draft); const body = { draft: { ...normalized, childGroupIds: [...normalized.childGroupIds].sort(), excludedUserIds: [...normalized.excludedUserIds].sort() }, enabled, reason: companyReason(reason), confirm: true };
  const response = await api.put(base(page.groupId), body, { headers: { 'If-Match': page.etag, 'Idempotency-Key': crypto.randomUUID() } }); if (response.status !== 200) fail(); const value = receiptSchema.parse(response.data);
  checked({ ...value, groupId: value.rule.groupId } as CompanyGroupRulePage, page.groupId, page.actorUserId, page.tenantId);
  if (value.rule.tenantId !== page.tenantId || value.rule.enabled !== enabled || JSON.stringify(value.rule.draft) !== JSON.stringify(body.draft) || value.rule.revision !== String(BigInt(page.rule?.revision || '0')+BigInt(1))) fail(); return value;
 },
 async preview(page: CompanyGroupRulePage): Promise<CompanyGroupRulePreview> {
  const response = await api.get(base(page.groupId) + '/preview'); if (response.status !== 200) fail(); const value = previewSchema.parse(response.data); checked(value as CompanyGroupRulePreview, page.groupId, page.actorUserId, page.tenantId);
  if (value.ruleRevision !== page.rule?.revision || value.enabled !== page.rule.enabled || new Set(value.desired.map(row => row.userId)).size !== value.desired.length || new Set(value.existing.map(row => row.userId)).size !== value.existing.length
   || value.existing.some(row => !row.effective && row.validUntil !== null) || value.additions !== value.desired.filter(row => !value.existing.some(member => member.userId === row.userId)).length) fail(); return value as CompanyGroupRulePreview;
 },
 async history(page: CompanyGroupRulePage, number = 1): Promise<CompanyGroupRuleHistory> {
  const response = await api.get(base(page.groupId) + '/history', { params: { page: number } }); if (response.status !== 200) fail(); const value = historySchema.parse(response.data); checked(value as CompanyGroupRuleHistory, page.groupId, page.actorUserId, page.tenantId);
  if (value.page !== number || value.events.length > value.total || new Set(value.events.map(row => row.id)).size !== value.events.length
   || value.events.some(event=>event.actorUserId===null ? !event.application||event.kind!=='membership' : !!event.application)) fail(); return value as CompanyGroupRuleHistory;
 },
 async sync(preview: CompanyGroupRulePreview, reason: string, onPage: (count: number) => void = () => {}): Promise<CompanyGroupRuleResult[]> {
  const targets = Array.from(new Set([...preview.desired.map(row => row.userId), ...preview.existing.filter(row => row.managed).map(row => row.userId)])).sort(); const results: CompanyGroupRuleResult[] = []; let cursor: string | null = null;
  for (let number = 0; number < 400; number++) {
   const response = await api.post(base(preview.groupId) + '/sync', { observation: preview.observation, cursor, reason: companyReason(reason), confirm: true }); if (response.status !== 200) fail(); const value = syncSchema.parse(response.data); checked(value as CompanyGroupRulePreview, preview.groupId, preview.actorUserId, preview.tenantId);
   const selected = targets.slice(results.length, results.length + 25); if (value.ruleRevision !== preview.ruleRevision || value.observation !== preview.observation || value.results.length !== selected.length || value.results.some((row, index) => row.userId !== selected[index])
    || value.hasBlocked !== value.results.some(row => row.status === 'blocked') || value.nextCursor !== (results.length + selected.length < targets.length ? selected.at(-1) : null)) fail();
   results.push(...value.results as CompanyGroupRuleResult[]); onPage(results.length); if (value.nextCursor === null) return results; cursor = value.nextCursor;
  } fail();
 },
};
