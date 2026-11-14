import { z } from 'zod';
import { api } from './api';
const uuid = z.string().regex(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
const time = z.string().datetime({ offset: true });
const counter = z.string().regex(/^(0|[1-9][0-9]{0,18})$/).refine(value => BigInt(value).toString() === value && BigInt(value) <= BigInt('9223372036854775807'));
const positive = counter.refine(value => value !== '0');
export const compliancePlatforms = ['macos', 'windows', 'linux'] as const;
export const complianceStates = ['compliant', 'non-compliant', 'unknown', 'not-configured', 'pending', 'stale', 'historical'] as const;
export const complianceLabels = { compliant: 'Konform', 'non-compliant': 'Abweichung', unknown: 'Unbekannt', 'not-configured': 'Keine Richtlinie', pending: 'Neue Meldung ausstehend', stale: 'Meldung abgelaufen', historical: 'Frühere Geräteverbindung' };
export const compliancePlatformLabels = { macos: 'macOS', windows: 'Windows', linux: 'Linux' };
const platforms = z.enum(['macos', 'windows', 'linux', 'ios', 'ipados', 'android', 'other']);
const version = z.string().regex(/^[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}$/).refine(value => !/\s/.test(value));
const permissions = z.array(z.enum(['devices.compliance.read', 'devices.compliance.manage'])).min(1).max(2).refine(value => value[0] === 'devices.compliance.read' && (value.length === 1 || value[1] === 'devices.compliance.manage'));
const contextSchema = z.object({ schemaVersion: z.literal(1), complianceProtocol: z.literal(1), actorUserId: uuid, tenantId: uuid, permissions }).strict();
export type ComplianceContext = z.infer<typeof contextSchema>;
export const complianceSettingsSchema = z.object({ enabled: z.boolean(), maxReportAgeSeconds: z.number().int().min(300).max(86400).multipleOf(60), minimumOsVersion: version.nullable(), requireDiskEncryption: z.boolean(), requireFirewall: z.boolean(), minimumDiskFreePercent: z.number().int().min(0).max(99).nullable() }).strict().refine(value => !value.enabled || value.minimumOsVersion !== null || value.requireDiskEncryption || value.requireFirewall || value.minimumDiskFreePercent !== null);
export type ComplianceSettings = z.infer<typeof complianceSettingsSchema>;
const policySchema = z.object({ tenantId: uuid, platform: z.enum(compliancePlatforms), revision: counter, settings: complianceSettingsSchema, createdAt: time.nullable(), updatedAt: time.nullable() }).strict().refine(value => value.revision === '0' ? value.createdAt === null && value.updatedAt === null : value.createdAt !== null && value.updatedAt !== null && Date.parse(value.createdAt) <= Date.parse(value.updatedAt));
export type CompliancePolicy = z.infer<typeof policySchema>;
const capacity = z.object({ totalBytes: positive, availableBytes: counter }).strict().refine(value => BigInt(value.availableBytes) <= BigInt(value.totalBytes));
const observation = z.object({ state: z.enum(['enabled', 'disabled', 'unknown']), reason: z.enum(['checked', 'probe-failed', 'timeout', 'unrecognized', 'not-supported']) }).strict().refine(value => value.state === 'unknown' ? value.reason !== 'checked' : value.reason === 'checked');
const security = z.object({ schemaVersion: z.literal(1), osVersion: version.nullable(), diskEncryption: observation, firewall: observation }).strict();
const source = z.object({ schemaVersion: z.literal(1), facts: security, receivedAt: time, enrolledAt: time, revision: positive, platform: z.enum(compliancePlatforms), agentVersion: z.string().min(1).max(40) }).strict();
const check = z.object({ id: z.enum(['os-version', 'disk-encryption', 'firewall', 'disk-free']), status: z.enum(['pass', 'fail', 'unknown']), expected: z.union([z.literal(true), version, z.number().int().min(0).max(99)]), actual: z.union([z.string().max(64), capacity]).nullable(), reason: z.enum(['checked', 'not-reported', 'source-not-current', 'probe-failed', 'timeout', 'unrecognized', 'not-supported']) }).strict();
const assessment = z.object({ schemaVersion: z.literal(1), tenantId: uuid, deviceId: uuid, platform: z.enum(compliancePlatforms), policyRevision: counter, policySettings: complianceSettingsSchema, evaluatedAt: time, validUntil: time, enrolledAt: time, agentRevision: positive, security: source, hardware: z.object({ receivedAt: time, enrolledAt: time, revision: positive, systemDisk: capacity }).strict().nullable(), checks: z.array(check).max(4), status: z.enum(['compliant', 'non-compliant', 'unknown', 'not-configured']), fingerprint: z.string().regex(/^[a-f0-9]{32}$/) }).strict().refine(value => new Set(value.checks.map(row => row.id)).size === value.checks.length && Date.parse(value.security.receivedAt) <= Date.parse(value.evaluatedAt) && Date.parse(value.evaluatedAt) <= Date.parse(value.validUntil) && (value.status !== 'compliant' || value.checks.length > 0 && value.checks.every(row => row.status === 'pass')));
const reportSchema = z.object({ schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, deviceId: uuid, assetId: z.string().min(1), platform: platforms, checkedAt: time, policyRevision: counter, status: z.enum(complianceStates), assessment: assessment.nullable() }).strict().refine(value => !value.assessment || value.assessment.deviceId === value.deviceId && value.assessment.tenantId === value.tenantId && Date.parse(value.assessment.evaluatedAt) <= Date.parse(value.checkedAt));
export type ComplianceReport = z.infer<typeof reportSchema>;
const count = z.number().int().nonnegative().safe();
const fleetSchema = z.object({ schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, checkedAt: time, page: z.number().int().min(1).max(1000000), limit: z.literal(25), total: count, counts: z.object({ total: count, compliant: count, 'non-compliant': count, unknown: count, 'not-configured': count, pending: count, stale: count, historical: count }).strict(), devices: z.array(z.object({ deviceId: uuid, assetId: z.string().min(1), platform: platforms, status: z.enum(complianceStates), policyRevision: counter, evaluatedAt: time.nullable() }).strict()).max(25) }).strict().refine(value => value.counts.total === complianceStates.reduce((sum, status) => sum + value.counts[status], 0) && value.devices.length === Math.min(25, Math.max(0, value.total - (value.page - 1) * 25)) && new Set(value.devices.map(row => row.deviceId)).size === value.devices.length);
export type ComplianceFleet = z.infer<typeof fleetSchema>;
const policyEvent = z.object({ id: uuid, createdAt: time, correlationId: uuid, before: policySchema.nullable(), after: policySchema, actorUserId: uuid, reason: z.string().min(10).max(500), deliveryStatus: z.literal('pending') }).strict();
const deviceEvent = z.object({ id: uuid, createdAt: time, correlationId: uuid, before: assessment.nullable(), after: assessment }).strict();
const historySchema = z.object({ schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, target: z.string(), page: z.number().int().min(1).max(1000000), limit: z.literal(25), total: count, events: z.array(z.union([policyEvent, deviceEvent])).max(25) }).strict();
export type ComplianceHistory = z.infer<typeof historySchema>;
function bound<Result extends { actorUserId: string; tenantId?: string }>(value: Result, context: ComplianceContext, signal: AbortSignal): Result {
 if (signal.aborted || value.actorUserId !== context.actorUserId || value.tenantId !== undefined && value.tenantId !== context.tenantId) throw new Error('Unconfirmed compliance source'); return value;
}
export async function complianceAccess(signal: AbortSignal) { const response = await api.get('/api/devices/compliance/capabilities', { signal }); if (response.status !== 200 || signal.aborted) throw new Error('Unconfirmed compliance access'); return contextSchema.parse(response.data); }
export async function readCompliancePolicies(context: ComplianceContext, signal: AbortSignal) {
 const response = await api.get('/api/devices/compliance/policies', { signal }); const result = bound(z.object({ schemaVersion: z.literal(1), actorUserId: uuid, tenantId: uuid, permissions, policies: z.array(policySchema).length(3) }).strict().parse(response.data), context, signal);
 if (response.status !== 200 || JSON.stringify(result.permissions) !== JSON.stringify(context.permissions) || new Set(result.policies.map(row => row.platform)).size !== 3 || result.policies.some(row => row.tenantId !== context.tenantId)) throw new Error('Unconfirmed company policies'); return result.policies;
}
export async function readComplianceFleet(context: ComplianceContext, params: { page: number; search?: string; status?: string; platform?: string }, signal: AbortSignal) {
 const response = await api.get('/api/devices/compliance', { params, signal }); const result = bound(fleetSchema.parse(response.data), context, signal);
 if (response.status !== 200 || result.page !== params.page || result.total !== (params.status ? result.counts[params.status as keyof typeof result.counts] : result.counts.total) || result.devices.some(row => params.platform && row.platform !== params.platform || params.status && row.status !== params.status)) throw new Error('Unconfirmed compliance page'); return result;
}
export async function readComplianceReport(context: ComplianceContext, deviceId: string, signal: AbortSignal) {
 const response = await api.get('/api/devices/' + uuid.parse(deviceId) + '/compliance', { signal }); const result = bound(reportSchema.parse(response.data), context, signal);
 if (response.status !== 200 || result.deviceId !== deviceId) throw new Error('Unconfirmed device assessment'); return result;
}
export async function readComplianceHistory(context: ComplianceContext, target: string, page: number, policy: boolean, signal: AbortSignal) {
 const path = policy ? '/api/devices/compliance/policies/' + z.enum(compliancePlatforms).parse(target) : '/api/devices/' + uuid.parse(target) + '/compliance';
 const response = await api.get(path + '/history', { params: { page }, signal }); const result = bound(historySchema.parse(response.data), context, signal);
 if (response.status !== 200 || result.target !== target || result.page !== page || result.events.length !== Math.min(25, Math.max(0, result.total - (page - 1) * 25)) || new Set(result.events.map(row => row.id)).size !== result.events.length || result.events.some(row => policy ? !('actorUserId' in row) || row.after.tenantId !== context.tenantId : 'actorUserId' in row || row.after.tenantId !== context.tenantId || row.after.deviceId !== target)) throw new Error('Unconfirmed compliance history'); return result;
}
export async function saveCompliancePolicy(context: ComplianceContext, previous: CompliancePolicy, input: ComplianceSettings, reason: string, signal: AbortSignal) {
 if (!context.permissions.includes('devices.compliance.manage') || previous.tenantId !== context.tenantId || previous.revision === '9223372036854775807') throw new Error('Confirmed compliance manager required');
 const settings = complianceSettingsSchema.parse(input); const explanation = reason.trim(); if (Array.from(explanation).length < 10 || Array.from(explanation).length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(explanation)) throw new Error('Begründung mit 10–500 Zeichen erforderlich.');
 const response = await api.put('/api/devices/compliance/policies/' + previous.platform, { settings, reason: explanation, confirm: true }, { headers: { 'If-Match': `"device-compliance-${context.tenantId}-${previous.platform}-${previous.revision}"` }, signal });
 const result = bound(z.object({ schemaVersion: z.literal(1), actorUserId: uuid, policy: policySchema, eventId: uuid, deliveryStatus: z.literal('pending') }).strict().parse(response.data), context, signal);
 if (response.status !== 200 || result.policy.tenantId !== context.tenantId || result.policy.platform !== previous.platform || BigInt(result.policy.revision) !== BigInt(previous.revision) + BigInt(1) || Object.keys(settings).some(key => settings[key as keyof ComplianceSettings] !== result.policy.settings[key as keyof ComplianceSettings])) throw new Error('Actual policy change unconfirmed'); return result.policy;
}
export function complianceError(error: unknown): string {
 const status = (error as { response?: { status?: number } })?.response?.status;
 return ({ 401: 'Die ursprüngliche Anmeldung ist nicht mehr gültig. Bitte erneut anmelden.', 403: 'Für diese Funktion fehlt die tatsächliche Compliance-Berechtigung. PIM-Aufgabe oder Firmenrolle prüfen.', 428: 'Eine höchstens fünf Minuten alte MFA-Anmeldung ist erforderlich. Bitte erneut anmelden.', 412: 'Die Richtlinie wurde geändert. Neu laden und die eigene Änderung erneut prüfen.', 409: 'Die Richtlinie ist unverändert oder der Zustand hat sich geändert. Bitte neu laden.', 400: 'Richtlinie oder Eingabefelder sind ungültig.', 503: 'Die Compliance-Quelle ist momentan nicht erreichbar. Bitte neu laden.' } as Record<number, string>)[status || 0] || 'Die Compliance-Antwort konnte nicht bestätigt werden. Bitte neu laden.';
}

export const deviceComplianceAssessmentSchema = assessment;
export const agentSecurityReceiptSchema = source;
