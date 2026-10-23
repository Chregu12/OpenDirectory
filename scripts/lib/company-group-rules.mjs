import { randomUUID } from 'node:crypto'; import { isDeepStrictEqual } from 'node:util';
import contract from '../../packages/company-group-rule-contract.js'; import { identifier, text } from '../../packages/company-license-contract/index.js';
const path = id => '/api/groups/' + identifier(id) + '/rule';
function checked(response, groupId, expected) {
 const value = response.data;
 if (response.status !== 200 || value?.schemaVersion !== 1 || value.companyGroupRuleProtocol !== 1) throw new Error('Group rule result unconfirmed; read stored state before retrying');
 identifier(value.actorUserId); identifier(value.tenantId);
 if (value.groupId !== groupId || expected && (value.actorUserId !== expected.actorUserId || value.tenantId !== expected.tenantId)) throw new Error('Group rule principal or target unconfirmed'); return value;
}
export function createGroupRuleClient(client) {
 const request = (method, route, body, options = {}) => client.request(method, route, body, { ...options, administrative: true });
 const api = {
  async get(groupId) {
   const response = await request('GET', path(groupId)); const value = checked(response, groupId);
   if (!Object.hasOwn(value,'rule') || value.executionMode !== 'manual' || value.etag !== contract.etag(groupId, value.rule?.revision || null) || response.etag !== value.etag || value.rule && (value.rule.groupId !== groupId || value.rule.tenantId !== value.tenantId || typeof value.rule.enabled !== 'boolean')) throw new Error('Current group rule version unconfirmed');
   if (value.rule) contract.draft(value.rule.draft); return value;
  },
  async configure(groupId, input) {
   const values = contract.command(input); const current = await api.get(groupId); const response = await request('PUT', path(groupId), values, { etag: current.etag, operationId: randomUUID() });
   const value = checked({ ...response, data: { ...response.data, groupId: response.data?.rule?.groupId } }, groupId, current);
   if (!['applied','already_applied'].includes(value.outcome) || value.rule.tenantId !== current.tenantId || value.rule.enabled !== values.enabled || !isDeepStrictEqual(value.rule.draft, values.draft)
    || response.etag !== contract.etag(groupId,value.rule.revision) || value.rule.revision !== String(BigInt(current.rule?.revision || '0')+1n)) throw new Error('Group rule configuration unconfirmed'); return value;
  },
  async preview(groupId) {
   const current = await api.get(groupId); const value = checked(await request('GET', path(groupId) + '/preview', undefined, { maxResponseBytes: 4 * 1024 * 1024 }), groupId, current);
   if (value.executionMode !== 'manual' || value.ruleRevision !== current.rule?.revision || typeof value.observation !== 'string' || !/^[a-f0-9]{64}$/.test(value.observation)
    || !Array.isArray(value.desired) || value.desired.length > 10000 || !Array.isArray(value.existing) || value.existing.length > 10000 || new Set(value.desired.map(row => row.userId)).size !== value.desired.length || new Set(value.existing.map(row => row.userId)).size !== value.existing.length) throw new Error('Complete group rule observation unconfirmed');
   for (const row of [...value.desired,...value.existing]) identifier(row.userId); for (const row of value.existing) { identifier(row.membershipId); if (typeof row.managed !== 'boolean' || typeof row.effective !== 'boolean' || row.validUntil !== null && (typeof row.validUntil !== 'string' || !Number.isFinite(Date.parse(row.validUntil)) || new Date(row.validUntil).toISOString() !== row.validUntil) || !row.effective && row.validUntil !== null) throw new Error('Group rule provenance unconfirmed'); } return value;
  },
  async sync(groupId, reason) {
   reason = text(reason,10,500);
   const preview = await api.preview(groupId); const targets = [...new Set([...preview.desired.map(row => row.userId), ...preview.existing.filter(row => row.managed).map(row => row.userId)])].sort();
   const results = []; let cursor = null;
   for (let iteration = 0; iteration < 400; iteration++) {
    const response = await request('POST', path(groupId) + '/sync', { observation: preview.observation, cursor, reason, confirm: true }); const value = checked(response, groupId, preview);
    const expected = targets.slice(results.length, results.length + 25);
    if (value.observation !== preview.observation || value.ruleRevision !== preview.ruleRevision || !Array.isArray(value.results) || value.results.length !== expected.length
     || value.hasBlocked !== value.results.some(row => row.status === 'blocked') || value.nextCursor !== (results.length + expected.length < targets.length ? expected.at(-1) : null)) throw new Error('Group rule page unconfirmed; earlier membership changes may be committed');
    value.results.forEach((row,index) => { if (row.userId !== expected[index] || !['added','retained','manual-retained','removed','awaiting-review','blocked'].includes(row.status) || (row.status === 'blocked' ? ![403,404,409,428].includes(row.code) : row.code !== null)) throw new Error('Group rule member result unconfirmed'); });
    results.push(...value.results); if (value.nextCursor === null) return { groupId, ruleRevision: preview.ruleRevision, results, hasBlocked: results.some(row => row.status === 'blocked'), requiresReview: results.some(row => row.status === 'awaiting-review') }; cursor = value.nextCursor;
   } throw new Error('Group rule page limit exceeded; inspect stored membership state');
  },
  async history(groupId, page = 1) {
   if (!Number.isInteger(page) || page < 1 || page > 999999) throw new Error('Bounded history page required'); const current = await api.get(groupId);
   const value = checked(await request('GET', path(groupId) + '/history?page=' + page), groupId, current);
   if (value.page !== page || value.limit !== 25 || !Array.isArray(value.events) || value.events.length > 25) throw new Error('Group rule history page unconfirmed'); return value;
  },
 }; return api;
}
