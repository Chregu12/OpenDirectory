import { randomUUID } from 'node:crypto';
import contract from '../../packages/company-license-group-contract.js';
const base = '/api/licenses/company/groups';
const uuid = value => typeof value === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value);
const revision = value => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n;
const fail = () => { throw new Error('Group or license result unconfirmed; inspect state before retrying. Earlier operations may be committed.'); };
function id(value) { if (!uuid(value)) fail(); return value; }
function rule(value, tenantId) {
  if (!value || ['id', 'groupId', 'poolId', 'blueprintId'].some(key => !uuid(value[key])) || value.tenantId !== tenantId
    || !(value.status === 'active' && value.revision === '1' || value.status === 'unlinked' && value.revision === '2')) fail();
  return value;
}
function envelope(value, expected) {
  if (value?.schemaVersion !== 1 || value.companyLicenseGroupsProtocol !== 1 || value.allocationMode !== 'local-only'
    || !uuid(value.actorUserId) || !uuid(value.tenantId) || expected && (value.actorUserId !== expected.actorUserId || value.tenantId !== expected.tenantId)) fail();
  return value;
}
function same(left, right) { if (['id', 'groupId', 'poolId', 'blueprintId', 'tenantId', 'status', 'revision'].some(key => left[key] !== right[key])) fail(); }
function group(value, expectedId) {
  if (!value || !uuid(value.id) || expectedId && value.id !== expectedId || !revision(value.revision) || typeof value.name !== 'string'
    || !Array.isArray(value.members) || value.members.length > 10000 || value.members.some(member => !uuid(member)) || new Set(value.members).size !== value.members.length) fail();
  return value;
}
export function createGroupClient(client) {
  const request = (method, path, body, options = {}) => client.request(method, path, body, { ...options, administrative: true });
  async function access(protocol, permission) {
    const result = await request('GET', '/api/identity/access'); const value = result.data;
    if (result.status !== 200 || !uuid(value?.userId) || value.demoMode !== false || value[protocol] !== 1 || !value.permissions?.includes(permission)) fail();
    return value;
  }
  async function list(groupId) {
    const result = await request('GET', base + (groupId === undefined ? '' : '?groupId=' + id(groupId))); const value = envelope(result.data);
    if (result.status !== 200 || value.truncated !== false || !Array.isArray(value.rules) || value.rules.length > 100
      || new Set(value.rules.map(row => row.id)).size !== value.rules.length) fail();
    for (const row of value.rules) { rule(row, value.tenantId); if (groupId && row.groupId !== groupId) fail(); }
    return value;
  }
  async function preview(ruleId, expected) {
    const result = await request('GET', base + '/' + id(ruleId) + '/preview'); const value = envelope(result.data, expected);
    if (result.status !== 200 || result.etag !== `"company-license-group-${ruleId}-${value.rule?.revision}"`) fail();
    rule(value.rule, value.tenantId); if (value.rule.id !== ruleId || !(value.groupRevision === null || revision(value.groupRevision))) fail();
    return { ...value, etag: result.etag };
  }
  async function sync(ruleId, reason, expected) {
    const captured = await preview(ruleId, expected); let cursor = null; const results = [];
    do {
      if (results.length >= 20000) fail();
      const body = contract.syncValues({ groupRevision: captured.groupRevision, cursor, reason, confirm: true });
      const response = await request('POST', base + '/' + id(ruleId) + '/sync', body); const value = envelope(response.data, captured);
      if (response.status !== 200) fail(); rule(value.rule, captured.tenantId); same(captured.rule, value.rule);
      if (value.groupRevision !== captured.groupRevision || !Array.isArray(value.results) || value.results.length > 25
        || value.results.some((row, index) => !uuid(row.userId) || row.userId <= (index ? value.results[index - 1].userId : cursor || '')
          || !['assigned', 'removed', 'retained', 'blocked'].includes(row.status) || (row.status === 'blocked' ? !Number.isInteger(row.code) || row.code < 400 || row.code > 499 : row.code !== null))
        || value.hasBlocked !== value.results.some(row => row.status === 'blocked')
        || value.nextCursor !== null && (!uuid(value.nextCursor) || value.nextCursor !== value.results.at(-1)?.userId)) fail();
      results.push(...value.results); cursor = value.nextCursor;
    } while (cursor !== null);
    return { rule: captured.rule, results, hasBlocked: results.some(row => row.status === 'blocked'), allocationMode: 'local-only' };
  }
  async function linkPool(groupId, poolId, reason, operationId = randomUUID()) {
    const before = await list(id(groupId)); const body = contract.linkValues({ groupId, poolId, reason, confirm: true });
    const response = await request('POST', base, body, { operationId: id(operationId) }); const value = envelope(response.data, before);
    if (response.status !== 201) fail(); const linked = rule(value.rule, before.tenantId);
    if (linked.groupId !== groupId || linked.poolId !== poolId || linked.status !== 'active') fail();
    return sync(linked.id, reason, before);
  }
  return {
    list, sync, linkPool,
    async create(name) {
      const before = await access('directoryCreationProtocol', 'groups.create');
      if (typeof name !== 'string' || !name.trim() || name.length > 255) fail();
      const result = await request('POST', '/api/groups', { name: name.trim() }); const value = group(result.data);
      if (result.status !== 201 || value.name !== name.trim() || value.members.length !== 0) fail();
      const after = await access('directoryReadProtocol', 'groups.read'); if (after.userId !== before.userId) fail(); return value;
    },
    async member(action, groupId, userId, reason = 'Skript: Gruppenmitgliedschaft abgleichen') {
      if (!['add', 'remove'].includes(action)) fail(); id(groupId); id(userId);
      const actor = await access('directoryGroupMutationProtocol', 'groups.members.manage');
      const before = await request('GET', '/api/groups/' + groupId); const original = group(before.data, groupId);
      const etag = `"group-${groupId}-${original.revision}"`; if (before.status !== 200 || before.etag !== etag) fail();
      if (original.members.includes(userId) === (action === 'add')) fail();
      const response = await request(action === 'add' ? 'POST' : 'DELETE', '/api/groups/' + groupId + '/members' + (action === 'add' ? '' : '/' + userId), action === 'add' ? { userId } : undefined, { etag });
      const changed = group(response.data, groupId);
      const expected = action === 'add' ? [...original.members, userId] : original.members.filter(member => member !== userId);
      if (response.status !== 200 || BigInt(changed.revision) <= BigInt(original.revision) || expected.length !== changed.members.length || expected.some(member => !changed.members.includes(member))) fail();
      if (!actor.companyOwner) return { group: changed, membershipConfirmed: true, membershipReview: response.data.membershipReview || null, licenses: [], hasBlocked: false };
      const linked = await list(groupId); if (linked.actorUserId !== actor.userId) fail(); const licenses = [];
      for (const row of linked.rules) licenses.push(await sync(row.id, reason, linked));
      return { group: changed, membershipConfirmed: true, membershipReview: response.data.membershipReview || null, licenses, hasBlocked: licenses.some(row => row.hasBlocked) };
    },
    async unlink(ruleId, reason) {
      const captured = await preview(ruleId); if (captured.rule.status !== 'active') fail();
      const response = await request('POST', base + '/' + id(ruleId) + '/unlink', contract.unlinkValues({ reason, confirm: true }), { etag: captured.etag, operationId: randomUUID() });
      const value = envelope(response.data, captured); if (response.status !== 200) fail(); rule(value.rule, captured.tenantId);
      same({ ...captured.rule, status: 'unlinked', revision: '2' }, value.rule); return sync(ruleId, reason, captured);
    },
  };
}
