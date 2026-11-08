'use strict';

const { randomUUID } = require('node:crypto');
const { ownConfigurations, CompanyBlueprintAssignments } = require('../licenses/CompanyBlueprintAssignments');
test('manual license proof accepts an active license window without extending blueprint assignment authority', async () => {
  const { validApplicationSource } = require('../licenses/CompanyBlueprintAssignments');
  const { COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS } = require('../../../../../packages/company-blueprint-assignment-contract');
  const now = Math.floor(Date.now() / 1000); const userId = randomUUID(); const targetId = randomUUID(); const tenant = { id: randomUUID(), version: '1', generation: '1' };
  const context = { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) };
  const user = { actor_type: 'user', token_use: 'access', iss: 'https://actual-owner.test', sub: 'actual-owner', jti: randomUUID(), iat: now, exp: now + 300, auth_time: now - 3600,
    identity_authorization: context, amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', authTime: now - 3600, methods: ['pwd', 'otp'] },
    company_license_activation: { schemaVersion: 1, scope: 'company-licenses', id: randomUUID(), tenant, expiresAt: now + 32400 } };
  const source = { schemaVersion: 1, issuer: user.iss, subject: user.sub, tokenId: user.jti, expiresAt: user.exp, context, tenant, actorUserId: userId,
    permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], validUntil: user.exp, target: { id: targetId, revision: '1', eligibilityRevision: '1', enabled: true, deleted: false } };
  expect(validApplicationSource(source, user, targetId)).toBe(true);
  for (const change of [{ company_license_activation: undefined }, { amr: ['pwd'] }, { exp: now + 3600 }, { token_use: 'id' }, { company_license_activation: { ...user.company_license_activation, tenant: { ...tenant, generation: '2' } } }]) {
    expect(validApplicationSource({ ...source, expiresAt: change.exp || source.expiresAt }, { ...user, ...change }, targetId)).toBe(false);
  }
  expect(validApplicationSource({ ...source, target: { ...source.target, eligibilityRevision: '0' } }, user, targetId)).toBe(false);
  const blueprintSource = { ...source, companyBlueprintAssignmentsProtocol: 1, permissions: [...COMPANY_BLUEPRINT_ASSIGNMENT_PERMISSIONS] };
  const database = {}; const isolated = new CompanyBlueprintAssignments(database, { allocator: { database }, authority: { read: async () => blueprintSource } });
  await expect(isolated.source(user, 'Bearer original', targetId)).rejects.toMatchObject({ status: 503 });
});
test('own configuration identities are scoped by blueprint rather than a global configuration UUID', () => {
  const id = randomUUID(); const rows = [randomUUID(), randomUUID()].map(blueprint_id => ({ id, blueprint_id, config_type: 'screen_lock', payload_json: '{"minutes":5,"requirePassword":true}', payload_rank: '1' }));
  expect(ownConfigurations(rows)).toMatchObject({ hasConflicts: false, effectiveConfigurations: [{ sources: [{ blueprintId: rows[0].blueprint_id, configurationId: id }, { blueprintId: rows[1].blueprint_id, configurationId: id }] }] });
});
test('same composite identity cannot be repeated inside an own blueprint snapshot', () => {
  const row = { id: randomUUID(), blueprint_id: randomUUID(), config_type: 'filevault', payload_json: '{"enabled":true}', payload_rank: '1' }; expect(() => ownConfigurations([row, row])).toThrow('Duplicate');
});
test('conflicting whole payloads have no effective winner', () => {
  const rows = [1, 2].map(rank => ({ id: randomUUID(), blueprint_id: randomUUID(), config_type: 'filevault', payload_json: JSON.stringify({ enabled: rank === 1 }), payload_rank: String(rank) })); expect(ownConfigurations(rows)).toMatchObject({ hasConflicts: true, effectiveConfigurations: [], conflicts: [{ configType: 'filevault', variants: expect.any(Array) }] });
});
test('an allocator from a different database cannot execute assignment commands', () => { expect(() => new CompanyBlueprintAssignments({}, { allocator: { database: {} } })).toThrow('Original allocator'); });
test('the exact own aggregate limit fails without silently truncating', () => { expect(() => ownConfigurations(Array(1001).fill({}))).toThrow('limit'); });
