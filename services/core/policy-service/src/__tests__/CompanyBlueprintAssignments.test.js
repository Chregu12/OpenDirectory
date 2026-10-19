'use strict';

const { randomUUID } = require('node:crypto');
const { ownConfigurations, CompanyBlueprintAssignments } = require('../licenses/CompanyBlueprintAssignments');
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
