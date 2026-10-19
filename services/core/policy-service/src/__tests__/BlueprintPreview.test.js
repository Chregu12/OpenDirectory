'use strict';

const { randomUUID } = require('node:crypto');
const { previewValues, resolveConfigurations, readConfigurations } = require('../BlueprintPreview');
const blueprintId = randomUUID();
const selection = () => ({ platform: 'macos', blueprints: [{ id: blueprintId, version: 3 }] });
const configuration = (changes = {}) => ({ id: randomUUID(), blueprint_id: blueprintId, config_type: 'screen_lock', payload_json: '{"minutes": 5}', payload_rank: '1', ...changes });
function fails(operation, status, code) { expect(operation).toThrow(expect.objectContaining({ status, code })); }

test('captures exact bounded selected versions independently of mutable request objects', () => {
  const input = selection(); const captured = previewValues(input); input.blueprints[0].version = 4;
  expect(captured).toEqual({ platform: 'macos', blueprints: [{ id: blueprintId, version: 3 }] });
});
test.each([
  null, [], {}, { ...selection(), platform: 'all' }, { ...selection(), platform: 'ios' },
  { ...selection(), blueprints: [] }, { ...selection(), tenantId: randomUUID() },
  { ...selection(), blueprints: [{ id: blueprintId, version: '3' }] },
  { ...selection(), blueprints: [{ id: blueprintId, version: 0 }] },
  { ...selection(), blueprints: [{ id: blueprintId, version: 1.5 }] },
  { ...selection(), blueprints: [{ id: blueprintId, version: 2147483648 }] },
  { ...selection(), blueprints: [{ id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', version: 1 }] },
  { ...selection(), blueprints: [{ id: '../outside', version: 1 }] },
  { ...selection(), blueprints: [{ id: blueprintId, version: 1, priority: 100 }] },
  { ...selection(), blueprints: [{ id: blueprintId, version: 1 }, { id: blueprintId, version: 2 }] },
  { ...selection(), blueprints: Array.from({ length: 26 }, () => ({ id: randomUUID(), version: 1 })) },
])('rejects non-exact or unsafe preview input %#', input => {
  fails(() => previewValues(input), 400, 'exact_blueprint_preview_required');
});
test('accepts the exact upper boundary without inventing default targets or priorities', () => {
  expect(previewValues({ platform: 'linux', blueprints: Array.from({ length: 25 }, () => ({ id: randomUUID(), version: 2147483647 })) }).blueprints).toHaveLength(25);
});
test('empty persisted configuration is an explicit empty preview, not invented defaults', () => {
  expect(resolveConfigurations([])).toEqual({ configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] });
});
test('database-equal numeric spellings share one result and retain both original sources', () => {
  const first = configuration({ payload_json: '{"minutes": 1}' });
  const second = configuration({ payload_json: '{"minutes": 1.0}' });
  const result = resolveConfigurations([first, second]);
  expect(result.configurationCount).toBe(2); expect(result.hasConflicts).toBe(false);
  expect(result.effectiveConfigurations).toEqual([{ configType: 'screen_lock', payloadJson: first.payload_json,
    sources: [first, second].map(row => ({ blueprintId: row.blueprint_id, configurationId: row.id })).sort((left, right) => left.configurationId.localeCompare(right.configurationId)) }]);
});
test('distinct SQL ranks preserve exact large-number conflicts despite JavaScript rounding', () => {
  const first = configuration({ payload_json: '{"value": 9007199254740992}' });
  const second = configuration({ payload_json: '{"value": 9007199254740993}', payload_rank: '2' });
  expect(JSON.parse(first.payload_json)).toEqual(JSON.parse(second.payload_json));
  const result = resolveConfigurations([second, first]);
  expect(result.hasConflicts).toBe(true); expect(result.effectiveConfigurations).toEqual([]);
  expect(result.conflicts[0].variants.map(item => item.payloadJson)).toEqual([first.payload_json, second.payload_json]);
});
test('different types remain separate and a conflicting type has no automatic winner', () => {
  const result = resolveConfigurations([configuration({ config_type: 'wifi' }), configuration(), configuration({ payload_rank: '2', payload_json: '{"minutes": 10}' })]);
  expect(result.configurationCount).toBe(3); expect(result.effectiveConfigurations.map(item => item.configType)).toEqual(['wifi']);
  expect(result.conflicts.map(item => item.configType)).toEqual(['screen_lock']);
});
test.each([
  { id: 'not-an-id' }, { blueprint_id: null }, { config_type: '' }, { config_type: 'bad\nkind' }, { config_type: 'x'.repeat(101) },
  { payload_rank: 1 }, { payload_rank: '0' }, { payload_rank: '1001' }, { payload_rank: '1.0' },
  { payload_json: {} }, { payload_json: 'null' }, { payload_json: '[]' }, { payload_json: 'broken' },
  { payload_json: '{"constructor": {}}' }, { payload_json: '{"nested": {"__proto__": true}}' }, { payload_json: '{"value":1e999}' },
])('fails closed on malformed persisted preview evidence %#', changes => {
  fails(() => resolveConfigurations([configuration(changes)]), 503, 'blueprint_preview_source_unavailable');
});
test('duplicate original configuration IDs cannot inflate provenance or available configuration counts', () => {
  const row = configuration(); fails(() => resolveConfigurations([row, row]), 503, 'blueprint_preview_source_unavailable');
});
test('deeply nested persisted payloads are rejected without a partial success', () => {
  let payload = {}; for (let depth = 0; depth < 22; depth++) payload = { nested: payload };
  fails(() => resolveConfigurations([configuration({ payload_json: JSON.stringify(payload) })]), 503, 'blueprint_preview_source_unavailable');
});
test('1001 original configurations are rejected instead of silently truncated', () => {
  fails(() => resolveConfigurations(Array.from({ length: 1001 }, () => configuration())), 409, 'blueprint_preview_limit_reached');
});
test('aggregate UTF-8 payload size is bounded before parsing and no truncated preview is returned', () => {
  fails(() => resolveConfigurations([configuration({ payload_json: JSON.stringify({ value: 'ä'.repeat(524288) }) })]), 409, 'blueprint_preview_limit_reached');
});
test('the actual database query derives ranks using JSONB ordering rather than lossy application parsing', async () => {
  const rows = [configuration()]; const client = { query: jest.fn().mockResolvedValue({ rows }) };
  await expect(readConfigurations(client, [blueprintId])).resolves.toBe(rows);
  expect(client.query).toHaveBeenCalledWith(expect.stringContaining('dense_rank() OVER (PARTITION BY config_type ORDER BY payload)'), [[blueprintId]]);
  expect(client.query.mock.calls[0][0]).toContain('payload::text AS payload_json');
  expect(client.query.mock.calls[0][0]).toContain('LIMIT 1001');
});
