import { api } from '@/lib/api';
import { BlueprintPreviewRequest, blueprintPreview, blueprintPreviewError } from '@/lib/blueprintPreview';

jest.mock('@/lib/api', () => ({ api: { post: jest.fn() } }));
const mock = api as jest.Mocked<typeof api>;
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const request = (): BlueprintPreviewRequest => ({ platform: 'macos', blueprints: [{ id: id(1), version: 3 }, { id: id(2), version: 4 }] });
const source = (blueprint: number, configuration: number) => ({ blueprintId: id(blueprint), configurationId: id(configuration) });
const fixture = () => ({
  schemaVersion: 1, scope: 'selected-blueprint-versions', comparison: 'whole-config-type', platform: 'macos', previewOnly: true, enforcementConfirmed: false, licenseReservations: 0,
  blueprints: [{ id: id(1), name: 'Blueprint Alpha', platform: 'all', version: 3 }, { id: id(2), name: 'Blueprint Beta', platform: 'macos', version: 4 }],
  configurationCount: 4, hasConflicts: true,
  effectiveConfigurations: [{ configType: 'wifi', payloadJson: '{"ssid": "Büro", "enabled": true}', sources: [source(1, 101), source(2, 102)] }],
  conflicts: [{ configType: 'screen_lock', variants: [{ payloadJson: '{"timeout": 300}', sources: [source(1, 103)] }, { payloadJson: '{"timeout": 600}', sources: [source(2, 104)] }] }],
});
const empty = () => ({ ...fixture(), configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] });
const respond = (data: unknown, status = 200) => mock.post.mockResolvedValue({ status, data });
beforeEach(() => jest.resetAllMocks());

test('sends only explicit IDs, versions and platform and accepts source-bound whole-type comparison', async () => {
  const data = fixture(); const controller = new AbortController(); respond(data);
  expect(await blueprintPreview.compare(request(), controller.signal)).toBe(data);
  expect(mock.post).toHaveBeenCalledWith('/api/blueprints/preview', request(), { signal: controller.signal });
  expect(mock.post).toHaveBeenCalledTimes(1);
});
test('accepts an empty actual configuration set and reordered blueprint metadata', async () => {
  const data = empty(); data.blueprints.reverse(); respond(data);
  expect((await blueprintPreview.compare(request())).configurationCount).toBe(0);
});
test('captures request values without retaining mutable caller objects', async () => {
  const input = request(); respond(fixture()); const pending = blueprintPreview.compare(input);
  input.blueprints[0].version = 99; input.platform = 'linux';
  await expect(pending).resolves.toMatchObject({ platform: 'macos' });
  expect(mock.post).toHaveBeenCalledWith('/api/blueprints/preview', request(), { signal: undefined });
});
test.each<[string, unknown]>([
  ['null', null], ['array', []], ['all platform', { ...request(), platform: 'all' }], ['missing platform', { blueprints: request().blueprints }],
  ['extra field', { ...request(), preview: true }], ['no selected versions', { ...request(), blueprints: [] }],
  ['26 selected versions', { ...request(), blueprints: Array.from({ length: 26 }, (_, index) => ({ id: id(index + 1), version: 1 })) }],
  ['duplicate ID', { ...request(), blueprints: [{ id: id(1), version: 1 }, { id: id(1), version: 2 }] }],
  ['uppercase UUID', { ...request(), blueprints: [{ id: 'AAAAAAAA-0000-4000-8000-000000000001', version: 1 }] }],
  ['alias ID', { ...request(), blueprints: [{ id: 'blueprint-1', version: 1 }] }],
  ['numeric ID', { ...request(), blueprints: [{ id: 1, version: 1 }] }],
  ['extra selected field', { ...request(), blueprints: [{ id: id(1), version: 1, snapshot: true }] }],
  ...[0, -1, 1.5, 2147483648, Number.MAX_SAFE_INTEGER, NaN, Infinity, '3', null].map<[string, unknown]>(value => [`version ${value}`, { ...request(), blueprints: [{ id: id(1), version: value }] }]),
])('rejects invalid request %s before any network call', async (_label, input) => {
  await expect(blueprintPreview.compare(input as BlueprintPreviewRequest)).rejects.toThrow(); expect(mock.post).not.toHaveBeenCalled();
});
test('accepts the maximum PostgreSQL integer version and exactly 25 unique selections', async () => {
  const selected = Array.from({ length: 25 }, (_, index) => ({ id: id(index + 1), version: 2147483647 }));
  respond({ ...empty(), blueprints: selected.map(item => ({ ...item, name: item.id, platform: 'all' })) });
  expect((await blueprintPreview.compare({ platform: 'macos', blueprints: selected })).blueprints).toHaveLength(25);
});
test.each([201, 202, 204, 206])('rejects a non-final or non-contract status %s', async status => {
  respond(fixture(), status); await expect(blueprintPreview.compare(request())).rejects.toThrow(); expect(mock.post).toHaveBeenCalledTimes(1);
});
test.each([
  ['schema', { schemaVersion: 2 }], ['scope', { scope: 'all-assigned-targets' }], ['comparison', { comparison: 'field-priority' }], ['platform', { platform: 'windows' }],
  ['preview flag', { previewOnly: false }], ['enforcement claim', { enforcementConfirmed: true }], ['license claim', { licenseReservations: 1 }],
  ['extra field', { deployment: 'complete' }], ['negative count', { configurationCount: -1 }], ['fractional count', { configurationCount: 1.5 }],
  ['excessive count', { configurationCount: 1001 }], ['string count', { configurationCount: '4' }], ['incorrect total', { configurationCount: 3 }],
  ['missing conflict flag', { hasConflicts: undefined }], ['false conflict flag', { hasConflicts: false }], ['no blueprint metadata', { blueprints: [] }],
  ['missing configurations', { effectiveConfigurations: null }], ['missing conflicts', { conflicts: null }],
])('rejects mismatched or wider response %s', async (_label, changes) => {
  respond({ ...fixture(), ...changes }); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each([
  ['wrong ID', { id: id(9) }], ['duplicate ID', { id: id(2), version: 4 }], ['wrong version', { version: 2 }], ['string version', { version: '3' }],
  ['wrong concrete platform', { platform: 'windows' }], ['empty name', { name: '' }], ['non-text name', { name: 1 }], ['metadata extra', { historical: true }],
])('rejects incorrect blueprint metadata %s', async (_label, changes) => {
  const data = fixture(); Object.assign(data.blueprints[0], changes); respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each([
  ['unknown blueprint', { blueprintId: id(9) }], ['uppercase blueprint', { blueprintId: 'AAAAAAAA-0000-4000-8000-000000000001' }],
  ['invalid configuration ID', { configurationId: 'configuration-1' }], ['extra source field', { targetId: id(9) }],
])('rejects unbound or malformed configuration source %s', async (_label, changes) => {
  const data = fixture(); Object.assign(data.effectiveConfigurations[0].sources[0], changes); respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each([
  ['empty sources', { sources: [] }], ['missing sources', { sources: undefined }], ['legacy object payload', { payload: { enabled: true } }],
  ['non-string JSON', { payloadJson: {} }], ['missing type', { configType: undefined }], ['empty type', { configType: '' }], ['oversized type', { configType: 'x'.repeat(101) }],
])('rejects malformed effective configuration %s', async (_label, changes) => {
  const data = fixture(); Object.assign(data.effectiveConfigurations[0], changes); respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each(['null', '[]', '42', '"text"', '{', '{"value": undefined}', '{"value": NaN}', '{"value": Infinity}'])('rejects non-object or invalid JSON text %s', async payloadJson => {
  const data = fixture(); data.effectiveConfigurations[0].payloadJson = payloadJson; respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each(['within a variant', 'across effective and conflict', 'across conflict variants'])('rejects globally repeated configuration IDs %s', async location => {
  const data = fixture();
  if (location === 'within a variant') data.effectiveConfigurations[0].sources[1].configurationId = id(101);
  if (location === 'across effective and conflict') data.conflicts[0].variants[0].sources[0].configurationId = id(101);
  if (location === 'across conflict variants') data.conflicts[0].variants[1].sources[0].configurationId = id(103);
  respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each(['effective', 'conflict', 'cross-list'])('rejects repeated configuration types in %s', async location => {
  const data = fixture();
  if (location === 'effective') data.effectiveConfigurations.push({ ...data.effectiveConfigurations[0], sources: [source(1, 105)] });
  if (location === 'conflict') data.conflicts.push({ ...data.conflicts[0], variants: [{ payloadJson: '{}', sources: [source(1, 105)] }, { payloadJson: '{"value":1}', sources: [source(2, 106)] }] });
  if (location === 'cross-list') data.conflicts[0].configType = 'wifi';
  respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test.each(['one variant', 'identical raw variants', 'extra variant field', 'extra conflict field'])('rejects an invalid conflict: %s', async defect => {
  const data = fixture();
  if (defect === 'one variant') data.conflicts[0].variants.pop();
  if (defect === 'identical raw variants') data.conflicts[0].variants[1].payloadJson = data.conflicts[0].variants[0].payloadJson;
  if (defect === 'extra variant field') Object.assign(data.conflicts[0].variants[0], { priority: 1 });
  if (defect === 'extra conflict field') Object.assign(data.conflicts[0], { winner: id(1) });
  respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test('retains distinct PostgreSQL numbers that JavaScript rounds to the same value', async () => {
  const data = fixture(); const first = '{"number": 9007199254740992}'; const second = '{"number": 9007199254740993}';
  expect(JSON.parse(first)).toEqual(JSON.parse(second)); data.conflicts[0].variants[0].payloadJson = first; data.conflicts[0].variants[1].payloadJson = second; respond(data);
  const result = await blueprintPreview.compare(request()); expect(result.conflicts[0].variants.map(item => item.payloadJson)).toEqual([first, second]);
});
test('accepts SQL-deduplicated 1 versus 1.0 source metadata without inventing a second variant', async () => {
  const data = { ...empty(), configurationCount: 2, effectiveConfigurations: [{ configType: 'opaque', payloadJson: '{"number": 1.0}', sources: [source(1, 101), source(2, 102)] }] };
  respond(data); const result = await blueprintPreview.compare(request()); expect(result.hasConflicts).toBe(false);
  expect(result.effectiveConfigurations[0].payloadJson).toBe('{"number": 1.0}'); expect(result.effectiveConfigurations[0].sources).toHaveLength(2);
});
test('validates only the JSON object container, preserving huge numbers, array order and whitespace as opaque text', async () => {
  const payloadJson = ' { "large": 1e10000, "array": [2,1], "nested": {"second":true,"first":false} } ';
  respond({ ...empty(), configurationCount: 1, effectiveConfigurations: [{ configType: 'vendor/type:opaque', payloadJson, sources: [source(1, 101)] }] });
  expect((await blueprintPreview.compare(request())).effectiveConfigurations[0].payloadJson).toBe(payloadJson);
});
test('accepts 1000 globally distinct source IDs and rejects 1001 even with a false count', async () => {
  const sources = Array.from({ length: 1000 }, (_, index) => source(index % 2 + 1, index + 101));
  const data = { ...empty(), configurationCount: 1000, effectiveConfigurations: [{ configType: 'opaque', payloadJson: '{}', sources }] };
  respond(data); expect((await blueprintPreview.compare(request())).configurationCount).toBe(1000);
  sources.push(source(1, 2000)); respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test('bounds wire representative bytes, not the unknowable sum of original deduplicated source texts', async () => {
  const payloadJson = '{"value":"' + 'x'.repeat(1048576 - 12) + '"}'; expect(Buffer.byteLength(payloadJson)).toBe(1048576);
  const data = { ...empty(), configurationCount: 2, effectiveConfigurations: [{ configType: 'opaque', payloadJson, sources: [source(1, 101), source(2, 102)] }] };
  respond(data); expect((await blueprintPreview.compare(request())).effectiveConfigurations[0].sources).toHaveLength(2);
  data.effectiveConfigurations[0].payloadJson = payloadJson + ' '; respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test('counts UTF-8 bytes across effective and conflicting wire payloads', async () => {
  const data = fixture(); data.effectiveConfigurations[0].payloadJson = '{"value":"' + 'é'.repeat(524280) + '"}';
  expect(data.effectiveConfigurations[0].payloadJson.length).toBeLessThan(1048576); respond(data); await expect(blueprintPreview.compare(request())).rejects.toThrow();
});
test('does not retry failed HTTP reads and exposes only conservative, static error messages', async () => {
  const failure = { response: { status: 412, data: { message: 'secret provider token' } } }; mock.post.mockRejectedValue(failure);
  await expect(blueprintPreview.compare(request())).rejects.toBe(failure); expect(mock.post).toHaveBeenCalledTimes(1);
  expect(blueprintPreviewError(failure)).toContain('nicht mehr aktuell'); expect(blueprintPreviewError(failure)).not.toContain('secret');
});
test.each([[404, 'nicht mehr verfügbar'], [409, 'Plattform'], [401, 'Sitzung'], [403, 'Les'], [400, 'nicht bestätigt'], [503, 'nicht bestätigt']])('maps error status %s without treating it as a successful comparison', (status, text) => {
  expect(blueprintPreviewError({ response: { status } })).toContain(text); expect(blueprintPreviewError(null)).toContain('nicht bestätigt');
});
