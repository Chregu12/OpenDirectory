import { api } from '@/lib/api';
import {
  CompanyBlueprintsClient, CompanyBlueprintDraft, CompanyBlueprintDetail, CompanyBlueprintReceipt,
  companyBlueprintPayload, companyBlueprintEtag, companyBlueprintsError, companyBlueprintsUnsafe,
  normalizeCompanyBlueprintDraft, normalizeCompanyBlueprintReason,
} from '@/lib/companyBlueprints';

jest.mock('@/lib/api', () => ({ api: { get: jest.fn(), post: jest.fn(), put: jest.fn() } }));
const mock = api as jest.Mocked<typeof api>;
const base = '/api/company-blueprints';
const id = (number: number) => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const now = '2026-10-19T12:00:00.000Z';
const capabilities = () => ({ schemaVersion: 1, companyBlueprintProtocol: 1, actorUserId: id(90), tenantId: id(91),
  permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'], configurationMode: 'local-only', maxConfigurations: 25, maxApplications: 25 });
const draft = (): CompanyBlueprintDraft => ({ name: 'Sicherer Arbeitsplatz', description: '', platform: 'macos', configurations: [
  { id: id(10), type: 'screen_lock', name: 'Bildschirmsperre', payloadJson: '{"minutes":5,"requirePassword":true}' },
], appPoolIds: [id(20)] });
const detail = (): CompanyBlueprintDetail => ({ id: id(1), tenantId: id(91), revision: '9007199254740993', publishedVersion: 1, draftChanged: true,
  draft: draft(), createdAt: now, updatedAt: now, preview: { configurationCount: 1, hasConflicts: false,
    effectiveConfigurations: [{ configType: 'screen_lock', payloadJson: '{"requirePassword":true, "minutes":5}', sources: [{ blueprintId: id(1), configurationId: id(10) }] }], conflicts: [] } });
const summary = () => ({ id: id(1), tenantId: id(91), name: 'Sicherer Arbeitsplatz', platform: 'macos', revision: '9007199254740993', publishedVersion: 1,
  draftChanged: true, configurationCount: 1, appCount: 1, createdAt: now, updatedAt: now });
const version = () => ({ version: 1, sourceRevision: '9007199254740992', publishedRevision: '9007199254740993', actorUserId: id(90), operationId: id(92), createdAt: now });
const event = () => ({ id: id(93), tenantId: id(91), type: 'blueprint.published', version: 1, blueprintId: id(1), actorUserId: id(90), correlationId: id(94),
  createdAt: now, beforeRevision: '9007199254740992', afterRevision: '9007199254740993', releasedVersion: 1, restoredFrom: null, reason: 'Geprüfte lokale Freigabe', deliveryStatus: 'pending' });
const envelope = (fields = {}) => ({ schemaVersion: 1, actorUserId: id(90), tenantId: id(91), ...fields });
const page = (fields = {}) => envelope({ total: 1, page: 1, limit: 25, ...fields });
const ok = (data: unknown, headers = {}) => ({ status: 200, data, headers });
let accessData: ReturnType<typeof capabilities>;
let detailData: CompanyBlueprintDetail;
let listData: Record<string, unknown>;
let versionsData: Record<string, unknown>;
let versionData: Record<string, unknown>;
let historyData: Record<string, unknown>;
let sequence = 100;
const clients: CompanyBlueprintsClient[] = [];
async function client() { const current = new CompanyBlueprintsClient(); clients.push(current); await current.access(); return current; }
function deferred<Value>() {
  let resolve: (value: Value) => void;
  const promise = new Promise<Value>(accept => { resolve = accept; });
  return { promise, resolve: (value: Value) => resolve(value) };
}
beforeEach(() => {
  jest.resetAllMocks(); sequence = 100;
  Object.defineProperty(crypto, 'randomUUID', { configurable: true, value: jest.fn(() => id(sequence++)) });
  accessData = capabilities(); detailData = detail(); listData = page({ blueprints: [summary()] });
  versionsData = page({ blueprintId: id(1), versions: [version()] });
  versionData = envelope({ blueprintId: id(1), version: { ...version(), draft: draft(), apps: [{ id: id(20), name: 'Büro-App', vendor: 'Hersteller', revision: '999' }] } });
  historyData = page({ blueprintId: id(1), events: [event()] });
  mock.get.mockImplementation(async url => {
    if (url === base + '/capabilities') return ok(accessData);
    if (url === base) return ok(listData);
    if (url === base + '/' + id(1)) return ok(envelope({ blueprint: detailData }), { etag: companyBlueprintEtag(detailData) });
    if (url.endsWith('/versions/1')) return ok(versionData);
    if (url.endsWith('/versions')) return ok(versionsData);
    if (url.endsWith('/history')) return ok(historyData);
    throw new Error('Unexpected read ' + url);
  });
});
afterEach(() => { clients.splice(0).forEach(current => current.dispose()); });

test('reads the exact root list with independent current authority and precision-safe revisions', async () => {
  const current = await client(); const result = await current.list(1, '  Arbeitsplatz  ');
  expect(result.rows[0].revision).toBe('9007199254740993'); expect(Object.isFrozen(result.rows[0])).toBe(true);
  expect(mock.get).toHaveBeenCalledWith(base, expect.objectContaining({ params: { page: 1, limit: 25, search: 'Arbeitsplatz' } }));
  expect(mock.get.mock.calls.filter(([url]) => url.endsWith('/capabilities'))).toHaveLength(2);
  expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled();
});
test.each([
  ['protocol', { companyBlueprintProtocol: 2 }], ['extra privilege', { permissions: [...capabilities().permissions, 'policies.deploy'] }],
  ['missing permission', { permissions: ['company.blueprints.read'] }], ['wrong order', { permissions: [...capabilities().permissions].reverse() }],
  ['wrong mode', { configurationMode: 'mdm' }], ['extra source', { isOwner: true }], ['wrong schema', { schemaVersion: 2 }],
  ['wrong config limit', { maxConfigurations: 26 }], ['wrong app limit', { maxApplications: 26 }], ['noncanonical actor', { actorUserId: id(90).toUpperCase().replace('10000000', 'ABCDEF00') }],
])('rejects %s in the exact eight-field capability', async (_label, changes) => {
  accessData = { ...accessData, ...changes } as typeof accessData;
  const current = new CompanyBlueprintsClient(); clients.push(current);
  await expect(current.access()).rejects.toThrow(); expect(mock.post).not.toHaveBeenCalled();
});
test.each([0, -1, 1.5, 1000001, Number.NaN, Infinity])('rejects invalid page %s before sending a list request', async invalid => {
  const current = await client(); await expect(current.list(invalid)).rejects.toThrow(); expect(mock.get).toHaveBeenCalledTimes(1);
});
test.each(['x'.repeat(101), 'search\nvalue', 'search\u007fvalue'])('rejects unsafe bounded search %j', async search => {
  const current = await client(); await expect(current.list(1, search)).rejects.toThrow(); expect(mock.get).toHaveBeenCalledTimes(1);
});
test.each([
  ['extra envelope field', { unexpected: true }], ['wrong page', { page: 2 }], ['wrong limit', { limit: 10 }], ['inconsistent total', { total: 2 }],
  ['negative total', { total: -1 }], ['duplicate rows', { total: 2, blueprints: [summary(), summary()] }],
  ['mixed tenant', { blueprints: [{ ...summary(), tenantId: id(92) }] }], ['numeric revision', { blueprints: [{ ...summary(), revision: 9007199254740992 }] }],
  ['overflow revision', { blueprints: [{ ...summary(), revision: '9223372036854775808' }] }], ['revision leading zero', { blueprints: [{ ...summary(), revision: '01' }] }],
  ['extra row privilege', { blueprints: [{ ...summary(), policies: ['all'] }] }], ['invalid timestamp', { blueprints: [{ ...summary(), createdAt: 'yesterday' }] }],
])('rejects %s rather than presenting a trusted catalogue', async (_label, changes) => {
  const current = await client(); listData = { ...listData, ...changes }; await expect(current.list()).rejects.toThrow();
});
test.each(['actorUserId', 'tenantId'])('clears captured intents if the returned %s changes', async field => {
  const current = await client(); const intent = current.capture('created', null, 'Ein sicherer neuer Entwurf', draft());
  listData[field] = id(99); await expect(current.list()).rejects.toThrow(); expect(current.canRetry(intent)).toBe(false);
});
test('observes exact detail ETag and safe whole-type comparison without deployments', async () => {
  const current = await client(); const result = await current.get(id(1));
  expect(result.preview.effectiveConfigurations[0].payloadJson).toBe('{"requirePassword":true, "minutes":5}');
  expect(companyBlueprintEtag(result)).toBe('"company-blueprint-' + id(1) + '-9007199254740993"');
  expect(Object.isFrozen(result.draft.configurations[0])).toBe(true); expect(mock.post).not.toHaveBeenCalled();
});
test.each(['W/"company-blueprint-x-1"', '"company-blueprint-' + id(1) + '-9007199254740992"', undefined, '"company-blueprint-' + id(1) + '-09007199254740993"'])('rejects nonexact ETag %s', async etag => {
  const current = await client(); const original = mock.get.getMockImplementation();
  mock.get.mockImplementation((url, options) => url === base + '/' + id(1) ? Promise.resolve(ok(envelope({ blueprint: detailData }), { etag })) : original(url, options));
  await expect(current.get(id(1))).rejects.toThrow();
});
test.each([
  ['wrong count', (value: CompanyBlueprintDetail) => { value.preview.configurationCount = 0; }],
  ['false conflict flag', (value: CompanyBlueprintDetail) => { value.preview.hasConflicts = true; }],
  ['missing provenance', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations[0].sources = []; }],
  ['foreign blueprint', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations[0].sources[0].blueprintId = id(2); }],
  ['unknown configuration', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations[0].sources[0].configurationId = id(11); }],
  ['wrong actual payload', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations[0].payloadJson = '{"minutes":10,"requirePassword":true}'; }],
  ['duplicate provenance', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations[0].sources.push(value.preview.effectiveConfigurations[0].sources[0]); }],
  ['missing type', (value: CompanyBlueprintDetail) => { value.preview.effectiveConfigurations = []; }],
  ['extra preview flag', (value: CompanyBlueprintDetail) => { Object.assign(value.preview, { deployed: true }); }],
])('rejects preview %s', async (_label, change) => {
  const current = await client(); change(detailData); await expect(current.get(id(1))).rejects.toThrow();
});
test('accepts real conflicts but blocks capture of a local publication', async () => {
  detailData.draft.configurations.push({ ...detailData.draft.configurations[0], id: id(11), payloadJson: '{"minutes":10,"requirePassword":true}' });
  detailData.preview = { configurationCount: 2, hasConflicts: true, effectiveConfigurations: [], conflicts: [{ configType: 'screen_lock', variants: [
    { payloadJson: draft().configurations[0].payloadJson, sources: [{ blueprintId: id(1), configurationId: id(10) }] },
    { payloadJson: detailData.draft.configurations[1].payloadJson, sources: [{ blueprintId: id(1), configurationId: id(11) }] },
  ] }] };
  const current = await client(); const result = await current.get(id(1));
  expect(result.preview.hasConflicts).toBe(true); expect(() => current.capture('published', result, 'Neue lokale Freigabe')).toThrow();
});
test.each([
  ['screen_lock', '{"minutes":1,"requirePassword":false}'], ['screen_lock', '{"requirePassword":true,"minutes":1440}'],
  ['filevault', '{"enabled":true}'], ['filevault', '{"enabled":false}'],
  ['software_update', '{"automatic":true,"deferralDays":0}'], ['software_update', '{"deferralDays":365,"automatic":false}'],
])('accepts bounded typed %s payload %s', (type, payload) => { expect(companyBlueprintPayload(type as 'screen_lock', payload)).toEqual(JSON.parse(payload)); });
test.each([
  ['screen_lock', '{"minutes":0,"requirePassword":true}'], ['screen_lock', '{"minutes":1441,"requirePassword":true}'],
  ['screen_lock', '{"minutes":1.0,"requirePassword":true}'], ['screen_lock', '{"minutes":1e1,"requirePassword":true}'],
  ['screen_lock', '{"minutes":5,"minutes":10,"requirePassword":true}'], ['screen_lock', '{"minutes":5,"requirePassword":"true"}'],
  ['screen_lock', '{"minutes":5,"requirePassword":true,"secret":"token"}'], ['filevault', '{"enabled":1}'],
  ['filevault', '{"enabled":true,"escrowKey":"secret"}'], ['software_update', '{"automatic":true,"deferralDays":366}'],
  ['software_update', '{"automatic":true,"deferralDays":-1}'], ['software_update', '{"automatic":true,"deferralDays":0.1}'],
  ['wifi', '{"password":"secret"}'], ['filevault', 'null'], ['filevault', '[true]'], ['filevault', 'not json'], ['filevault', '{"enabled":true,"enabled":false}'],
])('rejects unsupported or unsafe %s payload %s', (type, payload) => { expect(() => companyBlueprintPayload(type as 'screen_lock', payload)).toThrow(); });
test('normalizes only user-entered text and preserves stable configuration IDs and exact payloads', () => {
  const input = draft(); input.name = '  Arbeitsplatz  '; input.description = '  Sicher  '; input.configurations[0].name = '  Sperre  ';
  const result = normalizeCompanyBlueprintDraft(input); expect(result.name).toBe('Arbeitsplatz'); expect(result.description).toBe('Sicher');
  expect(result.configurations[0]).toEqual({ ...draft().configurations[0], name: 'Sperre' });
  expect(normalizeCompanyBlueprintReason('  Geprüfte neue Konfiguration  ')).toBe('Geprüfte neue Konfiguration');
});
test.each([
  ['duplicate config IDs', (value: CompanyBlueprintDraft) => { value.configurations.push(value.configurations[0]); }],
  ['duplicate app refs', (value: CompanyBlueprintDraft) => { value.appPoolIds.push(value.appPoolIds[0]); }],
  ['26 apps', (value: CompanyBlueprintDraft) => { value.appPoolIds = Array.from({ length: 26 }, (_, index) => id(index + 200)); }],
  ['26 configs', (value: CompanyBlueprintDraft) => { value.configurations = Array.from({ length: 26 }, (_, index) => ({ ...value.configurations[0], id: id(index + 200) })); }],
  ['unknown fields', (value: CompanyBlueprintDraft) => { Object.assign(value, { secret: 'no' }); }],
  ['control characters', (value: CompanyBlueprintDraft) => { value.description = 'first\nsecond'; }],
  ['empty name', (value: CompanyBlueprintDraft) => { value.name = ' '; }],
])('rejects draft %s before any request', (_label, change) => { const value = draft(); change(value); expect(() => normalizeCompanyBlueprintDraft(value)).toThrow(); });
test.each(['short', 'x'.repeat(501), 'validreason\nsecret', 'validreason\u0085secret'])('rejects invalid audit reason %j', reason => { expect(() => normalizeCompanyBlueprintReason(reason)).toThrow(); });
test('preserves historical app snapshots without comparing current pool revisions or claiming stock', async () => {
  const current = await client(); expect((await current.versions(id(1))).rows[0]).toEqual(version());
  const result = await current.version(id(1), 1); expect(result.apps[0].revision).toBe('999');
  expect(mock.get.mock.calls.some(([url]) => url.includes('/licenses'))).toBe(false);
  expect((await current.history(id(1))).rows[0]).toEqual(event());
});
test.each([
  ['wrong requested version', () => { versionData.version = { ...version(), version: 2, draft: draft(), apps: [{ id: id(20), name: 'App', vendor: 'Vendor', revision: '1' }] }; }],
  ['missing app snapshot', () => { (versionData.version as { apps: unknown[] }).apps = []; }],
  ['foreign app snapshot', () => { (versionData.version as { apps: unknown[] }).apps = [{ id: id(21), name: 'App', vendor: 'Vendor', revision: '1' }]; }],
  ['wrong published revision', () => { (versionData.version as { publishedRevision: string }).publishedRevision = '9007199254740994'; }],
  ['extra secret', () => { Object.assign(versionData.version, { secret: 'hidden' }); }],
])('rejects historical %s', async (_label, change) => { const current = await client(); change(); await expect(current.version(id(1), 1)).rejects.toThrow(); });
test.each([
  ['wrong event tenant', () => { historyData.events = [{ ...event(), tenantId: id(99) }]; }],
  ['wrong event blueprint', () => { historyData.events = [{ ...event(), blueprintId: id(2) }]; }],
  ['fake delivered event', () => { historyData.events = [{ ...event(), deliveryStatus: 'delivered' }]; }],
  ['bad event version', () => { historyData.events = [{ ...event(), version: 2 }]; }],
  ['missing release ordinal', () => { historyData.events = [{ ...event(), releasedVersion: null }]; }],
  ['duplicate versions', () => { versionsData.versions = [version(), version()]; versionsData.total = 2; }],
])('rejects %s', async (_label, change) => {
  const current = await client(); change(); await expect(versionsData.total === 2 ? current.versions(id(1)) : current.history(id(1))).rejects.toThrow();
});
function writeReply(action: CompanyBlueprintReceipt['action'], source: CompanyBlueprintDetail | null, outcome: 'applied' | 'already_applied' = 'applied') {
  return async (_url: string, body: { id?: string }, options: { headers: Record<string, string> }) => ({ status: action === 'created' && outcome === 'applied' ? 201 : 200,
    data: envelope({ operationId: options.headers['Idempotency-Key'], blueprintId: source?.id || body.id,
      revision: source ? String(BigInt(source.revision) + BigInt(1)) : '1', publishedVersion: action === 'published' ? (source.publishedVersion || 0) + 1 : source?.publishedVersion ?? null,
      action, outcome, deliveryStatus: 'pending' }), headers: {} });
}
test.each(['created', 'updated', 'published', 'restored'] as const)('captures immutable %s intent once and uses exact headers and endpoint', async action => {
  const current = await client(); const source = action === 'created' ? null : await current.get(id(1));
  const input = draft(); const intent = current.capture(action, source, '  Bewusste lokale Änderung  ', action === 'restored' ? 1 : input);
  input.name = 'Not the captured value'; expect(Object.isFrozen(intent.body)).toBe(true); expect(intent.body.reason).toBe('Bewusste lokale Änderung');
  if (action === 'created' || action === 'updated') expect(intent.body.draft.name).toBe('Sicherer Arbeitsplatz');
  mock.post.mockImplementation(writeReply(action, source)); mock.put.mockImplementation(writeReply(action, source));
  const beforeReads = mock.get.mock.calls.length; const result = await current.write(intent);
  expect(result.action).toBe(action); expect(current.canRetry(intent)).toBe(false);
  const call = (action === 'updated' ? mock.put : mock.post).mock.calls[0];
  expect(call[0]).toBe(action === 'created' ? base : base + '/' + id(1) + (action === 'updated' ? '' : action === 'published' ? '/publish' : '/restore'));
  expect(call[1]).toBe(intent.body); expect(call[2].headers).toEqual({ 'Idempotency-Key': intent.operationId, ...(source ? { 'If-Match': companyBlueprintEtag(source) } : {}) });
  expect(mock.get.mock.calls.slice(beforeReads).every(([url]) => url === base + '/capabilities')).toBe(true);
});
test('retains the exact original lost-ACK intent and accepts a historical effect-free recovery without refreshing the head', async () => {
  const current = await client(); const source = await current.get(id(1)); const intent = current.capture('updated', source, 'Originaler Änderungsversuch', draft());
  mock.put.mockRejectedValueOnce({ response: { status: 503 } }); await expect(current.write(intent)).rejects.toEqual({ response: { status: 503 } });
  expect(current.canRetry(intent)).toBe(true); expect(mock.put).toHaveBeenCalledTimes(1);
  detailData.revision = '9007199254741099'; mock.put.mockImplementation(writeReply('updated', source, 'already_applied'));
  const readsBeforeRetry = mock.get.mock.calls.length; const result = await current.write(intent);
  expect(result.revision).toBe('9007199254740994'); expect(result.outcome).toBe('already_applied');
  expect(mock.put.mock.calls[1][1]).toBe(mock.put.mock.calls[0][1]); expect(mock.put.mock.calls[1][2].headers).toEqual(mock.put.mock.calls[0][2].headers);
  expect(mock.get.mock.calls.slice(readsBeforeRetry).map(([url]) => url)).toEqual([base + '/capabilities', base + '/capabilities']);
});
test.each([400, 404, 409, 412, 401, 403, 428])('does not retain unsafe or definite rejected intent after status %s', async status => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  mock.post.mockRejectedValue({ response: { status } }); await expect(current.write(intent)).rejects.toEqual({ response: { status } });
  expect(current.canRetry(intent)).toBe(false); expect(mock.post).toHaveBeenCalledTimes(1);
});
test.each([undefined, 500, 502, 503, 504])('keeps a possibly committed intent after status %s without automatic retry', async status => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  mock.post.mockRejectedValue(status ? { response: { status } } : new Error('network lost'));
  await expect(current.write(intent)).rejects.toBeTruthy(); expect(current.canRetry(intent)).toBe(true); expect(mock.post).toHaveBeenCalledTimes(1);
});
test.each(['actorUserId', 'tenantId'])('preflight source change in %s blocks writes and discards original intents', async field => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  accessData[field] = id(99); await expect(current.write(intent)).rejects.toThrow(); expect(current.canRetry(intent)).toBe(false); expect(mock.post).not.toHaveBeenCalled();
});
test('source MFA failure before POST clears intent and sends no write', async () => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  mock.get.mockRejectedValue({ response: { status: 428 } }); await expect(current.write(intent)).rejects.toEqual({ response: { status: 428 } });
  expect(current.canRetry(intent)).toBe(false); expect(mock.post).not.toHaveBeenCalled();
});
test.each([
  ['extra delivered field', { delivered: true }], ['wrong operation', { operationId: id(99) }], ['wrong resource', { blueprintId: id(99) }],
  ['rounded revision', { revision: 1 }], ['wrong revision', { revision: '2' }], ['false deployment status', { deliveryStatus: 'delivered' }],
  ['false publication', { publishedVersion: 1 }], ['wrong outcome', { outcome: 'success' }],
])('does not acknowledge a malformed receipt: %s', async (_label, changes) => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  mock.post.mockResolvedValue({ status: 201, data: { ...envelope({ operationId: intent.operationId, blueprintId: intent.blueprintId, revision: '1', publishedVersion: null,
    action: 'created', outcome: 'applied', deliveryStatus: 'pending' }), ...changes } });
  await expect(current.write(intent)).rejects.toThrow(); expect(current.canRetry(intent)).toBe(true);
});
test('session errors discard snapshots and intents, abort live reads and ignore late success', async () => {
  const current = await client(); const source = await current.get(id(1)); const intent = current.capture('updated', source, 'Originaler Änderungsversuch', draft());
  const pending = deferred<ReturnType<typeof ok>>(); mock.get.mockReturnValueOnce(pending.promise);
  const reading = current.list(); const rejected = expect(reading).rejects.toThrow(); window.dispatchEvent(new Event('od:session-error'));
  expect(current.canRetry(intent)).toBe(false); pending.resolve(ok(listData)); await rejected;
  expect(() => current.capture('updated', source, 'Originaler Änderungsversuch', draft())).toThrow();
});
test('disposal prevents late receipt paint and recovery after a completed server operation', async () => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  const pending = deferred<unknown>(); mock.post.mockReturnValue(pending.promise as ReturnType<typeof api.post>);
  const writing = current.write(intent); await Promise.resolve(); await Promise.resolve();
  current.dispose(); pending.resolve({ status: 201, data: envelope({ operationId: intent.operationId, blueprintId: intent.blueprintId, revision: '1', publishedVersion: null,
    action: 'created', outcome: 'applied', deliveryStatus: 'pending' }) });
  await expect(writing).rejects.toThrow(); expect(current.canRetry(intent)).toBe(false);
});
test('allows saving empty drafts but refuses empty publication, while app-only publication remains valid', async () => {
  const current = await client(); const empty = { ...draft(), configurations: [], appPoolIds: [] };
  expect(current.capture('created', null, 'Leerer vorbereiteter Entwurf', empty).body.draft.configurations).toHaveLength(0);
  detailData.draft = empty; detailData.preview = { configurationCount: 0, hasConflicts: false, effectiveConfigurations: [], conflicts: [] };
  const emptyDetail = await current.get(id(1)); expect(() => current.capture('published', emptyDetail, 'Lokale Freigabe versuchen')).toThrow();
  detailData.draft = { ...empty, appPoolIds: [id(20)] }; const appOnly = await current.get(id(1));
  expect(current.capture('published', appOnly, 'Lokale App-Referenz freigeben').action).toBe('published');
});
test('forged or cross-client snapshots and intents never mint writes', async () => {
  const current = await client(); const source = await current.get(id(1)); const second = await client();
  expect(() => current.capture('updated', { ...source }, 'Originaler Änderungsversuch', draft())).toThrow();
  const intent = current.capture('updated', source, 'Originaler Änderungsversuch', draft());
  await expect(second.write(intent)).rejects.toThrow(); await expect(current.write({ ...intent })).rejects.toThrow(); expect(mock.put).not.toHaveBeenCalled();
});
test('rejects parallel submissions of the same intent without issuing a second POST', async () => {
  const current = await client(); const intent = current.capture('created', null, 'Geprüfter neuer Blueprint', draft());
  const pending = deferred<ReturnType<typeof ok>>(); mock.post.mockReturnValue(pending.promise as ReturnType<typeof api.post>);
  const original = current.write(intent); await Promise.resolve(); await Promise.resolve();
  await expect(current.write(intent)).rejects.toThrow();
  pending.resolve({ status: 201, data: envelope({ operationId: intent.operationId, blueprintId: intent.blueprintId, revision: '1', publishedVersion: null,
    action: 'created', outcome: 'applied', deliveryStatus: 'pending' }), headers: {} });
  await original; expect(mock.post).toHaveBeenCalledTimes(1);
});
test('authority changes after a successful read are detected before returning its rows', async () => {
  const current = await client(); const original = mock.get.getMockImplementation();
  mock.get.mockImplementation(async (url, options) => {
    if (url === base) { const result = await original(url, options); accessData.actorUserId = id(99); return result; }
    return original(url, options);
  });
  await expect(current.list()).rejects.toThrow(); expect(() => current.capture('created', null, 'Geprüfter neuer Blueprint', draft())).toThrow();
});
test.each(['2026-10-19T12:00:00Z', '2026-10-19T14:00:00.000+02:00', '2026-10-19T12:00:00.0000Z'])('rejects noncanonical timestamp %s', async createdAt => {
  const current = await client(); listData.blueprints = [{ ...summary(), createdAt }]; await expect(current.list()).rejects.toThrow();
});
test('enforces the aggregate payload budget rather than only per-profile limits', () => {
  const input = draft(); input.configurations = Array.from({ length: 5 }, (_, index) => ({
    id: id(index + 200), type: 'filevault', name: 'FileVault', payloadJson: '{"enabled":true}' + ' '.repeat(60000),
  }));
  expect(() => normalizeCompanyBlueprintDraft(input)).toThrow();
});
test('supports maximum safe payload whitespace and reordered escaped field names consistently with the server schema', () => {
  const payload = '{"enabled":true}'; expect(companyBlueprintPayload('filevault', payload + ' '.repeat(65536 - payload.length))).toEqual({ enabled: true });
  expect(companyBlueprintPayload('screen_lock', '{"requirePassword":true,"\\u006dinutes":5}')).toEqual({ minutes: 5, requirePassword: true });
});
test.each([[401, 'Sitzung'], [403, 'Berechtigung'], [428, 'zusätzliche'], [412, 'inzwischen'], [409, 'Konflikt'], [404, 'nicht verfügbar'], [400, 'Eingaben'], [503, 'könnte']])('maps error %s without leaking private server text', (status, message) => {
  const failure = { response: { status, data: { message: 'secret-token' } } };
  expect(companyBlueprintsError(failure)).toContain(message); expect(companyBlueprintsError(failure)).not.toContain('secret-token');
  expect(companyBlueprintsUnsafe(failure)).toBe([401, 403, 428].includes(status as number));
});
