'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { RustGraphLicenseClient, fulfillmentClient } = require('../fulfillment/RustGraphLicenseClient');
const { GraphLicenseClient } = require('../fulfillment/GraphLicenseClient');

const config = { tenantId: '11111111-1111-4111-8111-111111111111', clientId: '22222222-2222-4222-8222-222222222222', clientSecret: 'fixture-only-secret' };
const objectId = '33333333-3333-4333-8333-333333333333';
const skuId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const state = (extra = {}) => ({ id: objectId, accountEnabled: true, assignedLicenses: [], licenseAssignmentStates: [], ...extra });
const assignment = (extra = {}) => ({ skuId, disabledPlans: [], assignedByGroup: null, state: 'Active', error: null, ...extra });
let folder;
beforeEach(() => { folder = fs.mkdtempSync(path.join(os.tmpdir(), 'od-rust-user-')); });
afterEach(() => fs.rmSync(folder, { recursive: true, force: true }));
function fixture(reply, { source, fetchImpl } = {}) {
  const binary = path.join(folder, 'connector');
  fs.writeFileSync(binary, `#!${process.execPath}\nlet input='';process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',()=>{const request=JSON.parse(input);if(request.operation!=='microsoft.user'||request.objectId!==${JSON.stringify(objectId)}||request.accessToken!=='private.fixture.token'||process.argv.length!==2||process.env.HOME||process.env.DATABASE_URL||process.env.LICENSE_FULFILLMENT_CONFIG_FILE)process.exit(2);${source || `process.stdout.write(${JSON.stringify(JSON.stringify(reply))});`}});`, { mode: 0o700 });
  const graph = new RustGraphLicenseClient({ ...config, binary, fetchImpl });
  graph.tokens.get = jest.fn().mockResolvedValue('private.fixture.token'); graph.tokens.clear = jest.fn();
  return graph;
}

test('the actual child receives only the bound object and private token over stdin', async () => {
  const graph = fixture({ ok: true, user: state() });
  expect(await graph.inspect(objectId, skuId, [])).toEqual({ present: false, direct: false, active: false, plansMatch: false, inherited: false, accountEnabled: true });
  expect(graph.tokens.clear).not.toHaveBeenCalled();
});

test.each([
  [null, { direct: true, inherited: false, active: true }],
  [config.tenantId, { direct: false, inherited: true, active: false }],
])('shared observation distinguishes direct and inherited assignments: %s', async (group, expected) => {
  const graph = fixture({ ok: true, user: state({ assignedLicenses: [{ skuId, disabledPlans: [] }], licenseAssignmentStates: [assignment({ assignedByGroup: group })] }) });
  expect(await graph.inspect(objectId, skuId, [])).toMatchObject({ present: true, ...expected });
});

test('provider assignment errors retain the bounded observation used by the worker', async () => {
  const graph = fixture({ ok: true, user: state({ assignedLicenses: [{ skuId, disabledPlans: [] }], licenseAssignmentStates: [assignment({ state: 'Error', error: 'CountViolation' })] }) });
  await expect(graph.inspect(objectId, skuId, [])).rejects.toMatchObject({ code: 'graph_assignment_error', observation: { direct: true, present: true, active: false } });
});

test.each([
  { ok: true, user: state({ id: config.tenantId }) },
  { ok: true, user: state({ licenseAssignmentStates: undefined }) },
  { ok: true, user: state(), extra: 'private error' },
  { ok: false, code: 'graph_read_http_429', retryAfter: 3601 },
  { ok: false, code: 'graph_write_http_429', retryAfter: 30 },
])('rejects malformed, mismatched or unexpected process replies', async reply => {
  const graph = fixture(reply);
  await expect(graph.inspect(objectId, skuId, [])).rejects.toMatchObject({ code: 'graph_read_invalid_response' });
});

test('a 429 preserves backoff and clears the cached token without leaking output', async () => {
  const graph = fixture({ ok: false, code: 'graph_read_http_429', retryAfter: 90 });
  await expect(graph.inspect(objectId, skuId, [])).rejects.toMatchObject({ code: 'graph_read_http_429', retryAfter: 90, uncertain: false });
  expect(graph.tokens.clear).toHaveBeenCalledTimes(1);
});

test('deadline terminates a stuck child and never returns an empty assignment', async () => {
  jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate'] });
  try {
    const graph = fixture(null, { source: 'setTimeout(()=>{},30000);' });
    const check = expect(graph.inspect(objectId, skuId, [])).rejects.toMatchObject({ code: 'graph_read_incomplete' });
    await jest.advanceTimersByTimeAsync(10001);
    await check;
    expect(graph.tokens.clear).toHaveBeenCalledTimes(1);
  } finally { jest.useRealTimers(); }
});

test('invalid IDs are rejected before token acquisition or process creation', async () => {
  const graph = fixture(null);
  await expect(graph.inspect('../users', skuId, [])).rejects.toThrow();
  expect(graph.tokens.get).not.toHaveBeenCalled();
});

test('read selection is explicit and unknown engines fail closed', () => {
  expect(fulfillmentClient(config, 'rust')).toBeInstanceOf(RustGraphLicenseClient);
  expect(fulfillmentClient(config, 'javascript').constructor).toBe(GraphLicenseClient);
  expect(() => fulfillmentClient(config, 'automatic')).toThrow('Unknown fulfillment read connector engine');
});

test('writes use the existing Graph contract and remain uncertain after an ambiguous response', async () => {
  const fetchImpl = jest.fn(async () => Response.json({ id: objectId }, { status: 500 }));
  const graph = fixture({ ok: true, user: state() }, { fetchImpl });
  await expect(graph.mutate(objectId, skuId, [], true, 'reviewed.write.token', config.clientId)).rejects.toMatchObject({ code: 'graph_write_http_500', uncertain: true });
  expect(fetchImpl.mock.calls[0][0]).toBe(`https://graph.microsoft.com/v1.0/users/${objectId}/assignLicense`);
});
