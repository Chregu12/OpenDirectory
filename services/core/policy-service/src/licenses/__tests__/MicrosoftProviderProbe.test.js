'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { ProviderReadClient } = require('../providers/ProviderReadClient');
const { configuration, validateConfiguration } = require('../providers/ReadConfiguration');
const { probe } = require('../../../scripts/license-provider-probe');

const config = { schemaVersion: 1, provider: 'microsoft-365', consentReviewed: true,
  tenantId: '11111111-1111-4111-8111-111111111111', clientId: '22222222-2222-4222-8222-222222222222', clientSecret: 'private.fixture.secret' };
const product = { skuId: '33333333-3333-4333-8333-333333333333', skuPartNumber: 'TEST_PRODUCT', appliesTo: 'User', capabilityStatus: 'Enabled',
  prepaidUnits: { enabled: 5, warning: 0, suspended: 0, lockedOut: 0 }, consumedUnits: 2 };
let directory;
beforeEach(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-microsoft-probe-')); });
afterEach(() => { fs.rmSync(directory, { recursive: true, force: true }); });

function fixture(reply = { ok: true, rows: [product] }) {
  const binary = path.join(directory, 'connector');
  fs.writeFileSync(binary, `#!${process.execPath}\nlet input='';process.stdin.on('data',v=>input+=v);process.stdin.on('end',()=>{const body=JSON.parse(input);if(process.env.HOME||process.env.DATABASE_URL||process.argv.length!==2||Object.keys(body).join(',')!=='accessToken'||body.accessToken!=='private.fixture.token')process.exit(2);process.stdout.write(${JSON.stringify(JSON.stringify(reply))})});`, { mode: 0o700 });
  return { binary, fetchImpl: jest.fn(async () => Response.json({ token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 3600 })) };
}

test('Microsoft reuses the tenant-specific token and sends only that token to the existing Rust capacity reader', async () => {
  const options = fixture(); const client = new ProviderReadClient(config, options);
  expect(await client.inspect()).toEqual([product]); expect(await client.inspect()).toEqual([product]);
  expect(options.fetchImpl).toHaveBeenCalledTimes(1);
  const [url, request] = options.fetchImpl.mock.calls[0];
  expect(url).toBe(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`);
  expect(request.redirect).toBe('manual'); expect(url).not.toContain(config.clientSecret);
  expect(Object.fromEntries(new URLSearchParams(request.body))).toEqual({ grant_type: 'client_credentials', client_id: config.clientId, client_secret: config.clientSecret, scope: 'https://graph.microsoft.com/.default' });
});

test('the standalone probe returns normalized products without requiring a local connector or user mapping', async () => {
  const options = fixture({ ok: true, rows: [{ ...product, accountName: 'private account name', debug: 'private.fixture.secret' }] });
  expect(await probe(config, options)).toEqual({ ok: true, provider: config.provider, tenantId: config.tenantId, products: [product] });
});

test.each([
  { tenantId: 'common' }, { clientId: 'not-an-app-id' }, { clientSecret: 'short' },
  { clientSecret: 'private\nfixture.secret' }, { consentReviewed: false }, { tokenUrl: 'https://untrusted.invalid/token' },
  { connectorId: config.clientId },
])('Microsoft configuration rejects unbound or unsafe input: %j', changes => {
  expect(() => validateConfiguration({ ...config, ...changes })).toThrow();
});

test('an already cancelled probe cannot fetch a token or start a connector', async () => {
  const options = { fetchImpl: jest.fn(), spawnImpl: jest.fn() }; const controller = new AbortController(); controller.abort();
  await expect(new ProviderReadClient(config, options).inspect(controller.signal)).rejects.toMatchObject({ code: expect.stringMatching(/^graph_capacity_/) });
  expect(options.fetchImpl).not.toHaveBeenCalled(); expect(options.spawnImpl).not.toHaveBeenCalled();
});

function cli({ status = 200, reply, changes = {} } = {}) {
  const filename = path.join(directory, 'configuration.json'); fs.writeFileSync(filename, JSON.stringify({ ...config, ...changes }), { mode: 0o600 });
  const options = fixture(reply); const preload = path.join(directory, 'preload.cjs');
  fs.writeFileSync(preload, `const Module=require('module'),original=Module._load;Module._load=function(name,...args){if(name==='pg')throw new Error('Database access is forbidden in this probe');return original.call(this,name,...args)};const cp=require('child_process'),spawn=cp.spawn;cp.spawn=(binary,args,options)=>{if(binary!=='/usr/local/bin/opendirectory-connectors')throw new Error('Unexpected child');return spawn(${JSON.stringify(options.binary)},args,options)};global.fetch=async(url,request)=>{if(url!==${JSON.stringify(`https://login.microsoftonline.com/${config.tenantId}/oauth2/v2.0/token`)}||new URLSearchParams(request.body).get('client_secret')!==${JSON.stringify(config.clientSecret)})throw new Error('Unexpected token request');return Response.json(${JSON.stringify(status === 200 ? { token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 3600 } : { error: config.clientSecret })},{status:${status}})};`);
  return { filename, result: spawnSync(process.execPath, ['--require', preload, path.resolve(__dirname, '../../../scripts/license-provider-probe.js')], {
    encoding: 'utf8', env: { ...process.env, DATABASE_URL: 'postgres://must-not-connect.invalid/test', LICENSE_PROVIDER_PROBE_CONFIG_FILE: filename }, timeout: 10000,
  }) };
}

test('the actual CLI reads an owner-only file and succeeds without database access or local binding IDs', () => {
  const { filename, result } = cli();
  expect(configuration(filename)).toEqual(config); expect(result.status).toBe(0); expect(result.stderr).toBe('');
  expect(JSON.parse(result.stdout)).toEqual({ ok: true, provider: config.provider, tenantId: config.tenantId, products: [product] });
  expect(result.stdout).not.toContain(config.clientSecret); expect(result.stdout).not.toContain('private.fixture.token');
});

test.each([
  [{ status: 403 }, { ok: false, code: 'graph_capacity_token_http_403' }],
  [{ reply: { ok: false, code: 'graph_capacity_http_429', retryAfter: 90 } }, { ok: false, code: 'graph_capacity_http_429', retryAfter: 90 }],
  [{ changes: { consentReviewed: false } }, { ok: false, code: 'provider_probe_rejected' }],
])('CLI errors remain bounded and redact credentials', (input, expected) => {
  const { result } = cli(input); expect(result.status).toBe(1); expect(result.stdout).toBe(''); expect(JSON.parse(result.stderr)).toEqual(expected);
  expect(result.stderr).not.toContain(config.clientSecret); expect(result.stderr).not.toContain('private.fixture.token');
});
