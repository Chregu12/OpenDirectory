'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { jwtVerify } = require('jose');
const { ProviderReadClient, GOOGLE_SCOPE, GOOGLE_TOKEN_URL, ADOBE_SCOPE, ADOBE_TOKEN_URL } = require('../providers/ProviderReadClient');
const { configuration, validateConfiguration } = require('../providers/ReadConfiguration');
const { probe } = require('../../../scripts/license-provider-probe');

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const google = { schemaVersion: 1, provider: 'google-workspace', consentReviewed: true, customerId: 'C123', productId: 'Google-Apps', skuId: '101', serviceAccountEmail: 'connector@project.iam.gserviceaccount.com', delegatedSubject: 'admin@example.test', privateKey: keys.privateKey.export({ format: 'pem', type: 'pkcs8' }) };
const github = { schemaVersion: 1, provider: 'github-copilot', consentReviewed: true, organization: 'Fixture-Org', accessToken: 'private.fixture.token' };
const googleSnapshot = { customerId: 'C123', productId: 'Google-Apps', skuId: '101', assignments: [{ productId: 'Google-Apps', skuId: '101', userId: 'é@example.test' }] };
const githubSnapshot = { organization: 'fixture-org', totalSeats: 1, seats: [{ assigneeId: 123, login: 'mona-cat_octo', assigningTeamId: null, pendingCancellationDate: '2028-02-29' }] };
const adobe = { schemaVersion: 1, provider: 'adobe-enterprise', consentReviewed: true, organizationId: 'AB123@AdobeOrg', profileId: '42', profileName: 'Creative Cloud / Zürich', clientId: 'fixture-client-123456', clientSecret: 'private.fixture.secret' };
const slack = { schemaVersion: 1, provider: 'slack-scim', consentReviewed: true, directoryKind: 'workspace', directoryId: 'T123', accessToken: 'private.fixture.token' };
const adobeSnapshot = { organizationId: adobe.organizationId, profileId: adobe.profileId, profileName: adobe.profileName, productName: 'All Apps', members: [{ id: 'adobe-user', email: 'a@example.test', identityType: 'federatedID', status: null }] };
const slackSnapshot = { directoryKind: 'workspace', directoryId: 'T123', users: [{ id: 'U123', userName: 'alice', active: true }, { id: 'W456', userName: 'bob', active: false }] };
const atlassian = { schemaVersion: 1, provider: 'atlassian-cloud', consentReviewed: true, organizationId: '11111111-1111-4111-8111-111111111111', directoryId: '22222222-2222-4222-8222-222222222222', accessToken: 'private.fixture.token' };
const gitlab = { schemaVersion: 1, provider: 'gitlab-cloud', consentReviewed: true, groupId: '123', groupPath: 'fixture-org', accessToken: 'private.fixture.token' };
const atlassianSnapshot = { organizationId: atlassian.organizationId, directoryId: atlassian.directoryId, users: [{ accountId: 'user-1', accountType: 'atlassian', accountStatus: 'active', membershipStatus: null, status: null }] };
const gitlabSnapshot = { groupId: '123', groupPath: 'fixture-org', billableMembers: [{ id: 42, username: 'member-1', state: 'active', membershipType: 'group_member' }] };
let directory;
beforeEach(() => { directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-provider-read-')); });
afterEach(() => fs.rmSync(directory, { recursive: true, force: true }));
function fixture(reply, { source, fetchImpl } = {}) {
  const binary = path.join(directory, 'connector');
  fs.writeFileSync(binary, `#!${process.execPath}\nlet input='';process.stdin.on('data',part=>input+=part);process.stdin.on('end',()=>{const request=JSON.parse(input);if(process.env.HOME||process.env.DATABASE_URL||process.argv.length!==2||request.accessToken!=='private.fixture.token'||request.privateKey||request.delegatedSubject||request.clientSecret)process.exit(2);if(request.operation==='google.licenseAssignments'&&(request.customerId!=='C123'||request.productId!=='Google-Apps'||request.skuId!=='101'))process.exit(3);if(request.operation==='github.copilotSeats'&&request.organization!=='Fixture-Org')process.exit(3);if(request.operation==='adobe.profileMembers'&&(request.organizationId!=='AB123@AdobeOrg'||request.profileId!=='42'||request.clientId!=='fixture-client-123456'))process.exit(3);if(request.operation==='slack.users'&&(request.directoryKind!=='workspace'||request.directoryId!=='T123'))process.exit(3);if(request.operation==='atlassian.directoryUsers'&&(request.organizationId!=='11111111-1111-4111-8111-111111111111'||request.directoryId!=='22222222-2222-4222-8222-222222222222'))process.exit(3);if(request.operation==='gitlab.billableMembers'&&(request.groupId!=='123'||request.groupPath!=='fixture-org'))process.exit(3);${source || `process.stdout.write(${JSON.stringify(JSON.stringify(reply))});`}});`, { mode: 0o700 });
  return { binary, fetchImpl, ...(fetchImpl ? {} : { fetchImpl: jest.fn(async () => Response.json({ token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 3600 })) }) };
}

test('Google signs a bounded delegated JWT and sends only an OAuth access token to Rust', async () => {
  const calls = [];
  const options = fixture({ ok: true, snapshot: googleSnapshot }, { fetchImpl: async (url, request) => {
    calls.push({ url, request }); return Response.json({ token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 3600, scope: GOOGLE_SCOPE });
  } });
  const client = new ProviderReadClient(google, options);
  expect(await client.inspect()).toEqual(googleSnapshot); expect(await client.inspect()).toEqual(googleSnapshot);
  expect(calls).toHaveLength(1); expect(calls[0].url).toBe(GOOGLE_TOKEN_URL); expect(calls[0].request.redirect).toBe('manual');
  const form = new URLSearchParams(calls[0].request.body); expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:jwt-bearer');
  const { payload } = await jwtVerify(form.get('assertion'), keys.publicKey, { algorithms: ['RS256'], issuer: google.serviceAccountEmail, audience: GOOGLE_TOKEN_URL, subject: google.delegatedSubject });
  expect(payload.scope).toBe(GOOGLE_SCOPE); expect(payload.exp - payload.iat).toBe(300);
});

test('GitHub uses the pinned organization and never calls an OAuth or write endpoint', async () => {
  const options = fixture({ ok: true, snapshot: githubSnapshot });
  expect(await new ProviderReadClient(github, options).inspect()).toEqual(githubSnapshot); expect(options.fetchImpl).not.toHaveBeenCalled();
});

test.each([[google, googleSnapshot, { assignedUsers: 1 }], [github, githubSnapshot, { billedSeats: 1, pendingCancellations: 1 }]])('probe emits only counts and provider binding for %j', async (config, data, expected) => {
  const result = await probe(config, fixture({ ok: true, snapshot: data }));
  expect(result).toMatchObject({ ok: true, provider: config.provider, ...expected });
  const output = JSON.stringify(result); expect(output).not.toContain('é@'); expect(output).not.toContain('mona'); expect(output).not.toContain('private');
});

test.each([
  [google, { ...googleSnapshot, customerId: 'C999' }],
  [google, { ...googleSnapshot, productId: 'wrong' }],
  [google, { ...googleSnapshot, assignments: [{ ...googleSnapshot.assignments[0], skuId: 'other' }] }],
  [google, { ...googleSnapshot, assignments: [...googleSnapshot.assignments, ...googleSnapshot.assignments] }],
  [github, { ...githubSnapshot, organization: 'other-org' }],
  [github, { ...githubSnapshot, totalSeats: 2 }],
  [github, { ...githubSnapshot, seats: [{ ...githubSnapshot.seats[0], assigneeId: 0 }] }],
  [github, { ...githubSnapshot, seats: [{ ...githubSnapshot.seats[0], pendingCancellationDate: '2026-02-29' }] }],
  [github, { ...githubSnapshot, seats: [{ ...githubSnapshot.seats[0], extra: 'private' }] }],
])('rejects wrong namespaces, incomplete and malformed captures', async (config, data) => {
  await expect(new ProviderReadClient(config, fixture({ ok: true, snapshot: data })).inspect()).rejects.toMatchObject({ code: expect.stringMatching(/_invalid_response$/) });
});

test.each([['google-workspace', 'google_licenses'], ['github-copilot', 'github_copilot']])('propagates bounded retry without raw output for %s', async (provider, stage) => {
  const client = new ProviderReadClient(provider === google.provider ? google : github, fixture({ ok: false, code: stage + '_http_429', retryAfter: 90 }));
  await expect(client.inspect()).rejects.toMatchObject({ code: stage + '_http_429', retryAfter: 90, uncertain: false });
});

test.each([
  { token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 3600, scope: 'other-scope' },
  { token_type: 'Bearer', access_token: 'bad\nheader', expires_in: 3600 },
  { token_type: 'Bearer', access_token: 'private.fixture.token', expires_in: 1 },
])('invalid Google token metadata fails before any connector process', async data => {
  const spawnImpl = jest.fn();
  const client = new ProviderReadClient(google, { fetchImpl: async () => Response.json(data), spawnImpl });
  await expect(client.inspect()).rejects.toMatchObject({ code: 'google_token_invalid_response' }); expect(spawnImpl).not.toHaveBeenCalled();
});

test('a cancelled inspection terminates the child and never returns empty seats', async () => {
  const client = new ProviderReadClient(github, fixture(null, { source: 'setTimeout(()=>{},30000);' }));
  const controller = new AbortController(); const pending = client.inspect(controller.signal); controller.abort();
  await expect(pending).rejects.toMatchObject({ code: 'github_copilot_incomplete' });
});

test('deadline terminates a pending read without acknowledging partial seats', async () => {
  jest.useFakeTimers({ doNotFake: ['nextTick', 'setImmediate'] });
  try {
    const client = new ProviderReadClient(github, fixture(null, { source: 'setTimeout(()=>{},30000);' }));
    const check = expect(client.inspect()).rejects.toMatchObject({ code: 'github_copilot_incomplete' });
    await jest.advanceTimersByTimeAsync(20001); await check;
  } finally { jest.useRealTimers(); }
});

test.each([{ ok: true, snapshot: githubSnapshot, extra: 'private' }, { ok: false, code: 'private.secret' }, { ok: false, code: 'github_copilot_http_429', retryAfter: 99999 }])('invalid process envelopes do not escape into caller output', async reply => {
  await expect(new ProviderReadClient(github, fixture(reply)).inspect()).rejects.toMatchObject({ code: 'github_copilot_invalid_response' });
});

test('configuration is owner-only, bounded, explicit and rejects symlinks and foreign owners', () => {
  const filename = path.join(directory, 'connection.json'); fs.writeFileSync(filename, JSON.stringify(github), { mode: 0o600 });
  expect(configuration(filename)).toEqual(github); fs.chmodSync(filename, 0o640); expect(() => configuration(filename)).toThrow(); fs.chmodSync(filename, 0o600);
  fs.symlinkSync(filename, filename + '.link'); expect(() => configuration(filename + '.link')).toThrow();
  const actual = fs.fstatSync; const stat = jest.spyOn(fs, 'fstatSync').mockImplementation(fd => ({ ...actual(fd), isFile: () => true, uid: process.getuid() + 1 }));
  try { expect(() => configuration(filename)).toThrow('Owner-only'); } finally { stat.mockRestore(); }
  fs.writeFileSync(filename, ' '.repeat(65537)); expect(() => configuration(filename)).toThrow();
});

test.each([
  { ...github, consentReviewed: false }, { ...github, organization: '../escape' }, { ...github, apiUrl: 'https://evil.test' },
  { ...google, customerId: 'my_customer' }, { ...google, skuId: '../sku' }, { ...google, serviceAccountEmail: 'human@example.test' },
  { ...google, delegatedSubject: 'admin\n@example.test' }, { ...google, privateKey: 'invalid private key' },
])('configuration cannot select URLs or bypass explicit consent and key requirements', config => expect(() => validateConfiguration(config)).toThrow());

test('CLI rejection redacts file contents and provider secrets', () => {
  const filename = path.join(directory, 'connection.json'); fs.writeFileSync(filename, JSON.stringify({ ...github, organization: '../escape' }), { mode: 0o600 });
  const result = spawnSync(process.execPath, [path.resolve(__dirname, '../../../scripts/license-provider-probe.js')], { encoding: 'utf8', env: { ...process.env, LICENSE_PROVIDER_PROBE_CONFIG_FILE: filename } });
  expect(result.status).toBe(1); expect(JSON.parse(result.stderr)).toEqual({ ok: false, code: 'provider_probe_rejected' }); expect(result.stdout + result.stderr).not.toContain(github.accessToken);
});

test('Adobe uses the fixed current S2S endpoint, body credentials and reviewed UMAPI scope', async () => {
  const options = fixture({ ok: true, snapshot: adobeSnapshot });
  const client = new ProviderReadClient(adobe, options);
  expect(await client.inspect()).toEqual(adobeSnapshot); await client.inspect();
  expect(options.fetchImpl).toHaveBeenCalledTimes(1);
  const [url, request] = options.fetchImpl.mock.calls[0]; expect(url).toBe(ADOBE_TOKEN_URL); expect(request.redirect).toBe('manual');
  const form = new URLSearchParams(request.body);
  expect(Object.fromEntries(form)).toEqual({ grant_type: 'client_credentials', client_id: adobe.clientId, client_secret: adobe.clientSecret, scope: ADOBE_SCOPE });
  expect(url).not.toContain(adobe.clientSecret);
});

test.each([null, {}, { token_type: 123 }, { token_type: 'Bearer', access_token: 'bad\nheader', expires_in: 3600 }])('malformed S2S token data is a bounded error before process creation', async data => {
  const spawnImpl = jest.fn();
  const client = new ProviderReadClient(adobe, { fetchImpl: async () => Response.json(data), spawnImpl });
  await expect(client.inspect()).rejects.toMatchObject({ code: 'adobe_token_invalid_response' }); expect(spawnImpl).not.toHaveBeenCalled();
});

test('Slack keeps the configured directory scope and never makes a Node OAuth request', async () => {
  const options = fixture({ ok: true, snapshot: slackSnapshot });
  expect(await new ProviderReadClient(slack, options).inspect()).toEqual(slackSnapshot); expect(options.fetchImpl).not.toHaveBeenCalled();
});

test.each([
  [adobe, adobeSnapshot, { observedMembers: 1, profileId: '42' }],
  [slack, slackSnapshot, { observedUsers: 2, activeAccounts: 1, directoryKind: 'workspace' }],
])('new probe summaries retain only binding and counts', async (config, data, expected) => {
  const result = await probe(config, fixture({ ok: true, snapshot: data }));
  expect(result).toMatchObject({ ok: true, provider: config.provider, ...expected });
  for (const privateValue of ['a@example.test', 'adobe-user', 'alice', 'bob', 'private.fixture']) expect(JSON.stringify(result)).not.toContain(privateValue);
});

test.each([
  [adobe, { ...adobeSnapshot, organizationId: 'ABC@AdobeOrg' }],
  [adobe, { ...adobeSnapshot, profileId: '43' }],
  [adobe, { ...adobeSnapshot, profileName: 'Another profile' }],
  [adobe, { ...adobeSnapshot, members: [adobeSnapshot.members[0], adobeSnapshot.members[0]] }],
  [adobe, { ...adobeSnapshot, members: [{ ...adobeSnapshot.members[0], status: 'provisioned' }] }],
  [adobe, { ...adobeSnapshot, members: [{ ...adobeSnapshot.members[0], identityType: 'other' }] }],
  [slack, { ...slackSnapshot, directoryKind: 'enterprise' }],
  [slack, { ...slackSnapshot, directoryId: 'T999' }],
  [slack, { ...slackSnapshot, users: [slackSnapshot.users[0], slackSnapshot.users[0]] }],
  [slack, { ...slackSnapshot, users: [{ ...slackSnapshot.users[0], active: 'true' }] }],
])('profile, identity and directory mismatches fail at the process boundary', async (config, data) => {
  await expect(new ProviderReadClient(config, fixture({ ok: true, snapshot: data })).inspect()).rejects.toMatchObject({ code: expect.stringMatching(/_invalid_response$/) });
});

test.each([[adobe, 'adobe_profiles'], [slack, 'slack_directory']])('new providers preserve throttling without echoing raw bodies', async (config, stage) => {
  await expect(new ProviderReadClient(config, fixture({ ok: false, code: stage + '_http_429', retryAfter: 90 })).inspect()).rejects.toMatchObject({ code: stage + '_http_429', retryAfter: 90 });
});

test.each([
  { ...adobe, organizationId: '../org' }, { ...adobe, profileId: '01' }, { ...adobe, profileId: '18446744073709551616' },
  { ...adobe, profileName: '..' }, { ...adobe, clientId: 'bad\nheader' }, { ...adobe, tokenUrl: 'https://evil.test' },
  { ...slack, directoryKind: 'workspace', directoryId: 'E123' }, { ...slack, directoryKind: 'enterprise', directoryId: 'T123' },
  { ...slack, consentReviewed: false }, { ...slack, apiUrl: 'https://evil.test' },
])('new provider configuration cannot choose hosts or mix directory scopes', config => expect(() => validateConfiguration(config)).toThrow());

test.each([[atlassian, atlassianSnapshot], [gitlab, gitlabSnapshot]])('directory and billing readers use the selected binding without Node OAuth requests', async (config, data) => {
  const options = fixture({ ok: true, snapshot: data });
  expect(await new ProviderReadClient(config, options).inspect()).toEqual(data); expect(options.fetchImpl).not.toHaveBeenCalled();
});

test.each([[atlassian, atlassianSnapshot, { observedUsers: 1 }], [gitlab, gitlabSnapshot, { observedBillableMembers: 1 }]])('directory and billing summaries contain no member identities', async (config, data, expected) => {
  const result = await probe(config, fixture({ ok: true, snapshot: data }));
  expect(result).toMatchObject({ ok: true, provider: config.provider, ...expected });
  for (const value of ['user-1', 'member-1', 'private.fixture']) expect(JSON.stringify(result)).not.toContain(value);
});

test.each([
  [atlassian, { ...atlassianSnapshot, organizationId: google.customerId }],
  [atlassian, { ...atlassianSnapshot, directoryId: atlassian.organizationId }],
  [atlassian, { ...atlassianSnapshot, users: [atlassianSnapshot.users[0], atlassianSnapshot.users[0]] }],
  [atlassian, { ...atlassianSnapshot, users: [{ ...atlassianSnapshot.users[0], accountId: 'https://evil.test' }] }],
  [atlassian, { ...atlassianSnapshot, users: [{ ...atlassianSnapshot.users[0], membershipStatus: 'provisioned' }] }],
  [atlassian, { ...atlassianSnapshot, users: [{ ...atlassianSnapshot.users[0], email: 'private@example.test' }] }],
  [gitlab, { ...gitlabSnapshot, groupId: '124' }],
  [gitlab, { ...gitlabSnapshot, groupPath: 'another-org' }],
  [gitlab, { ...gitlabSnapshot, billableMembers: [gitlabSnapshot.billableMembers[0], gitlabSnapshot.billableMembers[0]] }],
  [gitlab, { ...gitlabSnapshot, billableMembers: [{ ...gitlabSnapshot.billableMembers[0], id: 9007199254740992 }] }],
  [gitlab, { ...gitlabSnapshot, billableMembers: [{ ...gitlabSnapshot.billableMembers[0], membershipType: 'bad\nvalue' }] }],
])('wrong directories, groups and malformed identities reject the process snapshot', async (config, data) => {
  await expect(new ProviderReadClient(config, fixture({ ok: true, snapshot: data })).inspect()).rejects.toMatchObject({ code: expect.stringMatching(/_invalid_response$/) });
});

test.each([[atlassian, 'atlassian_directory'], [gitlab, 'gitlab_billable']])('new directory and billing readers return bounded retry intervals', async (config, stage) => {
  await expect(new ProviderReadClient(config, fixture({ ok: false, code: stage + '_http_429', retryAfter: 90 })).inspect()).rejects.toMatchObject({ code: stage + '_http_429', retryAfter: 90 });
});

test.each([
  { ...atlassian, directoryId: '-' }, { ...atlassian, organizationId: '../org' }, { ...atlassian, consentReviewed: false }, { ...atlassian, apiUrl: 'https://evil.test' },
  { ...gitlab, groupId: '01' }, { ...gitlab, groupId: '9007199254740992' }, { ...gitlab, groupPath: 'parent/child' }, { ...gitlab, baseUrl: 'https://gitlab.example' },
])('new directory and billing configuration cannot broaden scope or select hosts', config => expect(() => validateConfiguration(config)).toThrow());
