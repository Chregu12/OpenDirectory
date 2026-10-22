'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, randomBytes, generateKeyPairSync, createHash } = require('node:crypto');
const { once } = require('node:events');
const { createRequire } = require('node:module');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { nextOtp, rememberFactor } = require('./fixtures/mfa.cjs');
const { totp } = require('../MfaAuthority');
const net = require('node:net');
const { Pool } = require('pg');
const { bootstrapApplications } = require('./fixtures/bootstrapApplications.cjs');

const frontend = path.resolve(__dirname, '../../../../../frontend/web-app');
const webRequire = createRequire(path.join(frontend, 'package.json'));
const schema = 'oauth_browser_' + randomUUID().replaceAll('-', '');
const identitySchema = 'identity_browser_' + randomUUID().replaceAll('-', '');
const policySchema='policy_browser_'+randomUUID().replaceAll('-','');
let policyDb; let policyServer; let policyBase;
const readerUser = randomUUID();
const browserTenant=randomUUID();const tenantBrowserUser=randomUUID();const tenantDirectoryReader=randomUUID();const tenantDirectoryCreator=randomUUID();
const actors = new Map([
  ['company-assignment-reviewer',{userId:randomUUID(),name:'Independent Assignment Company Reviewer',roles:['user'],permissions:[]}],
  ['company-blueprint-reviewer',{userId:randomUUID(),name:'Independent Blueprint Company Reviewer',roles:['user'],permissions:[]}],
  ['company-review-console',{userId:randomUUID(),name:'Explicit Company Reviewer',roles:['user'],permissions:[]}],
  ['organization-console-admin',{userId:randomUUID(),name:'Organization Profile Administrator',roles:['admin'],permissions:[]}],
  ['organization-console-delegate',{userId:randomUUID(),name:'Organization Profile Delegate',roles:['user'],permissions:[]}],
  ['mfa-counter-boundary',{userId:randomUUID(),name:'MFA Counter Boundary Owner',roles:['license-scope-administrator'],permissions:[]}],
  ['user-self-disable',{userId:randomUUID(),name:'Own Disable Operator',roles:['admin'],permissions:[]}],
  ['user-self-delete',{userId:randomUUID(),name:'Own Delete Operator',roles:['admin'],permissions:[]}],
  ['tenant-browser-user',{userId:tenantBrowserUser,name:'Separate Tenant Browser Owner',roles:['user'],permissions:[]}],
  ['tenant-directory-reader',{userId:tenantDirectoryReader,name:'Separate Tenant Directory Reader',roles:['directory-reader'],permissions:[]}],
  ['tenant-directory-creator',{userId:tenantDirectoryCreator,name:'Separate Tenant Directory Creator',roles:['admin'],permissions:[]}],
  ['policy-console-reviewer', { userId: randomUUID(), name: 'Independent Policy Publication Reviewer', roles: ['policy-publication-reviewer'], permissions: [] }],
  ['blueprint-console-reviewer', { userId: randomUUID(), name: 'Independent Blueprint Publication Reviewer', roles: ['policy-publication-reviewer'], permissions: [] }],
  ['blueprint-console-config', { userId: randomUUID(), name: 'Blueprint Configuration Administrator', roles: ['policy-administrator'], permissions: [] }],
  ['blueprint-console-read', { userId: randomUUID(), name: 'Blueprint Configuration Reader', roles: ['policy-reader'], permissions: [] }],
  ['policy-protocol-config', { userId: randomUUID(), name: 'Policy Protocol Configuration Operator', roles: ['policy-administrator'], permissions: [] }],
  ['policy-console-config', { userId: randomUUID(), name: 'Policy Configuration Administrator', roles: ['policy-administrator'], permissions: [] }],
  ['policy-console-read', { userId: randomUUID(), name: 'Policy Metadata Reader', roles: ['policy-reader'], permissions: [] }],
  ['source-console-config',{userId:randomUUID(),name:'Group Source Consent Administrator',roles:['license-scope-administrator'],permissions:[]}],
  ['source-console-reader',{userId:randomUUID(),name:'Group Source Consent Metadata Reader',roles:['license-scope-reader'],permissions:[]}],
  ['membership-config',{userId:randomUUID(),name:'Membership Review Policy Author',roles:['group-review-administrator'],permissions:[]}],
  ['membership-voter',{userId:randomUUID(),name:'Membership Independent Voter',roles:['group-reviewer'],permissions:[]}],
  ['membership-grantor',{userId:randomUUID(),name:'Membership Original Grantor',roles:['group-administrator'],permissions:[]}],
  ['membership-holder',{userId:randomUUID(),name:'Membership Holder',roles:['user'],permissions:[]}],
  ['membership-reader',{userId:randomUUID(),name:'Membership Review Metadata Reader',roles:['group-review-reader'],permissions:[]}],
  ['authority-review-config',{userId:randomUUID(),name:'Authority Review Grant Configurator',roles:['license-scope-administrator'],permissions:[]}],
  ['authority-review-maker',{userId:randomUUID(),name:'Authority Review Policy Administrator',roles:['license-delegation-review-administrator'],permissions:[]}],
  ['authority-review-voter',{userId:randomUUID(),name:'Authority Review Independent Voter',roles:['license-delegation-reviewer'],permissions:[]}],
  ['authority-review-owner',{userId:randomUUID(),name:'Authority Review Holder',roles:['license-delegate'],permissions:[]}],
  ['authority-review-reader',{userId:randomUUID(),name:'Authority Review Metadata Reader',roles:['license-delegation-review-reader'],permissions:[]}],
  ['pool-policy-config', { userId:randomUUID(),name:'Pool Policy Path Configurator',roles:['license-scope-administrator'],permissions:[] }],
  ['pool-policy-operator', { userId:randomUUID(),name:'Pool Policy Delegate',roles:['license-delegate'],permissions:[] }],
  ['pool-policy-reviewer', { userId:randomUUID(),name:'Pool Policy Reviewer',roles:['license-scope-activation-reviewer'],permissions:[] }],
  ['pool-policy-maker', { userId:randomUUID(),name:'Pool Policy Administrator',roles:['license-scope-policy-administrator'],permissions:[] }],
  ['pool-policy-reader', { userId:randomUUID(),name:'Pool Policy Reader',roles:['license-scope-policy-reader'],permissions:[] }],
  ['scope-pim-config', { userId: randomUUID(), name: 'Scope PIM Configurator', roles: ['license-scope-administrator'], permissions: [] }],
  ['scope-pim-operator', { userId: randomUUID(), name: 'Scope PIM Delegate', roles: ['license-delegate'], permissions: [] }],
  ['scope-pim-reviewer', { userId: randomUUID(), name: 'Scope PIM Reviewer', roles: ['license-scope-activation-reviewer'], permissions: [] }],
  ['scope-config', { userId: randomUUID(), name: 'Pool Delegation Configurator', roles: ['license-scope-administrator'], permissions: [] }],
  ['scope-operator', { userId: randomUUID(), name: 'Pool Delegate', roles: ['license-delegate'], permissions: [] }],
  ['license-review-config', { userId: randomUUID(), name: 'License Review Configurator', roles: ['license-review-administrator'], permissions: [] }],
  ['license-review-voter', { userId: randomUUID(), name: 'License Review Voter', roles: ['license-reviewer'], permissions: [] }],
  ['license-review-reader', { userId: randomUUID(), name: 'License Review Reader', roles: ['license-review-reader'], permissions: [] }],
  ['license-grant-manager', { userId: randomUUID(), name: 'License Grant Manager', roles: ['license-manager'], permissions: [] }],
  ['reader', { userId: readerUser, name: 'Verified Reader', roles: ['user'], permissions: [] }],
  ['viewer', { userId: randomUUID(), name: 'Directory Reader', roles: ['directory-reader'], permissions: [] }],
  ['lifecycle', { userId: randomUUID(), name: 'Lifecycle Operator', roles: ['user-lifecycle-operator'], permissions: [] }],
  ['profile-editor', { userId: randomUUID(), name: 'Profile Editor', roles: [], permissions: ['users.read', 'users.update'] }],
  ['session-operator', { userId: randomUUID(), name: 'Session Operator', roles: ['session-administrator'], permissions: [] }],
  ['role-operator', { userId: randomUUID(), name: 'Role Operator', roles: ['role-administrator'], permissions: [] }],
  ['pim-manager', { userId: randomUUID(), name: 'PIM Manager', roles: ['pim-administrator'], permissions: [] }],
  ['pim-reviewer', { userId: randomUUID(), name: 'PIM Reviewer', roles: ['pim-approver'], permissions: [] }],
  ['app-operator', { userId: randomUUID(), name: 'Application Operator', roles: ['application-administrator'], permissions: [] }],
  ['app-reader', { userId: randomUUID(), name: 'Application Reader', roles: ['application-reader'], permissions: [] }],
  ['app-access-manager', { userId: randomUUID(),name: 'Application Access Manager',roles: ['application-access-administrator'],permissions: [] }],
  ['app-access-reader', { userId: randomUUID(),name: 'Application Access Reader',roles: ['application-access-reader'],permissions: [] }],
  ['administrator', { userId: randomUUID(), name: 'Administrator', roles: ['admin'], permissions: [] }],
  ['managed', { userId: randomUUID(), name: 'Managed Employee', roles: ['user'], permissions: [] }],
]);
let legacyUserRequests = 0; let identityBase;
const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 });
const logicalIssuer = 'https://browser-issuer.test';
let directory; let database; let credentialServer; let issuerProcess; let nextProcess; let browser; let origin; let issuerBase; let issuerEnabled = true;
let buildDirectory; let testTsconfig; let issuerDb; let credentialAttempts = 0;
let identityDb; let identityServer;
let inventoryFixture;
let quickProcess; let quickBase; let quickReceiver; let quickReceipts = []; let quickGate; let quickCredentialFallbacks = 0;
actors.set('mfa-owner', { userId: randomUUID(), name: 'MFA Owner', roles: ['user'], permissions: [] });
actors.set('recovery-owner', { userId: randomUUID(), name: 'Recovery Owner', roles: ['user'], permissions: [] });
actors.set('authentication-manager', { userId: randomUUID(), name: 'Authentication Manager', roles: ['application-authentication-administrator'], permissions: [] });
actors.set('authentication-reader', { userId: randomUUID(), name: 'Authentication Reader', roles: ['application-authentication-reader'], permissions: [] });
actors.set('authentication-user', { userId: randomUUID(), name: 'Authentication User', roles: ['user'], permissions: [] });
actors.set('role-assurance-manager', { userId: randomUUID(),name:'Role Assurance Manager',roles:['authentication-policy-administrator'],permissions:[] });
actors.set('role-assurance-reader', { userId: randomUUID(),name:'Role Assurance Reader',roles:['authentication-policy-reader'],permissions:[] });
actors.set('role-assurance-user', { userId: randomUUID(),name:'Role Assurance User',roles:['license-manager'],permissions:[] });
actors.set('cloud-provider-config', { userId:randomUUID(),name:'Provider Configurator',roles:['license-provider-administrator'],permissions:[] });
actors.set('cloud-provider-read', { userId:randomUUID(),name:'Provider Reader',roles:['license-fulfillment-reader'],permissions:[] });
actors.set('cloud-beneficiary', { userId:randomUUID(),name:'Provider Beneficiary',roles:['user'],permissions:[] });
actors.set('pim-policy-manager',{ userId:randomUUID(),name:'Privileged Policy Manager',roles:['privileged-access-policy-administrator'],permissions:[] });
actors.set('pim-policy-reader',{ userId:randomUUID(),name:'Privileged Policy Reader',roles:['privileged-access-policy-reader'],permissions:[] });
actors.set('pim-policy-owner',{ userId:randomUUID(),name:'Privileged Policy Owner',roles:['license-manager'],permissions:[] });
actors.set('review-config',{ userId:randomUUID(),name:'Review Configuration Operator',roles:['access-review-administrator'],permissions:[] });
actors.set('review-voter',{ userId:randomUUID(),name:'Independent Review Operator',roles:['access-reviewer'],permissions:[] });
actors.set('review-reader',{ userId:randomUUID(),name:'Review Metadata Reader',roles:['access-review-reader'],permissions:[] });
actors.set('review-holder',{ userId:randomUUID(),name:'Review Entitlement Holder',roles:['user'],permissions:[] });

async function serverBase(server) {
  if (!server.listening) await once(server, 'listening');
  return 'http://127.0.0.1:' + server.address().port;
}

async function stop(child) {
  if (child && child.exitCode === null && child.signalCode === null) {
    const exited = once(child, 'exit'); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000);
    try { await exited; } finally { clearTimeout(timer); }
  }
}

async function waitReady(probe, child, output) {
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('Server exited: ' + output());
    try { if (await probe()) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('Server startup timed out: ' + output());
}

before(async () => {
  await administration.query(`CREATE SCHEMA ${schema}`);
  await administration.query(`CREATE SCHEMA ${identitySchema}`);
  await administration.query(`CREATE SCHEMA ${policySchema}`);
  const databaseUrl = new URL(process.env.OAUTH_TEST_DATABASE_URL); databaseUrl.searchParams.set('options', `-c search_path=${schema},public`);
  database = databaseUrl.toString(); issuerDb = new Pool({ connectionString: database, max: 2 });
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-real-browser-'));
  const signing = path.join(directory, 'signing.pem'); const cookieKey = path.join(directory, 'cookie.key'); const secret = path.join(directory, 'client.secret');
  const mfaKey = path.join(directory, 'mfa.key'); require('../../scripts/mfa-key').generate(mfaKey);
  fs.writeFileSync(signing, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(cookieKey, randomBytes(32), { mode: 0o600 }); fs.writeFileSync(secret, randomBytes(32).toString('base64url'), { mode: 0o600 });
  const probe = net.createServer().listen(0, '127.0.0.1'); origin = await serverBase(probe); await new Promise(resolve => probe.close(resolve));
  const identityProbe = net.createServer().listen(0, '127.0.0.1'); identityBase = await serverBase(identityProbe);
  await new Promise(resolve => identityProbe.close(resolve));
  const policyProbe=net.createServer().listen(0,'127.0.0.1');policyBase=await serverBase(policyProbe);await new Promise(resolve=>policyProbe.close(resolve));
  credentialServer = http.createServer(async (request, response) => {
    response.setHeader('Content-Type', 'application/json');
    if (request.url.startsWith('/api/users')) { legacyUserRequests++; return response.end(JSON.stringify({ users: [{ id: 'legacy-shadow', role: 'admin' }] })); }
    if (request.url !== '/api/auth/login' || request.method !== 'POST') { response.statusCode = 404; return response.end('{}'); }
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const credentials = JSON.parse(Buffer.concat(chunks)); credentialAttempts++;
    response.setHeader('Content-Type', 'application/json');
    if ((!actors.has(credentials.username) && !['company-registration-owner', 'company-blueprint-owner', 'company-assignment-owner', 'company-automation-owner','company-license-automation-owner'].includes(credentials.username)) || credentials.password !== 'disposable-password') {
      response.statusCode = 401; return response.end('{"success":false}');
    }
    const actor = actors.get(credentials.username);
    response.end(JSON.stringify({ success: true, user: { id: credentials.username + '-subject', name: actor?.name || 'Verified company registration owner', username: credentials.username,
      ...(credentials.username === 'company-registration-owner' ? { email: 'verified-company-owner@example.invalid' } : credentials.username === 'company-blueprint-owner' ? { email: 'verified-blueprint-owner@example.invalid' } : credentials.username === 'company-assignment-owner' ? { email: 'verified-assignment-owner@example.invalid' } : {}), roles: ['admin'], permissions: ['users.delete', 'identities.roles.manage'] } }));
  }).listen(0, '127.0.0.1');
  const credentialsBase = await serverBase(credentialServer);
  let issuerOutput = ''; let nextOutput = '';
  const issuerScript = `let server;const db=require('./src/db');process.on('SIGTERM',async()=>{server?.closeAllConnections();if(server)await new Promise(resolve=>server.close(resolve));await db.pool.end();process.exit(0)});require('./src').start().then(value=>{server=value;process.stdout.write('BROWSER_ISSUER_PORT '+server.address().port+'\\n')}).catch(error=>{process.stderr.write(error.stack);process.exit(1)});`;
  issuerProcess = spawn(process.execPath, ['-e', issuerScript], { cwd: path.join(__dirname, '../..'), stdio: ['ignore', 'pipe', 'pipe'], env: {
    ...process.env, NODE_ENV: 'test', OAUTH_PROVIDER_PORT: '0', DATABASE_URL: database, OAUTH_ISSUER: logicalIssuer,
    OAUTH_SIGNING_KEY_FILE: signing, OAUTH_VERIFICATION_JWKS_FILE: '', OAUTH_EPHEMERAL_SIGNING_KEYS: 'false', OAUTH_REVOCATION_DEMO_MODE: 'false',
    OAUTH_MFA_KEY_FILE: mfaKey,
    COMPANY_REGISTRATION_ENABLED: 'true', COMPANY_ACTIVATION_ENABLED: 'true', COMPANY_CONSOLE_CLIENT_ID: 'web-app',
    AUTH_SERVICE_URL: credentialsBase, GRAFANA_CLIENT_SECRET: 'disposable-grafana', DEVPORTAL_CLIENT_SECRET: 'disposable-devportal',
    OAUTH_IDENTITY_AUTHORITY_URL: identityBase + '/internal/identity/authorization-state',
    OAUTH_POLICY_SOURCE_URL: policyBase,
    OAUTH_WEB_CLIENT_ID: 'web-app', OAUTH_WEB_CLIENT_SECRET_FILE: secret, OAUTH_WEB_REDIRECT_URIS: JSON.stringify([origin + '/auth/callback']), OAUTH_WEB_ALLOW_HTTP_LOOPBACK: 'true',
  } });
  for (const stream of [issuerProcess.stdout, issuerProcess.stderr]) stream.on('data', chunk => { issuerOutput = (issuerOutput + chunk).slice(-16000); });
  await waitReady(async () => {
    const match = /BROWSER_ISSUER_PORT (\d+)/.exec(issuerOutput); if (!match) return false;
    issuerBase = 'http://127.0.0.1:' + match[1]; return true;
  }, issuerProcess, () => issuerOutput);
  const identityDatabaseUrl = new URL(process.env.OAUTH_TEST_DATABASE_URL); identityDatabaseUrl.searchParams.set('options', `-c search_path=${identitySchema},public`);
  Object.assign(process.env, { NODE_ENV: 'test', DATABASE_URL: identityDatabaseUrl.toString(), OIDC_ISSUER: logicalIssuer,
    JWKS_URI: issuerBase + '/.well-known/jwks.json', OIDC_ACCESS_STATE_URL: issuerBase + '/oauth/access-state', IDENTITY_DEMO_MODE: 'false', POLICY_SERVICE_URL:policyBase });
  identityDb = require('../../../identity-service/src/db'); assert.equal(await identityDb.initDb(), true);
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/045_company_offboarding_receipts.sql'), 'utf8'));
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/046_company_offboarding_groups.sql'), 'utf8'));
  await identityDb.query(fs.readFileSync(path.join(__dirname, '../../../identity-service/migrations/047_company_offboarding_access.sql'), 'utf8'));
  process.env.OIDC_TENANT_STATE_URL=issuerBase+'/oauth/tenant-state';
  await require('../../../../../scripts/lib/tenant-ownership-fixture.cjs').installTenantFixture(identityDb,identitySchema,{userTenants:{[tenantBrowserUser]:browserTenant,[tenantDirectoryReader]:browserTenant,[tenantDirectoryCreator]:browserTenant}});
  for (const [username, actor] of actors) {
    await identityDb.write('INSERT INTO users(id,username,email,display_name) VALUES($1,$2,$3,$4)', [actor.userId, username, username + '@test.invalid', actor.name], 'fixture-bootstrap');
    await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [logicalIssuer, username + '-subject', actor.userId], 'fixture-bootstrap');
    for (const role of username === 'profile-editor' ? ['user-profile-editor'] : actor.roles) {
      await identityDb.write('INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,$2,$3)', [actor.userId, role, 'Explicit disposable fixture bootstrap'], 'fixture-bootstrap');
    }
  }
  identityServer = require('../../../identity-service/src').listen(Number(new URL(identityBase).port), '127.0.0.1'); await serverBase(identityServer);
  inventoryFixture=await require('../../../../../scripts/lib/device-inventory-fixture.cjs').deviceInventoryFixture(process.env.OAUTH_TEST_DATABASE_URL,identityBase);
  const policyUrl=new URL(process.env.OAUTH_TEST_DATABASE_URL); policyUrl.searchParams.set('options',`-c search_path=${policySchema},public`);
  Object.assign(process.env,{ DATABASE_URL:policyUrl.toString(),IDENTITY_SERVICE_URL:identityBase,LICENSE_DEMO_MODE:'false',OAUTH_PROVIDER_URL:issuerBase });
  policyDb=require('../../../policy-service/src/db/postgres');
  for (const migration of fs.readdirSync(path.join(__dirname,'../../../policy-service/src/db/migrations')).filter(name=>/^(00[134-9]|01[0-9]|02[0123456789])_.*\.sql$/.test(name)).sort()) await policyDb.query(fs.readFileSync(path.join(__dirname,'../../../policy-service/src/db/migrations',migration),'utf8'));
  policyServer=require('../../../policy-service/src').listen(Number(new URL(policyBase).port),'127.0.0.1'); await serverBase(policyServer);
  process.env.OAUTH_POLICY_SOURCE_URL=policyBase;
  process.env.DATABASE_URL=identityDatabaseUrl.toString();
  await bootstrapApplications({ isAvailable: () => true,pool: issuerDb },{ issuer: logicalIssuer,identityBase,signingKeyFile: signing,clients: ['web-app'],users: [...actors.values()].map(actor => actor.userId) });
  const authorityProxy = http.createServer(async (incoming, outgoing) => {
    if (!issuerEnabled) { outgoing.writeHead(503, { 'Content-Type': 'application/json' }); return outgoing.end('{}'); }
    const chunks = []; for await (const chunk of incoming) chunks.push(chunk);
    const response = await fetch(issuerBase + incoming.url, { method: incoming.method, headers: incoming.headers,
      ...(['GET', 'HEAD'].includes(incoming.method) ? {} : { body: Buffer.concat(chunks) }), redirect: 'manual' });
    outgoing.writeHead(response.status, Object.fromEntries(response.headers)); outgoing.end(Buffer.from(await response.arrayBuffer()));
  }).listen(0, '127.0.0.1');
  credentialServer.authorityProxy = authorityProxy;
  const internal = await serverBase(authorityProxy);
  quickReceiver = http.createServer(async (incoming, outgoing) => {
    outgoing.setHeader('Content-Type', 'application/json');
    if (incoming.url === '/health') return outgoing.end('{"status":"healthy"}');
    if (incoming.url === '/forbidden-service-token') { quickCredentialFallbacks++; outgoing.statusCode = 500; return outgoing.end('{}'); }
    const state = await fetch(issuerBase + '/oauth/access-state', { headers: { Authorization: incoming.headers.authorization || '' } });
    if (state.status !== 200 || !(await state.json()).active) { outgoing.statusCode = 401; return outgoing.end('{}'); }
    const chunks = []; for await (const chunk of incoming) chunks.push(chunk); const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
    quickReceipts.push({ path: incoming.url, authorization: incoming.headers.authorization, operationId: incoming.headers['x-od-operation-id'] });
    if (incoming.url === '/api/computers/join' && quickGate) { const gate = quickGate; quickGate = null; gate.entered(); await gate.resume; }
    if (incoming.url === '/api/service-accounts' && incoming.method === 'GET') return outgoing.end(JSON.stringify({ accounts: [{ clientId: 'fixture-app', name: 'Fixture app', status: 'active', spn: 'app/fixture', permissions: [] }] }));
    if (incoming.url === '/api/service-accounts') { outgoing.statusCode = 201; return outgoing.end(JSON.stringify({ success: true, clientId: body.clientId })); }
    outgoing.end(JSON.stringify({ success: true, dn: 'CN=Fixture,DC=test,DC=invalid' }));
  }).listen(0, '127.0.0.1'); const quickReceiverBase = await serverBase(quickReceiver); let quickOutput = '';
  quickProcess = spawn(process.execPath, ['-e', `const app=require('./src');const server=app.listen(0,'127.0.0.1',()=>process.stdout.write('QA_PORT '+server.address().port+'\\n'));process.on('SIGTERM',()=>{server.closeAllConnections();server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),5000).unref();});`], {
    cwd: path.resolve(__dirname, '../../../../platform/quick-actions'), stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env,
      OIDC_ISSUER: logicalIssuer, JWKS_URI: issuerBase + '/.well-known/jwks.json', OIDC_ACCESS_STATE_URL: issuerBase + '/oauth/access-state',
      AUTH_SERVICE_URL: quickReceiverBase, SAMBA_SERVICE_URL: quickReceiverBase, KERBEROS_SERVICE_URL: quickReceiverBase, DIRECTORY_SERVICE_URL: quickReceiverBase,
      DEVICE_SERVICE_URL: quickReceiverBase, POLICY_SERVICE_URL: quickReceiverBase, PIM_SERVICE_URL: quickReceiverBase, MDM_SERVICE_URL: quickReceiverBase, APP_STORE_SERVICE_URL: quickReceiverBase,
      REDIS_URL: 'redis://127.0.0.1:1', QA_CLIENT_SECRET: 'must-not-be-used', TOKEN_ENDPOINT: quickReceiverBase + '/forbidden-service-token' },
  });
  for (const stream of [quickProcess.stdout, quickProcess.stderr]) stream.on('data', chunk => { quickOutput = (quickOutput + chunk).slice(-16000); });
  await waitReady(async () => { const match = /QA_PORT (\d+)/.exec(quickOutput); if (!match) return false; quickBase = 'http://127.0.0.1:' + match[1]; return true; }, quickProcess, () => quickOutput);
  const relativeBuild = '.next-browser-auth-' + randomUUID(); buildDirectory = path.join(frontend, relativeBuild);
  const relativeTsconfig = '.next-browser-config-' + randomUUID() + '.json'; testTsconfig = path.join(frontend, relativeTsconfig);
  const tsconfig = JSON.parse(fs.readFileSync(path.join(frontend, 'tsconfig.json'), 'utf8'));
  tsconfig.compilerOptions.baseUrl = frontend;
  tsconfig.include = [path.join(frontend, 'next-env.d.ts'), path.join(frontend, 'src/**/*.ts'), path.join(frontend, 'src/**/*.tsx')];
  tsconfig.exclude = [path.join(frontend, 'node_modules')];
  fs.mkdirSync(path.dirname(testTsconfig), { recursive: true }); fs.writeFileSync(testTsconfig, JSON.stringify(tsconfig), { mode: 0o600 });
  const nextEnvironment = { ...process.env, NODE_ENV: 'production', NEXT_TELEMETRY_DISABLED: '1', NEXT_DIST_DIR: relativeBuild, NEXT_TSCONFIG_PATH: relativeTsconfig,
      BROWSER_AUTH_ORIGIN: origin, BROWSER_AUTH_ISSUER: logicalIssuer, BROWSER_AUTH_PUBLIC_URL: issuerBase, BROWSER_AUTH_INTERNAL_URL: internal,
      BROWSER_AUTH_CLIENT_ID: 'web-app', BROWSER_AUTH_KEY_FILE: cookieKey, BROWSER_AUTH_CLIENT_SECRET_FILE: secret, BROWSER_AUTH_ALLOW_HTTP_LOOPBACK: 'true',
      IDENTITY_SERVICE_URL: identityBase, DEVICE_SERVICE_URL:inventoryFixture.base, API_BACKEND_URL: credentialsBase, QUICK_ACTIONS_URL: quickBase, OAUTH_PROVIDER_URL: issuerBase, POLICY_SERVICE_URL:policyBase,
    };
  nextProcess = spawn(process.execPath, [webRequire.resolve('next/dist/bin/next'), 'build'], { cwd: frontend, stdio: ['ignore', 'pipe', 'pipe'], env: nextEnvironment });
  for (const stream of [nextProcess.stdout, nextProcess.stderr]) stream.on('data', chunk => { nextOutput = (nextOutput + chunk).slice(-16000); });
  const [buildStatus, buildSignal] = await once(nextProcess, 'exit');
  assert.equal(buildSignal, null, nextOutput); assert.equal(buildStatus, 0, nextOutput);
  process.stdout.write('Frontend production build completed with exit 0:\n' + nextOutput + '\n'); nextOutput = '';
  nextProcess = spawn(process.execPath, [webRequire.resolve('next/dist/bin/next'), 'start', '-H', '127.0.0.1', '-p', new URL(origin).port], {
    cwd: frontend, stdio: ['ignore', 'pipe', 'pipe'], env: nextEnvironment });
  for (const stream of [nextProcess.stdout, nextProcess.stderr]) stream.on('data', chunk => { nextOutput = (nextOutput + chunk).slice(-16000); });
  await waitReady(async () => (await fetch(origin + '/api/auth/oidc/session', { signal: AbortSignal.timeout(15000) })).status === 405, nextProcess, () => nextOutput);
  const { chromium } = webRequire('@playwright/test');
  const executablePath = process.env.PLAYWRIGHT_EXECUTABLE_PATH || (process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : undefined);
  browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}), args: ['--no-sandbox'] });
  process.stdout.write('Actual Chrome ' + browser.version() + ' executable=' + (executablePath || 'Playwright Chromium') + ' runnerPid=' + process.pid + ' nextStartPid=' + nextProcess.pid + '\n');
}, { timeout: 180000 });

after(async () => {
  if(inventoryFixture)await inventoryFixture.close();
  if (browser) await browser.close(); await stop(nextProcess); await stop(quickProcess); await stop(issuerProcess);
  for (const server of [quickReceiver, credentialServer?.authorityProxy, credentialServer, identityServer,policyServer]) {
    if (server?.listening) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  }
  if (issuerDb) await issuerDb.end();
  if (identityDb) await identityDb.pool.end();
  if (policyDb) await policyDb.shutdown();
  await administration.query(`DROP SCHEMA IF EXISTS ${policySchema} CASCADE`);
  await administration.query(`DROP SCHEMA IF EXISTS ${identitySchema} CASCADE`);
  await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end();
  if (directory) fs.rmSync(directory, { recursive: true, force: true });
  if (buildDirectory) fs.rmSync(buildDirectory, { recursive: true, force: true });
  if (testTsconfig) fs.rmSync(testTsconfig, { force: true });
});

async function context({ realQuick = false, onboarded = true } = {}) {
  const value = await browser.newContext();
  if (onboarded) await value.addInitScript(() => localStorage.setItem('od_onboarded', 'true'));
  await value.route('**/api/**', async route => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/company-registration' || pathname.startsWith('/api/company-registration/')) return route.continue();
    if (realQuick && pathname.startsWith('/api/quick/')) return route.continue();
    if (pathname.startsWith('/api/licenses')) return route.continue();
    if (pathname === '/api/policies' || pathname.startsWith('/api/policies/')) return route.continue();
    if (pathname === '/api/blueprints' || pathname.startsWith('/api/blueprints/')) return route.continue();
    if (pathname === '/api/company-blueprints' || pathname.startsWith('/api/company-blueprints/')) return route.continue();
    if (pathname === '/api/company-blueprint-assignments' || pathname.startsWith('/api/company-blueprint-assignments/')) return route.continue();
    if (pathname === '/api/identity/company-blueprint-assignments') return route.continue();
    if (pathname === '/api/identity/company-blueprints') return route.continue();
    if (pathname.startsWith('/api/identity/automation/')) return route.continue();
    if (pathname === '/api/groups' || pathname.startsWith('/api/groups/')) return route.continue();
    if (pathname === '/api/ous' || pathname.startsWith('/api/ous/')) return route.continue();
    if (pathname === '/api/devices' || pathname.startsWith('/api/devices/')) return route.continue();
    if (pathname === '/api/devices/policy-commands' || /^\/api\/devices\/[A-Za-z0-9._~-]{1,255}\/commands\/[a-f0-9-]{36}\/cancel$/.test(pathname)) return route.continue();
    if (pathname.startsWith('/api/identity/membership-reviews/')) return route.continue();
    if (pathname.startsWith('/api/identity/organization/')) return route.continue();
    if (pathname === '/api/identity/company-registrations' || pathname.startsWith('/api/identity/company-registrations/')) return route.continue();
    if(pathname==='/api/identity/license-sources'||pathname.startsWith('/api/identity/license-sources/'))return route.continue();
    if (pathname === '/api/mfa' || pathname.startsWith('/api/mfa/') || pathname.startsWith('/api/clients') || pathname.startsWith('/api/auth/oidc/') || pathname === '/api/identity/access' || pathname === '/api/identity/organization' || pathname === '/api/identity/roles/catalog' || pathname.startsWith('/api/identity/authentication/') || pathname.startsWith('/api/identity/pim/') || pathname.startsWith('/api/identity/reviews/') || pathname === '/api/users' || pathname.startsWith('/api/users/')) return route.continue();
    if (pathname === '/api/quick/access') return route.fulfill({ json: { subject: 'reader-subject', permissions: [], delegablePermissions: [] } });
    return route.fulfill({ json: pathname === '/api/config/modules' ? {} : [] });
  });
  return value;
}

async function login(page, username = 'reader') {
  await page.goto(origin + '/login'); await page.getByRole('button', { name: 'Sign in with OpenDirectory' }).click();
  await page.waitForURL(url => url.origin === issuerBase && url.pathname === '/oauth/authorize');
  await page.locator('input[name=username]').fill(username); await page.locator('input[name=password]').fill('disposable-password');
  const otpCode = await nextOtp(username); if (otpCode) await page.locator('input[name=otpCode]').fill(otpCode);
  await page.getByRole('button', { name: 'Anmelden', exact: true }).click(); await page.waitForURL(origin + '/dashboard');
  await page.getByRole('button', { name: 'Benutzermenü' }).waitFor({ timeout: 60000 });
}

async function mediated(page, action = 'session') {
  return page.evaluate(async endpoint => {
    return navigator.locks.request('opendirectory-browser-session', async () => {
      const csrf = document.cookie.split(';').map(part => part.trim()).find(part => part.startsWith('od_csrf='))?.slice(8) || '';
      const response = await fetch('/api/auth/oidc/' + endpoint, { method: 'POST', headers: { 'X-OD-CSRF': csrf } });
      return { status: response.status, body: await response.json() };
    });
  }, action);
}

test('real browser login uses protected confidential client, verified user and no browser-stored credentials', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); await login(page); assert.ok(credentialAttempts > 0);
    const session = await mediated(page); assert.equal(session.status, 200); assert.deepEqual(session.body.user.roles, ['user']);
    assert.equal(session.body.user.id, 'reader-subject'); assert.equal(session.body.refresh_token, undefined);
    const stored = await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage }, cookie: document.cookie }));
    for (const name of ['access_token', 'refresh_token', 'auth_user']) assert.equal(stored.local[name], undefined);
    assert.deepEqual(stored.session, {}); assert.equal(stored.cookie.includes('od_session='), false);
    const cookie = (await activeContext.cookies()).find(value => value.name === 'od_session'); assert.equal(cookie.httpOnly, true); assert.equal(cookie.sameSite, 'Strict');
    const registered = (await issuerDb.query("SELECT grants,secret,secret_hash FROM oauth_clients WHERE id='web-app'")).rows[0];
    assert.deepEqual(registered.grants, ['authorization_code', 'refresh_token']); assert.equal(registered.secret, null);
    assert.equal(registered.secret_hash, createHash('sha256').update(fs.readFileSync(path.join(directory, 'client.secret'), 'utf8')).digest('hex'));
    const token = session.body.access_token;
    const response = await fetch(issuerBase + '/api/clients', { headers: { Authorization: 'Bearer ' + token } }); assert.equal(response.status, 403);
    await page.getByRole('button', { name: 'Benutzermenü' }).click(); await page.getByRole('button', { name: 'Abmelden', exact: true }).click();
    await page.waitForURL(origin + '/login');
    const state = await fetch(issuerBase + '/oauth/access-state', { headers: { Authorization: 'Bearer ' + token } });
    assert.equal(state.status, 200); assert.equal((await state.json()).active, false);
    assert.equal((await issuerDb.query('SELECT revoked_at FROM oauth_sessions WHERE id=$1', [JSON.parse(Buffer.from(token.split('.')[1], 'base64url')).sid])).rows[0].revoked_at instanceof Date, true);
  } finally { await activeContext.close(); }
});

test('forged auth_user cannot bypass the browser guard', { timeout: 60000 }, async () => {
  const activeContext = await context();
  try {
    await activeContext.addInitScript(() => { localStorage.setItem('auth_user', '{"name":"Forged Admin","role":"admin"}'); localStorage.setItem('access_token', 'forged'); });
    const page = await activeContext.newPage(); await page.goto(origin + '/dashboard'); await page.waitForURL(origin + '/login');
    assert.equal(await page.getByRole('button', { name: 'Benutzermenü' }).count(), 0);
  } finally { await activeContext.close(); }
});

test('refresh is coordinated across actual tabs and refresh/logout outage is never a successful login', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const first = await activeContext.newPage(); await login(first);
    const second = await activeContext.newPage();
    await Promise.all([first.reload(), second.goto(origin + '/dashboard')]);
    for (const page of [first, second]) await page.getByRole('button', { name: 'Benutzermenü' }).waitFor();
    assert.equal((await issuerDb.query("SELECT COUNT(*)::int AS count FROM oauth_sessions WHERE client_id='web-app' AND revoked_at IS NULL")).rows[0].count, 1);
    issuerEnabled = false;
    const failedLogout = await mediated(first, 'logout'); assert.equal(failedLogout.status, 503);
    await first.getByRole('button', { name: 'Benutzermenü' }).click(); await first.getByRole('button', { name: 'Abmelden', exact: true }).click();
    await first.getByText('Abmeldung nicht bestätigt. Bitte erneut versuchen.').waitFor(); assert.equal(first.url(), origin + '/dashboard');
    assert.ok((await activeContext.cookies()).find(value => value.name === 'od_session'));
    await first.reload(); await first.getByRole('status').filter({ hasText: 'Sitzungsprüfung derzeit nicht verfügbar.' }).waitFor();
    assert.equal(await first.getByRole('button', { name: 'Benutzermenü' }).count(), 0);
    issuerEnabled = true; await first.reload(); await first.getByRole('button', { name: 'Benutzermenü' }).waitFor();
  } finally { issuerEnabled = true; await activeContext.close(); }
});

test('an actual wrong-state callback neither creates a family nor a browser session', { timeout: 60000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); const families = (await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count;
    await page.goto(origin + '/api/auth/oidc/login');
    const response = await page.goto(origin + '/auth/callback?state=wrong&code=invalid'); assert.equal(response.status(), 401);
    assert.equal((await activeContext.cookies()).some(cookie => cookie.name === 'od_session'), false);
    assert.equal((await issuerDb.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count, families);
  } finally { await activeContext.close(); }
});

test('committed account disablement signs the browser out and reactivation cannot resurrect its old refresh cookie', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); await login(page); const session = await mediated(page);
    const savedCookies = await activeContext.cookies();
    await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [readerUser], 'fixture-disable');
    const state = await fetch(issuerBase + '/oauth/access-state', { headers: { Authorization: 'Bearer ' + session.body.access_token } });
    assert.equal((await state.json()).active, false);
    await page.reload(); await page.waitForURL(origin + '/login');
    assert.equal(await page.getByRole('button', { name: 'Benutzermenü' }).count(), 0);
    await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [readerUser], 'fixture-reactivate');
    await activeContext.addCookies(savedCookies); await page.goto(origin + '/dashboard'); await page.waitForURL(origin + '/login');
    await login(page); assert.equal((await mediated(page)).status, 200);
  } finally {
    await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [readerUser], 'fixture-cleanup'); await activeContext.close();
  }
});

test('actual tenant pause signs out only its browser and old cookies cannot revive after tenant re-enable',{timeout:120000},async()=>{
 const activeContext=await context();const otherContext=await context();const{enableTenant}=require('../../../../../scripts/lib/tenant-ownership-fixture.cjs');
 try{const page=await activeContext.newPage();await login(page,'tenant-browser-user');const session=await mediated(page);const cookies=await activeContext.cookies();const other=await otherContext.newPage();await login(other,'reader');
  await enableTenant(identityDb,identitySchema,browserTenant,false);assert.equal((await(await fetch(issuerBase+'/oauth/access-state',{headers:{Authorization:'Bearer '+session.body.access_token}})).json()).active,false);
  await page.reload();await page.waitForURL(origin+'/login');assert.equal((await mediated(other)).status,200);assert.equal(await page.getByRole('button',{name:'Benutzermenü'}).count(),0);
  await enableTenant(identityDb,identitySchema,browserTenant,true);await activeContext.addCookies(cookies);await page.goto(origin+'/dashboard');await page.waitForURL(origin+'/login');
  await login(page,'tenant-browser-user');assert.equal((await mediated(page)).status,200);await page.screenshot({path:path.join(os.tmpdir(),'od-tenant45-reauthenticated.png'),fullPage:false});
 }finally{if(!(await identityDb.query('SELECT enabled FROM identity_tenants WHERE id=$1',[browserTenant])).rows[0].enabled)await enableTenant(identityDb,identitySchema,browserTenant,true);await activeContext.close();await otherContext.close();}
});
async function openManagedUser(page) {
  await page.goto(origin + '/users');
  await page.getByRole('region',{name:'Kanonische Benutzerliste',exact:true}).getByLabel('Suche',{exact:true}).fill('managed');
  await page.getByRole('button', { name: 'Benutzer managed', exact: true }).click();
  await page.getByRole('heading', { name: 'Managed Employee', exact: true }).waitFor();
}

test('real directory pages and direct profile reads use only the original browser tenant, never a caller header or foreign UUID',{timeout:120000},async()=>{
 const activeContext=await context();try{
  const page=await activeContext.newPage();await login(page,'tenant-directory-reader');await page.goto(origin+'/users');await page.getByText('Separate Tenant Browser Owner',{exact:true}).first().waitFor();
  assert.equal(await page.getByText('Managed Employee',{exact:true}).count(),0);assert.equal(await page.getByText('Separate Tenant Directory Reader',{exact:true}).count()>0,true);
  const session=await mediated(page);const foreign=actors.get('managed').userId;const headers={Authorization:'Bearer '+session.body.access_token,'X-Tenant-ID':randomUUID()};
  const response=await fetch(identityBase+'/api/users',{headers});assert.equal(response.status,200);const result=await response.json();assert.equal(result.total,3);assert.deepEqual(new Set(result.users.map(user=>user.id)),new Set([tenantBrowserUser,tenantDirectoryReader,tenantDirectoryCreator]));
  assert.equal((await fetch(identityBase+'/api/users/'+foreign,{headers})).status,404);assert.equal((await fetch(identityBase+'/api/users?tenantId='+randomUUID(),{headers})).status,400);
 }finally{await activeContext.close();}
});

test('real browser creation uses the original non-default tenant with actual runtime ownership and immediate disabled readback',{timeout:120000},async()=>{
 const activeContext=await context();const foreignContext=await context();let createdId;
 try{
  const page=await activeContext.newPage();await login(page,'tenant-directory-creator');await page.goto(origin+'/users');await page.getByRole('button',{name:'Verzeichniseintrag erstellen',exact:true}).click();
  const username='tenant-created-'+randomUUID().slice(0,8);await page.getByLabel('Benutzername',{exact:true}).fill(username);await page.getByLabel('E-Mail',{exact:true}).fill(username+'@test.invalid');await page.getByLabel('Anzeigename',{exact:true}).fill('Separate Tenant Created Person');
  const completed=page.waitForResponse(response=>response.request().method()==='POST'&&new URL(response.url()).pathname==='/api/users');await page.getByRole('button',{name:'Speichern',exact:true}).click();assert.equal((await completed).status(),201);await page.getByRole('heading',{name:'Separate Tenant Created Person',exact:true}).waitFor();
  const stored=(await identityDb.query("SELECT account.id,account.enabled,ownership.tenant_id,ownership.reason FROM users account JOIN identity_tenant_ownership ownership ON ownership.resource_kind='user' AND ownership.resource_id=account.id WHERE account.username=$1",[username])).rows[0];createdId=stored.id;assert.equal(stored.enabled,false);assert.equal(stored.tenant_id,browserTenant);assert.equal(stored.reason,'Original-token-bound new-resource creation');
  const evidence=(await identityDb.query("SELECT actor FROM identity_tenant_events WHERE action='resource-created' AND details->>'resourceId'=$1",[createdId])).rows;assert.equal(evidence.length,1);assert.equal(evidence[0].actor.userId,tenantDirectoryCreator);
  const other=await foreignContext.newPage();await login(other,'viewer');const session=await mediated(other);assert.equal((await fetch(identityBase+'/api/users/'+createdId,{headers:{Authorization:'Bearer '+session.body.access_token}})).status,404);
 }finally{if(createdId)await identityDb.write('DELETE FROM users WHERE id=$1',[createdId],'Explicit browser fixture cleanup');await activeContext.close();await foreignContext.close();}
});

async function currentGroupTag(groupId){const row=(await identityDb.query('SELECT revision FROM groups WHERE id=$1',[groupId])).rows[0];assert.ok(row);return `"group-${groupId}-${row.revision}"`;}
test('real canonical group UI reads and creates owned empty groups without legacy samples, profile access or unsafe down-level mutations',{timeout:120000},async()=>{
 const activeContext=await context();const readerContext=await context();const foreignContext=await context();let createdId;
 try{const page=await activeContext.newPage();await page.route('**/api/identity/access',async route=>{const response=await route.fetch();const body=await response.json();delete body.directoryGroupMutationProtocol;await route.fulfill({response,json:body});});const calls=[];page.on('request',request=>{const path=new URL(request.url()).pathname;if(path.startsWith('/api/'))calls.push({path,method:request.method()});});await login(page,'membership-grantor');await page.goto(origin+'/usergroups');await page.getByRole('heading',{name:'Verzeichnisgruppen',exact:true}).waitFor();await page.getByRole('button',{name:'Gruppen',exact:true}).waitFor();await page.getByRole('button',{name:'Gruppe erstellen',exact:true}).click();
  const name='Actual browser group '+randomUUID().slice(0,8);await page.getByLabel('Gruppenname',{exact:true}).fill(name);await page.getByLabel('Gruppenbeschreibung',{exact:true}).fill('Actual owned canonical group without fabricated privileges');const pending=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/groups'&&response.request().method()==='POST');await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).click();const created=await pending;assert.equal(created.status(),201);const result=await created.json();createdId=result.id;assert.deepEqual(result.members,[]);await page.getByRole('heading',{name,exact:true}).waitFor();
  const ownership=(await identityDb.query("SELECT identity_tenant_id('group',$1) AS owner,identity_tenant_id('user',$2) AS actor_owner",[createdId,actors.get('membership-grantor').userId])).rows[0];assert.equal(ownership.owner,ownership.actor_owner);assert.notEqual(ownership.owner,null);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[createdId])).rows[0].count,0);
  for(const control of['Gruppenprofil bearbeiten','Mitglied verknüpfen','Gruppe löschen'])assert.equal(await page.getByRole('button',{name:control,exact:true}).isDisabled(),true);assert.equal(await page.getByText(/Schreibaktionen bleiben gesperrt/).count(),1);assert.equal(calls.some(call=>call.path.startsWith('/api/users')||call.path==='/api/auth/groups'||['PUT','DELETE'].includes(call.method)&&call.path.startsWith('/api/groups')),false);assert.equal(await page.getByText('Domain Admins',{exact:true}).count(),0);await page.screenshot({path:path.join(os.tmpdir(),'od-groups50-console.png'),fullPage:true});
  const reader=await readerContext.newPage();await login(reader,'viewer');await reader.goto(origin+'/usergroups');await reader.getByLabel('Gruppen suchen',{exact:true}).fill(name);await reader.getByRole('button',{name:'Gruppe '+name,exact:true}).click();await reader.getByRole('heading',{name,exact:true}).waitFor();for(const control of['Gruppe erstellen','Gruppenprofil bearbeiten','Mitglied verknüpfen','Gruppe löschen'])assert.equal(await reader.getByRole('button',{name:control,exact:true}).count(),0);
  const foreign=await foreignContext.newPage();await login(foreign,'tenant-directory-reader');await foreign.goto(origin+'/usergroups');await foreign.getByRole('button',{name:'Gruppen neu laden',exact:true}).waitFor({state:'visible'});await foreign.getByText('Keine kanonischen Gruppen vorhanden.',{exact:true}).waitFor();assert.equal(await foreign.getByText(name,{exact:true}).count(),0);const session=await mediated(foreign);assert.equal((await foreign.request.get(origin+'/api/groups/'+createdId,{headers:{Authorization:'Bearer '+session.body.access_token}})).status(),404);
 }finally{if(createdId)await identityDb.write('DELETE FROM groups WHERE id=$1',[createdId],'Explicit canonical group browser fixture cleanup');await activeContext.close();await readerContext.close();await foreignContext.close();}
});

test('real canonical group CRUD uses actual scoped receivers, exact versions and confirmed source removal without profile reads',{timeout:120000},async()=>{
 const activeContext=await context();const foreignContext=await context();let createdId;let foreignId;
 try{const page=await activeContext.newPage();const calls=[];page.on('request',request=>{const path=new URL(request.url()).pathname;if(path.startsWith('/api/'))calls.push({path,method:request.method()});});await login(page,'membership-grantor');await page.goto(origin+'/usergroups');await page.getByRole('button',{name:'Gruppe erstellen',exact:true}).click();const initial='CRUD group '+randomUUID().slice(0,8);await page.getByLabel('Gruppenname',{exact:true}).fill(initial);let pending=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/groups'&&response.request().method()==='POST');await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).click();let response=await pending;assert.equal(response.status(),201);createdId=(await response.json()).id;await page.getByRole('heading',{name:initial,exact:true}).waitFor();
  const route='/api/groups/'+createdId;const updated=initial+' renamed';await page.getByRole('button',{name:'Gruppenprofil bearbeiten',exact:true}).click();await page.getByLabel('Gruppenname',{exact:true}).fill(updated);await page.getByLabel('Gruppenbeschreibung',{exact:true}).fill('Verified conditional browser metadata');pending=page.waitForResponse(response=>new URL(response.url()).pathname===route&&response.request().method()==='PUT');await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).click();response=await pending;assert.equal(response.status(),200);assert.ok(response.headers().etag);await page.getByRole('heading',{name:updated,exact:true}).waitFor();
  const member=actors.get('managed').userId;await page.getByRole('button',{name:'Mitglied verknüpfen',exact:true}).click();await page.getByLabel('Kanonische Benutzer-ID',{exact:true}).fill(member);pending=page.waitForResponse(response=>new URL(response.url()).pathname===route+'/members'&&response.request().method()==='POST');await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).click();response=await pending;assert.equal(response.status(),200);await page.getByRole('button',{name:'Verknüpfung '+member+' entfernen',exact:true}).waitFor();const membershipOrigin=(await identityDb.query('SELECT * FROM identity_membership_origins WHERE group_id=$1',[createdId])).rows[0];assert.equal(membershipOrigin.user_id,member);assert.equal(membershipOrigin.created_by,actors.get('membership-grantor').userId);
  await page.getByRole('button',{name:'Gruppenprofil bearbeiten',exact:true}).click();await identityDb.write("UPDATE groups SET description='Independent newer profile' WHERE id=$1",[createdId],'Independent browser version-conflict fixture');pending=page.waitForResponse(response=>new URL(response.url()).pathname===route&&response.request().method()==='PUT');await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).click();assert.equal((await pending).status(),412);await page.getByRole('alert').getByText(/zwischenzeitlich geändert/).waitFor();assert.equal(await page.getByRole('button',{name:'Verbindlich speichern',exact:true}).isDisabled(),true);await page.getByRole('button',{name:'Abbrechen',exact:true}).click();await page.getByRole('button',{name:'Gruppe '+updated,exact:true}).click();await page.getByText('Independent newer profile',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Verknüpfung '+member+' entfernen',exact:true}).click();pending=page.waitForResponse(response=>new URL(response.url()).pathname===route+'/members/'+member&&response.request().method()==='DELETE');await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen',exact:true}).click();assert.equal((await pending).status(),200);await page.getByText('Keine Benutzer verknüpft.',{exact:true}).waitFor();assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_membership_origins WHERE membership_id=$1',[membershipOrigin.membership_id])).rows[0].count,1);
  const foreign=await foreignContext.newPage();await login(foreign,'tenant-directory-creator');const foreignSession=await mediated(foreign);const made=await fetch(identityBase+'/api/groups',{method:'POST',headers:{Authorization:'Bearer '+foreignSession.body.access_token,'Content-Type':'application/json'},body:JSON.stringify({name:'Separate owner group for actual browser denial'})});assert.equal(made.status,201);foreignId=(await made.json()).id;const session=await mediated(page);const headers={Authorization:'Bearer '+session.body.access_token,'If-Match':await currentGroupTag(foreignId)};assert.equal((await page.request.put(origin+'/api/groups/'+foreignId,{headers,data:{name:'No foreign overwrite'}})).status(),404);assert.equal((await page.request.post(origin+'/api/groups/'+foreignId+'/members',{headers,data:{userId:tenantBrowserUser}})).status(),404);assert.equal((await page.request.delete(origin+'/api/groups/'+foreignId,{headers})).status(),404);
  await page.screenshot({path:path.join(os.tmpdir(),'od-groups50-active-console.png'),fullPage:true});await page.getByRole('button',{name:'Gruppe löschen',exact:true}).click();pending=page.waitForResponse(response=>new URL(response.url()).pathname===route&&response.request().method()==='DELETE');await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen',exact:true}).click();assert.equal((await pending).status(),204);await page.getByText(/Kanonische Gruppe gelöscht/).waitFor();assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM groups WHERE id=$1',[createdId])).rows[0].count,0);assert.deepEqual((await identityDb.query('SELECT action FROM identity_directory_group_events WHERE group_id=$1 ORDER BY created_at',[createdId])).rows.map(row=>row.action),['update','member-add','member-remove','delete']);assert.equal(calls.some(call=>call.path==='/api/auth/groups'||call.path.startsWith('/api/users')),false);
 }finally{for(const identity of[createdId,foreignId])if(identity)await identityDb.write('DELETE FROM groups WHERE id=$1',[identity],'Explicit group CRUD browser fixture cleanup');await activeContext.close();await foreignContext.close();}
});

test('a real directory reader sees only canonical profiles and cannot turn UI knowledge into status-write permission', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); await login(page, 'viewer'); await openManagedUser(page);
    for (const name of ['Profil bearbeiten', 'Konto sperren', 'Sicherheitsreset', 'Eintrag löschen', 'Verzeichniseintrag erstellen']) assert.equal(await page.getByRole('button', { name, exact: true }).count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Reset Password' }).count(), 0);
    const session = await mediated(page); const target = actors.get('managed').userId;
    const record = await page.request.get(origin + '/api/users/' + target, { headers: { Authorization: 'Bearer ' + session.body.access_token } });
    assert.equal(record.status(), 200);
    const denied = await page.request.put(origin + '/api/users/' + target, { headers: { Authorization: 'Bearer ' + session.body.access_token, 'If-Match': record.headers().etag }, data: { enabled: false } });
    assert.equal(denied.status(), 403);
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [target])).rows[0].enabled, true);
    assert.equal(legacyUserRequests, 0);
  } finally { await activeContext.close(); }
});

test('the real user console creates disabled canonical records, edits profiles with an ETag, and reserves deletion for its separate grant', { timeout: 120000 }, async () => {
  const activeContext = await context(); let createdId;
  try {
    const page = await activeContext.newPage(); await login(page, 'lifecycle'); await page.goto(origin + '/users');
    await page.getByRole('button', { name: 'Verzeichniseintrag erstellen' }).click();
    await page.getByLabel('Benutzername', { exact: true }).fill('console-created'); await page.getByLabel('E-Mail', { exact: true }).fill('console-created@test.invalid');
    await page.getByLabel('Anzeigename', { exact: true }).fill('Console Created');
    await page.getByRole('button', { name: 'Speichern', exact: true }).click();
    await page.getByRole('heading', { name: 'Console Created', exact: true }).waitFor();
    const stored = (await identityDb.query("SELECT id,enabled FROM users WHERE username='console-created'")).rows;
    assert.equal(stored.length, 1); assert.equal(stored[0].enabled, false); createdId = stored[0].id;
    assert.equal(await page.getByRole('button', { name: 'Eintrag löschen', exact: true }).count(), 0);
    const writes = [];
    page.on('request', request => { if (request.method() === 'PUT' && new URL(request.url()).pathname === '/api/users/' + createdId) writes.push(request); });
    await page.getByRole('button', { name: 'Profil bearbeiten', exact: true }).click(); await page.getByLabel('Position', { exact: true }).fill('Profile from real browser');
    await page.getByRole('button', { name: 'Speichern', exact: true }).click(); await page.getByText('Profile from real browser', { exact: true }).waitFor();
    assert.equal(writes.length, 1); assert.ok(writes[0].headers()['if-match']); assert.equal(writes[0].postDataJSON().enabled, undefined);
    const audit = (await identityDb.query("SELECT actor,action FROM identity_user_record_audit WHERE user_id=$1 AND action='update'", [createdId])).rows;
    assert.deepEqual(audit, [{ actor: 'lifecycle-subject', action: 'update' }]);
    await page.getByRole('region',{ name:'Kanonische Benutzerliste' }).getByLabel('Suche',{ exact:true }).fill('console-created');
    await page.getByRole('button', { name: 'Benutzer console-created', exact: true }).waitFor();
    await page.screenshot({ path: path.join(os.tmpdir(), 'od-users-console.png'), fullPage: true });
    assert.equal(legacyUserRequests, 0);
  } finally {
    await activeContext.close();
    if (createdId) await identityDb.write('DELETE FROM users WHERE id=$1', [createdId], 'fixture-cleanup');
  }
});

test('a lifecycle operator disables and reactivates through the real Next UI without reviving the victim browser session', { timeout: 120000 }, async () => {
  const operatorContext = await context(); const victimContext = await context(); const target = actors.get('managed').userId;
  try {
    const victim = await victimContext.newPage(); await login(victim, 'managed'); const previousCookies = await victimContext.cookies();
    const page = await operatorContext.newPage(); await login(page, 'lifecycle'); await openManagedUser(page);
    await page.getByRole('button', { name: 'Konto sperren', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    await page.getByRole('button', { name: 'Konto freigeben', exact: true }).waitFor();
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [target])).rows[0].enabled, false);
    await victim.reload(); await victim.waitForURL(origin + '/login');
    await page.getByRole('button', { name: 'Konto freigeben', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    await page.getByRole('button', { name: 'Konto sperren', exact: true }).waitFor();
    await victimContext.addCookies(previousCookies); await victim.goto(origin + '/dashboard'); await victim.waitForURL(origin + '/login');
    await login(victim, 'managed'); assert.equal((await mediated(victim)).status, 200); assert.equal(legacyUserRequests, 0);
  } finally {
    await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [target], 'fixture-cleanup'); await operatorContext.close(); await victimContext.close();
  }
});

test('a profile editor cannot use a stale UI form to overwrite a newer disablement', { timeout: 120000 }, async () => {
  const activeContext = await context(); const target = actors.get('managed').userId;
  try {
    const page = await activeContext.newPage(); await login(page, 'profile-editor'); await openManagedUser(page);
    assert.equal(await page.getByRole('button', { name: 'Konto sperren', exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Profil bearbeiten', exact: true }).click(); await page.getByLabel('Position', { exact: true }).fill('Stale browser edit');
    await identityDb.write('UPDATE users SET enabled=false WHERE id=$1', [target], 'independent-lifecycle-operator');
    const response = page.waitForResponse(response => response.request().method() === 'PUT' && new URL(response.url()).pathname === '/api/users/' + target);
    await page.getByRole('button', { name: 'Speichern', exact: true }).click(); assert.equal((await response).status(), 412);
    await page.getByRole('dialog').getByRole('alert').filter({ hasText: 'zwischenzeitlich geändert' }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Speichern', exact: true }).isDisabled(), true);
    const stored = (await identityDb.query('SELECT enabled,title FROM users WHERE id=$1', [target])).rows[0];
    assert.equal(stored.enabled, false); assert.notEqual(stored.title, 'Stale browser edit');
  } finally { await identityDb.write('UPDATE users SET enabled=true WHERE id=$1', [target], 'fixture-cleanup'); await activeContext.close(); }
});

test('a reset-only browser operator invalidates a known UUID without reading the user directory', { timeout: 120000 }, async () => {
  const activeContext = await context(); const target = actors.get('managed').userId;
  try {
    const page = await activeContext.newPage(); await login(page, 'session-operator'); const reads = [];
    page.on('request', request => { if (request.method() === 'GET' && new URL(request.url()).pathname.startsWith('/api/users')) reads.push(request.url()); });
    await page.goto(origin + '/users'); await page.getByLabel('Kanonische Benutzer-ID', { exact: true }).fill(target);
    const previous = (await identityDb.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0].authorization_revision;
    await page.getByRole('button', { name: 'Sicherheitsreset vorbereiten', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    await page.getByText('Sicherheitsreset bestätigt.', { exact: true }).waitFor();
    assert.deepEqual(reads, []); assert.notEqual((await identityDb.query('SELECT authorization_revision FROM users WHERE id=$1', [target])).rows[0].authorization_revision, previous);
    assert.equal(await page.getByRole('button', { name: 'Verzeichniseintrag erstellen' }).count(), 0);
  } finally { await activeContext.close(); }
});

test('an explicitly authorized administrator deletes through a confirmed, versioned browser action', { timeout: 120000 }, async () => {
  const activeContext = await context(); const target = randomUUID();
  await identityDb.write('INSERT INTO users(id,username,email,display_name,enabled) VALUES($1,$2,$3,$4,false)', [target, 'delete-me', 'delete-me@test.invalid', 'Deletion Candidate'], 'fixture');
  try {
    const page = await activeContext.newPage(); await login(page, 'administrator'); await page.goto(origin + '/users');
    await page.getByRole('region',{ name:'Kanonische Benutzerliste' }).getByLabel('Suche',{ exact:true }).fill('delete-me');
    await page.getByRole('button', { name: 'Benutzer delete-me', exact: true }).click(); await page.getByRole('button', { name: 'Eintrag löschen', exact: true }).click();
    const response = page.waitForResponse(response => response.request().method() === 'DELETE' && new URL(response.url()).pathname === '/api/users/' + target);
    await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click(); assert.equal((await response).status(), 204);
    assert.equal((await identityDb.query('SELECT id FROM users WHERE id=$1', [target])).rows.length, 0);
    assert.equal((await identityDb.query('SELECT user_id FROM identity_deleted_users WHERE user_id=$1', [target])).rows.length, 1);
    assert.equal((await identityDb.query("SELECT actor FROM identity_user_record_audit WHERE user_id=$1 AND action='delete'", [target])).rows[0].actor, 'administrator-subject');
    assert.equal(legacyUserRequests, 0);
  } finally { await activeContext.close(); }
});

test('a browser-held non-default tenant administrator cannot mutate a known foreign user through actual Next API routing',{timeout:120000},async()=>{
 const activeContext=await context();const target=actors.get('managed').userId;const before=(await identityDb.query('SELECT * FROM users WHERE id=$1',[target])).rows[0];
 try{const page=await activeContext.newPage();await login(page,'tenant-directory-creator');const session=await mediated(page);const statuses=await page.evaluate(async({route,version,token})=>{
  const result=[];for(const [method,path,body]of[['PUT',route,{title:'Foreign browser overwrite'}],['DELETE',route,undefined],['POST',route+'/authorization/invalidate',{}]]){
   const response=await fetch(path,{method,headers:{'Content-Type':'application/json','If-Match':version,Authorization:'Bearer '+token},...(body===undefined?{}:{body:JSON.stringify(body)})});result.push(response.status);
  }return result;
 },{route:'/api/users/'+target,version:'"user-'+target+'-'+before.record_revision+'"',token:session.body.access_token});assert.deepEqual(statuses,[404,404,404]);assert.deepEqual((await identityDb.query('SELECT * FROM users WHERE id=$1',[target])).rows[0],before);
 }finally{await activeContext.close();}
});

for(const action of['disable','delete'])test('own '+action+' through the real user console commits evidence and ends the current browser session',{timeout:120000},async()=>{
 const activeContext=await context();const name='user-self-'+action;const target=actors.get(name).userId;
 try{const page=await activeContext.newPage();await login(page,name);await page.goto(origin+'/users');await page.getByRole('region',{name:'Kanonische Benutzerliste'}).getByLabel('Suche',{exact:true}).fill(name);await page.getByRole('button',{name:'Benutzer '+name,exact:true}).click();
  await page.getByRole('button',{name:action==='disable'?'Konto sperren':'Eintrag löschen',exact:true}).click();await page.getByRole('alertdialog').getByText(/Dies ist dein eigener Eintrag/).waitFor();await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen',exact:true}).click();await page.waitForURL(origin+'/login');
  const stored=(await identityDb.query('SELECT enabled FROM users WHERE id=$1',[target])).rows;if(action==='delete')assert.equal(stored.length,0);else assert.equal(stored[0].enabled,false);
  const evidence=(await identityDb.query('SELECT action,actor FROM identity_directory_user_events WHERE user_id=$1',[target])).rows;assert.equal(evidence.length,1);assert.equal(evidence[0].action,action==='delete'?'delete':'update');assert.equal(evidence[0].actor.subject,name+'-subject');
 }finally{if(action==='disable')await identityDb.write('UPDATE users SET enabled=true WHERE id=$1',[target],'Explicit own-browser fixture restoration');await activeContext.close();}
});

test('a self-reset through the narrow browser form immediately returns the actor to login', { timeout: 120000 }, async () => {
  const activeContext = await context(); const target = actors.get('session-operator').userId;
  try {
    const page = await activeContext.newPage(); await login(page, 'session-operator'); await page.goto(origin + '/users');
    await page.getByLabel('Kanonische Benutzer-ID', { exact: true }).fill(target); await page.getByRole('button', { name: 'Sicherheitsreset vorbereiten', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    await page.waitForURL(origin + '/login'); assert.equal(await page.getByRole('button', { name: 'Benutzermenü' }).count(), 0);
  } finally { await activeContext.close(); }
});

test('global user search obeys canonical read permission without a legacy LLDAP fallback', { timeout: 120000 }, async () => {
  for (const username of ['reader', 'viewer']) {
    const activeContext = await context();
    try {
      const page = await activeContext.newPage(); await login(page, username); const userReads = [];
      page.on('request', request => { if (new URL(request.url()).pathname === '/api/users') userReads.push(request.url()); });
      await page.getByRole('button', { name: 'Search... ⌘K' }).click();
      const capability = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/access');
      await page.getByPlaceholder('Suche nach Seiten, Nutzern, Geräten...', { exact: true }).fill('Managed'); await capability;
      if (username === 'reader') { await page.getByText(/Keine Ergebnisse für/).waitFor(); assert.deepEqual(userReads, []); assert.equal(await page.getByText('Managed Employee', { exact: true }).count(), 0); }
      else { await page.getByText('Managed Employee', { exact: true }).waitFor(); assert.ok(userReads.some(url => new URL(url).searchParams.get('search') === 'Managed')); }
      assert.equal(legacyUserRequests, 0);
    } finally { await activeContext.close(); }
  }
});

test('the real role console grants and revokes canonical license authority without directory-profile reads or credential-role trust', { timeout: 120000 }, async () => {
  const operatorContext = await context(); const oldVictimContext = await context(); const newVictimContext = await context(); const target = actors.get('viewer').userId;
  try {
    const operator = await operatorContext.newPage(); const victim = await oldVictimContext.newPage(); await login(operator, 'role-operator'); await login(victim, 'viewer');
    const userReads = []; operator.on('request', request => { if (new URL(request.url()).pathname === '/api/users') userReads.push(request.url()); });
    await operator.goto(origin + '/roles'); await operator.getByLabel('Verzeichnis-ID', { exact: true }).fill(target);
    await operator.getByRole('button', { name: 'Zuweisungen laden', exact: true }).click(); await operator.getByRole('heading', { name: 'Rollenzuweisungen für ' + target, exact: true }).waitFor();
    await operator.getByLabel('Rolle', { exact: true }).selectOption('license-manager'); await operator.getByLabel('Begründung', { exact: true }).fill('Reviewed real browser license delegation');
    const receipt = operator.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === `/api/users/${target}/roles`);
    await operator.getByRole('button', { name: 'Rollenzuweisung prüfen', exact: true }).click(); await operator.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const granted = await receipt; assert.equal(granted.status(), 201); const assignment = await granted.json(); assert.equal(assignment.role, 'license-manager');
    await operator.getByRole('button', { name: 'Widerrufen: license-manager', exact: true }).waitFor();
    assert.equal((await mediated(victim)).status, 401);
    const freshVictim = await newVictimContext.newPage(); await login(freshVictim, 'viewer');
    assert.deepEqual(JSON.parse(Buffer.from((await mediated(freshVictim)).body.access_token.split('.')[1], 'base64url')).roles, ['directory-reader', 'license-manager']);
    await operator.screenshot({ path: path.join(os.tmpdir(), 'od-roles-console.png'), fullPage: false });
    const revoked = operator.waitForResponse(response => response.request().method() === 'DELETE' && new URL(response.url()).pathname === `/api/users/${target}/roles/${assignment.id}`);
    await operator.getByRole('button', { name: 'Widerrufen: license-manager', exact: true }).click(); await operator.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    assert.equal((await revoked).status(), 200); assert.equal((await mediated(freshVictim)).status, 401); assert.deepEqual(userReads, []);
    const audit = (await identityDb.query('SELECT actor FROM identity_role_audit WHERE assignment_id=$1 ORDER BY created_at DESC LIMIT 1', [assignment.id])).rows[0];
    assert.equal(JSON.parse(audit.actor).userId, actors.get('role-operator').userId); assert.equal(legacyUserRequests, 0);
  } finally { await Promise.all([operatorContext.close(), oldVictimContext.close(), newVictimContext.close()]); }
});

test('ordinary browsers and canonical self-targets cannot use role-console navigation to escalate', { timeout: 120000 }, async () => {
  for (const username of ['reader', 'role-operator']) {
    const activeContext = await context();
    try {
      const page = await activeContext.newPage(); await login(page, username); await page.goto(origin + '/roles');
      if (username === 'reader') {
        await page.getByText('Keine Berechtigung zum Lesen der Rollenzuweisungen.', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Verzeichnis-ID', { exact: true }).count(), 0);
      } else {
        await page.getByLabel('Verzeichnis-ID', { exact: true }).fill(actors.get(username).userId); await page.getByRole('button', { name: 'Zuweisungen laden', exact: true }).click();
        await page.getByText('Eigene Rollen können hier nicht selbst administriert werden.', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Begründung', { exact: true }).count(), 0);
      }
      assert.equal(await page.getByRole('button', { name: 'Rollenzuweisung prüfen', exact: true }).count(), 0);
    } finally { await activeContext.close(); }
  }
});

test('real MFA enrollment, independent PIM review, factor-backed activation and revocation use canonical roles and force owner reauthentication', { timeout: 150000 }, async () => {
  const managerContext = await context(); const reviewerContext = await context(); const ownerContext = await context(); const target = actors.get('mfa-owner').userId;
  try {
    const manager = await managerContext.newPage(); const reviewer = await reviewerContext.newPage(); const owner = await ownerContext.newPage();
    const legacyReads = []; for (const page of [manager, reviewer, owner]) page.on('request', request => { const route = new URL(request.url()).pathname; if (route.startsWith('/api/pim') || route === '/api/users') legacyReads.push(route); });
    await login(manager, 'pim-manager'); await login(reviewer, 'pim-reviewer'); await login(owner, 'mfa-owner');
    const weaker = (await mediated(owner)).body.access_token;
    await owner.goto(origin + '/mfa'); await owner.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor();
    await owner.getByLabel('Eigener Benutzername', { exact: true }).fill('mfa-owner'); await owner.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const setupReceipt = owner.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll');
    await owner.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const setupResponse = await setupReceipt; assert.equal(setupResponse.status(), 200);
    const setup = await setupResponse.json(); await owner.getByText(setup.secret, { exact: true }).waitFor();
    const setupCounter = Math.floor(Date.now() / 30000) - 1;
    await owner.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(setup.secret, setupCounter));
    const confirmReceipt = owner.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm');
    await owner.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await confirmReceipt).status(), 200);
    await owner.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); assert.equal(await owner.getByText(setup.secret, { exact: true }).count(), 0);
    assert.equal((await owner.request.get(issuerBase + '/oauth/userinfo', { headers: { Authorization: 'Bearer ' + weaker } })).status(), 401);
    await owner.screenshot({ path: path.join(os.tmpdir(), 'od-verified-mfa.png'), fullPage: false });
    rememberFactor('mfa-owner', setup.secret, setupCounter); await login(owner, 'mfa-owner');
    const mfaClaims = JSON.parse(Buffer.from((await mediated(owner)).body.access_token.split('.')[1], 'base64url')); assert.deepEqual(mfaClaims.amr, ['pwd', 'otp']); assert.equal(mfaClaims.mfa_authorization.userId, target);
    await manager.goto(origin + '/pim'); await manager.getByLabel('Verzeichnis-ID', { exact: true }).fill(target); await manager.getByRole('button', { name: 'Berechtigungen laden', exact: true }).click();
    await manager.getByLabel('Berechtigte Rolle', { exact: true }).selectOption('license-manager'); await manager.getByLabel('Verwaltungsbegründung', { exact: true }).fill('Reviewed real browser PIM eligibility');
    const eligibleReceipt = manager.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/identity/pim/eligibilities');
    await manager.getByRole('button', { name: 'Berechtigung prüfen', exact: true }).click(); await manager.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const eligibleResponse = await eligibleReceipt; assert.equal(eligibleResponse.status(), 201); const eligibility = await eligibleResponse.json();
    assert.deepEqual(JSON.parse(Buffer.from((await mediated(owner)).body.access_token.split('.')[1], 'base64url')).roles, ['user']);
    await owner.goto(origin + '/pim'); await owner.getByLabel('Eigene Berechtigung', { exact: true }).selectOption(eligibility.id); await owner.getByLabel('Aktivierungsbegründung', { exact: true }).fill('Temporary real browser license operation');
    const pendingReceipt = owner.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/identity/pim/requests');
    await owner.getByRole('button', { name: 'Aktivierung beantragen', exact: true }).click(); await owner.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const pendingResponse = await pendingReceipt; assert.equal(pendingResponse.status(), 200); const pending = await pendingResponse.json(); assert.equal(pending.status, 'pending');
    await reviewer.goto(origin + '/pim'); const queue = reviewer.getByRole('listitem', { name: 'Antrag ' + pending.id, exact: true });
    await queue.getByRole('button', { name: 'Genehmigen', exact: true }).click(); const approvalReceipt = reviewer.waitForResponse(response => new URL(response.url()).pathname.endsWith('/' + pending.id + '/approve'));
    await reviewer.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click(); assert.equal((await approvalReceipt).status(), 200);
    assert.deepEqual(JSON.parse(Buffer.from((await mediated(owner)).body.access_token.split('.')[1], 'base64url')).roles, ['user']);
    await owner.getByRole('button', { name: 'Neu laden', exact: true }).click(); await owner.getByRole('button', { name: 'Jetzt aktivieren', exact: true }).click();
    const activeReceipt = owner.waitForResponse(response => new URL(response.url()).pathname.endsWith('/' + pending.id + '/activate'));
    await owner.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click(); const active = await activeReceipt; assert.equal(active.status(), 200); assert.equal((await active.json()).status, 'active');
    await owner.waitForURL(origin + '/login'); await login(owner, 'mfa-owner'); assert.deepEqual(JSON.parse(Buffer.from((await mediated(owner)).body.access_token.split('.')[1], 'base64url')).roles, ['license-manager', 'user']);
    await reviewer.getByRole('button', { name: 'Neu laden', exact: true }).click(); await queue.getByRole('button', { name: 'Aktivierung widerrufen', exact: true }).waitFor(); await queue.scrollIntoViewIfNeeded();
    await reviewer.screenshot({ path: path.join(os.tmpdir(), 'od-pim-console.png'), fullPage: false });
    await queue.getByRole('button', { name: 'Aktivierung widerrufen', exact: true }).click(); const revokedReceipt = reviewer.waitForResponse(response => new URL(response.url()).pathname.endsWith('/' + pending.id + '/revoke'));
    await reviewer.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click(); assert.equal((await revokedReceipt).status(), 200); assert.equal((await mediated(owner)).status, 401);
    const audit = (await identityDb.query('SELECT actor FROM identity_pim_audit WHERE entity_id=$1 ORDER BY created_at DESC LIMIT 1', [pending.id])).rows[0]; assert.equal(JSON.parse(audit.actor).userId, actors.get('pim-reviewer').userId);
    assert.deepEqual(legacyReads, []); assert.equal(legacyUserRequests, 0);
  } finally { await Promise.all([managerContext.close(), reviewerContext.close(), ownerContext.close()]); }
});

test('a signed-out browser recovers only its real MFA factor with password and one backup, receives no session and must sign in normally', { timeout: 150000 }, async () => {
  const ownerContext = await context(); const publicContext = await context(); const username = 'recovery-owner';
  try {
    const owner = await ownerContext.newPage(); await login(owner, username); await owner.goto(origin + '/mfa');
    await owner.getByLabel('Eigener Benutzername', { exact: true }).fill(username); await owner.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const enrollment = owner.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll');
    await owner.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const original = await (await enrollment).json();
    const firstCounter = Math.floor(Date.now() / 30000) - 1;
    await owner.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(original.secret, firstCounter));
    const activated = owner.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm');
    await owner.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await activated).status(), 200);
    rememberFactor(username, original.secret, firstCounter); await login(owner, username); const previous = (await mediated(owner)).body.access_token;
    await owner.goto(origin + '/mfa'); await owner.getByText('Verfügbare Notfallcodes: 0', { exact: true }).waitFor();
    await owner.getByRole('button', { name: 'Notfallcodes vorbereiten', exact: true }).click();
    await owner.getByLabel('Benutzername für Notfallcodes', { exact: true }).fill(username); await owner.getByLabel('Passwort für Notfallcodes', { exact: true }).fill('disposable-password');
    await owner.getByLabel('Neuer Einmalcode für Notfallcodes', { exact: true }).fill(await nextOtp(username));
    const rotation = owner.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/mfa/recovery-codes');
    await owner.getByRole('button', { name: 'Bisherige Codes ersetzen und neue erzeugen', exact: true }).click(); const rotated = await rotation; assert.equal(rotated.status(), 200); const codes = (await rotated.json()).recoveryCodes;
    assert.equal(codes.length, 8); await owner.getByText(codes[0], { exact: true }).waitFor();
    const page = await publicContext.newPage(); const requests = []; page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/api/')) requests.push(request); });
    await page.goto(origin + '/login'); await page.getByRole('link', { name: 'Authenticator verloren? Mit Notfallcode wiederherstellen', exact: true }).click(); await page.waitForURL(origin + '/auth/mfa-recovery');
    await page.getByLabel('Eigener Benutzername', { exact: true }).fill(username); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); await page.getByLabel('Gespeicherter Notfallcode', { exact: true }).fill(codes[0]);
    const starting = page.waitForResponse(response => new URL(response.url()).pathname === '/api/auth/oidc/recovery/start');
    await page.getByRole('button', { name: 'Notfallcode verbrauchen und Faktor vorbereiten', exact: true }).click(); const response = await starting; assert.equal(response.status(), 200); const replacement = await response.json();
    await page.getByLabel('Neuer MFA-Schlüssel', { exact: true }).waitFor(); assert.notEqual(replacement.secret, original.secret);
    assert.equal((await owner.request.get(issuerBase + '/oauth/userinfo', { headers: { Authorization: 'Bearer ' + previous } })).status(), 200);
    const counter = Math.floor(Date.now() / 30000) - 1; await page.getByLabel('Einmalcode des neuen Authenticators', { exact: true }).fill(totp(replacement.secret, counter));
    const confirming = page.waitForResponse(result => new URL(result.url()).pathname === '/api/auth/oidc/recovery/confirm');
    await page.getByRole('button', { name: 'Neuen Faktor bestätigen', exact: true }).click(); const confirmed = await confirming; assert.equal(confirmed.status(), 200); assert.equal(confirmed.headers()['set-cookie'], undefined);
    await page.getByText(/Faktorwechsel bestätigt/).waitFor(); assert.equal(await page.getByText(replacement.secret, { exact: true }).count(), 0);
    assert.equal((await publicContext.cookies()).some(cookie => cookie.name.includes('od_session')), false);
    assert.equal(requests.some(request => new URL(request.url()).pathname === '/api/auth/oidc/session' || request.headers().authorization), false);
    const stored = await page.evaluate(() => [...Object.values(localStorage), ...Object.values(sessionStorage)].join('|'));
    for (const material of [...codes, replacement.secret, replacement.challenge]) assert.equal(stored.includes(material), false);
    await page.screenshot({ path: path.join(os.tmpdir(), 'od-mfa-recovery.png'), fullPage: false });
    assert.equal((await owner.request.get(issuerBase + '/oauth/userinfo', { headers: { Authorization: 'Bearer ' + previous } })).status(), 401); assert.equal((await mediated(owner)).status, 401);
    rememberFactor(username, replacement.secret, counter); await login(page, username); const claims = JSON.parse(Buffer.from((await mediated(page)).body.access_token.split('.')[1], 'base64url'));
    assert.deepEqual(claims.roles, ['user']); assert.deepEqual(claims.amr, ['pwd', 'otp']); assert.equal(claims.identity_authorization.userId, actors.get(username).userId);
    await page.goto(origin + '/mfa'); await page.getByText('Verfügbare Notfallcodes: 0', { exact: true }).waitFor();
  } finally { await ownerContext.close(); await publicContext.close(); }
});

test('a real PIM approver cannot approve their own canonical activation and eligibility managers cannot self-authorize', { timeout: 120000 }, async () => {
  const managerContext = await context(); const reviewerContext = await context();
  try {
    const manager = await managerContext.newPage(); const reviewer = await reviewerContext.newPage(); await login(manager, 'pim-manager'); await login(reviewer, 'pim-reviewer');
    const managerSession = await mediated(manager); const reviewerSession = await mediated(reviewer); const target = actors.get('pim-reviewer').userId;
    const eligible = await manager.request.post(origin + '/api/identity/pim/eligibilities', { headers: { Authorization: 'Bearer ' + managerSession.body.access_token }, data: { userId: target, role: 'license-reader', maxDurationSeconds: 3600, validForSeconds: 86400, reason: 'Reviewed independent self-denial fixture' } }); assert.equal(eligible.status(), 201);
    const pending = await reviewer.request.post(origin + '/api/identity/pim/requests', { headers: { Authorization: 'Bearer ' + reviewerSession.body.access_token }, data: { id: randomUUID(), eligibilityId: (await eligible.json()).id, durationSeconds: 3600, reason: 'Must not approve own privileged request' } }); assert.equal(pending.status(), 200); const requestId = (await pending.json()).id;
    await reviewer.goto(origin + '/pim'); await reviewer.getByText('Keine eigene Genehmigung oder Ablehnung.', { exact: true }).waitFor(); assert.equal(await reviewer.getByRole('button', { name: 'Genehmigen', exact: true }).count(), 0);
    assert.equal((await reviewer.request.post(origin + `/api/identity/pim/requests/${requestId}/approve`, { headers: { Authorization: 'Bearer ' + reviewerSession.body.access_token }, data: {} })).status(), 403);
    await manager.goto(origin + '/pim'); await manager.getByLabel('Verzeichnis-ID', { exact: true }).fill(actors.get('pim-manager').userId); await manager.getByRole('button', { name: 'Berechtigungen laden', exact: true }).click(); await manager.getByText('Keine Selbstverwaltung eigener PIM-Berechtigungen.', { exact: true }).waitFor();
  } finally { await Promise.all([managerContext.close(), reviewerContext.close()]); }
});

test('the real application wizard confirms only a complete current delegated receipt', { timeout: 120000 }, async () => {
  const activeContext = await context({ realQuick: true });
  try {
    const page = await activeContext.newPage(); await login(page, 'app-operator'); await page.goto(origin + '/serviceprincipals');
    await page.getByTitle('New Service Principal', { exact: true }).click(); await page.getByPlaceholder('e.g. inventory-service', { exact: true }).fill('browser-delegated-app');
    const created = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/quick/service-principals');
    await page.getByRole('button', { name: 'Create →', exact: true }).click(); const receipt = await created; assert.equal(receipt.status(), 201);
    await page.getByRole('heading', { name: 'Service Principal Created', exact: true }).waitFor();
    const operationId = receipt.headers()['x-od-operation-id']; const own = quickReceipts.filter(call => call.operationId === operationId); assert.equal(own.length, 3);
    assert.ok(own.every(call => JSON.parse(Buffer.from(call.authorization.slice(7).split('.')[1], 'base64url')).sub === 'app-operator-subject')); assert.equal(quickCredentialFallbacks, 0);
  } finally { await activeContext.close(); }
});
test('a real partial orchestration after authorization loss is not a created application and cannot be blindly retried', { timeout: 120000 }, async () => {
  const activeContext = await context({ realQuick: true }); let release;
  try {
    const page = await activeContext.newPage(); await login(page, 'app-operator'); await page.goto(origin + '/serviceprincipals'); await page.getByTitle('New Service Principal', { exact: true }).click();
    await page.getByPlaceholder('e.g. inventory-service', { exact: true }).fill('browser-partial-app');
    let entered; const arrival = new Promise(resolve => { entered = resolve; }); const resume = new Promise(resolve => { release = resolve; }); quickGate = { entered, resume };
    const posts = []; page.on('request', request => { if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/quick/service-principals') posts.push(request); });
    const result = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/quick/service-principals'); await page.getByRole('button', { name: 'Create →', exact: true }).click();
    let timer; try { await Promise.race([arrival, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Delegated browser step not reached')), 10000); })]); } finally { clearTimeout(timer); }
    await identityDb.write('UPDATE users SET authorization_revision=authorization_revision+1 WHERE id=$1', [actors.get('app-operator').userId], 'fixture-security-reset'); release();
    assert.equal((await result).status(), 207); await page.getByRole('alert').filter({ hasText: 'Vorgang nicht vollständig bestätigt' }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'Service Principal Created', exact: true }).count(), 0); assert.equal(await page.getByRole('button', { name: 'Create →', exact: true }).isDisabled(), true);
    assert.equal(posts.length, 1); assert.equal(quickCredentialFallbacks, 0); await page.screenshot({ path: path.join(os.tmpdir(), 'od-quick-partial.png'), fullPage: false });
  } finally { if (release) release(); await activeContext.close(); }
});

async function applicationConsole(page, username = 'app-operator') {
  await login(page, username); await page.goto(origin + '/identity'); await page.getByRole('button', { name: 'OAuth2/OIDC', exact: true }).click();
  await page.getByRole('heading', { name: 'Anwendungsregistrierungen', exact: true }).waitFor();
}
async function issuerJson(route, { method = 'GET', token, body, headers = {} } = {}) {
  const response = await fetch(issuerBase + route, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
  return { status: response.status, body: response.status === 204 ? null : await response.json() };
}
test('the actual OAuth console registers, activates, rotates, disables and deletes the issuer client without readable stored secrets', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); await applicationConsole(page);
    await page.getByRole('button', { name: 'Anwendung registrieren', exact: true }).click();
    const name = 'Real canonical workload ' + randomUUID(); await page.getByLabel('Name', { exact: true }).fill(name); await page.getByLabel('Client-Typ', { exact: true }).selectOption('workload');
    const posts = []; page.on('request', request => { if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/clients') posts.push(request); });
    const created = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/clients');
    await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); assert.equal((await created).status(), 201);
    const oldSecret = await page.getByTestId('client-secret').textContent(); assert.match(oldSecret, /^[A-Za-z0-9_-]{43}$/);
    const stored = (await issuerDb.query('SELECT * FROM oauth_clients WHERE name=$1', [name])).rows[0]; assert.equal(stored.enabled, false); assert.equal(stored.secret, null);
    assert.equal(stored.secret_hash, createHash('sha256').update(oldSecret).digest('hex')); assert.equal(posts.length, 1);
    const mint = secret => issuerJson('/oauth/token', { method: 'POST', body: { grant_type: 'client_credentials', client_id: stored.id, client_secret: secret, scope: 'openid' } });
    assert.equal((await mint(oldSecret)).status, 401);
    await page.getByRole('button', { name: 'Zugangsdaten schließen', exact: true }).click(); const card = page.getByRole('article', { name, exact: true });
    await card.getByRole('button', { name: 'Aktivieren', exact: true }).click(); await page.getByRole('button', { name: 'Änderung bestätigen', exact: true }).click();
    await card.getByRole('button', { name: 'Deaktivieren', exact: true }).waitFor(); const issued = await mint(oldSecret); assert.equal(issued.status, 200);
    await card.getByRole('button', { name: 'Geheimnis ersetzen', exact: true }).click(); await page.getByRole('button', { name: 'Änderung bestätigen', exact: true }).click();
    const replacement = await page.getByTestId('client-secret').textContent(); assert.notEqual(replacement, oldSecret);
    assert.equal((await mint(oldSecret)).status, 401); const renewed = await mint(replacement); assert.equal(renewed.status, 200);
    assert.equal((await issuerJson('/oauth/access-state', { token: issued.body.access_token })).body.active, false);
    await page.getByRole('button', { name: 'Zugangsdaten schließen', exact: true }).click();
    await page.reload(); await page.getByRole('button', { name: 'OAuth2/OIDC', exact: true }).click(); await card.waitFor();
    assert.equal(await page.getByTestId('client-secret').count(), 0); assert.ok(!(await page.locator('body').innerText()).includes(replacement));
    await card.scrollIntoViewIfNeeded(); await page.screenshot({ path: path.join(os.tmpdir(), 'od-canonical-application.png'), fullPage: false });
    await card.getByRole('button', { name: 'Deaktivieren', exact: true }).click(); await page.getByRole('button', { name: 'Änderung bestätigen', exact: true }).click(); await card.getByRole('button', { name: 'Aktivieren', exact: true }).waitFor();
    assert.equal((await issuerJson('/oauth/access-state', { token: renewed.body.access_token })).body.active, false);
    await card.getByRole('button', { name: 'Registrierung löschen', exact: true }).click(); await page.getByRole('button', { name: 'Änderung bestätigen', exact: true }).click(); await card.waitFor({ state: 'detached' });
    const tombstone = (await issuerDb.query('SELECT * FROM oauth_clients WHERE id=$1', [stored.id])).rows[0]; assert.ok(tombstone.deleted_at instanceof Date); assert.equal(tombstone.secret, null);
    const audit = (await issuerDb.query('SELECT * FROM oauth_client_audit WHERE client_id=$1 ORDER BY id', [stored.id])).rows; assert.deepEqual(audit.map(row => row.action), ['created','updated','rotated','updated','deleted']);
    assert.ok(audit.every(row => row.actor_subject === 'app-operator-subject' && row.actor_user_id === actors.get('app-operator').userId)); assert.ok(!JSON.stringify(audit).includes(replacement));
  } finally { await activeContext.close(); }
});

test('a real application reader sees canonical records without profile access, mutation controls or secret readback', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); const requests = []; page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/api/')) requests.push(request); });
    await applicationConsole(page, 'app-reader'); await page.getByRole('article', { name: 'OpenDirectory Web', exact: true }).waitFor();
    for (const label of ['Anwendung registrieren','Konfiguration bearbeiten','Geheimnis ersetzen','Aktivieren','Registrierung löschen']) assert.equal(await page.getByRole('button', { name: label, exact: true }).count(), 0);
    const session = await mediated(page); assert.equal((await issuerJson('/api/clients', { token: session.body.access_token })).status, 200);
    assert.equal((await issuerJson('/api/clients', { method: 'POST', token: session.body.access_token, body: { name: 'Reader escalation', redirectUris: ['https://bad.test/callback'] } })).status, 403);
    assert.equal(requests.filter(request => new URL(request.url()).pathname === '/api/users').length, 0); assert.equal(requests.filter(request => request.method() !== 'GET' && new URL(request.url()).pathname.startsWith('/api/clients')).length, 0);
  } finally { await activeContext.close(); }
});

test('the real application editor cannot overwrite a concurrent issuer change with a stale form or automatic retry', { timeout: 120000 }, async () => {
  const activeContext = await context();
  try {
    const page = await activeContext.newPage(); await applicationConsole(page); const session = await mediated(page); const token = session.body.access_token;
    const name = 'Versioned browser app ' + randomUUID(); const created = await issuerJson('/api/clients', { method: 'POST', token, body: { name, redirectUris: ['https://versioned.test/callback'] } }); assert.equal(created.status, 201);
    await page.getByRole('button', { name: 'Register neu laden', exact: true }).click(); const card = page.getByRole('article', { name, exact: true }); await card.getByRole('button', { name: 'Konfiguration bearbeiten', exact: true }).click();
    await page.getByLabel('Name', { exact: true }).fill('Stale overwrite');
    const concurrent = await issuerJson('/api/clients/' + created.body.clientId, { method: 'PUT', token, headers: { 'If-Match': `"od-client:${created.body.clientId}:${created.body.version}"` }, body: { name: 'Newer confirmed name' } }); assert.equal(concurrent.status, 200);
    const attempts = []; page.on('request', request => { if (request.method() === 'PUT' && new URL(request.url()).pathname === '/api/clients/' + created.body.clientId) attempts.push(request); });
    await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); await page.getByRole('alert').filter({ hasText: 'Register inzwischen geändert' }).waitFor();
    assert.equal(await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).isDisabled(), true); assert.equal(attempts.length, 1);
    assert.equal((await issuerDb.query('SELECT name FROM oauth_clients WHERE id=$1', [created.body.clientId])).rows[0].name, 'Newer confirmed name');
  } finally { await activeContext.close(); }
});

async function loadApplicationAssignments(page,id) {
  await page.getByLabel('Client-ID für Zugriffsverwaltung',{ exact: true }).fill(id);
  await page.getByRole('button',{ name: 'Zuweisungen laden',exact: true }).click();
  await page.getByRole('heading',{ name: /^Zugriff für / }).waitFor();
}
async function grantFromConsole(page,targetType,targetId) {
  await page.getByLabel('Zieltyp',{ exact: true }).selectOption(targetType);
  await page.getByLabel('Kanonische Ziel-ID',{ exact: true }).fill(targetId);
  await page.getByLabel('Begründung der Anwendungszuweisung',{ exact: true }).fill('Independently reviewed browser application access');
  await page.getByRole('button',{ name: 'Anwendungszuweisung prüfen',exact: true }).click();
  await page.getByRole('button',{ name: 'Zuweisungsänderung bestätigen',exact: true }).click();
  await page.getByRole('dialog',{ name: 'Anwendungszuweisung bestätigen',exact: true }).waitFor({ state: 'detached' });
}
async function signInAssignedApplication(page,clientId,username) {
  const verifier = randomBytes(32).toString('base64url'); const callback = origin + '/owned-application/callback';
  const url = new URL(issuerBase + '/oauth/authorize');
  url.search = new URLSearchParams({ client_id: clientId,redirect_uri: callback,response_type: 'code',scope: 'openid profile email',code_challenge: createHash('sha256').update(verifier).digest('base64url'),code_challenge_method: 'S256' }).toString();
  await page.goto(url.toString()); await page.locator('input[name=username]').fill(username); await page.locator('input[name=password]').fill('disposable-password');
  const otpCode = await nextOtp(username); if (otpCode) await page.locator('input[name=otpCode]').fill(otpCode);
  const decision = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname === '/oauth/authorize/login');
  await page.getByRole('button',{ name: 'Anmelden',exact: true }).click(); const result = await decision;
  if (result.status() !== 302) return { status: result.status(),body: await result.json() };
  const code = new URL(result.headers().location).searchParams.get('code'); await page.waitForURL(url => url.pathname === '/owned-application/callback');
  return issuerJson('/oauth/token',{ method: 'POST',body: { grant_type: 'authorization_code',client_id: clientId,redirect_uri: callback,code,code_verifier: verifier } });
}
test('the real access console gates an actual public-app browser login, revokes it live and uses canonical groups for a new login', { timeout: 120000 }, async () => {
  const metadataContext = await context(); const managerContext = await context(); const userContext = await context();
  try {
    const metadataPage = await metadataContext.newPage(); await applicationConsole(metadataPage); const operator = await mediated(metadataPage);
    const created = await issuerJson('/api/clients',{ method: 'POST',token: operator.body.access_token,body: { name: 'Assigned browser application '+randomUUID(),publicClient: true,enabled: true,redirectUris: [origin + '/owned-application/callback'],scopes: ['openid','profile','email'],grantTypes: ['authorization_code','refresh_token'] } }); assert.equal(created.status,201);
    const clientId = created.body.clientId; const userPage = await userContext.newPage();
    await userContext.route(origin + '/owned-application/callback**',route => route.fulfill({ contentType: 'text/plain',body: 'Owned external application callback fixture' }));
    assert.equal((await signInAssignedApplication(userPage,clientId,'reader')).status,403);
    const managerPage = await managerContext.newPage(); const managementRequests = []; managerPage.on('request',request => managementRequests.push(request));
    await applicationConsole(managerPage,'app-access-manager'); await loadApplicationAssignments(managerPage,clientId);
    assert.equal(managementRequests.filter(request => new URL(request.url()).pathname === '/api/users' || new URL(request.url()).pathname === '/api/clients').length,0);
    await grantFromConsole(managerPage,'user',readerUser); const first = await signInAssignedApplication(userPage,clientId,'reader'); assert.equal(first.status,200);
    assert.equal((await issuerJson('/oauth/userinfo',{ token: first.body.access_token })).status,200);
    await managerPage.getByRole('button',{ name: 'Zuweisung widerrufen',exact: true }).click(); await managerPage.getByRole('button',{ name: 'Zuweisungsänderung bestätigen',exact: true }).click();
    await managerPage.getByRole('dialog',{ name: 'Anwendungszuweisung bestätigen',exact: true }).waitFor({ state: 'detached' });
    await managerPage.getByRole('listitem').filter({ hasText: readerUser }).filter({ hasText: 'Widerrufen' }).waitFor();
    assert.equal((await issuerJson('/oauth/userinfo',{ token: first.body.access_token })).status,401);
    assert.equal((await issuerJson('/oauth/token',{ method: 'POST',body: { grant_type: 'refresh_token',client_id: clientId,refresh_token: first.body.refresh_token } })).body.error,'invalid_grant');
    assert.equal((await signInAssignedApplication(userPage,clientId,'reader')).status,403);
    const groupId = randomUUID(); await identityDb.write('INSERT INTO groups(id,name) VALUES($1,$2)',[groupId,'Browser application group'],'fixture-group-operator');
    await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,readerUser],'fixture-group-operator');
    await grantFromConsole(managerPage,'group',groupId); const grouped = await signInAssignedApplication(userPage,clientId,'reader'); assert.equal(grouped.status,200);
    await identityDb.write('DELETE FROM group_members WHERE group_id=$1 AND user_id=$2',[groupId,readerUser],'fixture-group-operator');
    assert.equal((await issuerJson('/oauth/access-state',{ token: grouped.body.access_token })).body.active,false);
    await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,readerUser],'fixture-group-operator');
    assert.equal((await issuerJson('/oauth/access-state',{ token: grouped.body.access_token })).body.active,false); assert.equal((await signInAssignedApplication(userPage,clientId,'reader')).status,200);
    await managerPage.getByRole('heading',{ name: /^Zugriff für / }).scrollIntoViewIfNeeded(); await managerPage.screenshot({ path: path.join(os.tmpdir(),'od-application-assignments.png'),fullPage: false });
    const audit = (await issuerDb.query('SELECT * FROM oauth_application_access_audit WHERE details->>\'clientId\'=$1',[clientId])).rows;
    assert.deepEqual(audit.map(row => row.action),['granted','revoked','granted']); assert.ok(audit.every(row => row.actor.userId === actors.get('app-access-manager').userId));
  } finally { await metadataContext.close(); await managerContext.close(); await userContext.close(); }
});
test('real application MFA policy needs fresh independent management, blocks password access and bootstraps only an assigned factor in a signed-out browser', { timeout: 180000 }, async () => {
  const metadataContext=await context(); const managerContext=await context(); const userContext=await context(); const readerContext=await context();
  try {
    const metadata=await metadataContext.newPage(); await login(metadata,'app-operator'); const metadataToken=(await mediated(metadata)).body.access_token;
    const created=await issuerJson('/api/clients',{ method:'POST',token:metadataToken,body:{ name:'MFA-governed browser app '+randomUUID(),publicClient:true,enabled:true,redirectUris:[origin+'/owned-application/callback'],scopes:['openid','profile','email'],grantTypes:['authorization_code','refresh_token'] } }); assert.equal(created.status,201); const clientId=created.body.clientId;
    const grantor=await metadataContext.newPage(); await login(grantor,'app-access-manager'); const grantToken=(await mediated(grantor)).body.access_token;
    assert.equal((await issuerJson(`/api/clients/${clientId}/assignments`,{ method:'POST',token:grantToken,body:{ requestId:randomUUID(),targetType:'user',targetId:actors.get('authentication-user').userId,durationSeconds:28800,reason:'Independently assigned required MFA browser user' } })).status,201);
    const manager=await managerContext.newPage(); await applicationConsole(manager,'authentication-manager'); const forbidden=[]; manager.on('request',request=>{ const path=new URL(request.url()).pathname; if(path==='/api/users'||path==='/api/clients')forbidden.push(path); });
    await manager.getByLabel('Anwendungs-ID für MFA-Richtlinie',{exact:true}).fill(clientId); await manager.getByRole('button',{name:'Richtlinie laden',exact:true}).click(); await manager.getByRole('button',{name:'Für Richtlinienänderung neu anmelden',exact:true}).waitFor();
    assert.equal(await manager.getByRole('button',{name:'Anmelderichtlinie prüfen',exact:true}).count(),0);
    await manager.goto(origin+'/mfa'); await manager.getByLabel('Eigener Benutzername',{exact:true}).fill('authentication-manager'); await manager.getByLabel('Aktuelles Passwort',{exact:true}).fill('disposable-password');
    const enrolling=manager.waitForResponse(response=>new URL(response.url()).pathname==='/api/mfa/enroll'); await manager.getByRole('button',{name:'TOTP einrichten',exact:true}).click(); const factor=await(await enrolling).json(); const counter=Math.floor(Date.now()/30000)-1;
    await manager.getByLabel('Neuer OpenDirectory-Einmalcode',{exact:true}).fill(totp(factor.secret,counter)); const confirming=manager.waitForResponse(response=>new URL(response.url()).pathname==='/api/mfa/confirm'); await manager.getByRole('button',{name:'Einrichtung bestätigen',exact:true}).click(); assert.equal((await confirming).status(),200);
    rememberFactor('authentication-manager',factor.secret,counter); await applicationConsole(manager,'authentication-manager');
    await manager.getByLabel('Anwendungs-ID für MFA-Richtlinie',{exact:true}).fill(clientId); await manager.getByRole('button',{name:'Richtlinie laden',exact:true}).click(); await manager.getByLabel('MFA für Benutzeranmeldungen verlangen',{exact:true}).waitFor();
    await manager.getByLabel('MFA für Benutzeranmeldungen verlangen',{exact:true}).check(); await manager.getByLabel('Maximales Anmeldealter in Sekunden',{exact:true}).fill('300'); await manager.getByLabel('Begründung der Anmelderichtlinie',{exact:true}).fill('Reviewed mandatory browser MFA and authentication age'); await manager.getByRole('button',{name:'Anmelderichtlinie prüfen',exact:true}).click();
    const policyReceipt=manager.waitForResponse(response=>response.request().method()==='PUT'&&new URL(response.url()).pathname===`/api/clients/${clientId}/authentication`); await manager.getByRole('button',{name:'Richtlinie verbindlich speichern',exact:true}).click(); assert.equal((await policyReceipt).status(),200); await manager.getByText('MFA verbindlich; Anmeldung höchstens 300 Sekunden alt.',{exact:true}).waitFor();
    assert.deepEqual(forbidden,[]); assert.equal((await issuerJson(`/api/clients/${clientId}/authentication`,{method:'PUT',token:metadataToken,headers:{'If-Match':`"od-client:${clientId}:2"`},body:{required:false,maxAgeSeconds:3600,reason:'Metadata editor cannot weaken MFA'}})).status,403);
    await userContext.route(origin+'/owned-application/callback**',route=>route.fulfill({contentType:'text/plain',body:'Owned application callback fixture'})); const user=await userContext.newPage();
    const denied=await signInAssignedApplication(user,clientId,'authentication-user'); assert.equal(denied.status,401); assert.equal(denied.body.error,'mfa_enrollment_required');
    const calls=[]; user.on('request',request=>{if(new URL(request.url()).pathname.startsWith('/api/auth/oidc/'))calls.push(request);}); await user.goto(origin+'/login'); await user.getByRole('link',{name:'MFA-pflichtige Anwendung: Faktor erstmals einrichten',exact:true}).click(); await user.waitForURL(origin+'/auth/mfa-enroll');
    await user.getByLabel('Eigener Benutzername',{exact:true}).fill('authentication-user'); await user.getByLabel('Aktuelles Passwort',{exact:true}).fill('disposable-password'); await user.getByLabel('Anwendungs-ID für Ersteinrichtung',{exact:true}).fill(clientId);
    const setupReceipt=user.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/start'); await user.getByRole('button',{name:'Ersteinrichtung vorbereiten',exact:true}).click(); const setupResponse=await setupReceipt; assert.equal(setupResponse.status(),200); const setup=await setupResponse.json(); await user.getByLabel('Neuer MFA-Schlüssel',{exact:true}).waitFor();
    const setupCounter=Math.floor(Date.now()/30000)-1; await user.getByLabel('Einmalcode des neuen Authenticators',{exact:true}).fill(totp(setup.secret,setupCounter)); const activation=user.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/confirm'); await user.getByRole('button',{name:'Neuen Faktor bestätigen',exact:true}).click(); const activationResponse=await activation; assert.equal(activationResponse.status(),200); assert.equal(activationResponse.headers()['set-cookie'],undefined);
    await user.getByText(/Ersteinrichtung bestätigt/).waitFor(); assert.equal(await user.getByText(setup.secret,{exact:true}).count(),0); assert.equal((await userContext.cookies()).some(cookie=>cookie.name.includes('od_session')),false); assert.equal(calls.some(request=>new URL(request.url()).pathname==='/api/auth/oidc/session'||request.headers().authorization),false);
    const stored=await user.evaluate(()=>[...Object.values(localStorage),...Object.values(sessionStorage)].join('|')); assert.equal(stored.includes(setup.secret)||stored.includes(setup.challenge),false); await user.screenshot({path:path.join(os.tmpdir(),'od-mfa-required-enrollment.png'),fullPage:false});
    rememberFactor('authentication-user',setup.secret,setupCounter); const signedIn=await signInAssignedApplication(user,clientId,'authentication-user'); assert.equal(signedIn.status,200); const claims=JSON.parse(Buffer.from(signedIn.body.access_token.split('.')[1],'base64url')); assert.deepEqual(claims.amr,['pwd','otp']); assert.equal(claims.identity_authorization.userId,actors.get('authentication-user').userId); assert.equal(claims.roles,undefined);
    const read=await readerContext.newPage(); await applicationConsole(read,'authentication-reader'); await read.getByLabel('Anwendungs-ID für MFA-Richtlinie',{exact:true}).fill(clientId); await read.getByRole('button',{name:'Richtlinie laden',exact:true}).click(); await read.getByText('MFA verbindlich; Anmeldung höchstens 300 Sekunden alt.',{exact:true}).waitFor(); assert.equal(await read.getByRole('button',{name:'Anmelderichtlinie prüfen',exact:true}).count(),0);
    const reader=(await mediated(read)).body.access_token; assert.equal((await issuerJson(`/api/clients/${clientId}/authentication`,{method:'PUT',token:reader,headers:{'If-Match':`"od-client:${clientId}:2"`},body:{required:false,maxAgeSeconds:3600,reason:'Reader cannot weaken MFA'}})).status,403);
    const actualPolicy=await issuerDb.query('SELECT mfa_required,mfa_max_age_seconds FROM oauth_clients WHERE id=$1',[clientId]); assert.equal(actualPolicy.rows[0].mfa_required,true); assert.equal(actualPolicy.rows[0].mfa_max_age_seconds,300);
  } finally {await metadataContext.close();await managerContext.close();await userContext.close();await readerContext.close();}
});

test('real role-wide MFA survives client choice, bootstraps its security operator without a session and independently fences browser refresh', { timeout: 180000 }, async () => {
  const managerContext = await context(); const readerContext = await context(); const userContext = await context(); let managerToken; let changed = false;
  async function firstFactor(page,username) {
    await page.goto(origin+'/auth/mfa-enroll'); await page.getByLabel('Eigener Benutzername',{ exact:true }).fill(username);
    await page.getByLabel('Aktuelles Passwort',{ exact:true }).fill('disposable-password');
    const receipt = page.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/start');
    await page.getByRole('button',{ name:'Ersteinrichtung vorbereiten',exact:true }).click(); const response = await receipt; assert.equal(response.status(),200); const setup = await response.json();
    const counter = Math.floor(Date.now()/30000)-1; await page.getByLabel('Einmalcode des neuen Authenticators',{ exact:true }).fill(totp(setup.secret,counter));
    const completion = page.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/confirm');
    await page.getByRole('button',{ name:'Neuen Faktor bestätigen',exact:true }).click(); assert.equal((await completion).status(),200); await page.getByText(/Ersteinrichtung bestätigt/).waitFor();
    assert.equal((await page.context().cookies()).some(cookie=>cookie.name==='od_session'),false);
    assert.equal(await page.getByText(setup.secret,{ exact:true }).count(),0); rememberFactor(username,setup.secret,counter);
  }
  try {
    const user = await userContext.newPage(); await login(user,'role-assurance-user'); const weak = (await mediated(user)).body.access_token;
    const manager = await managerContext.newPage(); await firstFactor(manager,'role-assurance-manager'); await login(manager,'role-assurance-manager'); managerToken = (await mediated(manager)).body.access_token;
    await manager.goto(origin+'/roles'); await manager.getByLabel('Kanonische Rolle für MFA-Richtlinie',{ exact:true }).fill('license-manager');
    await manager.getByRole('button',{ name:'Rollenrichtlinie laden',exact:true }).click(); await manager.getByText(/license-manager · Version/).waitFor();
    await manager.getByLabel('MFA für diese Rolle verlangen',{ exact:true }).check(); await manager.getByLabel('Maximales Rollen-Anmeldealter in Sekunden',{ exact:true }).fill('300');
    await manager.getByLabel('Begründung der Rollenrichtlinie',{ exact:true }).fill('Reviewed cross-client browser license role assurance');
    await manager.getByRole('button',{ name:'Rollenrichtlinie prüfen',exact:true }).click(); await manager.getByRole('button',{ name:'Rollenrichtlinie verbindlich speichern',exact:true }).click();
    await manager.getByText(/Rollenrichtlinie bestätigt für license-manager/).waitFor(); changed = true;
    assert.equal((await issuerJson('/oauth/access-state',{ token:weak })).body.active,false); assert.equal((await mediated(user)).status,401);
    assert.equal((await issuerDb.query("SELECT mfa_required FROM oauth_clients WHERE id='web-app'")).rows[0].mfa_required,false);
    await firstFactor(user,'role-assurance-user'); await login(user,'role-assurance-user'); const strong = await mediated(user); assert.equal(strong.status,200);
    assert.deepEqual(JSON.parse(Buffer.from(strong.body.access_token.split('.')[1],'base64url').toString()).amr,['pwd','otp']);
    const reader = await readerContext.newPage(); const requests = []; reader.on('request',request=>{ if (new URL(request.url()).pathname.startsWith('/api/users')) requests.push(request.url()); });
    await login(reader,'role-assurance-reader'); const readerToken = (await mediated(reader)).body.access_token; await reader.goto(origin+'/roles');
    await reader.getByLabel('Kanonische Rolle für MFA-Richtlinie',{ exact:true }).fill('license-manager'); await reader.getByRole('button',{ name:'Rollenrichtlinie laden',exact:true }).click();
    await reader.getByText('Rollenweite MFA verbindlich; Anmeldung höchstens 300 Sekunden alt.',{ exact:true }).waitFor(); assert.equal(await reader.getByRole('button',{ name:'Rollenrichtlinie prüfen',exact:true }).count(),0); assert.equal(requests.length,0);
    const current = (await identityDb.query("SELECT version FROM identity_role_authentication WHERE role='license-manager'")).rows[0];
    const denied = await fetch(identityBase+'/api/identity/authentication/roles/license-manager',{ method:'PUT',headers:{ Authorization:'Bearer '+readerToken,'Content-Type':'application/json','If-Match':`"od-role-authentication:license-manager:${current.version}"` },body:JSON.stringify({ required:false,maxAgeSeconds:3600,reason:'Reader must not weaken role policy' }) }); assert.equal(denied.status,403);
    await reader.getByRole('region',{ name:'Rollenweite MFA-Richtlinien' }).scrollIntoViewIfNeeded(); await reader.screenshot({ path:path.join(os.tmpdir(),'od-role-authentication.png'),fullPage:false });
  } finally {
    if (changed) {
      const current = (await identityDb.query("SELECT version FROM identity_role_authentication WHERE role='license-manager'")).rows[0];
      const restored = await fetch(identityBase+'/api/identity/authentication/roles/license-manager',{ method:'PUT',headers:{ Authorization:'Bearer '+managerToken,'Content-Type':'application/json','If-Match':`"od-role-authentication:license-manager:${current.version}"` },body:JSON.stringify({ required:false,maxAgeSeconds:3600,reason:'Restore isolated browser policy fixture' }) }); assert.equal(restored.status,200);
    }
    await managerContext.close(); await readerContext.close(); await userContext.close();
  }
});
test('real provider console separates local approval, protected adoption and observed Graph state without exposing credentials or calling queued work fulfilled',{ timeout:180000 },async()=>{
  const configContext=await context(); const readContext=await context(); const adminContext=await context(); let graphServer;let capacityPool;let capacityRole;
  const json=async(route,{ method='GET',token,body,headers={} }={})=>{
    const response=await fetch(policyBase+route,{ method,headers:{ Authorization:'Bearer '+token,'Content-Type':'application/json',...headers },...(body?{ body:JSON.stringify(body) }:{}) });
    return { status:response.status,headers:response.headers,body:response.status===204?null:await response.json() };
  };
  try {
    const config=await configContext.newPage(); await config.goto(origin+'/auth/mfa-enroll'); await config.getByLabel('Eigener Benutzername',{ exact:true }).fill('cloud-provider-config'); await config.getByLabel('Aktuelles Passwort',{ exact:true }).fill('disposable-password');
    const preparation=config.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/start'); await config.getByRole('button',{ name:'Ersteinrichtung vorbereiten',exact:true }).click(); const setupResponse=await preparation; assert.equal(setupResponse.status(),200); const setup=await setupResponse.json(); const counter=Math.floor(Date.now()/30000)-1;
    await config.getByLabel('Einmalcode des neuen Authenticators',{ exact:true }).fill(totp(setup.secret,counter)); await config.getByRole('button',{ name:'Neuen Faktor bestätigen',exact:true }).click(); await config.getByText(/Ersteinrichtung bestätigt/).waitFor(); rememberFactor('cloud-provider-config',setup.secret,counter);
    await login(config,'cloud-provider-config'); const configToken=(await mediated(config)).body.access_token;
    const adminPage=await adminContext.newPage(); await login(adminPage,'administrator'); const adminToken=(await mediated(adminPage)).body.access_token;
    const license=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser-owned Microsoft pool',2) RETURNING id")).rows[0]; const reason='Reviewed exclusive direct provider console fixture';
    const connector=await json('/api/licenses/fulfillment/connectors',{ method:'POST',token:configToken,body:{ tenantId:randomUUID(),reason } }); assert.equal(connector.status,201);
    const product=await json('/api/licenses/fulfillment/products',{ method:'POST',token:configToken,body:{ connectorId:connector.body.id,licenseId:license.id,skuId:randomUUID(),disabledPlans:[],exclusiveDirectManagement:true,reason } }); assert.equal(product.status,201);
    const subject=await json('/api/licenses/fulfillment/subjects',{ method:'POST',token:configToken,body:{ connectorId:connector.body.id,userId:actors.get('cloud-beneficiary').userId,objectId:randomUUID(),exclusiveDirectManagement:true,reason } }); assert.equal(subject.status,201);
    for (const [kind,result] of [['connectors',connector],['products',product],['subjects',subject]]) assert.equal((await json(`/api/licenses/fulfillment/${kind}/${result.body.id}`,{ method:'PUT',token:configToken,headers:{ 'If-Match':result.headers.get('etag') },body:{ enabled:true,reason } })).status,200);
    const assignment={ assignee_type:'user',assignee_id:subject.body.userId }; assert.equal((await json(`/api/licenses/${license.id}/assign`,{ method:'POST',token:configToken,body:assignment })).status,403); assert.equal((await json(`/api/licenses/${license.id}/assign`,{ method:'POST',token:adminToken,body:assignment })).status,201);
    const sourceClient=await issuerJson('/api/clients',{ method:'POST',token:adminToken,body:{ name:'Owned provider source workload',enabled:true,scopes:['licenses.users.read'],grantTypes:['client_credentials'],redirectUris:[] } }); assert.equal(sourceClient.status,201);
    let present=true; let writes=0;const capacityClientId=randomUUID();
    graphServer=http.createServer(async(request,response)=>{
      const chunks=[]; for await (const chunk of request) chunks.push(chunk); response.setHeader('Content-Type','application/json');
      if (request.url.endsWith('/token')) return response.end(JSON.stringify({ access_token:new URLSearchParams(Buffer.concat(chunks).toString()).get('client_id')===capacityClientId?'owned-browser-capacity-token':'owned-browser-vendor-token',token_type:'Bearer',expires_in:3600 }));
      if(request.url.startsWith('/v1.0/subscribedSkus?')){assert.equal(request.method,'GET');assert.equal(request.headers.authorization,'Bearer owned-browser-capacity-token');return response.end(JSON.stringify({value:[{skuId:product.body.skuId,skuPartNumber:'BROWSER_CAPACITY',appliesTo:'User',capabilityStatus:'Enabled',prepaidUnits:{enabled:10,warning:2,suspended:1,lockedOut:0},consumedUnits:3}]}));}
      assert.equal(request.headers.authorization,'Bearer owned-browser-vendor-token');
      if (request.method==='POST') { const body=JSON.parse(Buffer.concat(chunks).toString());assert.ok(writes<2);assert.deepEqual(body,writes===0?{addLicenses:[],removeLicenses:[product.body.skuId]}:{addLicenses:[{skuId:product.body.skuId,disabledPlans:[]}],removeLicenses:[]});writes++;present=body.addLicenses.length===1;return response.end(JSON.stringify({id:subject.body.objectId})); }
      response.end(JSON.stringify({ id:subject.body.objectId,accountEnabled:true,assignedLicenses:present?[{ skuId:product.body.skuId,disabledPlans:[] }]:[],licenseAssignmentStates:present?[{ skuId:product.body.skuId,disabledPlans:[],assignedByGroup:null,state:'Active',error:null }]:[] }));
    }).listen(0,'127.0.0.1'); const graphOrigin=await serverBase(graphServer);
    const { WorkerIdentity }=require('../../../policy-service/src/licenses/fulfillment/WorkerConfiguration'); const { GraphLicenseClient }=require('../../../policy-service/src/licenses/fulfillment/GraphLicenseClient');
    const { ProviderStore }=require('../../../policy-service/src/licenses/fulfillment/ProviderStore'); const { LicenseAllocator }=require('../../../policy-service/src/licenses/LicenseAllocator'); const { FulfillmentWorker }=require('../../../policy-service/src/licenses/fulfillment/FulfillmentWorker');
    const identity=new WorkerIdentity({ sourceTokenUrl:issuerBase+'/oauth/token',sourceClientId:sourceClient.body.clientId,sourceClientSecret:sourceClient.body.clientSecret,identityUrl:identityBase+'/' });
    const graph=new GraphLicenseClient({ tenantId:connector.body.tenantId,clientId:randomUUID(),clientSecret:'owned-browser-vendor-secret',fetchImpl:(url,options)=>fetch(graphOrigin+new URL(url).pathname+new URL(url).search,options) });
    const store=new ProviderStore(new LicenseAllocator(policyDb)); const worker=new FulfillmentWorker({ store,identity,graph,connectorId:connector.body.id,tenantId:connector.body.tenantId,sourceClientId:sourceClient.body.clientId });
    const pending=await json(`/api/licenses/fulfillment/targets/${license.id}/${subject.body.userId}`,{ token:configToken }); await worker.target(pending.body.id); assert.equal(writes,0);
    const load=async page=>{ await page.goto(origin+'/licenses'); const panel=page.getByRole('region',{ name:'Externe Lizenzbereitstellung' }); await panel.getByLabel('Lokale Lizenz-ID für Provider-Status',{ exact:true }).fill(license.id); await panel.getByLabel('Verzeichnis-ID für Provider-Status',{ exact:true }).fill(subject.body.userId); await panel.getByRole('button',{ name:'Provider-Status prüfen',exact:true }).click(); return panel; };
    const reader=await readContext.newPage(); const profiles=[]; reader.on('request',request=>{ if (new URL(request.url()).pathname.startsWith('/api/users')) profiles.push(request.url()); }); await login(reader,'cloud-provider-read'); const readPanel=await load(reader);
    await readPanel.getByText('Abweichung oder fremd verwaltete Lizenz',{ exact:true }).waitFor(); assert.equal(await readPanel.getByRole('button',{ name:'Vorhandene Direktzuweisung übernehmen',exact:true }).count(),0); assert.equal(profiles.length,0);
    const panel=await load(config); await panel.getByRole('button',{ name:'Vorhandene Direktzuweisung übernehmen',exact:true }).click(); await panel.getByLabel('Begründung der Provider-Prüfentscheidung',{ exact:true }).fill('Independent review of existing direct vendor assignment'); await panel.getByRole('checkbox').check(); await panel.getByRole('button',{ name:'Provider-Prüfentscheidung speichern',exact:true }).click();
    await panel.getByText(/Dies bestätigt keine externe Bereitstellung/).waitFor(); await panel.getByText('Auftrag vorgemerkt',{ exact:true }).waitFor(); assert.equal(writes,0);
    await worker.target(pending.body.id); await readPanel.getByRole('button',{ name:'Provider-Status prüfen',exact:true }).click(); await readPanel.getByText('Zuletzt beobachteter Sollstand bestätigt',{ exact:true }).waitFor();
    assert.equal((await json(`/api/licenses/${license.id}/assignments/${subject.body.userId}?assignee_type=user`,{ method:'DELETE',token:adminToken })).status,204); await worker.target(pending.body.id); await worker.target(pending.body.id);
    await readPanel.getByRole('button',{ name:'Provider-Status prüfen',exact:true }).click(); await readPanel.getByText('Lizenz beim Provider nicht vorhanden.',{ exact:true }).waitFor(); assert.equal(writes,1);
    const capacity=readPanel.getByRole('region',{name:'Hersteller-Lizenzkapazität',exact:true});await capacity.getByLabel('Connector-ID für Kapazitätsvergleich',{exact:true}).fill(connector.body.id);await capacity.getByRole('button',{name:'Gespeicherte Herstellerkapazität prüfen',exact:true}).click();await capacity.getByText('Keine aktuelle vollständige Herstellerbeobachtung. Freie Plätze bleiben unbekannt.',{exact:true}).waitFor();
    capacityRole='capacity_browser_'+randomUUID().replaceAll('-','');const password='owned-'+randomUUID();await administration.query(`CREATE ROLE ${capacityRole} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT PASSWORD '${password}'`);await policyDb.query(fs.readFileSync(path.join(__dirname,'../../../policy-service/scripts/license-capacity-grants.sql'),'utf8').replaceAll(':"license_schema"',`"${policySchema}"`).replaceAll(':"collector_role"',`"${capacityRole}"`));const sourceId=randomUUID();
    const setupClient=await policyDb.getClient();try{await setupClient.query('BEGIN');await setupClient.query("SELECT set_config('opendirectory.capacity_source_reason','Explicit browser fixture offline read-only capacity setup',true)");await setupClient.query('INSERT INTO license_capacity_sources(id,connector_id,database_role,graph_client_id) VALUES($1,$2,$3,$4)',[sourceId,connector.body.id,capacityRole,capacityClientId]);await setupClient.query('UPDATE license_capacity_sources SET enabled=true,version=version+1 WHERE id=$1',[sourceId]);await setupClient.query('COMMIT');}finally{setupClient.release();}
    const capacityAddress=new URL(process.env.OAUTH_TEST_DATABASE_URL);capacityAddress.username=capacityRole;capacityAddress.password=password;capacityAddress.searchParams.set('options',`-c search_path=${policySchema},public`);capacityPool=new Pool({connectionString:capacityAddress.toString(),max:3});const restricted={query:(...args)=>capacityPool.query(...args),getClient:()=>capacityPool.connect()};
    const{CapacityObserver,assertCapacityDatabase}=require('../../../policy-service/src/licenses/fulfillment/CapacityObserver');const{GraphCapacityClient}=require('../../../policy-service/src/licenses/fulfillment/GraphCapacityClient');await assertCapacityDatabase(restricted);const capacityObserver=new CapacityObserver(restricted,{sourceId,connectorId:connector.body.id,tenantId:connector.body.tenantId,graphClientId:capacityClientId},new GraphCapacityClient({tenantId:connector.body.tenantId,clientId:capacityClientId,clientSecret:'owned-browser-capacity-secret',fetchImpl:(url,options)=>fetch(graphOrigin+new URL(url).pathname+new URL(url).search,options)}));assert.equal((await capacityObserver.sweep()).status,'complete');
    await capacity.getByRole('button',{name:'Gespeicherte Herstellerkapazität prüfen',exact:true}).click();await capacity.getByText('Zum Abrufzeitpunkt bestätigte Beobachtung, keine Reservierung.',{exact:true}).waitFor();await capacity.getByText('Beobachtete unzugewiesene aktive Einheiten: 7. Keine Zuweisungsgarantie.',{exact:true}).waitFor();assert.equal((await policyDb.query('SELECT total_seats FROM license_catalog WHERE id=$1',[license.id])).rows[0].total_seats,2);await capacity.scrollIntoViewIfNeeded();await reader.screenshot({path:path.join(os.tmpdir(),'od-capacity43-observation.png'),fullPage:false});
    await capacity.getByText('Kein geprüftes Freigabekontingent: Neue externe Zuweisungen gesperrt.',{exact:true}).waitFor();
    assert.equal((await json(`/api/licenses/${license.id}/assign`,{method:'POST',token:adminToken,body:{assignee_type:'user',assignee_id:subject.body.userId}})).status,201);await worker.target(pending.body.id);assert.equal(writes,1);await readPanel.getByRole('button',{name:'Provider-Status prüfen',exact:true}).click();await readPanel.getByText('Provider-Status: capacity_budget_required',{exact:true}).waitFor();
    const refreshed=await capacityObserver.sweep();assert.equal(refreshed.status,'complete');const{reviewCapacityBudget}=require('../../../../../scripts/lib/license-capacity-admission-fixture.cjs');await reviewCapacityBudget({database:policyDb,schema:policySchema,productId:product.body.id,runId:refreshed.runId});await worker.target(pending.body.id);await worker.target(pending.body.id);assert.equal(writes,2);
    await capacity.getByRole('button',{name:'Gespeicherte Herstellerkapazität prüfen',exact:true}).click();await capacity.getByText('Lokales Freigabekontingent: 7 · belastete Versuche: 1 · Restkontingent: 6. Keine Herstellerreservierung.',{exact:true}).waitFor();await capacity.scrollIntoViewIfNeeded();await reader.screenshot({path:path.join(os.tmpdir(),'od-admission44-budget.png'),fullPage:false});
    const pause=await policyDb.getClient();try{await pause.query('BEGIN');await pause.query("SELECT set_config('opendirectory.capacity_source_reason','Explicit pause of actual browser capacity observer',true)");await pause.query('UPDATE license_capacity_sources SET enabled=false,version=version+1 WHERE id=$1',[sourceId]);await pause.query('COMMIT');}finally{pause.release();}await capacity.getByRole('button',{name:'Gespeicherte Herstellerkapazität prüfen',exact:true}).click();await capacity.getByText('Beobachtete unzugewiesene aktive Einheiten: unbekannt. Keine Zuweisungsgarantie.',{exact:true}).waitFor();await capacity.getByText('Neue externe Zuweisungen sind ohne aktuelle Bestands- und Budgetfreigabe gesperrt.',{exact:true}).waitFor();assert.equal(writes,2);assert.equal(profiles.length,0);
    const storage=await config.evaluate(()=>[...Object.values(localStorage),...Object.values(sessionStorage)].join('|')); assert.equal(storage.includes('owned-browser-vendor-token')||storage.includes('owned-browser-vendor-secret')||storage.includes(sourceClient.body.clientSecret),false);
    await readPanel.scrollIntoViewIfNeeded(); await reader.screenshot({ path:path.join(os.tmpdir(),'od-license-fulfillment.png'),fullPage:false });
  } catch(error) {process.stderr.write('Provider console failure: '+error.stack+'\n');throw error;}
  finally {
    if(graphServer?.listening){graphServer.closeAllConnections();await new Promise(resolve=>graphServer.close(resolve));}
    try{await capacityPool?.end();if(capacityRole){await policyDb.query(`DROP OWNED BY ${capacityRole}`);await administration.query(`DROP ROLE ${capacityRole}`);}}
    finally{await configContext.close();await readContext.close();await adminContext.close();}
  }
});
test('a real access reader has no metadata/profile or assignment writes and the manager UI blocks canonical self assignment', { timeout: 120000 }, async () => {
  const metadataContext = await context(); const readerContext = await context(); const managerContext = await context();
  try {
    const metadataPage = await metadataContext.newPage(); await login(metadataPage,'app-operator'); const operator = await mediated(metadataPage);
    const created = await issuerJson('/api/clients',{ method: 'POST',token: operator.body.access_token,body: { name: 'Reader access application '+randomUUID(),redirectUris: ['https://reader-app.test/callback'] } }); assert.equal(created.status,201);
    const page = await readerContext.newPage(); await applicationConsole(page,'app-access-reader'); await loadApplicationAssignments(page,created.body.clientId);
    assert.equal(await page.getByRole('button',{ name: 'Anwendungszuweisung prüfen',exact: true }).count(),0); assert.equal(await page.getByRole('button',{ name: 'Anwendung registrieren',exact: true }).count(),0);
    const reader = await mediated(page); assert.equal((await issuerJson(`/api/clients/${created.body.clientId}/assignments`,{ method: 'POST',token: reader.body.access_token,body: { requestId: randomUUID(),targetType: 'user',targetId: readerUser,durationSeconds: 3600,reason: 'Forbidden reader assignment' } })).status,403);
    const manager = await managerContext.newPage(); await applicationConsole(manager,'app-access-manager'); await loadApplicationAssignments(manager,created.body.clientId); const requests = []; manager.on('request',request => { if (request.method() === 'POST' && new URL(request.url()).pathname.includes('/assignments')) requests.push(request); });
    await manager.getByLabel('Kanonische Ziel-ID',{ exact: true }).fill(actors.get('app-access-manager').userId); await manager.getByLabel('Begründung der Anwendungszuweisung',{ exact: true }).fill('Must not self-authorize browser access'); await manager.getByRole('button',{ name: 'Anwendungszuweisung prüfen',exact: true }).click();
    await manager.getByRole('alert').filter({ hasText: 'Eigene Anwendungszugriffe' }).waitFor(); assert.equal(requests.length,0);
  } finally { await metadataContext.close(); await readerContext.close(); await managerContext.close(); }
});

test('the real PIM policy console requires reviewed fresh MFA, removes direct browser authority and gives a separate reader no profile or policy writes',{ timeout:180000 },async()=>{
  const managerContext=await context(); const readerContext=await context(); const ownerContext=await context(); let managerToken; let changed=false;
  const route='/api/identity/pim/policies/license-manager';
  try {
    const owner=await ownerContext.newPage(); await login(owner,'pim-policy-owner'); const old=(await mediated(owner)).body.access_token;
    assert.ok(JSON.parse(Buffer.from(old.split('.')[1],'base64url')).roles.includes('license-manager'));
    const manager=await managerContext.newPage(); await manager.goto(origin+'/auth/mfa-enroll');
    await manager.getByLabel('Eigener Benutzername',{ exact:true }).fill('pim-policy-manager'); await manager.getByLabel('Aktuelles Passwort',{ exact:true }).fill('disposable-password');
    const setupReceipt=manager.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/start');
    await manager.getByRole('button',{ name:'Ersteinrichtung vorbereiten',exact:true }).click(); const setupResponse=await setupReceipt; assert.equal(setupResponse.status(),200); const setup=await setupResponse.json();
    const counter=Math.floor(Date.now()/30000)-1; await manager.getByLabel('Einmalcode des neuen Authenticators',{ exact:true }).fill(totp(setup.secret,counter));
    await manager.getByRole('button',{ name:'Neuen Faktor bestätigen',exact:true }).click(); await manager.getByText(/Ersteinrichtung bestätigt/).waitFor();
    assert.equal((await managerContext.cookies()).some(cookie=>cookie.name==='od_session'),false); assert.equal(await manager.getByText(setup.secret,{ exact:true }).count(),0);
    rememberFactor('pim-policy-manager',setup.secret,counter); await login(manager,'pim-policy-manager'); managerToken=(await mediated(manager)).body.access_token;
    await manager.goto(origin+'/pim'); await manager.getByLabel('Kanonische Rolle für PIM-Richtlinie',{ exact:true }).fill('license-manager');
    await manager.getByRole('button',{ name:'PIM-Richtlinie laden',exact:true }).click(); await manager.getByText(/license-manager · Version/).waitFor();
    await manager.getByLabel('PIM-Aktivierung verbindlich verlangen',{ exact:true }).check();
    await manager.getByLabel('Maximale PIM-Aktivierungsdauer in Sekunden',{ exact:true }).fill('600');
    await manager.getByLabel('Begründung der PIM-Richtlinie',{ exact:true }).fill('Reviewed canonical browser mandatory activation');
    await manager.getByRole('button',{ name:'PIM-Richtlinie prüfen',exact:true }).click();
    const save=manager.getByRole('button',{ name:'PIM-Richtlinie verbindlich speichern',exact:true }); assert.equal(await save.isDisabled(),true);
    await manager.getByLabel('Rechteentzug und Wiederherstellung geprüft',{ exact:true }).check();
    const receipt=manager.waitForResponse(response=>new URL(response.url()).pathname===route && response.request().method()==='PUT');
    await save.click(); assert.equal((await receipt).status(),200); changed=true;
    await manager.getByText(/PIM-Richtlinie für license-manager bestätigt/).waitFor();
    assert.equal((await owner.request.get(origin+'/api/licenses/access',{ headers:{ Authorization:'Bearer '+old } })).status(),401);
    assert.equal((await mediated(owner)).status,401);
    await login(owner,'pim-policy-owner'); const current=JSON.parse(Buffer.from((await mediated(owner)).body.access_token.split('.')[1],'base64url'));
    assert.ok(!current.roles.includes('license-manager'));
    const reader=await readerContext.newPage(); const forbidden=[];
    reader.on('request',request=>{ const pathname=new URL(request.url()).pathname; if(pathname==='/api/users' || pathname.startsWith('/api/identity/search'))forbidden.push(pathname); });
    await login(reader,'pim-policy-reader'); await reader.goto(origin+'/pim');
    await reader.getByLabel('Kanonische Rolle für PIM-Richtlinie',{ exact:true }).fill('license-manager'); await reader.getByRole('button',{ name:'PIM-Richtlinie laden',exact:true }).click();
    await reader.getByText(/Nur unabhängig genehmigte PIM-Aktivierung erlaubt/).waitFor();
    assert.equal(await reader.getByRole('button',{ name:'PIM-Richtlinie prüfen',exact:true }).count(),0); assert.equal(forbidden.length,0);
    const readerToken=(await mediated(reader)).body.access_token;
    assert.equal((await reader.request.put(origin+route,{ headers:{ Authorization:'Bearer '+readerToken },data:{} })).status(),403);
    const panel=reader.getByRole('region',{ name:'Verbindliche PIM-Richtlinien' }); await panel.scrollIntoViewIfNeeded();
    await reader.screenshot({ path:path.join(os.tmpdir(),'od-pim-policy.png'),fullPage:false });
  } finally {
    if(changed && managerToken) {
      const before=await fetch(identityBase+route,{ headers:{ Authorization:'Bearer '+managerToken } }); const policy=await before.json(); assert.equal(before.status,200);
      const restored=await fetch(identityBase+route,{ method:'PUT',headers:{ Authorization:'Bearer '+managerToken,'Content-Type':'application/json','If-Match':`"od-role-activation:license-manager:${policy.version}"` },
        body:JSON.stringify({ required:false,maxDurationSeconds:28800,reason:'Reviewed isolated browser policy restoration',acknowledgeInvalidation:true }) }); assert.equal(restored.status,200);
    }
    await managerContext.close(); await readerContext.close(); await ownerContext.close();
  }
});

async function browserPublication(config,reviewPage,kind,id,reviewerName){
 const plural=kind==='policy'?'policies':'blueprints';const root='/api/'+plural+'/'+id;
 const scope=kind==='policy'?config.getByRole('article').filter({hasText:id}).getByRole('region',{name:'Unabhängige Richtlinienfreigabe',exact:true}):config.getByRole('region',{name:'Unabhängige Richtlinienfreigabe',exact:true});
 await scope.getByRole('button',{name:'Freigaberahmen laden',exact:true}).click();await scope.getByLabel('Kanonische Prüfer-ID',{exact:true}).fill(actors.get(reviewerName).userId);await scope.getByLabel('Gültigkeit ab Anforderung',{exact:true}).selectOption('300');await scope.getByRole('button',{name:'Freigabeanforderung prüfen',exact:true}).click();
 const confirm=async(panel)=>{await panel.getByLabel('Begründung der Freigabe',{exact:true}).fill('Actual independently inspected browser content and targets');await panel.getByRole('checkbox',{name:'Vollständigen Inhalt, Zielumfang, Unabhängigkeit und Frist geprüft.',exact:true}).check();await panel.getByRole('button',{name:'Freigabeaktion verbindlich bestätigen',exact:true}).click();};
 const pendingReceipt=config.waitForResponse(response=>new URL(response.url()).pathname===root+'/publications'&&response.request().method()==='POST');await confirm(scope);const pending=await pendingReceipt;assert.equal(pending.status(),201,await pending.text());const requested=await pending.json();assert.equal(requested.requestedBy,kind==='policy'?actors.get('policy-console-config').userId:actors.get('blueprint-console-config').userId);
 assert.equal(await scope.getByRole('button',{name:'Unabhängige Zustimmung prüfen',exact:true}).count(),0);
 await reviewFirstFactor(reviewPage,reviewerName);await login(reviewPage,reviewerName);await reviewPage.goto(origin+'/'+plural);
 if(kind==='blueprint')await reviewPage.getByRole('article').filter({hasText:id}).getByRole('button',{name:'Blueprint laden',exact:true}).click();
 const panel=kind==='policy'?reviewPage.getByRole('article').filter({hasText:id}).getByRole('region',{name:'Unabhängige Richtlinienfreigabe',exact:true}):reviewPage.getByRole('region',{name:'Unabhängige Richtlinienfreigabe',exact:true});
 await panel.getByRole('button',{name:'Freigaberahmen laden',exact:true}).click();await panel.getByRole('button',{name:'Unabhängige Zustimmung prüfen',exact:true}).click();
 assert.equal(await reviewPage.getByRole('button',{name:kind==='policy'?'Richtlinienentwurf prüfen':'Teilkonfiguration prüfen',exact:true}).count(),0);
 await panel.getByText('Vollständigen Inhalt und Zielumfang prüfen',{exact:true}).click();await panel.getByRole('group',{name:'Unabhängige Freigabe bestätigen',exact:true}).scrollIntoViewIfNeeded();await reviewPage.screenshot({path:path.join(os.tmpdir(),'od-policy40-publication-'+kind+'.png'),fullPage:true});
 const approvedReceipt=reviewPage.waitForResponse(response=>new URL(response.url()).pathname===root+'/publications/'+requested.id+'/decisions');await confirm(panel);const approved=await approvedReceipt;assert.equal(approved.status(),200,await approved.text());const row=await approved.json();assert.equal(row.decidedBy,actors.get(reviewerName).userId);
 await scope.getByRole('button',{name:'Freigaberahmen laden',exact:true}).click();await scope.getByRole('button',{name:'Gespeicherte Freigabe auswählen',exact:true}).click();return{row,reviewPanel:panel,confirm};
}
test('the actual policy console replaces sample success with canonical fresh-MFA writes and a separately read-only operator', { timeout: 180000 }, async () => {
  const configContext = await context(); const readerContext = await context(); const reviewContext=await context();
  try {
    const config = await configContext.newPage(); await reviewFirstFactor(config, 'policy-console-config'); await login(config, 'policy-console-config');
    await config.goto(origin + '/policies'); const panel = config.getByRole('region', { name: 'Kanonische Richtlinienverwaltung', exact: true });
    await panel.getByRole('heading', { name: 'Richtlinien & Berechtigungen', exact: true }).waitFor();
    await panel.getByLabel('Name der Richtlinie', { exact: true }).fill('Actual browser-owned canonical policy');
    await panel.getByLabel('Einstellungen (JSON)', { exact: true }).fill(JSON.stringify({ screenLock: { minutes: 5 }, firewall: true }));
    await panel.getByRole('button', { name: 'Richtlinienentwurf prüfen', exact: true }).click();
    assert.equal(await panel.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen', exact: true }).isEnabled(), false);
    await panel.getByRole('checkbox', { name: 'Richtlinie, Aktion und Umfang geprüft.', exact: true }).check();
    await panel.getByLabel('Begründung der Richtlinienänderung', { exact: true }).fill('Actual browser-owned exact draft creation');
    await panel.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen', exact: true }).click();
    await panel.getByText('Richtlinienentwurf im kanonischen Dienst bestätigt.', { exact: true }).waitFor();
    const row = (await policyDb.query('SELECT * FROM policies WHERE name=$1', ['Actual browser-owned canonical policy'])).rows[0]; assert.ok(row); assert.equal(row.status, 'draft'); assert.equal(row.created_by, actors.get('policy-console-config').userId);
    const article = panel.locator('article').filter({ hasText: row.id });assert.equal(await article.getByRole('button',{name:'Aktivierung prüfen',exact:true}).isDisabled(),true);
    await browserPublication(config,await reviewContext.newPage(),'policy',row.id,'policy-console-reviewer');await article.getByRole('button', { name: 'Aktivierung prüfen', exact: true }).click();
    await panel.getByLabel('Begründung der Richtlinienänderung', { exact: true }).fill('Actual browser-owned exact version activation');
    await panel.getByRole('checkbox', { name: 'Richtlinie, Aktion und Umfang geprüft.', exact: true }).check(); await panel.getByRole('button', { name: 'Richtlinienänderung verbindlich bestätigen', exact: true }).click();
    await panel.getByText('Gespeicherter Richtlinienstatus bestätigt. Keine Geräteausführung bestätigt.', { exact: true }).waitFor();
    assert.equal((await policyDb.query('SELECT status FROM policies WHERE id=$1', [row.id])).rows[0].status, 'active');
    const reader = await readerContext.newPage(); await login(reader, 'policy-console-read'); await reader.goto(origin + '/policies');
    await reader.getByRole('heading', { name: row.name, exact: true }).waitFor(); assert.equal(await reader.getByRole('button', { name: 'Deaktivierung prüfen', exact: true }).count(), 0); assert.equal(await reader.getByLabel('Name der Richtlinie', { exact: true }).count(), 0);
    const token = (await mediated(reader)).body.access_token;
    const denied = await reader.request.post(origin + '/api/policies/' + row.id + '/deactivate', { headers: { Authorization: 'Bearer ' + token }, data: { roles: ['admin'] } }); assert.equal(denied.status(), 403);
    assert.equal(await reader.getByText('Default Domain Policy', { exact: true }).count(), 0);
    await panel.evaluate(element => { element.scrollTop = 0; }); await panel.getByRole('heading', { name: 'Richtlinien & Berechtigungen', exact: true }).scrollIntoViewIfNeeded();
    await config.screenshot({ path: path.join(os.tmpdir(), 'od-policy38-console.png'), fullPage: true });
  } finally { await configContext.close(); await readerContext.close(); await reviewContext.close(); }
});

test('the actual policy client rejects a down-level receiver protocol before sending a privileged write', { timeout: 120000 }, async () => {
 const owner=await context();try{const page=await owner.newPage();await reviewFirstFactor(page,'policy-protocol-config');await login(page,'policy-protocol-config');let writes=0;page.on('request',incoming=>{if(incoming.method()!=='GET'&&new URL(incoming.url()).pathname.startsWith('/api/policies'))writes++;});
 await page.route('**/api/policies/access',route=>route.fulfill({json:{schemaVersion:3,subject:'policy-protocol-config-subject',userId:actors.get('policy-protocol-config').userId,permissions:['policies.read','policies.manage','policies.deploy'],freshMfa:true,writeAuthenticationMaxAgeSeconds:300}}));
 await page.goto(origin+'/policies');await page.getByRole('alert').filter({hasText:'Keine Beispieldaten'}).waitFor();assert.equal(await page.getByRole('button',{name:'Richtlinienentwurf prüfen',exact:true}).count(),0);assert.equal(writes,0);
 }finally{await owner.close();}
});

test('the actual blueprint console binds child changes and delivery to exact durable versions and excludes read-only mutation', { timeout: 180000 }, async () => {
 const configContext=await context();const readerContext=await context();const reviewContext=await context();
 try{const config=await configContext.newPage();await reviewFirstFactor(config,'blueprint-console-config');await login(config,'blueprint-console-config');await config.goto(origin+'/blueprints');const panel=config.getByRole('region',{name:'Versionierte Blueprint-Verwaltung',exact:true});
 await panel.getByLabel('Blueprint-Name',{exact:true}).fill('Actual durable browser blueprint');await panel.getByRole('button',{name:'Blueprint-Erstellung prüfen',exact:true}).click();
 const confirm=async reason=>{if(reason)await panel.getByLabel('Begründung der Blueprint-Änderung',{exact:true}).fill(reason);await panel.getByRole('checkbox',{name:'Blueprint, Elternversion, Aktion und Umfang geprüft.',exact:true}).check();await panel.getByRole('button',{name:'Blueprint-Aktion verbindlich bestätigen',exact:true}).click();};
 await confirm('Actual known blueprint creation with audit');await panel.getByText('Versionierte Blueprint-Änderung mit atomarem Nachweis bestätigt.',{exact:true}).waitFor();
 const row=(await policyDb.query('SELECT * FROM blueprints WHERE name=$1',['Actual durable browser blueprint'])).rows[0];assert.ok(row);assert.equal(row.version,1);assert.equal(row.created_by,actors.get('blueprint-console-config').userId);
 await panel.getByLabel('Konfigurationsname',{exact:true}).fill('Actual screen lock');await panel.getByLabel('Konfigurationsinhalt (JSON)',{exact:true}).fill(JSON.stringify({minutes:5,enabled:true}));await panel.getByRole('button',{name:'Teilkonfiguration prüfen',exact:true}).click();await confirm('Actual exact parent version child configuration');await panel.getByText('Versionierte Blueprint-Änderung mit atomarem Nachweis bestätigt.',{exact:true}).waitFor();assert.equal((await policyDb.query('SELECT version FROM blueprints WHERE id=$1',[row.id])).rows[0].version,2);
 const device='browser-blueprint-'+randomUUID();await issuerDb.query("INSERT INTO enrolled_devices(id,hostname,platform) VALUES($1,'Owned browser blueprint recipient','windows')",[device]);
 await panel.getByLabel('Kanonische Ziel-ID',{exact:true}).fill(device);await panel.getByRole('button',{name:'Zielzuweisung prüfen',exact:true}).click();await confirm('Actual independently captured device target scope');await panel.getByText('Versionierte Blueprint-Änderung mit atomarem Nachweis bestätigt.',{exact:true}).waitFor();assert.equal((await policyDb.query('SELECT version FROM blueprints WHERE id=$1',[row.id])).rows[0].version,3);
 assert.equal(await panel.getByRole('button',{name:'Versionierte Zustellung prüfen',exact:true}).isDisabled(),true);const reviewPage=await reviewContext.newPage();const publication=await browserPublication(config,reviewPage,'blueprint',row.id,'blueprint-console-reviewer');
 await panel.getByRole('button',{name:'Versionierte Zustellung prüfen',exact:true}).click();const delivered=config.waitForResponse(response=>new URL(response.url()).pathname==='/api/blueprints/'+row.id+'/apply');await confirm();const response=await delivered;const deliveredBody=await response.json();assert.equal(response.status(),200,JSON.stringify(deliveredBody));assert.equal(deliveredBody.results[0].policyReceipt.persistence,'committed');await panel.getByText('Zustellstatus queued: 1 vorgemerkte Befehle. Keine Geräteausführung bestätigt.',{exact:true}).waitFor();assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[device])).rows[0].count,1);
 const durable=panel.getByRole('region',{name:'Dauerhafte Geräteaufträge',exact:true});await durable.getByText('Geräteauftrag '+deliveredBody.results[0].commandId+' · Abholfrist '+deliveredBody.results[0].policyReceipt.expiresAt,{exact:true}).waitFor();await durable.scrollIntoViewIfNeeded();await config.screenshot({path:path.join(os.tmpdir(),'od-policy41-receipts.png'),fullPage:false});
 await publication.reviewPanel.getByRole('button',{name:'Freigabe zurückziehen prüfen',exact:true}).click();const withdrawal=reviewPage.waitForResponse(result=>new URL(result.url()).pathname==='/api/blueprints/'+row.id+'/publications/'+publication.row.id+'/decisions');await publication.confirm(publication.reviewPanel);assert.equal((await withdrawal).status(),200);
 await panel.getByRole('button',{name:'Versionierte Zustellung prüfen',exact:true}).click();const stopped=config.waitForResponse(result=>new URL(result.url()).pathname==='/api/blueprints/'+row.id+'/apply');await confirm();assert.equal((await stopped).status(),409);await panel.getByRole('alert').filter({hasText:'nicht blind wiederholen'}).waitFor();assert.equal((await issuerDb.query('SELECT count(*)::int AS count FROM mdm_commands WHERE device_id=$1',[device])).rows[0].count,1);
 await config.reload();await panel.getByRole('heading',{name:row.name,exact:true}).waitFor();await panel.locator('article').filter({hasText:row.id}).getByRole('button',{name:'Blueprint laden',exact:true}).click();
 await durable.getByText('Geräteauftrag '+deliveredBody.results[0].commandId+' · Abholfrist '+deliveredBody.results[0].policyReceipt.expiresAt,{exact:true}).waitFor();await durable.getByRole('button',{name:'Eigenen Geräteauftrag stoppen prüfen',exact:true}).click();
 await durable.getByLabel('Begründung der Auftragsstornierung',{exact:true}).fill('Explicit browser cancellation after independent publication withdrawal');await durable.getByRole('checkbox',{name:'Exakten eigenen Auftrag und Grenze bereits angebotener Geräteaktionen geprüft.',exact:true}).check();
 const cancelledResponse=config.waitForResponse(result=>new URL(result.url()).pathname==='/api/devices/'+device+'/commands/'+deliveredBody.results[0].commandId+'/cancel');await durable.getByRole('button',{name:'Geräteauftrag verbindlich stoppen',exact:true}).click();const cancelled=await cancelledResponse;assert.equal(cancelled.status(),200,await cancelled.text());const cancellation=await cancelled.json();assert.equal(cancellation.furtherOffersStopped,true);assert.equal(cancellation.enforcementConfirmed,false);
 await durable.getByText(/Status cancelled/).waitFor();await durable.scrollIntoViewIfNeeded();await config.screenshot({path:path.join(os.tmpdir(),'od-policy42-cancellation.png'),fullPage:false});assert.equal((await issuerDb.query('SELECT status FROM mdm_commands WHERE id=$1',[deliveredBody.results[0].commandId])).rows[0].status,'cancelled');
 await config.reload();await panel.getByRole('heading',{name:row.name,exact:true}).waitFor();await panel.locator('article').filter({hasText:row.id}).getByRole('button',{name:'Blueprint laden',exact:true}).click();await durable.getByText(/Stornierung .*Explicit browser cancellation/).waitFor();assert.equal(await durable.getByRole('button',{name:'Eigenen Geräteauftrag stoppen prüfen',exact:true}).count(),0);
 const reader=await readerContext.newPage();await login(reader,'blueprint-console-read');await reader.goto(origin+'/blueprints');await reader.getByRole('heading',{name:row.name,exact:true}).waitFor();assert.equal(await reader.getByRole('button',{name:'Blueprint-Erstellung prüfen',exact:true}).count(),0);const article=reader.locator('article').filter({hasText:row.id});await article.getByRole('button',{name:'Blueprint laden',exact:true}).click();await reader.getByText('Actual screen lock',{exact:true}).waitFor();assert.equal(await reader.getByRole('button',{name:'Teilkonfiguration prüfen',exact:true}).count(),0);
 const token=(await mediated(reader)).body.access_token;const denied=await reader.request.delete(origin+'/api/blueprints/'+row.id,{headers:{Authorization:'Bearer '+token,'If-Match':`"od-blueprint:${row.id}:3"`},data:{reason:'Reader cannot delete this configuration',acknowledgeScope:true}});assert.equal(denied.status(),403);
 await panel.evaluate(element=>{element.scrollTop=0;});await panel.getByRole('heading',{name:'Blueprints · exakte Konfigurationsversionen',exact:true}).scrollIntoViewIfNeeded();await config.screenshot({path:path.join(os.tmpdir(),'od-policy39-blueprint.png'),fullPage:true});
 const secondName='Actual overlapping browser blueprint';
 await panel.getByLabel('Blueprint-Name',{exact:true}).fill(secondName);await panel.getByRole('button',{name:'Blueprint-Erstellung prüfen',exact:true}).click();await confirm('Actual second overlapping blueprint creation');await panel.getByText('Versionierte Blueprint-Änderung mit atomarem Nachweis bestätigt.',{exact:true}).waitFor();
 const second=(await policyDb.query('SELECT * FROM blueprints WHERE name=$1',[secondName])).rows[0];assert.ok(second);assert.equal(second.version,1);assert.equal(second.created_by,actors.get('blueprint-console-config').userId);
 const addConfiguration=async(name,minutes,version)=>{
  await panel.getByLabel('Konfigurationsname',{exact:true}).fill(name);await panel.getByLabel('Konfigurationsinhalt (JSON)',{exact:true}).fill(JSON.stringify({minutes,enabled:true}));await panel.getByRole('button',{name:'Teilkonfiguration prüfen',exact:true}).click();
  const accepted=config.waitForResponse(result=>new URL(result.url()).pathname==='/api/blueprints/'+second.id+'/configurations'&&result.request().method()==='POST');await confirm('Actual overlapping complete screen lock configuration');const result=await accepted;assert.equal(result.status(),201,await result.text());assert.equal((await result.json()).parentVersion,version);await panel.getByText('Versionierte Blueprint-Änderung mit atomarem Nachweis bestätigt.',{exact:true}).waitFor();assert.equal((await policyDb.query('SELECT version FROM blueprints WHERE id=$1',[second.id])).rows[0].version,version);
 };
 await addConfiguration('Actual overlapping screen lock',5,2);
 const originalConfiguration=(await policyDb.query('SELECT id,payload::text AS payload_json FROM blueprint_configurations WHERE blueprint_id=$1',[row.id])).rows;const matchingConfiguration=(await policyDb.query('SELECT id,payload::text AS payload_json FROM blueprint_configurations WHERE blueprint_id=$1',[second.id])).rows;assert.equal(originalConfiguration.length,1);assert.equal(matchingConfiguration.length,1);assert.equal(matchingConfiguration[0].payload_json,originalConfiguration[0].payload_json);
 const matchingSources=[{blueprintId:row.id,configurationId:originalConfiguration[0].id},{blueprintId:second.id,configurationId:matchingConfiguration[0].id}].sort((left,right)=>`${left.blueprintId}:${left.configurationId}`.localeCompare(`${right.blueprintId}:${right.configurationId}`));
 const previewEvidence=async()=>({
  policy:(await policyDb.query('SELECT (SELECT count(*)::int FROM policy_configuration_audit) AS configuration_audit,(SELECT count(*)::int FROM policy_configuration_outbox) AS configuration_outbox,(SELECT count(*)::int FROM policy_publication_audit) AS publication_audit,(SELECT count(*)::int FROM policy_publication_outbox) AS publication_outbox,(SELECT count(*)::int FROM license_assignments) AS license_assignments')).rows[0],
  commands:(await issuerDb.query('SELECT id,status FROM mdm_commands WHERE device_id=$1 ORDER BY id',[device])).rows,
  commandEvidence:(await issuerDb.query('SELECT (SELECT count(*)::int FROM policy_device_operations) AS operations,(SELECT count(*)::int FROM policy_device_command_audit) AS audit,(SELECT count(*)::int FROM policy_device_command_outbox) AS outbox,(SELECT count(*)::int FROM policy_device_cancellations) AS cancellations')).rows[0],
 });
 const compareSelected=async(selection)=>{
  await reader.reload();await reader.getByRole('heading',{name:secondName,exact:true}).waitFor();const comparison=reader.getByRole('region',{name:'Ausgewählte Blueprint-Versionen vergleichen',exact:true});await comparison.getByRole('button',{name:'Ausgewählte Blueprint-Versionen vergleichen',exact:true}).click();await comparison.getByLabel('Vorschau-Plattform',{exact:true}).selectOption('windows');
  for(const selected of selection){const item=comparison.getByRole('listitem').filter({hasText:selected.id});assert.ok((await item.innerText()).includes('Version '+selected.version));await item.getByRole('checkbox').check();}
  const received=reader.waitForResponse(result=>new URL(result.url()).pathname==='/api/blueprints/preview'&&result.request().method()==='POST');await comparison.getByRole('button',{name:'Vorschau berechnen',exact:true}).click();const result=await received;assert.deepEqual(result.request().postDataJSON(),{platform:'windows',blueprints:selection});assert.equal(result.status(),200,await result.text());return result.json();
 };
 await reader.setViewportSize({width:1440,height:1200});const beforeMatchingPreview=await previewEvidence();assert.deepEqual(beforeMatchingPreview.commands,[{id:deliveredBody.results[0].commandId,status:'cancelled'}]);
 const matchingPreview=await compareSelected([{id:row.id,version:3},{id:second.id,version:2}]);
 assert.deepEqual(matchingPreview,{schemaVersion:1,scope:'selected-blueprint-versions',comparison:'whole-config-type',platform:'windows',previewOnly:true,enforcementConfirmed:false,licenseReservations:0,blueprints:[{id:row.id,name:row.name,platform:'all',version:3},{id:second.id,name:secondName,platform:'all',version:2}],configurationCount:2,hasConflicts:false,effectiveConfigurations:[{configType:'screen_lock',payloadJson:originalConfiguration[0].payload_json,sources:matchingSources}],conflicts:[]});
 const previewResult=reader.getByRole('region',{name:'Bestätigte Auswahlvorschau',exact:true});await previewResult.getByText('Keine Konflikte innerhalb dieser Auswahl. Keine Aussage über weitere Zuweisungen.',{exact:true}).waitFor();const effective=previewResult.getByRole('region',{name:'Nicht widersprüchliche Konfigurationsarten',exact:true});assert.equal(await effective.getByRole('article').count(),1);assert.equal(await effective.getByRole('listitem').count(),2);await effective.getByText('Unverändertes Konfigurations-JSON anzeigen',{exact:true}).click();assert.equal(await effective.locator('pre').innerText(),originalConfiguration[0].payload_json);await previewResult.evaluate(element=>element.scrollIntoView({block:'start'}));await reader.screenshot({path:'/tmp/od-business20-blueprint-preview.png',fullPage:false});assert.deepEqual(await previewEvidence(),beforeMatchingPreview);
 await addConfiguration('Actual contradictory screen lock',10,3);const beforeConflictPreview=await previewEvidence();assert.equal(beforeConflictPreview.policy.configuration_audit,beforeMatchingPreview.policy.configuration_audit+1);assert.equal(beforeConflictPreview.policy.configuration_outbox,beforeMatchingPreview.policy.configuration_outbox+1);assert.deepEqual(beforeConflictPreview.commands,beforeMatchingPreview.commands);assert.deepEqual(beforeConflictPreview.commandEvidence,beforeMatchingPreview.commandEvidence);
 const conflictingConfiguration=(await policyDb.query('SELECT id,payload::text AS payload_json FROM blueprint_configurations WHERE blueprint_id=$1 AND id<>$2',[second.id,matchingConfiguration[0].id])).rows;assert.equal(conflictingConfiguration.length,1);
 const conflictPreview=await compareSelected([{id:row.id,version:3},{id:second.id,version:3}]);assert.equal(conflictPreview.previewOnly,true);assert.equal(conflictPreview.enforcementConfirmed,false);assert.equal(conflictPreview.licenseReservations,0);assert.equal(conflictPreview.configurationCount,3);assert.equal(conflictPreview.hasConflicts,true);assert.deepEqual(conflictPreview.blueprints,[{id:row.id,name:row.name,platform:'all',version:3},{id:second.id,name:secondName,platform:'all',version:3}]);assert.deepEqual(conflictPreview.effectiveConfigurations,[]);assert.equal(conflictPreview.conflicts.length,1);assert.equal(conflictPreview.conflicts[0].configType,'screen_lock');assert.equal(conflictPreview.conflicts[0].variants.length,2);
 assert.deepEqual(conflictPreview.conflicts[0].variants.find(variant=>variant.payloadJson===originalConfiguration[0].payload_json),{payloadJson:originalConfiguration[0].payload_json,sources:matchingSources});assert.deepEqual(conflictPreview.conflicts[0].variants.find(variant=>variant.payloadJson===conflictingConfiguration[0].payload_json),{payloadJson:conflictingConfiguration[0].payload_json,sources:[{blueprintId:second.id,configurationId:conflictingConfiguration[0].id}]});
 await previewResult.getByText('Konflikte in 1 Konfigurationsarten. Keine automatische Auflösung.',{exact:true}).waitFor();assert.equal(await effective.getByRole('article').count(),0);await effective.getByText('Keine nicht widersprüchlichen Konfigurationsarten in dieser Auswahl.',{exact:true}).waitFor();const conflicts=previewResult.getByRole('region',{name:'Konflikte der Auswahl',exact:true});assert.equal(await conflicts.getByRole('article').count(),1);assert.equal(await conflicts.getByRole('listitem').count(),3);assert.equal(await conflicts.getByText('Unverändertes Konfigurations-JSON anzeigen',{exact:true}).count(),2);for(const summary of await conflicts.getByText('Unverändertes Konfigurations-JSON anzeigen',{exact:true}).all())await summary.click();assert.deepEqual((await conflicts.locator('pre').allInnerTexts()).sort(),[originalConfiguration[0].payload_json,conflictingConfiguration[0].payload_json].sort());await previewResult.evaluate(element=>element.scrollIntoView({block:'start'}));await reader.screenshot({path:'/tmp/od-business20-blueprint-conflicts.png',fullPage:false});assert.deepEqual(await previewEvidence(),beforeConflictPreview);
 const readerProof=await mediated(reader);assert.equal(readerProof.status,200);const stale=await reader.request.post(origin+'/api/blueprints/preview',{headers:{Authorization:'Bearer '+readerProof.body.access_token},data:{platform:'windows',blueprints:[{id:row.id,version:3},{id:second.id,version:2}]}});assert.equal(stale.status(),412,await stale.text());assert.deepEqual(await stale.json(),{error:'policy_configuration_changed'});
 const configProof=await mediated(config);assert.equal(configProof.status,200);const blocked=await config.request.post(origin+'/api/blueprints/'+second.id+'/apply',{headers:{Authorization:'Bearer '+configProof.body.access_token,'If-Match':`"od-blueprint:${second.id}:3"`},data:{acknowledgeScope:true}});assert.equal(blocked.status(),409,await blocked.text());assert.deepEqual(await blocked.json(),{error:'blueprint_configuration_conflict'});assert.deepEqual(await previewEvidence(),beforeConflictPreview);assert.equal((await policyDb.query('SELECT version FROM blueprints WHERE id=$1',[row.id])).rows[0].version,3);assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM policy_publications WHERE resource_kind=$1 AND resource_id=$2',['blueprint',second.id])).rows[0].count,0);
 }finally{await configContext.close();await readerContext.close();await reviewContext.close();}
});

test('the actual source consent console requires fresh MFA and exact client generation, grants no license or secret, and separately permits metadata reading',{timeout:180000},async()=>{
 const adminContext=await context();const configContext=await context();const readerContext=await context();const assignmentsBefore=(await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE assignee_id=$1',[readerUser])).rows[0].count;
 try{
 const admin=await adminContext.newPage();await login(admin,'administrator');const token=(await mediated(admin)).body.access_token;
 const client=await issuerJson('/api/clients',{method:'POST',token,body:{name:'Browser-owned dedicated group source',enabled:true,grantTypes:['client_credentials'],scopes:['licenses.groups.derive'],redirectUris:[]}});assert.equal(client.status,201,JSON.stringify(client.body));
 const groupId=randomUUID();await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Browser consented license source')",[groupId],'owned-source-console');await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[groupId,readerUser],'owned-source-console');
 const config=await configContext.newPage();await reviewFirstFactor(config,'source-console-config');await login(config,'source-console-config');await config.goto(origin+'/licenses');const panel=config.getByRole('region',{name:'Service-Lesefreigaben für Lizenzgruppen',exact:true});
 await panel.getByLabel('Servicefreigabe-Gruppen-ID',{exact:true}).fill(groupId);await panel.getByRole('button',{name:'Gruppen-Servicefreigaben laden',exact:true}).click();await panel.getByText(/0 bekannte Freigaben/).waitFor();
 await panel.getByLabel('Servicefreigabe-Client-ID',{exact:true}).fill(client.body.clientId);await panel.getByRole('button',{name:'Service-Client prüfen',exact:true}).click();await panel.getByText(/Dedizierter Gruppen-Nachweisleser/).waitFor();
 await panel.getByRole('button',{name:'Service-Lesefreigabe erstellen prüfen',exact:true}).click();assert.equal(await panel.getByRole('button',{name:'Service-Lesefreigabe verbindlich bestätigen',exact:true}).isDisabled(),true);
 await panel.getByLabel('Begründung der Service-Lesefreigabe',{exact:true}).fill('Explicit actual browser consent for a known group and client generation');await panel.getByLabel('Exakte Gruppe, Client-Fassung, Lesebereich und Ablauf geprüft.',{exact:true}).check();await panel.getByLabel('Begründung der Service-Lesefreigabe',{exact:true}).scrollIntoViewIfNeeded();await config.screenshot({path:path.join(os.tmpdir(),'od-group-source-consent.png'),fullPage:false});
 const receipt=config.waitForResponse(response=>new URL(response.url()).pathname==='/api/identity/license-sources'&&response.request().method()==='POST');await panel.getByRole('button',{name:'Service-Lesefreigabe verbindlich bestätigen',exact:true}).click();const created=await receipt;assert.equal(created.status(),201,await created.text());const grant=await created.json();assert.equal(grant.clientRevision,client.body.version);await panel.getByText(/Begrenzte Service-Lesefreigabe bestätigt/).waitFor();
 const machine=await issuerJson('/oauth/token',{method:'POST',body:{grant_type:'client_credentials',client_id:client.body.clientId,client_secret:client.body.clientSecret,scope:'licenses.groups.derive'}});assert.equal(machine.status,200);
 const read=await fetch(identityBase+'/api/license-groups/'+groupId+'/snapshot',{headers:{Authorization:'Bearer '+machine.body.access_token}});assert.equal(read.status,200);assert.equal((await read.json()).sourceAuthorization.grantId,grant.id);
 const reader=await readerContext.newPage();await login(reader,'source-console-reader');await reader.goto(origin+'/licenses');const metadata=reader.getByRole('region',{name:'Service-Lesefreigaben für Lizenzgruppen',exact:true});await metadata.getByLabel('Servicefreigabe-Gruppen-ID',{exact:true}).fill(groupId);await metadata.getByRole('button',{name:'Gruppen-Servicefreigaben laden',exact:true}).click();await metadata.getByRole('article').filter({hasText:grant.id}).waitFor();assert.equal(await metadata.getByRole('button',{name:'Service-Lesefreigabe erstellen prüfen',exact:true}).count(),0);assert.equal(await metadata.getByRole('button',{name:'Service-Lesefreigabe entziehen prüfen',exact:true}).count(),0);
 await panel.getByRole('article').filter({hasText:grant.id}).getByRole('button',{name:'Service-Lesefreigabe entziehen prüfen',exact:true}).click();assert.equal(await panel.getByLabel('Exakte Gruppe, Client-Fassung, Lesebereich und Ablauf geprüft.',{exact:true}).isChecked(),false);await panel.getByLabel('Begründung der Service-Lesefreigabe',{exact:true}).fill('Explicit browser withdrawal of only this workload read consent');await panel.getByLabel('Exakte Gruppe, Client-Fassung, Lesebereich und Ablauf geprüft.',{exact:true}).check();
 const withdrawal=config.waitForResponse(response=>new URL(response.url()).pathname==='/api/identity/license-sources/'+grant.id+'/revoke');await panel.getByRole('button',{name:'Service-Lesefreigabe verbindlich bestätigen',exact:true}).click();assert.equal((await withdrawal).status(),200);await panel.getByText(/Service-Lesefreigabe entzogen/).waitFor();
 assert.equal((await fetch(identityBase+'/api/license-groups/'+groupId+'/snapshot',{headers:{Authorization:'Bearer '+machine.body.access_token}})).status,403);
 const storage=await config.evaluate(()=>JSON.stringify([Object.values(localStorage),Object.values(sessionStorage)]));assert.equal(storage.includes(client.body.clientSecret)||storage.includes(machine.body.access_token),false);
 assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE assignee_id=$1',[readerUser])).rows[0].count,assignmentsBefore);
 }finally{await adminContext.close();await configContext.close();await readerContext.close();}
});
test('real license source confirmation uses actual fresh MFA, exact local grant versions and preserves overlapping entitlement', { timeout: 180000 }, async () => {
  const owned = await context();
  const json = async (base, route, token, method = 'GET', body) => {
    const response = await fetch(base + route, { method, headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
  };
  try {
    const page = await owned.newPage(); const username = 'license-grant-manager';
    await identityDb.write("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE user_id=$1 AND role='license-manager' AND revoked_at IS NULL", [actors.get(username).userId], 'fixture-source-policy-generation');
    await identityDb.write("INSERT INTO identity_role_assignments(user_id,role,reason) VALUES($1,'license-manager','Fresh fixture grant after prior activation policy tests')", [actors.get(username).userId], 'fixture-source-policy-generation');
    await login(page, username);
    const initial = (await mediated(page)).body.access_token;
    const setup = await json(issuerBase, '/api/mfa/enroll', initial, 'POST', { username, password: 'disposable-password' }); assert.equal(setup.status, 200);
    const counter = Math.floor(Date.now() / 30000) - 1;
    assert.equal((await json(issuerBase, '/api/mfa/confirm', initial, 'POST', { code: totp(setup.body.secret, counter) })).status, 200);
    rememberFactor(username, setup.body.secret, counter); await login(page, username); const token = (await mediated(page)).body.access_token;
    const license = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser source review pool',3) RETURNING id")).rows[0];
    const groupId = randomUUID(); const recipient = actors.get('reader').userId;
    await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Browser source review team')", [groupId], 'fixture-license-group');
    await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, recipient], 'fixture-license-group');
    for (const type of ['group', 'user']) {
      const allocated = await json(policyBase, `/api/licenses/${license.id}/assign`, token, 'POST', { assignee_type: type, assignee_id: type === 'group' ? groupId : recipient });
      assert.equal(allocated.status, 201, JSON.stringify(allocated.body));
    }
    await page.goto(origin + '/licenses'); const row = page.getByText('Browser source review pool · Browser source review team').locator('..');
    await row.getByText(/Verzeichnis gültig bis:/).waitFor();const leaseBefore=(await policyDb.query('SELECT * FROM license_group_observations WHERE license_id=$1',[license.id])).rows[0];
    await policyDb.query("CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '301 seconds'; $$");
    try{await page.reload();await row.getByText('Verzeichnisnachweis abgelaufen',{exact:true}).waitFor();await row.getByText('0 / 1 Mitglieder',{exact:true}).waitFor();await row.scrollIntoViewIfNeeded();await page.screenshot({path:path.join(os.tmpdir(),'od-group-directory-lease.png'),fullPage:false});assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_assignments WHERE license_id=$1 AND (expires_at IS NULL OR expires_at>license_now())',[license.id])).rows[0].count,1);}
    finally{await policyDb.query('CREATE OR REPLACE FUNCTION license_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');}
    const renewal=page.waitForResponse(response=>new URL(response.url()).pathname===`/api/licenses/${license.id}/groups/${groupId}/reconcile`);await row.getByRole('button',{name:'Abgleichen',exact:true}).click();assert.equal((await renewal).status(),200);await row.getByText('Aktiv',{exact:true}).waitFor();assert.ok((await policyDb.query('SELECT valid_until FROM license_group_observations WHERE license_id=$1',[license.id])).rows[0].valid_until>leaseBefore.valid_until);
    await row.getByRole('button', { name: 'Gruppenquelle entziehen' }).click();
    const dialog = page.getByRole('dialog', { name: 'Lizenzquelle gezielt entziehen' }); await dialog.getByText(/Ganze Gruppenregel/).waitFor();
    assert.equal(await dialog.getByRole('button', { name: 'Geprüfte Quelle entziehen' }).isDisabled(), true);
    await dialog.getByLabel('Begründung (10–500 Zeichen)').fill('Actual independent browser source withdrawal');
    await dialog.getByLabel('Ich bestätige den Entzug dieser Quelle und Version.').check();
    await page.screenshot({ path: path.join(os.tmpdir(), 'od-license-source.png'), fullPage: false });
    const receipt = page.waitForResponse(response => /\/grants\/[^/]+\/revoke$/.test(new URL(response.url()).pathname));
    await dialog.getByRole('button', { name: 'Geprüfte Quelle entziehen' }).click(); const withdrawn = await receipt; assert.equal(withdrawn.status(), 200);
    const result = await withdrawn.json(); assert.equal(result.localOnly, true); assert.equal(result.usersRetainingAssignment, 1);
    await dialog.waitFor({ state: 'detached' });
    assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1', [license.id])).rows[0].used_seats, 1);
    const events = await policyDb.query('SELECT * FROM license_grant_events WHERE grant_id=$1 ORDER BY version DESC LIMIT 1', [result.grant.id]);
    assert.equal(events.rows[0].actor_user_id, actors.get(username).userId);
    assert.equal((await json(policyBase, `/api/licenses/${license.id}/groups/${groupId}/reconcile`, token, 'POST')).body.rule.enabled, false);
  } finally { await owned.close(); }
});

test('real license review console separates configuration, independent group withdrawal and read-only source evidence', { timeout: 180000 }, async () => {
  const configContext = await context(); const voterContext = await context(); const readerContext = await context(); const adminContext = await context();
  try {
    const admin = await adminContext.newPage(); await login(admin, 'administrator'); const token = (await mediated(admin)).body.access_token;
    const poolId = (await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser recurring review pool',3) RETURNING id")).rows[0].id;
    const groupId = randomUUID(); const recipient = actors.get('reader').userId;
    await identityDb.write("INSERT INTO groups(id,name) VALUES($1,'Browser reviewed license team')", [groupId], 'fixture-reviewed-team');
    await identityDb.write('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)', [groupId, recipient], 'fixture-reviewed-team');
    for (const type of ['group', 'user']) {
      const result = await fetch(policyBase + `/api/licenses/${poolId}/assign`, { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ assignee_type: type, assignee_id: type === 'group' ? groupId : recipient }) });
      assert.equal(result.status, 201);
    }
    const config = await configContext.newPage(); await reviewFirstFactor(config, 'license-review-config'); await login(config, 'license-review-config'); await config.goto(origin + '/licenses');
    const panel = config.getByRole('region', { name: 'Wiederkehrende Lizenzprüfungen' }); await panel.getByLabel('Bekannte Lizenzpool-ID', { exact: true }).fill(poolId);
    await panel.getByRole('button', { name: 'Lizenzprüfrichtlinie laden', exact: true }).click(); await panel.getByText('Keine Richtlinie für diesen Pool').waitFor();
    const voter = await voterContext.newPage(); await reviewFirstFactor(voter, 'license-review-voter'); await login(voter, 'license-review-voter');
    await panel.getByLabel('Unabhängige Prüfer-IDs (kommagetrennt)', { exact: true }).fill(actors.get('license-review-voter').userId);
    await panel.getByLabel('Antwortfenster in Minuten', { exact: true }).fill('1'); await panel.getByLabel('Begründung der Richtlinie', { exact: true }).fill('Real browser recurring recipient certification');
    await panel.getByLabel('Fristen und Entzug geprüft; Stilllegen hebt bestehende Fristen nicht auf.', { exact: true }).check();
    const creation = config.waitForResponse(response => new URL(response.url()).pathname === '/api/licenses/reviews/policies' && response.request().method() === 'POST');
    await panel.getByRole('button', { name: 'Lizenzprüfrichtlinie verbindlich erstellen', exact: true }).click(); const created = await creation; assert.equal(created.status(), 201);
    await voter.goto(origin + '/licenses'); const votes = voter.getByRole('region', { name: 'Wiederkehrende Lizenzprüfungen' });
    await votes.getByRole('button', { name: 'Meine Lizenzprüfungen laden', exact: true }).click();
    await votes.getByRole('button', { name: `Ganze Gruppe · ${groupId} · pending`, exact: true }).click();
    await votes.getByRole('button', { name: 'Lizenzquelle entziehen prüfen', exact: true }).click(); await votes.getByLabel('Begründung der Lizenzentscheidung', { exact: true }).fill('Real independently reviewed whole group source withdrawal');
    await votes.getByLabel('Quelle, Versionen, Frist und unabhängige Wirkung geprüft.', { exact: true }).check();
    await votes.scrollIntoViewIfNeeded(); await voter.screenshot({ path: path.join(os.tmpdir(), 'od-license-review.png'), fullPage: false });
    const receipt = voter.waitForResponse(response => /\/api\/licenses\/reviews\/[^/]+\/decisions$/.test(new URL(response.url()).pathname));
    await votes.getByRole('button', { name: 'Lizenzentscheidung verbindlich bestätigen', exact: true }).click(); const result = await receipt; assert.equal(result.status(), 200); const denied = await result.json(); assert.equal(denied.state, 'denied');
    assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1', [poolId])).rows[0].used_seats, 1);
    const read = await readerContext.newPage(); await login(read, 'license-review-reader'); await read.goto(origin + '/licenses'); const readPanel = read.getByRole('region', { name: 'Wiederkehrende Lizenzprüfungen' });
    await readPanel.getByLabel('Bekannte Lizenzprüfungs-ID', { exact: true }).fill(denied.id); await readPanel.getByRole('button', { name: 'Lizenzprüfung laden', exact: true }).click(); await readPanel.getByText(`Ganze Gruppe · ${groupId} · denied`, { exact: true }).waitFor();
    assert.equal(await readPanel.getByRole('button', { name: /Lizenzquelle .* prüfen/ }).count(), 0); assert.equal(await readPanel.getByLabel('Unabhängige Prüfer-IDs (kommagetrennt)', { exact: true }).count(), 0);
  } finally { await configContext.close(); await voterContext.close(); await readerContext.close(); await adminContext.close(); }
});

test('real membership governance console requires an independent first grant, shows own effective cutoffs and withdraws actual group authority',{timeout:180000},async()=>{
 const configContext=await context();const voterContext=await context();const grantContext=await context();const holderContext=await context();const readerContext=await context();
 try{
  const grantor=await grantContext.newPage();await login(grantor,'membership-grantor');const weak=(await mediated(grantor)).body.access_token;const setup=await fetch(issuerBase+'/api/mfa/enroll',{method:'POST',headers:{Authorization:'Bearer '+weak,'Content-Type':'application/json'},body:JSON.stringify({username:'membership-grantor',password:'disposable-password'})});assert.equal(setup.status,200);const enrollment=await setup.json();const counter=Math.floor(Date.now()/30000)-1;assert.equal((await fetch(issuerBase+'/api/mfa/confirm',{method:'POST',headers:{Authorization:'Bearer '+weak,'Content-Type':'application/json'},body:JSON.stringify({code:totp(enrollment.secret,counter)})})).status,200);rememberFactor('membership-grantor',enrollment.secret,counter);await grantContext.clearCookies();await login(grantor,'membership-grantor');const grantToken=(await mediated(grantor)).body.access_token;
  const created=await fetch(identityBase+'/api/groups',{method:'POST',headers:{Authorization:'Bearer '+grantToken,'Content-Type':'application/json'},body:JSON.stringify({name:'Browser independently approved membership team'})});assert.equal(created.status,201);const groupId=(await created.json()).id;const config=await configContext.newPage();await reviewFirstFactor(config,'membership-config');await login(config,'membership-config');await config.goto(origin+'/roles');const panel=config.getByRole('region',{name:'Gruppenmitgliedschafts-Prüfung',exact:true});await panel.getByLabel('Prüfregel-Gruppen-ID',{exact:true}).fill(groupId);const loadResponse=config.waitForResponse(value=>new URL(value.url()).pathname==='/api/identity/membership-reviews/policies/groups/'+groupId);await panel.getByRole('button',{name:'Gruppenprüfregel laden',exact:true}).click();const loaded=await loadResponse;assert.equal(loaded.status(),200,await loaded.text());await panel.getByText('Keine Gruppenprüfregel vorhanden.',{exact:true}).waitFor();await panel.getByLabel('Gruppen-Prüfzyklus in Minuten',{exact:true}).fill('10');await panel.getByLabel('Gruppen-Antwortfenster in Minuten',{exact:true}).fill('5');await panel.getByLabel('Unabhängige Gruppen-Prüfer (UUIDs)',{exact:true}).fill(actors.get('membership-voter').userId);
  const voter=await voterContext.newPage();await reviewFirstFactor(voter,'membership-voter');await login(voter,'membership-voter');await panel.getByRole('button',{name:'Gruppenprüfregel erstellen prüfen',exact:true}).click();const base='/api/identity/membership-reviews';
  const confirm=async(page,control,endpoint,status)=>{await control.getByLabel('Begründung der Gruppenprüfung',{exact:true}).fill('Independent actual browser membership and application/license effects');await control.getByLabel('Unabhängigkeit, Mitgliedschaftsversion und App-/Lizenzwirkung geprüft.',{exact:true}).check();const response=page.waitForResponse(value=>new URL(value.url()).pathname===endpoint&&value.request().method()==='POST');await control.getByRole('button',{name:'Gruppenprüfung verbindlich bestätigen',exact:true}).click();const result=await response;assert.equal(result.status(),status);const row=await result.json();await control.getByRole('status').waitFor();return row;};const policy=await confirm(config,panel,base+'/policies',201);
  assert.equal((await fetch(identityBase+'/api/groups/'+groupId+'/members',{method:'POST',headers:{Authorization:'Bearer '+grantToken,'Content-Type':'application/json','If-Match':await currentGroupTag(groupId)},body:JSON.stringify({userId:actors.get('membership-holder').userId})})).status,200);const source=new(require('../../../identity-service/src/GroupSnapshotStore').GroupSnapshotStore)(identityDb);assert.deepEqual((await source.snapshot(groupId)).memberIds,[]);
  const holder=await holderContext.newPage();await login(holder,'membership-holder');await holder.goto(origin+'/roles');const own=holder.getByRole('region',{name:'Gruppenmitgliedschafts-Prüfung',exact:true});await own.getByRole('button',{name:'Meine Gruppenprüffristen laden',exact:true}).click();await own.getByRole('article').filter({hasText:'awaiting'}).waitFor();assert.equal(await own.getByRole('button',{name:'Gruppenmitgliedschaft freigeben prüfen',exact:true}).count(),0);
  await voter.goto(origin+'/roles');const queue=voter.getByRole('region',{name:'Gruppenmitgliedschafts-Prüfung',exact:true});await queue.getByRole('button',{name:'Zugewiesene Gruppenprüfungen laden',exact:true}).click();const entry=queue.getByRole('article').filter({hasText:groupId});await entry.getByRole('button',{name:'Gruppenmitgliedschaft freigeben prüfen',exact:true}).click();await queue.getByLabel('Begründung der Gruppenprüfung',{exact:true}).fill('Independent first membership approval, not original grantor self-certification');await queue.getByLabel('Begründung der Gruppenprüfung',{exact:true}).scrollIntoViewIfNeeded();await voter.screenshot({path:path.join(os.tmpdir(),'od-group-membership-review.png'),fullPage:false});
  const reviewId=(await identityDb.query('SELECT lease.id FROM identity_membership_review_leases lease JOIN identity_membership_origins origin ON origin.membership_id=lease.membership_id WHERE origin.group_id=$1',[groupId])).rows[0].id;const retained=await confirm(voter,queue,base+'/'+reviewId+'/decisions',200);assert.equal(retained.effective,true);assert.deepEqual((await source.snapshot(groupId)).memberIds,[actors.get('membership-holder').userId]);
  await identityDb.query("CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '601 seconds'; $$");await queue.getByRole('button',{name:'Zugewiesene Gruppenprüfungen laden',exact:true}).click();await queue.getByRole('article').filter({hasText:reviewId}).getByRole('button',{name:'Gruppenmitgliedschaft entziehen prüfen',exact:true}).click();assert.equal(await queue.getByLabel('Unabhängigkeit, Mitgliedschaftsversion und App-/Lizenzwirkung geprüft.',{exact:true}).isChecked(),false);const denied=await confirm(voter,queue,base+'/'+reviewId+'/decisions',200);assert.equal(denied.state,'denied');assert.deepEqual((await source.snapshot(groupId)).memberIds,[]);assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM group_members WHERE group_id=$1',[groupId])).rows[0].count,0);
  const reader=await readerContext.newPage();await login(reader,'membership-reader');await reader.goto(origin+'/roles');const read=reader.getByRole('region',{name:'Gruppenmitgliedschafts-Prüfung',exact:true});await read.getByLabel('Bekannte Gruppenprüfungs-ID',{exact:true}).fill(reviewId);await read.getByRole('button',{name:'Bekannte Gruppenprüfung laden',exact:true}).click();await read.getByRole('article').filter({hasText:'denied'}).waitFor();assert.equal(await read.getByRole('button',{name:/Gruppenmitgliedschaft .* prüfen/}).count(),0);await panel.getByRole('button',{name:'Gruppenprüfregel stilllegen prüfen',exact:true}).click();await confirm(config,panel,base+'/policies/'+policy.id+'/retire',200);
 }finally{await identityDb.query('CREATE OR REPLACE FUNCTION identity_membership_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');await configContext.close();await voterContext.close();await grantContext.close();await holderContext.close();await readerContext.close();}
});

test('real administrative review console independently configures, retains and revokes actual pool authority without business-license withdrawal',{timeout:180000},async()=>{
 const configContext=await context();const makerContext=await context();const voterContext=await context();const ownerContext=await context();const readContext=await context();
 try{
  const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser administrative review pool',3) RETURNING id")).rows[0].id;const base='/api/licenses/delegations/reviews';
  const config=await configContext.newPage();await reviewFirstFactor(config,'authority-review-config');await login(config,'authority-review-config');const owner=await ownerContext.newPage();await reviewFirstFactor(owner,'authority-review-owner');await login(owner,'authority-review-owner');const maker=await makerContext.newPage();await reviewFirstFactor(maker,'authority-review-maker');await login(maker,'authority-review-maker');const voter=await voterContext.newPage();await reviewFirstFactor(voter,'authority-review-voter');await login(voter,'authority-review-voter');
  const configToken=(await mediated(config)).body.access_token;const ownerToken=(await mediated(owner)).body.access_token;const scoped=policyBase+'/api/licenses/scoped/pools/'+poolId;
  const grant=async()=>{const result=await fetch(policyBase+'/api/licenses/delegations',{method:'POST',headers:{Authorization:'Bearer '+configToken,'Content-Type':'application/json'},body:JSON.stringify({licenseId:poolId,userId:actors.get('authority-review-owner').userId,duty:'allocator',durationSeconds:3600,reason:'Browser actual bounded administrative review target',confirm:true})});assert.equal(result.status,201);return{row:await result.json(),tag:result.headers.get('etag')};};const original=await grant();
  assert.equal((await fetch(scoped+'/assign',{method:'POST',headers:{Authorization:'Bearer '+ownerToken,'Content-Type':'application/json'},body:JSON.stringify({assigneeType:'user',assigneeId:actors.get('reader').userId,expiresAt:null,reason:'Business license must survive review of administrative rights',confirm:true})})).status,201);
  await maker.goto(origin+'/licenses');const panel=maker.getByRole('region',{name:'Verwaltungsrechte-Prüfung',exact:true});await panel.getByLabel('Prüfregel-Pool-ID',{exact:true}).fill(poolId);await panel.getByRole('button',{name:'Verwaltungs-Prüfregel laden',exact:true}).click();await panel.getByText('Keine aktive Prüfregel für dieses Ziel.',{exact:true}).waitFor();await panel.getByLabel('Prüfzyklus in Minuten',{exact:true}).fill('10');await panel.getByLabel('Antwortfenster in Minuten',{exact:true}).fill('5');await panel.getByLabel('Unabhängige Verwaltungs-Prüfer (UUIDs)',{exact:true}).fill(actors.get('authority-review-voter').userId);await panel.getByRole('button',{name:'Verwaltungs-Prüfregel erstellen prüfen',exact:true}).click();
  const confirm=async(page,control,endpoint,status)=>{await control.getByLabel('Begründung der Verwaltungs-Prüfung',{exact:true}).fill('Independent actual browser administrative recertification');await control.getByLabel('Unabhängigkeit, Zielversion und bindende Verwaltungsfrist geprüft.',{exact:true}).check();const response=page.waitForResponse(value=>new URL(value.url()).pathname===endpoint&&value.request().method()==='POST');await control.getByRole('button',{name:'Verwaltungs-Prüfung verbindlich bestätigen',exact:true}).click();const result=await response;assert.equal(result.status(),status);const row=await result.json();await control.getByRole('status').waitFor();return row;};
  const policy=await confirm(maker,panel,base+'/policies',201);await owner.goto(origin+'/licenses');const own=owner.getByRole('region',{name:'Verwaltungsrechte-Prüfung',exact:true});await own.getByRole('button',{name:'Meine Verwaltungs-Prüffristen laden',exact:true}).click();await own.getByRole('article').filter({hasText:original.row.id}).waitFor();assert.equal(await own.getByRole('button',{name:'Verwaltungsrecht behalten prüfen',exact:true}).count(),0);
  await voter.goto(origin+'/licenses');const queue=voter.getByRole('region',{name:'Verwaltungsrechte-Prüfung',exact:true});await queue.getByRole('button',{name:'Zugewiesene Verwaltungs-Prüfungen laden',exact:true}).click();const first=queue.getByRole('article').filter({hasText:original.row.id});await first.getByRole('button',{name:'Verwaltungsrecht behalten prüfen',exact:true}).click();const reviewId=(await policyDb.query('SELECT id FROM license_scope_review_leases WHERE target_id=$1',[original.row.id])).rows[0].id;const retained=await confirm(voter,queue,base+'/'+reviewId+'/decisions',200);assert.equal(retained.cycle,'2');assert.equal(retained.baseExpiresAt,original.row.expiresAt);
  const retired=await fetch(policyBase+'/api/licenses/delegations/'+original.row.id+'/revoke',{method:'POST',headers:{Authorization:'Bearer '+configToken,'Content-Type':'application/json','If-Match':original.tag},body:JSON.stringify({reason:'Explicit retirement before another independently reviewed grant',confirm:true})});assert.equal(retired.status,200);const replacement=await grant();assert.notEqual(replacement.row.id,original.row.id);
  await queue.getByRole('button',{name:'Zugewiesene Verwaltungs-Prüfungen laden',exact:true}).click();const next=queue.getByRole('article').filter({hasText:replacement.row.id});await next.getByRole('button',{name:'Verwaltungsrecht entziehen prüfen',exact:true}).click();assert.equal(await queue.getByLabel('Unabhängigkeit, Zielversion und bindende Verwaltungsfrist geprüft.',{exact:true}).isChecked(),false);await queue.getByLabel('Begründung der Verwaltungs-Prüfung',{exact:true}).fill('Independent browser denial of administrative rights only');await queue.getByLabel('Begründung der Verwaltungs-Prüfung',{exact:true}).scrollIntoViewIfNeeded();await voter.screenshot({path:path.join(os.tmpdir(),'od-license-authority-review.png'),fullPage:false});
  const nextId=(await policyDb.query('SELECT id FROM license_scope_review_leases WHERE target_id=$1',[replacement.row.id])).rows[0].id;const denied=await confirm(voter,queue,base+'/'+nextId+'/decisions',200);assert.equal(denied.targetVersion,'2');assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+ownerToken}})).status,404);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
  const read=await readContext.newPage();await login(read,'authority-review-reader');await read.goto(origin+'/licenses');const readPanel=read.getByRole('region',{name:'Verwaltungsrechte-Prüfung',exact:true});await readPanel.getByLabel('Bekannte Verwaltungs-Prüfungs-ID',{exact:true}).fill(nextId);await readPanel.getByRole('button',{name:'Bekannte Verwaltungs-Prüfung laden',exact:true}).click();await readPanel.getByRole('article').filter({hasText:'denied'}).waitFor();assert.equal(await readPanel.getByRole('button',{name:/Verwaltungsrecht .* prüfen/}).count(),0);
  await panel.getByRole('button',{name:'Verwaltungs-Prüfregel stilllegen prüfen',exact:true}).click();await confirm(maker,panel,base+'/policies/'+policy.id+'/retire',200);await panel.getByText('Prüfregel stillgelegt. Akzeptierte Fristen bleiben bindend; keine Wiederbelebung alter Rechte.',{exact:true}).waitFor();
 }finally{await configContext.close();await makerContext.close();await voterContext.close();await ownerContext.close();await readContext.close();}
});

test('real mandatory pool policy console invalidates standing authority, uses an independent prepared path and never revives old PIM after relaxation',{timeout:180000},async()=>{
 const configContext=await context();const ownerContext=await context();const reviewerContext=await context();const policyContext=await context();const readContext=await context();
 try{
  const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser mandatory PIM pool',3) RETURNING id")).rows[0].id;const base='/api/licenses/delegations/pim';
  const owner=await ownerContext.newPage();await reviewFirstFactor(owner,'pool-policy-operator');await login(owner,'pool-policy-operator');const reviewer=await reviewerContext.newPage();await reviewFirstFactor(reviewer,'pool-policy-reviewer');await login(reviewer,'pool-policy-reviewer');
  const config=await configContext.newPage();await reviewFirstFactor(config,'pool-policy-config');await login(config,'pool-policy-config');await config.goto(origin+'/licenses');const control=config.getByRole('region',{name:'Pool-PIM',exact:true});
  await control.getByLabel('PIM-Pool-ID',{exact:true}).fill(poolId);await control.getByLabel('PIM-Delegate-ID',{exact:true}).fill(actors.get('pool-policy-operator').userId);await control.getByLabel('Maximale Aktivierung in Minuten (1–480)',{exact:true}).fill('5');await control.getByLabel('Unabhängige Pool-Aktivierungsprüfer (UUIDs)',{exact:true}).fill(actors.get('pool-policy-reviewer').userId);await control.getByRole('button',{name:'Pool-Berechtigung erstellen prüfen',exact:true}).click();
  const confirmPim=async(page,panel,endpoint,status)=>{await panel.getByLabel('Begründung der Pool-PIM-Aktion',{exact:true}).fill('Independent browser mandatory policy activation evidence');await panel.getByLabel('Pool, unabhängige Freigabe, Version und Laufzeit geprüft.',{exact:true}).check();const response=page.waitForResponse(value=>new URL(value.url()).pathname===endpoint&&value.request().method()==='POST');await panel.getByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen',exact:true}).click();const result=await response;assert.equal(result.status(),status);return result.json();};
  const eligibility=await confirmPim(config,control,base+'/eligibilities',201);const configToken=(await mediated(config)).body.access_token;const token=(await mediated(owner)).body.access_token;const scoped=policyBase+'/api/licenses/scoped/pools/'+poolId;
  const standing=await fetch(policyBase+'/api/licenses/delegations',{method:'POST',headers:{Authorization:'Bearer '+configToken,'Content-Type':'application/json'},body:JSON.stringify({licenseId:poolId,userId:actors.get('pool-policy-operator').userId,duty:'allocator',durationSeconds:300,reason:'Original standing authority before independently required PIM',confirm:true})});assert.equal(standing.status,201);const lease=await standing.json();assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,200);
  const policymaker=await policyContext.newPage();await reviewFirstFactor(policymaker,'pool-policy-maker');await login(policymaker,'pool-policy-maker');await policymaker.goto(origin+'/licenses');const policyPanel=policymaker.getByRole('region',{name:'Pool-PIM-Richtlinie',exact:true});await policyPanel.getByLabel('Richtlinien-Pool-ID',{exact:true}).fill(poolId);await policyPanel.getByRole('button',{name:'Pool-PIM-Richtlinie laden',exact:true}).click();await policyPanel.getByText(/Version 1/).waitFor();
  await policyPanel.getByLabel('PIM für diese Aufgabe verpflichtend',{exact:true}).check();await policyPanel.getByLabel('Richtlinien-Maximum in Minuten',{exact:true}).fill('5');await policyPanel.getByLabel('Vorbereitete unabhängige Berechtigungs-IDs',{exact:true}).fill(eligibility.id);await policyPanel.getByRole('button',{name:'Pool-PIM-Regel ändern prüfen',exact:true}).click();
  const confirmPolicy=async()=>{await policyPanel.getByLabel('Begründung der Pool-PIM-Richtlinie',{exact:true}).fill('Independent preparation and irreversible pool authority invalidation');await policyPanel.getByLabel('Entwertung alter Rechte, unabhängige Pfade und Laufzeit geprüft.',{exact:true}).check();const response=policymaker.waitForResponse(value=>new URL(value.url()).pathname===`/api/licenses/delegations/policies/pools/${poolId}/allocator`&&value.request().method()==='PUT');await policyPanel.getByRole('button',{name:'Pool-PIM-Richtlinie verbindlich bestätigen',exact:true}).click();const result=await response;assert.equal(result.status(),200);return result.json();};
  await policyPanel.getByLabel('Begründung der Pool-PIM-Richtlinie',{exact:true}).scrollIntoViewIfNeeded();await policymaker.screenshot({path:path.join(os.tmpdir(),'od-license-pool-policy.png'),fullPage:false});const rule=await confirmPolicy();assert.equal(rule.version,'2');assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,404);
  const retired=await fetch(policyBase+'/api/licenses/delegations/'+lease.id+'/revoke',{method:'POST',headers:{Authorization:'Bearer '+configToken,'Content-Type':'application/json','If-Match':standing.headers.get('etag')},body:JSON.stringify({reason:'Explicit retirement before a new independently activated origin',confirm:true})});assert.equal(retired.status,200);
  await owner.goto(origin+'/licenses');const panel=owner.getByRole('region',{name:'Pool-PIM',exact:true});await panel.getByRole('button',{name:'Meine Pool-PIM-Einträge laden',exact:true}).click();await panel.getByLabel('Gewünschte Aktivierung in Minuten',{exact:true}).fill('1');await panel.getByRole('article').filter({hasText:eligibility.id}).getByRole('button',{name:'Pool-Aktivierung beantragen prüfen',exact:true}).click();const request=await confirmPim(owner,panel,base+'/eligibilities/'+eligibility.id+'/requests',201);
  await reviewer.goto(origin+'/licenses');const queue=reviewer.getByRole('region',{name:'Pool-PIM',exact:true});await queue.getByRole('button',{name:'Zugewiesene Pool-Aktivierungen laden',exact:true}).click();await queue.getByRole('article').filter({hasText:request.id}).getByRole('button',{name:'Pool-Aktivierung genehmigen prüfen',exact:true}).click();await confirmPim(reviewer,queue,base+'/requests/'+request.id+'/decisions',200);
  await panel.getByRole('button',{name:'Meine Pool-PIM-Einträge laden',exact:true}).click();await panel.getByRole('article').filter({hasText:request.id}).getByRole('button',{name:'Genehmigtes Poolrecht aktivieren prüfen',exact:true}).click();await confirmPim(owner,panel,base+'/requests/'+request.id+'/activate',200);
  assert.equal((await fetch(scoped+'/assign',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({assigneeType:'user',assigneeId:actors.get('reader').userId,expiresAt:null,reason:'Only the independently activated policy origin can allocate',confirm:true})})).status,201);
  const read=await readContext.newPage();await login(read,'pool-policy-reader');await read.goto(origin+'/licenses');const readPanel=read.getByRole('region',{name:'Pool-PIM-Richtlinie',exact:true});await readPanel.getByLabel('Richtlinien-Pool-ID',{exact:true}).fill(poolId);await readPanel.getByRole('button',{name:'Pool-PIM-Richtlinie laden',exact:true}).click();await readPanel.getByText(/Version 2/).waitFor();assert.equal(await readPanel.getByRole('button',{name:'Pool-PIM-Regel ändern prüfen',exact:true}).count(),0);
  await policyPanel.getByLabel('PIM für diese Aufgabe verpflichtend',{exact:true}).uncheck();await policyPanel.getByLabel('Vorbereitete unabhängige Berechtigungs-IDs',{exact:true}).fill('');await policyPanel.getByRole('button',{name:'Pool-PIM-Regel ändern prüfen',exact:true}).click();assert.equal(await policyPanel.getByLabel('Entwertung alter Rechte, unabhängige Pfade und Laufzeit geprüft.',{exact:true}).isChecked(),false);await confirmPolicy();assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,404);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
 }finally{await configContext.close();await ownerContext.close();await reviewerContext.close();await policyContext.close();await readContext.close();}
});

test('real pool PIM console separates eligibility, independent approval and owner activation and deactivation', {timeout:180000}, async()=>{
  const configContext=await context();const ownerContext=await context();const reviewerContext=await context();
  try{
    const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Real browser PIM pool',3) RETURNING id")).rows[0].id;const base='/api/licenses/delegations/pim';
    const owner=await ownerContext.newPage();await reviewFirstFactor(owner,'scope-pim-operator');await login(owner,'scope-pim-operator');
    const reviewer=await reviewerContext.newPage();await reviewFirstFactor(reviewer,'scope-pim-reviewer');await login(reviewer,'scope-pim-reviewer');
    const config=await configContext.newPage();await reviewFirstFactor(config,'scope-pim-config');await login(config,'scope-pim-config');await config.goto(origin+'/licenses');
    const control=config.getByRole('region',{name:'Pool-PIM'});await control.getByLabel('PIM-Pool-ID',{exact:true}).fill(poolId);await control.getByLabel('PIM-Delegate-ID',{exact:true}).fill(actors.get('scope-pim-operator').userId);
    await control.getByLabel('Unabhängige Pool-Aktivierungsprüfer (UUIDs)',{exact:true}).fill(actors.get('scope-pim-reviewer').userId);await control.getByRole('button',{name:'Pool-Berechtigung erstellen prüfen',exact:true}).click();
    const confirm=async(page,panel,endpoint,status)=>{await panel.getByLabel('Begründung der Pool-PIM-Aktion',{exact:true}).fill('Independent real browser resource activation evidence');await panel.getByLabel('Pool, unabhängige Freigabe, Version und Laufzeit geprüft.',{exact:true}).check();const response=page.waitForResponse(value=>new URL(value.url()).pathname===endpoint&&value.request().method()==='POST');await panel.getByRole('button',{name:'Pool-PIM-Aktion verbindlich bestätigen',exact:true}).click();const result=await response;assert.equal(result.status(),status);return result.json();};
    const eligibility=await confirm(config,control,base+'/eligibilities',201);await control.getByText('Pool-Berechtigung erstellt; noch keine aktiven Rechte.',{exact:true}).waitFor();
    await owner.goto(origin+'/licenses');const panel=owner.getByRole('region',{name:'Pool-PIM'});await panel.getByRole('button',{name:'Meine Pool-PIM-Einträge laden',exact:true}).click();
    await panel.getByLabel('Gewünschte Aktivierung in Minuten',{exact:true}).fill('1');await panel.getByRole('article').filter({hasText:eligibility.id}).getByRole('button',{name:'Pool-Aktivierung beantragen prüfen',exact:true}).click();
    const request=await confirm(owner,panel,base+'/eligibilities/'+eligibility.id+'/requests',201);const token=(await mediated(owner)).body.access_token;const scoped=policyBase+'/api/licenses/scoped/pools/'+poolId;
    assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,404);
    await reviewer.goto(origin+'/licenses');const queue=reviewer.getByRole('region',{name:'Pool-PIM'});assert.equal(await queue.getByLabel('PIM-Pool-ID',{exact:true}).count(),0);await queue.getByRole('button',{name:'Zugewiesene Pool-Aktivierungen laden',exact:true}).click();
    await queue.getByRole('article').filter({hasText:request.id}).getByRole('button',{name:'Pool-Aktivierung genehmigen prüfen',exact:true}).click();await confirm(reviewer,queue,base+'/requests/'+request.id+'/decisions',200);
    await queue.getByText('Unabhängig genehmigt; der Inhaber muss separat aktivieren.',{exact:true}).waitFor();assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,404);
    await panel.getByRole('button',{name:'Meine Pool-PIM-Einträge laden',exact:true}).click();await panel.getByRole('article').filter({hasText:request.id}).getByRole('button',{name:'Genehmigtes Poolrecht aktivieren prüfen',exact:true}).click();
    await panel.getByLabel('Begründung der Pool-PIM-Aktion',{exact:true}).scrollIntoViewIfNeeded();await owner.screenshot({path:path.join(os.tmpdir(),'od-license-scope-pim.png'),fullPage:false});await confirm(owner,panel,base+'/requests/'+request.id+'/activate',200);
    await panel.getByText('Poolrecht aktiviert; Pool-Delegationen neu laden. Keine globale Lizenzrolle.',{exact:true}).waitFor();
    const allocation=await fetch(scoped+'/assign',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({assigneeType:'user',assigneeId:actors.get('reader').userId,expiresAt:null,reason:'A browser activated lease grants only this pool source',confirm:true})});assert.equal(allocation.status,201);
    await panel.getByRole('button',{name:'Meine Pool-PIM-Einträge laden',exact:true}).click();await panel.getByRole('article').filter({hasText:request.id}).getByRole('button',{name:'Poolrecht deaktivieren prüfen',exact:true}).click();await confirm(owner,panel,base+'/requests/'+request.id+'/deactivate',200);
    await panel.getByText('Poolrecht deaktiviert; bestehende Lizenzen bleiben bestehen.',{exact:true}).waitFor();assert.equal((await fetch(scoped,{headers:{Authorization:'Bearer '+token}})).status,404);assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
  }finally{await configContext.close();await ownerContext.close();await reviewerContext.close();}
});

test('real scoped licensing console gives a canonical delegate only its assigned pool and no global license administration', {timeout:180000}, async()=>{
  const configContext=await context();const operatorContext=await context();
  try{
    const poolId=(await policyDb.query("INSERT INTO license_catalog(name,total_seats,notes) VALUES('Browser delegated pool',3,'Private global note') RETURNING id")).rows[0].id;
    const foreign=(await policyDb.query("INSERT INTO license_catalog(name,total_seats) VALUES('Browser foreign pool',3) RETURNING id")).rows[0].id;
    const operator=await operatorContext.newPage();await reviewFirstFactor(operator,'scope-operator');await login(operator,'scope-operator');
    const config=await configContext.newPage();await reviewFirstFactor(config,'scope-config');await login(config,'scope-config');await config.goto(origin+'/licenses');
    const control=config.getByRole('region',{name:'Lizenzpool-Delegationen'});
    await control.getByLabel('Bekannte Pool-ID für Delegation',{exact:true}).fill(poolId);await control.getByLabel('Kanonische Delegate-ID',{exact:true}).fill(actors.get('scope-operator').userId);
    await control.getByLabel('Pool-Aufgabe',{exact:true}).selectOption('allocator');await control.getByRole('button',{name:'Pool-Delegation erstellen prüfen',exact:true}).click();
    await control.getByLabel('Begründung der Pool-Aktion',{exact:true}).fill('Real independently confirmed single pool delegation');await control.getByLabel('Pool, Ziel, Aufgabe und Wirkung unabhängig geprüft.',{exact:true}).check();
    const creation=config.waitForResponse(response=>new URL(response.url()).pathname==='/api/licenses/delegations'&&response.request().method()==='POST');await control.getByRole('button',{name:'Pool-Aktion verbindlich bestätigen',exact:true}).click();const created=await creation;assert.equal(created.status(),201);const lease=await created.json();
    await operator.goto(origin+'/licenses');const panel=operator.getByRole('region',{name:'Lizenzpool-Delegationen'});await panel.getByRole('button',{name:'Meine Pool-Delegationen laden',exact:true}).click();
    await panel.getByRole('button',{name:new RegExp(poolId+' · allocator')}).click();await panel.getByText('Delegierter Pool: Browser delegated pool',{exact:true}).waitFor();
    assert.equal(await operator.getByRole('button',{name:'Verwaltung',exact:true}).count(),0);
    const token=(await mediated(operator)).body.access_token;const read=await fetch(policyBase+'/api/licenses/scoped/pools/'+foreign,{headers:{Authorization:'Bearer '+token}});assert.equal(read.status,404);
    await panel.getByLabel('Kanonisches Lizenzziel',{exact:true}).fill(actors.get('reader').userId);await panel.getByRole('button',{name:'Pool-Zuweisung prüfen',exact:true}).click();
    await panel.getByLabel('Begründung der Pool-Aktion',{exact:true}).fill('Actual single pool source allocation from the delegated console');await panel.getByLabel('Pool, Ziel, Aufgabe und Wirkung unabhängig geprüft.',{exact:true}).check();
    await panel.scrollIntoViewIfNeeded();await operator.screenshot({path:path.join(os.tmpdir(),'od-license-delegation.png'),fullPage:false});
    const receipt=operator.waitForResponse(response=>new URL(response.url()).pathname===`/api/licenses/scoped/pools/${poolId}/assign`);await panel.getByRole('button',{name:'Pool-Aktion verbindlich bestätigen',exact:true}).click();assert.equal((await receipt).status(),201);
    await panel.getByText('Quelle lokal vergeben; Herstellerstatus separat prüfen.',{exact:true}).waitFor();assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1',[poolId])).rows[0].used_seats,1);
    const configToken=(await mediated(config)).body.access_token;const revoked=await fetch(policyBase+'/api/licenses/delegations/'+lease.id+'/revoke',{method:'POST',headers:{Authorization:'Bearer '+configToken,'Content-Type':'application/json','If-Match':`"od-license-delegation:${lease.id}:${lease.version}"`},body:JSON.stringify({confirm:true,reason:'Explicitly retire the browser-owned delegation'})});assert.equal(revoked.status,200);
    await panel.getByRole('button',{name:'Meine Pool-Delegationen laden',exact:true}).click();await panel.getByText('Keine nutzbaren Pool-Delegationen.',{exact:true}).waitFor();
  }finally{await configContext.close();await operatorContext.close();}
});

async function reviewFirstFactor(page,username) {
  await page.goto(origin+'/auth/mfa-enroll'); await page.getByLabel('Eigener Benutzername',{ exact:true }).fill(username); await page.getByLabel('Aktuelles Passwort',{ exact:true }).fill('disposable-password');
  const receipt=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/auth/oidc/enrollment/start');
  await page.getByRole('button',{ name:'Ersteinrichtung vorbereiten',exact:true }).click(); const response=await receipt; assert.equal(response.status(),200); const setup=await response.json();
  const counter=Math.floor(Date.now()/30000); await page.getByLabel('Einmalcode des neuen Authenticators',{ exact:true }).fill(totp(setup.secret,counter));
  const confirmation=page.waitForResponse(result=>new URL(result.url()).pathname==='/api/auth/oidc/enrollment/confirm'&&result.request().method()==='POST');
  await page.getByRole('button',{ name:'Neuen Faktor bestätigen',exact:true }).click(); const confirmed=await confirmation; const outcome=await confirmed.json();
  assert.equal(confirmed.status(),200,username+' first-factor confirmation: '+String(outcome.error||'unconfirmed').slice(0,100)); await page.getByText(/Ersteinrichtung bestätigt/).waitFor();
  assert.equal((await page.context().cookies()).some(cookie=>cookie.name==='od_session'),false); assert.equal(await page.getByText(setup.secret,{ exact:true }).count(),0); rememberFactor(username,setup.secret,counter);
}
test('real company registration UI persists one disabled tenant and candidate through actual credentials, issuer proof, BFF and status recovery', { timeout: 360000 }, async () => {
  const isolated = await context({ onboarded: false }); const page = await isolated.newPage();
  try {
    await page.goto(origin + '/register'); await page.getByLabel('Benutzername', { exact: true }).fill('company-registration-owner'); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const registrationId = await page.getByLabel('Registrierungs-ID (für Statusabfrage aufbewahren)', { exact: true }).inputValue();
    for (const [label, value] of [['Firmenname *', 'Actual Pending Browser Company'], ['Strasse und Hausnummer *', 'Business Street 1'], ['Postleitzahl *', '8000'], ['Ort *', 'Zürich'], ['Land (zweistellig, z. B. CH) *', 'CH'], ['Kontakt-E-Mail *', 'office@example.invalid']]) await page.getByLabel(label, { exact: true }).fill(value);
    await page.getByRole('checkbox').check(); const pendingResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/submit'); await page.getByRole('button', { name: 'Unternehmen zur Prüfung anmelden', exact: true }).click(); const submitted = await pendingResponse; assert.equal(submitted.status(), 201, await submitted.text()); const receipt = await submitted.json();
    await page.getByText('Zur Prüfung vorgemerkt', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Aktuelles Passwort', { exact: true }).inputValue(), ''); assert.equal(receipt.registrationId, registrationId); assert.equal(receipt.tenantEnabled, false); assert.equal(receipt.administratorEnabled, false);
    await page.reload(); assert.equal(await page.getByLabel('Registrierungs-ID (für Statusabfrage aufbewahren)', { exact: true }).inputValue(), registrationId); await page.getByLabel('Benutzername', { exact: true }).fill('company-registration-owner'); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('wrong-password');
    await page.getByRole('button', { name: 'Bestehenden Status prüfen', exact: true }).click(); await page.getByRole('alert').filter({ hasText: 'Zugangsdaten wurden nicht bestätigt' }).waitFor();
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); const statusResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/status'); await page.getByRole('button', { name: 'Bestehenden Status prüfen', exact: true }).click(); const confirmed = await statusResponse; assert.equal(confirmed.status(), 200); assert.equal((await confirmed.json()).tenantId, receipt.tenantId);
    await page.getByText('Bestehende Registrierung bestätigt; kein zweiter Mandant angelegt.', { exact: true }).waitFor();
    const actual = (await identityDb.query('SELECT tenant.enabled AS tenant_enabled,account.enabled AS user_enabled FROM identity_company_registrations registration JOIN identity_tenants tenant ON tenant.id=registration.tenant_id JOIN users account ON account.id=registration.user_id WHERE registration.id=$1', [registrationId])).rows; assert.deepEqual(actual, [{ tenant_enabled: false, user_enabled: false }]);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    const reviewContext = await context(); const reviewPage = await reviewContext.newPage();
    try {
      await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer: logicalIssuer, userId: actors.get('company-review-console').userId, version: '0', enabled: true, reason: 'Explicit independent real browser company reviewer' });
      await login(reviewPage, 'company-review-console'); await reviewPage.goto(origin + '/registration-reviews');
      const reviewSession = await mediated(reviewPage); assert.equal(reviewSession.status, 200);
      const metadata = await reviewPage.request.get(origin + '/api/identity/access', { headers: { Authorization: 'Bearer ' + reviewSession.body.access_token } }); assert.equal(metadata.status(), 200); const reviewAccess = await metadata.json(); assert.deepEqual(reviewAccess.permissions, ['company.registrations.review']); assert.equal(reviewAccess.companyRegistrationReviewProtocol, 1);
      await reviewPage.getByRole('heading', { name: 'Firmenprüfung', exact: true }).waitFor(); await reviewPage.getByRole('alert').filter({ hasText: 'frische MFA-Anmeldung' }).waitFor(); await reviewPage.getByRole('link', { name: 'MFA-Einstellungen öffnen', exact: true }).click();
      await reviewPage.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor(); await reviewPage.getByLabel('Eigener Benutzername', { exact: true }).fill('company-review-console'); await reviewPage.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
      const setupReceipt = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll'); await reviewPage.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const setupResponse = await setupReceipt; assert.equal(setupResponse.status(), 200); const setup = await setupResponse.json(); const counter = Math.floor(Date.now() / 30000);
      await reviewPage.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(setup.secret, counter)); const factorReceipt = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm'); await reviewPage.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await factorReceipt).status(), 200);
      await reviewPage.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); rememberFactor('company-review-console', setup.secret, counter); await login(reviewPage, 'company-review-console'); await reviewPage.goto(origin + '/registration-reviews');
      await reviewPage.getByRole('button', { name: 'Antrag öffnen: Actual Pending Browser Company', exact: true }).click();
      const save = reviewPage.getByRole('button', { name: 'Prüfentscheidung speichern', exact: true }); await save.waitFor(); assert.equal(await save.isDisabled(), true);
      await reviewPage.getByLabel('Entscheidung', { exact: true }).selectOption('approved'); await reviewPage.getByLabel('Prüfbegründung', { exact: true }).fill('Actual browser independently reviewed company request'); assert.equal(await save.isDisabled(), true); await reviewPage.getByRole('checkbox').check();
      const deciding = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/company-registrations/' + registrationId + '/review' && response.request().method() === 'POST');
      await save.click(); const decided = await deciding; assert.equal(decided.status(), 200, await decided.text()); await reviewPage.getByText('Prüfentscheidung bestätigt. Mandant und Administrator bleiben gesperrt.', { exact: true }).waitFor();
      await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); const reconciled = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/status'); await page.getByRole('button', { name: 'Bestehenden Status prüfen', exact: true }).click(); const actualStatus = await reconciled; assert.equal(actualStatus.status(), 200); assert.equal((await actualStatus.json()).status, 'pending-activation');
      await page.getByRole('heading', { name: 'Freigegeben – Aktivierung ausstehend', exact: true }).waitFor();
      assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [receipt.administratorId])).rows[0].enabled, false);
      await reviewPage.screenshot({ path: '/tmp/od-business5-company-review.png', fullPage: true });
    } finally { await reviewContext.close(); }
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    await page.getByLabel('Ich bestätige die Aktivierung meiner freigegebenen Firma mit Pflicht-MFA und ohne globale Adminrechte.', { exact: true }).check();
    const activating = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/activate'); await page.getByRole('button', { name: 'Freigegebene Firma aktivieren', exact: true }).click(); const activated = await activating; assert.equal(activated.status(), 200, await activated.text()); const activatedReceipt = await activated.json(); assert.equal(activatedReceipt.status, 'active'); assert.equal(activatedReceipt.mfaRequired, true);
    await page.getByRole('heading', { name: 'Unternehmen aktiviert – MFA erforderlich', exact: true }).waitFor(); assert.equal(await page.getByLabel('Aktuelles Passwort', { exact: true }).inputValue(), '');
    await page.screenshot({ path: '/tmp/od-business6-company-registration.png', fullPage: true });
    await reviewFirstFactor(page, 'company-registration-owner'); await login(page, 'company-registration-owner'); await page.goto(origin + '/organization');
    assert.equal(await page.evaluate(() => localStorage.getItem('od_onboarded')), null);
    await page.getByText('Gespeicherte Version 1', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Firmenname *', { exact: true }).inputValue(), 'Actual Pending Browser Company');
    const ownerSession = await mediated(page); const ownerAccess = await page.request.get(origin + '/api/identity/access', { headers: { Authorization: 'Bearer ' + ownerSession.body.access_token } }); assert.deepEqual((await ownerAccess.json()).permissions, ['organization.read', 'organization.manage', 'organization.delegations.manage', ...require('../../../identity-service/src/CompanyOwner').COMPANY_DIRECTORY_PERMISSIONS]);
    assert.equal(require('../../../identity-service/src/CompanyOwner').COMPANY_DIRECTORY_PERMISSIONS.length, 14);
    const ownerPeople = await page.request.get(origin + '/api/users', { headers: { Authorization: 'Bearer ' + ownerSession.body.access_token } }); assert.equal(ownerPeople.status(), 200); assert.deepEqual((await ownerPeople.json()).users.map(account => account.id), [receipt.administratorId]);
    await page.getByLabel('Ort *', { exact: true }).fill('Bern'); await page.getByLabel('Begründung der Änderung', { exact: true }).fill('New company owner updates only the own original profile'); await page.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).click(); await page.getByText('Organisationsprofil gespeichert. Version 2.', { exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/od-business6-company-owner.png', fullPage: true });
    const unitIds = [];
    for (const [name, parent] of [['Engineering', null], ['Platform', 'Engineering']]) {
      await page.getByLabel('Name der Organisationseinheit', { exact: true }).fill(name);
      await page.getByLabel('Übergeordnete Einheit', { exact: true }).selectOption(parent ? { label: parent } : '');
      const pending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ous' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Organisationseinheit erstellen', exact: true }).click(); const confirmed = await pending; assert.equal(confirmed.status(), 201, await confirmed.text()); unitIds.push((await confirmed.json()).id);
      await page.getByText(`Organisationseinheit „${name}“ bestätigt.`, { exact: true }).waitFor();
    }
    await page.screenshot({ path: '/tmp/od-business7-company-hierarchy.png', fullPage: true });
    assert.equal(await page.getByRole('button', { name: 'Organisationseinheit Engineering löschen', exact: true }).isDisabled(), true);
    await page.getByRole('button', { name: 'Organisationseinheit Platform bearbeiten', exact: true }).click(); await page.getByLabel('Name der Organisationseinheit', { exact: true }).fill('Platform Services'); await page.getByLabel('Übergeordnete Einheit', { exact: true }).selectOption('');
    let unitPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ous/' + unitIds[1] && response.request().method() === 'PUT'); await page.getByRole('button', { name: 'Organisationseinheit speichern', exact: true }).click(); let unitResponse = await unitPending; assert.equal(unitResponse.status(), 200, await unitResponse.text()); assert.equal((await unitResponse.json()).parentId, undefined); await page.getByText('Organisationseinheit „Platform Services“ bestätigt.', { exact: true }).waitFor();
    const staleUnit = await page.request.put(origin + '/api/ous/' + unitIds[1], { headers: { Authorization: 'Bearer ' + ownerSession.body.access_token, 'If-Match': `"ou-${unitIds[1]}-1"` }, data: { name: 'No stale overwrite' } }); assert.equal(staleUnit.status(), 412);
    await page.getByRole('button', { name: 'Organisationseinheit Platform Services bearbeiten', exact: true }).click(); await page.getByLabel('Übergeordnete Einheit', { exact: true }).selectOption({ label: 'Engineering' });
    unitPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ous/' + unitIds[1] && response.request().method() === 'PUT'); await page.getByRole('button', { name: 'Organisationseinheit speichern', exact: true }).click(); unitResponse = await unitPending; assert.equal(unitResponse.status(), 200, await unitResponse.text()); await page.getByText('Organisationseinheit „Platform Services“ bestätigt.', { exact: true }).waitFor();
    await page.getByLabel('Name der Organisationseinheit', { exact: true }).fill('Temporary unit');
    unitPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ous' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Organisationseinheit erstellen', exact: true }).click(); unitResponse = await unitPending; assert.equal(unitResponse.status(), 201, await unitResponse.text()); const temporaryUnitId = (await unitResponse.json()).id; await page.getByText('Organisationseinheit „Temporary unit“ bestätigt.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Organisationseinheit Temporary unit löschen', exact: true }).click(); await page.getByRole('alertdialog', { name: 'Organisationseinheit löschen', exact: true }).waitFor(); assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM ous WHERE id=$1', [temporaryUnitId])).rows[0].count, 1);
    unitPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/ous/' + temporaryUnitId && response.request().method() === 'DELETE'); await page.getByRole('alertdialog').getByRole('button', { name: 'Bestätigen', exact: true }).click(); unitResponse = await unitPending; assert.equal(unitResponse.status(), 204); await page.getByText('Organisationseinheit „Temporary unit“ gelöscht.', { exact: true }).waitFor();
    assert.deepEqual((await identityDb.query('SELECT action FROM identity_directory_ou_events WHERE tenant_id=$1 ORDER BY created_at', [receipt.tenantId])).rows.map(event => event.action), ['update', 'update', 'delete']);
    await page.screenshot({ path: '/tmp/od-business8-company-hierarchy.png', fullPage: true });
    const employeeIds = [];
    await page.goto(origin + '/users');
    for (const [username, name] of [['browser-company-employee-one', 'Company Employee One'], ['browser-company-employee-two', 'Company Employee Two']]) {
      await page.getByRole('button', { name: 'Verzeichniseintrag erstellen', exact: true }).click(); await page.getByLabel('Benutzername', { exact: true }).fill(username); await page.getByLabel('E-Mail', { exact: true }).fill(username + '@example.invalid'); await page.getByLabel('Anzeigename', { exact: true }).fill(name);
      const pending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/users' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Speichern', exact: true }).click(); const confirmed = await pending; assert.equal(confirmed.status(), 201, await confirmed.text()); const employee = await confirmed.json(); assert.equal(employee.enabled, false); employeeIds.push(employee.id); await page.getByRole('heading', { name, exact: true }).waitFor();
    }
    await page.goto(origin + '/usergroups'); await page.getByRole('button', { name: 'Gruppe erstellen', exact: true }).click(); await page.getByLabel('Gruppenname', { exact: true }).fill('Company Engineering Team');
    let groupPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/groups' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); let groupResponse = await groupPending; assert.equal(groupResponse.status(), 201, await groupResponse.text()); const group = await groupResponse.json(); await page.getByRole('heading', { name: 'Company Engineering Team', exact: true }).waitFor();
    for (const employeeId of employeeIds) {
      await page.getByRole('button', { name: 'Mitglied verknüpfen', exact: true }).click(); await page.getByLabel('Kanonische Benutzer-ID', { exact: true }).fill(employeeId);
      groupPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/groups/' + group.id + '/members' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); groupResponse = await groupPending; assert.equal(groupResponse.status(), 200, await groupResponse.text()); await page.getByRole('status').filter({ hasText: 'Verknüpfung bestätigt' }).waitFor();
    }
    const directoryOwnership = (await identityDb.query("SELECT resource_kind,resource_id FROM identity_tenant_ownership WHERE tenant_id=$1 AND reason='Original-token-bound new-resource creation' ORDER BY resource_kind,resource_id", [receipt.tenantId])).rows;
    assert.deepEqual(new Set(directoryOwnership.map(resource => resource.resource_id)), new Set([...unitIds, temporaryUnitId, ...employeeIds, group.id]));
    assert.deepEqual((await identityDb.query('SELECT user_id FROM group_members WHERE group_id=$1 ORDER BY user_id', [group.id])).rows.map(member => member.user_id), [...employeeIds].sort());
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    assert.equal((await page.request.get(origin + '/api/identity/roles/catalog', { headers: { Authorization: 'Bearer ' + ownerSession.body.access_token } })).status(), 403);
    await page.getByRole('button', { name: 'Gruppe erstellen', exact: true }).click(); await page.getByLabel('Gruppenname', { exact: true }).fill('Company Operations Team');
    groupPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/groups' && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); groupResponse = await groupPending; assert.equal(groupResponse.status(), 201, await groupResponse.text()); const secondGroup = await groupResponse.json();
    await page.getByRole('heading', { name: 'Company Operations Team', exact: true }).waitFor();
    for (const employeeId of employeeIds) {
      await page.getByRole('button', { name: 'Mitglied verknüpfen', exact: true }).click(); await page.getByLabel('Kanonische Benutzer-ID', { exact: true }).fill(employeeId);
      groupPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/groups/' + secondGroup.id + '/members' && response.request().method() === 'POST');
      await page.getByRole('button', { name: 'Verbindlich speichern', exact: true }).click(); groupResponse = await groupPending; assert.equal(groupResponse.status(), 200, await groupResponse.text()); await page.getByRole('status').filter({ hasText: 'Verknüpfung bestätigt' }).waitFor();
    }
    await page.screenshot({ path: '/tmp/od-business7-company-group.png', fullPage: true });
    await page.goto(origin + '/organization');
    for (const unitName of ['Engineering', 'Platform Services']) {
      await page.getByRole('button', { name: 'Organisationseinheit ' + unitName + ' Mitglieder', exact: true }).click();
      await page.getByRole('heading', { name: 'Mitglieder von ' + unitName, exact: true }).waitFor();
      await page.getByLabel('Mitarbeitende suchen', { exact: true }).fill('Company Employee One');
      await page.getByRole('button', { name: 'Mitarbeitenden Company Employee One auswählen', exact: true }).click();
      const membershipPending = page.waitForResponse(response => /^\/api\/ous\/[^/]+\/members$/.test(new URL(response.url()).pathname) && response.request().method() === 'POST');
      await page.getByRole('button', { name: 'Zuordnung hinzufügen', exact: true }).click(); const membershipResponse = await membershipPending; assert.equal(membershipResponse.status(), 201, await membershipResponse.text());
      await page.getByRole('button', { name: 'OU-Zuordnung Company Employee One entfernen', exact: true }).waitFor();
      await page.getByRole('button', { name: 'Zur Organisationsstruktur', exact: true }).click();
      await page.getByRole('button', { name: 'Organisationseinheit ' + unitName + ' Mitglieder', exact: true }).waitFor();
    }
    assert.deepEqual(new Set((await identityDb.query('SELECT ou_id FROM identity_directory_ou_members WHERE user_id=$1', [employeeIds[0]])).rows.map(link => link.ou_id)), new Set(unitIds));
    assert.equal(await page.getByRole('button', { name: 'Organisationseinheit Platform Services löschen', exact: true }).isDisabled(), true);
    await page.getByRole('button', { name: 'Organisationseinheit Engineering Mitglieder', exact: true }).click(); await page.getByRole('heading', { name: 'Mitglieder von Engineering', exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/od-business9-company-members.png', fullPage: true });
    await page.getByRole('button', { name: 'OU-Zuordnung Company Employee One entfernen', exact: true }).click();
    const membershipDialog = page.getByRole('alertdialog', { name: 'OU-Zuordnung entfernen', exact: true }); await membershipDialog.waitFor();
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_directory_ou_members WHERE user_id=$1', [employeeIds[0]])).rows[0].count, 2);
    const unlinkPending = page.waitForResponse(response => /^\/api\/ous\/[^/]+\/members\/[^/]+$/.test(new URL(response.url()).pathname) && response.request().method() === 'DELETE');
    await membershipDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const unlinkResponse = await unlinkPending; assert.equal(unlinkResponse.status(), 200, await unlinkResponse.text());
    await page.getByText('0 bestätigte Zuordnungen · OU-Version 3 · Seite 1', { exact: true }).waitFor();
    assert.deepEqual((await identityDb.query('SELECT ou_id FROM identity_directory_ou_members WHERE user_id=$1', [employeeIds[0]])).rows.map(link => link.ou_id), [unitIds[1]]);
    assert.deepEqual((await identityDb.query('SELECT user_id FROM group_members WHERE group_id=$1 ORDER BY user_id', [group.id])).rows.map(link => link.user_id), [...employeeIds].sort());
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [employeeIds[0]])).rows[0].count, 0);
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [employeeIds[0]])).rows[0].enabled, false);
    await page.screenshot({ path: '/tmp/od-business9-company-unlinked.png', fullPage: true });
    await page.goto(origin+'/devices');await page.getByRole('heading',{name:'Geräteinventar',exact:true}).waitFor();
    await page.getByRole('button',{name:'Gerät erfassen',exact:true}).click();const inventoryForm=page.getByRole('dialog',{name:'Gerät erfassen',exact:true});
    for(const [label,value] of [['Inventarnummer','BROWSER-LAPTOP-01'],['Seriennummer','BROWSER-SERIAL-01'],['Hersteller','Example Manufacturer'],['Modell','Business Laptop']])await inventoryForm.getByLabel(label,{exact:true}).fill(value);
    await inventoryForm.getByLabel('Plattform',{exact:true}).selectOption('macos');
    const registeredInventory=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/devices'&&response.request().method()==='POST');await inventoryForm.getByRole('button',{name:'Im Inventar speichern',exact:true}).click();const registeredInventoryResponse=await registeredInventory;assert.equal(registeredInventoryResponse.status(),201,await registeredInventoryResponse.text());const inventoryDevice=await registeredInventoryResponse.json();
    await page.getByRole('button',{name:'BROWSER-LAPTOP-01',exact:true}).click();const inventoryDetails=page.getByRole('article',{name:'Gerätedetails',exact:true});await inventoryDetails.waitFor();
    await inventoryDetails.getByLabel('Benutzer auswählen',{exact:true}).selectOption(employeeIds[0]);await inventoryDetails.getByRole('button',{name:'Benutzer zuweisen',exact:true}).click();
    const inventoryConfirmation=page.getByRole('alertdialog');await inventoryConfirmation.waitFor();assert.equal((await inventoryFixture.db.query('SELECT assigned_user FROM devices WHERE id=$1',[inventoryDevice.id])).rows[0].assigned_user,null);
    let inventoryAssignment=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/devices/'+inventoryDevice.id+'/assignment'&&response.request().method()==='PUT');await inventoryConfirmation.getByRole('button',{name:'Bestätigen',exact:true}).click();let inventoryAssignmentResponse=await inventoryAssignment;assert.equal(inventoryAssignmentResponse.status(),200,await inventoryAssignmentResponse.text());const assignedInventory=await inventoryAssignmentResponse.json();assert.equal(assignedInventory.assignedUserId,employeeIds[0]);
    await inventoryDetails.getByRole('button',{name:'Zuweisung aufheben',exact:true}).waitFor();await inventoryDetails.getByRole('region',{name:'Gerätehistorie',exact:true}).getByText('Benutzer zugewiesen',{exact:true}).waitFor();
    await page.screenshot({path:'/tmp/od-business10-company-device-assigned.png',fullPage:true});
    await inventoryDetails.getByRole('button',{name:'Zuweisung aufheben',exact:true}).click();inventoryAssignment=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/devices/'+inventoryDevice.id+'/assignment'&&response.request().method()==='PUT');await page.getByRole('alertdialog').getByRole('button',{name:'Bestätigen',exact:true}).click();inventoryAssignmentResponse=await inventoryAssignment;assert.equal(inventoryAssignmentResponse.status(),200,await inventoryAssignmentResponse.text());assert.equal((await inventoryAssignmentResponse.json()).assignedUserId,null);
    await inventoryDetails.getByRole('region',{name:'Gerätehistorie',exact:true}).getByText('Zuweisung aufgehoben',{exact:true}).waitFor();
    const inventoryActual=(await inventoryFixture.db.query('SELECT tenant_id,assigned_user,status,last_seen,enrolled_at,compliance_status FROM devices WHERE id=$1',[inventoryDevice.id])).rows[0];assert.deepEqual(inventoryActual,{tenant_id:receipt.tenantId,assigned_user:null,status:'inventory-only',last_seen:null,enrolled_at:null,compliance_status:'unknown'});
    assert.equal((await inventoryFixture.db.query('SELECT count(*)::int AS count FROM device_inventory_assignments WHERE device_id=$1 AND released_at IS NOT NULL',[inventoryDevice.id])).rows[0].count,1);
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1',[employeeIds[0]])).rows[0].enabled,false);
    await page.screenshot({path:'/tmp/od-business10-company-device-released.png',fullPage:true});
    await page.goto(origin + '/users');
    await page.getByRole('region', { name: 'Kanonische Benutzerliste', exact: true }).getByLabel('Suche', { exact: true }).fill('browser-company-employee-one');
    await page.getByRole('button', { name: 'Benutzer browser-company-employee-one', exact: true }).click();
    const employeeDetails = page.getByRole('article', { name: 'Benutzerdetails', exact: true });
    await employeeDetails.getByRole('heading', { name: 'Company Employee One', exact: true }).waitFor();
    await employeeDetails.getByRole('button', { name: 'Konto freigeben', exact: true }).click();
    const enableDialog = page.getByRole('alertdialog', { name: 'Konto freigeben', exact: true }); await enableDialog.waitFor();
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [employeeIds[0]])).rows[0].enabled, false);
    const enablingEmployee = page.waitForResponse(response => new URL(response.url()).pathname === '/api/users/' + employeeIds[0] && response.request().method() === 'PUT');
    await enableDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const enabledEmployeeResponse = await enablingEmployee; assert.equal(enabledEmployeeResponse.status(), 200, await enabledEmployeeResponse.text());
    assert.deepEqual(enabledEmployeeResponse.request().postDataJSON(), { enabled: true }); assert.ok(enabledEmployeeResponse.request().headers()['if-match']);
    const enabledEmployee = await enabledEmployeeResponse.json(); assert.equal(enabledEmployee.id, employeeIds[0]); assert.equal(enabledEmployee.enabled, true);
    await employeeDetails.getByRole('button', { name: 'Konto sperren', exact: true }).waitFor();
    assert.deepEqual((await identityDb.query("SELECT enabled,identity_tenant_id('user',id) AS tenant_id FROM users WHERE id=$1", [employeeIds[0]])).rows, [{ enabled: true, tenant_id: receipt.tenantId }]);
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [employeeIds[1]])).rows[0].enabled, false);
    const providerProductsBefore = (await policyDb.query('SELECT count(*)::int AS count FROM license_provider_products')).rows[0].count;
    const companyRoute = '/api/licenses/company'; const companyWrites = []; const companyPoolEdits = [];
    page.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname.startsWith(companyRoute + '/')) companyWrites.push(request);
      if (request.method() === 'PATCH' && new URL(request.url()).pathname.startsWith(companyRoute + '/pools/')) companyPoolEdits.push(request);
    });
    const checkingCompanyLicenseAccess = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/capabilities' && response.request().method() === 'GET');
    await page.goto(origin + '/applications'); await page.getByRole('heading', { name: 'Anwendungen & Lizenzen', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Bisherige Direktverwaltung', exact: true }).click();
    const companyLicenseAccessResponse = await checkingCompanyLicenseAccess; assert.equal(companyLicenseAccessResponse.status(), 200, await companyLicenseAccessResponse.text());
    assert.deepEqual(await companyLicenseAccessResponse.json(), { schemaVersion: 1, companyLicenseProtocol: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId,
      permissions: ['company.apps.read', 'company.apps.create', 'company.apps.assign'], allocationMode: 'local-only', supportedTargets: ['user'] });
    assert.equal(await page.getByText(/Keine Cloud-Zuweisung, Installation, SSO-Einrichtung oder Abrechnung/).count(), 1);
    await page.getByRole('button', { name: 'Lizenzpool erstellen', exact: true }).click();
    const poolDialog = page.getByRole('alertdialog', { name: 'Lizenzpool erstellen', exact: true });
    const companyPoolValues = { name: 'Browser Company Licensed Editor', vendor: 'Example Company Vendor', description: 'Actual own company local license stock', totalSeats: 1, reason: 'Reviewed own company single seat license stock' };
    for (const [label, value] of [['Anwendungsname', companyPoolValues.name], ['Hersteller', companyPoolValues.vendor], ['Beschreibung', companyPoolValues.description], ['Lizenzanzahl', '1'], ['Begründung', companyPoolValues.reason]]) await poolDialog.getByLabel(label, { exact: true }).fill(value);
    assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_catalog WHERE business_tenant_id=$1', [receipt.tenantId])).rows[0].count, 0);
    assert.equal(companyWrites.length, 0);
    const creatingCompanyPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools' && response.request().method() === 'POST');
    await poolDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const companyPoolResponse = await creatingCompanyPool; assert.equal(companyPoolResponse.status(), 201, await companyPoolResponse.text()); assert.deepEqual(companyPoolResponse.request().postDataJSON(), companyPoolValues);
    const companyPool = await companyPoolResponse.json(); assert.equal(companyPool.tenantId, receipt.tenantId); assert.equal(companyPool.revision, '1');
    assert.deepEqual([companyPool.totalSeats, companyPool.usedSeats, companyPool.availableSeats, companyPool.licenseType, companyPool.allocationMode], [1, 0, 1, 'per_user', 'local-only']);
    const allocationState = async (poolId = companyPool.id) => (await policyDb.query(`SELECT business_tenant_id AS tenant_id,total_seats,used_seats,business_revision::text AS revision,
      (SELECT count(*)::int FROM license_assignments WHERE license_id=catalog.id) AS assignments,
      (SELECT count(*)::int FROM license_assignment_sources WHERE license_id=catalog.id) AS sources,
      (SELECT count(*)::int FROM license_grants WHERE license_id=catalog.id) AS grants,
      (SELECT count(*)::int FROM license_grants retained JOIN LATERAL
        (SELECT state FROM license_grant_events WHERE grant_id=retained.id ORDER BY version DESC LIMIT 1) current ON true
        WHERE retained.license_id=catalog.id AND current.state='active') AS active_grants
      FROM license_catalog catalog WHERE catalog.id=$1`, [poolId])).rows[0];
    const emptyCompanyPool = { tenant_id: receipt.tenantId, total_seats: 1, used_seats: 0, revision: '1', assignments: 0, sources: 0, grants: 0, active_grants: 0 };
    assert.deepEqual(await allocationState(), emptyCompanyPool);
    await page.getByRole('button', { name: companyPoolValues.name, exact: true }).click();
    const companyPoolDetails = page.getByRole('article', { name: 'Lizenzpooldetails', exact: true }); await companyPoolDetails.waitFor();
    const companyHistory = companyPoolDetails.getByRole('region', { name: 'Lizenzhistorie', exact: true }); await companyHistory.getByText('Lizenzpool erstellt', { exact: true }).waitFor();
    const companyUserPicker = companyPoolDetails.getByLabel('Benutzer auswählen', { exact: true }); await companyUserPicker.selectOption(employeeIds[0]);
    assert.equal(await companyUserPicker.locator('option[value="' + employeeIds[0] + '"]').count(), 1); assert.equal(await companyUserPicker.locator('option[value="' + employeeIds[1] + '"]').count(), 0);
    const assignmentReason = 'Actual browser assigns one enabled own company employee';
    await companyPoolDetails.getByLabel('Begründung', { exact: true }).fill(assignmentReason); await companyPoolDetails.getByRole('button', { name: 'Lizenz zuweisen', exact: true }).click();
    const licenseAssignmentDialog = page.getByRole('alertdialog', { name: 'Lizenzzuweisung bestätigen', exact: true }); await licenseAssignmentDialog.waitFor();
    assert.equal(await licenseAssignmentDialog.getByText(companyPoolValues.name + ' · Benutzer-ID: ' + employeeIds[0], { exact: true }).count(), 1);
    assert.deepEqual(await allocationState(), emptyCompanyPool); assert.equal(companyWrites.length, 1);
    const assigningCompanyLicense = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/assignments' && response.request().method() === 'POST');
    const readingAssignedHistory = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/history' && response.request().method() === 'GET');
    await licenseAssignmentDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const companyAssignmentResponse = await assigningCompanyLicense; assert.equal(companyAssignmentResponse.status(), 201, await companyAssignmentResponse.text());
    assert.deepEqual(companyAssignmentResponse.request().postDataJSON(), { userId: employeeIds[0], reason: assignmentReason, confirm: true }); assert.equal(companyAssignmentResponse.request().headers()['if-match'], '"company-pool-' + companyPool.id + '-1"');
    const assignedCompanyPool = await companyAssignmentResponse.json(); assert.deepEqual([assignedCompanyPool.id, assignedCompanyPool.tenantId, assignedCompanyPool.revision, assignedCompanyPool.totalSeats, assignedCompanyPool.usedSeats, assignedCompanyPool.availableSeats], [companyPool.id, receipt.tenantId, '2', 1, 1, 0]);
    await page.getByText('Lokale Lizenzzuweisung gespeichert.', { exact: true }).waitFor(); await companyHistory.getByText('Lizenz zugewiesen', { exact: true }).waitFor();
    for (const [label, value] of [['Lizenzbestand', '1'], ['Zugewiesen', '1'], ['Verfügbar', '0']]) assert.equal(await companyPoolDetails.locator('dt').filter({ hasText: new RegExp('^' + label + '$') }).locator('..').locator('dd').innerText(), value);
    assert.deepEqual(await allocationState(), { ...emptyCompanyPool, used_seats: 1, revision: '2', assignments: 1, sources: 1, grants: 1, active_grants: 1 });
    const canonicalCompanyAllocation = (await policyDb.query(`SELECT catalog.business_tenant_id AS tenant_id,assignment.id AS assignment_id,assignment.assignee_type,assignment.assignee_id,assignment.assigned_by,assignment.assigned_at,assignment.expires_at,
      source.user_id AS source_user_id,source.source_type,source.source_id,source.assigned_by AS source_actor,source.grant_id,
      retained.kind,retained.recipient_id,retained.origin FROM license_catalog catalog
      JOIN license_assignments assignment ON assignment.license_id=catalog.id
      JOIN license_assignment_sources source ON source.license_id=catalog.id AND source.user_id=assignment.assignee_id
      JOIN license_grants retained ON retained.id=source.grant_id AND retained.license_id=catalog.id WHERE catalog.id=$1`, [companyPool.id])).rows;
    assert.equal(canonicalCompanyAllocation.length, 1); const { assigned_at: companyAssignedAt, ...companyAllocation } = canonicalCompanyAllocation[0];
    assert.deepEqual(companyAllocation, { tenant_id: receipt.tenantId, assignment_id: companyAllocation.assignment_id, assignee_type: 'user', assignee_id: employeeIds[0], assigned_by: receipt.administratorId, expires_at: null,
      source_user_id: employeeIds[0], source_type: 'direct', source_id: 'direct', source_actor: receipt.administratorId, grant_id: companyAllocation.grant_id, kind: 'direct', recipient_id: employeeIds[0], origin: 'allocated' });
    assert.match(companyAllocation.assignment_id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/); assert.match(companyAllocation.grant_id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    const assignedHistoryResponse = await readingAssignedHistory; assert.equal(assignedHistoryResponse.status(), 200, await assignedHistoryResponse.text()); const assignedHistory = await assignedHistoryResponse.json();
    assert.deepEqual([assignedHistory.schemaVersion, assignedHistory.actorUserId, assignedHistory.tenantId, assignedHistory.poolId, assignedHistory.total], [1, receipt.administratorId, receipt.tenantId, companyPool.id, 2]);
    assert.deepEqual(assignedHistory.events.map(event => event.type).sort(), ['app.license.assigned', 'app.license.pool.created']); assert.ok(assignedHistory.events.every(event => event.deliveryStatus === 'pending'));
    assert.equal(await companyHistory.getByText('Ereigniszustellung ausstehend', { exact: true }).count(), 2);
    assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_provider_products WHERE license_id=$1', [companyPool.id])).rows[0].count, 0);
    const companyAssignmentRow = companyPoolDetails.getByRole('region', { name: 'Lizenzzuweisungen', exact: true }).getByRole('row').filter({ hasText: 'Company Employee One' });
    await companyAssignmentRow.getByRole('cell', { name: 'Company Employee One', exact: true }).waitFor();
    assert.equal(await companyAssignmentRow.locator('time').getAttribute('datetime'), companyAssignedAt.toISOString());
    assert.equal(await companyAssignmentRow.locator('time').innerText(), await page.evaluate(value => new Date(value).toLocaleString('de-CH', { dateStyle: 'medium', timeStyle: 'short' }), companyAssignedAt.toISOString()));
    const companyProof = companyAssignmentRow.locator('details'); await companyProof.locator('summary').focus(); await companyProof.locator('summary').press('Enter');
    assert.equal(await companyProof.getAttribute('open'), ''); assert.equal(await companyProof.getByText(companyAllocation.assignment_id, { exact: true }).isVisible(), true); assert.equal(await companyProof.getByText(companyAllocation.grant_id, { exact: true }).isVisible(), true);
    await companyProof.locator('summary').press('Enter'); assert.equal(await companyProof.getAttribute('open'), null);
    await page.getByRole('heading', { name: 'Anwendungen & Lizenzen', exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: '/tmp/od-business12-company-license-assigned.png', fullPage: true });
    const releaseReason = 'Actual browser explicitly returns the own company seat';
    await companyPoolDetails.getByLabel('Begründung', { exact: true }).fill(releaseReason);
    await companyPoolDetails.getByRole('region', { name: 'Lizenzzuweisungen', exact: true }).getByRole('button', { name: 'Lizenz freigeben', exact: true }).click();
    const licenseReleaseDialog = page.getByRole('alertdialog', { name: 'Lizenzfreigabe bestätigen', exact: true }); await licenseReleaseDialog.waitFor();
    assert.deepEqual(await allocationState(), { ...emptyCompanyPool, used_seats: 1, revision: '2', assignments: 1, sources: 1, grants: 1, active_grants: 1 }); assert.equal(companyWrites.length, 2);
    const releasingCompanyLicense = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/assignments/' + companyAllocation.assignment_id + '/revoke' && response.request().method() === 'POST');
    const readingReleasedHistory = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/history' && response.request().method() === 'GET');
    await licenseReleaseDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const companyReleaseResponse = await releasingCompanyLicense; assert.equal(companyReleaseResponse.status(), 200, await companyReleaseResponse.text());
    assert.deepEqual(companyReleaseResponse.request().postDataJSON(), { userId: employeeIds[0], reason: releaseReason, confirm: true }); assert.equal(companyReleaseResponse.request().headers()['if-match'], '"company-pool-' + companyPool.id + '-2"');
    const releasedCompanyPool = await companyReleaseResponse.json(); assert.deepEqual([releasedCompanyPool.id, releasedCompanyPool.tenantId, releasedCompanyPool.revision, releasedCompanyPool.totalSeats, releasedCompanyPool.usedSeats, releasedCompanyPool.availableSeats], [companyPool.id, receipt.tenantId, '3', 1, 0, 1]);
    await page.getByText('Lokale Lizenzzuweisung freigegeben.', { exact: true }).waitFor(); await companyHistory.getByText('Lizenz freigegeben', { exact: true }).waitFor();
    await companyPoolDetails.getByRole('region', { name: 'Lizenzzuweisungen', exact: true }).getByText('Keine Lizenzzuweisungen vorhanden.', { exact: true }).waitFor();
    for (const [label, value] of [['Lizenzbestand', '1'], ['Zugewiesen', '0'], ['Verfügbar', '1']]) assert.equal(await companyPoolDetails.locator('dt').filter({ hasText: new RegExp('^' + label + '$') }).locator('..').locator('dd').innerText(), value);
    assert.deepEqual(await allocationState(), { ...emptyCompanyPool, revision: '3', grants: 1 });
    assert.deepEqual((await policyDb.query('SELECT state,event,actor_user_id,actor_issuer FROM license_grant_events WHERE grant_id=$1 ORDER BY version', [companyAllocation.grant_id])).rows, [
      { state: 'active', event: 'source-created', actor_user_id: receipt.administratorId, actor_issuer: logicalIssuer }, { state: 'revoked', event: 'source-removed', actor_user_id: receipt.administratorId, actor_issuer: logicalIssuer },
    ]);
    const releasedHistoryResponse = await readingReleasedHistory; assert.equal(releasedHistoryResponse.status(), 200, await releasedHistoryResponse.text()); const releasedHistory = await releasedHistoryResponse.json();
    assert.deepEqual([releasedHistory.actorUserId, releasedHistory.tenantId, releasedHistory.poolId, releasedHistory.total], [receipt.administratorId, receipt.tenantId, companyPool.id, 3]); assert.ok(releasedHistory.events.every(event => event.deliveryStatus === 'pending'));
    assert.deepEqual((await policyDb.query(`SELECT events.type,events.tenant_id,events.actor_user_id,events.target_user_id,events.version,events.before_revision::text,events.after_revision::text,outbox.status
      FROM license_company_events events JOIN license_company_outbox outbox ON outbox.id=events.id WHERE events.license_id=$1 ORDER BY events.after_revision`, [companyPool.id])).rows, [
      { type: 'app.license.pool.created', tenant_id: receipt.tenantId, actor_user_id: receipt.administratorId, target_user_id: null, version: 1, before_revision: null, after_revision: '1', status: 'pending' },
      { type: 'app.license.assigned', tenant_id: receipt.tenantId, actor_user_id: receipt.administratorId, target_user_id: employeeIds[0], version: 1, before_revision: '1', after_revision: '2', status: 'pending' },
      { type: 'app.license.released', tenant_id: receipt.tenantId, actor_user_id: receipt.administratorId, target_user_id: employeeIds[0], version: 1, before_revision: '2', after_revision: '3', status: 'pending' },
    ]);
    assert.equal(companyWrites.length, 3); assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_provider_products')).rows[0].count, providerProductsBefore);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    await page.getByRole('heading', { name: 'Anwendungen & Lizenzen', exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: '/tmp/od-business12-company-license-released.png', fullPage: true });
    await companyUserPicker.selectOption(employeeIds[0]); await companyPoolDetails.getByLabel('Begründung', { exact: true }).fill(assignmentReason);
    await companyPoolDetails.getByRole('button', { name: 'Lizenz zuweisen', exact: true }).click();
    const reassigningFirstPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/assignments' && response.request().method() === 'POST');
    await page.getByRole('alertdialog', { name: 'Lizenzzuweisung bestätigen', exact: true }).getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const firstPoolReassigned = await reassigningFirstPool; assert.equal(firstPoolReassigned.status(), 201, await firstPoolReassigned.text());
    await page.getByText('Lokale Lizenzzuweisung gespeichert.', { exact: true }).waitFor();
    const occupiedCompanyPool = await firstPoolReassigned.json();
    const beforePoolEdit = await allocationState(); assert.equal(beforePoolEdit.used_seats, 1);
    const poolEditState = async () => {
      const state = {};
      for (const table of ['license_subjects', 'license_assignments', 'license_assignment_sources', 'license_grants', 'license_grant_events', 'license_provider_connectors', 'license_provider_products', 'license_provider_subjects', 'license_provider_limits', 'license_fulfillment_targets', 'license_fulfillment_changes', 'license_fulfillment_events']) {
        state[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
      }
      return state;
    };
    const retainedBeforePoolEdit = await poolEditState();
    const companyPoolEditValues = { name: 'Browser Company Renamed Licensed Editor', vendor: 'Updated Company Vendor', description: 'Actual browser metadata and occupied local stock correction', totalSeats: 3, reason: 'Explicit actual browser metadata and license stock correction', confirm: true };
    const checkingPoolEdit = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/edit-capabilities' && response.request().method() === 'GET');
    await companyPoolDetails.getByRole('button', { name: 'App und Lizenzbestand bearbeiten', exact: true }).click();
    const poolEditCapabilities = await checkingPoolEdit; assert.equal(poolEditCapabilities.status(), 200, await poolEditCapabilities.text());
    assert.deepEqual(await poolEditCapabilities.json(), { schemaVersion: 1, companyPoolEditProtocol: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, poolId: companyPool.id, poolRevision: occupiedCompanyPool.revision });
    const poolEditDialog = page.getByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten', exact: true }); await poolEditDialog.waitFor();
    for (const [label, value] of [['Anwendungsname', occupiedCompanyPool.name], ['Hersteller', occupiedCompanyPool.vendor], ['Beschreibung', occupiedCompanyPool.description], ['Lizenzanzahl', String(occupiedCompanyPool.totalSeats)]]) assert.equal(await poolEditDialog.getByLabel(label, { exact: true }).inputValue(), value);
    assert.equal(await poolEditDialog.getByLabel('Lizenzanzahl', { exact: true }).getAttribute('min'), '1'); assert.equal(await poolEditDialog.getByLabel('Lizenzanzahl', { exact: true }).getAttribute('max'), '10000');
    for (const [label, value] of [['Anwendungsname', companyPoolEditValues.name], ['Hersteller', companyPoolEditValues.vendor], ['Beschreibung', companyPoolEditValues.description], ['Lizenzanzahl', String(companyPoolEditValues.totalSeats)], ['Begründung', companyPoolEditValues.reason]]) await poolEditDialog.getByLabel(label, { exact: true }).fill(value);
    assert.deepEqual(await allocationState(), beforePoolEdit); assert.deepEqual(await poolEditState(), retainedBeforePoolEdit); assert.equal(companyPoolEdits.length, 0);
    await poolEditDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const poolEditConfirmation = page.getByRole('alertdialog', { name: 'Änderungen an App und Lizenzbestand bestätigen', exact: true }); await poolEditConfirmation.waitFor();
    const editComparison = poolEditConfirmation.getByRole('table', { name: 'App und Lizenzbestand vorher und nachher', exact: true });
    assert.deepEqual(await editComparison.getByRole('columnheader').allTextContents(), ['Feld', 'Vorher', 'Nachher']);
    for (const [label, previous, next] of [['Anwendungsname', occupiedCompanyPool.name, companyPoolEditValues.name], ['Hersteller', occupiedCompanyPool.vendor, companyPoolEditValues.vendor], ['Beschreibung', occupiedCompanyPool.description, companyPoolEditValues.description], ['Lizenzbestand', String(occupiedCompanyPool.totalSeats), String(companyPoolEditValues.totalSeats)]]) {
      const changeRow = editComparison.getByRole('row').filter({ has: page.getByRole('rowheader', { name: label, exact: true }) });
      assert.deepEqual(await changeRow.getByRole('cell').allTextContents(), [previous, next]);
    }
    await poolEditConfirmation.getByText('Begründung: ' + companyPoolEditValues.reason, { exact: true }).waitFor();
    assert.deepEqual(await allocationState(), beforePoolEdit); assert.deepEqual(await poolEditState(), retainedBeforePoolEdit); assert.equal(companyPoolEdits.length, 0);
    await page.screenshot({ path: '/tmp/od-business16-pool-edit-confirmation.png', fullPage: true });
    const updatingCompanyPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id && response.request().method() === 'PATCH');
    const refreshingCompanyPools = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools' && response.request().method() === 'GET');
    const readingEditedPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id && response.request().method() === 'GET');
    const readingEditedHistory = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + companyPool.id + '/history' && response.request().method() === 'GET');
    await poolEditConfirmation.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const poolEditResponse = await updatingCompanyPool; assert.equal(poolEditResponse.status(), 200, await poolEditResponse.text());
    assert.deepEqual(poolEditResponse.request().postDataJSON(), companyPoolEditValues); assert.equal(poolEditResponse.request().headers()['if-match'], '"company-pool-' + companyPool.id + '-' + occupiedCompanyPool.revision + '"');
    const editedCompanyPool = await poolEditResponse.json();
    assert.deepEqual(editedCompanyPool, { ...occupiedCompanyPool, name: companyPoolEditValues.name, vendor: companyPoolEditValues.vendor, description: companyPoolEditValues.description,
      totalSeats: 3, usedSeats: 1, availableSeats: 2, revision: String(BigInt(occupiedCompanyPool.revision) + 1n), updatedAt: editedCompanyPool.updatedAt });
    assert.equal(poolEditResponse.headers().etag, '"company-pool-' + companyPool.id + '-' + editedCompanyPool.revision + '"'); assert.equal(poolEditResponse.headers()['cache-control'], 'no-store');
    await page.getByText('App und lokaler Lizenzbestand aktualisiert.', { exact: true }).waitFor();
    const refreshedCompanyPools = await refreshingCompanyPools; assert.equal(refreshedCompanyPools.status(), 200, await refreshedCompanyPools.text());
    assert.deepEqual((await refreshedCompanyPools.json()).pools.find(pool => pool.id === companyPool.id), editedCompanyPool);
    const editedPoolReadback = await readingEditedPool; assert.equal(editedPoolReadback.status(), 200, await editedPoolReadback.text()); assert.deepEqual(await editedPoolReadback.json(), editedCompanyPool);
    await companyPoolDetails.getByRole('heading', { name: companyPoolEditValues.name, exact: true }).waitFor();
    for (const [label, value] of [['Lizenzbestand', '3'], ['Zugewiesen', '1'], ['Verfügbar', '2']]) assert.equal(await companyPoolDetails.locator('dt').filter({ hasText: new RegExp('^' + label + '$') }).locator('..').locator('dd').innerText(), value);
    assert.deepEqual(await allocationState(), { ...beforePoolEdit, total_seats: 3, revision: editedCompanyPool.revision }); assert.deepEqual(await poolEditState(), retainedBeforePoolEdit); assert.equal(companyPoolEdits.length, 1);
    await companyPoolDetails.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business16-pool-edit-completed.png', fullPage: true });
    const poolEditHistoryResponse = await readingEditedHistory; assert.equal(poolEditHistoryResponse.status(), 200, await poolEditHistoryResponse.text()); const poolEditHistory = await poolEditHistoryResponse.json();
    assert.deepEqual([poolEditHistory.actorUserId, poolEditHistory.tenantId, poolEditHistory.poolId, poolEditHistory.total], [receipt.administratorId, receipt.tenantId, companyPool.id, 5]); assert.ok(poolEditHistory.events.every(event => event.deliveryStatus === 'pending'));
    const poolEditEvents = poolEditHistory.events.filter(event => event.type === 'app.license.pool.updated'); assert.equal(poolEditEvents.length, 1);
    assert.deepEqual([poolEditEvents[0].userId, poolEditEvents[0].beforeRevision, poolEditEvents[0].afterRevision], [null, occupiedCompanyPool.revision, editedCompanyPool.revision]);
    const retainedPoolEdit = (await policyDb.query(`SELECT event.*,outbox.status,license_company_event_valid(event) AS valid FROM license_company_events event JOIN license_company_outbox outbox USING(id) WHERE event.id=$1`, [poolEditEvents[0].id])).rows[0];
    assert.deepEqual([retainedPoolEdit.tenant_id, retainedPoolEdit.actor_user_id, retainedPoolEdit.target_user_id, retainedPoolEdit.status, retainedPoolEdit.valid], [receipt.tenantId, receipt.administratorId, null, 'pending', true]);
    const editAuthorization = poolEditResponse.request().headers().authorization; assert.match(editAuthorization, /^Bearer [A-Za-z0-9._~-]+$/);
    const ownerClaims = JSON.parse(Buffer.from(editAuthorization.slice('Bearer '.length).split('.')[1], 'base64url'));
    assert.equal(ownerClaims.actor_type, 'user'); assert.equal(ownerClaims.identity_authorization.userId, receipt.administratorId);
    assert.equal(ownerClaims.iss, logicalIssuer); assert.equal(ownerClaims.sub, 'company-registration-owner-subject'); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(ownerClaims), true);
    assert.equal(retainedPoolEdit.proof.source.tokenId, ownerClaims.jti); assert.equal(retainedPoolEdit.proof.source.subject, ownerClaims.sub); assert.equal(retainedPoolEdit.proof.source.issuer, logicalIssuer);
    assert.deepEqual(retainedPoolEdit.proof.source.context, ownerClaims.identity_authorization); assert.deepEqual(ownerClaims.amr, ['pwd', 'otp']); assert.deepEqual(ownerClaims.roles, []);
    assert.deepEqual(retainedPoolEdit.proof.source.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']); assert.equal(retainedPoolEdit.proof.source.target, null); assert.deepEqual(retainedPoolEdit.proof.checkpoint, retainedPoolEdit.proof.source);
    assert.deepEqual(retainedPoolEdit.proof.command.values, { name: companyPoolEditValues.name, vendor: companyPoolEditValues.vendor, description: companyPoolEditValues.description, totalSeats: 3 });
    const poolEditOrigins = (await policyDb.query('SELECT relation,operation,before_state,after_state FROM license_company_origins WHERE command_id=$1 ORDER BY ordinal', [poolEditEvents[0].id])).rows;
    assert.deepEqual(poolEditOrigins.map(entry => entry.relation + ':' + entry.operation).sort(), ['license_audit_events:INSERT', 'license_catalog:UPDATE', 'license_catalog:UPDATE']);
    const poolEditCatalogOrigins = poolEditOrigins.filter(entry => entry.relation === 'license_catalog'); assert.equal(poolEditCatalogOrigins.length, 2);
    assert.ok(poolEditCatalogOrigins.every(entry => entry.operation === 'UPDATE' && entry.before_state.id === companyPool.id && entry.after_state.id === companyPool.id && entry.before_state.used_seats === entry.after_state.used_seats));
    assert.equal(poolEditCatalogOrigins[0].before_state.name, occupiedCompanyPool.name); assert.equal(poolEditCatalogOrigins.at(-1).after_state.name, companyPoolEditValues.name); assert.equal(poolEditCatalogOrigins.at(-1).after_state.total_seats, 3);
    await companyHistory.getByText('App und Lizenzbestand aktualisiert', { exact: true }).waitFor();
    await companyHistory.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business16-pool-edit-history.png', fullPage: true });
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    const secondPoolValues = { ...companyPoolValues, name: 'Browser Company Licensed Designer' };
    await page.getByRole('button', { name: 'Lizenzpool erstellen', exact: true }).click();
    for (const [label, value] of [['Anwendungsname', secondPoolValues.name], ['Hersteller', secondPoolValues.vendor], ['Beschreibung', secondPoolValues.description], ['Lizenzanzahl', '1'], ['Begründung', secondPoolValues.reason]]) await poolDialog.getByLabel(label, { exact: true }).fill(value);
    const creatingSecondPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools' && response.request().method() === 'POST');
    await poolDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const secondPoolResponse = await creatingSecondPool; assert.equal(secondPoolResponse.status(), 201, await secondPoolResponse.text()); const secondPool = await secondPoolResponse.json();
    await page.getByRole('button', { name: secondPoolValues.name, exact: true }).click(); await companyUserPicker.selectOption(employeeIds[0]);
    await companyPoolDetails.getByLabel('Begründung', { exact: true }).fill(assignmentReason); await companyPoolDetails.getByRole('button', { name: 'Lizenz zuweisen', exact: true }).click();
    const assigningSecondPool = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/pools/' + secondPool.id + '/assignments' && response.request().method() === 'POST');
    await page.getByRole('alertdialog', { name: 'Lizenzzuweisung bestätigen', exact: true }).getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const secondPoolAssigned = await assigningSecondPool; assert.equal(secondPoolAssigned.status(), 201, await secondPoolAssigned.text());
    await page.getByText('Lokale Lizenzzuweisung gespeichert.', { exact: true }).waitFor();
    const returnPoolIds = [companyPool.id, secondPool.id]; const returnStates = await Promise.all(returnPoolIds.map(poolId => allocationState(poolId)));
    assert.deepEqual(returnStates.map(state => [state.used_seats, state.assignments, state.sources, state.active_grants]), [[1, 1, 1, 1], [1, 1, 1, 1]]);
    const returnRoute = companyRoute + '/users/' + employeeIds[0] + '/license-returns';
    const returnsPanel = page.getByRole('region', { name: 'Mitarbeiter-Lizenzrückgabe', exact: true });
    await returnsPanel.getByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben', exact: true }).click();
    await returnsPanel.getByLabel('Mitarbeiter-ID für Lizenzrückgabe', { exact: true }).fill(employeeIds[0]);
    const activePreviewPending = page.waitForResponse(response => new URL(response.url()).pathname === returnRoute && response.request().method() === 'GET');
    await returnsPanel.getByRole('button', { name: 'Lizenzrückgabe-Vorschau laden', exact: true }).click();
    const activePreviewResponse = await activePreviewPending; assert.equal(activePreviewResponse.status(), 200, await activePreviewResponse.text()); const activePreview = await activePreviewResponse.json();
    assert.equal(activePreview.target.enabled, true); assert.equal(activePreview.total, 2); assert.equal(activePreview.assignments.length, 2);
    await returnsPanel.getByText('Aktiver Mitarbeiter: Rückgabe gesperrt. Zuerst People → Konto sperren, danach ausdrücklich eine neue Vorschau laden.', { exact: true }).waitFor();
    assert.equal(await returnsPanel.getByRole('button', { name: 'Diese Seite zurückgeben', exact: true }).isDisabled(), true);
    assert.equal(companyWrites.length, 6); assert.deepEqual(await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))), returnStates);
    await page.goto(origin + '/users');
    await page.getByRole('region', { name: 'Kanonische Benutzerliste', exact: true }).getByLabel('Suche', { exact: true }).fill('browser-company-employee-one');
    await page.getByRole('button', { name: 'Benutzer browser-company-employee-one', exact: true }).click(); await employeeDetails.getByRole('button', { name: 'Konto sperren', exact: true }).click();
    const disableDialog = page.getByRole('alertdialog', { name: 'Konto sperren', exact: true }); await disableDialog.waitFor();
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [employeeIds[0]])).rows[0].enabled, true);
    const disablingEmployee = page.waitForResponse(response => new URL(response.url()).pathname === '/api/users/' + employeeIds[0] && response.request().method() === 'PUT');
    await disableDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const disabledEmployeeResponse = await disablingEmployee;
    assert.equal(disabledEmployeeResponse.status(), 200, await disabledEmployeeResponse.text()); assert.deepEqual(disabledEmployeeResponse.request().postDataJSON(), { enabled: false }); assert.ok(disabledEmployeeResponse.request().headers()['if-match']);
    await employeeDetails.getByRole('button', { name: 'Konto freigeben', exact: true }).waitFor();
    assert.equal((await identityDb.query('SELECT enabled FROM users WHERE id=$1', [employeeIds[0]])).rows[0].enabled, false);
    assert.deepEqual(await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))), returnStates); assert.equal(companyWrites.length, 6);
    await page.goto(origin + '/applications'); await returnsPanel.getByRole('button', { name: 'Lizenzen eines Mitarbeiters zurückgeben', exact: true }).click();
    await returnsPanel.getByLabel('Mitarbeiter-ID für Lizenzrückgabe', { exact: true }).fill(employeeIds[0]);
    const returnPreviewPending = page.waitForResponse(response => new URL(response.url()).pathname === returnRoute && response.request().method() === 'GET');
    await returnsPanel.getByRole('button', { name: 'Lizenzrückgabe-Vorschau laden', exact: true }).click(); const returnPreviewResponse = await returnPreviewPending;
    assert.equal(returnPreviewResponse.status(), 200, await returnPreviewResponse.text()); const returnPreview = await returnPreviewResponse.json();
    assert.deepEqual(returnPreview, { ...activePreview, target: { enabled: false, deleted: false, eligibilityRevision: String((await identityDb.query('SELECT eligibility_revision FROM users WHERE id=$1', [employeeIds[0]])).rows[0].eligibility_revision) } });
    assert.ok(BigInt(returnPreview.target.eligibilityRevision) > BigInt(activePreview.target.eligibilityRevision));
    await returnsPanel.getByRole('region', { name: 'Lizenzrückgabe-Vorschau', exact: true }).getByText('2 Zuweisungen auf dieser Seite von 2 insgesamt. Nur diese vollständige Seite mit höchstens 25 Zuweisungen wird ausgewählt.', { exact: true }).waitFor();
    const returnReason = 'Actual Chrome returns this captured page after People account disable';
    await returnsPanel.getByLabel('Begründung der Lizenzrückgabe', { exact: true }).fill(returnReason); await returnsPanel.getByRole('button', { name: 'Diese Seite zurückgeben', exact: true }).click();
    const returnDialog = page.getByRole('alertdialog', { name: 'Mitarbeiter-Lizenzrückgabe bestätigen', exact: true }); await returnDialog.waitFor();
    await returnDialog.getByText('Seite 1: genau 2 von insgesamt 2 Zuweisungen. Weitere Seiten werden nicht automatisch bearbeitet.', { exact: true }).waitFor();
    assert.deepEqual(await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))), returnStates); assert.equal(companyWrites.length, 6);
    await page.screenshot({ path: '/tmp/od-business13-company-license-return-confirmation.png', fullPage: true });
    const returningLicenses = page.waitForResponse(response => new URL(response.url()).pathname === returnRoute && response.request().method() === 'POST');
    await returnDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const returnResponse = await returningLicenses;
    assert.equal(returnResponse.status(), 200, await returnResponse.text()); const returned = await returnResponse.json();
    const returnAssignments = returnPreview.assignments.map(assignment => ({ poolId: assignment.poolId, assignmentId: assignment.id, poolRevision: assignment.poolRevision }));
    assert.deepEqual(returnResponse.request().postDataJSON(), { reason: returnReason, confirm: true, assignments: returnAssignments });
    assert.match(returned.correlationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
    assert.deepEqual(returned, { schemaVersion: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, userId: employeeIds[0], correlationId: returned.correlationId,
      results: returnAssignments.map(assignment => ({ poolId: assignment.poolId, assignmentId: assignment.assignmentId, status: 'released', code: 200 })) });
    const returnedStates = await Promise.all(returnPoolIds.map(poolId => allocationState(poolId)));
    assert.deepEqual(returnedStates, returnStates.map(state => ({ ...state, used_seats: 0, revision: String(BigInt(state.revision) + 1n), assignments: 0, sources: 0, active_grants: 0 })));
    const returnReceipts = (await policyDb.query(`SELECT events.id,events.license_id,events.type,events.actor_user_id,events.target_user_id,events.tenant_id,events.correlation_id,outbox.status,license_company_event_valid(events) AS valid
      FROM license_company_events events JOIN license_company_outbox outbox ON outbox.id=events.id WHERE events.correlation_id=$1 ORDER BY events.license_id`, [returned.correlationId])).rows;
    assert.deepEqual(returnReceipts, [...returnPoolIds].sort().map(poolId => ({ id: returnReceipts.find(event => event.license_id === poolId)?.id, license_id: poolId, type: 'app.license.released', actor_user_id: receipt.administratorId,
      target_user_id: employeeIds[0], tenant_id: receipt.tenantId, correlation_id: returned.correlationId, status: 'pending', valid: true })));
    assert.equal(new Set(returnReceipts.map(event => event.id)).size, 2);
    for (const event of returnReceipts) {
      await assert.rejects(policyDb.query('UPDATE license_company_events SET correlation_id=$2 WHERE id=$1', [event.id, randomUUID()]), error => ['42501', '23514'].includes(error.code));
      await assert.rejects(policyDb.query('DELETE FROM license_company_outbox WHERE id=$1', [event.id]), error => ['42501', '23514'].includes(error.code));
    }
    const returnResult = page.getByRole('region', { name: 'Ergebnis der Lizenzrückgabe', exact: true });
    await returnResult.getByText('2 von 2 Freigaben dieser Seite bestätigt · Seite 1 · zuvor 2 Zuweisungen insgesamt.', { exact: true }).waitFor();
    assert.equal(await returnResult.getByRole('listitem').count(), 2);
    for (const assignment of returnPreview.assignments) {
      const resultRow = returnResult.getByRole('listitem').filter({ hasText: assignment.name + ' · Freigabe bestätigt (200)' });
      await resultRow.getByText(assignment.name + ' · Freigabe bestätigt (200)', { exact: true }).waitFor(); await resultRow.getByText(assignment.vendor, { exact: true }).waitFor();
      const proof = resultRow.locator('details'); const proofSummary = proof.locator('summary');
      assert.equal(await proof.getAttribute('open'), null);
      for (const value of [assignment.poolId, assignment.id, employeeIds[0], returned.correlationId]) assert.equal(await proof.getByText(value, { exact: true }).isVisible(), false);
      await proofSummary.focus(); await proofSummary.press('Enter'); assert.equal(await proof.getAttribute('open'), '');
      for (const value of [assignment.poolId, assignment.id, employeeIds[0], returned.correlationId]) assert.equal(await proof.getByText(value, { exact: true }).isVisible(), true);
      if (assignment.id === returnPreview.assignments[0].id) await page.screenshot({ path: '/tmp/od-business13-company-license-return-proof.png', fullPage: true });
      await proofSummary.press('Enter'); assert.equal(await proof.getAttribute('open'), null);
    }
    assert.equal((await returnResult.innerText()).includes(returned.correlationId), false);
    assert.equal(companyWrites.length, 7); assert.equal(companyWrites.filter(write => new URL(write.url()).pathname === returnRoute).length, 1);
    assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_provider_products')).rows[0].count, providerProductsBefore);
    assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_fulfillment_targets target JOIN license_provider_products product ON product.id=target.product_id WHERE product.license_id=ANY($1::uuid[])', [returnPoolIds])).rows[0].count, 0);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    await page.getByRole('heading', { name: 'Anwendungen & Lizenzen', exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: '/tmp/od-business13-company-license-returns.png', fullPage: true });
    await page.goto(origin + '/users');
    await page.getByRole('region', { name: 'Kanonische Benutzerliste', exact: true }).getByLabel('Suche', { exact: true }).fill('browser-company-employee-one');
    await page.getByRole('button', { name: 'Benutzer browser-company-employee-one', exact: true }).click();
    await employeeDetails.getByRole('button', { name: 'Konto freigeben', exact: true }).click();
    const enablingOffboardingEmployee = page.waitForResponse(response => new URL(response.url()).pathname === '/api/users/' + employeeIds[0] && response.request().method() === 'PUT');
    await page.getByRole('alertdialog', { name: 'Konto freigeben', exact: true }).getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const offboardingEmployeeResponse = await enablingOffboardingEmployee; assert.equal(offboardingEmployeeResponse.status(), 200, await offboardingEmployeeResponse.text());
    await employeeDetails.getByRole('button', { name: 'Konto sperren', exact: true }).waitFor();
    await page.goto(origin + '/applications');
    for (const poolName of [companyPoolEditValues.name, secondPoolValues.name]) {
      await page.getByRole('button', { name: poolName, exact: true }).click(); await companyUserPicker.selectOption(employeeIds[0]);
      await companyPoolDetails.getByLabel('Begründung', { exact: true }).fill('Actual Chrome prepares two owned grants for combined durable offboarding');
      await companyPoolDetails.getByRole('button', { name: 'Lizenz zuweisen', exact: true }).click();
      const assigningOffboardingLicense = page.waitForResponse(response => response.request().method() === 'POST' && new URL(response.url()).pathname.startsWith(companyRoute + '/pools/') && new URL(response.url()).pathname.endsWith('/assignments'));
      await page.getByRole('alertdialog', { name: 'Lizenzzuweisung bestätigen', exact: true }).getByRole('button', { name: 'Bestätigen', exact: true }).click();
      const assigned = await assigningOffboardingLicense; assert.equal(assigned.status(), 201, await assigned.text()); await page.getByText('Lokale Lizenzzuweisung gespeichert.', { exact: true }).waitFor();
    }
    const offboardingAccount = async () => (await identityDb.query('SELECT enabled,record_revision::text,eligibility_revision::text,authorization_revision::text FROM users WHERE id=$1', [employeeIds[0]])).rows[0];
    const accessApi = async (route, { method = 'GET', token, body, headers = {} } = {}) => {
      const response = await page.request.fetch(origin + route, { method, headers: { ...(token ? { Authorization: 'Bearer ' + token } : {}), ...headers }, ...(body ? { data: body } : {}) });
      return { status: response.status(), body: await response.json() };
    };
    const accessOwnerToken = (await mediated(page)).body.access_token; const accessActors = new Map();
    for (const [name, roles] of [['company-access-operator', ['role-administrator', 'pim-administrator']], ['company-access-reviewer', ['admin', 'pim-approver']]]) {
      const account = await accessApi('/api/users', { method: 'POST', token: accessOwnerToken, body: { username: name, email: name + '@example.invalid' } }); assert.equal(account.status, 201, JSON.stringify(account.body));
      const enabled = await accessApi('/api/users/' + account.body.id, { method: 'PUT', token: accessOwnerToken, headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(account.body) }, body: { enabled: true } }); assert.equal(enabled.status, 200, JSON.stringify(enabled.body));
      actors.set(name, { userId: account.body.id, name, roles, permissions: [] }); accessActors.set(name, { id: account.body.id, roles });
      await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [logicalIssuer, name + '-subject', account.body.id], 'fixture-bootstrap');
      for (const role of roles) await require('../../../identity-service/scripts/bootstrap-role').bootstrapRole(identityDb, { userId: account.body.id, role, duration: 3600, reason: 'Explicit isolated Slice18 own-tenant independent canonical operator fixture' });
    }
    const accessTargetName = 'company-access-target'; actors.set(accessTargetName, { userId: employeeIds[0], name: 'Actual company access target', roles: [], permissions: [] });
    await identityDb.write('INSERT INTO identity_subject_links(issuer,subject,user_id) VALUES($1,$2,$3)', [logicalIssuer, accessTargetName + '-subject', employeeIds[0]], 'fixture-bootstrap');
    await bootstrapApplications({ isAvailable: () => true, pool: issuerDb }, { issuer: logicalIssuer, identityBase, signingKeyFile: path.join(directory, 'signing.pem'), clients: ['web-app'], users: [...accessActors.values()].map(actor => actor.id).concat(employeeIds[0]) });
    const accessEnrollmentContext = await context();
    try {
      for (const name of ['company-access-operator', 'company-access-reviewer', accessTargetName]) {
        const enrollmentPage = await accessEnrollmentContext.newPage(); await login(enrollmentPage, name); const original = (await mediated(enrollmentPage)).body.access_token;
        const setup = await issuerJson('/api/mfa/enroll', { method: 'POST', token: original, body: { username: name, password: 'disposable-password' } }); assert.equal(setup.status, 200, JSON.stringify(setup.body)); const counter = Math.floor(Date.now() / 30000) - 1;
        const confirmed = await issuerJson('/api/mfa/confirm', { method: 'POST', token: original, body: { code: totp(setup.body.secret, counter) } }); assert.equal(confirmed.status, 200, JSON.stringify(confirmed.body)); rememberFactor(name, setup.body.secret, counter);
        await enrollmentPage.close(); await accessEnrollmentContext.clearCookies();
      }
    } finally { await accessEnrollmentContext.close(); }
    const accessOperatorContext = await context(); const accessReviewerContext = await context();
    let accessOperatorToken; let accessReviewerToken; let accessTargetToken;
    try {
      const operatorPage = await accessOperatorContext.newPage(); await login(operatorPage, 'company-access-operator'); accessOperatorToken = (await mediated(operatorPage)).body.access_token;
      const reviewerPage = await accessReviewerContext.newPage(); await login(reviewerPage, 'company-access-reviewer'); accessReviewerToken = (await mediated(reviewerPage)).body.access_token;
    } finally { await accessOperatorContext.close(); await accessReviewerContext.close(); }
    const accessOperatorId = accessActors.get('company-access-operator').id;
    const accessMetadata = await accessApi('/api/identity/access', { token: accessOperatorToken }); assert.equal(accessMetadata.status, 200); for (const forbidden of ['users.read', 'company.apps.read', 'company.apps.create', 'company.apps.assign']) assert.equal(accessMetadata.body.permissions.includes(forbidden), false);
    const accessRole = await accessApi('/api/users/' + employeeIds[0] + '/roles', { method: 'POST', token: accessOperatorToken, body: { role: 'group-administrator', durationSeconds: 3600, reason: 'Actual nonprotected canonical role for independently authorized browser cleanup' } }); assert.equal(accessRole.status, 201, JSON.stringify(accessRole.body));
    const accessProtectedRole = await accessApi('/api/users/' + employeeIds[0] + '/roles', { method: 'POST', token: accessReviewerToken, body: { role: 'role-administrator', durationSeconds: 3600, reason: 'Actual protected canonical assignment must remain blocked to the ordinary operator' } }); assert.equal(accessProtectedRole.status, 201, JSON.stringify(accessProtectedRole.body));
    const accessEligibility = await accessApi('/api/identity/pim/eligibilities', { method: 'POST', token: accessOperatorToken, body: { userId: employeeIds[0], role: 'license-manager', maxDurationSeconds: 3600, validForSeconds: 7200, reason: 'Actual canonical PIM eligibility for later linked offboarding cascade' } }); assert.equal(accessEligibility.status, 201, JSON.stringify(accessEligibility.body));
    const accessTargetLogin = await context();
    let accessActiveRequest;
    try {
      const targetPage = await accessTargetLogin.newPage(); await login(targetPage, accessTargetName); accessTargetToken = (await mediated(targetPage)).body.access_token;
      accessActiveRequest = await accessApi('/api/identity/pim/requests', { method: 'POST', token: accessTargetToken, body: { id: randomUUID(), eligibilityId: accessEligibility.body.id, durationSeconds: 3600, reason: 'Actual beneficiary obtains an independently approved temporary assignment' } }); assert.equal(accessActiveRequest.status, 200, JSON.stringify(accessActiveRequest.body));
      const approved = await accessApi('/api/identity/pim/requests/' + accessActiveRequest.body.id + '/approve', { method: 'POST', token: accessReviewerToken }); assert.equal(approved.status, 200, JSON.stringify(approved.body));
      const active = await accessApi('/api/identity/pim/requests/' + accessActiveRequest.body.id + '/activate', { method: 'POST', token: accessTargetToken }); assert.equal(active.status, 200, JSON.stringify(active.body)); assert.equal(active.body.status, 'active');
    } finally { await accessTargetLogin.close(); }
    const accessActiveAssignment = (await identityDb.query('SELECT id FROM identity_role_assignments WHERE activation_request_id=$1 AND revoked_at IS NULL', [accessActiveRequest.body.id])).rows[0]; assert.ok(accessActiveAssignment);
    const beforeOffboardingAccount = await offboardingAccount(); assert.equal(beforeOffboardingAccount.enabled, true);
    const offboardingStates = await Promise.all(returnPoolIds.map(poolId => allocationState(poolId)));
    assert.deepEqual(offboardingStates.map(state => [state.used_seats, state.assignments, state.sources, state.active_grants]), [[1, 1, 1, 1], [1, 1, 1, 1]]);
    const offboardingAssignments = (await policyDb.query(`SELECT assignment.id AS assignment_id,assignment.license_id,source.grant_id FROM license_assignments assignment
      JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
      WHERE assignment.license_id=ANY($1::uuid[]) AND assignment.assignee_id=$2 ORDER BY assignment.license_id`, [returnPoolIds, employeeIds[0]])).rows;
    assert.equal(offboardingAssignments.length, 2);
    const returnDevices = [];
    for (const suffix of ['CANCEL', 'PHYSICAL', 'CHANGED']) {
      const registered = await accessApi('/api/devices', { method: 'POST', token: accessOwnerToken, body: { assetId: 'BROWSER-RETURN-' + suffix, serialNumber: 'BROWSER-RETURN-SERIAL-' + suffix, manufacturer: 'Example Manufacturer', model: 'Actual browser return laptop', deviceClass: 'laptop', platform: 'macos' } }); assert.equal(registered.status, 201, JSON.stringify(registered.body));
      const assigned = await accessApi('/api/devices/' + registered.body.id + '/assignment', { method: 'PUT', token: accessOwnerToken, headers: { 'If-Match': require('../../../../../packages/device-inventory-contract').deviceEtag(registered.body) }, body: { userId: employeeIds[0] } }); assert.equal(assigned.status, 200, JSON.stringify(assigned.body)); returnDevices.push(assigned.body);
    }
    const offboardingDevicesBefore = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM devices record ORDER BY id')).rows;
    const offboardingGroupsBefore = (await identityDb.query('SELECT to_jsonb(record) AS row FROM group_members record ORDER BY to_jsonb(record)::text')).rows;
    const groupCleanupCalls = []; page.on('request', request => { if (new URL(request.url()).pathname.includes('/company-offboarding-groups')) groupCleanupCalls.push(request); });
    const workflowRoute = companyRoute + '/offboarding-workflows'; const offboardingPanel = page.getByRole('region', { name: 'Mitarbeiter-Offboarding', exact: true });
    await page.goto(origin + '/users');
    await page.getByRole('region', { name: 'Kanonische Benutzerliste', exact: true }).getByLabel('Suche', { exact: true }).fill('browser-company-employee-one');
    await page.getByRole('button', { name: 'Benutzer browser-company-employee-one', exact: true }).click();
    const checkingOffboarding = page.waitForResponse(response => new URL(response.url()).pathname === workflowRoute + '/capabilities' && response.request().method() === 'GET');
    await employeeDetails.getByRole('link', { name: 'Mitarbeiter-Offboarding', exact: true }).click();
    const offboardingCapabilitiesResponse = await checkingOffboarding; assert.equal(offboardingCapabilitiesResponse.status(), 200, await offboardingCapabilitiesResponse.text());
    assert.deepEqual(await offboardingCapabilitiesResponse.json(), { schemaVersion: 1, companyOffboardingProtocol: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, scope: 'account-and-local-licenses', requiresFreshMfa: true });
    await offboardingPanel.getByRole('button', { name: 'Mitarbeitervorschau laden', exact: true }).waitFor();
    assert.equal(await offboardingPanel.getByLabel('Mitarbeiter-ID', { exact: true }).inputValue(), employeeIds[0]);
    const readingOffboardingPreview = page.waitForResponse(response => new URL(response.url()).pathname === companyRoute + '/users/' + employeeIds[0] + '/offboarding-preview' && response.request().method() === 'GET');
    await offboardingPanel.getByRole('button', { name: 'Mitarbeitervorschau laden', exact: true }).click();
    const offboardingPreviewResponse = await readingOffboardingPreview; assert.equal(offboardingPreviewResponse.status(), 200, await offboardingPreviewResponse.text()); const offboardingPreview = await offboardingPreviewResponse.json();
    assert.deepEqual(offboardingPreview, { schemaVersion: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, user: { id: employeeIds[0], name: 'Company Employee One', userRevision: beforeOffboardingAccount.record_revision, eligibilityRevision: beforeOffboardingAccount.eligibility_revision, enabled: true }, licenseCount: 2 });
    await offboardingPanel.getByLabel('Offboarding-Vorschau', { exact: true }).getByText('Company Employee One · Freigegeben · 2 lokale Lizenzzuweisungen zum Vorschauzeitpunkt.', { exact: true }).waitFor();
    const offboardingReason = 'Actual Chrome confirms durable account disable and two local license releases';
    await offboardingPanel.getByLabel('Begründung für neuen Offboarding-Vorgang', { exact: true }).fill(offboardingReason);
    await offboardingPanel.getByRole('button', { name: 'Kontosperre und Lizenzrückgabe starten', exact: true }).click();
    const offboardingDialog = page.getByRole('alertdialog', { name: 'Mitarbeiter-Offboarding bestätigen', exact: true }); await offboardingDialog.waitFor();
    await offboardingDialog.getByText('Vorschau: 2 lokale Zuweisungen.', { exact: true }).waitFor();
    assert.deepEqual(await offboardingAccount(), beforeOffboardingAccount); assert.deepEqual(await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))), offboardingStates);
    assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM company_offboarding_jobs WHERE tenant_id=$1', [receipt.tenantId])).rows[0].count, 0);
    assert.equal(companyWrites.length, 9); await page.screenshot({ path: '/tmp/od-business15-offboarding-confirmation.png', fullPage: true });
    const creatingOffboarding = page.waitForResponse(response => new URL(response.url()).pathname === workflowRoute && response.request().method() === 'POST');
    await offboardingDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const offboardingResponse = await creatingOffboarding; assert.equal(offboardingResponse.status(), 201, await offboardingResponse.text()); const offboarding = await offboardingResponse.json(); const offboardingJob = offboarding.workflow;
    assert.match(offboardingJob.id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
    assert.deepEqual(offboardingResponse.request().postDataJSON(), { workflowId: offboardingJob.id, userId: employeeIds[0], userRevision: offboardingPreview.user.userRevision, eligibilityRevision: offboardingPreview.user.eligibilityRevision, reason: offboardingReason, confirm: true });
    assert.deepEqual([offboarding.actorUserId, offboarding.tenantId, offboardingJob.userId, offboardingJob.createdBy, offboardingJob.phase, offboardingJob.totalLicenses, offboardingJob.completedLicenses, offboardingJob.failure], [receipt.administratorId, receipt.tenantId, employeeIds[0], receipt.administratorId, 'completed_local', 2, 2, null]);
    const offboardingWork = offboardingPanel.getByRole('article', { name: 'Offboarding-Arbeitsstand', exact: true });
    await offboardingWork.getByRole('heading', { name: 'Kontosperre und lokale Lizenzen geprüft', exact: true }).waitFor();
    await offboardingWork.getByText('2 von 2 erfassten lokalen Lizenzzuweisungen zurückgegeben.', { exact: true }).waitFor();
    await offboardingWork.getByText('Kontostatus beim letzten Abruf: Gesperrt.', { exact: true }).waitFor();
    const afterOffboardingAccount = await offboardingAccount(); assert.equal(afterOffboardingAccount.enabled, false);
    for (const field of ['record_revision', 'eligibility_revision', 'authorization_revision']) assert.ok(BigInt(afterOffboardingAccount[field]) > BigInt(beforeOffboardingAccount[field]), field);
    assert.deepEqual(await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))), offboardingStates.map(state => ({ ...state, used_seats: 0, revision: String(BigInt(state.revision) + 1n), assignments: 0, sources: 0, active_grants: 0 })));
    const offboardingIdentityReceipt = (await identityDb.query(`SELECT record.operation_id,record.action,outbox.status FROM identity_company_offboarding_receipts record JOIN identity_company_offboarding_outbox outbox USING(tenant_id,workflow_id) WHERE record.tenant_id=$1 AND record.workflow_id=$2 AND record.user_id=$3`, [receipt.tenantId, offboardingJob.id, employeeIds[0]])).rows;
    assert.deepEqual(offboardingIdentityReceipt, [{ operation_id: offboardingJob.checkpoint.operationId, action: 'disabled', status: 'pending' }]);
    assert.equal(Object.keys(offboardingJob.checkpoint).length, 13);
    const offboardingAuthorization = offboardingResponse.request().headers().authorization; assert.match(offboardingAuthorization, /^Bearer [A-Za-z0-9._~-]+$/u);
    const offboardingClaims = JSON.parse(Buffer.from(offboardingAuthorization.slice('Bearer '.length).split('.')[1], 'base64url'));
    assert.deepEqual(offboardingClaims.roles, []); assert.equal(offboardingClaims.identity_authorization.userId, receipt.administratorId); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(offboardingClaims), true);
    const offboardingChildren = (await policyDb.query(`SELECT event.id,event.license_id,event.type,event.target_user_id,event.actor_user_id,event.correlation_id,event.before_state,event.proof,outbox.status,license_company_event_valid(event) AS valid
      FROM license_company_events event JOIN license_company_outbox outbox ON outbox.id=event.id WHERE event.tenant_id=$1 AND event.correlation_id=$2 ORDER BY event.license_id`, [receipt.tenantId, offboardingJob.id])).rows;
    assert.equal(offboardingChildren.length, 2);
    for (const [index, event] of offboardingChildren.entries()) {
      assert.deepEqual([event.license_id, event.type, event.target_user_id, event.actor_user_id, event.correlation_id, event.status, event.valid], [offboardingAssignments[index].license_id, 'app.license.released', employeeIds[0], receipt.administratorId, offboardingJob.id, 'pending', true]);
      assert.equal(event.before_state.assignment.id, offboardingAssignments[index].assignment_id); assert.equal(event.before_state.source.grant_id, offboardingAssignments[index].grant_id);
      assert.equal(event.proof.source.tokenId, offboardingClaims.jti); assert.equal(event.proof.source.subject, offboardingClaims.sub); assert.deepEqual(event.proof.source.context, offboardingClaims.identity_authorization); assert.deepEqual(event.proof.checkpoint, event.proof.source);
    }
    const offboardingHistoryRows = (await policyDb.query(`SELECT event.id,event.revision::text,event.after_state,outbox.status FROM company_offboarding_events event JOIN company_offboarding_outbox outbox USING(id,tenant_id) WHERE event.tenant_id=$1 AND event.workflow_id=$2 ORDER BY event.revision DESC`, [receipt.tenantId, offboardingJob.id])).rows;
    assert.equal(offboardingHistoryRows.length, Number(offboardingJob.revision)); assert.ok(offboardingHistoryRows.every(event => event.status === 'pending'));
    assert.equal((await policyDb.query('SELECT company_offboarding_job_valid(job) AS valid FROM company_offboarding_jobs job WHERE tenant_id=$1 AND id=$2', [receipt.tenantId, offboardingJob.id])).rows[0].valid, true);
    await offboardingPanel.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business15-offboarding-completed.png', fullPage: true });
    await page.reload();
    const savedOffboarding = offboardingPanel.getByRole('region', { name: 'Gespeicherte Offboarding-Vorgänge', exact: true });
    const savedJobButton = savedOffboarding.getByRole('button', { name: /Kontosperre und lokale Lizenzen geprüft · 2 \/ 2$/ }); await savedJobButton.waitFor();
    const readingSavedJob = page.waitForResponse(response => new URL(response.url()).pathname === workflowRoute + '/' + offboardingJob.id && response.request().method() === 'GET');
    const readingSavedHistory = page.waitForResponse(response => new URL(response.url()).pathname === workflowRoute + '/' + offboardingJob.id + '/history' && response.request().method() === 'GET');
    await savedJobButton.click(); const savedJobResponse = await readingSavedJob; assert.equal(savedJobResponse.status(), 200, await savedJobResponse.text()); assert.deepEqual(await savedJobResponse.json(), offboarding);
    const savedHistoryResponse = await readingSavedHistory; assert.equal(savedHistoryResponse.status(), 200, await savedHistoryResponse.text()); const savedHistory = await savedHistoryResponse.json();
    assert.deepEqual([savedHistory.actorUserId, savedHistory.tenantId, savedHistory.workflowId, savedHistory.total, savedHistory.page, savedHistory.limit], [receipt.administratorId, receipt.tenantId, offboardingJob.id, offboardingHistoryRows.length, 1, 25]);
    assert.deepEqual(savedHistory.events.map(event => [event.id, event.revision, event.phase, event.deliveryStatus]), offboardingHistoryRows.map(event => [event.id, event.revision, event.after_state.state.phase, 'pending']));
    await offboardingWork.getByText('2 von 2 erfassten lokalen Lizenzzuweisungen zurückgegeben.', { exact: true }).waitFor();
    const offboardingHistory = offboardingWork.getByRole('region', { name: 'Offboarding-Historie', exact: true }); await offboardingHistory.getByRole('listitem').first().waitFor();
    assert.equal(await offboardingHistory.getByRole('listitem').count(), savedHistory.total);
    await page.screenshot({ path: '/tmp/od-business15-offboarding-history.png', fullPage: true });
    const checkpointProof = offboardingWork.getByRole('region', { name: 'Nachweis der Kontosperre', exact: true }).locator('details');
    assert.equal(await checkpointProof.getAttribute('open'), null); assert.equal(await checkpointProof.getByText(offboardingJob.checkpoint.operationId, { exact: true }).isVisible(), false);
    await checkpointProof.locator('summary').focus(); await checkpointProof.locator('summary').press('Enter');
    for (const value of [offboardingJob.id, offboardingJob.checkpoint.operationId, receipt.administratorId]) assert.equal(await checkpointProof.getByText(value, { exact: true }).isVisible(), true);
    await page.screenshot({ path: '/tmp/od-business15-offboarding-proof.png', fullPage: true });
    assert.equal(companyWrites.length, 10); assert.equal(companyWrites.filter(write => new URL(write.url()).pathname === workflowRoute).length, 1); assert.equal(companyPoolEdits.length, 1);
    assert.deepEqual(await offboardingAccount(), afterOffboardingAccount);
    assert.deepEqual((await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM devices record ORDER BY id')).rows, offboardingDevicesBefore);
    assert.deepEqual((await identityDb.query('SELECT to_jsonb(record) AS row FROM group_members record ORDER BY to_jsonb(record)::text')).rows, offboardingGroupsBefore);
    assert.equal((await policyDb.query('SELECT count(*)::int AS count FROM license_provider_products')).rows[0].count, providerProductsBefore);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    const groupCleanupRoute = '/api/users/' + employeeIds[0] + '/company-offboarding-groups';
    const groupCleanupQuery = '?workflowId=' + offboardingJob.id + '&page=1&limit=25';
    const groupCleanupEnvelope = { schemaVersion: 1, companyOffboardingGroupsProtocol: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, workflowId: offboardingJob.id, userId: employeeIds[0],
      target: { enabled: false, eligibilityRevision: afterOffboardingAccount.eligibility_revision } };
    const { companyOffboardingGroupsProtocol, ...groupCleanupHistoryEnvelope } = groupCleanupEnvelope;
    const capturedGroupLinks = (await identityDb.query(`SELECT collection.id AS "groupId",collection.name,collection.revision::text AS "groupRevision",member.membership_id AS "membershipId"
      FROM groups collection JOIN group_members member ON member.group_id=collection.id WHERE member.user_id=$1 ORDER BY collection.id`, [employeeIds[0]])).rows;
    assert.equal(capturedGroupLinks.length, 2); assert.deepEqual(new Set(capturedGroupLinks.map(item => item.groupId)), new Set([group.id, secondGroup.id]));
    const groupCleanupState = async () => {
      const state = { pools: await Promise.all(returnPoolIds.map(poolId => allocationState(poolId))) };
      for (const table of ['users', 'groups', 'group_members', 'identity_group_audit', 'identity_group_outbox', 'identity_membership_origins', 'identity_membership_review_leases', 'identity_membership_review_audit', 'identity_directory_group_events', 'identity_directory_group_outbox', 'identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'identity_company_offboarding_group_receipts', 'identity_company_offboarding_group_outbox', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit']) {
        state[table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
      }
      for (const table of ['company_offboarding_jobs', 'company_offboarding_events', 'company_offboarding_outbox', 'license_company_events', 'license_company_outbox']) {
        state[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
      }
      return state;
    };
    const beforeGroupCleanup = await groupCleanupState(); assert.equal(groupCleanupCalls.length, 0);
    const readingGroupPreview = page.waitForResponse(response => new URL(response.url()).pathname === groupCleanupRoute && response.request().method() === 'GET');
    const readingEmptyGroupHistory = page.waitForResponse(response => new URL(response.url()).pathname === groupCleanupRoute + '/history' && response.request().method() === 'GET');
    await offboardingWork.getByRole('button', { name: 'Gruppen beim Austritt entfernen', exact: true }).click();
    const groupCleanupPanel = offboardingWork.getByRole('region', { name: 'Gruppenbereinigung beim Austritt', exact: true }); await groupCleanupPanel.waitFor();
    const groupPreviewResponse = await readingGroupPreview; assert.equal(groupPreviewResponse.status(), 200, await groupPreviewResponse.text()); const groupPreview = await groupPreviewResponse.json();
    assert.deepEqual(groupPreview, { ...groupCleanupEnvelope, groups: capturedGroupLinks, total: 2, page: 1, limit: 25 });
    const emptyGroupHistoryResponse = await readingEmptyGroupHistory; assert.equal(emptyGroupHistoryResponse.status(), 200, await emptyGroupHistoryResponse.text());
    assert.deepEqual(await emptyGroupHistoryResponse.json(), { ...groupCleanupHistoryEnvelope, receipts: [], total: 0, page: 1, limit: 25 });
    for (const response of [groupPreviewResponse, emptyGroupHistoryResponse]) {
      const query = new URL(response.url()).searchParams; assert.equal(query.get('workflowId'), offboardingJob.id); assert.equal(query.get('page'), '1'); assert.equal(query.get('limit'), '25'); assert.equal([...query].length, 3);
    }
    for (const membership of capturedGroupLinks) await groupCleanupPanel.getByRole('region', { name: 'Gruppenvorschau', exact: true }).getByText(membership.name + ' · Gruppenversion ' + membership.groupRevision, { exact: true }).waitFor();
    assert.deepEqual(await groupCleanupState(), beforeGroupCleanup);
    const groupCleanupReason = 'Actual Chrome explicitly removes only two previewed own company group links';
    await groupCleanupPanel.getByLabel('Begründung für Gruppenentfernung', { exact: true }).fill(groupCleanupReason);
    await groupCleanupPanel.getByRole('button', { name: 'Angezeigte Gruppen entfernen', exact: true }).click();
    const groupCleanupDialog = page.getByRole('alertdialog', { name: 'Gruppenentfernung bestätigen', exact: true }); await groupCleanupDialog.waitFor();
    await groupCleanupDialog.getByText('Genau diese 2 angezeigten Gruppenmitgliedschaften entfernen. Weitere Seiten benötigen eine neue Vorschau und Bestätigung.', { exact: true }).waitFor();
    await groupCleanupDialog.getByRole('button', { name: 'Abbrechen', exact: true }).click();
    assert.equal(groupCleanupCalls.filter(request => request.method() === 'POST').length, 0); assert.deepEqual(await groupCleanupState(), beforeGroupCleanup);
    await groupCleanupPanel.getByRole('button', { name: 'Angezeigte Gruppen entfernen', exact: true }).click(); await groupCleanupDialog.waitFor();
    assert.equal(groupCleanupCalls.filter(request => request.method() === 'POST').length, 0); assert.deepEqual(await groupCleanupState(), beforeGroupCleanup);
    await groupCleanupDialog.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business17-group-cleanup-confirmation.png', fullPage: true });
    const unknownGroupResponse = process.env.OD_BUSINESS17_UNKNOWN_GROUP_RESPONSE === '1'; let actualGroupRemoval;
    if (unknownGroupResponse) await page.route('**' + groupCleanupRoute, async route => {
      if (route.request().method() !== 'POST') return route.fallback();
      const actual = await route.fetch(); assert.equal(actual.status(), 200, await actual.text()); actualGroupRemoval = await actual.json();
      await route.fulfill({ response: actual, json: { ...actualGroupRemoval, results: [] } });
    });
    const removingGroups = page.waitForResponse(response => new URL(response.url()).pathname === groupCleanupRoute && response.request().method() === 'POST');
    await groupCleanupDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const removedGroupResponse = await removingGroups; assert.equal(removedGroupResponse.status(), 200, await removedGroupResponse.text()); const removedGroups = unknownGroupResponse ? actualGroupRemoval : await removedGroupResponse.json();
    assert.deepEqual(removedGroupResponse.request().postDataJSON(), { workflowId: offboardingJob.id, eligibilityRevision: afterOffboardingAccount.eligibility_revision, reason: groupCleanupReason, confirm: true,
      memberships: capturedGroupLinks.map(({ name, ...membership }) => membership) }); assert.equal(new URL(removedGroupResponse.url()).search, '');
    assert.deepEqual(removedGroups, { schemaVersion: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, workflowId: offboardingJob.id, userId: employeeIds[0], correlationId: removedGroups.correlationId,
      results: capturedGroupLinks.map(membership => ({ groupId: membership.groupId, membershipId: membership.membershipId, status: 'removed', code: 200, operationId: removedGroups.results.find(result => result.groupId === membership.groupId)?.operationId })) });
    assert.match(removedGroups.correlationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
    const groupAuthorization = removedGroupResponse.request().headers().authorization; assert.match(groupAuthorization, /^Bearer [A-Za-z0-9._~-]+$/u);
    const groupBearer = groupAuthorization.slice('Bearer '.length); const groupClaims = JSON.parse(Buffer.from(groupBearer.split('.')[1], 'base64url'));
    assert.deepEqual(groupClaims.roles, []); assert.deepEqual(groupClaims.amr, ['pwd', 'otp']); assert.equal(groupClaims.identity_authorization.userId, receipt.administratorId); assert.equal(groupClaims.iss, logicalIssuer); assert.equal(groupClaims.sub, 'company-registration-owner-subject'); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(groupClaims), true);
    const groupReceipts = (await identityDb.query(`SELECT record.*,outbox.status FROM identity_company_offboarding_group_receipts record JOIN identity_company_offboarding_group_outbox outbox USING(id)
      WHERE record.tenant_id=$1 AND record.workflow_id=$2 AND record.user_id=$3 ORDER BY record.created_at,record.id`, [receipt.tenantId, offboardingJob.id, employeeIds[0]])).rows;
    assert.equal(groupReceipts.length, 2);
    for (const record of groupReceipts) {
      const membership = capturedGroupLinks.find(item => item.groupId === record.group_id); const result = removedGroups.results.find(item => item.groupId === record.group_id); assert.ok(membership); assert.ok(result);
      assert.match(result.operationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u);
      assert.deepEqual([record.membership_id, record.operation_id, record.actor_user_id, record.reason, record.status], [membership.membershipId, result.operationId, receipt.administratorId, groupCleanupReason, 'pending']);
      assert.equal(String(record.before_group_revision), membership.groupRevision); assert.ok(BigInt(record.after_group_revision) > BigInt(membership.groupRevision));
      assert.equal((await identityDb.query('SELECT revision::text FROM groups WHERE id=$1', [record.group_id])).rows[0].revision, String(record.after_group_revision));
      assert.equal(record.source.tokenSha256, createHash('sha256').update(groupAuthorization).digest('hex')); assert.equal(record.source.subject, groupClaims.sub); assert.equal(record.source.issuer, groupClaims.iss); assert.deepEqual(record.source.context, groupClaims.identity_authorization);
      await identityDb.query('SELECT identity_company_offboarding_group_validate($1)', [record.id]);
      const canonical = (await identityDb.query('SELECT event.*,outbox.status FROM identity_directory_group_events event JOIN identity_directory_group_outbox outbox USING(id) WHERE event.id=$1', [record.operation_id])).rows;
      assert.equal(canonical.length, 1); assert.equal(canonical[0].action, 'member-remove'); assert.equal(canonical[0].tenant_id, receipt.tenantId); assert.equal(canonical[0].group_id, record.group_id); assert.equal(canonical[0].status, 'pending'); assert.equal(canonical[0].transaction_id, record.transaction_id);
      assert.deepEqual(canonical[0].actor, { issuer: logicalIssuer, subject: groupClaims.sub, userId: receipt.administratorId }); assert.equal(canonical[0].details.beforeRevision, String(record.before_group_revision)); assert.equal(canonical[0].details.afterRevision, String(record.after_group_revision));
    }
    const groupCleanupResult = groupCleanupPanel.getByRole('region', { name: 'Ergebnis der Gruppenentfernung', exact: true });
    if (unknownGroupResponse) {
      await groupCleanupPanel.getByRole('alert').filter({ hasText: /nicht bestätigt/ }).waitFor(); assert.equal(await groupCleanupResult.count(), 0);
      assert.deepEqual((await removedGroupResponse.json()).results, []); assert.equal(await groupCleanupPanel.getByRole('button', { name: 'Angezeigte Gruppen entfernen', exact: true }).count(), 0);
    } else {
      await groupCleanupPanel.getByText('Angezeigte Gruppenentfernungen bestätigt. Vorschau und Historie ausdrücklich neu laden.', { exact: true }).waitFor(); assert.equal(await groupCleanupResult.getByRole('listitem').count(), 2);
    }
    await groupCleanupPanel.getByText('Vor einem weiteren Schreibschritt Gruppenvorschau und Historie ausdrücklich neu laden. Keine automatische Wiederholung.', { exact: true }).waitFor();
    assert.equal(groupCleanupCalls.filter(request => request.method() === 'POST').length, 1); assert.equal(groupCleanupCalls.filter(request => request.method() === 'GET').length, 2);
    const afterGroupCleanup = await groupCleanupState();
    for (const table of ['users', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit', 'identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'company_offboarding_jobs', 'company_offboarding_events', 'company_offboarding_outbox', 'license_company_events', 'license_company_outbox', 'pools']) assert.deepEqual(afterGroupCleanup[table], beforeGroupCleanup[table]);
    assert.deepEqual(afterGroupCleanup.group_members, beforeGroupCleanup.group_members.filter(({ row }) => row.user_id !== employeeIds[0]));
    assert.deepEqual((await identityDb.query('SELECT user_id FROM group_members WHERE group_id=ANY($1::uuid[]) ORDER BY group_id', [[group.id, secondGroup.id]])).rows.map(member => member.user_id), [employeeIds[1], employeeIds[1]]);
    await groupCleanupPanel.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business17-group-cleanup-completed.png', fullPage: true });
    const refreshingGroupPreview = page.waitForResponse(response => new URL(response.url()).pathname === groupCleanupRoute && response.request().method() === 'GET');
    const refreshingGroupHistory = page.waitForResponse(response => new URL(response.url()).pathname === groupCleanupRoute + '/history' && response.request().method() === 'GET');
    await groupCleanupPanel.getByRole('button', { name: 'Gruppenvorschau und Historie neu laden', exact: true }).click();
    const refreshedGroupPreview = await refreshingGroupPreview; assert.equal(refreshedGroupPreview.status(), 200, await refreshedGroupPreview.text()); assert.deepEqual(await refreshedGroupPreview.json(), { ...groupCleanupEnvelope, groups: [], total: 0, page: 1, limit: 25 });
    const refreshedGroupHistory = await refreshingGroupHistory; assert.equal(refreshedGroupHistory.status(), 200, await refreshedGroupHistory.text());
    assert.deepEqual(await refreshedGroupHistory.json(), { ...groupCleanupHistoryEnvelope, receipts: groupReceipts.map(record => ({ id: record.id, groupId: record.group_id, name: record.name, membershipId: record.membership_id, operationId: record.operation_id,
      beforeGroupRevision: String(record.before_group_revision), afterGroupRevision: String(record.after_group_revision), actorUserId: record.actor_user_id, reason: record.reason, createdAt: record.created_at.toISOString(), deliveryStatus: 'pending' })), total: 2, page: 1, limit: 25 });
    const groupCleanupHistory = groupCleanupPanel.getByRole('region', { name: 'Gruppenentfernungs-Historie', exact: true }); await groupCleanupHistory.getByRole('listitem').first().waitFor(); assert.equal(await groupCleanupHistory.getByRole('listitem').count(), 2);
    await groupCleanupHistory.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business17-group-cleanup-history.png', fullPage: true });
    assert.deepEqual(await groupCleanupState(), afterGroupCleanup); assert.equal(groupCleanupCalls.filter(request => request.method() === 'POST').length, 1);
    process.stdout.write('Slice17 actual Chrome original PATCH jti and POST bearer SHA256 verified; two captured group links removed, second employee unchanged, 046/canonical pending receipts verified; unknown-response readback=' + unknownGroupResponse + '.\n');
    const accessRoute = '/api/users/' + employeeIds[0] + '/company-offboarding-access';
    const accessQueries = kind => '?workflowId=' + offboardingJob.id + '&kind=' + kind + '&page=1&limit=25';
    const accessTarget = { enabled: false, eligibilityRevision: afterOffboardingAccount.eligibility_revision };
    const accessEnvelope = { schemaVersion: 1, companyOffboardingAccessProtocol: 1, actorUserId: accessOperatorId, tenantId: receipt.tenantId, workflowId: offboardingJob.id, userId: employeeIds[0], target: accessTarget };
    const accessState = async () => {
      const state = {};
      for (const table of ['users', 'identity_role_assignments', 'identity_role_audit', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_pim_audit', 'identity_company_offboarding_receipts', 'identity_company_offboarding_outbox', 'identity_company_offboarding_access_receipts', 'identity_company_offboarding_access_outbox', 'identity_authority_command_checkpoints', 'identity_authority_command_checkpoint_events', 'identity_authority_command_checkpoint_outbox']) state[table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
      return state;
    };
    const beforeOwnerAccess = await accessState();
    const ownerAccessCheck = page.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/capabilities');
    await offboardingWork.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen', exact: true }).click();
    const deniedOwnerAccess = await ownerAccessCheck; assert.equal(deniedOwnerAccess.status(), 403, await deniedOwnerAccess.text());
    const deniedOwnerPanel = offboardingWork.getByRole('region', { name: 'Rollen- und PIM-Bereinigung beim Austritt', exact: true });
    await deniedOwnerPanel.getByRole('alert').filter({ hasText: 'Separate Rollen- oder PIM-Berechtigung erforderlich.' }).waitFor(); assert.deepEqual(await accessState(), beforeOwnerAccess);
    assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
    const accessContext = await context();
    try {
      const operatorPage = await accessContext.newPage(); await login(operatorPage, 'company-access-operator');
      const accessCalls = []; const profileCalls = [];
      operatorPage.on('request', request => { const pathname = new URL(request.url()).pathname; if (pathname.startsWith(accessRoute)) accessCalls.push(request); if (pathname === '/api/users' || pathname === '/api/users/' + employeeIds[0]) profileCalls.push(request); });
      await operatorPage.getByRole('button', { name: 'Austritt: Rollen & PIM', exact: true }).click(); await operatorPage.waitForURL(origin + '/offboarding-access');
      await operatorPage.getByRole('heading', { name: 'Berechtigungsentzug beim Austritt', exact: true }).waitFor();
      await operatorPage.getByLabel('Benutzer-ID', { exact: true }).fill(employeeIds[0]); await operatorPage.getByLabel('Vorgangs-ID der Kontosperre', { exact: true }).fill(offboardingJob.id);
      await operatorPage.getByRole('button', { name: 'Arbeitsbereich öffnen', exact: true }).click();
      const accessPanel = operatorPage.getByRole('region', { name: 'Rollen- und PIM-Bereinigung beim Austritt', exact: true }); await accessPanel.waitFor(); assert.equal(accessCalls.length, 0);
      const accessCapabilitiesResponse = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/capabilities');
      const rolePreviewResponse = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'GET');
      const roleEmptyHistoryResponse = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/history');
      const beforeAccessReads = await accessState(); await accessPanel.getByRole('button', { name: 'Rollen und PIM beim Austritt bereinigen', exact: true }).click();
      const capabilitiesResponse = await accessCapabilitiesResponse; assert.equal(capabilitiesResponse.status(), 200, await capabilitiesResponse.text());
      assert.deepEqual(await capabilitiesResponse.json(), { ...accessEnvelope, permissions: ['identities.roles.read', 'identities.roles.manage', 'pim.eligibilities.read', 'pim.eligibilities.manage'], supportedKinds: ['role', 'eligibility'] });
      assert.equal(new URL(capabilitiesResponse.url()).search, '?workflowId=' + offboardingJob.id);
      const previewResponse = await rolePreviewResponse; assert.equal(previewResponse.status(), 200, await previewResponse.text()); const rolePreview = await previewResponse.json();
      const historyResponse = await roleEmptyHistoryResponse; assert.equal(historyResponse.status(), 200, await historyResponse.text()); assert.deepEqual((await historyResponse.json()).receipts, []);
      assert.deepEqual({ ...rolePreview, items: [] }, { ...accessEnvelope, kind: 'role', canRevoke: true, items: [], total: 3, page: 1, limit: 25 });
      for (const response of [previewResponse, historyResponse]) assert.equal(new URL(response.url()).search, accessQueries('role'));
      const directItem = rolePreview.items.find(item => item.id === accessRole.body.id); const protectedItem = rolePreview.items.find(item => item.id === accessProtectedRole.body.id); assert.ok(directItem); assert.equal(protectedItem.canRevoke, false); assert.equal(protectedItem.blockedReason, 'protected_role');
      assert.equal(await accessPanel.getByRole('checkbox', { name: 'Zuweisung auswählen: role-administrator · ' + protectedItem.id, exact: true }).isDisabled(), true);
      const expectedRoleHash = await identityDb.transaction(async client => { await client.query("SET LOCAL timezone='UTC'"); return (await client.query("SELECT encode(sha256(convert_to(to_jsonb(record)::text,'UTF8')),'hex') AS version FROM identity_role_assignments record WHERE id=$1", [directItem.id])).rows[0].version; }, { readOnly: true }); assert.equal(directItem.version, expectedRoleHash);
      assert.deepEqual(await accessState(), beforeAccessReads); assert.deepEqual(profileCalls, []);
      await accessPanel.getByRole('checkbox', { name: 'Zuweisung auswählen: group-administrator · ' + directItem.id, exact: true }).check();
      const accessReason = 'Actual Chrome explicitly revokes only this original canonical role after account offboarding';
      await accessPanel.getByLabel('Begründung für Berechtigungsentzug', { exact: true }).fill(accessReason);
      await accessPanel.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen', exact: true }).click();
      const accessDialog = operatorPage.getByRole('alertdialog', { name: 'Berechtigungsentzug bestätigen', exact: true }); await accessDialog.waitFor();
      await accessDialog.getByText('Genau diese ursprünglichen Zuweisungen widerrufen: 1 · Rollen.', { exact: true }).waitFor();
      await accessDialog.getByRole('button', { name: 'Abbrechen', exact: true }).click(); assert.deepEqual(await accessState(), beforeAccessReads); assert.equal(accessCalls.filter(call => call.method() === 'POST').length, 0);
      await accessPanel.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen', exact: true }).click(); await accessDialog.waitFor();
      await accessDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Zuweisungen.', exact: true }).check();
      await accessDialog.scrollIntoViewIfNeeded(); await operatorPage.screenshot({ path: '/tmp/od-business18-access-confirmation.png', fullPage: true });
      const unknownAccessResponse = process.env.OD_BUSINESS18_UNKNOWN_ACCESS_RESPONSE === '1'; let actualAccessResult; let accessResponseLost = false;
      if (unknownAccessResponse) await operatorPage.route('**' + accessRoute, async route => {
        if (route.request().method() !== 'POST' || accessResponseLost) return route.fallback();
        const actual = await route.fetch(); assert.equal(actual.status(), 200, await actual.text()); actualAccessResult = await actual.json(); accessResponseLost = true;
        await route.fulfill({ response: actual, json: { ...actualAccessResult, results: [] } });
      });
      const revokingAccess = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'POST');
      await accessDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
      const revokedResponse = await revokingAccess; assert.equal(revokedResponse.status(), 200, await revokedResponse.text()); const revokedAccess = unknownAccessResponse ? actualAccessResult : await revokedResponse.json();
      const roleAccessInput = { workflowId: offboardingJob.id, eligibilityRevision: accessTarget.eligibilityRevision, kind: 'role', reason: accessReason, confirm: true, items: [{ id: directItem.id, version: directItem.version }] };
      assert.deepEqual(revokedResponse.request().postDataJSON(), roleAccessInput); assert.equal(new URL(revokedResponse.url()).search, ''); assert.deepEqual(revokedAccess.results, [{ id: directItem.id, status: 'revoked', code: 200, checkpointId: revokedAccess.results[0].checkpointId }]);
      const accessAuthorizations = new Map([[directItem.id, revokedResponse.request().headers().authorization]]);
      if (unknownAccessResponse) { await accessPanel.getByRole('alert').filter({ hasText: 'Ergebnis nicht bestätigt' }).waitFor(); assert.deepEqual((await revokedResponse.json()).results, []); assert.equal(await accessPanel.getByRole('region', { name: 'Ergebnis des Berechtigungsentzugs', exact: true }).count(), 0); }
      else await accessPanel.getByRole('region', { name: 'Ergebnis des Berechtigungsentzugs', exact: true }).getByText(/Nur die ausgewählten ursprünglichen Zuweisungen sind bestätigt widerrufen/).waitFor();
      assert.equal(accessCalls.filter(call => call.method() === 'POST').length, 1); assert.equal(accessCalls.filter(call => call.method() === 'GET').length, 3);
      assert.ok((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [directItem.id])).rows[0].revoked_at);
      const laterGrant = await accessApi('/api/users/' + employeeIds[0] + '/roles', { method: 'POST', token: accessOperatorToken, body: { role: directItem.role, durationSeconds: 3600, reason: 'A later independently granted role cannot be substituted into original browser recovery' } }); assert.equal(laterGrant.status, 201, JSON.stringify(laterGrant.body)); assert.notEqual(laterGrant.body.id, directItem.id);
      const reloadingAccessRoles = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'GET');
      const reloadingRoleHistory = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/history');
      await accessPanel.getByRole('button', { name: 'Vorschau und Historie neu laden', exact: true }).click();
      const afterRolePreview = await reloadingAccessRoles; assert.equal(afterRolePreview.status(), 200, await afterRolePreview.text()); assert.ok((await afterRolePreview.json()).items.some(item => item.id === laterGrant.body.id));
      const firstRoleHistory = await reloadingRoleHistory; assert.equal(firstRoleHistory.status(), 200, await firstRoleHistory.text()); assert.equal((await firstRoleHistory.json()).receipts[0].resourceId, directItem.id);
      if (unknownAccessResponse) {
        const beforeRecovery = await accessState(); await accessPanel.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen', exact: true }).click();
        const recoveryDialog = operatorPage.getByRole('alertdialog', { name: 'Ursprünglichen Versuch bestätigen', exact: true }); await recoveryDialog.waitFor(); await recoveryDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Zuweisungen.', exact: true }).check();
        const recoveringAccess = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'POST'); await recoveryDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
        const recovered = await recoveringAccess; assert.equal(recovered.status(), 200, await recovered.text()); assert.deepEqual(recovered.request().postDataJSON(), roleAccessInput); assert.deepEqual((await recovered.json()).results, revokedAccess.results.map(result => ({ ...result, status: 'already_revoked' }))); assert.deepEqual(await accessState(), beforeRecovery);
      }
      assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [laterGrant.body.id])).rows[0].revoked_at, null);
      const readingEligibility = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'GET' && new URL(response.url()).searchParams.get('kind') === 'eligibility');
      const readingEligibilityHistory = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/history' && new URL(response.url()).searchParams.get('kind') === 'eligibility');
      await accessPanel.getByRole('tab', { name: 'PIM-Berechtigungen', exact: true }).click(); const eligibleResponse = await readingEligibility; assert.equal(eligibleResponse.status(), 200, await eligibleResponse.text()); const eligiblePreview = await eligibleResponse.json(); assert.equal(eligiblePreview.total, 1); assert.equal(eligiblePreview.items[0].id, accessEligibility.body.id); assert.equal((await readingEligibilityHistory).status(), 200);
      const eligibilityItem = eligiblePreview.items[0]; await accessPanel.getByRole('checkbox', { name: 'Zuweisung auswählen: license-manager · ' + eligibilityItem.id, exact: true }).check(); await accessPanel.getByLabel('Begründung für Berechtigungsentzug', { exact: true }).fill('Actual browser invokes the existing eligibility revocation cascade for this original grant');
      await accessPanel.getByRole('button', { name: 'Ausgewählte Zuweisungen widerrufen', exact: true }).click(); await accessDialog.waitFor(); await accessDialog.getByText(/Die bestehende PIM-Kaskade kann verknüpfte Aktivierungen/).waitFor(); await accessDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Zuweisungen.', exact: true }).check();
      const revokingEligibility = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'POST'); await accessDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
      const eligibilityRevokedResponse = await revokingEligibility; assert.equal(eligibilityRevokedResponse.status(), 200, await eligibilityRevokedResponse.text()); const eligibilityResult = await eligibilityRevokedResponse.json(); assert.equal(eligibilityResult.results[0].status, 'revoked'); assert.equal(eligibilityResult.results[0].id, eligibilityItem.id); accessAuthorizations.set(eligibilityItem.id, eligibilityRevokedResponse.request().headers().authorization);
      await accessPanel.getByRole('region', { name: 'Ergebnis des Berechtigungsentzugs', exact: true }).getByText(/Nur die ausgewählten ursprünglichen Zuweisungen sind bestätigt widerrufen/).waitFor();
      assert.equal((await identityDb.query('SELECT state FROM identity_pim_requests WHERE id=$1', [accessActiveRequest.body.id])).rows[0].state, 'revoked'); assert.ok((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [accessActiveAssignment.id])).rows[0].revoked_at);
      assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [protectedItem.id])).rows[0].revoked_at, null); assert.equal((await identityDb.query('SELECT revoked_at FROM identity_role_assignments WHERE id=$1', [laterGrant.body.id])).rows[0].revoked_at, null);
      const accessReceipts = (await identityDb.query(`SELECT record.*,outbox.status,checkpoint.original_context,checkpoint.token_sha256,checkpoint.issuer AS checkpoint_issuer,checkpoint.subject AS checkpoint_subject,checkpoint.transaction_id AS checkpoint_transaction_id,checkpoint_outbox.status AS checkpoint_status FROM identity_company_offboarding_access_receipts record JOIN identity_company_offboarding_access_outbox outbox USING(id) JOIN identity_authority_command_checkpoints checkpoint ON checkpoint.id=record.checkpoint_id JOIN identity_authority_command_checkpoint_outbox checkpoint_outbox ON checkpoint_outbox.id=checkpoint.id WHERE record.tenant_id=$1 AND record.workflow_id=$2 ORDER BY record.created_at,record.id`, [receipt.tenantId, offboardingJob.id])).rows;
      assert.equal(accessReceipts.length, 2);
      for (const record of accessReceipts) {
        const authorization = accessAuthorizations.get(record.resource_id); assert.match(authorization, /^Bearer [A-Za-z0-9._~-]+$/); const claims = JSON.parse(Buffer.from(authorization.slice(7).split('.')[1], 'base64url'));
        assert.equal(claims.identity_authorization.userId, accessOperatorId); assert.equal(claims.sub, 'company-access-operator-subject'); assert.deepEqual(claims.roles, ['pim-administrator', 'role-administrator']); assert.deepEqual(claims.amr, ['pwd', 'otp']); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(claims), true);
        assert.equal(record.actor_user_id, accessOperatorId); assert.equal(record.status, 'pending'); assert.equal(record.checkpoint_status, 'pending'); assert.equal(record.transaction_id, record.checkpoint_transaction_id); assert.equal(record.checkpoint_issuer, logicalIssuer); assert.equal(record.checkpoint_subject, claims.sub); assert.deepEqual(record.original_context, claims.identity_authorization); assert.equal(record.token_sha256, createHash('sha256').update(JSON.stringify(claims.jti)).digest('hex')); assert.equal(record.source.tokenSha256, createHash('sha256').update(authorization).digest('hex'));
        await identityDb.query('SELECT identity_company_offboarding_access_validate($1)', [record.id]);
        assert.equal(record.before_state.grant.id, record.resource_id); assert.equal(record.before_state.grant.revoked_at, null); assert.ok(record.after_state.grant.revoked_at);
      }
      await accessPanel.scrollIntoViewIfNeeded(); await operatorPage.screenshot({ path: '/tmp/od-business18-access-completed.png', fullPage: true });
      const beforeFinalAccessReads = await accessState(); const finalPreviewResponse = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute && response.request().method() === 'GET'); const finalHistoryResponse = operatorPage.waitForResponse(response => new URL(response.url()).pathname === accessRoute + '/history');
      await accessPanel.getByRole('button', { name: 'Vorschau und Historie neu laden', exact: true }).click(); const finalPreview = await finalPreviewResponse; assert.equal(finalPreview.status(), 200, await finalPreview.text()); assert.deepEqual((await finalPreview.json()).items, []);
      const finalHistory = await finalHistoryResponse; assert.equal(finalHistory.status(), 200, await finalHistory.text()); const eligibilityHistory = await finalHistory.json(); assert.equal(eligibilityHistory.receipts.length, 1); assert.equal(eligibilityHistory.receipts[0].resourceId, eligibilityItem.id); assert.equal(eligibilityHistory.receipts[0].checkpointId, eligibilityResult.results[0].checkpointId); assert.equal(eligibilityHistory.receipts[0].deliveryStatus, 'pending');
      const historyPanel = accessPanel.getByRole('region', { name: 'Berechtigungsentzugs-Historie', exact: true }); await historyPanel.getByRole('listitem').waitFor(); await historyPanel.getByText('Nachweis', { exact: true }).click(); await historyPanel.getByText(eligibilityResult.results[0].checkpointId, { exact: true }).waitFor();
      await historyPanel.scrollIntoViewIfNeeded(); await operatorPage.screenshot({ path: '/tmp/od-business18-access-history.png', fullPage: true }); assert.deepEqual(await accessState(), beforeFinalAccessReads); assert.deepEqual(profileCalls, []);
      assert.equal(accessCalls.filter(call => call.method() === 'POST').length, unknownAccessResponse ? 3 : 2); assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
      process.stdout.write('Slice18 actual Chrome own-tenant separate canonical role/PIM operator without profile/company-app rights; roleless Owner403; protected UI blocked; original bearer SHA256/checkpoint/pending receipts; real active PIM cascade; later role grant preserved; malformed access result=' + unknownAccessResponse + '; explicit original-ID recovery=' + unknownAccessResponse + '.\n');
    } finally { await accessContext.close(); }
    {
    await login(page, 'company-registration-owner'); const returnOwnerToken = (await mediated(page)).body.access_token;
    await page.goto(origin + '/applications'); await offboardingPanel.getByRole('button', { name: 'Mitarbeiter-Offboarding', exact: true }).click();
    await offboardingPanel.getByLabel('Bekannte Vorgangs-ID', { exact: true }).fill(offboardingJob.id);
    const loadingReturnWorkflow = page.waitForResponse(response => new URL(response.url()).pathname === workflowRoute + '/' + offboardingJob.id && response.request().method() === 'GET');
    await offboardingPanel.getByRole('button', { name: 'Arbeitsstand neu laden', exact: true }).click(); const returnWorkflowResponse = await loadingReturnWorkflow; assert.equal(returnWorkflowResponse.status(), 200, await returnWorkflowResponse.text()); assert.equal((await returnWorkflowResponse.json()).workflow.checkpoint.operationId, offboardingJob.checkpoint.operationId);
    const deviceReturnBase = '/api/devices/returns'; const deviceOffboardingRoute = '/api/devices/users/' + employeeIds[0] + '/offboarding-returns';
    const returnPanel = page.getByRole('region', { name: 'Geräterückgaben beim Austritt', exact: true }); const returnCalls = [];
    page.on('request', incoming => { const pathname = new URL(incoming.url()).pathname; if (pathname === deviceOffboardingRoute || pathname.startsWith(deviceOffboardingRoute + '/') || pathname === deviceReturnBase || pathname.startsWith(deviceReturnBase + '/')) returnCalls.push(incoming); });
    const originalInventoryState = async () => {
      const state = {}; for (const table of ['devices', 'device_inventory_assignments', 'device_inventory_events', 'device_inventory_outbox']) state[table] = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM ' + table + ' record ORDER BY to_jsonb(record)::text')).rows; return state;
    };
    const allReturnState = async () => {
      const state = {}; const tables = (await inventoryFixture.db.query("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND (tablename='devices' OR tablename LIKE 'device_inventory_%' OR tablename LIKE 'device_return%') ORDER BY tablename")).rows;
      for (const { tablename } of tables) state[tablename] = (await inventoryFixture.db.query('SELECT to_jsonb(record) AS row FROM ' + tablename + ' record ORDER BY to_jsonb(record)::text')).rows; return state;
    };
    const returnEtag = value => '"device-return-' + value.id + '-' + value.revision + '-' + value.currentDeviceRevision + '"';
    const beforeReturnInventory = await originalInventoryState(); const beforeReturnRequests = await allReturnState();
    assert.equal(await returnPanel.getByRole('button', { name: 'Geräterückgaben beim Austritt planen', exact: true }).getAttribute('aria-expanded'), 'false'); assert.equal(returnCalls.length, 0);
    const readingReturnCapabilities = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute + '/capabilities');
    const readingReturnPreview = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute && response.request().method() === 'GET');
    const readingReturnHistory = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute + '/history');
    await returnPanel.getByRole('button', { name: 'Geräterückgaben beim Austritt planen', exact: true }).click();
    const returnCapabilitiesResponse = await readingReturnCapabilities; assert.equal(returnCapabilitiesResponse.status(), 200, await returnCapabilitiesResponse.text()); const returnCapabilities = await returnCapabilitiesResponse.json();
    assert.deepEqual(returnCapabilities, { schemaVersion: 1, deviceOffboardingReturnsProtocol: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, workflowId: offboardingJob.id, userId: employeeIds[0], target: { enabled: false, eligibilityRevision: afterOffboardingAccount.eligibility_revision }, permissions: require('../../../../../packages/device-inventory-contract').INVENTORY_PERMISSIONS, managementMode: 'inventory-only' });
    const returnPreviewResponse = await readingReturnPreview; assert.equal(returnPreviewResponse.status(), 200, await returnPreviewResponse.text()); const returnPreview = await returnPreviewResponse.json(); assert.equal(returnPreview.total, 3); assert.equal(returnPreview.devices.length, 3); assert.deepEqual(new Set(returnPreview.devices.map(value => value.deviceId)), new Set(returnDevices.map(value => value.id)));
    assert.equal((await readingReturnHistory).status(), 200); assert.deepEqual(await allReturnState(), beforeReturnRequests);
    const requestReason = 'Actual Chrome explicitly requests the captured original device assignments without physical return';
    for (const unit of returnDevices) await returnPanel.getByRole('checkbox', { name: 'Rückgabe für ' + unit.assetId + ' auswählen', exact: true }).check();
    await returnPanel.getByLabel('Begründung für Rückgabeauftrag', { exact: true }).fill(requestReason); await returnPanel.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern', exact: true }).click();
    const requestDialog = page.getByRole('alertdialog', { name: 'Rückgabeaufträge bestätigen', exact: true }); await requestDialog.waitFor(); assert.equal(await requestDialog.getByRole('button', { name: 'Bestätigen', exact: true }).isDisabled(), true);
    await requestDialog.getByRole('button', { name: 'Abbrechen', exact: true }).click(); assert.deepEqual(await allReturnState(), beforeReturnRequests); assert.equal(returnCalls.filter(call => call.method() === 'POST').length, 0);
    await returnPanel.getByRole('button', { name: 'Ausgewählte Rückgaben anfordern', exact: true }).click(); await requestDialog.waitFor(); await requestDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Gerätezuweisungen.', exact: true }).check();
    await page.screenshot({ path: '/tmp/od-business19-device-return-confirmation.png', fullPage: false });
    const unknownReturnResponse = process.env.OD_BUSINESS19_UNKNOWN_RETURN_RESPONSE === '1'; let committedReturnRequests; let requestResponseLost = false;
    if (unknownReturnResponse) await page.route('**' + deviceOffboardingRoute, async route => {
      if (route.request().method() !== 'POST' || requestResponseLost) return route.fallback();
      const actual = await route.fetch(); assert.equal(actual.status(), 200, await actual.text()); committedReturnRequests = await actual.json(); requestResponseLost = true;
      await route.fulfill({ response: actual, json: { ...committedReturnRequests, results: [] } });
    });
    const creatingReturnRequests = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute && response.request().method() === 'POST'); await requestDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
    const returnRequestsResponse = await creatingReturnRequests; assert.equal(returnRequestsResponse.status(), 200, await returnRequestsResponse.text()); const requestedReturns = unknownReturnResponse ? committedReturnRequests : await returnRequestsResponse.json();
    const requestInput = returnRequestsResponse.request().postDataJSON(); assert.deepEqual({ ...requestInput, items: [] }, { workflowId: offboardingJob.id, eligibilityRevision: afterOffboardingAccount.eligibility_revision, reason: requestReason, confirm: true, items: [] }); assert.equal(requestInput.items.length, 3); assert.equal(new Set(requestInput.items.map(item => item.requestId)).size, 3);
    for (const item of requestInput.items) { const unit = returnDevices.find(device => device.id === item.deviceId); assert.ok(unit); assert.deepEqual({ ...item, requestId: null }, { deviceId: unit.id, deviceRevision: unit.revision, assignmentId: unit.assignmentId, requestId: null }); assert.match(item.requestId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/); }
    assert.deepEqual(requestedReturns.results, requestInput.items.map(item => ({ deviceId: item.deviceId, assignmentId: item.assignmentId, requestId: item.requestId, status: 'requested', code: 200, operationId: requestedReturns.results.find(result => result.requestId === item.requestId)?.operationId })));
    const returnAuthorization = returnRequestsResponse.request().headers().authorization; assert.match(returnAuthorization, /^Bearer [A-Za-z0-9._~-]+$/u); const returnClaims = JSON.parse(Buffer.from(returnAuthorization.slice(7).split('.')[1], 'base64url')); assert.deepEqual(returnClaims.roles, []); assert.deepEqual(returnClaims.amr, ['pwd', 'otp']); assert.equal(returnClaims.identity_authorization.userId, receipt.administratorId); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(returnClaims), true); assert.ok(Date.now() / 1000 - returnClaims.auth_time <= 300);
    assert.deepEqual(await originalInventoryState(), beforeReturnInventory);
    if (unknownReturnResponse) { await returnPanel.getByRole('alert').filter({ hasText: 'Geräterückgabe nicht bestätigt.' }).waitFor(); assert.equal(await returnPanel.getByRole('region', { name: 'Ergebnis der Rückgabeanforderung', exact: true }).count(), 0); assert.deepEqual((await returnRequestsResponse.json()).results, []); }
    else await returnPanel.getByRole('region', { name: 'Ergebnis der Rückgabeanforderung', exact: true }).getByText('Ausgewählte ursprüngliche Rückgabeaufträge bestätigt. Keine physische Rückgabe bestätigt.', { exact: true }).waitFor();
    assert.equal(returnCalls.filter(call => call.method() === 'POST').length, 1);
    const pendingReturns = [];
    for (const item of requestInput.items) { const detail = await accessApi(deviceReturnBase + '/' + item.requestId, { token: returnOwnerToken }); assert.equal(detail.status, 200, JSON.stringify(detail.body)); assert.equal(detail.body.status, 'requested'); assert.equal(detail.body.assignmentId, item.assignmentId); assert.equal(detail.body.operationId, requestedReturns.results.find(result => result.requestId === item.requestId).operationId); pendingReturns.push(detail.body); }
    const requestEvents = (await inventoryFixture.db.query('SELECT event.*,outbox.status AS delivery_status FROM device_return_events event JOIN device_return_outbox outbox USING(id,tenant_id) WHERE event.id=ANY($1::uuid[]) ORDER BY event.id', [requestedReturns.results.map(result => result.operationId)])).rows; assert.equal(requestEvents.length, 3);
    for (const event of requestEvents) { const item = requestInput.items.find(value => value.requestId === event.request_id); assert.ok(item); assert.equal(event.type, 'device.return.requested'); assert.equal(event.version, 1); assert.equal(event.delivery_status, 'pending'); assert.equal(event.actor_user_id, receipt.administratorId); assert.equal(event.tenant_id, receipt.tenantId); assert.equal(Object.keys(event.proof.source).length, 13); assert.equal(event.proof.source.tokenId, returnClaims.jti); assert.equal(event.proof.source.issuer, logicalIssuer); assert.equal(event.proof.source.subject, returnClaims.sub); assert.deepEqual(event.proof.source.context, returnClaims.identity_authorization); assert.deepEqual(event.proof.item, item); assert.equal(event.proof.source.parent.workflowId, offboardingJob.id); assert.equal(event.proof.source.parent.operationId, offboardingJob.checkpoint.operationId); assert.equal(event.proof.source.target.eligibilityRevision, afterOffboardingAccount.eligibility_revision); assert.equal(event.proof.source.target.enabled, false); assert.ok(event.created_at < event.valid_until); assert.ok(event.valid_until.getTime() <= (returnClaims.auth_time + 300) * 1000); assert.equal((await inventoryFixture.db.query('SELECT count(*)::int AS count FROM device_inventory_events WHERE transaction_id=$1', [event.transaction_id])).rows[0].count, 0); await inventoryFixture.db.query('SELECT device_returns_validate($1)', [event.request_id]); }
    const changedReturn = pendingReturns.find(value => value.deviceId === returnDevices[2].id);
    const ordinaryChange = await accessApi('/api/devices/' + changedReturn.deviceId + '/assignment', { method: 'PUT', token: returnOwnerToken, headers: { 'If-Match': require('../../../../../packages/device-inventory-contract').deviceEtag(returnDevices[2]) }, body: { userId: employeeIds[1] } }); assert.equal(ordinaryChange.status, 200, JSON.stringify(ordinaryChange.body)); assert.notEqual(ordinaryChange.body.assignmentId, changedReturn.assignmentId);
    const reloadingReturnPreview = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute && response.request().method() === 'GET'); const reloadingReturnHistory = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute + '/history');
    await returnPanel.getByRole('button', { name: 'Gerätevorschau und Rückgabehistorie neu laden', exact: true }).click(); const readbackPreview = await reloadingReturnPreview; assert.equal(readbackPreview.status(), 200, await readbackPreview.text()); const readbackDevices = (await readbackPreview.json()).devices; assert.equal(readbackDevices.length, 2); assert.ok(readbackDevices.every(device => device.openRequestId !== null));
    const readbackHistory = await reloadingReturnHistory; assert.equal(readbackHistory.status(), 200, await readbackHistory.text()); assert.equal((await readbackHistory.json()).requests.find(value => value.id === changedReturn.id).status, 'assignment_changed');
    for (const unit of returnDevices.slice(0, 2)) assert.equal(await returnPanel.getByRole('checkbox', { name: 'Rückgabe für ' + unit.assetId + ' auswählen', exact: true }).isDisabled(), true);
    if (unknownReturnResponse) {
      const beforeRecovery = await allReturnState(); await returnPanel.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen', exact: true }).click(); const recovery = page.getByRole('alertdialog', { name: 'Ursprüngliche Rückgabeaufträge bestätigen', exact: true }); await recovery.waitFor(); await recovery.getByRole('checkbox', { name: 'Ich bestätige genau diese ursprünglichen Gerätezuweisungen.', exact: true }).check();
      const recoveringRequests = page.waitForResponse(response => new URL(response.url()).pathname === deviceOffboardingRoute && response.request().method() === 'POST'); await recovery.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const recovered = await recoveringRequests; assert.equal(recovered.status(), 200, await recovered.text()); assert.deepEqual(recovered.request().postDataJSON(), requestInput); assert.deepEqual((await recovered.json()).results, requestedReturns.results.map(result => ({ ...result, status: 'already_requested' }))); assert.deepEqual(await allReturnState(), beforeRecovery);
    }
    const readingGeneralReturns = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase && response.request().method() === 'GET'); await page.getByRole('button', { name: 'Geräterückgaben', exact: true }).click(); await page.waitForURL(origin + '/device-returns'); const generalReturnsResponse = await readingGeneralReturns; assert.equal(generalReturnsResponse.status(), 200, await generalReturnsResponse.text()); assert.equal((await generalReturnsResponse.json()).total, 3);
    const generalPanel = page.getByRole('region', { name: 'Geräterückgaben', exact: true }); const returnDetails = generalPanel.getByRole('region', { name: 'Rückgabeauftragdetails', exact: true });
    const openReturn = async value => {
      const loading = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase + '/' + value.id && response.request().method() === 'GET'); const events = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase + '/' + value.id + '/history');
      await generalPanel.getByRole('button', { name: 'Rückgabe ' + value.assetId + ' öffnen', exact: true }).click(); const response = await loading; assert.equal(response.status(), 200, await response.text()); assert.equal(response.headers().etag, returnEtag(await response.json())); assert.equal((await events).status(), 200); return response;
    };
    const cancelledReturn = pendingReturns.find(value => value.deviceId === returnDevices[0].id); await openReturn(cancelledReturn);
    const cancelReason = 'Actual Chrome cancels only this return task without releasing the original device'; await returnDetails.getByLabel('Begründung für Rückgabeentscheidung', { exact: true }).fill(cancelReason); await returnDetails.getByRole('button', { name: 'Rückgabeauftrag stornieren', exact: true }).click(); const cancellationDialog = page.getByRole('alertdialog', { name: 'Rückgabeauftrag stornieren', exact: true }); await cancellationDialog.waitFor(); assert.equal(await cancellationDialog.getByRole('button', { name: 'Bestätigen', exact: true }).isDisabled(), true); await cancellationDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese Rückgabeentscheidung.', exact: true }).check();
    const beforeCancelInventory = await originalInventoryState(); const cancellingTask = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase + '/' + cancelledReturn.id + '/decision'); await cancellationDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const cancelledResponse = await cancellingTask; assert.equal(cancelledResponse.status(), 200, await cancelledResponse.text()); assert.deepEqual(cancelledResponse.request().postDataJSON(), { action: 'cancelled', reason: cancelReason, confirm: true }); assert.equal(cancelledResponse.request().headers()['if-match'], returnEtag(cancelledReturn)); const cancelledOutcome = await cancelledResponse.json(); assert.equal(cancelledOutcome.outcome, 'cancelled'); assert.equal((await inventoryFixture.db.query('SELECT version FROM device_return_events WHERE id=$1', [cancelledOutcome.operationId])).rows[0].version, 1); assert.deepEqual(await originalInventoryState(), beforeCancelInventory);
    await generalPanel.getByRole('region', { name: 'Ergebnis der Rückgabeentscheidung', exact: true }).getByText(/Auftrag storniert. Keine Inventaränderung./).waitFor();
    const reloadingAfterCancel = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase && response.request().method() === 'GET'); await generalPanel.getByRole('button', { name: 'Rückgaben und Historie neu laden', exact: true }).click(); assert.equal((await reloadingAfterCancel).status(), 200);
    const physicalReturn = pendingReturns.find(value => value.deviceId === returnDevices[1].id); await openReturn(physicalReturn); const physicalReason = 'Actual Chrome operator confirms physical receipt and releases exactly the captured original inventory assignment';
    await returnDetails.getByLabel('Begründung für Rückgabeentscheidung', { exact: true }).fill(physicalReason); await returnDetails.getByRole('button', { name: 'Physische Rückgabe bestätigen', exact: true }).click(); const physicalDialog = page.getByRole('alertdialog', { name: 'Physische Rückgabe bestätigen', exact: true }); await physicalDialog.waitFor(); await physicalDialog.getByRole('checkbox', { name: 'Ich bestätige genau diese Rückgabeentscheidung.', exact: true }).check();
    let committedDecision; let decisionResponseLost = false; const physicalDecisionPath = deviceReturnBase + '/' + physicalReturn.id + '/decision';
    if (unknownReturnResponse) await page.route('**' + physicalDecisionPath, async route => {
      if (route.request().method() !== 'POST' || decisionResponseLost) return route.fallback(); const actual = await route.fetch(); assert.equal(actual.status(), 200, await actual.text()); committedDecision = await actual.json(); decisionResponseLost = true; await route.fulfill({ response: actual, json: { ...committedDecision, request: null } });
    });
    const confirmingPhysicalReturn = page.waitForResponse(response => new URL(response.url()).pathname === physicalDecisionPath && response.request().method() === 'POST'); await physicalDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const physicalResponse = await confirmingPhysicalReturn; assert.equal(physicalResponse.status(), 200, await physicalResponse.text()); const physicalOutcome = unknownReturnResponse ? committedDecision : await physicalResponse.json(); assert.equal(physicalOutcome.outcome, 'returned'); assert.equal(physicalOutcome.request.status, 'returned'); assert.equal(physicalOutcome.request.assignmentId, physicalReturn.assignmentId); assert.equal(physicalOutcome.request.revision, '2'); assert.equal(physicalResponse.request().headers()['if-match'], returnEtag(physicalReturn)); assert.deepEqual(physicalResponse.request().postDataJSON(), { action: 'returned', reason: physicalReason, confirm: true });
    const releasedEvent = (await inventoryFixture.db.query('SELECT event.*,outbox.status FROM device_inventory_events event JOIN device_inventory_outbox outbox USING(id) WHERE event.id=$1', [physicalOutcome.request.inventoryOperationId])).rows; assert.equal(releasedEvent.length, 1); assert.equal(releasedEvent[0].type, 'device.assignment.released'); assert.equal(releasedEvent[0].before_assignment.id, physicalReturn.assignmentId); assert.equal(releasedEvent[0].after_assignment, null); assert.equal(releasedEvent[0].status, 'pending'); const physicalAuthorization = physicalResponse.request().headers().authorization; const physicalClaims = JSON.parse(Buffer.from(physicalAuthorization.slice(7).split('.')[1], 'base64url')); assert.equal(releasedEvent[0].proof.source.tokenId, physicalClaims.jti); assert.deepEqual(releasedEvent[0].proof.source.context, physicalClaims.identity_authorization);
    const decisionEvents = (await inventoryFixture.db.query('SELECT event.*,outbox.status AS delivery_status FROM device_return_events event JOIN device_return_outbox outbox USING(id,tenant_id) WHERE event.id=$1', [physicalOutcome.operationId])).rows; assert.equal(decisionEvents.length, 1); assert.equal(decisionEvents[0].version, 1); assert.equal(decisionEvents[0].type, 'device.return.confirmed'); assert.equal(decisionEvents[0].delivery_status, 'pending'); assert.equal(decisionEvents[0].transaction_id, releasedEvent[0].transaction_id); assert.equal(decisionEvents[0].inventory_operation_id, releasedEvent[0].id); assert.equal(Object.keys(decisionEvents[0].proof.source).length, 11); assert.deepEqual(decisionEvents[0].proof.source, releasedEvent[0].proof.source); assert.equal(decisionEvents[0].proof.expected, returnEtag(physicalReturn)); assert.equal(decisionEvents[0].proof.reason, physicalReason); await inventoryFixture.db.query('SELECT device_returns_validate($1)', [physicalReturn.id]);
    const actuallyReleased = await accessApi('/api/devices/' + physicalReturn.deviceId, { token: returnOwnerToken }); assert.equal(actuallyReleased.status, 200); assert.equal(actuallyReleased.body.assignedUserId, null);
    if (unknownReturnResponse) { await generalPanel.getByRole('alert').filter({ hasText: 'Geräterückgabe nicht bestätigt.' }).waitFor(); assert.equal(await generalPanel.getByRole('region', { name: 'Ergebnis der Rückgabeentscheidung', exact: true }).count(), 0); }
    else await generalPanel.getByRole('region', { name: 'Ergebnis der Rückgabeentscheidung', exact: true }).getByText(/Physische Rückgabe manuell bestätigt./).waitFor();
    const laterInventoryAssignment = await accessApi('/api/devices/' + physicalReturn.deviceId + '/assignment', { method: 'PUT', token: returnOwnerToken, headers: { 'If-Match': require('../../../../../packages/device-inventory-contract').deviceEtag(actuallyReleased.body) }, body: { userId: employeeIds[1] } }); assert.equal(laterInventoryAssignment.status, 200, JSON.stringify(laterInventoryAssignment.body)); assert.notEqual(laterInventoryAssignment.body.assignmentId, physicalReturn.assignmentId);
    const refreshGeneral = async () => {
      const loading = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase + '/' + physicalReturn.id && response.request().method() === 'GET'); const events = page.waitForResponse(response => new URL(response.url()).pathname === deviceReturnBase + '/' + physicalReturn.id + '/history'); await generalPanel.getByRole('button', { name: 'Rückgaben und Historie neu laden', exact: true }).click(); const result = await loading; assert.equal(result.status(), 200, await result.text()); const history = await events; assert.equal(history.status(), 200, await history.text()); return { result: await result.json(), history: await history.json() };
    };
    const physicalReadback = await refreshGeneral(); assert.equal(physicalReadback.result.currentDeviceRevision, laterInventoryAssignment.body.revision); await returnDetails.getByText('Historischer Rückgabenachweis. Das Gerät kann inzwischen erneut zugewiesen sein; dieser Nachweis bestätigt keine aktuelle Verfügbarkeit.', { exact: true }).waitFor();
    if (unknownReturnResponse) {
      const beforeRecovery = await allReturnState(); await generalPanel.getByRole('button', { name: 'Ursprünglichen Versuch wiederherstellen', exact: true }).click(); const recovery = page.getByRole('alertdialog', { name: 'Ursprüngliche Rückgabeentscheidung bestätigen', exact: true }); await recovery.waitFor(); await recovery.getByRole('checkbox', { name: 'Ich bestätige genau diese Rückgabeentscheidung.', exact: true }).check(); const recoveringDecision = page.waitForResponse(response => new URL(response.url()).pathname === physicalDecisionPath && response.request().method() === 'POST'); await recovery.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const recovered = await recoveringDecision; assert.equal(recovered.status(), 200, await recovered.text()); assert.equal(recovered.request().headers()['if-match'], returnEtag(physicalReturn)); assert.deepEqual(recovered.request().postDataJSON(), physicalResponse.request().postDataJSON()); const value = await recovered.json(); assert.equal(value.outcome, 'already_returned'); assert.equal(value.operationId, physicalOutcome.operationId); assert.equal(value.request.currentDeviceRevision, laterInventoryAssignment.body.revision); assert.deepEqual(await allReturnState(), beforeRecovery); await generalPanel.getByRole('region', { name: 'Ergebnis der Rückgabeentscheidung', exact: true }).getByText(/Ursprünglicher historischer Entscheidungsnachweis wiederhergestellt./).waitFor();
    }
    await generalPanel.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business19-device-return-completed.png', fullPage: false });
    const finalPhysicalReadback = unknownReturnResponse ? await refreshGeneral() : physicalReadback; assert.equal(finalPhysicalReadback.history.events.length, 2); assert.ok(finalPhysicalReadback.history.events.every(event => event.version === 1)); assert.deepEqual(new Set(finalPhysicalReadback.history.events.map(event => event.type)), new Set(['device.return.requested', 'device.return.confirmed'])); assert.equal(finalPhysicalReadback.history.events.find(event => event.type === 'device.return.confirmed').inventoryOperationId, physicalOutcome.request.inventoryOperationId);
    const returnHistoryPanel = generalPanel.getByRole('region', { name: 'Rückgabeereignishistorie', exact: true }); await returnHistoryPanel.getByRole('listitem').first().waitFor(); await returnHistoryPanel.getByRole('listitem').filter({ hasText: physicalReason }).getByText('Nachweis', { exact: true }).click(); await returnHistoryPanel.getByText(physicalOutcome.request.inventoryOperationId, { exact: true }).waitFor(); await returnHistoryPanel.scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business19-device-return-history.png', fullPage: false });
    const changedReadback = await openReturn(changedReturn); const changedRequest = await changedReadback.json(); assert.equal(changedRequest.status, 'assignment_changed'); assert.equal(changedRequest.closingOperationId, null); assert.match(changedRequest.inventoryOperationId, /^[a-f0-9-]{36}$/); await returnDetails.getByText('Die ursprüngliche Zuweisung wurde durch eine gewöhnliche Inventaraktion beendet. Kein Rückgabeereignis und keine physische Rückgabe behauptet. Keine Entscheidung möglich; eine neue Zuweisung bleibt unberührt.', { exact: true }).waitFor(); assert.equal(await returnDetails.getByRole('button', { name: 'Physische Rückgabe bestätigen', exact: true }).count(), 0);
    const changedHistory = await accessApi(deviceReturnBase + '/' + changedReturn.id + '/history?page=1&limit=25', { token: returnOwnerToken }); assert.equal(changedHistory.status, 200); assert.equal(changedHistory.body.events.length, 1); assert.equal(changedHistory.body.events[0].type, 'device.return.requested'); assert.equal(changedHistory.body.events[0].version, 1);
    assert.equal((await inventoryFixture.db.query('SELECT assigned_user FROM devices WHERE id=$1', [physicalReturn.deviceId])).rows[0].assigned_user, employeeIds[1]); assert.equal((await identityDb.query('SELECT count(*)::int AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0); assert.equal((await offboardingAccount()).enabled, false);
    assert.equal(returnCalls.filter(call => call.method() === 'POST' && new URL(call.url()).pathname === deviceOffboardingRoute).length, unknownReturnResponse ? 2 : 1); assert.equal(returnCalls.filter(call => call.method() === 'POST' && new URL(call.url()).pathname === physicalDecisionPath).length, unknownReturnResponse ? 2 : 1);
    process.stdout.write('Slice19 actual Chrome: real original inventory assignments and parent045; UI request/cancel/physical return through actual network; old005 release/outbox; ordinary reassign derives assignment_changed; roleless Owner preserved; malformed request+decision results=' + unknownReturnResponse + '; explicit original-ID/ETag recovery retains later device assignment=' + unknownReturnResponse + '.\n');
    }
  } finally { await isolated.close(); }
});
test('real own-company blueprint Owner UI registers, independently activates and releases immutable versions with historical recovery', { timeout: 360000 }, async () => {
  const ownerUsername = 'company-blueprint-owner'; const reviewerUsername = 'company-blueprint-reviewer';
  const isolated = await context({ onboarded: false }); const page = await isolated.newPage();
  try {
    await page.goto(origin + '/register'); await page.getByLabel('Benutzername', { exact: true }).fill(ownerUsername); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const registrationId = await page.getByLabel('Registrierungs-ID (für Statusabfrage aufbewahren)', { exact: true }).inputValue();
    for (const [label, value] of [['Firmenname *', 'Actual Blueprint Browser Company'], ['Strasse und Hausnummer *', 'Blueprint Street 1'], ['Postleitzahl *', '8000'], ['Ort *', 'Zürich'], ['Land (zweistellig, z. B. CH) *', 'CH'], ['Kontakt-E-Mail *', 'blueprints@example.invalid']]) await page.getByLabel(label, { exact: true }).fill(value);
    await page.getByRole('checkbox').check(); const submitting = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/submit'); await page.getByRole('button', { name: 'Unternehmen zur Prüfung anmelden', exact: true }).click();
    const submitted = await submitting; assert.equal(submitted.status(), 201, await submitted.text()); const receipt = await submitted.json(); assert.equal(receipt.tenantEnabled, false); assert.equal(receipt.administratorEnabled, false);
    const reviewContext = await context(); const reviewPage = await reviewContext.newPage();
    try {
      await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer: logicalIssuer, userId: actors.get(reviewerUsername).userId, version: '0', enabled: true, reason: 'Dedicated independent company blueprint registration reviewer' });
      await login(reviewPage, reviewerUsername); await reviewPage.goto(origin + '/mfa'); await reviewPage.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor();
      await reviewPage.getByLabel('Eigener Benutzername', { exact: true }).fill(reviewerUsername); await reviewPage.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
      const enrolling = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll'); await reviewPage.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const enrolled = await enrolling; assert.equal(enrolled.status(), 200); const factor = await enrolled.json(); const counter = Math.floor(Date.now() / 30000);
      await reviewPage.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(factor.secret, counter)); const confirming = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm'); await reviewPage.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await confirming).status(), 200);
      await reviewPage.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); rememberFactor(reviewerUsername, factor.secret, counter); await login(reviewPage, reviewerUsername); await reviewPage.goto(origin + '/registration-reviews');
      const reviewer = await mediated(reviewPage); const reviewerClaims = JSON.parse(Buffer.from(reviewer.body.access_token.split('.')[1], 'base64url')); assert.deepEqual(reviewerClaims.roles, ['user']); assert.notEqual(reviewerClaims.identity_authorization.userId, receipt.administratorId);
      await reviewPage.getByRole('button', { name: 'Antrag öffnen: Actual Blueprint Browser Company', exact: true }).click(); await reviewPage.getByLabel('Entscheidung', { exact: true }).selectOption('approved'); await reviewPage.getByLabel('Prüfbegründung', { exact: true }).fill('Actual independent approval for the own blueprint company journey'); await reviewPage.getByRole('checkbox').check();
      const deciding = reviewPage.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/company-registrations/' + registrationId + '/review' && response.request().method() === 'POST'); await reviewPage.getByRole('button', { name: 'Prüfentscheidung speichern', exact: true }).click(); const decided = await deciding; assert.equal(decided.status(), 200, await decided.text()); assert.equal((await decided.json()).status, 'pending-activation');
    } finally { await reviewContext.close(); }
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); const reconciling = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/status'); await page.getByRole('button', { name: 'Bestehenden Status prüfen', exact: true }).click(); const reconciled = await reconciling; assert.equal(reconciled.status(), 200); assert.equal((await reconciled.json()).status, 'pending-activation');
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); await page.getByLabel('Ich bestätige die Aktivierung meiner freigegebenen Firma mit Pflicht-MFA und ohne globale Adminrechte.', { exact: true }).check();
    const activating = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/activate'); await page.getByRole('button', { name: 'Freigegebene Firma aktivieren', exact: true }).click(); const activated = await activating; assert.equal(activated.status(), 200, await activated.text()); assert.equal((await activated.json()).status, 'active');
    await reviewFirstFactor(page, ownerUsername); await login(page, ownerUsername); await page.goto(origin + '/applications'); await page.getByRole('heading', { name: 'Anwendungen & Lizenzen', exact: true }).waitFor();
    const companyPoolValues = { name: 'Blueprint Browser Desired Editor', vendor: 'Blueprint Browser Vendor', description: 'Finite own pool for a desired reference, not an installation', totalSeats: 2, reason: 'Create the actual own company pool for immutable blueprint planning' };
    await page.getByRole('button', { name: 'Lizenzpool erstellen', exact: true }).click(); const poolDialog = page.getByRole('alertdialog', { name: 'Lizenzpool erstellen', exact: true });
    for (const [label, value] of [['Anwendungsname', companyPoolValues.name], ['Hersteller', companyPoolValues.vendor], ['Beschreibung', companyPoolValues.description], ['Lizenzanzahl', '2'], ['Begründung', companyPoolValues.reason]]) await poolDialog.getByLabel(label, { exact: true }).fill(value);
    const creatingPool = page.waitForResponse(response => new URL(response.url()).pathname === '/api/licenses/company/pools' && response.request().method() === 'POST'); await poolDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const createdPool = await creatingPool; assert.equal(createdPool.status(), 201, await createdPool.text()); const companyPool = await createdPool.json(); assert.equal(companyPool.tenantId, receipt.tenantId); assert.equal(companyPool.usedSeats, 0);
    await page.getByRole('button', { name: companyPoolValues.name, exact: true }).click(); await page.getByRole('article', { name: 'Lizenzpooldetails', exact: true }).waitFor();
    let companyBlueprintEvidence;
    {
      const blueprintPage = await isolated.newPage(); const blueprintEditorPage = await isolated.newPage(); const blueprintBase = '/api/company-blueprints';
      const blueprintName = 'Browser own-company security blueprint'; const blueprintWrites = [];
      const observeBlueprintWrite = outgoing => { if (['POST', 'PUT'].includes(outgoing.method()) && new URL(outgoing.url()).pathname.startsWith(blueprintBase)) blueprintWrites.push(outgoing); };
      blueprintPage.on('request', observeBlueprintWrite); blueprintEditorPage.on('request', observeBlueprintWrite);
      let refreshedBlueprintOwner = false;
      try {
        await blueprintPage.setViewportSize({ width: 1440, height: 1100 }); await blueprintEditorPage.setViewportSize({ width: 1440, height: 1100 });
        await blueprintPage.goto(origin + '/company-blueprints');
        let blueprintSession = await mediated(blueprintPage); assert.equal(blueprintSession.status, 200);
        let blueprintClaims = JSON.parse(Buffer.from(blueprintSession.body.access_token.split('.')[1], 'base64url'));
        if (Math.floor(Date.now() / 1000) - blueprintClaims.auth_time >= 240) {
          await login(blueprintPage, ownerUsername); await blueprintPage.goto(origin + '/company-blueprints');
          blueprintSession = await mediated(blueprintPage); blueprintClaims = JSON.parse(Buffer.from(blueprintSession.body.access_token.split('.')[1], 'base64url')); refreshedBlueprintOwner = true;
        }
        const blueprintToken = blueprintSession.body.access_token;
        assert.deepEqual(blueprintClaims.roles, []); assert.equal(blueprintClaims.identity_authorization.userId, receipt.administratorId); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(blueprintClaims), true);
        const blueprintRequest = async (route, { method = 'GET', headers = {}, body } = {}) => {
          const response = await blueprintPage.request.fetch(origin + route, { method, headers: { Authorization: 'Bearer ' + blueprintToken, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(body ? { data: body } : {}) });
          return { status: response.status(), body: await response.json() };
        };
        const blueprintTables = ['company_blueprints', 'company_blueprint_operations', 'company_blueprint_versions', 'company_blueprint_events', 'company_blueprint_outbox'];
        const blueprintRows = async () => {
          const result = {};
          for (const table of blueprintTables) result[table] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
          return result;
        };
        const unrelatedBlueprintState = async () => {
          const result = {}; const tables = (await policyDb.query('SELECT tablename FROM pg_tables WHERE schemaname=current_schema() ORDER BY tablename')).rows;
          for (const { tablename } of tables) if (!blueprintTables.includes(tablename)) result[tablename] = (await policyDb.query(`SELECT to_jsonb(record) AS row FROM "${tablename}" record ORDER BY to_jsonb(record)::text`)).rows;
          for (const table of ['mdm_commands', 'policy_device_operations', 'policy_device_command_audit', 'policy_device_command_outbox', 'policy_device_cancellations']) result['issuer.' + table] = (await issuerDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
          for (const table of ['users', 'identity_role_assignments', 'identity_pim_eligibilities', 'identity_pim_requests', 'identity_company_activations']) result['identity.' + table] = (await identityDb.query(`SELECT to_jsonb(record) AS row FROM ${table} record ORDER BY to_jsonb(record)::text`)).rows;
          return result;
        };
        const beforeBlueprints = await blueprintRows(); const beforeBlueprintEffects = await unrelatedBlueprintState();
        const blueprintSource = await blueprintRequest('/api/identity/company-blueprints'); assert.equal(blueprintSource.status, 200, JSON.stringify(blueprintSource.body));
        assert.equal(Object.keys(blueprintSource.body).length, 11); assert.equal(blueprintSource.body.companyBlueprintProtocol, 1); assert.equal(blueprintSource.body.tokenId, blueprintClaims.jti);
        assert.deepEqual(blueprintSource.body.permissions, ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish']); assert.equal(blueprintSource.body.tenant.id, receipt.tenantId);
        const blueprintCapabilities = await blueprintRequest(blueprintBase + '/capabilities'); assert.equal(blueprintCapabilities.status, 200);
        assert.deepEqual(blueprintCapabilities.body, { schemaVersion: 1, actorUserId: receipt.administratorId, tenantId: receipt.tenantId, companyBlueprintProtocol: 1,
          permissions: ['company.blueprints.read', 'company.blueprints.manage', 'company.blueprints.publish'], configurationMode: 'local-only', maxConfigurations: 25, maxApplications: 25 });
        await blueprintPage.getByRole('button', { name: 'Blueprint erstellen', exact: true }).click();
        const blueprintEditor = blueprintPage.getByRole('region', { name: 'Blueprint-Editor', exact: true }); await blueprintEditor.waitFor();
        await blueprintEditor.getByLabel('Blueprint-Name', { exact: true }).fill(blueprintName); await blueprintEditor.getByLabel('Blueprint-Plattform', { exact: true }).selectOption('macos');
        await blueprintEditor.getByLabel('Beschreibung', { exact: true }).fill('Actual own-company desired security plan, no installation');
        await blueprintEditor.getByLabel('Neue Konfigurationsart', { exact: true }).selectOption('screen_lock'); await blueprintEditor.getByRole('button', { name: 'Konfiguration hinzufügen', exact: true }).click();
        await blueprintEditor.getByLabel('Konfigurationsname 1', { exact: true }).fill('Five minute screen lock'); await blueprintEditor.getByLabel('Sperre nach Minuten 1', { exact: true }).fill('5');
        assert.equal(await blueprintEditor.getByLabel('Passwort bei Entsperrung verlangen 1', { exact: true }).isChecked(), true);
        const appPicker = blueprintEditor.getByRole('region', { name: 'Gewünschte Firmen-Apps', exact: true }); await appPicker.getByRole('button', { name: 'App-Auswahl laden', exact: true }).click();
        await appPicker.getByRole('checkbox', { name: companyPoolValues.name + ' · ' + companyPoolValues.vendor, exact: true }).check();
        await blueprintPage.getByLabel('Begründung für die Änderung', { exact: true }).fill('Actual roleless owner creates a typed company security blueprint with one desired app');
        await blueprintEditor.scrollIntoViewIfNeeded(); await blueprintPage.screenshot({ path: '/tmp/od-business21-blueprint-typed-editor.png', fullPage: true });
        const confirmBlueprint = async (target, title) => {
          const dialog = target.getByRole('alertdialog', { name: title, exact: true }); await dialog.waitFor();
          await dialog.getByRole('checkbox', { name: 'Ich bestätige diesen lokalen Blueprint-Vorgang.', exact: true }).check();
          await dialog.getByRole('button', { name: 'Bestätigen', exact: true }).click();
        };
        const creatingBlueprint = blueprintPage.waitForResponse(response => new URL(response.url()).pathname === blueprintBase && response.request().method() === 'POST');
        await blueprintEditor.getByRole('button', { name: 'Blueprint anlegen', exact: true }).click(); await confirmBlueprint(blueprintPage, 'Blueprint erstellen');
        const createdBlueprintResponse = await creatingBlueprint; assert.equal(createdBlueprintResponse.status(), 201, await createdBlueprintResponse.text());
        const createdBlueprint = await createdBlueprintResponse.json(); const blueprintPath = blueprintBase + '/' + createdBlueprint.blueprintId;
        assert.equal(createdBlueprint.outcome, 'applied'); assert.equal(createdBlueprint.revision, '1'); assert.equal(createdBlueprint.publishedVersion, null);
        const blueprintCreateInput = createdBlueprintResponse.request().postDataJSON(); assert.deepEqual(blueprintCreateInput.draft.appPoolIds, [companyPool.id]); assert.deepEqual(JSON.parse(blueprintCreateInput.draft.configurations[0].payloadJson), { minutes: 5, requirePassword: true });
        const selectBlueprint = async target => {
          const reading = target.waitForResponse(response => new URL(response.url()).pathname === blueprintPath && response.request().method() === 'GET');
          await target.getByRole('button', { name: blueprintName, exact: true }).click(); const response = await reading; assert.equal(response.status(), 200, await response.text());
          await target.getByRole('region', { name: 'Blueprint-Details', exact: true }).waitFor(); return { body: await response.json(), etag: response.headers().etag };
        };
        const reloadBlueprint = async target => { await target.getByRole('button', { name: 'Aktuellen Blueprint-Stand neu laden', exact: true }).click(); return selectBlueprint(target); };
        const originalBlueprint = await reloadBlueprint(blueprintPage); const originalBlueprintDraft = originalBlueprint.body.blueprint.draft;
        assert.equal(Object.hasOwn(originalBlueprint.body.blueprint, 'createdAtISO'), false); assert.equal(Object.hasOwn(originalBlueprint.body.blueprint, 'updatedAtISO'), false);
        assert.equal(new Date(originalBlueprint.body.blueprint.createdAt).toISOString(), originalBlueprint.body.blueprint.createdAt); assert.equal(new Date(originalBlueprint.body.blueprint.updatedAt).toISOString(), originalBlueprint.body.blueprint.updatedAt);
        let publicationAckLost = false; let resolvePublication; let rejectPublication;
        const committedPublication = new Promise((resolve, reject) => { resolvePublication = resolve; rejectPublication = reject; });
        await blueprintPage.route(origin + blueprintPath + '/publish', async network => {
          if (network.request().method() !== 'POST' || publicationAckLost) return network.continue();
          publicationAckLost = true;
          try {
            const response = await network.fetch(); assert.equal(response.status(), 200, await response.text()); const result = await response.json();
            const retained = (await policyDb.query('SELECT receipt.*,company_blueprint_evidence_valid(receipt) AS valid FROM company_blueprint_operations receipt WHERE id=$1', [result.operationId])).rows;
            assert.equal(retained.length, 1); assert.equal(retained[0].valid, true); assert.equal(result.publishedVersion, 1);
            resolvePublication({ body: result, request: network.request() }); await network.abort('connectionfailed');
          } catch (error) { rejectPublication(error); await network.abort('failed'); }
        });
        await blueprintPage.getByLabel('Begründung für die Änderung', { exact: true }).fill('First immutable local company release with a deliberately lost acknowledgement');
        await blueprintPage.getByRole('region', { name: 'Blueprint-Details', exact: true }).getByRole('button', { name: 'Version lokal freigeben', exact: true }).click(); await confirmBlueprint(blueprintPage, 'Version lokal freigeben');
        const firstPublication = await committedPublication; assert.equal(firstPublication.body.revision, '2');
        await blueprintPage.getByRole('region', { name: 'Unbestätigter Änderungsversuch', exact: true }).waitFor();
        await blueprintEditorPage.goto(origin + '/company-blueprints'); const firstPublishedHead = await selectBlueprint(blueprintEditorPage);
        assert.equal(firstPublishedHead.body.blueprint.revision, '2'); assert.equal(firstPublishedHead.body.blueprint.publishedVersion, 1); assert.equal(firstPublishedHead.body.blueprint.draftChanged, false);
        const openBlueprintVersion = async (target, version) => {
          const reading = target.waitForResponse(response => new URL(response.url()).pathname === blueprintPath + '/versions/' + version && response.request().method() === 'GET');
          await target.getByRole('button', { name: 'Version ' + version + ' ansehen', exact: true }).click(); const response = await reading; assert.equal(response.status(), 200, await response.text());
          await target.getByRole('region', { name: 'Gespeicherte Version ' + version, exact: true }).waitFor(); return response.json();
        };
        const firstBlueprintVersion = await openBlueprintVersion(blueprintEditorPage, 1);
        assert.deepEqual(firstBlueprintVersion.version.draft, originalBlueprintDraft); assert.deepEqual(firstBlueprintVersion.version.apps, [{ id: companyPool.id, name: companyPoolValues.name, vendor: companyPoolValues.vendor, revision: companyPool.revision }]);
        const releasedRegion = blueprintEditorPage.getByRole('region', { name: 'Gespeicherte Version 1', exact: true });
        await releasedRegion.getByText('Gespeichertes Profil anzeigen', { exact: true }).click(); assert.equal(await releasedRegion.locator('pre').innerText(), originalBlueprintDraft.configurations[0].payloadJson);
        await releasedRegion.scrollIntoViewIfNeeded(); await blueprintEditorPage.screenshot({ path: '/tmp/od-business21-blueprint-immutable-version.png', fullPage: true });
        await blueprintEditorPage.getByRole('region', { name: 'Blueprint-Details', exact: true }).getByRole('button', { name: 'Entwurf bearbeiten', exact: true }).click();
        const changedEditor = blueprintEditorPage.getByRole('region', { name: 'Blueprint-Editor', exact: true });
        await changedEditor.getByLabel('Sperre nach Minuten 1', { exact: true }).fill('10');
        await changedEditor.getByLabel('Neue Konfigurationsart', { exact: true }).selectOption('filevault'); await changedEditor.getByRole('button', { name: 'Konfiguration hinzufügen', exact: true }).click();
        await changedEditor.getByLabel('Konfigurationsname 2', { exact: true }).fill('Desired disk encryption'); assert.equal(await changedEditor.getByLabel('FileVault gewünscht 2', { exact: true }).isChecked(), true);
        await changedEditor.getByLabel('Neue Konfigurationsart', { exact: true }).selectOption('software_update'); await changedEditor.getByRole('button', { name: 'Konfiguration hinzufügen', exact: true }).click();
        await changedEditor.getByLabel('Konfigurationsname 3', { exact: true }).fill('Desired automatic updates'); await changedEditor.getByLabel('Update-Aufschub in Tagen 3', { exact: true }).fill('7');
        await blueprintEditorPage.getByLabel('Begründung für die Änderung', { exact: true }).fill('Explicitly update the desired screen lock, FileVault and automatic update plan');
        const updatingBlueprint = blueprintEditorPage.waitForResponse(response => new URL(response.url()).pathname === blueprintPath && response.request().method() === 'PUT');
        await changedEditor.getByRole('button', { name: 'Entwurf speichern', exact: true }).click(); await confirmBlueprint(blueprintEditorPage, 'Entwurf speichern');
        const updatedBlueprintResponse = await updatingBlueprint; assert.equal(updatedBlueprintResponse.status(), 200, await updatedBlueprintResponse.text()); const updatedBlueprint = await updatedBlueprintResponse.json(); assert.equal(updatedBlueprint.revision, '3'); assert.equal(updatedBlueprint.publishedVersion, 1);
        await reloadBlueprint(blueprintEditorPage);
        const publishBlueprint = async reason => {
          await blueprintEditorPage.getByLabel('Begründung für die Änderung', { exact: true }).fill(reason);
          const publishing = blueprintEditorPage.waitForResponse(response => new URL(response.url()).pathname === blueprintPath + '/publish' && response.request().method() === 'POST');
          await blueprintEditorPage.getByRole('region', { name: 'Blueprint-Details', exact: true }).getByRole('button', { name: 'Version lokal freigeben', exact: true }).click(); await confirmBlueprint(blueprintEditorPage, 'Version lokal freigeben');
          const response = await publishing; assert.equal(response.status(), 200, await response.text()); return response.json();
        };
        const secondPublication = await publishBlueprint('Second immutable local release of the explicitly updated company security plan'); assert.equal(secondPublication.revision, '4'); assert.equal(secondPublication.publishedVersion, 2);
        await reloadBlueprint(blueprintEditorPage);
        const secondBlueprintVersion = await openBlueprintVersion(blueprintEditorPage, 2);
        assert.deepEqual(secondBlueprintVersion.version.draft.configurations.map(config => [config.type, JSON.parse(config.payloadJson)]), [
          ['screen_lock', { minutes: 10, requirePassword: true }], ['filevault', { enabled: true }], ['software_update', { automatic: true, deferralDays: 7 }],
        ]);
        const beforeStaleBlueprint = await blueprintRows(); const staleBlueprint = await blueprintRequest(blueprintPath, { method: 'PUT', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': originalBlueprint.etag }, body: updatedBlueprintResponse.request().postDataJSON() });
        assert.equal(staleBlueprint.status, 412, JSON.stringify(staleBlueprint.body)); assert.deepEqual(await blueprintRows(), beforeStaleBlueprint);
        assert.deepEqual(await openBlueprintVersion(blueprintEditorPage, 1), firstBlueprintVersion);
        await blueprintEditorPage.getByLabel('Begründung für die Änderung', { exact: true }).fill('Restore version one into the draft without changing immutable local version two');
        const restoringBlueprint = blueprintEditorPage.waitForResponse(response => new URL(response.url()).pathname === blueprintPath + '/restore' && response.request().method() === 'POST');
        await blueprintEditorPage.getByRole('region', { name: 'Gespeicherte Version 1', exact: true }).getByRole('button', { name: 'Als Entwurf wiederherstellen', exact: true }).click(); await confirmBlueprint(blueprintEditorPage, 'Als Entwurf wiederherstellen');
        const restoredBlueprintResponse = await restoringBlueprint; assert.equal(restoredBlueprintResponse.status(), 200, await restoredBlueprintResponse.text()); const restoredBlueprint = await restoredBlueprintResponse.json(); assert.equal(restoredBlueprint.revision, '5'); assert.equal(restoredBlueprint.publishedVersion, 2);
        const restoredHead = await reloadBlueprint(blueprintEditorPage); assert.deepEqual(restoredHead.body.blueprint.draft, originalBlueprintDraft); assert.equal(restoredHead.body.blueprint.publishedVersion, 2); assert.equal(restoredHead.body.blueprint.draftChanged, true);
        assert.equal((await blueprintRequest(blueprintPath + '/versions')).body.total, 2);
        await blueprintEditorPage.getByRole('region', { name: 'Blueprint-Details', exact: true }).scrollIntoViewIfNeeded(); await blueprintEditorPage.screenshot({ path: '/tmp/od-business21-blueprint-restored-draft.png', fullPage: true });
        const thirdPublication = await publishBlueprint('Third explicit local release of the original restored company security blueprint'); assert.equal(thirdPublication.revision, '6'); assert.equal(thirdPublication.publishedVersion, 3);
        const newestHead = await reloadBlueprint(blueprintEditorPage); assert.equal(newestHead.body.blueprint.revision, '6'); assert.equal(newestHead.body.blueprint.publishedVersion, 3); assert.equal(newestHead.body.blueprint.draftChanged, false);
        const thirdBlueprintVersion = await openBlueprintVersion(blueprintEditorPage, 3); assert.deepEqual(thirdBlueprintVersion.version.draft, originalBlueprintDraft);
        const beforeBlueprintRecovery = await blueprintRows();
        const recoveringPublication = blueprintPage.waitForResponse(response => new URL(response.url()).pathname === blueprintPath + '/publish' && response.request().method() === 'POST');
        await blueprintPage.getByRole('region', { name: 'Unbestätigter Änderungsversuch', exact: true }).getByRole('button', { name: 'Ursprünglichen Versuch wiederaufnehmen', exact: true }).click(); await confirmBlueprint(blueprintPage, 'Version lokal freigeben');
        const recoveredPublicationResponse = await recoveringPublication; assert.equal(recoveredPublicationResponse.status(), 200, await recoveredPublicationResponse.text()); const recoveredPublication = await recoveredPublicationResponse.json();
        assert.deepEqual(recoveredPublication, { ...firstPublication.body, outcome: 'already_applied' }); assert.deepEqual(recoveredPublicationResponse.request().postDataJSON(), firstPublication.request.postDataJSON());
        for (const header of ['idempotency-key', 'if-match']) assert.equal(recoveredPublicationResponse.request().headers()[header], firstPublication.request.headers()[header]);
        assert.deepEqual(await blueprintRows(), beforeBlueprintRecovery); assert.deepEqual((await blueprintRequest(blueprintPath)).body, newestHead.body);
        await blueprintPage.getByRole('region', { name: 'Bestätigter Änderungsnachweis', exact: true }).getByText('Ursprünglicher Versuch bereits gespeichert. Historischer Nachweis für Revision 2; kein Nachweis des aktuellen Stands.', { exact: true }).waitFor();
        const finalBlueprintHistory = await blueprintRequest(blueprintPath + '/history'); assert.equal(finalBlueprintHistory.status, 200); assert.equal(finalBlueprintHistory.body.total, 6);
        assert.deepEqual(finalBlueprintHistory.body.events.map(event => [event.type, event.afterRevision, event.releasedVersion, event.restoredFrom, event.deliveryStatus]), [
          ['blueprint.published', '6', 3, null, 'pending'], ['blueprint.draft.restored', '5', null, 1, 'pending'], ['blueprint.published', '4', 2, null, 'pending'],
          ['blueprint.draft.updated', '3', null, null, 'pending'], ['blueprint.published', '2', 1, null, 'pending'], ['blueprint.created', '1', null, null, 'pending'],
        ]);
        const blueprintHistoryRegion = blueprintEditorPage.getByRole('region', { name: 'Blueprint-Historie', exact: true }); assert.equal(await blueprintHistoryRegion.getByRole('listitem').count(), 6);
        await blueprintHistoryRegion.getByText('Ereignisnachweis', { exact: true }).first().click(); await blueprintHistoryRegion.scrollIntoViewIfNeeded(); await blueprintEditorPage.screenshot({ path: '/tmp/od-business21-blueprint-history.png', fullPage: true });
        const retainedBlueprintOperations = (await policyDb.query('SELECT receipt.*,company_blueprint_evidence_valid(receipt) AS valid FROM company_blueprint_operations receipt WHERE blueprint_id=$1 ORDER BY (after_state->>\'revision\')::bigint', [createdBlueprint.blueprintId])).rows;
        assert.equal(retainedBlueprintOperations.length, 6);
        for (const operation of retainedBlueprintOperations) {
          const outgoing = blueprintWrites.find(write => write.headers()['idempotency-key'] === operation.id); assert.ok(outgoing);
          const claims = JSON.parse(Buffer.from(outgoing.headers().authorization.slice('Bearer '.length).split('.')[1], 'base64url'));
          assert.deepEqual(claims.roles, []); assert.equal(operation.valid, true); assert.equal(operation.actor_user_id, receipt.administratorId); assert.equal(operation.tenant_id, receipt.tenantId);
          assert.equal(operation.source.tokenId, claims.jti); assert.equal(Object.keys(operation.source).length, 11); assert.deepEqual(operation.source.permissions, blueprintSource.body.permissions);
          assert.deepEqual(operation.application_source.permissions, ['company.apps.read', 'company.apps.create', 'company.apps.assign']); assert.equal(operation.application_source.tokenId, claims.jti); assert.deepEqual(operation.application_source.tenant, operation.source.tenant);
          assert.equal(operation.valid_until.getTime(), Math.min(operation.source.validUntil, operation.application_source.validUntil) * 1000);
        }
        const afterBlueprints = await blueprintRows();
        for (const [table, added] of [['company_blueprints', 1], ['company_blueprint_operations', 6], ['company_blueprint_versions', 3], ['company_blueprint_events', 6], ['company_blueprint_outbox', 6]]) assert.equal(afterBlueprints[table].length - beforeBlueprints[table].length, added);
        assert.deepEqual(await unrelatedBlueprintState(), beforeBlueprintEffects); assert.equal(blueprintWrites.length, 7);
        companyBlueprintEvidence = { path: blueprintPath, token: blueprintToken, version: firstBlueprintVersion };
        process.stdout.write('Slice21 actual Chrome: roleless Owner; typed UI create/release1/update/release2/restore1/release3; first release committed then real ACK aborted; original UI key/ETag/body recovery after revision6 is effect-free historical already_applied; six real pending receipts, no allocator/legacy/MDM effects.\n');
      } finally { await blueprintEditorPage.close(); await blueprintPage.close(); }
      if (refreshedBlueprintOwner) { await page.reload(); await page.getByRole('button', { name: companyPoolValues.name, exact: true }).click(); }
    }
    const companyPoolDetails = page.getByRole('article', { name: 'Lizenzpooldetails', exact: true });
    await companyPoolDetails.getByRole('button', { name: 'App und Lizenzbestand bearbeiten', exact: true }).click(); const editingPool = page.getByRole('alertdialog', { name: 'App und Lizenzbestand bearbeiten', exact: true });
    for (const [label, value] of [['Anwendungsname', 'Renamed Blueprint Desired Editor'], ['Hersteller', 'Updated Blueprint Vendor'], ['Begründung', 'Explicit later catalog rename must preserve historical blueprint app snapshots']]) await editingPool.getByLabel(label, { exact: true }).fill(value);
    await editingPool.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const poolConfirmation = page.getByRole('alertdialog', { name: 'Änderungen an App und Lizenzbestand bestätigen', exact: true });
    const updatingPool = page.waitForResponse(response => new URL(response.url()).pathname === '/api/licenses/company/pools/' + companyPool.id && response.request().method() === 'PATCH'); await poolConfirmation.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const updatedPool = await updatingPool; assert.equal(updatedPool.status(), 200, await updatedPool.text()); const renamedPool = await updatedPool.json();
    assert.equal(renamedPool.name, 'Renamed Blueprint Desired Editor'); assert.equal(renamedPool.vendor, 'Updated Blueprint Vendor'); assert.notEqual(renamedPool.revision, companyPool.revision); assert.equal(renamedPool.usedSeats, 0);
    const historicalAfterCatalogEdit = await page.request.get(origin + companyBlueprintEvidence.path + '/versions/1', { headers: { Authorization: 'Bearer ' + companyBlueprintEvidence.token } }); assert.equal(historicalAfterCatalogEdit.status(), 200, await historicalAfterCatalogEdit.text()); assert.deepEqual(await historicalAfterCatalogEdit.json(), companyBlueprintEvidence.version);
    assert.equal((await policyDb.query('SELECT count(*)::integer AS count FROM license_assignments WHERE license_id=$1', [companyPool.id])).rows[0].count, 0);
    assert.equal((await identityDb.query('SELECT count(*)::integer AS count FROM identity_role_assignments WHERE user_id=$1', [receipt.administratorId])).rows[0].count, 0);
  } finally { await isolated.close(); }
});
test('real organization profile UI persists the own company through actual MFA, SQL receipts and stale-version refusal', { timeout: 180000 }, async () => {
  const isolated = await context(); const page = await isolated.newPage(); const route = '/api/identity/organization';
  const profile = { name: 'Actual Browser Company', legalForm: 'AG', registrationNumber: '', taxId: '', addressLine1: 'Business Street 1', addressLine2: '', postalCode: '8000', city: 'Zürich', country: 'CH', timezone: 'Europe/Zurich', defaultLanguage: 'de', contactEmail: 'office@example.invalid', contactPhone: '', website: '' };
  try {
    await login(page, 'organization-console-admin'); await page.goto(origin + '/organization');
    await page.getByText('Noch kein Organisationsprofil gespeichert.', { exact: true }).waitFor(); assert.equal(await page.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).isDisabled(), true);
    await page.getByRole('alert').filter({ hasText: 'Zum Speichern ist eine frische MFA-Anmeldung erforderlich.' }).getByRole('link', { name: 'MFA-Einstellungen öffnen', exact: true }).click(); await page.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor();
    await page.getByLabel('Eigener Benutzername', { exact: true }).fill('organization-console-admin'); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const setupReceipt = page.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll'); await page.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const setupResponse = await setupReceipt; assert.equal(setupResponse.status(), 200); const setup = await setupResponse.json(); const counter = Math.floor(Date.now() / 30000);
    await page.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(setup.secret, counter)); const confirmReceipt = page.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm'); await page.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await confirmReceipt).status(), 200);
    await page.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); rememberFactor('organization-console-admin', setup.secret, counter); await login(page, 'organization-console-admin'); await page.goto(origin + '/organization');
    await page.getByText('Noch kein Organisationsprofil gespeichert.', { exact: true }).waitFor();
    for (const [label, value] of [['Firmenname *', profile.name], ['Rechtsform', profile.legalForm], ['Strasse und Hausnummer *', profile.addressLine1], ['Postleitzahl *', profile.postalCode], ['Ort *', profile.city], ['Land (zweistellig, z. B. CH) *', profile.country], ['Zeitzone (z. B. Europe/Zurich) *', profile.timezone], ['Kontakt-E-Mail *', profile.contactEmail]]) await page.getByLabel(label, { exact: true }).fill(value);
    await page.getByLabel('Begründung der Änderung', { exact: true }).fill('Actual browser company profile creation');
    let receipt = page.waitForResponse(response => new URL(response.url()).pathname === route && response.request().method() === 'PUT');
    await page.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).click(); let confirmed = await receipt; assert.equal(confirmed.status(), 200, await confirmed.text());
    await page.getByText('Organisationsprofil gespeichert. Version 1.', { exact: true }).waitFor(); await page.reload(); await page.getByText('Gespeicherte Version 1', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Firmenname *', { exact: true }).inputValue(), profile.name);
    await page.getByLabel('Ort *', { exact: true }).fill('Bern'); await page.getByLabel('Begründung der Änderung', { exact: true }).fill('Actual browser persisted address update');
    receipt = page.waitForResponse(response => new URL(response.url()).pathname === route && response.request().method() === 'PUT'); await page.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).click(); confirmed = await receipt; assert.equal(confirmed.status(), 200); const latest = await confirmed.json();
    await page.getByText('Organisationsprofil gespeichert. Version 2.', { exact: true }).waitFor();
    const session = await mediated(page); const competing = await fetch(identityBase + route, { method: 'PUT', headers: { Authorization: 'Bearer ' + session.body.access_token, 'Content-Type': 'application/json', 'If-Match': latest.etag }, body: JSON.stringify({ profile: { ...profile, city: 'Lausanne' }, reason: 'Independent actual version conflict through the authorized receiver' }) }); assert.equal(competing.status, 200);
    await page.getByLabel('Ort *', { exact: true }).fill('Geneva'); await page.getByLabel('Begründung der Änderung', { exact: true }).fill('Stale captured browser profile must not overwrite'); await page.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).click(); await page.getByRole('alert').filter({ hasText: 'nicht bestätigt' }).waitFor(); assert.equal(await page.getByLabel('Ort *', { exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Neu laden', exact: true }).click(); await page.getByText('Gespeicherte Version 3', { exact: true }).waitFor(); assert.equal(await page.getByLabel('Ort *', { exact: true }).inputValue(), 'Lausanne');
    const rows = (await identityDb.query("SELECT profile.*,event.actor,outbox.status FROM identity_organization_profiles profile JOIN identity_organization_events event ON event.id=profile.command_id JOIN identity_organization_outbox outbox ON outbox.id=event.id WHERE profile.tenant_id=identity_tenant_id('user',$1::uuid)", [actors.get('organization-console-admin').userId])).rows;
    assert.equal(rows.length, 1); assert.equal(rows[0].city, 'Lausanne'); assert.equal(rows[0].actor.userId, actors.get('organization-console-admin').userId); assert.equal(rows[0].status, 'pending');
    const delegationRoute = route + '/delegations'; const recipientId = actors.get('organization-console-delegate').userId;
    await page.getByLabel('Kanonische Benutzer-ID (UUID, aus Personen)', { exact: true }).fill(recipientId); await page.getByLabel('Laufzeit in Sekunden', { exact: true }).fill('3600'); await page.getByLabel('Begründung der Berechtigung', { exact: true }).fill('Actual browser grants only the company profile');
    receipt = page.waitForResponse(response => new URL(response.url()).pathname === delegationRoute && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Profilberechtigung erteilen', exact: true }).click(); confirmed = await receipt; assert.equal(confirmed.status(), 201, await confirmed.text()); const delegated = await confirmed.json();
    await page.getByRole('status').filter({ hasText: 'tatsächlicher Bestand bestätigt' }).waitFor();
    const delegateContext = await context(); const delegatePage = await delegateContext.newPage();
    try {
      await login(delegatePage, 'organization-console-delegate'); await delegatePage.goto(origin + '/organization'); await delegatePage.getByRole('alert').filter({ hasText: 'MFA' }).waitFor();
      await delegatePage.getByRole('link', { name: 'MFA-Einstellungen öffnen', exact: true }).click(); await delegatePage.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor();
      await delegatePage.getByLabel('Eigener Benutzername', { exact: true }).fill('organization-console-delegate'); await delegatePage.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
      const enrollment = delegatePage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll'); await delegatePage.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const enrolled = await enrollment; assert.equal(enrolled.status(), 200); const factor = await enrolled.json(); const factorCounter = Math.floor(Date.now() / 30000);
      await delegatePage.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(factor.secret, factorCounter)); const verification = delegatePage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm'); await delegatePage.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await verification).status(), 200);
      await delegatePage.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); rememberFactor('organization-console-delegate', factor.secret, factorCounter); await login(delegatePage, 'organization-console-delegate'); await delegatePage.goto(origin + '/organization'); await delegatePage.getByText('Gespeicherte Version 3', { exact: true }).waitFor();
      assert.equal(await delegatePage.getByRole('heading', { name: 'Firmenprofil delegieren', exact: true }).count(), 0);
      await delegatePage.getByLabel('Ort *', { exact: true }).fill('Basel'); await delegatePage.getByLabel('Begründung der Änderung', { exact: true }).fill('Actual browser delegate edits the own company only');
      const update = delegatePage.waitForResponse(response => new URL(response.url()).pathname === route && response.request().method() === 'PUT'); await delegatePage.getByRole('button', { name: 'Organisationsprofil speichern', exact: true }).click(); assert.equal((await update).status(), 200); await delegatePage.getByText('Organisationsprofil gespeichert. Version 4.', { exact: true }).waitFor();
      const captured = await mediated(delegatePage); assert.deepEqual(captured.body.user.roles, ['user']);
      await page.getByRole('button', { name: 'Widerruf vorbereiten: Organization Profile Delegate', exact: true }).click(); await page.getByLabel('Begründung der Berechtigung', { exact: true }).fill('Actual browser independently revokes the profile delegation');
      receipt = page.waitForResponse(response => new URL(response.url()).pathname === delegationRoute + '/' + delegated.grantId + '/revoke'); await page.getByRole('button', { name: 'Widerruf bestätigen', exact: true }).click(); assert.equal((await receipt).status(), 200); await page.getByText('Widerrufen', { exact: true }).waitFor();
      const withdrawn = await fetch(identityBase + route, { headers: { Authorization: 'Bearer ' + captured.body.access_token } }); assert.equal(withdrawn.status, 401);
      const actual = (await identityDb.query("SELECT city FROM identity_organization_profiles WHERE tenant_id=identity_tenant_id('user',$1::uuid)", [actors.get('organization-console-admin').userId])).rows; assert.deepEqual(actual, [{ city: 'Basel' }]);
    } finally { await delegateContext.close(); }
    await page.getByRole('heading', { name: 'Firmenprofil delegieren', exact: true }).scrollIntoViewIfNeeded(); await page.screenshot({ path: '/tmp/od-business3-organization-delegations.png', fullPage: true });
  } finally { await isolated.close(); }
});
test('real browser MFA enrollment rejects a code that crosses its final accepted counter boundary and confirms only a fresh code',{timeout:90000},async()=>{
  const isolated=await context(); const page=await isolated.newPage(); const username='mfa-counter-boundary';
  try{
    await page.goto(origin+'/auth/mfa-enroll'); await page.getByLabel('Eigener Benutzername',{exact:true}).fill(username); await page.getByLabel('Aktuelles Passwort',{exact:true}).fill('disposable-password');
    const starting=page.waitForResponse(result=>new URL(result.url()).pathname==='/api/auth/oidc/enrollment/start'&&result.request().method()==='POST');
    await page.getByRole('button',{name:'Ersteinrichtung vorbereiten',exact:true}).click(); const start=await starting; assert.equal(start.status(),200); const setup=await start.json();
    const staleCounter=Math.floor(Date.now()/30000)-1; await page.getByLabel('Einmalcode des neuen Authenticators',{exact:true}).fill(totp(setup.secret,staleCounter));
    await new Promise(resolve=>setTimeout(resolve,Math.max(0,(staleCounter+2)*30000+100-Date.now())));
    const rejected=page.waitForResponse(result=>new URL(result.url()).pathname==='/api/auth/oidc/enrollment/confirm'&&result.request().method()==='POST');
    await page.getByRole('button',{name:'Neuen Faktor bestätigen',exact:true}).click(); const denied=await rejected; assert.equal(denied.status(),401); assert.equal((await denied.json()).error,'invalid_otp');
    await page.getByRole('alert').filter({hasText:'Code des neuen Authenticators nicht bestätigt.'}).waitFor(); assert.equal((await isolated.cookies()).some(cookie=>cookie.name==='od_session'),false);
    const counter=Math.floor(Date.now()/30000); await page.getByLabel('Einmalcode des neuen Authenticators',{exact:true}).fill(totp(setup.secret,counter));
    const confirming=page.waitForResponse(result=>new URL(result.url()).pathname==='/api/auth/oidc/enrollment/confirm'&&result.request().method()==='POST');
    await page.getByRole('button',{name:'Neuen Faktor bestätigen',exact:true}).click(); const confirmed=await confirming; assert.equal(confirmed.status(),200); assert.equal(confirmed.headers()['set-cookie'],undefined);
    await page.getByText(/Ersteinrichtung bestätigt/).waitFor(); assert.equal((await isolated.cookies()).some(cookie=>cookie.name==='od_session'),false); assert.equal(await page.getByText(setup.secret,{exact:true}).count(),0);
    const replay=await page.evaluate(async body=>{const result=await fetch('/api/auth/oidc/enrollment/confirm',{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json','X-OD-Enrollment':'1'},body:JSON.stringify(body)});return{status:result.status,error:(await result.json()).error};},{challenge:setup.challenge,code:totp(setup.secret,counter)});
    assert.equal(replay.status,401); assert.equal(replay.error,'invalid_enrollment_challenge');
  }finally{await isolated.close();}
});
test('real recurring review UI separates configuration, independent MFA voting and read-only status while deadlines remove actual license authority',{ timeout:180000 },async()=>{
  const managerContext=await context(); const voterContext=await context(); const readerContext=await context(); const holderContext=await context(); const grantContext=await context();
  let policy; let managerToken;
  try {
    const grantor=await grantContext.newPage(); await login(grantor,'role-operator'); const grantToken=(await mediated(grantor)).body.access_token;
    const grantResponse=await grantor.request.post(origin+'/api/users/'+actors.get('review-holder').userId+'/roles',{ headers:{ Authorization:'Bearer '+grantToken },data:{ role:'license-manager',durationSeconds:3600,reason:'Independently delegated review-governed role' } }); assert.equal(grantResponse.status(),201); const grant=await grantResponse.json();
    const manager=await managerContext.newPage(); await reviewFirstFactor(manager,'review-config'); await login(manager,'review-config'); managerToken=(await mediated(manager)).body.access_token;
    const voter=await voterContext.newPage(); await reviewFirstFactor(voter,'review-voter'); await login(voter,'review-voter');
    const holder=await holderContext.newPage(); await login(holder,'review-holder'); const initial=(await mediated(holder)).body.access_token;
    await manager.goto(origin+'/roles'); await manager.getByLabel('Kanonische Rolle für Zugriffsprüfung',{ exact:true }).fill('license-manager'); await manager.getByRole('button',{ name:'Prüfrichtlinie laden',exact:true }).click();
    await manager.getByText('Keine Prüfrichtlinie eingerichtet.',{ exact:true }).waitFor();
    await manager.getByLabel('Prüfintervall in Sekunden',{ exact:true }).fill('3600'); await manager.getByLabel('Prüffenster in Sekunden',{ exact:true }).fill('300');
    await manager.getByLabel('Prüfer-UUIDs (eine je Zeile)',{ exact:true }).fill(actors.get('review-voter').userId); await manager.getByLabel('Begründung der Prüfrichtlinie',{ exact:true }).fill('Real independent recurring privilege recertification');
    await manager.getByRole('button',{ name:'Prüfrichtlinie anlegen prüfen',exact:true }).click(); assert.equal(await manager.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen',exact:true }).isDisabled(),true);
    await manager.getByLabel('Ziel, Fristen und unabhängige Wirkung geprüft',{ exact:true }).check(); const created=manager.waitForResponse(response=>new URL(response.url()).pathname==='/api/identity/reviews/policies' && response.request().method()==='POST');
    await manager.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen',exact:true }).click(); const response=await created; assert.equal(response.status(),201); policy=await response.json();
    await manager.getByText(/Prüfrichtlinie bestätigt/).waitFor(); assert.equal((await holder.request.get(origin+'/api/licenses/access',{ headers:{ Authorization:'Bearer '+initial } })).status(),401); assert.equal((await mediated(holder)).status,401);
    await login(holder,'review-holder'); assert.ok(JSON.parse(Buffer.from((await mediated(holder)).body.access_token.split('.')[1],'base64url')).roles.includes('license-manager'));
    await voter.goto(origin+'/roles'); const article=voter.getByRole('article').filter({ hasText:grant.id }); await article.getByText('license-manager · Offen',{ exact:true }).waitFor();
    await article.getByRole('button',{ name:'Vergabe behalten prüfen',exact:true }).click();
    await voter.getByLabel('Begründung der Bestätigung',{ exact:true }).fill('Independent actual review of existing privilege only'); await voter.getByLabel('Ziel, Fristen und unabhängige Wirkung geprüft',{ exact:true }).check();
    const decided=voter.waitForResponse(result=>new URL(result.url()).pathname.endsWith('/decisions') && result.request().method()==='POST');
    await voter.getByRole('button',{ name:'Zugriffsprüfung verbindlich bestätigen',exact:true }).click(); const decisionResponse=await decided; assert.equal(decisionResponse.status(),200); const decision=await decisionResponse.json(); assert.equal(decision.state,'scheduled');
    await voter.getByText(/Bestehende Vergabe bestätigt; nächste Prüfung geplant/).waitFor();
    assert.equal((await identityDb.query('SELECT expires_at FROM identity_role_assignments WHERE id=$1',[grant.id])).rows[0].expires_at.toISOString(),grant.expiresAt);
    assert.equal((await mediated(holder)).status,401); await login(holder,'review-holder'); const current=(await mediated(holder)).body.access_token;
    assert.equal((await holder.request.get(origin+'/api/licenses/access',{ headers:{ Authorization:'Bearer '+current } })).status(),200);
    await identityDb.query("CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp()+interval '3901 seconds'; $$");
    assert.equal((await holder.request.get(origin+'/api/licenses/access',{ headers:{ Authorization:'Bearer '+current } })).status(),401); assert.equal((await mediated(holder)).status,401);
    await login(holder,'review-holder'); assert.ok(!JSON.parse(Buffer.from((await mediated(holder)).body.access_token.split('.')[1],'base64url')).roles.includes('license-manager'));
    const reader=await readerContext.newPage(); const profiles=[]; reader.on('request',request=>{ const pathname=new URL(request.url()).pathname; if(pathname==='/api/users' || pathname.startsWith('/api/users/') || pathname==='/api/identity/search')profiles.push(pathname); });
    await login(reader,'review-reader'); await reader.goto(origin+'/roles'); await reader.getByLabel('Bekannte Prüfungs-ID',{ exact:true }).fill(decision.id); await reader.getByRole('button',{ name:'Zugriffsprüfung laden',exact:true }).click();
    await reader.getByText('license-manager · Prüffrist abgelaufen',{ exact:true }).waitFor(); assert.equal(await reader.getByRole('button',{ name:'Vergabe behalten prüfen',exact:true }).count(),0); assert.equal(profiles.length,0);
    const panel=reader.getByRole('region',{ name:'Wiederkehrende Rollenprüfungen' }); await panel.scrollIntoViewIfNeeded(); await reader.screenshot({ path:path.join(os.tmpdir(),'od-role-review.png'),fullPage:false });
  } finally {
    if(policy && managerToken) {
      await identityDb.transaction(async client=>{
        await client.query("SELECT set_config('opendirectory.review_reason','Isolated browser cleanup without deadline resurrection',true)");
        await client.query('UPDATE identity_role_review_policies SET retired_at=identity_role_review_now(),version=version+1 WHERE id=$1 AND retired_at IS NULL',[policy.id]);
        await client.query("UPDATE identity_role_assignments SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND id IN (SELECT target_id FROM identity_role_review_leases WHERE policy_id=$1 AND target_kind='assignment')",[policy.id]);
        await client.query("UPDATE identity_pim_eligibilities SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL AND id IN (SELECT target_id FROM identity_role_review_leases WHERE policy_id=$1 AND target_kind='eligibility')",[policy.id]);
      },{ actor:'isolated-review-browser-owner' });
    }
    await identityDb.query('CREATE OR REPLACE FUNCTION identity_role_review_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$');
    for(const owned of [managerContext,voterContext,readerContext,holderContext,grantContext])await owned.close();
  }
});

test('real own-company Owner UI assigns pinned blueprints and displays actual license origins through negative offboarding', { timeout: 240000 }, async () => {
  const ownerUsername = 'company-assignment-owner'; const reviewerUsername = 'company-assignment-reviewer';
  const isolated = await context({ onboarded: false }); const page = await isolated.newPage();
  const savedEnvironment = Object.fromEntries(['NODE_ENV', 'CORS_ORIGIN', 'POLICY_SERVICE_URL', 'DEVICE_SERVICE_URL'].map(name => [name, process.env[name]]));
  let productionGateway; let GatewayModule; const gatewayRequests = [];
  try {
    Object.assign(process.env, { NODE_ENV: 'production', CORS_ORIGIN: origin, POLICY_SERVICE_URL: policyBase, DEVICE_SERVICE_URL: inventoryFixture.base });
    GatewayModule = require('../../../api-gateway/src'); await GatewayModule.databaseReady;
    productionGateway = new GatewayModule({ discover: false, enabledModules: ['identity-service', 'policy-service', 'device-management'] }); productionGateway.server.listen(0, '127.0.0.1');
    const gatewayOrigin = await serverBase(productionGateway.server);
    await isolated.route('**/api/**', async route => {
      const target = new URL(route.request().url());
      if (!/^\/api\/(?:company-blueprints|company-blueprint-assignments|licenses|users|groups|ous|identity)(?:\/|$)/.test(target.pathname)) return route.fallback();
      const headers = Object.fromEntries(Object.entries(route.request().headers()).filter(([name]) => !['cookie', 'host'].includes(name)));
      const response = await route.fetch({ url: gatewayOrigin + target.pathname + target.search, headers, maxRedirects: 0 });
      gatewayRequests.push({ path: target.pathname, method: route.request().method(), authorization: headers.authorization, status: response.status() });
      await route.fulfill({ response });
    });
    await page.setViewportSize({ width: 1440, height: 1100 }); await page.goto(origin + '/register');
    await page.getByLabel('Benutzername', { exact: true }).fill(ownerUsername); await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
    const registrationId = await page.getByLabel('Registrierungs-ID (für Statusabfrage aufbewahren)', { exact: true }).inputValue();
    for (const [label, value] of [['Firmenname *', 'Actual Assignment Browser Company'], ['Strasse und Hausnummer *', 'Assignment Street 1'], ['Postleitzahl *', '8000'], ['Ort *', 'Zürich'], ['Land (zweistellig, z. B. CH) *', 'CH'], ['Kontakt-E-Mail *', 'assignments@example.invalid']]) await page.getByLabel(label, { exact: true }).fill(value);
    await page.getByRole('checkbox').check(); const submitting = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/submit'); await page.getByRole('button', { name: 'Unternehmen zur Prüfung anmelden', exact: true }).click();
    const submitted = await submitting; assert.equal(submitted.status(), 201, await submitted.text()); const registration = await submitted.json(); assert.equal(registration.tenantEnabled, false); assert.equal(registration.administratorEnabled, false);
    const reviewContext = await context(); const reviewerPage = await reviewContext.newPage();
    try {
      await require('../../../identity-service/scripts/company-review-operator').changeOperator(identityDb, { issuer: logicalIssuer, userId: actors.get(reviewerUsername).userId, version: '0', enabled: true, reason: 'Independent review of the isolated actual assignment browser company' });
      await login(reviewerPage, reviewerUsername); await reviewerPage.goto(origin + '/mfa'); await reviewerPage.getByText('TOTP nicht eingerichtet', { exact: true }).waitFor();
      await reviewerPage.getByLabel('Eigener Benutzername', { exact: true }).fill(reviewerUsername); await reviewerPage.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password');
      const enrolling = reviewerPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/enroll'); await reviewerPage.getByRole('button', { name: 'TOTP einrichten', exact: true }).click(); const enrolled = await enrolling; assert.equal(enrolled.status(), 200); const factor = await enrolled.json(); const counter = Math.floor(Date.now() / 30000);
      await reviewerPage.getByLabel('Neuer OpenDirectory-Einmalcode', { exact: true }).fill(totp(factor.secret, counter)); const confirming = reviewerPage.waitForResponse(response => new URL(response.url()).pathname === '/api/mfa/confirm'); await reviewerPage.getByRole('button', { name: 'Einrichtung bestätigen', exact: true }).click(); assert.equal((await confirming).status(), 200);
      await reviewerPage.getByText(/Änderung bestätigt. Alle bisherigen Tokens/).waitFor(); rememberFactor(reviewerUsername, factor.secret, counter); await login(reviewerPage, reviewerUsername);
      const reviewerSession = await mediated(reviewerPage); const reviewerClaims = JSON.parse(Buffer.from(reviewerSession.body.access_token.split('.')[1], 'base64url')); assert.deepEqual(reviewerClaims.roles, ['user']); assert.notEqual(reviewerClaims.identity_authorization.userId, registration.administratorId);
      const pending = await fetch(gatewayOrigin + '/api/identity/company-registrations/' + registrationId, { headers: { Authorization: 'Bearer ' + reviewerSession.body.access_token } }); assert.equal(pending.status, 200); const review = await pending.json();
      const approved = await fetch(gatewayOrigin + '/api/identity/company-registrations/' + registrationId + '/review', { method: 'POST', headers: { Authorization: 'Bearer ' + reviewerSession.body.access_token, 'Content-Type': 'application/json', 'If-Match': review.etag }, body: JSON.stringify({ decision: 'approved', reason: 'Actual independent reviewer approves the company without global administrator authority', confirm: true }) }); assert.equal(approved.status, 200, await approved.text());
    } finally { await reviewContext.close(); }
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); const reconciling = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/status'); await page.getByRole('button', { name: 'Bestehenden Status prüfen', exact: true }).click(); assert.equal((await reconciling).status(), 200);
    await page.getByLabel('Aktuelles Passwort', { exact: true }).fill('disposable-password'); await page.getByLabel('Ich bestätige die Aktivierung meiner freigegebenen Firma mit Pflicht-MFA und ohne globale Adminrechte.', { exact: true }).check();
    const activating = page.waitForResponse(response => new URL(response.url()).pathname === '/api/company-registration/activate'); await page.getByRole('button', { name: 'Freigegebene Firma aktivieren', exact: true }).click(); const activated = await activating; assert.equal(activated.status(), 200, await activated.text()); assert.equal((await activated.json()).status, 'active');
    await reviewFirstFactor(page, ownerUsername); await login(page, ownerUsername); const ownerSession = await mediated(page); assert.equal(ownerSession.status, 200); const token = ownerSession.body.access_token;
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url')); assert.deepEqual(claims.roles, []); assert.equal(claims.identity_authorization.userId, registration.administratorId); assert.equal(require('../../../../../packages/mfa-authorization-contract').provenMfa(claims), true); const startedAt = Date.now();
    const api = async (route, { method = 'GET', body, headers = {} } = {}, expectedStatus = 200) => {
      const response = await fetch(gatewayOrigin + route, { method, headers: { Authorization: 'Bearer ' + token, ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(body ? { body: JSON.stringify(body) } : {}) });
      const result = await response.json(); assert.equal(response.status, expectedStatus, JSON.stringify({ route, result })); return { body: result, headers: response.headers };
    };
    const createdUser = (await api('/api/users', { method: 'POST', body: { username: 'browser-assignment-employee', email: 'browser-assignment-employee@example.invalid' } }, 201)).body; assert.equal(createdUser.enabled, false);
    const employee = (await api('/api/users/' + createdUser.id, { method: 'PUT', headers: { 'If-Match': require('../../../identity-service/src/DirectoryUsers').userEtag(createdUser) }, body: { enabled: true } })).body;
    const pool = (await api('/api/licenses/company/pools', { method: 'POST', body: { name: 'Actual browser overlapping editor', vendor: 'Actual Browser Vendor', description: 'One physical local seat with several real origins', totalSeats: 1, reason: 'Create the actual finite application pool for the isolated browser journey' } }, 201)).body;
    const assignmentBase = '/api/company-blueprint-assignments'; const appV2 = '/api/licenses/company/v2';
    const manualPreview = (await api(appV2 + '/pools/' + pool.id + '/assignment-preview', { method: 'POST', body: { userId: employee.id } })).body;
    await api(appV2 + '/pools/' + pool.id + '/assignments', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': '"company-pool-' + pool.id + '-' + manualPreview.poolRevision + '"' }, body: { userId: employee.id, eligibilityRevision: manualPreview.target.eligibilityRevision, assignmentId: null, sources: [], reason: 'Actual original manual origin before independent blueprint user assignment', confirm: true } }, 201);
    const release = async (name, appPoolIds, configurations) => {
      const id = randomUUID(); await api('/api/company-blueprints', { method: 'POST', headers: { 'Idempotency-Key': randomUUID() }, body: { id, draft: { name, description: 'Actual immutable company configuration plan', platform: 'macos', configurations, appPoolIds }, reason: 'Create an actual company blueprint for the isolated browser assignment', confirm: true } }, 201);
      const head = await api('/api/company-blueprints/' + id); await api('/api/company-blueprints/' + id + '/publish', { method: 'POST', headers: { 'Idempotency-Key': randomUUID(), 'If-Match': head.headers.get('etag') }, body: { reason: 'Release the immutable local version before the real user assignment', confirm: true } }); return { id, name };
    };
    const configuration = () => [{ id: randomUUID(), type: 'screen_lock', name: 'Actual five minute lock', payloadJson: '{"minutes":5,"requirePassword":true}' }];
    const first = await release('Browser employee blueprint A', [pool.id], configuration()); const second = await release('Browser employee blueprint B', [pool.id], configuration());
    const zero = await release('Browser zero-app encryption blueprint', [], [{ id: randomUUID(), type: 'filevault', name: 'Desired encryption', payloadJson: '{"enabled":true}' }]);
    const assignmentWrites = []; page.on('request', outgoing => { const pathname = new URL(outgoing.url()).pathname; if (outgoing.method() === 'POST' && (pathname === assignmentBase || pathname.startsWith(assignmentBase + '/') && pathname.endsWith('/remove'))) assignmentWrites.push(outgoing); });
    const assignThroughUi = async (blueprint, screenshot = false) => {
      await page.goto(origin + '/company-blueprints'); await page.getByRole('button', { name: blueprint.name, exact: true }).click();
      await page.getByRole('button', { name: 'Version 1 ansehen', exact: true }).click(); await page.getByRole('button', { name: 'Mitarbeitenden zuweisen', exact: true }).click();
      await page.getByLabel('Blueprint-Mitarbeiter auswählen', { exact: true }).selectOption(employee.id);
      const loading = page.waitForResponse(response => new URL(response.url()).pathname === assignmentBase + '/preview' && response.request().method() === 'POST'); await page.getByRole('button', { name: 'Neue Zuweisung prüfen', exact: true }).click(); const loaded = await loading; assert.equal(loaded.status(), 200, await loaded.text()); const preview = await loaded.json();
      assert.equal(preview.userId, employee.id); assert.equal(preview.blueprintId, blueprint.id); assert.equal(preview.version, 1); assert.equal(preview.hasConflicts, false); if (preview.pools.length) assert.equal(preview.pools[0].additionalSeats, 0);
      await page.getByRole('region', { name: 'Blueprint-Zuweisungsvorschau', exact: true }).waitFor();
      if (screenshot) await page.screenshot({ path: '/tmp/od-business22-blueprint-assignment-preview.png', fullPage: true });
      await page.getByLabel('Begründung der Blueprint-Zuweisung', { exact: true }).fill('Actual browser confirms this immutable user blueprint and captured application versions');
      await page.getByRole('button', { name: 'Blueprint-Zuweisung vorbereiten', exact: true }).click(); const dialog = page.getByRole('alertdialog'); await dialog.getByLabel('Ich bestätige diese lokale Zuweisung.', { exact: true }).check();
      const applying = page.waitForResponse(response => new URL(response.url()).pathname === assignmentBase && response.request().method() === 'POST'); await dialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const applied = await applying; assert.equal(applied.status(), 201, await applied.text()); const receipt = await applied.json();
      assert.equal(receipt.actorUserId, registration.administratorId); assert.equal(receipt.tenantId, registration.tenantId); assert.equal(receipt.action, 'assigned'); assert.equal(receipt.deliveryStatus, 'pending');
      const original = applied.request(); assert.equal(original.headers().authorization, 'Bearer ' + token); assert.equal(original.postDataJSON().version, 1); assert.equal(original.postDataJSON().userId, employee.id); assert.equal(original.postDataJSON().id, receipt.assignmentId); assert.equal(original.headers()['idempotency-key'], receipt.operationId);
      await page.getByRole('heading', { name: 'Lokale Zuweisung bestätigt', exact: true }).waitFor();
      return receipt;
    };
    const firstBinding = await assignThroughUi(first, true); const secondBinding = await assignThroughUi(second); const zeroBinding = await assignThroughUi(zero);
    const fullSources = (await api(appV2 + '/pools/' + pool.id + '/assignments')).body; assert.equal(fullSources.total, 1); assert.equal(fullSources.assignments[0].sources.length, 3); assert.equal((await api('/api/licenses/company/pools/' + pool.id)).body.usedSeats, 1);
    assert.deepEqual(fullSources.assignments[0].sources.map(source => [source.sourceType, source.sourceId]).sort(), [['blueprint', firstBinding.assignmentId], ['blueprint', secondBinding.assignmentId], ['direct', 'direct']].sort());
    await page.goto(origin + '/applications'); await page.getByRole('button', { name: pool.name, exact: true }).click();
    const origins = page.getByRole('region', { name: 'Vollständige Lizenzquellen', exact: true });
    await origins.getByText('Manuell', { exact: true }).waitFor(); assert.equal(await origins.getByText('Blueprint-Version', { exact: true }).count(), 2);
    for (const proof of await origins.locator('details').all()) await proof.locator('summary').click();
    for (const source of fullSources.assignments[0].sources) assert.ok((await origins.innerText()).includes(source.grantId));
    await page.screenshot({ path: '/tmp/od-business22-license-origins.png', fullPage: true });
    await page.goto(origin + '/company-blueprints'); await page.getByRole('button', { name: first.name, exact: true }).click(); await page.getByRole('button', { name: 'Version 1 ansehen', exact: true }).click(); await page.getByRole('button', { name: 'Mitarbeitenden zuweisen', exact: true }).click();
    await page.getByLabel('Blueprint-Mitarbeiter auswählen', { exact: true }).selectOption(employee.id);
    const beforeRemovalRead = gatewayRequests.length; const writesBeforeRemovalRead = assignmentWrites.length;
    const readingBindings = page.waitForResponse(response => { const target = new URL(response.url()); return target.pathname === assignmentBase && target.searchParams.get('userId') === employee.id && response.request().method() === 'GET'; });
    const readingEffective = page.waitForResponse(response => new URL(response.url()).pathname === assignmentBase + '/users/' + employee.id + '/effective' && response.request().method() === 'GET');
    await page.getByRole('button', { name: 'Mitarbeiterzuweisungen laden', exact: true }).click();
    const bindingsResponse = await readingBindings; assert.equal(bindingsResponse.status(), 200, await bindingsResponse.text()); assert.equal((await bindingsResponse.json()).total, 3);
    const effectiveResponse = await readingEffective; assert.equal(effectiveResponse.status(), 200, await effectiveResponse.text()); assert.equal((await effectiveResponse.json()).assignments.length, 3);
    assert.equal(assignmentWrites.length, writesBeforeRemovalRead); assert.ok(gatewayRequests.slice(beforeRemovalRead).filter(request => request.path.startsWith(assignmentBase)).every(request => request.method === 'GET'));
    assert.deepEqual((await api(appV2 + '/pools/' + pool.id + '/assignments')).body, fullSources);
    await page.getByLabel('Begründung der Blueprint-Zuweisung', { exact: true }).fill('Remove only this blueprint origin while retaining manual and the other blueprint origin');
    await page.getByRole('region', { name: 'Gespeicherte Blueprint-Zuweisungen', exact: true }).getByRole('listitem').filter({ hasText: 'Blueprint ' + first.id + ' · Version 1 · Aktiv' }).getByRole('button', { name: 'Zuweisung entfernen', exact: true }).click(); const removingDialog = page.getByRole('alertdialog'); await removingDialog.getByLabel('Ich bestätige diese lokale Zuweisung.', { exact: true }).check();
    const removing = page.waitForResponse(response => new URL(response.url()).pathname === assignmentBase + '/' + firstBinding.assignmentId + '/remove' && response.request().method() === 'POST'); await removingDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const removed = await removing; assert.equal(removed.status(), 200, await removed.text()); const removal = await removed.json(); assert.equal(removal.pools[0].sourceRemoved, true); assert.equal(removal.pools[0].seatReleased, false); assert.equal(removal.pools[0].effectiveAssignmentRetained, true);
    assert.equal((await api(appV2 + '/pools/' + pool.id + '/assignments')).body.assignments[0].sources.length, 2); await page.getByRole('heading', { name: 'Lokale Rücknahme bestätigt', exact: true }).waitFor(); await page.screenshot({ path: '/tmp/od-business22-blueprint-removal.png', fullPage: true });
    await page.goto(origin + '/applications'); await page.getByRole('button', { name: 'Offboarding mit Blueprint-Rückgabe', exact: true }).click();
    await page.getByLabel('Blueprint-Offboarding Mitarbeiter-ID', { exact: true }).fill(employee.id); const checking = page.waitForResponse(response => new URL(response.url()).pathname === appV2 + '/users/' + employee.id + '/offboarding-preview'); await page.getByRole('button', { name: 'Blueprint-Offboarding-Vorschau laden', exact: true }).click(); const checked = await checking; assert.equal(checked.status(), 200, await checked.text()); const preview = await checked.json(); assert.equal(preview.licenseCount, 1); assert.equal(preview.bindingCount, 2);
    await page.getByLabel('Begründung des Blueprint-Offboardings', { exact: true }).fill('Actual browser confirms the original account disable and every license origin plus zero-app binding'); await page.getByRole('button', { name: 'Blueprint-Offboarding starten', exact: true }).click();
    const offboardingDialog = page.getByRole('alertdialog'); await offboardingDialog.getByLabel('Ich bestätige diesen Blueprint-Offboarding-Schritt.', { exact: true }).check(); const offboardingRequest = page.waitForResponse(response => new URL(response.url()).pathname === appV2 + '/offboarding-workflows' && response.request().method() === 'POST'); await offboardingDialog.getByRole('button', { name: 'Bestätigen', exact: true }).click(); const offboarded = await offboardingRequest; assert.equal(offboarded.status(), 201, await offboarded.text()); const result = await offboarded.json();
    assert.equal(result.workflow.phase, 'completed_local'); assert.equal(result.workflow.totalLicenses, 1); assert.equal(result.workflow.completedLicenses, 1); assert.equal(result.workflow.totalBindings, 2); assert.equal(result.workflow.completedBindings, 2); assert.equal(result.workflow.checkpoint.action, 'disabled'); assert.equal(Object.keys(result.workflow.checkpoint).length, 13); assert.equal(result.currentTarget.enabled, false);
    await page.getByRole('article', { name: 'Blueprint-Offboarding-Arbeitsstand', exact: true }).waitFor(); await page.screenshot({ path: '/tmp/od-business22-negative-offboarding.png', fullPage: true });
    assert.equal((await api(appV2 + '/pools/' + pool.id + '/assignments')).body.total, 0); assert.equal((await api('/api/licenses/company/pools/' + pool.id)).body.usedSeats, 0);
    const bindings = (await policyDb.query('SELECT id,status FROM company_blueprint_user_assignments WHERE user_id=$1 ORDER BY id', [employee.id])).rows; assert.equal(bindings.length, 3); assert.ok(bindings.every(binding => binding.status === 'removed')); assert.ok(bindings.some(binding => binding.id === zeroBinding.assignmentId));
    const originalNegative = (await identityDb.query('SELECT receipt.*,outbox.status FROM identity_company_offboarding_receipts receipt JOIN identity_company_offboarding_outbox outbox USING(tenant_id,workflow_id) WHERE receipt.workflow_id=$1', [result.workflow.id])).rows; assert.equal(originalNegative.length, 1); assert.equal(originalNegative[0].operation_id, result.workflow.checkpoint.operationId); assert.equal(originalNegative[0].status, 'pending'); assert.equal(originalNegative[0].source.subject, claims.sub);
    assert.equal(assignmentWrites.length, 4); assert.ok(gatewayRequests.filter(request => request.path.startsWith(assignmentBase)).length >= 10); assert.ok(gatewayRequests.filter(request => request.path.startsWith(assignmentBase)).every(request => request.authorization === 'Bearer ' + token && request.status < 400));
    assert.equal((await identityDb.query('SELECT count(*)::integer AS count FROM identity_role_assignments WHERE user_id=$1', [registration.administratorId])).rows[0].count, 0); assert.ok(Date.now() - startedAt < 240000);
    for (const table of ['mdm_commands', 'policy_device_operations']) assert.equal((await issuerDb.query('SELECT count(*)::integer AS count FROM ' + table)).rows[0].count, 0);
    process.stdout.write('Slice22 actual Chrome: independently registered roleless Owner with original fresh BFF bearer through production gateway; actual UI pinned assignments A+B plus manual consume one seat; full origin display; source-only A removal; original045 negative workflow retires all remaining origins and zero-app binding; no MDM claim.\n');
  } finally {
    await isolated.close();
    if (productionGateway) { const closed = once(productionGateway.server, 'close'); productionGateway.stop(); productionGateway.server.closeAllConnections(); await closed; }
    if (GatewayModule) await GatewayModule.closeDatabase();
    for (const [name, value] of Object.entries(savedEnvironment)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  }
});

test('real company automation Owner UI grants an actual app worker, downloads its own export and revokes queued work', { timeout: 240000 }, async () => {
  const ownerUsername = 'company-automation-owner';
  const company = await require('../../../../../scripts/lib/company-owner-fixture.cjs').activeCompany(identityDb, identitySchema, logicalIssuer,
    { subject: ownerUsername + '-subject', username: ownerUsername });
  const adminContext = await context(); const ownerContext = await context(); const adminPage = await adminContext.newPage(); const page = await ownerContext.newPage();
  try {
    await login(adminPage, 'organization-console-admin');
    const admin = await mediated(adminPage); assert.equal(admin.status, 200);
    const created = await fetch(issuerBase + '/api/clients', { method: 'POST', headers: { Authorization: 'Bearer ' + admin.body.access_token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Actual browser automation app', publicClient: false, enabled: true, redirectUris: [], grantTypes: ['client_credentials'], scopes: ['company.automation'] }) });
    assert.equal(created.status, 201, await created.clone().text()); const client = await created.json();
    const execute = require('node:util').promisify(require('node:child_process').execFile);
    const cli = async args => execute(process.execPath, [path.resolve(__dirname, '../../../../../scripts/od.mjs'), ...args], { env: { ...process.env,
      OPENDIRECTORY_ISSUER: issuerBase, OPENDIRECTORY_API_URL: identityBase, OPENDIRECTORY_CLIENT_ID: client.clientId, OPENDIRECTORY_CLIENT_SECRET: client.clientSecret,
      OPENDIRECTORY_SCOPES: 'company.automation', OPENDIRECTORY_ADMIN_ACCESS_TOKEN: '' } });
    const enrolled = JSON.parse((await cli(['automation', 'enroll', 'Actual browser export worker'])).stdout);
    assert.equal(enrolled.clientId, client.clientId); assert.equal(enrolled.clientRevision, client.version);
    await reviewFirstFactor(page, ownerUsername); await login(page, ownerUsername); const owner = await mediated(page); assert.equal(owner.status, 200);
    const claims = JSON.parse(Buffer.from(owner.body.access_token.split('.')[1], 'base64url')); assert.deepEqual(claims.roles, []); assert.equal(claims.identity_authorization.userId, company.receipt.administratorId);
    await page.setViewportSize({ width: 1440, height: 1100 }); await page.goto(origin + '/automation'); await page.getByRole('heading', { name: 'Automationen', exact: true }).waitFor();
    await page.getByLabel('App-Anmeldungs-ID', { exact: true }).fill(enrolled.id); await page.getByRole('button', { name: 'App-Anmeldung prüfen', exact: true }).click();
    await page.getByText('Von der App angegebener Name: Actual browser export worker', { exact: true }).waitFor();
    await page.getByLabel('Benutzer exportieren', { exact: true }).check(); await page.getByLabel('Freigabe-Laufzeit in Stunden', { exact: true }).fill('1');
    await page.getByLabel('Automationsfreigabe begründen', { exact: true }).fill('Actual roleless owner approves only its own user export for this exact app generation');
    await page.getByRole('button', { name: 'Ausgewählte App-Rechte bestätigen', exact: true }).click();
    const approvalDialog = page.getByRole('dialog', { name: 'App-Datenzugriff bestätigen', exact: true }); await approvalDialog.getByText(new RegExp(client.clientId)).waitFor();
    const approving = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/grants' && response.request().method() === 'POST');
    await approvalDialog.getByRole('button', { name: 'Verbindlich bestätigen', exact: true }).click(); const approved = await approving; assert.equal(approved.status(), 201, await approved.text());
    const permission = (await approved.json()).grant; assert.equal(permission.tenantId, company.receipt.tenantId); assert.deepEqual(permission.actions, ['directory.users.export']);
    await page.getByLabel('Automationsfreigabe auswählen', { exact: true }).selectOption(permission.id);
    await page.getByLabel('Automationsaktion', { exact: true }).selectOption('directory.users.export'); await page.getByLabel('Exportformat', { exact: true }).selectOption('csv');
    const queueing = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/jobs' && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Exportjob einreihen', exact: true }).click(); const queued = await queueing; assert.equal(queued.status(), 201); const firstJob = (await queued.json()).job;
    const worker = await cli(['automation', 'worker', permission.id, '--once']); const workerLines = worker.stdout.trim().split('\n').map(line => JSON.parse(line));
    assert.equal(workerLines[0].job.id, firstJob.id); assert.equal(workerLines[0].job.status, 'succeeded'); assert.equal(workerLines[0].principal.kind, 'application'); assert.equal(workerLines[0].principal.clientId, client.clientId);
    await page.getByRole('button', { name: 'Automationen neu laden', exact: true }).click();
    const downloading = page.waitForEvent('download'); await page.getByRole('button', { name: 'Export herunterladen (1 Zeilen)', exact: true }).click();
    const downloaded = await downloading; const file = path.join(directory, 'actual-company-automation.csv'); await downloaded.saveAs(file); const csv = fs.readFileSync(file, 'utf8');
    assert.ok(csv.includes(company.receipt.administratorId)); assert.ok(csv.includes(ownerUsername)); assert.equal(csv.includes(actors.get('organization-console-admin').userId), false);
    await page.screenshot({ path: '/tmp/od-company-automation-export.png', fullPage: true });
    await page.getByRole('button', { name: 'Job-Historie', exact: true }).click(); await page.getByRole('complementary', { name: 'Job-Historie', exact: true }).getByText(new RegExp(client.clientId)).first().waitFor();
    await page.getByLabel('Automationsaktion', { exact: true }).selectOption('directory.users.export');
    const queueingAgain = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/jobs' && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Exportjob einreihen', exact: true }).click(); const secondJob = (await (await queueingAgain).json()).job;
    await page.getByRole('button', { name: 'App-Freigabe widerrufen', exact: true }).click();
    const revoking = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/grants/' + permission.id + '/revoke');
    await page.getByRole('dialog', { name: 'App-Freigabe widerrufen', exact: true }).getByRole('button', { name: 'Verbindlich bestätigen', exact: true }).click();
    const revoked = await revoking; assert.equal(revoked.status(), 200); assert.equal((await revoked.json()).grant.status, 'revoked');
    await assert.rejects(cli(['automation', 'worker', permission.id, '--once']), error => error.code === 1);
    const records = (await identityDb.query('SELECT id,status FROM identity_automation_jobs WHERE grant_id=$1 ORDER BY id', [permission.id])).rows;
    assert.equal(records.find(row => row.id === firstJob.id).status, 'succeeded'); assert.equal(records.find(row => row.id === secondJob.id).status, 'cancelled');
    await page.getByText('App-Freigabe widerrufen.', { exact: true }).waitFor();
    await page.getByText('Benutzer exportieren · Abgebrochen · Versuch 0/5', { exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/od-company-automation-browser.png', fullPage: true });
  } finally { await adminContext.close(); await ownerContext.close(); }
});

test('real scheduled app worker assigns and returns a group license through OAuth, Identity, Policy and the Owner UI', { timeout: 360000 }, async () => {
  const ownerUsername = 'company-license-automation-owner';
  const company = await require('../../../../../scripts/lib/company-owner-fixture.cjs').activeCompany(identityDb, identitySchema, logicalIssuer,
    { subject: ownerUsername + '-subject', username: ownerUsername });
  const adminContext = await context(); const ownerContext = await context(); const adminPage = await adminContext.newPage(); const page = await ownerContext.newPage();
  let worker; let workerOutput = ''; let workerErrors = ''; const receiverRejections = []; const originalFetch = global.fetch;
  global.fetch = async (...args) => {
    const response = await originalFetch(...args); const pathname = new URL(String(args[0])).pathname;
    if (!response.ok && ['/api/licenses/automation/groups/step', '/api/identity/automation/license-source'].includes(pathname)) receiverRejections.push({ pathname, status: response.status, error: (await response.clone().json()).error });
    return response;
  };
  try {
    await login(adminPage, 'organization-console-admin'); const admin = await mediated(adminPage); assert.equal(admin.status, 200);
    const created = await fetch(issuerBase + '/api/clients', { method: 'POST', headers: { Authorization: 'Bearer ' + admin.body.access_token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Actual browser license app', publicClient: false, enabled: true, redirectUris: [], grantTypes: ['client_credentials'], scopes: ['company.automation'] }) });
    assert.equal(created.status, 201, await created.clone().text()); const client = await created.json();
    const environment = { ...process.env, OPENDIRECTORY_ISSUER: issuerBase, OPENDIRECTORY_API_URL: identityBase,
      OPENDIRECTORY_CLIENT_ID: client.clientId, OPENDIRECTORY_CLIENT_SECRET: client.clientSecret, OPENDIRECTORY_SCOPES: 'company.automation', OPENDIRECTORY_ADMIN_ACCESS_TOKEN: '' };
    const cliPath = path.resolve(__dirname, '../../../../../scripts/od.mjs');
    const execute = require('node:util').promisify(require('node:child_process').execFile);
    const enrolled = JSON.parse((await execute(process.execPath, [cliPath, 'automation', 'enroll', 'Actual scheduled license worker'], { env: environment })).stdout);
    await reviewFirstFactor(page, ownerUsername); await login(page, ownerUsername); const owner = await mediated(page); assert.equal(owner.status, 200);
    const claims = JSON.parse(Buffer.from(owner.body.access_token.split('.')[1], 'base64url')); assert.deepEqual(claims.roles, []);
    const request = async (url, method, body, headers = {}, status = 200) => {
      const response = await fetch(url, { method, headers: { Authorization: 'Bearer ' + owner.body.access_token, 'Content-Type': 'application/json', ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
      assert.equal(response.status, status, await response.clone().text()); return { value: await response.json(), etag: response.headers.get('etag') };
    };
    let group = await request(identityBase + '/api/groups', 'POST', { name: 'Actual scheduled license group' }, {}, 201);
    group = await request(identityBase + '/api/groups/' + group.value.id + '/members', 'POST', { userId: company.receipt.administratorId }, { 'If-Match': group.etag });
    const product = await request(policyBase + '/api/licenses/company/pools', 'POST', { name: 'Actual app-managed pool', vendor: 'Local browser fixture', description: '', totalSeats: 1, reason: 'Create one real local seat for scheduled app reconciliation' }, {}, 201);
    const linked = await request(policyBase + '/api/licenses/company/groups', 'POST', { groupId: group.value.id, poolId: product.value.id, reason: 'Link actual own group to the finite local pool', confirm: true }, { 'Idempotency-Key': randomUUID() }, 201);
    const rule = linked.value.rule;
    await page.setViewportSize({ width: 1440, height: 1100 }); await page.goto(origin + '/automation?licenseRule=' + rule.id);
    await page.getByRole('heading', { name: 'Automationen', exact: true }).waitFor();
    await page.getByLabel('App-Anmeldungs-ID', { exact: true }).fill(enrolled.id); await page.getByRole('button', { name: 'App-Anmeldung prüfen', exact: true }).click();
    await page.getByLabel('Gruppenlizenzen zuweisen und entziehen', { exact: true }).check();
    await page.getByLabel('Freigabe-Laufzeit in Stunden', { exact: true }).fill('1');
    await page.getByLabel('Automationsfreigabe begründen', { exact: true }).fill('Owner explicitly approves actual unattended assignment and return of local group license seats');
    await page.getByRole('button', { name: 'Ausgewählte App-Rechte bestätigen', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'App-Datenzugriff bestätigen', exact: true }); await dialog.getByText(/Lizenzsitze/).waitFor();
    const approving = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/grants' && response.request().method() === 'POST');
    await dialog.getByRole('button', { name: 'Verbindlich bestätigen', exact: true }).click(); const approved = await approving;
    assert.equal(approved.status(), 201, await approved.text()); const permission = (await approved.json()).grant; assert.deepEqual(permission.actions, ['licenses.groups.reconcile']);
    await page.getByLabel('Automationsfreigabe auswählen', { exact: true }).selectOption(permission.id);
    await page.getByLabel('Automationsaktion', { exact: true }).selectOption('licenses.groups.reconcile');
    assert.equal(await page.getByLabel('Lizenzgruppen-Verknüpfungs-ID', { exact: true }).inputValue(), rule.id);
    await page.getByRole('button', { name: 'Lizenzgruppe prüfen', exact: true }).click(); await page.getByText(/Gruppe: Actual scheduled license group/).waitFor();
    const scheduling = page.waitForResponse(response => new URL(response.url()).pathname === '/api/identity/automation/schedules' && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Zeitplan erstellen', exact: true }).click(); const scheduled = await scheduling;
    assert.equal(scheduled.status(), 201, await scheduled.text()); const schedule = (await scheduled.json()).schedule; assert.equal(schedule.ruleId, rule.id); assert.equal(schedule.intervalSeconds, 60);
    worker = spawn(process.execPath, [cliPath, 'automation', 'worker', permission.id], { env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
    worker.stdout.on('data', chunk => { workerOutput += chunk; }); worker.stderr.on('data', chunk => { workerErrors += chunk; });
    const completedJob = async afterId => {
      const deadline = Date.now() + 100000;
      while (Date.now() < deadline) {
        assert.equal(worker.exitCode, null, 'Worker stopped: ' + workerErrors);
        const rows = (await identityDb.query('SELECT * FROM identity_automation_jobs WHERE schedule_id=$1 ORDER BY created_at', [schedule.id])).rows;
        const current = rows.find(row => row.id !== afterId);
        if (current && ['succeeded', 'partial', 'failed', 'retry_wait'].includes(current.status)) { assert.equal(current.status, 'succeeded', JSON.stringify({ status: current.status, errorCode: current.error_code, progress: current.progress, receiverRejections })); return current; }
        await new Promise(resolve => setTimeout(resolve, 250));
      }
      assert.fail('Actual scheduled license job did not complete: ' + workerErrors);
    };
    const first = await completedJob(); assert.equal(first.progress.completed, 1); assert.equal(first.progress.blocked, 0);
    assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1', [product.value.id])).rows[0].used_seats, 1);
    await page.getByRole('button', { name: 'Automationen neu laden', exact: true }).click(); await page.getByRole('button', { name: 'Lizenzbericht anzeigen', exact: true }).click();
    const report = page.getByRole('complementary', { name: 'Geprüfter Lizenzbericht', exact: true }); await report.getByText(new RegExp(client.clientId)).waitFor();
    await report.getByText(company.receipt.administratorId + ' · Zugewiesen', { exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/od-company-license-automation-assigned.png', fullPage: true });
    group = await request(identityBase + '/api/groups/' + group.value.id + '/members/' + company.receipt.administratorId, 'DELETE', undefined, { 'If-Match': group.etag });
    // Wait for the real 60-second schedule; do not modify its persisted clock or impersonate an owner on the worker.
    const second = await completedJob(first.id); assert.equal(second.progress.completed, 1);
    assert.equal((await policyDb.query('SELECT used_seats FROM license_catalog WHERE id=$1', [product.value.id])).rows[0].used_seats, 0);
    assert.equal(JSON.parse(second.artifact_content).results[0].status, 'removed');
    await page.getByRole('button', { name: 'Automationen neu laden', exact: true }).click();
    const jobCard = page.locator('article').filter({ hasText: second.id }); await jobCard.getByRole('button', { name: 'Lizenzbericht anzeigen', exact: true }).click();
    await report.getByText(company.receipt.administratorId + ' · Gruppenquelle nicht mehr zugewiesen', { exact: true }).waitFor();
    await page.screenshot({ path: '/tmp/od-company-license-automation-returned.png', fullPage: true });
    await page.getByRole('button', { name: 'Zeitplan stoppen', exact: true }).click(); await page.getByText('Zeitplan gestoppt; bereits erstellte Jobs separat beachten.', { exact: true }).waitFor();
    assert.equal((await identityDb.query('SELECT enabled FROM identity_automation_schedules WHERE id=$1', [schedule.id])).rows[0].enabled, false);
    const lines = workerOutput.trim().split('\n').map(line => JSON.parse(line)); assert.ok(lines.length >= 2);
    for (const line of lines) { assert.equal(line.principal.kind, 'application'); assert.equal(line.principal.clientId, client.clientId); assert.equal(Object.hasOwn(line.principal, 'userId'), false); }
    assert.equal(workerOutput.includes(client.clientSecret), false); assert.equal(workerOutput.includes(owner.body.access_token), false);
  } finally { global.fetch = originalFetch; await stop(worker); await adminContext.close(); await ownerContext.close(); }
});
