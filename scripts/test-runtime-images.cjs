'use strict';

const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { readJson } = require('./lib/runtime-image-http.cjs');

const root = path.resolve(__dirname, '..');
const project = 'od-runtime-test-' + randomBytes(5).toString('hex');
const containers = [];
const images = [project + '-app-store', project + '-kerberos-kdc'];
const network = project + '-network';
const postgres = project + '-postgres';
const databasePassword = randomBytes(24).toString('hex');
const masterPassword = randomBytes(24).toString('hex');
const adminPassword = randomBytes(24).toString('hex');
const children = new Set();
let interrupted = false;
let finished = false;
process.once('beforeExit', () => {
  if (!finished) { console.error('Runtime image checks did not finish'); process.exitCode = 1; }
});

for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  interrupted = true;
  for (const child of children) child.kill('SIGTERM');
});

function docker(args, { input, env = process.env, echo = false } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { cwd: root, env, stdio: ['pipe', 'pipe', 'pipe'] });
    children.add(child);
    let output = ''; let errors = '';
    child.stdout.on('data', chunk => { output += chunk; if (echo) process.stdout.write(chunk); });
    child.stderr.on('data', chunk => { errors += chunk; if (echo) process.stderr.write(chunk); });
    child.once('error', reject);
    child.once('exit', code => {
      children.delete(child);
      if (code === 0) resolve(output.trim());
      else reject(new Error('Docker ' + args[0] + ' failed: ' + errors.slice(-3000)));
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

async function until(label, operation) {
  const deadline = Date.now() + 60000;
  let lastError;
  while (Date.now() < deadline && !interrupted) {
    try { const result = await operation(); if (result) return result; }
    catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error(label + ' unavailable: ' + (lastError?.message || 'startup timeout'));
}

async function create(name, args, image) {
  containers.push(name);
  await docker(['run', '-d', '--name', name, '--label', 'opendirectory.test=runtime-images', '--network', network, ...args, image]);
}

async function address(name, port) {
  const state = JSON.parse(await docker(['inspect', name]))[0];
  return 'http://127.0.0.1:' + state.NetworkSettings.Ports[port + '/tcp'][0].HostPort;
}

async function healthy(base, check) {
  return until(base + '/health', async () => {
    const response = await readJson(base + '/health');
    if (!response.ok) return false;
    const body = response.body;
    return check(body) && body;
  });
}

async function main() {
  const env = { ...process.env, COMPOSE_PROJECT_NAME: project };
  for (const key of ['DB_PASSWORD', 'POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'MONGO_PASSWORD', 'RABBITMQ_PASSWORD', 'LLDAP_ADMIN_PASSWORD', 'LLDAP_JWT_SECRET', 'JWT_SECRET', 'GRAFANA_PASSWORD', 'ADMIN_PASSWORD']) env[key] = 'disposable_build_only';
  try {
    await docker(['compose', '--env-file', '/dev/null', '-f', 'docker-compose.yml', '--profile', '*', 'build', 'app-store', 'kerberos-kdc'], { env, echo: true });
    await docker(['network', 'create', '--label', 'opendirectory.test=runtime-images', network]);
    await create(postgres, ['--network-alias', 'database', '--tmpfs', '/var/lib/postgresql/data', '-e', 'POSTGRES_USER=runtime_test', '-e', 'POSTGRES_DB=postgres', '-e', 'POSTGRES_PASSWORD=' + databasePassword, '-e', 'POSTGRES_HOST_AUTH_METHOD=scram-sha-256'], 'postgres:16');
    await until('Disposable PostgreSQL', () => docker(['exec', postgres, 'pg_isready', '-h', '127.0.0.1', '-U', 'runtime_test', '-d', 'postgres']).then(() => true));
    for (const db of ['app_store', 'kerberos']) await docker(['exec', postgres, 'createdb', '-U', 'runtime_test', db]);
    const database = ['-e', 'DB_HOST=database', '-e', 'DB_USER=runtime_test', '-e', 'DB_PASSWORD=' + databasePassword];
    const oidc = ['-e', 'OIDC_ISSUER=https://runtime-test.invalid', '-e', 'OIDC_AUDIENCE=runtime-test', '-e', 'JWKS_URI=http://127.0.0.1:1/unavailable'];
    const appstore = project + '-appstore'; const kerberos = project + '-kerberos';
    await create(appstore, ['-p', '127.0.0.1::3906', ...database, ...oidc, '-e', 'DB_NAME=app_store'], images[0]);
    console.log('Checking App Store startup, authorization and package storage');
    const storeAddress = await address(appstore, 3906);
    await healthy(storeAddress, body => body.status === 'healthy');
    assert.equal((await readJson(storeAddress + '/api/store/catalog')).status, 401);
    const uid = await docker(['exec', appstore, 'node', '-p', 'process.getuid()']);
    assert.notEqual(uid, '0');
    await docker(['exec', appstore, 'node', '-e', "const fs=require('fs');fs.writeFileSync('/data/packages/.runtime-test','own image storage');fs.unlinkSync('/data/packages/.runtime-test')"]);
    const grpc = await docker(['exec', appstore, 'node', '-p', "require('/packages/grpc-event-bus/node_modules/@grpc/grpc-js/package.json').version"]);
    const [major, minor, patch] = grpc.split('.').map(Number);
    assert.ok(major === 1 && (minor > 14 || minor === 14 && patch >= 7));
    console.log('Checking Kerberos startup, PostgreSQL and native tickets');
    await create(kerberos, ['-p', '127.0.0.1::3013', '--tmpfs', '/var/lib/krb5kdc', ...database, ...oidc, '-e', 'DB_NAME=kerberos', '-e', 'KRB5_REALM=CI.TEST', '-e', 'KDC_HOST=localhost', '-e', 'KRB5_DB_PASSWORD=' + masterPassword, '-e', 'KRB5_ADMIN_PASSWORD=' + adminPassword], images[1]);
    const kdcAddress = await address(kerberos, 3013);
    await healthy(kdcAddress, body => body.status === 'ok' && body.db === 'connected');
    assert.equal((await readJson(kdcAddress + '/api/kerberos/principals')).status, 401);
    assert.equal(await docker(['exec', kerberos, 'cat', '/proc/1/comm']), 'node');
    assert.match(await docker(['exec', kerberos, 'node', '--version']), /^v20\./);
    await docker(['exec', '-i', kerberos, 'kinit', '-c', '/tmp/runtime-test.ccache', 'admin/admin@CI.TEST'], { input: adminPassword + '\n' });
    const tickets = await docker(['exec', kerberos, 'klist', '-c', '/tmp/runtime-test.ccache']);
    assert.match(tickets, /admin\/admin@CI\.TEST/);
    assert.match(tickets, /krbtgt\/CI\.TEST@CI\.TEST/);
    console.log(JSON.stringify({ appStore: { healthy: true, nonRootUid: uid, writablePackageStorage: true, grpc, anonymousCatalog: 401 }, kerberos: { healthy: true, database: 'connected', foregroundApi: true, nativeTicket: true, anonymousPrincipals: 401 } }, null, 2));
  } catch (error) {
    for (const name of containers) {
      console.error(name + ':');
      await docker(['logs', '--tail', '30', name], { echo: true }).catch(() => {});
    }
    throw error;
  } finally {
    for (const name of containers.reverse()) await docker(['rm', '-f', name]).catch(() => {});
    await docker(['network', 'rm', network]).catch(() => {});
    for (const name of images) await docker(['image', 'rm', name]).catch(() => {});
  }
}

main().then(() => { finished = true; }).catch(error => { finished = true; console.error(error.message); process.exitCode = 1; });
