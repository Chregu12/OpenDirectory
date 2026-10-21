'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { Pool } = require('pg');
const { MfaAuthority, totp } = require('../MfaAuthority');
const { MfaRecovery } = require('../MfaRecovery');
const { MfaEnrollment } = require('../MfaEnrollment');
const { ClientRegistry, etag } = require('../ClientRegistry');
const { nextOtp, rememberFactor } = require('./fixtures/mfa.cjs');
const { generate } = require('../../scripts/mfa-key');
const actor = () => ({ sid: randomUUID(), actor_type: 'user', identity_authorization: { userId: randomUUID(), revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) } });
const claims = (payload, context) => ({ ...payload, auth_time: context.authTime, amr: context.methods, mfa_authorization: context });

async function authority(operation) {
  const schema = 'oauth_mfa_' + randomUUID().replaceAll('-', '');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'od-mfa-pg-')); const keyFile = path.join(directory, 'mfa.key'); generate(keyFile);
  const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 }); let pool;
  try {
    await administration.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.OAUTH_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public`);
    pool = new Pool({ connectionString: url.toString(), max: 5 });
    const migrate = async () => {
      const migrations = path.join(__dirname, '../../migrations');
      for (const filename of fs.readdirSync(migrations).filter(filename => filename.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(migrations, filename), 'utf8'));
    };
    await migrate(); const database = { pool, isAvailable: () => true, query: (...args) => pool.query(...args) };
    const create = (file = keyFile) => new MfaAuthority(database, { keyFile: file, demo: false, production: true });
    const payload = actor(); const identity = { state: async () => ({ context: structuredClone(payload.identity_authorization) }) };
    const recovery = () => new MfaRecovery({ mfa: create(), identity, issuer: 'https://mfa-recovery.test' });
    await operation({ service: create(), create, pool, directory, keyFile, migrate, payload, identity, recovery, database });
  } finally {
    if (pool) await pool.end();
    await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end(); fs.rmSync(directory, { recursive: true, force: true });
  }
}
async function enable(service, payload) {
  const setup = await service.enroll(payload); const counter = Math.floor(Date.now() / 30000) - 1;
  await service.confirm(payload, totp(setup.secret, counter)); return { setup, counter };
}

test('persistent federated evidence needs an independent local OTP and survives another verifier instance', () => authority(async ({ service, create, payload }) => {
  const userId = payload.identity_authorization.userId;
  const weak = claims(payload, await service.login(userId, undefined, 'federated'));
  assert.deepEqual(weak.amr, ['federated']);
  assert.equal(await create().matches(weak), true);
  const { setup, counter } = await enable(service, payload);
  assert.equal(await create().matches(weak), false);
  await assert.rejects(create().login(userId, undefined, 'federated'), { code: 'otp_required' });
  const context = await create().login(userId, totp(setup.secret, counter + 1), 'federated');
  assert.deepEqual(context.methods, ['federated', 'otp']);
  assert.equal(await create().matches(claims(payload, context)), true);
  await assert.rejects(create().login(userId, totp(setup.secret, counter + 1), 'federated'), { code: 'invalid_otp' });
}));

test('persistent MFA evidence and anti-replay counters survive independent instances and migration reapplication', () => authority(async ({ service, create, migrate, payload }) => {
  const weaker = claims(payload, await service.login(payload.identity_authorization.userId)); const { setup, counter } = await enable(service, payload);
  assert.equal(await create().matches(weaker), false);
  const proof = claims(payload, await create().login(payload.identity_authorization.userId, totp(setup.secret, counter + 1)));
  await migrate(); assert.equal(await create().matches(proof), true);
  await assert.rejects(create().login(payload.identity_authorization.userId, totp(setup.secret, counter + 1)), { code: 'invalid_otp' });
}));
test('two persistent verifier instances cannot consume the same second factor concurrently', () => authority(async ({ service, create, payload }) => {
  const { setup, counter } = await enable(service, payload);
  const results = await Promise.allSettled([service.login(payload.identity_authorization.userId, totp(setup.secret, counter + 1)), create().login(payload.identity_authorization.userId, totp(setup.secret, counter + 1))]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(results.filter(result => result.status === 'rejected' && result.reason.code === 'invalid_otp').length, 1);
}));
test('no plaintext seed, password, recovery code or unverified claim is persisted in MFA evidence', () => authority(async ({ service, pool, payload }) => {
  const { setup } = await enable(service, payload); const userId = payload.identity_authorization.userId;
  const stored = (await pool.query('SELECT * FROM oauth_mfa_factors WHERE user_id=$1', [userId])).rows[0];
  assert.equal(stored.pending_seed, null); assert.equal(JSON.stringify(stored).includes(setup.secret), false);
  const events = (await pool.query('SELECT * FROM oauth_mfa_audit WHERE user_id=$1 ORDER BY created_at', [userId])).rows;
  assert.deepEqual(events.map(event => event.action), ['setup_started', 'enabled']); assert.equal(JSON.stringify(events).includes(setup.secret), false);
  assert.equal(events[1].session_id, payload.sid);
}));
test('audit-storage failure rolls back enabling, counter consumption and any claimed success', () => authority(async ({ service, pool, payload }) => {
  const setup = await service.enroll(payload); const counter = Math.floor(Date.now() / 30000);
  await pool.query('ALTER TABLE oauth_mfa_audit RENAME TO unavailable_mfa_audit');
  try { await assert.rejects(service.confirm(payload, totp(setup.secret, counter)), { status: 503 }); }
  finally { await pool.query('ALTER TABLE unavailable_mfa_audit RENAME TO oauth_mfa_audit'); }
  const row = (await pool.query('SELECT * FROM oauth_mfa_factors WHERE user_id=$1', [payload.identity_authorization.userId])).rows[0];
  assert.equal(row.enabled, false); assert.equal(row.revision, '0'); assert.equal(row.last_counter, '-1');
  assert.equal((await service.confirm(payload, totp(setup.secret, counter))).enabled, true);
}));
test('disabled and re-enrolled incarnations never resurrect weaker or previously verified sessions', () => authority(async ({ service, create, pool, payload }) => {
  const weaker = claims(payload, await service.login(payload.identity_authorization.userId)); const { setup, counter } = await enable(service, payload);
  const stronger = claims(payload, await service.login(payload.identity_authorization.userId, totp(setup.secret, counter + 1)));
  await service.disable(payload, totp(setup.secret, counter + 2));
  assert.equal(await create().matches(weaker), false); assert.equal(await create().matches(stronger), false);
  await enable(create(), payload); assert.equal(await create().matches(weaker), false); assert.equal(await create().matches(stronger), false);
  assert.equal((await pool.query('SELECT revision FROM oauth_mfa_factors WHERE user_id=$1', [payload.identity_authorization.userId])).rows[0].revision, '3');
}));
test('persisted failure throttling cannot be bypassed by another instance or another setup attempt', () => authority(async ({ service, create, payload }) => {
  const setup = await service.enroll(payload); const current = Math.floor(Date.now() / 30000); let wrong = '000000';
  while ([current - 1, current, current + 1].some(counter => totp(setup.secret, counter) === wrong)) wrong = String(Number(wrong) + 1).padStart(6, '0');
  for (let attempt = 0; attempt < 5; attempt++) await assert.rejects(create().confirm(payload, wrong), { code: 'invalid_otp' });
  await assert.rejects(create().confirm(payload, totp(setup.secret, current)), { code: 'mfa_temporarily_locked' });
  await assert.rejects(create().enroll(payload), { code: 'mfa_temporarily_locked' });
}));
test('missing or changed encryption authority fails closed for login and existing assurance', () => authority(async ({ service, create, directory, payload }) => {
  const { setup, counter } = await enable(service, payload);
  const proof = claims(payload, await service.login(payload.identity_authorization.userId, totp(setup.secret, counter + 1)));
  const otherFile = path.join(directory, 'wrong.key'); generate(otherFile);
  await assert.rejects(create(otherFile).matches(proof), { status: 503 }); await assert.rejects(create(otherFile).login(payload.identity_authorization.userId, totp(setup.secret, counter + 2)), { status: 503 });
  assert.equal(await create().matches(proof), true);
}));
test('database guards preserve factor incarnations and immutable audit evidence', () => authority(async ({ service, pool, payload }) => {
  const { setup, counter } = await enable(service, payload); const userId = payload.identity_authorization.userId;
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_factors WHERE user_id=$1', [userId]));
  await assert.rejects(pool.query('UPDATE oauth_mfa_factors SET revision=0 WHERE user_id=$1', [userId]));
  await assert.rejects(pool.query('UPDATE oauth_mfa_factors SET encrypted_seed=$2 WHERE user_id=$1', [userId, service.cipher.encrypt(userId, 'active', setup.secret)]));
  await assert.rejects(pool.query("UPDATE oauth_mfa_audit SET action='disabled' WHERE user_id=$1", [userId]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_audit WHERE user_id=$1', [userId]));
  await service.login(userId, totp(setup.secret, counter + 1));
  await assert.rejects(pool.query('UPDATE oauth_mfa_factors SET last_counter=-1 WHERE user_id=$1', [userId]));
}));
test('pending factor ownership, timeout and encrypted purpose are enforced against persistent state', () => authority(async ({ service, create, pool, payload }) => {
  const setup = await service.enroll(payload); const code = totp(setup.secret, Math.floor(Date.now() / 30000));
  await assert.rejects(create().confirm({ ...payload, sid: randomUUID() }, code), { code: 'mfa_setup_not_pending' });
  await pool.query("UPDATE oauth_mfa_factors SET pending_expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1", [payload.identity_authorization.userId]);
  await assert.rejects(create().confirm(payload, code), { code: 'mfa_setup_not_pending' });
  await service.enroll(payload);
  await pool.query('UPDATE oauth_mfa_factors SET pending_seed=$2 WHERE user_id=$1', [payload.identity_authorization.userId, service.cipher.encrypt(payload.identity_authorization.userId, 'active', setup.secret)]);
  await assert.rejects(create().confirm(payload, code), { status: 503 });
}));

async function recoveryFixture(fixture) {
  const { service, payload, recovery } = fixture; const { setup, counter } = await enable(service, payload); const userId = payload.identity_authorization.userId;
  rememberFactor(userId, setup.secret, counter);
  const proof = claims(payload, await service.login(userId, await nextOtp(userId)));
  const recoveryCodes = (await recovery().rotate(proof, await nextOtp(userId))).recoveryCodes;
  return { ...fixture, userId, proof, recoveryCodes, originalSecret: setup.secret, begin: recoveryCode => recovery().start('owner-subject', payload.identity_authorization, recoveryCode) };
}
test('recovery codes are high-entropy, hashed, one-disclosure own-account credentials and status never retrieves them', () => authority(async fixture => {
  const { recoveryCodes, recovery, proof, pool, userId } = await recoveryFixture(fixture);
  assert.equal(recoveryCodes.length, 8); assert.equal(new Set(recoveryCodes).size, 8);
  for (const code of recoveryCodes) assert.match(code, /^[a-f0-9]{8}(?:-[a-f0-9]{8}){3}$/);
  assert.deepEqual(await recovery().status(proof), { remaining: 8 });
  const records = (await pool.query('SELECT * FROM oauth_mfa_recovery_codes WHERE user_id=$1', [userId])).rows;
  assert.equal(records.length, 8); for (const code of recoveryCodes) assert.equal(JSON.stringify(records).includes(code), false);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM oauth_mfa_recovery_audit WHERE user_id=$1 AND action='codes_rotated'", [userId])).rows[0].count, 1);
}));
test('a recovery start consumes exactly one backup, leaves MFA mandatory and issues only a bounded factor-setup challenge', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, proof, service, userId, pool } = await recoveryFixture(fixture);
  const started = await begin(recoveryCodes[0]); assert.deepEqual(Object.keys(started).sort(), ['challenge', 'expiresAt', 'otpauthUri', 'secret']);
  assert.equal(started.challenge.length, 80); assert.deepEqual(await recovery().status(proof), { remaining: 7 });
  await assert.rejects(service.login(userId), { code: 'otp_required' }); await assert.rejects(service.login(userId, recoveryCodes[1]), { code: 'invalid_otp' });
  assert.equal(await service.matches(proof), true);
  const row = (await pool.query('SELECT * FROM oauth_mfa_recovery_challenges WHERE user_id=$1', [userId])).rows[0];
  assert.equal(new Date(row.expires_at) - new Date(row.created_at), 600000); assert.equal(row.token_hash.includes(started.challenge), false); assert.equal(row.encrypted_seed.includes(started.secret), false);
  await assert.rejects(begin(recoveryCodes[0]), { code: 'invalid_recovery_code' });
}));
test('independent instances cannot consume one backup code or finish one recovery twice', () => authority(async fixture => {
  const prepared = await recoveryFixture(fixture); const { begin, recoveryCodes, recovery, service, proof, userId } = prepared;
  const attempts = await Promise.allSettled([begin(recoveryCodes[0]), begin(recoveryCodes[0])]);
  assert.equal(attempts.filter(result => result.status === 'fulfilled').length, 1);
  const started = attempts.find(result => result.status === 'fulfilled').value; const code = totp(started.secret, Math.floor(Date.now() / 30000));
  const completed = await Promise.allSettled([recovery().confirm(started.challenge, code), recovery().confirm(started.challenge, code)]);
  assert.equal(completed.filter(result => result.status === 'fulfilled').length, 1); assert.equal(await service.matches(proof), false);
  await assert.rejects(begin(recoveryCodes[1]), { code: 'invalid_recovery_code' });
  const next = claims(fixture.payload, await service.login(userId, totp(started.secret, Math.floor(Date.now() / 30000) + 1)));
  assert.equal(await service.matches(next), true); assert.deepEqual(await recovery().status(next), { remaining: 0 });
}));
test('a successful factor recovery survives migration reapplication without revalidating the old seed, old sessions or backup family', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, service, proof, userId, migrate, pool } = await recoveryFixture(fixture);
  const started = await begin(recoveryCodes[0]); const counter = Math.floor(Date.now() / 30000) - 1;
  assert.deepEqual(await recovery().confirm(started.challenge, totp(started.secret, counter)), { enabled: true, reauthenticationRequired: true });
  await migrate(); assert.equal(await service.matches(proof), false); await assert.rejects(recovery().confirm(started.challenge, totp(started.secret, counter + 1)), { code: 'invalid_recovery_challenge' });
  await assert.rejects(begin(recoveryCodes[1]), { code: 'invalid_recovery_code' });
  const next = claims(fixture.payload, await service.login(userId, totp(started.secret, counter + 1))); assert.equal(next.mfa_authorization.revision, '2'); assert.equal(await service.matches(next), true);
  assert.equal((await pool.query("SELECT COUNT(*)::int AS count FROM oauth_mfa_audit WHERE user_id=$1 AND action='recovered'", [userId])).rows[0].count, 1);
}));
test('recovery audit failure atomically rolls back code consumption and challenge issuance', () => authority(async fixture => {
  const { begin, recoveryCodes, pool, userId } = await recoveryFixture(fixture);
  await pool.query('ALTER TABLE oauth_mfa_recovery_audit RENAME TO unavailable_recovery_audit');
  try { await assert.rejects(begin(recoveryCodes[0]), { status: 503 }); }
  finally { await pool.query('ALTER TABLE unavailable_recovery_audit RENAME TO oauth_mfa_recovery_audit'); }
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_mfa_recovery_codes WHERE user_id=$1 AND consumed_at IS NOT NULL', [userId])).rows[0].count, 0);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_mfa_recovery_challenges WHERE user_id=$1', [userId])).rows[0].count, 0); assert.ok((await begin(recoveryCodes[0])).challenge);
}));
test('completion audit failure cannot replace the active factor or spend the completion challenge', () => authority(async fixture => {
  const { begin, recoveryCodes, pool, userId, recovery, service, proof } = await recoveryFixture(fixture); const started = await begin(recoveryCodes[0]); const code = totp(started.secret, Math.floor(Date.now() / 30000));
  await pool.query('ALTER TABLE oauth_mfa_recovery_audit RENAME TO unavailable_recovery_audit');
  try { await assert.rejects(recovery().confirm(started.challenge, code), { status: 503 }); }
  finally { await pool.query('ALTER TABLE unavailable_recovery_audit RENAME TO oauth_mfa_recovery_audit'); }
  assert.equal((await pool.query('SELECT revision FROM oauth_mfa_factors WHERE user_id=$1', [userId])).rows[0].revision, '1'); assert.equal(await service.matches(proof), true);
  assert.equal((await pool.query('SELECT consumed_at FROM oauth_mfa_recovery_challenges WHERE user_id=$1', [userId])).rows[0].consumed_at, null); await recovery().confirm(started.challenge, code);
}));
test('a directory generation or role change and a real source outage cannot be bypassed by a saved recovery challenge', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, identity, payload, service, proof } = await recoveryFixture(fixture); const started = await begin(recoveryCodes[0]); const code = totp(started.secret, Math.floor(Date.now() / 30000));
  const original = identity.state;
  identity.state = async () => { throw Object.assign(new Error('unavailable'), { status: 503 }); };
  await assert.rejects(recovery().confirm(started.challenge, code), { status: 503 }); identity.state = original;
  payload.identity_authorization = { ...payload.identity_authorization, rolesRevision: 'b'.repeat(64) };
  await assert.rejects(recovery().confirm(started.challenge, code), { code: 'recovery_identity_changed' }); assert.equal(await service.matches(proof), true);
}));
test('backup-code and challenge failures persist throttling across verifier instances', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, userId, pool } = await recoveryFixture(fixture);
  for (let attempt = 0; attempt < 5; attempt++) await assert.rejects(begin('00000000-00000000-00000000-00000000'), { code: 'invalid_recovery_code' });
  await assert.rejects(begin(recoveryCodes[0]), { code: 'mfa_temporarily_locked' });
  await pool.query("UPDATE oauth_mfa_factors SET locked_until=clock_timestamp()-interval '1 second' WHERE user_id=$1", [userId]);
  const started = await begin(recoveryCodes[0]); const current = Math.floor(Date.now() / 30000); let wrong = '000000';
  while ([current - 1, current, current + 1].some(counter => totp(started.secret, counter) === wrong)) wrong = String(Number(wrong) + 1).padStart(6, '0');
  for (let attempt = 0; attempt < 5; attempt++) await assert.rejects(recovery().confirm(started.challenge, wrong), { code: 'invalid_otp' });
  await assert.rejects(recovery().confirm(started.challenge, totp(started.secret, current)), { code: 'mfa_temporarily_locked' });
}));
test('rotating backups invalidates every old backup and a pending recovery but does not invent a new login', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, proof, userId, service } = await recoveryFixture(fixture); const started = await begin(recoveryCodes[0]);
  const rotated = await recovery().rotate(proof, await nextOtp(userId)); assert.equal(rotated.remaining, 8); assert.equal(await service.matches(proof), true);
  await assert.rejects(begin(recoveryCodes[1]), { code: 'invalid_recovery_code' }); await assert.rejects(recovery().confirm(started.challenge, totp(started.secret, Math.floor(Date.now() / 30000))), { code: 'invalid_recovery_challenge' });
  assert.ok((await begin(rotated.recoveryCodes[0])).challenge);
}));
test('database recovery evidence cannot be rewritten, revived, extended or used as an unconsumed factor-change witness', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, pool, userId, service } = await recoveryFixture(fixture); const started = await begin(recoveryCodes[0]); const id = started.challenge.split('.')[0];
  await assert.rejects(pool.query('UPDATE oauth_mfa_recovery_codes SET consumed_at=NULL WHERE user_id=$1 AND consumed_at IS NOT NULL', [userId]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_recovery_codes WHERE user_id=$1', [userId]));
  await assert.rejects(pool.query("UPDATE oauth_mfa_recovery_challenges SET expires_at=expires_at+interval '1 hour' WHERE id=$1", [id]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_recovery_challenges WHERE id=$1', [id]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_recovery_audit WHERE user_id=$1', [userId]));
  const connection = await pool.connect(); await connection.query('BEGIN');
  try {
    await connection.query("SELECT set_config('opendirectory.mfa_recovery',$1,true)", [id]);
    await assert.rejects(connection.query('UPDATE oauth_mfa_factors SET revision=revision+1,encrypted_seed=$2 WHERE user_id=$1', [userId, service.cipher.encrypt(userId, 'active', started.secret)]));
  } finally { await connection.query('ROLLBACK'); connection.release(); }
  await recovery().confirm(started.challenge, totp(started.secret, Math.floor(Date.now() / 30000)));
  await assert.rejects(pool.query('UPDATE oauth_mfa_recovery_challenges SET consumed_at=NULL WHERE id=$1', [id]));
}));
test('an expired challenge, corrupted encrypted purpose or cross-user backup cannot recover a factor', () => authority(async fixture => {
  const { begin, recoveryCodes, recovery, pool, userId, service, payload } = await recoveryFixture(fixture);
  await assert.rejects(recovery().start('another-owner', { ...payload.identity_authorization, userId: randomUUID() }, recoveryCodes[0]), { code: 'recovery_identity_changed' });
  const started = await begin(recoveryCodes[0]); const id = started.challenge.split('.')[0];
  await pool.query('ALTER TABLE oauth_mfa_recovery_challenges DISABLE TRIGGER oauth_mfa_recovery_challenge_guard');
  try { await pool.query("UPDATE oauth_mfa_recovery_challenges SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [id]); }
  finally { await pool.query('ALTER TABLE oauth_mfa_recovery_challenges ENABLE TRIGGER oauth_mfa_recovery_challenge_guard'); }
  await assert.rejects(recovery().confirm(started.challenge, '123456'), { code: 'invalid_recovery_challenge' });
  const replacement = await begin(recoveryCodes[1]); const replacementId = replacement.challenge.split('.')[0];
  await pool.query('ALTER TABLE oauth_mfa_recovery_challenges DISABLE TRIGGER oauth_mfa_recovery_challenge_guard');
  try { await pool.query('UPDATE oauth_mfa_recovery_challenges SET encrypted_seed=$2 WHERE id=$1', [replacementId, service.cipher.encrypt(userId, 'active', replacement.secret)]); }
  finally { await pool.query('ALTER TABLE oauth_mfa_recovery_challenges ENABLE TRIGGER oauth_mfa_recovery_challenge_guard'); }
  await assert.rejects(recovery().confirm(replacement.challenge, '123456'), { status: 503 });
}));

async function enrollmentFixture(fixture) {
  const { database, payload, service, identity } = fixture; const clients = new ClientRegistry(database); const administrator = actor();
  const verified = await enable(service, administrator);
  const management = { ...claims(administrator, await service.login(administrator.identity_authorization.userId, totp(verified.setup.secret, verified.counter + 1))),
    roles: ['admin'], iss: 'https://mfa-policy.test', sub: 'reviewed-administrator', client_id: 'independent-control' };
  let client = await clients.create({ name: 'Required-MFA application', redirectUris: ['https://application.test/callback'], enabled: true }, management);
  await clients.setAuthentication(client.clientId, etag(client), { required: true, maxAgeSeconds: 300, reason: 'Reviewed owned enrollment policy' }, management); client = await clients.get(client.clientId);
  const applications = { revision: 'c'.repeat(64), assigned: true,
    async context(clientId) { return { schemaVersion: 1, clientId, userId: payload.identity_authorization.userId, revision: this.revision }; },
    async matches(clientId, _state, context) { return this.assigned && context.clientId === clientId && context.userId === payload.identity_authorization.userId && context.revision === this.revision; } };
  const enrollment = () => new MfaEnrollment({ mfa: fixture.create(), clients, identity, applications, issuer: 'https://mfa-policy.test' });
  return { ...fixture, clients, client, management, applications, enrollment, begin: () => enrollment().start(client.clientId, 'owner-subject') };
}
test('assigned required-MFA enrollment creates only a bounded, encrypted, purpose-specific factor ticket and no OAuth session', () => authority(async fixture => {
  const { begin, pool, payload, service } = await enrollmentFixture(fixture); const weaker = claims(payload, await service.login(payload.identity_authorization.userId));
  const started = await begin(); assert.deepEqual(Object.keys(started).sort(), ['challenge','expiresAt','otpauthUri','secret']);
  const row = (await pool.query('SELECT * FROM oauth_mfa_enrollments WHERE user_id=$1', [payload.identity_authorization.userId])).rows[0];
  assert.equal(new Date(row.expires_at) - new Date(row.created_at), 600000); assert.equal(JSON.stringify(row).includes(started.secret), false); assert.equal(row.token_hash.includes(started.challenge), false);
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_sessions')).rows[0].count, 0); assert.equal(await service.matches(weaker), true);
}));
test('actual enrollment confirmation enables one factor across instances, fences weaker proof and cannot be replayed or used as recovery', () => authority(async fixture => {
  const { begin, enrollment, payload, service, recovery } = await enrollmentFixture(fixture); const weaker = claims(payload, await service.login(payload.identity_authorization.userId));
  const started = await begin(); const counter = Math.floor(Date.now() / 30000) - 1; const code = totp(started.secret, counter);
  await assert.rejects(recovery().confirm(started.challenge, code), { code: 'invalid_recovery_challenge' });
  await assert.rejects(service.confirm({ ...payload, sid: started.challenge.split('.')[0] }, code), { status: 503 });
  const results = await Promise.allSettled([enrollment().confirm(started.challenge, code), enrollment().confirm(started.challenge, code)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1); assert.equal(await service.matches(weaker), false);
  await assert.rejects(begin(), { code: 'mfa_already_enabled' }); await assert.rejects(service.login(payload.identity_authorization.userId, code), { code: 'invalid_otp' });
  const stronger = claims(payload, await service.login(payload.identity_authorization.userId, totp(started.secret, counter + 1))); assert.equal(await service.matches(stronger), true);
}));
test('policy generation changes, disablement and later re-enforcement cannot revive an old enrollment', () => authority(async fixture => {
  const { begin, enrollment, clients, client, management } = await enrollmentFixture(fixture); const started = await begin();
  const disabled = await clients.setAuthentication(client.clientId, etag(client), { required: false, maxAgeSeconds: 300, reason: 'Reviewed explicit policy withdrawal' }, management);
  await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'enrollment_authorization_changed' });
  await clients.setAuthentication(client.clientId, etag(disabled), { required: true, maxAgeSeconds: 300, reason: 'Reviewed explicit policy restoration' }, management);
  await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'enrollment_authorization_changed' });
}));
test('canonical role generations and removed/readded application sources fence enrollment even when the password remains valid', () => authority(async fixture => {
  const prepared = await enrollmentFixture(fixture); const { begin, enrollment, applications, payload } = prepared; const started = await begin();
  applications.assigned = false; await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'enrollment_authorization_changed' });
  applications.assigned = true; applications.revision = 'd'.repeat(64); await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'enrollment_authorization_changed' });
  applications.revision = 'c'.repeat(64); payload.identity_authorization = { ...payload.identity_authorization, rolesRevision: 'e'.repeat(64) };
  await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'enrollment_authorization_changed' });
}));
test('failed enrollment audit cannot expose a seed, enable a factor or spend a completion challenge', () => authority(async fixture => {
  const { begin, enrollment, pool, payload } = await enrollmentFixture(fixture);
  await pool.query('ALTER TABLE oauth_mfa_enrollment_audit RENAME TO unavailable_enrollment_audit');
  try { await assert.rejects(begin(), { status: 503 }); } finally { await pool.query('ALTER TABLE unavailable_enrollment_audit RENAME TO oauth_mfa_enrollment_audit'); }
  assert.equal((await pool.query('SELECT COUNT(*)::int AS count FROM oauth_mfa_enrollments')).rows[0].count, 0);
  const started = await begin(); const code = totp(started.secret, Math.floor(Date.now() / 30000));
  await pool.query('ALTER TABLE oauth_mfa_enrollment_audit RENAME TO unavailable_enrollment_audit');
  try { await assert.rejects(enrollment().confirm(started.challenge, code), { status: 503 }); } finally { await pool.query('ALTER TABLE unavailable_enrollment_audit RENAME TO oauth_mfa_enrollment_audit'); }
  assert.equal((await pool.query('SELECT enabled FROM oauth_mfa_factors WHERE user_id=$1', [payload.identity_authorization.userId])).rows[0].enabled, false);
  assert.equal((await pool.query('SELECT consumed_at FROM oauth_mfa_enrollments')).rows[0].consumed_at, null); await enrollment().confirm(started.challenge, code);
}));
test('enrollment source loss and persistent failed-code throttling cannot become password-only authentication', () => authority(async fixture => {
  const { begin, enrollment, identity, payload, pool } = await enrollmentFixture(fixture); const started = await begin(); const original = identity.state;
  identity.state = async () => { throw Object.assign(new Error('offline'), { status: 503 }); };
  await assert.rejects(enrollment().confirm(started.challenge, '123456'), { status: 503 }); identity.state = original;
  const current = Math.floor(Date.now() / 30000); let wrong = '000000'; while ([current-1,current,current+1].some(counter => totp(started.secret,counter) === wrong)) wrong = String(Number(wrong)+1).padStart(6,'0');
  for (let attempt = 0; attempt < 5; attempt++) await assert.rejects(enrollment().confirm(started.challenge, wrong), { code: 'invalid_otp' });
  await assert.rejects(begin(), { code: 'mfa_temporarily_locked' }); await assert.rejects(enrollment().confirm(started.challenge, totp(started.secret,current)), { code: 'mfa_temporarily_locked' });
  assert.equal((await pool.query('SELECT enabled FROM oauth_mfa_factors WHERE user_id=$1', [payload.identity_authorization.userId])).rows[0].enabled, false);
}));
test('enrollment origin, deadline and one-way completion are immutable, including after migration reapplication', () => authority(async fixture => {
  const { begin, pool, migrate, enrollment } = await enrollmentFixture(fixture); const started = await begin(); const id = started.challenge.split('.')[0]; await migrate();
  await assert.rejects(pool.query("UPDATE oauth_mfa_enrollments SET expires_at=expires_at+interval '1 hour' WHERE id=$1", [id]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_enrollments WHERE id=$1', [id]));
  await assert.rejects(pool.query('DELETE FROM oauth_mfa_enrollment_audit WHERE enrollment_id=$1', [id]));
  await enrollment().confirm(started.challenge, totp(started.secret, Math.floor(Date.now()/30000)));
  await assert.rejects(pool.query('UPDATE oauth_mfa_enrollments SET consumed_at=NULL WHERE id=$1', [id]));
}));
test('replacing a public enrollment or expiring its immutable ticket cannot be bypassed by a still-known code', () => authority(async fixture => {
  const { begin, enrollment, pool } = await enrollmentFixture(fixture); const old = await begin(); const started = await begin();
  await assert.rejects(enrollment().confirm(old.challenge, totp(old.secret, Math.floor(Date.now()/30000))), { code: 'invalid_enrollment_challenge' });
  await pool.query('ALTER TABLE oauth_mfa_enrollments DISABLE TRIGGER oauth_mfa_enrollment_guard');
  try { await pool.query("UPDATE oauth_mfa_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", [started.challenge.split('.')[0]]); }
  finally { await pool.query('ALTER TABLE oauth_mfa_enrollments ENABLE TRIGGER oauth_mfa_enrollment_guard'); }
  await assert.rejects(enrollment().confirm(started.challenge, '123456'), { code: 'invalid_enrollment_challenge' });
}));
