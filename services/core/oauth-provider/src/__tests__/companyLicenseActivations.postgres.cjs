'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const fs = require('node:fs'); const path = require('node:path');
const { Pool } = require('pg');
const { CompanyLicenseActivations } = require('../CompanyLicenseActivations');
const { ClientRegistry } = require('../ClientRegistry');
const { SessionStore } = require('../SessionStore');
const contract = require('../../../../../packages/company-license-activation');

test('company license activation uses real PostgreSQL authority, immutable audit and session binding', async t => {
  const schema = 'activation_' + randomUUID().replaceAll('-', '');
  const administration = new Pool({ connectionString: process.env.OAUTH_TEST_DATABASE_URL, max: 1 }); let pool;
  try {
    await administration.query(`CREATE SCHEMA ${schema}`);
    const url = new URL(process.env.OAUTH_TEST_DATABASE_URL); url.searchParams.set('options', `-c search_path=${schema},public`);
    pool = new Pool({ connectionString: url.toString(), max: 5 });
    const directory = path.join(__dirname, '../../migrations');
    for (const file of fs.readdirSync(directory).filter(file => file.endsWith('.sql')).sort()) await pool.query(fs.readFileSync(path.join(directory, file), 'utf8'));
    const database = { pool, query: (...args) => pool.query(...args), isAvailable: () => true };
    await new ClientRegistry(database).initialize([{ clientId: 'web-app', name: 'Disposable console', publicClient: true, clientSecretHash: null, redirectUris: ['https://console.test/callback'], grantTypes: ['authorization_code', 'refresh_token'], scopes: ['openid'] }]);
    const tenant = { id: randomUUID(), version: '1', generation: '1' };
    const userId = randomUUID(); const now = Math.floor(Date.now() / 1000);
    await pool.query("INSERT INTO oauth_mfa_factors(user_id,revision,enabled,encrypted_seed) VALUES($1,1,true,'disposable-encrypted-fixture')", [userId]);
    async function actor(expiresAt = Date.now() + 86400000) {
      const user = { actor_type: 'user', iss: 'https://activation.test', sub: 'actual-owner', sid: randomUUID(), client_id: 'web-app', client_revision: '1',
        iat: now, exp: now + 3600, auth_time: now, identity_authorization: { userId, revision: '1', linkRevision: '1', rolesRevision: 'a'.repeat(64) },
        amr: ['pwd', 'otp'], mfa_authorization: { schemaVersion: 1, userId, revision: '1', methods: ['pwd', 'otp'], authTime: now } };
      await new SessionStore(database).create({ id: user.sid, issuer: user.iss, subject: user.sub, principalType: 'user', clientId: user.client_id, authTime: now, expiresAt });
      return user;
    }
    const eligibility = async user => ({ tenant, context: user.identity_authorization });
    const store = new CompanyLicenseActivations(database, { eligibility });
    const input = { durationSeconds: 36000, reason: 'Actual own-company license administration', confirm: true };
    await t.test('ten hours require explicit confirmation and proven fresh MFA', async () => {
      const user = await actor();
      for (const value of [{ ...input, confirm: false }, { ...input, durationSeconds: 36001 }, { ...input, tenant }, { ...input, reason: 'bad\nreason' }]) await assert.rejects(store.change(user, 'Bearer original', value), { status: 400 });
      await assert.rejects(store.change({ ...user, amr: ['pwd'] }, 'Bearer original', input), { status: 428 });
      const created = await store.change(user, 'Bearer original', input); assert.ok(contract.validClaim(created.activation));
      assert.ok(created.activation.expiresAt - now <= 36000 && created.activation.expiresAt - now >= 35990);
      assert.equal((await store.status(user, 'Bearer original')).activation.id, created.activation.id);
      await assert.rejects(store.change(user, 'Bearer original', input), { status: 409 });
      await assert.rejects(store.change(user, 'Bearer original', { activationId: randomUUID(), confirm: true }), { status: 409 });
      assert.equal((await store.state({ ...user, client_revision: '2' })).activation, null);
      assert.equal((await store.state({ ...user, auth_time: now - 1 })).activation, null);
      assert.equal((await store.state({ ...user, identity_authorization: { ...user.identity_authorization, rolesRevision: 'b'.repeat(64) } })).activation, null);
      assert.equal((await store.state(await actor())).known, false);
      await store.change(user, 'Bearer original', { activationId: created.activation.id, confirm: true });
      assert.deepEqual(await store.state(user), { known: true, activation: null });
      assert.deepEqual((await pool.query('SELECT action FROM oauth_company_license_activation_audit WHERE activation_id=$1 ORDER BY id', [created.activation.id])).rows.map(row => row.action), ['activated', 'revoked']);
      await assert.rejects(pool.query('UPDATE oauth_company_license_activations SET expires_at=expires_at+interval \'1 hour\' WHERE id=$1', [created.activation.id]));
      await assert.rejects(pool.query('DELETE FROM oauth_company_license_activation_audit WHERE activation_id=$1', [created.activation.id]));
    });
    await t.test('operator maximum cannot be bypassed', async () => {
      const limited = new CompanyLicenseActivations(database, { eligibility, maximum: 3600 });
      await assert.rejects(limited.change(await actor(), 'Bearer original', input), { status: 400 });
      assert.deepEqual((await limited.status(await actor(), 'Bearer original')).durations, [900, 3600]);
      assert.throws(() => new CompanyLicenseActivations(database, { maximum: 36001 }));
    });
    await t.test('authority withdrawn after audit rolls back activation and audit together', async () => {
      const user = await actor(); let calls = 0;
      const withdrawn = new CompanyLicenseActivations(database, { eligibility: async value => { if (++calls > 1) throw Object.assign(new Error('withdrawn'), { status: 403 }); return eligibility(value); } });
      await assert.rejects(withdrawn.change(user, 'Bearer original', input), { status: 403 });
      assert.equal((await store.state(user)).known, false);
    });
    await t.test('audit failure cannot leave an unaudited grant', async () => {
      const user = await actor();
      await pool.query("ALTER TABLE oauth_company_license_activation_audit ADD CONSTRAINT injected_audit_failure CHECK(action<>'activated') NOT VALID");
      try { await assert.rejects(store.change(user, 'Bearer original', input), { status: 503 }); assert.equal((await store.state(user)).known, false); }
      finally { await pool.query('ALTER TABLE oauth_company_license_activation_audit DROP CONSTRAINT injected_audit_failure'); }
    });
    await t.test('absolute session expiry caps a long request and expires the stored window without fallback', async () => {
      const user = await actor(Date.now() + 2000);
      const created = await store.change(user, 'Bearer original', input);
      assert.ok(created.activation.expiresAt <= Math.floor(Date.now() / 1000) + 2);
      await pool.query('SELECT pg_sleep(2.1)');
      assert.deepEqual(await store.state(user), { known: true, activation: null });
    });
    await t.test('migrations reapply without reactivating revoked leases', async () => {
      await pool.query(fs.readFileSync(path.join(directory, '016_company_license_activations.sql'), 'utf8'));
      assert.equal(Number((await pool.query("SELECT count(*) FROM oauth_company_license_activations WHERE revoked_at IS NOT NULL")).rows[0].count), 1);
    });
  } finally { if (pool) await pool.end(); await administration.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await administration.end(); }
});
