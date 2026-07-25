'use strict';

/**
 * P0 regression test: the root CA private key must survive a restart.
 *
 * Before the fix, src/index.js's initCA() unconditionally generated a fresh
 * 4096-bit RSA root key pair on every process boot and never persisted it —
 * so every certificate issued by a previous boot was silently signed by a
 * root key that no longer existed. rootCaService.loadOrCreateRootCa() is the
 * fix: it looks the key up in the DB first, and only generates (+ persists)
 * a new one when no row exists yet.
 *
 * These tests exercise loadOrCreateRootCa() directly against a tiny in-memory
 * fake Pool (a plain object with a jest.fn() query implementation) rather
 * than booting the whole Express app — that keeps the "does boot #2 reuse
 * the key from boot #1" assertion simple and deterministic (no need to spin
 * up two HTTP servers or fight port conflicts / module caching).
 */

const forge = require('node-forge');
const { loadOrCreateRootCa } = require('../rootCaService');

// A 32-byte hex key so fieldEncryption.js takes the real AES-256-GCM path
// instead of its (intentionally non-encrypting) base64 fallback.
const TEST_ENCRYPTION_KEY = 'ab'.repeat(32);

function makeFakePool() {
  // Simulates the ca_root_key singleton row (id = 1) exactly as Postgres
  // would store it across "restarts" of the service under test.
  let row = null;
  return {
    query: jest.fn(async (sql, params) => {
      if (/SELECT\s+private_key_pem,\s*certificate_pem\s+FROM\s+ca_root_key/i.test(sql)) {
        return { rows: row ? [row] : [] };
      }
      if (/INSERT INTO ca_root_key/i.test(sql)) {
        if (!row) {
          row = {
            private_key_pem: params[0],
            certificate_pem: params[1],
            common_name: params[2],
          };
        }
        return { rows: [] };
      }
      throw new Error(`Unexpected query in fake pool: ${sql}`);
    }),
  };
}

const CA_OPTS = { commonName: 'Test Root CA', org: 'TestOrg', country: 'CH', validityYears: 10 };

describe('rootCaService.loadOrCreateRootCa', () => {
  const OLD_KEY = process.env.ENCRYPTION_KEY;
  beforeAll(() => { process.env.ENCRYPTION_KEY = TEST_ENCRYPTION_KEY; });
  afterAll(() => {
    if (OLD_KEY === undefined) delete process.env.ENCRYPTION_KEY;
    else process.env.ENCRYPTION_KEY = OLD_KEY;
  });

  it('generates and persists a new root CA when the DB has no existing row (first boot)', async () => {
    const pool = makeFakePool();
    const genSpy = jest.spyOn(forge.pki.rsa, 'generateKeyPair');

    const result = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });

    expect(result.loadedFromDb).toBe(false);
    expect(genSpy).toHaveBeenCalledTimes(1);
    expect(result.caKeyPem).toMatch(/PRIVATE KEY/);
    expect(result.caCertPem).toMatch(/BEGIN CERTIFICATE/);

    const insertCall = pool.query.mock.calls.find(([sql]) => /INSERT INTO ca_root_key/i.test(sql));
    expect(insertCall).toBeDefined();

    // The persisted value must be encrypted, not the raw PEM.
    const storedPrivateKey = insertCall[1][0];
    expect(storedPrivateKey).not.toBe(result.caKeyPem);
    expect(storedPrivateKey).not.toContain('PRIVATE KEY');
    expect(storedPrivateKey.split(':')).toHaveLength(3); // iv:authTag:ciphertext

    genSpy.mockRestore();
  });

  it('CORE FIX: on the second boot (process restart), loads the persisted key from the DB instead of generating a new one', async () => {
    const pool = makeFakePool();

    // Boot #1: empty DB → generate + persist.
    const boot1 = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });
    expect(boot1.loadedFromDb).toBe(false);

    // Boot #2: same underlying "database" (the fake pool's row survives,
    // simulating the process having restarted against the same Postgres).
    // This is the regression the P0 fix targets — assert no new key pair is
    // generated and the exact same key/cert come back.
    const genSpy = jest.spyOn(forge.pki.rsa, 'generateKeyPair');
    const boot2 = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });

    expect(boot2.loadedFromDb).toBe(true);
    expect(genSpy).not.toHaveBeenCalled();
    expect(boot2.caKeyPem).toBe(boot1.caKeyPem);
    expect(boot2.caCertPem).toBe(boot1.caCertPem);
    expect(boot2.caCert.serialNumber).toBe(boot1.caCert.serialNumber);

    genSpy.mockRestore();
  });

  it('a third boot still reuses the same key (persistence is not a one-shot fluke)', async () => {
    const pool = makeFakePool();
    const boot1 = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });
    const boot2 = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });
    const boot3 = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });

    expect(boot1.caKeyPem).toBe(boot2.caKeyPem);
    expect(boot2.caKeyPem).toBe(boot3.caKeyPem);
  });

  it('falls back to (unpersisted) in-memory generation when the DB is unavailable, without querying it', async () => {
    const pool = makeFakePool();
    const result = await loadOrCreateRootCa({ pool, dbReady: false, ...CA_OPTS });

    expect(result.loadedFromDb).toBe(false);
    expect(pool.query).not.toHaveBeenCalled();
  });

  it('gracefully falls back to generating a new CA if the SELECT query itself fails (e.g. table missing)', async () => {
    const pool = { query: jest.fn().mockRejectedValue(new Error('relation "ca_root_key" does not exist')) };
    const result = await loadOrCreateRootCa({ pool, dbReady: true, ...CA_OPTS });

    expect(result.loadedFromDb).toBe(false);
    expect(result.caKeyPem).toMatch(/PRIVATE KEY/);
  });
});
