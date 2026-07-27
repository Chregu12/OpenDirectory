'use strict';

// Runs with Node's built-in test runner:
//   node --test src/computer/__tests__/
//
// Regression coverage for the persistence-audit finding on BitLocker
// recovery-key escrow (src/computer/computerManager.js#escrowBitLockerKey):
// with a pg Pool present but no migration runner, the DB write threw on a
// missing `bitlocker_keys` table; and — the more dangerous half of the bug
// — when no DB was configured at all, escrowBitLockerKey skipped the write
// entirely and still returned { success: true }, so a caller (and the
// admin relying on it) would believe the key was durably escrowed when it
// was never stored anywhere. This file proves both halves are fixed:
//   1. with an available DB, escrow really persists (write -> read
//      roundtrip against a stateful fake pg pool), and
//   2. without a DB (missing, or present-but-not-yet-migrated), escrow now
//      throws a clear error instead of reporting fake success.

const { test } = require('node:test');
const assert = require('node:assert/strict');

const ComputerManager = require('../computerManager');

// Encryption key so encrypt()/decrypt() in ../crypto/fieldEncryption use
// real AES-256-GCM rather than the base64 "no key configured" fallback —
// exercises the same code path production traffic would use.
process.env.ENCRYPTION_KEY = 'a'.repeat(64);

const sambaLdapStub = {}; // unused by the escrow/read paths under test

/**
 * A minimal stateful fake of the src/db/index.js module contract
 * ({ isAvailable(), query(sql, params) }), backed by an in-memory table so
 * a write really has to be persisted and read back for these tests to
 * pass — this is not just "was .query() called", it's "does the row
 * actually come back out".
 */
function makeFakeDb({ available = true } = {}) {
  const bitlockerKeys = [];
  const accessLog = [];

  return {
    isAvailable: () => available,
    query(sql, params = []) {
      if (sql.includes('INSERT INTO bitlocker_keys')) {
        const [computerName, volumeType, recoveryKeyId, encryptedRecoveryKey, tpmThumbprint] = params;
        if (bitlockerKeys.some(k => k.recovery_key_id === recoveryKeyId)) {
          return Promise.resolve({ rows: [] }); // ON CONFLICT (recovery_key_id) DO NOTHING
        }
        bitlockerKeys.push({
          id: `id-${bitlockerKeys.length + 1}`,
          computer_name: computerName,
          volume_type: volumeType,
          recovery_key_id: recoveryKeyId,
          encrypted_recovery_key: encryptedRecoveryKey,
          tpm_thumbprint: tpmThumbprint,
          escrowed_at: new Date().toISOString()
        });
        return Promise.resolve({ rows: [] });
      }

      if (sql.includes('SELECT * FROM bitlocker_keys')) {
        const [computerName, recoveryKeyId] = params;
        const rows = bitlockerKeys.filter(
          k => k.computer_name === computerName && k.recovery_key_id === recoveryKeyId
        );
        return Promise.resolve({ rows });
      }

      if (sql.includes('SELECT id, computer_name')) {
        const [computerName] = params;
        const rows = bitlockerKeys.filter(k => k.computer_name === computerName);
        return Promise.resolve({ rows });
      }

      if (sql.includes('INSERT INTO bitlocker_key_access_log')) {
        accessLog.push({ recovery_key_id: params[0], retrieved_by: params[1] });
        return Promise.resolve({ rows: [] });
      }

      return Promise.reject(new Error(`unexpected query in fake db: ${sql}`));
    },
    _debug: { bitlockerKeys, accessLog }
  };
}

test('escrowBitLockerKey(): with an available DB, the key is really persisted (write -> read roundtrip)', async () => {
  const db = makeFakeDb({ available: true });
  const cm = new ComputerManager(sambaLdapStub, db);

  const escrowResult = await cm.escrowBitLockerKey('laptop-01', {
    volumeType: 'os',
    recoveryKeyId: 'KEY-ROUNDTRIP-1',
    recoveryKey: '123456-654321-123456-654321-123456-654321-123456',
    tpmThumbprint: 'AA:BB:CC'
  });

  assert.equal(escrowResult.success, true);
  assert.equal(escrowResult.computerName, 'LAPTOP-01');

  // Prove it didn't just "not throw" — the plaintext key really comes back
  // out through a fresh read, decrypted, from the (fake, but stateful) DB.
  const readBack = await cm.getBitLockerKey('laptop-01', 'KEY-ROUNDTRIP-1', 'admin-1');
  assert.equal(readBack.recoveryKey, '123456-654321-123456-654321-123456-654321-123456');
  assert.equal(readBack.volumeType, 'os');
  assert.equal(readBack.tpmThumbprint, 'AA:BB:CC');

  const listed = await cm.listBitLockerKeys('laptop-01');
  assert.equal(listed.length, 1);
  assert.equal(listed[0].recovery_key_id, 'KEY-ROUNDTRIP-1');
});

test('escrowBitLockerKey(): recovery key is stored encrypted at rest, not as plaintext', async () => {
  const db = makeFakeDb({ available: true });
  const cm = new ComputerManager(sambaLdapStub, db);
  const plaintext = '111111-222222-333333-444444-555555-666666-777777';

  await cm.escrowBitLockerKey('laptop-02', {
    volumeType: 'os',
    recoveryKeyId: 'KEY-ENC-CHECK',
    recoveryKey: plaintext
  });

  assert.equal(db._debug.bitlockerKeys.length, 1);
  assert.notEqual(db._debug.bitlockerKeys[0].encrypted_recovery_key, plaintext);
});

test('escrowBitLockerKey(): with NO db configured at all, throws instead of reporting fake success', async () => {
  const cm = new ComputerManager(sambaLdapStub, null);

  await assert.rejects(
    () => cm.escrowBitLockerKey('laptop-03', {
      volumeType: 'os',
      recoveryKeyId: 'KEY-NO-DB',
      recoveryKey: '999999-999999-999999-999999-999999-999999-999999'
    }),
    /NOT escrowed/
  );
});

test('escrowBitLockerKey(): with a db present but not yet migrated/available, throws instead of reporting fake success', async () => {
  const db = makeFakeDb({ available: false });
  const cm = new ComputerManager(sambaLdapStub, db);

  await assert.rejects(
    () => cm.escrowBitLockerKey('laptop-04', {
      volumeType: 'data',
      recoveryKeyId: 'KEY-NOT-READY',
      recoveryKey: '888888-888888-888888-888888-888888-888888-888888'
    }),
    /NOT escrowed/
  );

  // And, crucially: nothing was written anywhere a later read could find.
  assert.equal(db._debug.bitlockerKeys.length, 0);
});

test('escrowBitLockerKey(): a real DB write failure (e.g. missing table) still throws with a clear message, not fake success', async () => {
  const db = {
    isAvailable: () => true,
    query: () => Promise.reject(new Error('relation "bitlocker_keys" does not exist'))
  };
  const cm = new ComputerManager(sambaLdapStub, db);

  await assert.rejects(
    () => cm.escrowBitLockerKey('laptop-05', {
      volumeType: 'os',
      recoveryKeyId: 'KEY-DB-ERROR',
      recoveryKey: '777777-777777-777777-777777-777777-777777-777777'
    }),
    /Failed to escrow BitLocker key/
  );
});

test('getBitLockerKey()/listBitLockerKeys(): degrade to null/empty (not a throw) when no DB is configured', async () => {
  const cm = new ComputerManager(sambaLdapStub, null);

  const got = await cm.getBitLockerKey('laptop-06', 'SOME-KEY-ID', 'admin-1');
  assert.equal(got.recoveryKey, null);

  const listed = await cm.listBitLockerKeys('laptop-06');
  assert.deepEqual(listed, []);
});
