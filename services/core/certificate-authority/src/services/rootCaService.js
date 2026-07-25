'use strict';

/**
 * Root CA key/certificate lifecycle: generate once, persist, and reload on
 * every subsequent boot.
 *
 * BEFORE THIS MODULE EXISTED: src/index.js generated a brand-new 4096-bit
 * RSA root CA key pair on every process start and never persisted it. Every
 * certificate previously issued by this service (stored in ca_certificates)
 * was signed by a root key that no longer existed after a restart, silently
 * making the entire previously-issued cert population untrusted. This module
 * fixes that: the singleton `ca_root_key` table (see
 * ../../migrations/001_ca_root_key.sql) holds exactly one row; on boot we
 * look for it first and only fall back to generating a new key pair when the
 * table is empty (true first boot).
 *
 * CONFIDENTIALITY: the private key is encrypted at rest via
 * ../crypto/fieldEncryption.js (AES-256-GCM, key from the ENCRYPTION_KEY env
 * var). If ENCRYPTION_KEY is not set, fieldEncryption transparently falls
 * back to base64 (NOT encryption) and logs a loud warning — see that
 * module's header comment. Operators MUST set ENCRYPTION_KEY in any
 * deployment that runs this service; this is a known, tracked gap shared
 * with every other service in this repo that already uses the same
 * fieldEncryption module (conditional-access, samba-ad-dc).
 */

const forge = require('node-forge');
const { encrypt, decrypt } = require('../crypto/fieldEncryption');

/**
 * Attempt to load the persisted root CA row from the DB.
 * @returns {null|{caKey, caCert, caKeyPem, caCertPem}}
 */
async function loadFromDb(pool) {
  let r;
  try {
    r = await pool.query(
      'SELECT private_key_pem, certificate_pem FROM ca_root_key WHERE id = 1'
    );
  } catch (err) {
    // Table missing (migration not applied yet) or a transient DB error.
    // Falling back to "no row found" here carries the same risk profile as
    // the pre-fix behavior (a fresh key is generated) — never worse. The
    // decrypt-failure case below is handled differently (see comment there):
    // that one is NOT caught, because a row we can't decrypt is a signal we
    // must not paper over by silently minting a new, unpersisted key.
    console.warn('[CA] Could not query ca_root_key — falling back to generating a new root CA:', err.message);
    return null;
  }
  if (!r.rows || r.rows.length === 0) return null;

  const row = r.rows[0];
  const caKeyPem = decrypt(row.private_key_pem);
  const caCertPem = row.certificate_pem;
  if (!caKeyPem) {
    // decrypt() returns null on failure (e.g. ENCRYPTION_KEY rotated/lost).
    // Do NOT silently regenerate here — that would be exactly the bug this
    // module exists to fix. Surface it loudly instead.
    throw new Error(
      'ca_root_key row found but private_key_pem could not be decrypted ' +
      '(ENCRYPTION_KEY mismatch or missing). Refusing to regenerate the ' +
      'root CA automatically — that would invalidate every issued certificate.'
    );
  }

  return {
    caKey: forge.pki.privateKeyFromPem(caKeyPem),
    caCert: forge.pki.certificateFromPem(caCertPem),
    caKeyPem,
    caCertPem,
  };
}

/**
 * Generate a brand-new self-signed root CA key pair + certificate.
 * Pure function — does not touch the DB.
 */
function generate({ commonName, org, country, validityYears }) {
  const keys = forge.pki.rsa.generateKeyPair({ bits: 4096, e: 0x10001 });
  const caKey = keys.privateKey;

  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + validityYears);

  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: org },
    { name: 'countryName', value: country },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ]);

  cert.sign(caKey, forge.md.sha256.create());

  const caCert = cert;
  const caKeyPem = forge.pki.privateKeyToPem(caKey);
  const caCertPem = forge.pki.certificateToPem(caCert);

  return { caKey, caCert, caKeyPem, caCertPem };
}

/** Persist a freshly generated root CA. No-op (via ON CONFLICT) if a row already exists. */
async function persist(pool, { caKeyPem, caCertPem, commonName }) {
  await pool.query(
    `INSERT INTO ca_root_key(id, private_key_pem, certificate_pem, common_name)
     VALUES(1, $1, $2, $3)
     ON CONFLICT (id) DO NOTHING`,
    [encrypt(caKeyPem), caCertPem, commonName]
  );
}

/**
 * Load the existing root CA from the DB, or generate + persist a new one if
 * this is the first boot. This is the entry point src/index.js's initCA()
 * calls.
 *
 * @param {object} opts
 * @param {import('pg').Pool} opts.pool
 * @param {boolean} opts.dbReady - whether the DB connection is currently usable.
 * @param {string} opts.commonName
 * @param {string} opts.org
 * @param {string} opts.country
 * @param {number} opts.validityYears
 * @returns {{caKey, caCert, caKeyPem, caCertPem, loadedFromDb: boolean}}
 */
async function loadOrCreateRootCa({ pool, dbReady, commonName, org, country, validityYears }) {
  if (dbReady) {
    const existing = await loadFromDb(pool);
    if (existing) return { ...existing, loadedFromDb: true };
  }

  const created = generate({ commonName, org, country, validityYears });

  if (dbReady) {
    try {
      await persist(pool, { caKeyPem: created.caKeyPem, caCertPem: created.caCertPem, commonName });
      console.log('[CA] Root CA persisted to database');
    } catch (err) {
      console.error(
        '[CA] FAILED to persist the newly generated root CA key. It will be ' +
        'regenerated on next restart, invalidating ALL certificates issued ' +
        'in the meantime:', err.message
      );
    }
  } else {
    console.error(
      '[CA] WARNING: database unavailable at boot — the root CA private key ' +
      'is NOT being persisted. It will be regenerated on next restart, ' +
      'invalidating ALL previously issued certificates. This is a ' +
      'degraded-availability fallback, not a supported operating mode.'
    );
  }

  return { ...created, loadedFromDb: false };
}

module.exports = { loadOrCreateRootCa, loadFromDb, generate, persist };
