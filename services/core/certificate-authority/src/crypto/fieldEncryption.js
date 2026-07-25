'use strict';

/**
 * Field-level AES-256-GCM encryption utility.
 *
 * Mirrors services/core/conditional-access/src/crypto/fieldEncryption.js and
 * services/core/samba-ad-dc/src/crypto/fieldEncryption.js so all services that
 * persist secrets at rest (here: the root CA private key, see
 * ../services/rootCaService.js) share the same mechanism and env var name.
 *
 * Reads the encryption key from ENCRYPTION_KEY (32-byte hex string, i.e. 64 hex chars).
 * If the variable is absent a one-time warning is emitted and the module falls back to
 * base64 encoding so the service does not crash in development — but the data is NOT
 * encrypted in that case.
 *
 * Encrypted format (all parts base64-encoded, joined with ':'): iv:authTag:ciphertext
 */

const crypto = require('crypto');

const ALGO = 'aes-256-gcm';
const IV_BYTES = 12;     // 96-bit IV recommended for GCM
const TAG_BYTES = 16;    // 128-bit auth tag

// Warn only once per process when the key is missing.
let _warnedMissingKey = false;

function _getKey() {
  const keyHex = process.env.ENCRYPTION_KEY;
  if (!keyHex) {
    if (!_warnedMissingKey) {
      console.warn(
        '[fieldEncryption] WARNING: ENCRYPTION_KEY env var is not set. ' +
        'Sensitive fields (including the root CA private key) will be ' +
        'base64-encoded but NOT encrypted. Set a 32-byte hex key (64 hex ' +
        'chars) in production.'
      );
      _warnedMissingKey = true;
    }
    return null;
  }
  if (keyHex.length !== 64) {
    throw new Error(
      'ENCRYPTION_KEY must be exactly 64 hex characters (32 bytes). ' +
      `Got ${keyHex.length} chars.`
    );
  }
  return Buffer.from(keyHex, 'hex');
}

/**
 * Encrypt a plaintext string.
 *
 * @param {string} plaintext
 * @returns {string} Encrypted token: "<iv_b64>:<authTag_b64>:<ciphertext_b64>"
 *                   Falls back to "b64:<base64>" when ENCRYPTION_KEY is unset.
 */
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;

  const key = _getKey();

  if (!key) {
    // Fallback: clearly-prefixed base64 so decrypt() can detect it.
    return 'b64:' + Buffer.from(String(plaintext), 'utf8').toString('base64');
  }

  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  return [
    iv.toString('base64'),
    authTag.toString('base64'),
    encrypted.toString('base64')
  ].join(':');
}

/**
 * Decrypt a value produced by encrypt().
 *
 * @param {string} token  Result of encrypt()
 * @returns {string|null} Plaintext, or null if decryption fails.
 */
function decrypt(token) {
  if (token === null || token === undefined) return token;

  const str = String(token);

  // Fallback path: value was stored while key was absent.
  if (str.startsWith('b64:')) {
    return Buffer.from(str.slice(4), 'base64').toString('utf8');
  }

  const key = _getKey();
  if (!key) {
    // Key now missing but value looks encrypted — cannot decrypt.
    console.warn('[fieldEncryption] Cannot decrypt: ENCRYPTION_KEY is not set.');
    return null;
  }

  try {
    const parts = str.split(':');
    if (parts.length !== 3) throw new Error('Invalid ciphertext format');
    const [ivB64, tagB64, ctB64] = parts;
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const ciphertext = Buffer.from(ctB64, 'base64');

    if (iv.length !== IV_BYTES) throw new Error('Invalid IV length');
    if (authTag.length !== TAG_BYTES) throw new Error('Invalid auth tag length');

    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(ciphertext).toString('utf8') + decipher.final('utf8');
  } catch (err) {
    console.warn('[fieldEncryption] Decryption failed:', err.message);
    return null;
  }
}

module.exports = { encrypt, decrypt };
