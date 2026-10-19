'use strict';

/**
 * Shared hash-format detection + verification for the two password-hash
 * formats that coexist in production:
 *
 *   - bcrypt ($2a$/$2b$/$2y$ prefix) — written by the legacy UserService /
 *     AuthenticationManager (createUser, changePassword, admin resets).
 *     This is what the overwhelming majority of real users have.
 *   - scrypt ("salt:derivedHex") — written by the DDD Password value
 *     object (PasswordApplicationService.resetWithToken()).
 *
 * The hash format must be detected up front rather than inferred from a
 * thrown exception: value-objects/Password exports the class directly
 * (module.exports = Password), so `const { Password } = require(...)`
 * would destructure `undefined`, making `Password.fromHash(...)` throw on
 * *every* call and silently fall through to a bcrypt-only code path — which
 * would coincidentally keep bcrypt logins working while leaving the
 * scrypt/VO path completely dead. Fixing that naively (still trying
 * Password.fromHash().verify() first, unconditionally) would regress in the
 * other direction: verify() does NOT throw on a bcrypt hash, it just
 * returns false (there's no ':' to split cleanly), so real bcrypt-hashed
 * users would silently fail with no fallback ever triggering. Detecting the
 * format explicitly up front avoids both failure modes.
 *
 * This module is the single source of truth for that detection, shared by
 * every code path that verifies a plaintext password against a stored hash:
 * AuthApplicationService.login(), UserService.verifyCurrentPassword(), and
 * AuthenticationManager.verifyPassword()/authenticateLocal().
 */

const BCRYPT_PREFIX_RE = /^\$2[aby]?\$/;

/**
 * @param {string} hash
 * @returns {boolean} true if `hash` looks like a bcrypt hash.
 */
function isBcryptHash(hash) {
  return BCRYPT_PREFIX_RE.test(hash || '');
}

/**
 * Verify a plaintext password against a stored hash, regardless of which of
 * the two supported formats (bcrypt or scrypt/Password-VO) it was written
 * in. Never throws — any error while hashing/comparing (malformed hash,
 * missing salt, etc.) resolves to `false`, matching the previous
 * bcrypt-only behavior of returning false rather than rejecting.
 *
 * @param {string} plaintext
 * @param {string} storedHash
 * @returns {Promise<boolean>}
 */
async function verifyPasswordAnyFormat(plaintext, storedHash) {
  if (!plaintext || !storedHash) return false;
  try {
    if (isBcryptHash(storedHash)) {
      const bcrypt = require('bcryptjs');
      return await bcrypt.compare(plaintext, storedHash);
    }
    const Password = require('../domain/value-objects/Password');
    const pw = Password.fromHash(storedHash);
    return await pw.verify(plaintext);
  } catch (e) {
    return false;
  }
}

module.exports = { isBcryptHash, verifyPasswordAnyFormat };
