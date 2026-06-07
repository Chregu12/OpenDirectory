'use strict';

/**
 * MFAService — TOTP-based Multi-Factor Authentication
 *
 * Uses speakeasy for TOTP secret generation and code verification,
 * and qrcode for otpauth QR images. Falls back to an in-memory Map
 * when PostgreSQL is unavailable.
 */

const speakeasy = require('speakeasy');
const QRCode   = require('qrcode');
const crypto   = require('crypto');
const db       = require('../db');

// ─── In-memory fallback stores ────────────────────────────────────────────────
const inMemorySecrets       = new Map(); // userId → base32 secret
const inMemoryEnabled       = new Map(); // userId → boolean
const inMemoryRecoveryCodes = new Map(); // userId → string[]

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Generate 10 one-time recovery codes (8 hex chars each).
 */
function generateRecoveryCodes(count = 10) {
  return Array.from({ length: count }, () => crypto.randomBytes(4).toString('hex').toUpperCase());
}

/**
 * Hash a recovery code for safe storage.
 */
function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

// ─── Database helpers (fail-silent) ───────────────────────────────────────────

async function dbSaveSecret(userId, secret, recoveryCodes) {
  if (!db.isAvailable()) return;
  try {
    const hashedCodes = recoveryCodes.map(hashCode);
    await db.query(
      `INSERT INTO mfa_secrets (user_id, totp_secret, recovery_codes, enabled, created_at, updated_at)
       VALUES ($1, $2, $3, false, NOW(), NOW())
       ON CONFLICT (user_id) DO UPDATE
         SET totp_secret    = EXCLUDED.totp_secret,
             recovery_codes = EXCLUDED.recovery_codes,
             enabled        = false,
             updated_at     = NOW()`,
      [userId, secret, JSON.stringify(hashedCodes)]
    );
  } catch (err) {
    console.warn('[mfa] dbSaveSecret error:', err.message);
  }
}

async function dbEnableMFA(userId) {
  if (!db.isAvailable()) return;
  try {
    await db.query(
      `UPDATE mfa_secrets SET enabled = true, updated_at = NOW() WHERE user_id = $1`,
      [userId]
    );
    await db.query(
      `UPDATE users SET mfa_enabled = true WHERE id = $1`,
      [userId]
    );
  } catch (err) {
    console.warn('[mfa] dbEnableMFA error:', err.message);
  }
}

async function dbDisableMFA(userId) {
  if (!db.isAvailable()) return;
  try {
    await db.query(
      `UPDATE mfa_secrets SET enabled = false, totp_secret = NULL, recovery_codes = '[]', updated_at = NOW()
       WHERE user_id = $1`,
      [userId]
    );
    await db.query(
      `UPDATE users SET mfa_enabled = false WHERE id = $1`,
      [userId]
    );
  } catch (err) {
    console.warn('[mfa] dbDisableMFA error:', err.message);
  }
}

async function dbGetSecret(userId) {
  if (!db.isAvailable()) return null;
  try {
    const result = await db.query(
      `SELECT totp_secret, enabled, recovery_codes FROM mfa_secrets WHERE user_id = $1`,
      [userId]
    );
    return result.rows[0] || null;
  } catch (err) {
    console.warn('[mfa] dbGetSecret error:', err.message);
    return null;
  }
}

async function dbConsumeRecoveryCode(userId, code) {
  if (!db.isAvailable()) return false;
  try {
    const row = await dbGetSecret(userId);
    if (!row || !row.recovery_codes) return false;

    let codes;
    try { codes = JSON.parse(row.recovery_codes); } catch { return false; }

    const hashed = hashCode(code.toUpperCase().replace(/-/g, ''));
    const idx = codes.indexOf(hashed);
    if (idx === -1) return false;

    // Remove used code
    codes.splice(idx, 1);
    await db.query(
      `UPDATE mfa_secrets SET recovery_codes = $1, updated_at = NOW() WHERE user_id = $2`,
      [JSON.stringify(codes), userId]
    );
    return true;
  } catch (err) {
    console.warn('[mfa] dbConsumeRecoveryCode error:', err.message);
    return false;
  }
}

// ─── MFAService class ─────────────────────────────────────────────────────────

class MFAService {
  /**
   * Generate a new TOTP secret for the user, persist it (pending confirmation),
   * and return the secret, a QR code data-URL, and recovery codes.
   *
   * @param {string} userId
   * @returns {{ secret: string, qrCode: string, recoveryCodes: string[] }}
   */
  async setupMFA(userId) {
    // Generate TOTP secret
    const secretObj = speakeasy.generateSecret({
      name:   `OpenDirectory (${userId})`,
      issuer: 'OpenDirectory',
      length: 20,
    });

    const secret = secretObj.base32;

    // Generate recovery codes (plain-text returned to user once)
    const recoveryCodes = generateRecoveryCodes(10);

    // Persist (not yet enabled — user must verify first)
    if (db.isAvailable()) {
      await dbSaveSecret(userId, secret, recoveryCodes);
    }

    // Always keep in-memory copy (acts as authoritative fallback)
    inMemorySecrets.set(String(userId), secret);
    inMemoryEnabled.set(String(userId), false);
    // Store plain codes in memory for recovery (only pre-enable)
    inMemoryRecoveryCodes.set(String(userId), recoveryCodes);

    // Also expose via global for the inline TOTP check in login handler
    if (!global.__od_userMfaSecrets) global.__od_userMfaSecrets = new Map();
    // Don't add to __od_userMfaSecrets yet — only after enableMFA is called

    if (!global.__od_speakeasy) global.__od_speakeasy = speakeasy;

    // Build otpauth URI and render QR code
    const otpauthUrl = secretObj.otpauth_url ||
      `otpauth://totp/OpenDirectory:${encodeURIComponent(userId)}?secret=${secret}&issuer=OpenDirectory`;

    const qrCode = await QRCode.toDataURL(otpauthUrl);

    return { secret, qrCode, recoveryCodes };
  }

  /**
   * Verify a TOTP code for a user.
   * Also accepts recovery codes (8-char hex, case-insensitive).
   *
   * @param {string} userId
   * @param {string} code
   * @returns {boolean}
   */
  async verifyCode(userId, code) {
    if (!code) return false;
    const uid = String(userId);

    // ── Try TOTP ──────────────────────────────────────────────────────────────
    const secret = await this._getSecret(uid);
    if (secret) {
      const totpValid = speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token:    String(code).replace(/\s/g, ''),
        window:   2, // allow ±2 time steps (60 s)
      });
      if (totpValid) return true;
    }

    // ── Try recovery code ─────────────────────────────────────────────────────
    const normalised = String(code).toUpperCase().replace(/[^A-F0-9]/g, '');
    if (normalised.length === 8) {
      // DB attempt first
      const consumed = await dbConsumeRecoveryCode(uid, normalised);
      if (consumed) return true;

      // In-memory fallback
      const memoryCodes = inMemoryRecoveryCodes.get(uid) || [];
      const idx = memoryCodes.findIndex(c => c === normalised);
      if (idx !== -1) {
        memoryCodes.splice(idx, 1);
        inMemoryRecoveryCodes.set(uid, memoryCodes);
        return true;
      }
    }

    return false;
  }

  /**
   * Mark MFA as fully enabled for a user (called after successful verifyCode).
   *
   * @param {string} userId
   */
  async enableMFA(userId) {
    const uid = String(userId);
    inMemoryEnabled.set(uid, true);

    // Expose secret to global in-memory TOTP store used by login handler
    const secret = inMemorySecrets.get(uid);
    if (secret) {
      if (!global.__od_userMfaSecrets) global.__od_userMfaSecrets = new Map();
      global.__od_userMfaSecrets.set(uid, secret);
    }

    await dbEnableMFA(uid);
  }

  /**
   * Disable MFA for a user and remove all associated secrets.
   *
   * @param {string} userId
   */
  async disableMFA(userId) {
    const uid = String(userId);
    inMemoryEnabled.set(uid, false);
    inMemorySecrets.delete(uid);
    inMemoryRecoveryCodes.delete(uid);

    // Remove from global in-memory TOTP store
    if (global.__od_userMfaSecrets) global.__od_userMfaSecrets.delete(uid);

    await dbDisableMFA(uid);
  }

  /**
   * Return the current set of recovery codes for a user.
   * Returns plain-text codes from the in-memory pre-enable store,
   * or an empty array if MFA is already enabled (codes were already shown).
   *
   * @param {string} userId
   * @returns {string[]}
   */
  async getRecoveryCodes(userId) {
    const uid = String(userId);

    // Only return plain codes while MFA setup is pending (not yet confirmed)
    // After enableMFA the codes are hashed in DB and can't be retrieved plain-text
    const enabled = inMemoryEnabled.get(uid) || false;
    if (!enabled) {
      return inMemoryRecoveryCodes.get(uid) || [];
    }

    // If DB available return count of remaining codes (not their values)
    if (db.isAvailable()) {
      try {
        const row = await dbGetSecret(uid);
        if (row && row.recovery_codes) {
          let codes;
          try { codes = JSON.parse(row.recovery_codes); } catch { codes = []; }
          // Return placeholders so the caller knows how many codes remain
          return codes.map((_, i) => `****-CODE-${i + 1}`);
        }
      } catch { /* fall through */ }
    }

    return [];
  }

  /**
   * Check whether MFA is currently enabled for a user.
   *
   * @param {string} userId
   * @returns {boolean}
   */
  async isMFAEnabled(userId) {
    const uid = String(userId);

    // In-memory is authoritative while DB is unavailable
    if (inMemoryEnabled.has(uid)) return inMemoryEnabled.get(uid);

    const row = await dbGetSecret(uid);
    if (row) {
      inMemoryEnabled.set(uid, row.enabled);
      if (row.enabled && row.totp_secret) {
        inMemorySecrets.set(uid, row.totp_secret);
        if (!global.__od_userMfaSecrets) global.__od_userMfaSecrets = new Map();
        global.__od_userMfaSecrets.set(uid, row.totp_secret);
      }
      return row.enabled;
    }

    return false;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  async _getSecret(userId) {
    // In-memory first
    if (inMemorySecrets.has(userId)) return inMemorySecrets.get(userId);

    // DB fallback
    const row = await dbGetSecret(userId);
    if (row && row.totp_secret) {
      inMemorySecrets.set(userId, row.totp_secret);
      return row.totp_secret;
    }

    return null;
  }
}

module.exports = MFAService;
