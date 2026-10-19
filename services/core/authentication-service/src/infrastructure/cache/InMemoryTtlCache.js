'use strict';

/**
 * InMemoryTtlCache
 *
 * Minimal Redis-shaped cache ({ get, set, del }) backed by a plain Map with
 * manual TTL expiry — used to give PasswordApplicationService a `cache`
 * dependency without introducing a hard runtime dependency on a real Redis
 * instance for password-reset tokens.
 *
 * Semantics intentionally mirror the ad-hoc `Map` + `expiresAt` bookkeeping
 * that routes/users.js previously did inline for `passwordResetTokens`:
 * entries are lazily evicted on read once past their expiry.
 */
class InMemoryTtlCache {
  constructor() {
    this._store = new Map();
  }

  /**
   * @param {string} key
   * @returns {Promise<string|null>}
   */
  async get(key) {
    const entry = this._store.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
      this._store.delete(key);
      return null;
    }
    return entry.value;
  }

  /**
   * @param {string} key
   * @param {string} value
   * @param {string} [mode] - 'EX' to set a TTL in seconds via the next argument (Redis-compatible signature)
   * @param {number} [ttlSeconds]
   * @returns {Promise<'OK'>}
   */
  async set(key, value, mode, ttlSeconds) {
    const expiresAt = (mode === 'EX' && typeof ttlSeconds === 'number')
      ? Date.now() + ttlSeconds * 1000
      : null;
    this._store.set(key, { value, expiresAt });
    return 'OK';
  }

  /**
   * @param {string} key
   * @returns {Promise<number>} 1 if a key was removed, 0 otherwise
   */
  async del(key) {
    const existed = this._store.delete(key);
    return existed ? 1 : 0;
  }
}

module.exports = InMemoryTtlCache;
