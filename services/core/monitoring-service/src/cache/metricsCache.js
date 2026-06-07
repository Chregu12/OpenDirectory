'use strict';

const logger = require('../utils/logger');

/**
 * MetricsCache — an in-memory TTL cache for hot metric values.
 *
 * Design: Map<key, { value, expiresAt }>
 * A lightweight lazy-expiration approach — entries are removed on the next
 * access or on the periodic sweep.
 */
class MetricsCache {
  constructor(options = {}) {
    this._store = new Map();
    this._defaultTtlMs = options.defaultTtlMs || 30000; // 30 s
    this._closed = false;

    // Sweep for expired entries every minute
    this._sweepTimer = setInterval(() => this._sweep(), 60000);
    if (this._sweepTimer.unref) this._sweepTimer.unref();

    logger.info('MetricsCache initialised (in-memory)');
  }

  // ---------------------------------------------------------------------------
  // Core operations
  // ---------------------------------------------------------------------------

  set(key, value, ttlMs) {
    const expiresAt = Date.now() + (ttlMs ?? this._defaultTtlMs);
    this._store.set(key, { value, expiresAt });
  }

  get(key) {
    const entry = this._store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this._store.delete(key);
      return null;
    }
    return entry.value;
  }

  has(key) {
    return this.get(key) !== null;
  }

  delete(key) {
    return this._store.delete(key);
  }

  clear() {
    this._store.clear();
  }

  // ---------------------------------------------------------------------------
  // Batch helpers
  // ---------------------------------------------------------------------------

  /**
   * Get or compute.  If the key is not cached the factory is called and the
   * result is stored.
   */
  async getOrSet(key, factory, ttlMs) {
    const cached = this.get(key);
    if (cached !== null) return cached;
    const value = await factory();
    this.set(key, value, ttlMs);
    return value;
  }

  /**
   * Invalidate all keys that match a prefix.
   */
  invalidatePrefix(prefix) {
    for (const key of this._store.keys()) {
      if (key.startsWith(prefix)) this._store.delete(key);
    }
  }

  size() {
    return this._store.size;
  }

  // ---------------------------------------------------------------------------
  // Maintenance
  // ---------------------------------------------------------------------------

  _sweep() {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this._store.entries()) {
      if (now > entry.expiresAt) {
        this._store.delete(key);
        removed++;
      }
    }
    if (removed > 0) {
      logger.debug('MetricsCache sweep', { removed });
    }
  }

  async close() {
    this._closed = true;
    if (this._sweepTimer) clearInterval(this._sweepTimer);
    logger.info('MetricsCache closed');
  }
}

module.exports = MetricsCache;
