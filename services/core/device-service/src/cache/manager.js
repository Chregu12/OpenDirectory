'use strict';

const logger = require('../utils/logger');

/**
 * CacheManager — wraps Redis with an in-memory fallback.
 */
class CacheManager {
  constructor() {
    this._mem = new Map();
    this._expiry = new Map();
    this._client = null;
    this._connect();
  }

  async _connect() {
    try {
      const config = require('../config');
      if (config.redis && config.redis.url && config.redis.url !== 'redis://localhost:6379') {
        const { createClient } = require('redis');
        this._client = createClient({ url: config.redis.url });
        this._client.on('error', (err) => logger.warn('Redis error:', err.message));
        await this._client.connect();
        logger.info('CacheManager: connected to Redis');
      } else {
        logger.warn('CacheManager: using in-memory cache (no REDIS_URL configured)');
      }
    } catch (err) {
      logger.warn(`CacheManager: Redis unavailable, using in-memory cache (${err.message})`);
      this._client = null;
    }
  }

  async get(key) {
    if (this._client) {
      try { return await this._client.get(key); } catch (e) { /* fall through */ }
    }
    const expiry = this._expiry.get(key);
    if (expiry && Date.now() > expiry) {
      this._mem.delete(key);
      this._expiry.delete(key);
      return null;
    }
    return this._mem.get(key) ?? null;
  }

  async set(key, value, ...args) {
    // args may be ['EX', seconds]
    let ttlMs = null;
    for (let i = 0; i < args.length - 1; i++) {
      if (String(args[i]).toUpperCase() === 'EX') ttlMs = parseInt(args[i + 1]) * 1000;
    }

    if (this._client) {
      try {
        if (ttlMs) return await this._client.set(key, value, { EX: Math.ceil(ttlMs / 1000) });
        return await this._client.set(key, value);
      } catch (e) { /* fall through */ }
    }

    this._mem.set(key, value);
    if (ttlMs) this._expiry.set(key, Date.now() + ttlMs);
    return 'OK';
  }

  async del(key) {
    if (this._client) {
      try { return await this._client.del(key); } catch (e) { /* fall through */ }
    }
    this._mem.delete(key);
    this._expiry.delete(key);
    return 1;
  }

  async healthCheck() {
    if (this._client) {
      try { await this._client.ping(); return { status: 'healthy' }; } catch (e) { /* fall through */ }
    }
    return { status: 'healthy' }; // in-memory is always healthy
  }

  close() {
    if (this._client) this._client.quit().catch(() => {});
  }
}

module.exports = CacheManager;
