'use strict';

const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * SessionManager
 *
 * Creates, retrieves, and revokes user sessions.  Uses Redis as the primary
 * backend when available and falls back to an in-memory Map otherwise.
 *
 * Session shape:
 *   { id, userId, ip, userAgent, deviceId, provider, createdAt, expiresAt, active }
 */
class SessionManager {
  constructor() {
    // In-memory fallback: Map<sessionId, sessionObject>
    this._sessions = new Map();
    // Index for efficient per-user lookup: Map<userId, Set<sessionId>>
    this._userIndex = new Map();

    this._redisClient = null;
    this._ttl = config.session.ttl || 86400; // seconds
    this._initRedis();
    this._startCleanupTimer();
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  async _initRedis() {
    try {
      const Redis = require('ioredis');
      this._redisClient = new Redis({
        host: config.redis.host,
        port: config.redis.port,
        password: config.redis.password,
        db: config.redis.db || 0,
        lazyConnect: true,
        enableOfflineQueue: false,
      });

      await this._redisClient.ping();
      logger.info('SessionManager: Redis backend connected');
    } catch (err) {
      logger.warn('SessionManager: Redis not available, using in-memory store', { error: err.message });
      this._redisClient = null;
    }
  }

  _startCleanupTimer() {
    // Purge expired in-memory sessions every 5 minutes
    setInterval(() => this._cleanupExpired(), 5 * 60 * 1000).unref();
  }

  _cleanupExpired() {
    const now = Date.now();
    for (const [id, session] of this._sessions) {
      if (!session.active || new Date(session.expiresAt).getTime() < now) {
        this._sessions.delete(id);
        const userSet = this._userIndex.get(session.userId);
        if (userSet) userSet.delete(id);
      }
    }
  }

  // ── Redis helpers ───────────────────────────────────────────────────────────

  _sessionKey(sessionId) {
    return `${config.redis.keyPrefix}session:${sessionId}`;
  }

  _userSessionsKey(userId) {
    return `${config.redis.keyPrefix}user-sessions:${userId}`;
  }

  async _redisGetSession(sessionId) {
    try {
      const raw = await this._redisClient.get(this._sessionKey(sessionId));
      return raw ? JSON.parse(raw) : null;
    } catch (err) {
      logger.warn('SessionManager: Redis get failed', { error: err.message });
      return null;
    }
  }

  async _redisSetSession(session) {
    try {
      const ttl = Math.max(
        1,
        Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000)
      );
      await this._redisClient.set(this._sessionKey(session.id), JSON.stringify(session), 'EX', ttl);
      // Track session ID in the per-user sorted set (score = expiresAt ms for easy pruning)
      await this._redisClient.zadd(
        this._userSessionsKey(session.userId),
        new Date(session.expiresAt).getTime(),
        session.id
      );
      // Expire the sorted set slightly after the last session would expire
      await this._redisClient.expire(this._userSessionsKey(session.userId), ttl + 60);
    } catch (err) {
      logger.warn('SessionManager: Redis set failed', { error: err.message });
      throw err;
    }
  }

  async _redisDeleteSession(sessionId, userId) {
    try {
      await this._redisClient.del(this._sessionKey(sessionId));
      if (userId) {
        await this._redisClient.zrem(this._userSessionsKey(userId), sessionId);
      }
    } catch (err) {
      logger.warn('SessionManager: Redis delete failed', { error: err.message });
    }
  }

  async _redisGetUserSessions(userId) {
    try {
      const now = Date.now();
      // Remove expired session IDs from the sorted set first
      await this._redisClient.zremrangebyscore(this._userSessionsKey(userId), '-inf', now);
      const ids = await this._redisClient.zrange(this._userSessionsKey(userId), 0, -1);

      const sessions = await Promise.all(ids.map(id => this._redisGetSession(id)));
      return sessions.filter(s => s !== null && s.active);
    } catch (err) {
      logger.warn('SessionManager: Redis user-sessions query failed', { error: err.message });
      return [];
    }
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Create a new session for a user.
   * @param {string} userId
   * @param {{ ip, userAgent, deviceId, provider }} meta
   * @returns {Promise<{ id, userId, expiresAt, ... }>}
   */
  async createSession(userId, meta = {}) {
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this._ttl * 1000);

    const session = {
      id: uuidv4(),
      userId,
      ip: meta.ip || null,
      userAgent: meta.userAgent || null,
      deviceId: meta.deviceId || null,
      provider: meta.provider || 'local',
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      active: true,
    };

    if (this._redisClient) {
      try {
        await this._redisSetSession(session);
        return session;
      } catch {
        // Fall through to in-memory
      }
    }

    // In-memory fallback
    this._sessions.set(session.id, session);
    if (!this._userIndex.has(userId)) this._userIndex.set(userId, new Set());
    this._userIndex.get(userId).add(session.id);

    return session;
  }

  /**
   * Retrieve a session by ID.
   * Returns null if not found, expired, or inactive.
   */
  async getSession(sessionId) {
    if (!sessionId) return null;

    if (this._redisClient) {
      const session = await this._redisGetSession(sessionId);
      if (!session || !session.active || new Date(session.expiresAt) < new Date()) {
        return null;
      }
      return session;
    }

    const session = this._sessions.get(sessionId);
    if (!session || !session.active || new Date(session.expiresAt) < new Date()) {
      return null;
    }
    return session;
  }

  /**
   * Return all active sessions for a user.
   */
  async getUserSessions(userId) {
    if (!userId) return [];

    if (this._redisClient) {
      return this._redisGetUserSessions(userId);
    }

    const ids = this._userIndex.get(userId) || new Set();
    const sessions = [];
    const now = new Date();
    for (const id of ids) {
      const s = this._sessions.get(id);
      if (s && s.active && new Date(s.expiresAt) > now) {
        sessions.push(s);
      }
    }
    return sessions;
  }

  /**
   * Revoke a specific session.
   * If userId is provided the session must belong to that user (ownership check).
   */
  async revokeSession(sessionId, userId = null) {
    if (!sessionId) return false;

    if (this._redisClient) {
      const session = await this._redisGetSession(sessionId);
      if (!session) return false;
      if (userId && session.userId !== userId) {
        throw new Error('Session does not belong to the specified user');
      }
      await this._redisDeleteSession(sessionId, session.userId);
      return true;
    }

    const session = this._sessions.get(sessionId);
    if (!session) return false;
    if (userId && session.userId !== userId) {
      throw new Error('Session does not belong to the specified user');
    }
    session.active = false;
    this._sessions.set(sessionId, session);
    const userSet = this._userIndex.get(session.userId);
    if (userSet) userSet.delete(sessionId);
    return true;
  }

  /**
   * Revoke all sessions for a user.
   */
  async revokeAllUserSessions(userId) {
    if (!userId) return 0;

    if (this._redisClient) {
      const sessions = await this._redisGetUserSessions(userId);
      await Promise.all(sessions.map(s => this._redisDeleteSession(s.id, userId)));
      try {
        await this._redisClient.del(this._userSessionsKey(userId));
      } catch { /* ignore */ }
      return sessions.length;
    }

    const ids = this._userIndex.get(userId) || new Set();
    let count = 0;
    for (const id of ids) {
      const s = this._sessions.get(id);
      if (s) {
        s.active = false;
        this._sessions.set(id, s);
        count++;
      }
    }
    this._userIndex.delete(userId);
    return count;
  }

  /**
   * Extend a session's expiry (e.g. on activity).
   */
  async touchSession(sessionId) {
    if (this._redisClient) {
      const session = await this._redisGetSession(sessionId);
      if (!session || !session.active) return null;
      session.expiresAt = new Date(Date.now() + this._ttl * 1000).toISOString();
      await this._redisSetSession(session);
      return session;
    }

    const session = this._sessions.get(sessionId);
    if (!session || !session.active) return null;
    session.expiresAt = new Date(Date.now() + this._ttl * 1000).toISOString();
    this._sessions.set(sessionId, session);
    return session;
  }
}

module.exports = SessionManager;
