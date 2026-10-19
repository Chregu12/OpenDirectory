'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * TokenService
 *
 * Handles JWT access tokens, refresh tokens, temporary tokens, and password-reset
 * tokens.  Maintains a revocation set (in-memory with optional Redis persistence)
 * so tokens can be explicitly invalidated before their natural expiry.
 */
class TokenService {
  constructor() {
    // Revocation store: Set of jti (JWT ID) strings
    this._revokedTokens = new Set();
    // Refresh-token store: Map<refreshTokenHash, { userId, jti, expiresAt }>
    this._refreshTokens = new Map();
    // Temp-token store: Map<jti, { userId, expiresAt }>
    this._tempTokens = new Map();
    // Reset-token store: Map<token, { userId, expiresAt }>
    this._resetTokens = new Map();

    this._redisClient = null;
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
      logger.info('TokenService: Redis backend connected');
    } catch (err) {
      logger.warn('TokenService: Redis not available, using in-memory revocation store', { error: err.message });
      this._redisClient = null;
    }
  }

  _startCleanupTimer() {
    // Purge expired entries from in-memory stores every 10 minutes
    setInterval(() => this._cleanupExpired(), 10 * 60 * 1000).unref();
  }

  _cleanupExpired() {
    const now = Date.now();
    for (const [hash, entry] of this._refreshTokens) {
      if (entry.expiresAt < now) this._refreshTokens.delete(hash);
    }
    for (const [jti, entry] of this._tempTokens) {
      if (entry.expiresAt < now) this._tempTokens.delete(jti);
    }
    for (const [token, entry] of this._resetTokens) {
      if (entry.expiresAt < now) this._resetTokens.delete(token);
    }
  }

  // ── Token generation ────────────────────────────────────────────────────────

  /**
   * Generate a short-lived JWT access token for a user.
   */
  async generateAccessToken(user) {
    const jti = uuidv4();
    const payload = {
      sub: user.id,
      username: user.username,
      email: user.email,
      roles: user.roles || ['user'],
      permissions: user.permissions || [],
      jti,
      type: 'access',
    };

    const token = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    });

    return token;
  }

  /**
   * Generate a long-lived opaque refresh token.  The token itself is a random
   * string; its hash is stored alongside metadata.
   */
  async generateRefreshToken(user) {
    const rawToken = crypto.randomBytes(48).toString('hex');
    const tokenHash = this._hash(rawToken);
    const expiresAt = this._parseExpiry(config.jwt.refreshExpiresIn);

    const entry = {
      userId: user.id,
      username: user.username,
      jti: uuidv4(),
      expiresAt,
      createdAt: Date.now(),
    };

    if (this._redisClient) {
      try {
        const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
        await this._redisClient.set(
          `${config.redis.keyPrefix}refresh:${tokenHash}`,
          JSON.stringify(entry),
          'EX', ttlSeconds
        );
      } catch (err) {
        logger.warn('TokenService.generateRefreshToken: Redis write failed', { error: err.message });
        this._refreshTokens.set(tokenHash, entry);
      }
    } else {
      this._refreshTokens.set(tokenHash, entry);
    }

    return rawToken;
  }

  /**
   * Generate a short-lived temporary token (used for MFA challenge flows).
   */
  async generateTempToken(userId) {
    const jti = uuidv4();
    const expiresAt = this._parseExpiry(config.jwt.tempExpiresIn || '5m');

    const token = jwt.sign(
      { sub: userId, jti, type: 'temp' },
      config.jwt.secret,
      { expiresIn: config.jwt.tempExpiresIn || '5m', issuer: config.jwt.issuer }
    );

    this._tempTokens.set(jti, { userId, expiresAt });
    return token;
  }

  /**
   * Generate a password-reset token (opaque random string).
   */
  async generatePasswordResetToken(userId) {
    const rawToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = this._parseExpiry(config.jwt.resetExpiresIn || '1h');

    const entry = { userId, expiresAt, createdAt: Date.now() };

    if (this._redisClient) {
      try {
        const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
        await this._redisClient.set(
          `${config.redis.keyPrefix}reset:${rawToken}`,
          JSON.stringify(entry),
          'EX', ttlSeconds
        );
      } catch (err) {
        logger.warn('TokenService.generatePasswordResetToken: Redis write failed', { error: err.message });
        this._resetTokens.set(rawToken, entry);
      }
    } else {
      this._resetTokens.set(rawToken, entry);
    }

    return rawToken;
  }

  // ── Token verification ──────────────────────────────────────────────────────

  /**
   * Validate any JWT (access or temp).  Returns true/false.
   */
  async validateToken(token) {
    try {
      const decoded = jwt.verify(token, config.jwt.secret, {
        issuer: config.jwt.issuer,
        audience: config.jwt.audience,
      });

      // Check revocation
      if (decoded.jti && await this._isRevoked(decoded.jti)) {
        return false;
      }

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Exchange a valid refresh token for a new access token.
   * Returns { accessToken } or null.
   */
  async refreshAccessToken(rawRefreshToken) {
    const tokenHash = this._hash(rawRefreshToken);
    let entry = null;

    if (this._redisClient) {
      try {
        const raw = await this._redisClient.get(`${config.redis.keyPrefix}refresh:${tokenHash}`);
        if (raw) entry = JSON.parse(raw);
      } catch (err) {
        logger.warn('TokenService.refreshAccessToken: Redis read failed', { error: err.message });
      }
    }

    if (!entry) {
      entry = this._refreshTokens.get(tokenHash) || null;
    }

    if (!entry) return null;
    if (entry.expiresAt < Date.now()) {
      await this._deleteRefreshToken(tokenHash);
      return null;
    }

    // Look up the user to embed fresh claims
    let user = null;
    try {
      const UserService = require('./userService');
      // Avoid circular instantiation: reuse a shared singleton if possible
      if (!this._userServiceInstance) {
        this._userServiceInstance = new UserService();
      }
      user = await this._userServiceInstance.getUserById(entry.userId);
    } catch (err) {
      logger.warn('TokenService.refreshAccessToken: could not fetch user, using cached claims', { error: err.message });
    }

    const userForToken = user || { id: entry.userId, username: entry.username, roles: ['user'], permissions: [] };
    const accessToken = await this.generateAccessToken(userForToken);

    return { accessToken };
  }

  /**
   * Revoke a JWT by its jti claim so it cannot be used again.
   */
  async revokeToken(jti) {
    if (!jti) return;

    if (this._redisClient) {
      try {
        // Store revocation with a reasonable TTL (access token lifetime)
        const ttl = this._parseExpiry(config.jwt.expiresIn) - Date.now();
        const ttlSeconds = Math.max(60, Math.floor(ttl / 1000));
        await this._redisClient.set(
          `${config.redis.keyPrefix}revoked:${jti}`,
          '1',
          'EX', ttlSeconds
        );
        return;
      } catch (err) {
        logger.warn('TokenService.revokeToken: Redis write failed', { error: err.message });
      }
    }

    this._revokedTokens.add(jti);
  }

  /**
   * Verify and consume a password-reset token.
   * Returns the userId if valid, null otherwise.
   */
  async verifyPasswordResetToken(rawToken) {
    let entry = null;

    if (this._redisClient) {
      try {
        const raw = await this._redisClient.get(`${config.redis.keyPrefix}reset:${rawToken}`);
        if (raw) entry = JSON.parse(raw);
      } catch (err) {
        logger.warn('TokenService.verifyPasswordResetToken: Redis read failed', { error: err.message });
      }
    }

    if (!entry) {
      entry = this._resetTokens.get(rawToken) || null;
    }

    if (!entry || entry.expiresAt < Date.now()) {
      return null;
    }

    // One-time use — delete after verification
    if (this._redisClient) {
      try {
        await this._redisClient.del(`${config.redis.keyPrefix}reset:${rawToken}`);
      } catch { /* ignore */ }
    }
    this._resetTokens.delete(rawToken);

    return entry.userId;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  _hash(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

  /**
   * Parse a JWT-style duration string ("15m", "7d", "1h") into an absolute ms timestamp.
   */
  _parseExpiry(expiry) {
    const units = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    const match = String(expiry).match(/^(\d+)([smhd])$/);
    if (match) {
      return Date.now() + parseInt(match[1], 10) * (units[match[2]] || 1000);
    }
    // Numeric seconds fallback
    const seconds = parseInt(expiry, 10);
    return Date.now() + (isNaN(seconds) ? 900 : seconds) * 1000;
  }

  async _isRevoked(jti) {
    if (this._redisClient) {
      try {
        const exists = await this._redisClient.exists(`${config.redis.keyPrefix}revoked:${jti}`);
        return exists === 1;
      } catch (err) {
        logger.warn('TokenService._isRevoked: Redis read failed', { error: err.message });
      }
    }
    return this._revokedTokens.has(jti);
  }

  async _deleteRefreshToken(tokenHash) {
    if (this._redisClient) {
      try {
        await this._redisClient.del(`${config.redis.keyPrefix}refresh:${tokenHash}`);
      } catch { /* ignore */ }
    }
    this._refreshTokens.delete(tokenHash);
  }
}

module.exports = TokenService;
