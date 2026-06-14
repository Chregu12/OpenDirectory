'use strict';

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * UserService
 *
 * CRUD operations for users.  Uses the DB when available and falls back to an
 * in-memory store so the service stays operational without a database.
 *
 * Password hashing is handled here (bcryptjs) whenever a new user is created or
 * a password is changed.  The plaintext password is never stored.
 */
class UserService {
  constructor() {
    this._db = null;
    this._dbAvailable = false;
    // In-memory store: Map<userId, userObject>
    this._users = new Map();
    // Secondary index: Map<username_lower, userId>
    this._byUsername = new Map();
    // Secondary index: Map<email_lower, userId>
    this._byEmail = new Map();

    this._initDb();
    this._mailer = this._createMailer();
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  async _initDb() {
    try {
      const db = require('../db');
      this._db = db;
      this._dbAvailable = typeof db.isAvailable === 'function'
        ? await db.isAvailable()
        : true;

      if (this._dbAvailable) {
        await this._ensureSchema();
        logger.info('UserService: database backend ready');
      } else {
        logger.warn('UserService: database not available, using in-memory fallback');
      }
    } catch (err) {
      logger.warn('UserService: db module not found, using in-memory fallback', { error: err.message });
      this._dbAvailable = false;
    }
  }

  async _ensureSchema() {
    if (!this._dbAvailable || !this._db) return;
    try {
      // Table may already exist (created by AuthenticationManager); use IF NOT EXISTS
      await this._db.query(`
        CREATE TABLE IF NOT EXISTS users (
          id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          username            VARCHAR(256) UNIQUE NOT NULL,
          email               VARCHAR(512) UNIQUE,
          password_hash       TEXT,
          first_name          VARCHAR(256),
          last_name           VARCHAR(256),
          roles               JSONB        NOT NULL DEFAULT '["user"]',
          permissions         JSONB        NOT NULL DEFAULT '[]',
          provider            VARCHAR(64)  NOT NULL DEFAULT 'local',
          mfa_enabled         BOOLEAN      NOT NULL DEFAULT FALSE,
          mfa_secret          TEXT,
          is_locked           BOOLEAN      NOT NULL DEFAULT FALSE,
          lock_reason         TEXT,
          locked_until        TIMESTAMPTZ,
          password_changed_at TIMESTAMPTZ  DEFAULT NOW(),
          last_login          TIMESTAMPTZ,
          created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      logger.info('UserService: schema verified');
    } catch (err) {
      logger.warn('UserService: schema init warning', { error: err.message });
    }
  }

  _createMailer() {
    try {
      return nodemailer.createTransport({
        host: config.email.host,
        port: config.email.port,
        secure: config.email.secure,
        auth: config.email.user ? { user: config.email.user, pass: config.email.password } : undefined,
      });
    } catch (err) {
      logger.warn('UserService: failed to create mailer', { error: err.message });
      return null;
    }
  }

  // ── Shape helpers ───────────────────────────────────────────────────────────

  _toPublic(row) {
    if (!row) return null;
    return {
      id: row.id,
      username: row.username,
      email: row.email || null,
      firstName: row.first_name || row.firstName || null,
      lastName: row.last_name || row.lastName || null,
      roles: this._parseJson(row.roles, ['user']),
      permissions: this._parseJson(row.permissions, []),
      provider: row.provider || 'local',
      mfaEnabled: row.mfa_enabled || row.mfaEnabled || false,
      isLocked: row.is_locked || row.isLocked || false,
      lockReason: row.lock_reason || row.lockReason || null,
      lockedUntil: row.locked_until || row.lockedUntil || null,
      passwordChangedAt: row.password_changed_at || row.passwordChangedAt || null,
      lastLogin: row.last_login || row.lastLogin || null,
      createdAt: row.created_at || row.createdAt,
      updatedAt: row.updated_at || row.updatedAt,
      // expose hash only for internal password verification
      password: row.password_hash || row.password || null,
    };
  }

  _parseJson(value, fallback) {
    if (Array.isArray(value)) return value;
    if (typeof value === 'string') {
      try { return JSON.parse(value); } catch { return fallback; }
    }
    return fallback;
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Validate registration input.
   * Returns { valid: boolean, errors: string[] }
   */
  async validateRegistration(data) {
    const errors = [];
    const { username, email, password } = data;

    if (!username || username.trim().length < 3) {
      errors.push('Username must be at least 3 characters');
    }
    if (username && !/^[a-zA-Z0-9._-]+$/.test(username)) {
      errors.push('Username may only contain letters, digits, dots, hyphens, and underscores');
    }
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push('A valid email address is required');
    }
    if (!password || password.length < (config.security.passwordMinLength || 8)) {
      errors.push(`Password must be at least ${config.security.passwordMinLength || 8} characters`);
    }
    if (password && password.length > (config.security.passwordMaxLength || 128)) {
      errors.push(`Password must not exceed ${config.security.passwordMaxLength || 128} characters`);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Create a new user.  Hashes the password before persisting.
   */
  async createUser({ username, email, password, firstName, lastName, provider = 'local', roles, permissions }) {
    const passwordHash = password
      ? await bcrypt.hash(password, config.security.bcryptRounds || 12)
      : null;

    const rolesJson = JSON.stringify(roles || ['user']);
    const permissionsJson = JSON.stringify(permissions || []);

    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query(
          `INSERT INTO users
             (username, email, password_hash, first_name, last_name, provider, roles, permissions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING *`,
          [username, email || null, passwordHash, firstName || null, lastName || null,
           provider, rolesJson, permissionsJson]
        );
        return this._toPublic(rows[0]);
      } catch (err) {
        logger.warn('UserService.createUser: DB insert failed', { error: err.message });
        if (err.code === '23505') {
          // Unique violation
          throw Object.assign(new Error('User already exists'), { status: 409 });
        }
        throw err;
      }
    }

    // In-memory fallback
    const key = username.toLowerCase();
    if (this._byUsername.has(key)) {
      throw Object.assign(new Error('User already exists'), { status: 409 });
    }

    const id = uuidv4();
    const now = new Date().toISOString();
    const user = {
      id,
      username,
      email: email || null,
      password_hash: passwordHash,
      first_name: firstName || null,
      last_name: lastName || null,
      roles: JSON.parse(rolesJson),
      permissions: JSON.parse(permissionsJson),
      provider,
      mfa_enabled: false,
      is_locked: false,
      password_changed_at: now,
      created_at: now,
      updated_at: now,
    };
    this._users.set(id, user);
    this._byUsername.set(key, id);
    if (email) this._byEmail.set(email.toLowerCase(), id);

    return this._toPublic(user);
  }

  /**
   * Find a user by ID.
   */
  async getUserById(id) {
    if (!id) return null;

    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [id]);
        return this._toPublic(rows[0] || null);
      } catch (err) {
        logger.warn('UserService.getUserById: DB query failed', { error: err.message });
      }
    }

    return this._toPublic(this._users.get(id) || null);
  }

  /**
   * Find a user by username (case-insensitive).
   */
  async getUserByUsername(username) {
    if (!username) return null;

    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query(
          'SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
          [username]
        );
        return this._toPublic(rows[0] || null);
      } catch (err) {
        logger.warn('UserService.getUserByUsername: DB query failed', { error: err.message });
      }
    }

    const id = this._byUsername.get(username.toLowerCase());
    return id ? this._toPublic(this._users.get(id) || null) : null;
  }

  /**
   * Find a user by email (case-insensitive).
   */
  async getUserByEmail(email) {
    if (!email) return null;

    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query(
          'SELECT * FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1',
          [email]
        );
        return this._toPublic(rows[0] || null);
      } catch (err) {
        logger.warn('UserService.getUserByEmail: DB query failed', { error: err.message });
      }
    }

    const id = this._byEmail.get(email.toLowerCase());
    return id ? this._toPublic(this._users.get(id) || null) : null;
  }

  /**
   * Update user fields.  Protected fields (id, username, password, roles) are
   * stripped upstream in the route handler before reaching here; we strip them
   * again defensively.
   */
  async updateUser(id, updates) {
    if (!id) throw new Error('User ID required');

    // Strip fields that should never be updated via this method
    const { password, password_hash, id: _id, ...safe } = updates;

    if (this._dbAvailable && this._db) {
      try {
        const setClauses = [];
        const params = [];
        let idx = 1;

        const columnMap = {
          email: 'email',
          firstName: 'first_name',
          lastName: 'last_name',
          roles: 'roles',
          permissions: 'permissions',
          provider: 'provider',
          mfaEnabled: 'mfa_enabled',
          isLocked: 'is_locked',
          lockReason: 'lock_reason',
          lockedUntil: 'locked_until',
          lastLogin: 'last_login',
        };

        for (const [key, col] of Object.entries(columnMap)) {
          if (Object.prototype.hasOwnProperty.call(safe, key)) {
            setClauses.push(`${col} = $${idx++}`);
            const value = (key === 'roles' || key === 'permissions')
              ? JSON.stringify(safe[key])
              : safe[key];
            params.push(value);
          }
        }

        if (setClauses.length === 0) return this.getUserById(id);

        setClauses.push(`updated_at = NOW()`);
        params.push(id);

        const { rows } = await this._db.query(
          `UPDATE users SET ${setClauses.join(', ')} WHERE id = $${idx} RETURNING *`,
          params
        );
        return this._toPublic(rows[0] || null);
      } catch (err) {
        logger.warn('UserService.updateUser: DB update failed', { error: err.message });
        throw err;
      }
    }

    // In-memory fallback
    const user = this._users.get(id);
    if (!user) return null;

    if (safe.email !== undefined) {
      if (user.email) this._byEmail.delete(user.email.toLowerCase());
      user.email = safe.email;
      if (safe.email) this._byEmail.set(safe.email.toLowerCase(), id);
    }
    if (safe.firstName !== undefined) user.first_name = safe.firstName;
    if (safe.lastName !== undefined) user.last_name = safe.lastName;
    if (safe.roles !== undefined) user.roles = safe.roles;
    if (safe.permissions !== undefined) user.permissions = safe.permissions;
    if (safe.mfaEnabled !== undefined) user.mfa_enabled = safe.mfaEnabled;
    if (safe.isLocked !== undefined) user.is_locked = safe.isLocked;
    if (safe.lockReason !== undefined) user.lock_reason = safe.lockReason;
    if (safe.lockedUntil !== undefined) user.locked_until = safe.lockedUntil;
    if (safe.lastLogin !== undefined) user.last_login = safe.lastLogin;
    user.updated_at = new Date().toISOString();

    this._users.set(id, user);
    return this._toPublic(user);
  }

  /**
   * Delete a user by ID.
   */
  async deleteUser(id) {
    if (!id) throw new Error('User ID required');

    if (this._dbAvailable && this._db) {
      try {
        const { rowCount } = await this._db.query('DELETE FROM users WHERE id = $1', [id]);
        return rowCount > 0;
      } catch (err) {
        logger.warn('UserService.deleteUser: DB delete failed', { error: err.message });
        throw err;
      }
    }

    const user = this._users.get(id);
    if (!user) return false;
    this._byUsername.delete((user.username || '').toLowerCase());
    if (user.email) this._byEmail.delete(user.email.toLowerCase());
    this._users.delete(id);
    return true;
  }

  /**
   * List users with pagination and optional search.
   */
  async listUsers({ page = 1, limit = 50, search } = {}) {
    const offset = (Math.max(1, page) - 1) * limit;

    if (this._dbAvailable && this._db) {
      try {
        const params = [];
        let where = '';
        if (search) {
          where = `WHERE username ILIKE $1 OR email ILIKE $1`;
          params.push(`%${search}%`);
        }
        params.push(limit);
        params.push(offset);

        const [{ rows }, { rows: countRows }] = await Promise.all([
          this._db.query(
            `SELECT * FROM users ${where} ORDER BY created_at DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
          ),
          this._db.query(
            `SELECT COUNT(*) AS total FROM users ${where}`,
            search ? [`%${search}%`] : []
          ),
        ]);

        return {
          users: rows.map(r => this._toPublic(r)),
          total: parseInt(countRows[0].total, 10),
          page,
          limit,
          pages: Math.ceil(parseInt(countRows[0].total, 10) / limit),
        };
      } catch (err) {
        logger.warn('UserService.listUsers: DB query failed', { error: err.message });
      }
    }

    // In-memory fallback
    let users = [...this._users.values()].map(u => this._toPublic(u));
    if (search) {
      const q = search.toLowerCase();
      users = users.filter(u =>
        (u.username || '').toLowerCase().includes(q) ||
        (u.email || '').toLowerCase().includes(q)
      );
    }
    users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const total = users.length;

    return {
      users: users.slice(offset, offset + limit),
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    };
  }

  /**
   * Change a user's password.  Hashes the new password and bumps passwordChangedAt.
   */
  async changePassword(id, newPassword) {
    if (!id) throw new Error('User ID required');
    if (!newPassword) throw new Error('New password required');

    const hash = await bcrypt.hash(newPassword, config.security.bcryptRounds || 12);
    const now = new Date().toISOString();

    if (this._dbAvailable && this._db) {
      try {
        await this._db.query(
          'UPDATE users SET password_hash = $1, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2',
          [hash, id]
        );
        return true;
      } catch (err) {
        logger.warn('UserService.changePassword: DB update failed', { error: err.message });
        throw err;
      }
    }

    const user = this._users.get(id);
    if (!user) throw new Error('User not found');
    user.password_hash = hash;
    user.password_changed_at = now;
    user.updated_at = now;
    this._users.set(id, user);
    return true;
  }

  /**
   * Lock a user account.
   * @param {string} id
   * @param {string} reason
   * @param {number|null} durationMs  Duration in ms; null = permanent until unlocked.
   */
  async lockUser(id, reason = 'admin lock', durationMs = null) {
    if (!id) throw new Error('User ID required');
    const lockedUntil = durationMs ? new Date(Date.now() + durationMs).toISOString() : null;

    if (this._dbAvailable && this._db) {
      try {
        await this._db.query(
          `UPDATE users SET is_locked = TRUE, lock_reason = $1, locked_until = $2, updated_at = NOW()
           WHERE id = $3`,
          [reason, lockedUntil, id]
        );
        return true;
      } catch (err) {
        logger.warn('UserService.lockUser: DB update failed', { error: err.message });
        throw err;
      }
    }

    const user = this._users.get(id);
    if (!user) throw new Error('User not found');
    user.is_locked = true;
    user.lock_reason = reason;
    user.locked_until = lockedUntil;
    user.updated_at = new Date().toISOString();
    this._users.set(id, user);
    return true;
  }

  /**
   * Unlock a user account.
   */
  async unlockUser(id) {
    if (!id) throw new Error('User ID required');

    if (this._dbAvailable && this._db) {
      try {
        await this._db.query(
          `UPDATE users SET is_locked = FALSE, lock_reason = NULL, locked_until = NULL, updated_at = NOW()
           WHERE id = $1`,
          [id]
        );
        return true;
      } catch (err) {
        logger.warn('UserService.unlockUser: DB update failed', { error: err.message });
        throw err;
      }
    }

    const user = this._users.get(id);
    if (!user) throw new Error('User not found');
    user.is_locked = false;
    user.lock_reason = null;
    user.locked_until = null;
    user.updated_at = new Date().toISOString();
    this._users.set(id, user);
    return true;
  }

  /**
   * Send a password-reset email.
   */
  async sendPasswordResetEmail(email, resetToken) {
    if (!this._mailer) {
      logger.warn('UserService.sendPasswordResetEmail: no mailer configured');
      return false;
    }

    const resetUrl = `${config.frontend.url}/reset-password?token=${resetToken}`;

    try {
      await this._mailer.sendMail({
        from: config.email.from,
        to: email,
        subject: 'Password Reset Request – OpenDirectory',
        text: `You requested a password reset.\n\nClick the link below to reset your password (valid for 1 hour):\n\n${resetUrl}\n\nIf you did not request this, ignore this email.`,
        html: `<p>You requested a password reset.</p>
               <p><a href="${resetUrl}">Reset your password</a> (valid for 1 hour)</p>
               <p>If you did not request this, ignore this email.</p>`,
      });
      logger.info(`UserService.sendPasswordResetEmail: sent to ${email}`);
      return true;
    } catch (err) {
      logger.error('UserService.sendPasswordResetEmail: send failed', { error: err.message });
      return false;
    }
  }
}

module.exports = UserService;
