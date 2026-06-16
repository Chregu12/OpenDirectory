'use strict';

const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * UserService
 *
 * CRUD operations for users.  All users-table access goes through the injected
 * userRepository (IUserRepository / PostgresUserRepository).  A db connection is
 * accepted for audit-log queries only — never for direct users-table access.
 *
 * Falls back to an in-memory store when the repository is unavailable so the
 * service stays operational without a database.
 */
class UserService {
  /**
   * @param {{ db?: object, userRepository?: import('../domain/repositories/IUserRepository'), logger?: object }} opts
   */
  constructor({ db, userRepository, logger: log } = {}) {
    this._db = db || null;                    // kept for audit log queries only
    this._userRepository = userRepository || null;
    this._logger = log || logger;

    // In-memory fallback store: Map<userId, userObject>
    this._users = new Map();
    this._byUsername = new Map();             // Map<username_lower, userId>
    this._byEmail = new Map();                // Map<email_lower, userId>

    this._mailer = this._createMailer();
  }

  // ── Initialisation ──────────────────────────────────────────────────────────

  _createMailer() {
    try {
      return nodemailer.createTransport({
        host: config.email.host,
        port: config.email.port,
        secure: config.email.secure,
        auth: config.email.user ? { user: config.email.user, pass: config.email.password } : undefined,
      });
    } catch (err) {
      this._logger.warn('UserService: failed to create mailer', { error: err.message });
      return null;
    }
  }

  // ── Shape helpers ───────────────────────────────────────────────────────────

  /**
   * Convert a UserAggregate or plain in-memory object to the public API shape.
   * Password hashes and MFA secrets are intentionally excluded.
   */
  _toPublic(source) {
    if (!source) return null;

    const isAggregate = typeof source.toJSON === 'function';
    if (isAggregate) {
      const j = source.toJSON();
      return {
        id: j.id,
        username: j.username,
        email: j.email || null,
        firstName: null,
        lastName: null,
        roles: j.roles,
        permissions: [],
        provider: 'local',
        mfaEnabled: j.mfaEnabled,
        isLocked: typeof source.isLocked === 'function' ? source.isLocked() : j.locked,
        lockReason: null,
        lockedUntil: j.lockUntil || null,
        passwordChangedAt: null,
        lastLogin: null,
        createdAt: j.createdAt,
        updatedAt: j.updatedAt,
        // NOTE: password_hash / mfaSecret / recoveryCodes are intentionally omitted
      };
    }

    // Plain in-memory object
    return {
      id: source.id,
      username: source.username,
      email: source.email || null,
      firstName: source.first_name || source.firstName || null,
      lastName: source.last_name || source.lastName || null,
      roles: this._parseJson(source.roles, ['user']),
      permissions: this._parseJson(source.permissions, []),
      provider: source.provider || 'local',
      mfaEnabled: source.mfa_enabled || source.mfaEnabled || false,
      isLocked: source.is_locked || source.isLocked || false,
      lockReason: source.lock_reason || source.lockReason || null,
      lockedUntil: source.locked_until || source.lockedUntil || null,
      passwordChangedAt: source.password_changed_at || source.passwordChangedAt || null,
      lastLogin: source.last_login || source.lastLogin || null,
      createdAt: source.created_at || source.createdAt,
      updatedAt: source.updated_at || source.updatedAt,
      // NOTE: password_hash is intentionally omitted
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
   * Create a new user via UserAggregate.create() + userRepository.save().
   */
  async createUser({ username, email, password, firstName, lastName, provider = 'local', roles, permissions }) {
    const UserAggregate = require('../domain/aggregates/UserAggregate');

    const passwordHash = password
      ? await bcrypt.hash(password, config.security.bcryptRounds || 12)
      : null;

    if (this._userRepository) {
      try {
        const aggregate = UserAggregate.create({
          id: uuidv4(),
          username,
          email: email || null,
          passwordHash,
          roles: roles || ['user'],
          provider,
        });
        await this._userRepository.save(aggregate);
        return this._toPublic(aggregate);
      } catch (err) {
        this._logger.warn('UserService.createUser: repository save failed', { error: err.message });
        if (err.code === '23505') {
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
      roles: roles || ['user'],
      permissions: permissions || [],
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
   * Find a user by ID via userRepository.findById().
   */
  async getUserById(id) {
    if (!id) return null;

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findById(id);
        return this._toPublic(aggregate);
      } catch (err) {
        this._logger.warn('UserService.getUserById: repository query failed', { error: err.message });
      }
    }

    return this._toPublic(this._users.get(id) || null);
  }

  /**
   * Find a user by username via userRepository.findByUsername().
   */
  async getUserByUsername(username) {
    if (!username) return null;

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findByUsername(username);
        return this._toPublic(aggregate);
      } catch (err) {
        this._logger.warn('UserService.getUserByUsername: repository query failed', { error: err.message });
      }
    }

    const id = this._byUsername.get(username.toLowerCase());
    return id ? this._toPublic(this._users.get(id) || null) : null;
  }

  /**
   * Find a user by email via userRepository.findByEmail().
   */
  async getUserByEmail(email) {
    if (!email) return null;

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findByEmail(email);
        return this._toPublic(aggregate);
      } catch (err) {
        this._logger.warn('UserService.getUserByEmail: repository query failed', { error: err.message });
      }
    }

    const id = this._byEmail.get(email.toLowerCase());
    return id ? this._toPublic(this._users.get(id) || null) : null;
  }

  /**
   * Update user fields.  Loads the aggregate via findById(), updates fields, saves.
   */
  async updateUser(id, updates) {
    if (!id) throw new Error('User ID required');

    // Strip fields that should never be updated via this method
    const { password, password_hash, id: _id, ...safe } = updates;

    const UserAggregate = require('../domain/aggregates/UserAggregate');

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findById(id);
        if (!aggregate) return null;

        // Build an updated aggregate with allowed field changes.
        // UserAggregate doesn't have a generic setField() method, so we rebuild it
        // with merged props while preserving identity/security fields.
        const json = aggregate.toJSON();
        const updatedAggregate = new UserAggregate({
          id: json.id,
          username: json.username,
          email: safe.email !== undefined ? safe.email : aggregate.email,
          passwordHash: aggregate.passwordHash,
          roles: safe.roles !== undefined ? safe.roles : aggregate.roles,
          mfaEnabled: safe.mfaEnabled !== undefined ? safe.mfaEnabled : aggregate.mfaEnabled,
          mfaSecret: aggregate.mfaSecret,
          recoveryCodes: aggregate.recoveryCodes,
          locked: safe.isLocked !== undefined ? safe.isLocked : aggregate.locked,
          lockUntil: safe.lockedUntil !== undefined ? safe.lockedUntil : aggregate.lockUntil,
          loginAttempts: aggregate.loginAttempts,
          createdAt: json.createdAt,
          updatedAt: new Date(),
        });

        await this._userRepository.save(updatedAggregate);
        return this._toPublic(updatedAggregate);
      } catch (err) {
        this._logger.warn('UserService.updateUser: repository update failed', { error: err.message });
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
   * Delete a user by ID via userRepository.delete().
   */
  async deleteUser(id) {
    if (!id) throw new Error('User ID required');

    if (this._userRepository) {
      try {
        await this._userRepository.delete(id);
        return true;
      } catch (err) {
        this._logger.warn('UserService.deleteUser: repository delete failed', { error: err.message });
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

    if (this._userRepository) {
      try {
        const filters = { limit, offset };
        const aggregates = await this._userRepository.findAll(filters);
        // findAll doesn't support search filtering natively — apply in-process
        let users = aggregates.map(a => this._toPublic(a));
        if (search) {
          const q = search.toLowerCase();
          users = users.filter(u =>
            (u.username || '').toLowerCase().includes(q) ||
            (u.email || '').toLowerCase().includes(q)
          );
        }
        return {
          users,
          total: users.length,
          page,
          limit,
          pages: Math.ceil(users.length / limit),
        };
      } catch (err) {
        this._logger.warn('UserService.listUsers: repository query failed', { error: err.message });
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
   * Change a user's password.  Loads aggregate, calls changePassword(), saves.
   */
  async changePassword(id, newPassword) {
    if (!id) throw new Error('User ID required');
    if (!newPassword) throw new Error('New password required');

    const hash = await bcrypt.hash(newPassword, config.security.bcryptRounds || 12);

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findById(id);
        if (!aggregate) throw new Error('User not found');
        aggregate.changePassword(hash);
        await this._userRepository.save(aggregate);
        return true;
      } catch (err) {
        this._logger.warn('UserService.changePassword: repository update failed', { error: err.message });
        throw err;
      }
    }

    // In-memory fallback
    const user = this._users.get(id);
    if (!user) throw new Error('User not found');
    user.password_hash = hash;
    user.password_changed_at = new Date().toISOString();
    user.updated_at = new Date().toISOString();
    this._users.set(id, user);
    return true;
  }

  /**
   * Lock a user account.  Loads aggregate, calls recordLoginFailure() iteratively
   * (or directly sets locked via aggregate rebuild), saves.
   *
   * @param {string} id
   * @param {string} reason
   * @param {number|null} durationMs  Duration in ms; null = permanent until unlocked.
   */
  async lockUser(id, reason = 'admin lock', durationMs = null) {
    if (!id) throw new Error('User ID required');

    const lockedUntil = durationMs ? new Date(Date.now() + durationMs) : null;

    const UserAggregate = require('../domain/aggregates/UserAggregate');

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findById(id);
        if (!aggregate) throw new Error('User not found');

        // Rebuild aggregate with lock applied
        const json = aggregate.toJSON();
        const locked = new UserAggregate({
          id: json.id,
          username: json.username,
          email: aggregate.email,
          passwordHash: aggregate.passwordHash,
          roles: aggregate.roles,
          mfaEnabled: aggregate.mfaEnabled,
          mfaSecret: aggregate.mfaSecret,
          recoveryCodes: aggregate.recoveryCodes,
          locked: true,
          lockUntil: lockedUntil,
          loginAttempts: aggregate.loginAttempts,
          createdAt: json.createdAt,
          updatedAt: new Date(),
        });
        await this._userRepository.save(locked);
        return true;
      } catch (err) {
        this._logger.warn('UserService.lockUser: repository update failed', { error: err.message });
        throw err;
      }
    }

    // In-memory fallback
    const user = this._users.get(id);
    if (!user) throw new Error('User not found');
    user.is_locked = true;
    user.lock_reason = reason;
    user.locked_until = lockedUntil ? lockedUntil.toISOString() : null;
    user.updated_at = new Date().toISOString();
    this._users.set(id, user);
    return true;
  }

  /**
   * Unlock a user account.  Loads aggregate, calls unlock(), saves.
   */
  async unlockUser(id) {
    if (!id) throw new Error('User ID required');

    if (this._userRepository) {
      try {
        const aggregate = await this._userRepository.findById(id);
        if (!aggregate) throw new Error('User not found');
        aggregate.unlock();
        await this._userRepository.save(aggregate);
        return true;
      } catch (err) {
        this._logger.warn('UserService.unlockUser: repository update failed', { error: err.message });
        throw err;
      }
    }

    // In-memory fallback
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
      this._logger.warn('UserService.sendPasswordResetEmail: no mailer configured');
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
      this._logger.info(`UserService.sendPasswordResetEmail: sent to ${email}`);
      return true;
    } catch (err) {
      this._logger.error('UserService.sendPasswordResetEmail: send failed', { error: err.message });
      return false;
    }
  }
}

module.exports = UserService;
