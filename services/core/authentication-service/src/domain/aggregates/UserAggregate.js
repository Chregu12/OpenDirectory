'use strict';

const { randomUUID } = require('crypto');

/**
 * Domain event type constants for the authentication service.
 */
const AuthEvents = {
  USER_CREATED:  'auth.user.created',
  USER_LOCKED:   'auth.user.locked',
  USER_UNLOCKED: 'auth.user.unlocked',
  LOGIN_SUCCESS: 'auth.login.success',
  LOGIN_FAILED:  'auth.login.failed',
  MFA_ENABLED:   'auth.mfa.enabled',
  MFA_DISABLED:  'auth.mfa.disabled',
  PASSWORD_CHANGED: 'auth.password.changed',
};

const MAX_LOGIN_ATTEMPTS = 5;

/**
 * UserAggregate — Aggregate Root for a user identity.
 *
 * Encapsulates all state transitions and domain events for a user account.
 * Consumers must always go through the public command methods rather than
 * mutating properties directly.
 */
class UserAggregate {
  /**
   * @param {object} data
   */
  constructor(data) {
    this._validate(data);
    this.id             = data.id || null;
    this.username       = data.username;
    this.email          = data.email;
    this.passwordHash   = data.passwordHash || null;
    this.roles          = Array.isArray(data.roles) ? [...data.roles] : ['user'];
    this.loginAttempts  = typeof data.loginAttempts === 'number' ? data.loginAttempts : 0;
    this.lockedAt       = data.lockedAt ? new Date(data.lockedAt) : null;
    this.mfaEnabled     = !!data.mfaEnabled;
    this.mfaSecret      = data.mfaSecret || null;
    this.mfaBackupCodes = Array.isArray(data.mfaBackupCodes) ? [...data.mfaBackupCodes] : [];
    this.createdAt      = data.createdAt ? new Date(data.createdAt) : new Date();
    this.updatedAt      = data.updatedAt ? new Date(data.updatedAt) : new Date();
    this._domainEvents  = [];
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Create a new user and record a USER_CREATED domain event.
   * @param {object} props
   * @returns {UserAggregate}
   */
  static create(props) {
    const user = new UserAggregate(props);
    user._addDomainEvent(AuthEvents.USER_CREATED, {
      userId:   user.id,
      username: user.username,
      email:    user.email,
      roles:    user.roles
    });
    return user;
  }

  /**
   * Reconstitute a user from a persisted row (no domain event emitted).
   * @param {object} row
   * @returns {UserAggregate}
   */
  static fromRow(row) {
    return new UserAggregate({
      id:             row.id,
      username:       row.username,
      email:          row.email,
      passwordHash:   row.password_hash || row.passwordHash,
      roles:          row.roles || ['user'],
      loginAttempts:  row.login_attempts || row.loginAttempts || 0,
      lockedAt:       row.locked_at || row.lockedAt || null,
      mfaEnabled:     row.mfa_enabled || row.mfaEnabled || false,
      mfaSecret:      row.mfa_secret || row.mfaSecret || null,
      mfaBackupCodes: row.mfa_backup_codes || row.mfaBackupCodes || [],
      createdAt:      row.created_at || row.createdAt,
      updatedAt:      row.updated_at || row.updatedAt
    });
  }

  // ── Queries ────────────────────────────────────────────────────────────────

  /** Returns true if the account is currently locked. */
  isLocked() {
    return this.lockedAt !== null;
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Record a failed login attempt. Locks the account after MAX_LOGIN_ATTEMPTS.
   */
  recordLoginFailure() {
    this.loginAttempts += 1;
    this.updatedAt = new Date();

    this._addDomainEvent(AuthEvents.LOGIN_FAILED, {
      userId:        this.id,
      loginAttempts: this.loginAttempts
    });

    if (this.loginAttempts >= MAX_LOGIN_ATTEMPTS && !this.isLocked()) {
      this.lockedAt = new Date();
      this._addDomainEvent(AuthEvents.USER_LOCKED, {
        userId:    this.id,
        lockedAt:  this.lockedAt,
        reason:    'Too many failed login attempts'
      });
    }
  }

  /**
   * Record a successful login — resets the failed-attempt counter.
   */
  recordLoginSuccess() {
    this.loginAttempts = 0;
    this.lockedAt      = null;
    this.updatedAt     = new Date();

    this._addDomainEvent(AuthEvents.LOGIN_SUCCESS, {
      userId: this.id
    });
  }

  /**
   * Unlock the account (admin action).
   */
  unlock() {
    if (!this.isLocked()) return;
    this.lockedAt      = null;
    this.loginAttempts = 0;
    this.updatedAt     = new Date();

    this._addDomainEvent(AuthEvents.USER_UNLOCKED, {
      userId: this.id
    });
  }

  /**
   * Enable MFA for the user.
   * @param {string} secret  - TOTP secret
   * @param {string[]} codes - backup codes (plaintext; caller should hash before persisting)
   */
  enableMFA(secret, codes) {
    if (!secret) throw new Error('MFA secret is required');
    this.mfaEnabled     = true;
    this.mfaSecret      = secret;
    this.mfaBackupCodes = Array.isArray(codes) ? [...codes] : [];
    this.updatedAt      = new Date();

    this._addDomainEvent(AuthEvents.MFA_ENABLED, {
      userId: this.id
    });
  }

  /**
   * Disable MFA for the user.
   */
  disableMFA() {
    if (!this.mfaEnabled) return;
    this.mfaEnabled     = false;
    this.mfaSecret      = null;
    this.mfaBackupCodes = [];
    this.updatedAt      = new Date();

    this._addDomainEvent(AuthEvents.MFA_DISABLED, {
      userId: this.id
    });
  }

  // ── Domain events ──────────────────────────────────────────────────────────

  /**
   * Return and clear all pending domain events.
   * Call this after persisting the aggregate to dispatch events.
   * @returns {Array<{type: string, payload: object, occurredAt: Date, eventId: string}>}
   */
  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  // ── Serialisation ──────────────────────────────────────────────────────────

  toJSON() {
    return {
      id:             this.id,
      username:       this.username,
      email:          this.email,
      roles:          this.roles,
      loginAttempts:  this.loginAttempts,
      lockedAt:       this.lockedAt,
      mfaEnabled:     this.mfaEnabled,
      createdAt:      this.createdAt,
      updatedAt:      this.updatedAt
    };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _validate(data) {
    if (!data || typeof data !== 'object') throw new Error('User data must be an object');
    if (!data.username || typeof data.username !== 'string' || !data.username.trim()) {
      throw new Error('User username is required');
    }
    if (!data.email || typeof data.email !== 'string' || !data.email.trim()) {
      throw new Error('User email is required');
    }
  }

  _addDomainEvent(type, payload) {
    this._domainEvents.push({
      type,
      payload,
      occurredAt: new Date(),
      eventId:    randomUUID()
    });
  }
}

UserAggregate.AuthEvents = AuthEvents;
UserAggregate.MAX_LOGIN_ATTEMPTS = MAX_LOGIN_ATTEMPTS;

module.exports = UserAggregate;
