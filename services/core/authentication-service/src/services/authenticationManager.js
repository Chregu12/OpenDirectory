'use strict';

const bcrypt = require('bcryptjs');
const ldap = require('ldapjs');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * AuthenticationManager
 *
 * Handles local password authentication, LDAP user mapping and LDAP user creation.
 *
 * All users-table access goes through the injected userRepository (IUserRepository).
 * The db connection is kept only for LDAP operations that do not touch the users table.
 */
class AuthenticationManager {
  /**
   * @param {{ db?: object, userRepository?: import('../domain/repositories/IUserRepository'), logger?: object }} opts
   */
  constructor({ db, userRepository, logger: log } = {}) {
    this._db = db || null;
    this._userRepository = userRepository || null;
    this._logger = log || logger;
    // In-memory fallback when neither DB nor repository is available
    this._users = new Map();
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  /**
   * Convert a UserAggregate (or plain row from the in-memory fallback) to the
   * public shape expected by the rest of the service.
   */
  _aggregateToPublic(aggregate) {
    if (!aggregate) return null;
    // UserAggregate has getters; plain objects have properties
    const isAggregate = typeof aggregate.toJSON === 'function';
    if (isAggregate) {
      return {
        id: aggregate.id,
        username: aggregate.username,
        email: aggregate.email,
        firstName: null,
        lastName: null,
        roles: aggregate.roles,
        permissions: [],
        provider: 'local',
        mfaEnabled: aggregate.mfaEnabled,
        isLocked: aggregate.isLocked ? aggregate.isLocked() : aggregate.locked,
        lockReason: null,
        lockedUntil: aggregate.lockUntil,
        lastLogin: null,
        // Expose hash for in-code bcrypt comparison (e.g., disableMFA / changePassword)
        password: aggregate.passwordHash,
      };
    }
    // In-memory plain object fallback
    const { password_hash, mfa_secret, ...safe } = aggregate;
    return {
      id: safe.id,
      username: safe.username,
      email: safe.email || null,
      firstName: safe.first_name || safe.firstName || null,
      lastName: safe.last_name || safe.lastName || null,
      roles: Array.isArray(safe.roles) ? safe.roles : (safe.roles ? JSON.parse(safe.roles) : ['user']),
      permissions: Array.isArray(safe.permissions) ? safe.permissions : (safe.permissions ? JSON.parse(safe.permissions) : []),
      provider: safe.provider || 'local',
      mfaEnabled: safe.mfa_enabled || safe.mfaEnabled || false,
      isLocked: safe.is_locked || safe.isLocked || false,
      lockReason: safe.lock_reason || safe.lockReason || null,
      lockedUntil: safe.locked_until || safe.lockedUntil || null,
      lastLogin: safe.last_login || safe.lastLogin || null,
      password: password_hash,
    };
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Authenticate a user with username + password (local strategy).
   * Uses userRepository.findByUsername() when available.
   * Returns the sanitised user object on success, null on failure.
   */
  async authenticateLocal(username, password) {
    if (!username || !password) return null;

    let aggregate = null;

    if (this._userRepository) {
      try {
        aggregate = await this._userRepository.findByUsername(username);
      } catch (err) {
        throw Object.assign(new Error('Credential storage unavailable'),{status:503});
      }
    }

    if (!aggregate && !this._userRepository) {
      // In-memory fallback
      const row = this._users.get(username.toLowerCase()) || null;
      if (!row) {
        // Dummy compare to prevent timing attacks
        await bcrypt.compare(password, '$2a$12$invalidhashpadding000000000000000000000000000000000000');
        return null;
      }
      aggregate = row;
    }
    if(!aggregate)return null;

    // Get password hash — aggregate vs plain object
    const hash = (typeof aggregate.passwordHash !== 'undefined')
      ? aggregate.passwordHash
      : (aggregate.password_hash || aggregate.password);

    if (!hash) return null;

    // Format-agnostic: stored hash may be bcrypt (legacy writes) or scrypt
    // (DDD Password value object writes, e.g. via
    // PasswordApplicationService.resetWithToken()). See utils/passwordHash
    // for the shared detection logic also used by
    // AuthApplicationService.login() and UserService.verifyCurrentPassword().
    const { verifyPasswordAnyFormat } = require('../utils/passwordHash');
    const valid = await verifyPasswordAnyFormat(password, hash);
    if (!valid) return null;

    // Check account lock
    const locked = (typeof aggregate.isLocked === 'function')
      ? aggregate.isLocked()
      : (aggregate.is_locked || aggregate.locked || false);
    const lockedUntil = aggregate.lockUntil || aggregate.locked_until || null;

    if (locked && (!lockedUntil || new Date(lockedUntil) > new Date())) {
      this._logger.warn(`AuthenticationManager: login attempt on locked account ${username}`);
      return null;
    }

    return this._aggregateToPublic(aggregate);
  }

  /**
   * Verify a plain-text password against a stored hash.
   *
   * Format-agnostic: `hash` may be bcrypt (legacy writes) or scrypt (DDD
   * Password value object writes). See utils/passwordHash for the shared
   * detection logic also used by AuthApplicationService.login() and
   * UserService.verifyCurrentPassword().
   */
  async verifyPassword(plaintext, hash) {
    if (!plaintext || !hash) return false;
    const { verifyPasswordAnyFormat } = require('../utils/passwordHash');
    return verifyPasswordAnyFormat(plaintext, hash);
  }

  /**
   * Hash a plain-text password.
   */
  async hashPassword(plaintext) {
    return bcrypt.hash(plaintext, config.security.bcryptRounds || 12);
  }

  /**
   * Map an LDAP user object to a local user shape, upserting via userRepository.
   */
  async mapLdapUser(ldapUser) {
    if (!ldapUser) throw new Error('No LDAP user provided');

    const username = ldapUser.uid || ldapUser.sAMAccountName || ldapUser.cn;
    const email = Array.isArray(ldapUser.mail) ? ldapUser.mail[0] : ldapUser.mail;
    const firstName = ldapUser.givenName || ldapUser.firstName || '';
    const lastName = ldapUser.sn || ldapUser.lastName || '';

    if (!username) throw new Error('LDAP user missing uid/sAMAccountName');

    return this._upsertSSOUser({
      username,
      email: email || null,
      firstName,
      lastName,
      provider: 'ldap',
    });
  }

  /**
   * Create a user in LDAP (called during local registration when syncNewUsers is true).
   */
  async createLdapUser(user) {
    return new Promise((resolve, reject) => {
      const client = ldap.createClient({ url: config.ldap.url });

      client.bind(config.ldap.bindDN, config.ldap.bindPassword, (bindErr) => {
        if (bindErr) {
          client.destroy();
          this._logger.error('AuthenticationManager.createLdapUser: bind failed', { error: bindErr.message });
          return reject(bindErr);
        }

        const dn = `uid=${user.username},${config.ldap.searchBase}`;
        const entry = {
          cn: user.username,
          sn: user.lastName || user.username,
          uid: user.username,
          mail: user.email,
          objectClass: ['inetOrgPerson', 'posixAccount', 'top'],
          uidNumber: String(Math.floor(Math.random() * 90000) + 10000),
          gidNumber: '500',
          homeDirectory: `/home/${user.username}`,
        };

        client.add(dn, entry, (addErr) => {
          client.unbind();
          client.destroy();
          if (addErr) {
            if (addErr.code === 68) {
              this._logger.info(`AuthenticationManager.createLdapUser: user ${user.username} already exists in LDAP`);
              return resolve(true);
            }
            this._logger.error('AuthenticationManager.createLdapUser: add failed', { error: addErr.message });
            return reject(addErr);
          }
          this._logger.info(`AuthenticationManager.createLdapUser: created ${dn}`);
          resolve(true);
        });
      });
    });
  }

  /**
   * Upsert an SSO/LDAP user via userRepository (findByUsername + save) or in-memory fallback.
   */
  async _upsertSSOUser({ username, email, firstName, lastName, provider }) {
    const UserAggregate = require('../domain/aggregates/UserAggregate');

    if (this._userRepository) {
      try {
        let aggregate = await this._userRepository.findByUsername(username);
        if (aggregate) {
          // User exists — update email/name via save (aggregate doesn't have a dedicated
          // "updateProfile" method, so we mutate directly through a new aggregate)
          const updated = new UserAggregate({
            id: aggregate.id,
            username: aggregate.username,
            email: email || aggregate.email,
            passwordHash: aggregate.passwordHash,
            roles: aggregate.roles,
            mfaEnabled: aggregate.mfaEnabled,
            mfaSecret: aggregate.mfaSecret,
            recoveryCodes: aggregate.recoveryCodes,
            locked: aggregate.locked,
            lockUntil: aggregate.lockUntil,
            loginAttempts: aggregate.loginAttempts,
            recordRevision: aggregate.recordRevision,
            securityRevision: aggregate.securityRevision,
            createdAt: aggregate.toJSON().createdAt,
            updatedAt: new Date(),
          });
          await this._userRepository.save(updated);
          return this._aggregateToPublic(updated);
        }

        // New user
        const newAggregate = UserAggregate.create({
          id: uuidv4(),
          username,
          email: email || null,
          passwordHash: null,
          roles: ['user'],
          provider,
        });
        await this._userRepository.save(newAggregate);
        return this._aggregateToPublic(newAggregate);
      } catch (err) {
        throw Object.assign(new Error('Credential storage unavailable'),{status:503});
      }
    }

    // In-memory fallback
    const key = username.toLowerCase();
    const existing = this._users.get(key);
    if (existing) return this._aggregateToPublic(existing);

    const user = {
      id: uuidv4(),
      username,
      email: email || null,
      first_name: firstName,
      last_name: lastName,
      roles: ['user'],
      permissions: [],
      provider,
      mfa_enabled: false,
      is_locked: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    this._users.set(key, user);
    return this._aggregateToPublic(user);
  }
}

module.exports = AuthenticationManager;
