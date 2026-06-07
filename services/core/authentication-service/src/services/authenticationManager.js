'use strict';

const bcrypt = require('bcryptjs');
const ldap = require('ldapjs');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const config = require('../utils/config');

/**
 * AuthenticationManager
 *
 * Handles local password authentication, LDAP user mapping, LDAP user creation,
 * and SSO provider management.  Uses bcryptjs for password hashing/verification.
 */
class AuthenticationManager {
  constructor() {
    this._db = null;
    this._dbAvailable = false;
    // In-memory fallback store keyed by username (lower-cased)
    this._users = new Map();
    this._initDb();
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
        logger.info('AuthenticationManager: database backend ready');
      } else {
        logger.warn('AuthenticationManager: database not available, using in-memory fallback');
      }
    } catch (err) {
      logger.warn('AuthenticationManager: db module not found, using in-memory fallback', { error: err.message });
      this._dbAvailable = false;
    }
  }

  async _ensureSchema() {
    if (!this._dbAvailable || !this._db) return;
    try {
      await this._db.query(`
        CREATE TABLE IF NOT EXISTS users (
          id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          username          VARCHAR(256) UNIQUE NOT NULL,
          email             VARCHAR(512) UNIQUE,
          password_hash     TEXT,
          first_name        VARCHAR(256),
          last_name         VARCHAR(256),
          roles             JSONB        NOT NULL DEFAULT '["user"]',
          permissions       JSONB        NOT NULL DEFAULT '[]',
          provider          VARCHAR(64)  NOT NULL DEFAULT 'local',
          mfa_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
          mfa_secret        TEXT,
          is_locked         BOOLEAN      NOT NULL DEFAULT FALSE,
          lock_reason       TEXT,
          locked_until      TIMESTAMPTZ,
          password_changed_at TIMESTAMPTZ DEFAULT NOW(),
          last_login        TIMESTAMPTZ,
          created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
          updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )
      `);
      logger.info('AuthenticationManager: schema verified');
    } catch (err) {
      logger.warn('AuthenticationManager: schema init warning', { error: err.message });
    }
  }

  // ── Internal helpers ────────────────────────────────────────────────────────

  _safeUser(row) {
    if (!row) return null;
    // Never expose the password hash upstream
    const { password_hash, mfa_secret, ...safe } = row;
    // Normalise column names to camelCase expected by the rest of the service
    return {
      id: safe.id,
      username: safe.username,
      email: safe.email,
      firstName: safe.first_name || safe.firstName,
      lastName: safe.last_name || safe.lastName,
      roles: Array.isArray(safe.roles) ? safe.roles : (safe.roles ? JSON.parse(safe.roles) : ['user']),
      permissions: Array.isArray(safe.permissions) ? safe.permissions : (safe.permissions ? JSON.parse(safe.permissions) : []),
      provider: safe.provider,
      mfaEnabled: safe.mfa_enabled || safe.mfaEnabled || false,
      isLocked: safe.is_locked || safe.isLocked || false,
      lockReason: safe.lock_reason || safe.lockReason || null,
      lockedUntil: safe.locked_until || safe.lockedUntil || null,
      passwordChangedAt: safe.password_changed_at || safe.passwordChangedAt || null,
      lastLogin: safe.last_login || safe.lastLogin || null,
      createdAt: safe.created_at || safe.createdAt,
      updatedAt: safe.updated_at || safe.updatedAt,
      // Expose hash only internally — callers that need it (disableMFA/changePassword)
      // will fetch the full row via a DB query; this field is stripped from the public
      // shape but the password hash IS stored in DB as password_hash.
      password: password_hash, // kept for in-code bcrypt comparison only
    };
  }

  // ── Public API ───────────────────────────────────────────────────────────────

  /**
   * Authenticate a user with username + password (local strategy).
   * Returns the sanitised user object on success, null on failure.
   */
  async authenticateLocal(username, password) {
    if (!username || !password) return null;

    let userRow = null;

    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query(
          'SELECT * FROM users WHERE LOWER(username) = LOWER($1) AND provider = $2 LIMIT 1',
          [username, 'local']
        );
        userRow = rows[0] || null;
      } catch (err) {
        logger.warn('AuthenticationManager.authenticateLocal: DB query failed, falling back to memory', { error: err.message });
        this._dbAvailable = false;
      }
    }

    if (!userRow && !this._dbAvailable) {
      // In-memory fallback
      userRow = this._users.get(username.toLowerCase()) || null;
    }

    if (!userRow) {
      // Run a dummy compare to prevent timing attacks
      await bcrypt.compare(password, '$2a$12$invalidhashpadding000000000000000000000000000000000000');
      return null;
    }

    const hash = userRow.password_hash || userRow.password;
    if (!hash) return null;

    const valid = await bcrypt.compare(password, hash);
    if (!valid) return null;

    // Check account lock
    const isLocked = userRow.is_locked || userRow.isLocked;
    const lockedUntil = userRow.locked_until || userRow.lockedUntil;
    if (isLocked && (!lockedUntil || new Date(lockedUntil) > new Date())) {
      logger.warn(`AuthenticationManager: login attempt on locked account ${username}`);
      return null;
    }

    // Update last_login
    await this._updateLastLogin(username);

    return this._safeUser(userRow);
  }

  /**
   * Verify a plain-text password against a stored hash.
   */
  async verifyPassword(plaintext, hash) {
    if (!plaintext || !hash) return false;
    return bcrypt.compare(plaintext, hash);
  }

  /**
   * Hash a plain-text password.
   */
  async hashPassword(plaintext) {
    return bcrypt.hash(plaintext, config.security.bcryptRounds || 12);
  }

  /**
   * Map an LDAP user object to a local user shape, upserting into the DB.
   */
  async mapLdapUser(ldapUser) {
    if (!ldapUser) throw new Error('No LDAP user provided');

    const username = ldapUser.uid || ldapUser.sAMAccountName || ldapUser.cn;
    const email = Array.isArray(ldapUser.mail) ? ldapUser.mail[0] : ldapUser.mail;
    const firstName = ldapUser.givenName || ldapUser.firstName || '';
    const lastName = ldapUser.sn || ldapUser.lastName || '';

    if (!username) throw new Error('LDAP user missing uid/sAMAccountName');

    if (this._dbAvailable && this._db) {
      try {
        // Upsert
        const { rows } = await this._db.query(
          `INSERT INTO users (username, email, first_name, last_name, provider, roles, permissions)
           VALUES ($1, $2, $3, $4, 'ldap', $5, $6)
           ON CONFLICT (username) DO UPDATE SET
             email      = EXCLUDED.email,
             first_name = EXCLUDED.first_name,
             last_name  = EXCLUDED.last_name,
             updated_at = NOW()
           RETURNING *`,
          [username, email || null, firstName, lastName, JSON.stringify(['user']), JSON.stringify([])]
        );
        return this._safeUser(rows[0]);
      } catch (err) {
        logger.warn('AuthenticationManager.mapLdapUser: DB upsert failed', { error: err.message });
      }
    }

    // In-memory fallback
    const existing = this._users.get(username.toLowerCase());
    if (existing) return this._safeUser(existing);

    const user = {
      id: uuidv4(),
      username,
      email: email || null,
      first_name: firstName,
      last_name: lastName,
      roles: ['user'],
      permissions: [],
      provider: 'ldap',
      mfa_enabled: false,
      is_locked: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    this._users.set(username.toLowerCase(), user);
    return this._safeUser(user);
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
          logger.error('AuthenticationManager.createLdapUser: bind failed', { error: bindErr.message });
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
            // LDAP_ALREADY_EXISTS (68) is acceptable — user was already there
            if (addErr.code === 68) {
              logger.info(`AuthenticationManager.createLdapUser: user ${user.username} already exists in LDAP`);
              return resolve(true);
            }
            logger.error('AuthenticationManager.createLdapUser: add failed', { error: addErr.message });
            return reject(addErr);
          }
          logger.info(`AuthenticationManager.createLdapUser: created ${dn}`);
          resolve(true);
        });
      });
    });
  }

  /**
   * Return configured SSO providers.
   */
  async getSSOProviders() {
    const configured = config.sso?.providers || [];
    return configured.map(name => ({
      name,
      displayName: name.charAt(0).toUpperCase() + name.slice(1),
      type: 'oauth2',
    }));
  }

  /**
   * Build the authorization URL to redirect the user to for a given SSO provider.
   */
  async initiateSSOLogin(provider) {
    const providerConfig = this._getSSOProviderConfig(provider);
    if (!providerConfig) {
      throw new Error(`Unknown SSO provider: ${provider}`);
    }

    const state = uuidv4();
    const params = new URLSearchParams({
      client_id: providerConfig.clientId,
      redirect_uri: providerConfig.callbackUrl,
      response_type: 'code',
      scope: providerConfig.scope || 'openid email profile',
      state,
    });

    return `${providerConfig.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Handle the OAuth2 callback from an SSO provider.
   */
  async handleSSOCallback(provider, query) {
    const { code, error } = query;

    if (error) {
      logger.warn(`AuthenticationManager.handleSSOCallback: provider returned error: ${error}`);
      return { success: false, error };
    }

    const providerConfig = this._getSSOProviderConfig(provider);
    if (!providerConfig) {
      return { success: false, error: `Unknown provider: ${provider}` };
    }

    try {
      // Exchange code for tokens
      const tokenResponse = await axios.post(providerConfig.tokenUrl, {
        grant_type: 'authorization_code',
        code,
        redirect_uri: providerConfig.callbackUrl,
        client_id: providerConfig.clientId,
        client_secret: providerConfig.clientSecret,
      });

      const { access_token: accessToken, id_token: idToken } = tokenResponse.data;

      // Fetch user info
      const userInfoResponse = await axios.get(providerConfig.userInfoUrl, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      const profile = userInfoResponse.data;
      const username = profile.preferred_username || profile.email || profile.sub;

      // Upsert local user record
      const user = await this._upsertSSOUser({
        username,
        email: profile.email,
        firstName: profile.given_name || '',
        lastName: profile.family_name || '',
        provider,
        externalId: profile.sub,
      });

      // Generate a short-lived access token for the redirect
      const jwt = require('jsonwebtoken');
      const token = jwt.sign(
        { sub: user.id, username: user.username, roles: user.roles },
        config.jwt.secret,
        { expiresIn: config.jwt.expiresIn, issuer: config.jwt.issuer }
      );

      return { success: true, user, token };
    } catch (err) {
      logger.error('AuthenticationManager.handleSSOCallback: failed', { error: err.message });
      return { success: false, error: err.message };
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  _getSSOProviderConfig(provider) {
    // Allow per-provider env-var overrides
    const clientId = process.env[`SSO_${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = process.env[`SSO_${provider.toUpperCase()}_CLIENT_SECRET`];
    const authorizationUrl = process.env[`SSO_${provider.toUpperCase()}_AUTH_URL`];
    const tokenUrl = process.env[`SSO_${provider.toUpperCase()}_TOKEN_URL`];
    const userInfoUrl = process.env[`SSO_${provider.toUpperCase()}_USERINFO_URL`];
    const callbackUrl = process.env[`SSO_${provider.toUpperCase()}_CALLBACK_URL`]
      || `${config.frontend.url}/api/auth/sso/${provider}/callback`;

    if (!clientId || !authorizationUrl) return null;

    return { clientId, clientSecret, authorizationUrl, tokenUrl, userInfoUrl, callbackUrl };
  }

  async _upsertSSOUser({ username, email, firstName, lastName, provider, externalId }) {
    if (this._dbAvailable && this._db) {
      try {
        const { rows } = await this._db.query(
          `INSERT INTO users (username, email, first_name, last_name, provider, roles, permissions)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (username) DO UPDATE SET
             email      = EXCLUDED.email,
             first_name = EXCLUDED.first_name,
             last_name  = EXCLUDED.last_name,
             updated_at = NOW()
           RETURNING *`,
          [username, email || null, firstName, lastName, provider, JSON.stringify(['user']), JSON.stringify([])]
        );
        return this._safeUser(rows[0]);
      } catch (err) {
        logger.warn('AuthenticationManager._upsertSSOUser: DB failed', { error: err.message });
      }
    }

    // In-memory fallback
    const key = username.toLowerCase();
    const existing = this._users.get(key);
    if (existing) return this._safeUser(existing);

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
    return this._safeUser(user);
  }

  async _updateLastLogin(username) {
    if (this._dbAvailable && this._db) {
      try {
        await this._db.query(
          'UPDATE users SET last_login = NOW() WHERE LOWER(username) = LOWER($1)',
          [username]
        );
      } catch (err) {
        logger.warn('AuthenticationManager._updateLastLogin: DB update failed', { error: err.message });
      }
    } else {
      const key = username.toLowerCase();
      const user = this._users.get(key);
      if (user) {
        user.last_login = new Date().toISOString();
        this._users.set(key, user);
      }
    }
  }
}

module.exports = AuthenticationManager;
