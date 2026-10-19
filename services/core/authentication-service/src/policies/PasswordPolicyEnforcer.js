'use strict';

/**
 * PasswordPolicyEnforcer — Fine-Grained Password Policy (FGPP) enforcement.
 *
 * Mirrors Active Directory Fine-Grained Password Policies (PSOs — Password
 * Settings Objects). Multiple policies can exist; the effective policy for a
 * given user is the one with the highest precedence value that applies to the
 * user's group or to 'domain' (the domain-wide default).
 *
 * Wire-up note: instantiate this class after the database pool is available
 * and call its methods from:
 *   - Registration flow (validatePassword before creating account)
 *   - Password-change flow (validatePassword + addPasswordHistory)
 *   - Authentication flow (recordFailedAuth / recordSuccessfulAuth)
 *   - Session/middleware (checkPasswordAge to force rotation)
 *
 * Example:
 *   const enforcer = new PasswordPolicyEnforcer(db.pool);
 *   const result = await enforcer.validatePassword(userId, newPassword, adminUser);
 *   if (!result.valid) return res.status(400).json({ errors: result.errors });
 */
class PasswordPolicyEnforcer {
  /**
   * @param {import('pg').Pool} db - PostgreSQL connection pool
   */
  constructor(db) {
    this.db = db;
  }

  // ─── Policy CRUD ────────────────────────────────────────────────────────────

  /**
   * Create a new fine-grained password policy.
   *
   * @param {object} opts
   * @param {string}   opts.name                 - Unique policy name
   * @param {number}   opts.precedence            - Higher value wins when multiple policies apply
   * @param {string}   opts.appliesTo             - Group DN or 'domain' for domain-wide default
   * @param {number}   [opts.minLength=8]
   * @param {object}   [opts.complexity]          - { upperCase, lowerCase, digit, special, minCategories }
   * @param {number}   [opts.maxAge=90]           - Days until password expires
   * @param {number}   [opts.minAge=1]            - Minimum days before password can be changed
   * @param {number}   [opts.historyCount=10]     - Number of previous passwords to remember
   * @param {number}   [opts.lockoutThreshold=5]  - Failed attempts before lockout
   * @param {number}   [opts.lockoutDuration=30]  - Minutes account remains locked
   * @param {number}   [opts.lockoutWindow=30]    - Observation window in minutes for failure counting
   */
  async createPolicy({
    name,
    precedence = 0,
    appliesTo = 'domain',
    minLength = 8,
    complexity = { minCategories: 3 },
    maxAge = 90,
    minAge = 1,
    historyCount = 10,
    lockoutThreshold = 5,
    lockoutDuration = 30,
    lockoutWindow = 30,
  }) {
    const { rows } = await this.db.query(
      `INSERT INTO password_policies
         (name, precedence, applies_to, min_length, complexity, max_age_days, min_age_days,
          history_count, lockout_threshold, lockout_duration_minutes, lockout_observation_window_minutes)
       VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [name, precedence, appliesTo, minLength, JSON.stringify(complexity),
       maxAge, minAge, historyCount, lockoutThreshold, lockoutDuration, lockoutWindow]
    );
    return this._formatPolicy(rows[0]);
  }

  /**
   * Update an existing policy by ID.
   * @param {string} policyId - UUID
   * @param {object} updates  - Partial policy fields
   */
  async updatePolicy(policyId, updates) {
    const allowed = [
      'name', 'precedence', 'applies_to', 'min_length', 'complexity',
      'max_age_days', 'min_age_days', 'history_count',
      'lockout_threshold', 'lockout_duration_minutes', 'lockout_observation_window_minutes',
    ];
    const setClauses = [];
    const params = [];

    // Map camelCase update keys to snake_case DB columns
    const keyMap = {
      name: 'name',
      precedence: 'precedence',
      appliesTo: 'applies_to',
      minLength: 'min_length',
      complexity: 'complexity',
      maxAge: 'max_age_days',
      minAge: 'min_age_days',
      historyCount: 'history_count',
      lockoutThreshold: 'lockout_threshold',
      lockoutDuration: 'lockout_duration_minutes',
      lockoutWindow: 'lockout_observation_window_minutes',
    };

    for (const [camel, snake] of Object.entries(keyMap)) {
      if (updates[camel] !== undefined) {
        params.push(camel === 'complexity' ? JSON.stringify(updates[camel]) : updates[camel]);
        const cast = camel === 'complexity' ? '::jsonb' : '';
        setClauses.push(`${snake} = $${params.length}${cast}`);
      }
    }

    if (!setClauses.length) throw new Error('No valid fields to update');

    params.push(policyId);
    const { rows } = await this.db.query(
      `UPDATE password_policies SET ${setClauses.join(', ')} WHERE id = $${params.length} RETURNING *`,
      params
    );
    if (!rows.length) throw new Error('Policy not found');
    return this._formatPolicy(rows[0]);
  }

  /**
   * Delete a policy by ID.
   * @param {string} policyId - UUID
   */
  async deletePolicy(policyId) {
    const { rowCount } = await this.db.query(
      'DELETE FROM password_policies WHERE id = $1',
      [policyId]
    );
    return { deleted: rowCount > 0 };
  }

  /**
   * List all policies ordered by precedence (highest first).
   */
  async listPolicies() {
    const { rows } = await this.db.query(
      'SELECT * FROM password_policies ORDER BY precedence DESC, name'
    );
    return rows.map(r => this._formatPolicy(r));
  }

  /**
   * Determine the effective password policy for a given user.
   *
   * Resolution order:
   *  1. Find all policies that apply to the user's group memberships.
   *  2. Among those, pick the one with the highest precedence.
   *  3. Fall back to the 'domain' policy if no group-specific policy applies.
   *
   * @param {string} userId - User ID or UPN
   * @param {string[]} [groupDNs=[]] - Group DNs the user belongs to (for group-specific policies)
   * @returns {object} Effective policy
   */
  async getPolicyForUser(userId, groupDNs = []) {
    // Try group-specific policies first (highest precedence wins)
    if (groupDNs.length) {
      const { rows } = await this.db.query(
        `SELECT * FROM password_policies
         WHERE applies_to = ANY($1)
         ORDER BY precedence DESC
         LIMIT 1`,
        [groupDNs]
      );
      if (rows.length) return this._formatPolicy(rows[0]);
    }

    // Fall back to domain-wide policy
    const { rows } = await this.db.query(
      `SELECT * FROM password_policies
       WHERE applies_to = 'domain'
       ORDER BY precedence DESC
       LIMIT 1`
    );
    if (rows.length) return this._formatPolicy(rows[0]);

    // Absolute fallback (hardcoded defaults)
    return {
      name: 'Built-in Default',
      precedence: -1,
      appliesTo: 'domain',
      minLength: 8,
      complexity: { minCategories: 3 },
      maxAgeDays: 90,
      minAgeDays: 1,
      historyCount: 10,
      lockoutThreshold: 5,
      lockoutDurationMinutes: 30,
      lockoutObservationWindowMinutes: 30,
    };
  }

  // ─── Enforcement ────────────────────────────────────────────────────────────

  /**
   * Validate a new password against the effective policy for a user.
   *
   * @param {string} userId
   * @param {string} newPassword  - Plaintext (will NOT be stored; only validated and hashed for history)
   * @param {string} [requestedBy] - Who is requesting the change (admin, user, system)
   * @param {string[]} [groupDNs=[]] - User's group memberships for policy resolution
   * @returns {{ valid: boolean, errors: string[], historyViolation: boolean }}
   */
  async validatePassword(userId, newPassword, requestedBy, groupDNs = []) {
    const policy = await this.getPolicyForUser(userId, groupDNs);
    const errors = [];
    let historyViolation = false;

    // Length check
    if (newPassword.length < policy.minLength) {
      errors.push(`Password must be at least ${policy.minLength} characters long`);
    }

    // Complexity check
    const complexity = policy.complexity || {};
    const minCategories = complexity.minCategories || 3;
    const categories = [
      /[A-Z]/.test(newPassword),   // uppercase
      /[a-z]/.test(newPassword),   // lowercase
      /[0-9]/.test(newPassword),   // digit
      /[^A-Za-z0-9]/.test(newPassword), // special character
    ];
    const metCount = categories.filter(Boolean).length;

    if (complexity.upperCase && !/[A-Z]/.test(newPassword)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    if (complexity.lowerCase && !/[a-z]/.test(newPassword)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    if (complexity.digit && !/[0-9]/.test(newPassword)) {
      errors.push('Password must contain at least one digit');
    }
    if (complexity.special && !/[^A-Za-z0-9]/.test(newPassword)) {
      errors.push('Password must contain at least one special character');
    }
    if (metCount < minCategories) {
      errors.push(`Password must meet at least ${minCategories} of 4 character categories (upper, lower, digit, special)`);
    }

    // History check
    const history = await this.getPasswordHistory(userId, policy.historyCount);
    if (history.length > 0) {
      const bcrypt = require('bcrypt');
      for (const entry of history) {
        let matches = false;
        try { matches = await bcrypt.compare(newPassword, entry.passwordHash); } catch { /* skip */ }
        if (matches) { historyViolation = true; break; }
      }
      if (historyViolation) {
        errors.push(`Password was used recently — cannot reuse the last ${policy.historyCount} passwords`);
      }
    }

    return { valid: errors.length === 0, errors, historyViolation };
  }

  /**
   * Check whether a user's password has expired or is about to expire.
   *
   * @param {string} userId
   * @param {Date} [lastChanged] - When the password was last changed (defaults to querying history)
   * @param {string[]} [groupDNs=[]]
   * @returns {{ expired: boolean, daysUntilExpiry: number|null, mustChange: boolean }}
   */
  async checkPasswordAge(userId, lastChanged, groupDNs = []) {
    const policy = await this.getPolicyForUser(userId, groupDNs);

    // If maxAgeDays is 0, password never expires
    if (!policy.maxAgeDays) {
      return { expired: false, daysUntilExpiry: null, mustChange: false };
    }

    let changedAt = lastChanged;
    if (!changedAt) {
      // Try to infer from password history (most recent entry)
      const { rows } = await this.db.query(
        `SELECT changed_at FROM password_history WHERE user_id = $1 ORDER BY changed_at DESC LIMIT 1`,
        [userId]
      );
      changedAt = rows.length ? rows[0].changed_at : null;
    }

    if (!changedAt) {
      // No history; assume never changed — treat as expired if maxAgeDays > 0
      return { expired: true, daysUntilExpiry: 0, mustChange: true };
    }

    const now = new Date();
    const changed = new Date(changedAt);
    const ageMs = now - changed;
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    const daysUntilExpiry = Math.max(0, policy.maxAgeDays - ageDays);
    const expired = ageDays >= policy.maxAgeDays;

    return {
      expired,
      daysUntilExpiry: Math.round(daysUntilExpiry),
      mustChange: expired,
    };
  }

  /**
   * Record a failed authentication attempt and lock the account if threshold exceeded.
   *
   * @param {string} userId
   * @param {string} [ipAddress]
   * @param {string[]} [groupDNs=[]]
   * @returns {{ locked: boolean, failureCount: number, lockoutUntil: Date|null }}
   */
  async recordFailedAuth(userId, ipAddress, groupDNs = []) {
    const policy = await this.getPolicyForUser(userId, groupDNs);
    const windowMinutes = policy.lockoutObservationWindowMinutes || 30;
    const threshold = policy.lockoutThreshold || 5;
    const durationMinutes = policy.lockoutDurationMinutes || 30;

    // Reset counter if last failure was outside the observation window
    await this.db.query(
      `UPDATE auth_failure_tracking
       SET failure_count = 0, last_failure = NULL
       WHERE user_id = $1
         AND last_failure < NOW() - INTERVAL '${windowMinutes} minutes'
         AND (locked_until IS NULL OR locked_until < NOW())`,
      [userId]
    );

    // Upsert failure record
    const { rows } = await this.db.query(
      `INSERT INTO auth_failure_tracking (user_id, failure_count, last_failure, last_ip)
       VALUES ($1, 1, NOW(), $2::inet)
       ON CONFLICT (user_id) DO UPDATE
         SET failure_count = auth_failure_tracking.failure_count + 1,
             last_failure = NOW(),
             last_ip = $2::inet
       RETURNING failure_count, locked_until`,
      [userId, ipAddress || null]
    );

    const row = rows[0];
    const failureCount = row.failure_count;
    let locked = false;
    let lockoutUntil = row.locked_until;

    // Lock account if threshold reached and not already locked
    if (failureCount >= threshold && (!lockoutUntil || new Date(lockoutUntil) < new Date())) {
      lockoutUntil = new Date(Date.now() + durationMinutes * 60 * 1000);
      await this.db.query(
        'UPDATE auth_failure_tracking SET locked_until = $1 WHERE user_id = $2',
        [lockoutUntil, userId]
      );
      locked = true;
    } else if (lockoutUntil && new Date(lockoutUntil) > new Date()) {
      locked = true;
    }

    return { locked, failureCount, lockoutUntil: lockoutUntil || null };
  }

  /**
   * Record a successful authentication — resets the failure counter.
   * @param {string} userId
   */
  async recordSuccessfulAuth(userId) {
    await this.db.query(
      `UPDATE auth_failure_tracking
       SET failure_count = 0, last_failure = NULL, locked_until = NULL
       WHERE user_id = $1`,
      [userId]
    );
    return { userId, failureCountReset: true };
  }

  /**
   * Administratively unlock a locked account.
   * @param {string} userId
   * @param {string} unlockedBy - Administrator who performed the action
   */
  async unlockAccount(userId, unlockedBy) {
    await this.db.query(
      `UPDATE auth_failure_tracking
       SET failure_count = 0, last_failure = NULL, locked_until = NULL
       WHERE user_id = $1`,
      [userId]
    );
    return { userId, unlockedBy, unlockedAt: new Date().toISOString() };
  }

  // ─── Password History ───────────────────────────────────────────────────────

  /**
   * Retrieve the last N password hashes for a user (for history enforcement).
   * @param {string} userId
   * @param {number} count
   * @returns {Array<{ passwordHash: string, changedAt: Date }>}
   */
  async getPasswordHistory(userId, count = 10) {
    const { rows } = await this.db.query(
      `SELECT password_hash, changed_at
       FROM password_history
       WHERE user_id = $1
       ORDER BY changed_at DESC
       LIMIT $2`,
      [userId, count]
    );
    return rows.map(r => ({ passwordHash: r.password_hash, changedAt: r.changed_at }));
  }

  /**
   * Record a new password hash in the history table (call after password change).
   * @param {string} userId
   * @param {string} passwordHash - bcrypt hash of the new password
   */
  async addPasswordHistory(userId, passwordHash) {
    await this.db.query(
      `INSERT INTO password_history (user_id, password_hash)
       VALUES ($1, $2)
       ON CONFLICT (user_id, password_hash) DO NOTHING`,
      [userId, passwordHash]
    );
  }

  // ─── Internal Helpers ───────────────────────────────────────────────────────

  _formatPolicy(row) {
    return {
      id: row.id,
      name: row.name,
      precedence: row.precedence,
      appliesTo: row.applies_to,
      minLength: row.min_length,
      complexity: row.complexity,
      maxAgeDays: row.max_age_days,
      minAgeDays: row.min_age_days,
      historyCount: row.history_count,
      lockoutThreshold: row.lockout_threshold,
      lockoutDurationMinutes: row.lockout_duration_minutes,
      lockoutObservationWindowMinutes: row.lockout_observation_window_minutes,
      createdAt: row.created_at,
    };
  }
}

module.exports = PasswordPolicyEnforcer;
