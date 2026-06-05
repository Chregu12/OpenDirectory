'use strict';

/**
 * ProtectedUsersPolicy — enforces restrictions for members of the Protected Users
 * security group (mirrors Windows Active Directory "Protected Users" group behaviour).
 *
 * Members receive these automatic security restrictions:
 *  - No NTLM, Digest, or CredSSP authentication (Kerberos only)
 *  - Kerberos tickets are NOT renewable beyond 4 hours
 *  - No Kerberos delegation (neither constrained nor unconstrained)
 *  - Kerberos AES encryption ONLY (RC4 and DES are prohibited)
 *
 * These restrictions cannot be overridden on a per-account basis — membership
 * in Protected Users is the control.
 */
class ProtectedUsersPolicy {
  /**
   * @param {import('pg').Pool} db - PostgreSQL connection pool
   */
  constructor(db) {
    this.db = db;

    // Maximum ticket life for Protected Users (4 hours in seconds)
    this.MAX_TICKET_LIFE_SECONDS = 4 * 60 * 60;

    // Prohibited operations for Protected Users
    this.RESTRICTED_OPERATIONS = new Set(['ntlm', 'delegation', 'ticket-renewal', 'rc4', 'des', 'digest', 'credssp']);
  }

  // ─── Membership Management ──────────────────────────────────────────────────

  /**
   * Add a user principal to the Protected Users group.
   *
   * @param {string} userPrincipal - UPN or SPN (e.g. 'alice@EXAMPLE.COM')
   * @param {string} addedBy - Administrator who performed the action (for audit)
   */
  async addMember(userPrincipal, addedBy) {
    await this.db.query(
      `INSERT INTO protected_users (user_principal, added_by)
       VALUES ($1, $2)
       ON CONFLICT (user_principal) DO NOTHING`,
      [userPrincipal, addedBy || null]
    );
    return { userPrincipal, addedBy, addedAt: new Date().toISOString() };
  }

  /**
   * Remove a user principal from the Protected Users group.
   *
   * @param {string} userPrincipal
   * @param {string} removedBy - Administrator who performed the action (for audit)
   */
  async removeMember(userPrincipal, removedBy) {
    const { rowCount } = await this.db.query(
      'DELETE FROM protected_users WHERE user_principal = $1',
      [userPrincipal]
    );
    return { removed: rowCount > 0, userPrincipal, removedBy };
  }

  /**
   * List all members of the Protected Users group.
   */
  async listMembers() {
    const { rows } = await this.db.query(
      'SELECT user_principal, added_at, added_by FROM protected_users ORDER BY user_principal'
    );
    return rows.map(row => ({
      userPrincipal: row.user_principal,
      addedAt: row.added_at,
      addedBy: row.added_by,
    }));
  }

  /**
   * Check whether a user principal is a member of Protected Users.
   * @param {string} userPrincipal
   * @returns {boolean}
   */
  async isMember(userPrincipal) {
    const { rows } = await this.db.query(
      'SELECT 1 FROM protected_users WHERE user_principal = $1',
      [userPrincipal]
    );
    return rows.length > 0;
  }

  // ─── Policy Enforcement ─────────────────────────────────────────────────────

  /**
   * Enforce Protected Users restrictions for a given operation.
   *
   * Call this during authentication or ticket issuance to determine whether
   * the requested operation is permitted for this principal.
   *
   * @param {string} userPrincipal
   * @param {'ntlm'|'delegation'|'ticket-renewal'|'rc4'|'des'|'digest'|'credssp'} requestedOperation
   * @returns {{ allowed: boolean, reason: string }}
   */
  async enforceRestrictions(userPrincipal, requestedOperation) {
    const member = await this.isMember(userPrincipal);
    if (!member) {
      return { allowed: true, reason: 'Not a Protected Users member — no restrictions applied' };
    }

    const op = requestedOperation.toLowerCase();

    if (this.RESTRICTED_OPERATIONS.has(op)) {
      const reasons = {
        ntlm: 'Protected Users members cannot authenticate via NTLM',
        digest: 'Protected Users members cannot authenticate via Digest authentication',
        credssp: 'Protected Users members cannot authenticate via CredSSP',
        delegation: 'Protected Users members cannot be delegated (Kerberos delegation prohibited)',
        'ticket-renewal': `Protected Users members cannot renew Kerberos tickets beyond ${this.MAX_TICKET_LIFE_SECONDS / 3600} hours`,
        rc4: 'Protected Users members must use AES encryption only (RC4 prohibited)',
        des: 'Protected Users members must use AES encryption only (DES prohibited)',
      };
      return {
        allowed: false,
        reason: reasons[op] || `Operation '${requestedOperation}' is prohibited for Protected Users members`,
      };
    }

    // Operation is permitted
    return {
      allowed: true,
      reason: `Operation '${requestedOperation}' is permitted for Protected Users members`,
    };
  }

  // ─── Reporting ──────────────────────────────────────────────────────────────

  /**
   * Generate a protection report summarising all Protected Users members
   * and the restrictions that apply to each.
   *
   * @returns {object} Summary report
   */
  async getProtectionReport() {
    const members = await this.listMembers();
    return {
      generatedAt: new Date().toISOString(),
      memberCount: members.length,
      restrictionsApplied: [
        'No NTLM authentication',
        'No Digest authentication',
        'No CredSSP authentication',
        `Maximum Kerberos ticket life: ${this.MAX_TICKET_LIFE_SECONDS / 3600} hours (non-renewable)`,
        'No Kerberos delegation (constrained or unconstrained)',
        'AES encryption only (RC4 and DES prohibited)',
      ],
      members,
    };
  }
}

module.exports = ProtectedUsersPolicy;
