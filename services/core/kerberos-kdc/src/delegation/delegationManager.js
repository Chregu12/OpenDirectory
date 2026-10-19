'use strict';

/**
 * DelegationManager — manages Kerberos delegation types for the KDC.
 *
 * Supports:
 *  - Constrained delegation (KCD) via S4U2Self / S4U2Proxy
 *  - Resource-Based Constrained Delegation (RBCD)
 *  - Unconstrained delegation (legacy, audit/security purposes)
 *
 * All delegation attempts are written to the delegation_audit table for
 * compliance and forensic review.
 */
class DelegationManager {
  /**
   * @param {import('pg').Pool} db - PostgreSQL connection pool
   */
  constructor(db) {
    this.db = db;
  }

  // ─── Constrained Delegation (KCD) ──────────────────────────────────────────

  /**
   * Configure constrained delegation for a service principal.
   *
   * @param {string} servicePrincipal - The service account that will delegate (e.g. 'http/web.example.com')
   * @param {{ allowedTargets: string[], protocol: 'kerberos-only' | 'any' }} opts
   *   - allowedTargets: SPNs this service is trusted to delegate to
   *   - protocol: 'kerberos-only' restricts to pure Kerberos; 'any' also allows
   *     NTLM→Kerberos protocol transition via S4U2Self
   */
  async setConstrainedDelegation(servicePrincipal, { allowedTargets = [], protocol = 'kerberos-only' } = {}) {
    await this.db.query(
      `INSERT INTO delegation_config (service_principal, delegation_type, allowed_targets, protocol, updated_at)
       VALUES ($1, 'constrained', $2::jsonb, $3, NOW())
       ON CONFLICT (service_principal, delegation_type)
       DO UPDATE SET allowed_targets = $2::jsonb, protocol = $3, updated_at = NOW()`,
      [servicePrincipal, JSON.stringify(allowedTargets), protocol]
    );
    return { servicePrincipal, allowedTargets, protocol };
  }

  /**
   * Retrieve constrained delegation configuration for a service principal.
   * @returns {object|null}
   */
  async getConstrainedDelegation(servicePrincipal) {
    const { rows } = await this.db.query(
      `SELECT * FROM delegation_config
       WHERE service_principal = $1 AND delegation_type = 'constrained'`,
      [servicePrincipal]
    );
    if (!rows.length) return null;
    const row = rows[0];
    return {
      servicePrincipal: row.service_principal,
      allowedTargets: row.allowed_targets,
      protocol: row.protocol,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  /**
   * Remove constrained delegation configuration for a service principal.
   */
  async removeConstrainedDelegation(servicePrincipal) {
    const { rowCount } = await this.db.query(
      `DELETE FROM delegation_config
       WHERE service_principal = $1 AND delegation_type = 'constrained'`,
      [servicePrincipal]
    );
    return { removed: rowCount > 0 };
  }

  // ─── Resource-Based Constrained Delegation (RBCD) ──────────────────────────

  /**
   * Configure RBCD on a resource (target service).
   * The resource itself declares which principals are allowed to delegate to it.
   *
   * @param {string} resourcePrincipal - The target resource SPN
   * @param {{ allowedDelegators: string[] }} opts
   *   - allowedDelegators: service account DNs/principals permitted to delegate
   */
  async setRBCD(resourcePrincipal, { allowedDelegators = [] } = {}) {
    await this.db.query(
      `INSERT INTO rbcd_config (resource_principal, allowed_delegators, updated_at)
       VALUES ($1, $2::jsonb, NOW())
       ON CONFLICT (resource_principal)
       DO UPDATE SET allowed_delegators = $2::jsonb, updated_at = NOW()`,
      [resourcePrincipal, JSON.stringify(allowedDelegators)]
    );
    return { resourcePrincipal, allowedDelegators };
  }

  /**
   * Retrieve RBCD configuration for a resource principal.
   * @returns {object|null}
   */
  async getRBCD(resourcePrincipal) {
    const { rows } = await this.db.query(
      'SELECT * FROM rbcd_config WHERE resource_principal = $1',
      [resourcePrincipal]
    );
    if (!rows.length) return null;
    const row = rows[0];
    return {
      resourcePrincipal: row.resource_principal,
      allowedDelegators: row.allowed_delegators,
      updatedAt: row.updated_at,
    };
  }

  /**
   * Remove RBCD configuration from a resource principal.
   */
  async removeRBCD(resourcePrincipal) {
    const { rowCount } = await this.db.query(
      'DELETE FROM rbcd_config WHERE resource_principal = $1',
      [resourcePrincipal]
    );
    return { removed: rowCount > 0 };
  }

  // ─── List Delegations ───────────────────────────────────────────────────────

  /**
   * List delegation configurations.
   * @param {{ type: 'constrained' | 'rbcd' | 'unconstrained' | 'all' }} opts
   */
  async listDelegations({ type = 'all' } = {}) {
    const result = { constrained: [], rbcd: [], unconstrained: [] };

    if (type === 'all' || type === 'constrained' || type === 'unconstrained') {
      const types = type === 'all'
        ? ['constrained', 'unconstrained']
        : [type];
      const { rows } = await this.db.query(
        `SELECT * FROM delegation_config WHERE delegation_type = ANY($1) ORDER BY service_principal`,
        [types]
      );
      for (const row of rows) {
        const entry = {
          servicePrincipal: row.service_principal,
          allowedTargets: row.allowed_targets,
          protocol: row.protocol,
          updatedAt: row.updated_at,
        };
        if (row.delegation_type === 'constrained') result.constrained.push(entry);
        else result.unconstrained.push(entry);
      }
    }

    if (type === 'all' || type === 'rbcd') {
      const { rows } = await this.db.query(
        'SELECT * FROM rbcd_config ORDER BY resource_principal'
      );
      result.rbcd = rows.map(row => ({
        resourcePrincipal: row.resource_principal,
        allowedDelegators: row.allowed_delegators,
        updatedAt: row.updated_at,
      }));
    }

    return result;
  }

  // ─── S4U2Self ───────────────────────────────────────────────────────────────

  /**
   * Simulate S4U2Self: service obtains a ticket on behalf of a user.
   *
   * S4U2Self allows a service to obtain a service ticket for itself on behalf
   * of any user (including those who authenticated via non-Kerberos means like
   * NTLM). The resulting ticket's forwardable flag depends on the delegation
   * configuration:
   *  - constrained delegation with protocol='any' → forwardable ticket produced
   *  - kerberos-only → ticket is NOT forwardable (cannot be used for S4U2Proxy)
   *
   * @param {string} servicePrincipal
   * @param {string} userPrincipal
   * @returns {{ allowed: boolean, reason: string, effectiveTicket: object }}
   */
  async simulateS4U2Self(servicePrincipal, userPrincipal) {
    // Check if the service has constrained delegation configured
    const config = await this.getConstrainedDelegation(servicePrincipal);

    // Check Protected Users membership via delegation_config lookup
    // (ProtectedUsersPolicy is a separate class; here we just check
    //  delegation config — actual Protected Users check happens in ProtectedUsersPolicy)

    if (!config) {
      // No constrained delegation configured; S4U2Self produces a non-forwardable ticket
      const effectiveTicket = {
        userPrincipal,
        servicePrincipal,
        forwardable: false,
      };
      await this.logDelegationAttempt({
        servicePrincipal,
        targetSPN: servicePrincipal,
        userPrincipal,
        type: 's4u2self',
        allowed: true,
        reason: 'S4U2Self allowed; no constrained delegation — ticket not forwardable',
      });
      return {
        allowed: true,
        reason: 'S4U2Self allowed; ticket is not forwardable (no constrained delegation configured)',
        effectiveTicket,
      };
    }

    // With constrained delegation configured, forwardability depends on protocol
    const forwardable = config.protocol === 'any';
    const effectiveTicket = { userPrincipal, servicePrincipal, forwardable };
    const reason = forwardable
      ? 'S4U2Self allowed; ticket is forwardable (protocol transition enabled)'
      : 'S4U2Self allowed; ticket is NOT forwardable (kerberos-only — no protocol transition)';

    await this.logDelegationAttempt({
      servicePrincipal,
      targetSPN: servicePrincipal,
      userPrincipal,
      type: 's4u2self',
      allowed: true,
      reason,
    });

    return { allowed: true, reason, effectiveTicket };
  }

  // ─── S4U2Proxy ──────────────────────────────────────────────────────────────

  /**
   * Validate S4U2Proxy: can service use an evidence ticket to access targetServiceSPN?
   *
   * S4U2Proxy requires:
   *  1. The evidence ticket (obtained via S4U2Self or normal authentication) is forwardable.
   *  2. The service has either:
   *     a. Constrained delegation configured and targetServiceSPN is in allowedTargets, OR
   *     b. RBCD configured on targetServiceSPN listing this servicePrincipal as an allowed delegator.
   *
   * @param {string} servicePrincipal
   * @param {string} targetServiceSPN
   * @param {{ forwardable: boolean, userPrincipal: string }} evidenceTicket
   * @returns {{ allowed: boolean, reason: string, delegationType: string|null }}
   */
  async validateS4U2Proxy(servicePrincipal, targetServiceSPN, evidenceTicket = {}) {
    if (!evidenceTicket.forwardable) {
      await this.logDelegationAttempt({
        servicePrincipal,
        targetSPN: targetServiceSPN,
        userPrincipal: evidenceTicket.userPrincipal || null,
        type: 's4u2proxy',
        allowed: false,
        reason: 'Evidence ticket is not forwardable',
      });
      return { allowed: false, reason: 'Evidence ticket is not forwardable', delegationType: null };
    }

    // Check constrained delegation (KCD)
    const kcdConfig = await this.getConstrainedDelegation(servicePrincipal);
    if (kcdConfig) {
      const targets = Array.isArray(kcdConfig.allowedTargets) ? kcdConfig.allowedTargets : [];
      if (targets.includes(targetServiceSPN)) {
        await this.logDelegationAttempt({
          servicePrincipal,
          targetSPN: targetServiceSPN,
          userPrincipal: evidenceTicket.userPrincipal || null,
          type: 's4u2proxy',
          allowed: true,
          reason: 'Constrained delegation (KCD): target SPN in allowedTargets',
        });
        return {
          allowed: true,
          reason: 'Allowed via constrained delegation (KCD)',
          delegationType: 'constrained',
        };
      }
    }

    // Check RBCD on the target resource
    const rbcdConfig = await this.getRBCD(targetServiceSPN);
    if (rbcdConfig) {
      const delegators = Array.isArray(rbcdConfig.allowedDelegators)
        ? rbcdConfig.allowedDelegators
        : [];
      if (delegators.includes(servicePrincipal)) {
        await this.logDelegationAttempt({
          servicePrincipal,
          targetSPN: targetServiceSPN,
          userPrincipal: evidenceTicket.userPrincipal || null,
          type: 's4u2proxy',
          allowed: true,
          reason: 'Resource-Based Constrained Delegation (RBCD): service in allowedDelegators',
        });
        return {
          allowed: true,
          reason: 'Allowed via Resource-Based Constrained Delegation (RBCD)',
          delegationType: 'rbcd',
        };
      }
    }

    const reason = 'S4U2Proxy denied: service not authorized to delegate to target (no KCD or RBCD grant)';
    await this.logDelegationAttempt({
      servicePrincipal,
      targetSPN: targetServiceSPN,
      userPrincipal: evidenceTicket.userPrincipal || null,
      type: 's4u2proxy',
      allowed: false,
      reason,
    });
    return { allowed: false, reason, delegationType: null };
  }

  // ─── Unconstrained Delegation (Legacy) ─────────────────────────────────────

  /**
   * Enable or disable unconstrained delegation for a principal.
   * WARNING: Unconstrained delegation is a significant security risk.
   * Any service with unconstrained delegation can impersonate any user that
   * authenticates to it against any service in the domain.
   *
   * @param {string} principal
   * @param {boolean} enabled
   */
  async setUnconstrainedDelegation(principal, enabled) {
    if (enabled) {
      await this.db.query(
        `INSERT INTO delegation_config (service_principal, delegation_type, allowed_targets, protocol, updated_at)
         VALUES ($1, 'unconstrained', '[]'::jsonb, 'any', NOW())
         ON CONFLICT (service_principal, delegation_type)
         DO UPDATE SET updated_at = NOW()`,
        [principal]
      );
    } else {
      await this.db.query(
        `DELETE FROM delegation_config
         WHERE service_principal = $1 AND delegation_type = 'unconstrained'`,
        [principal]
      );
    }
    return { principal, unconstrainedDelegation: enabled };
  }

  /**
   * List all principals with unconstrained delegation (security audit).
   */
  async listUnconstrainedDelegations() {
    const { rows } = await this.db.query(
      `SELECT service_principal, created_at, updated_at
       FROM delegation_config
       WHERE delegation_type = 'unconstrained'
       ORDER BY service_principal`
    );
    return rows.map(row => ({
      servicePrincipal: row.service_principal,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      securityRisk: 'HIGH — unconstrained delegation allows impersonation of any authenticating user',
    }));
  }

  // ─── Audit Log ─────────────────────────────────────────────────────────────

  /**
   * Write a delegation attempt to the audit log.
   *
   * @param {{ servicePrincipal, targetSPN, userPrincipal, type, allowed, reason }} opts
   */
  async logDelegationAttempt({ servicePrincipal, targetSPN, userPrincipal, type, allowed, reason }) {
    try {
      await this.db.query(
        `INSERT INTO delegation_audit (service_principal, target_spn, user_principal, delegation_type, allowed, reason)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [servicePrincipal, targetSPN || null, userPrincipal || null, type, allowed, reason]
      );
    } catch (err) {
      console.error('[DelegationManager] Failed to write audit log:', err.message);
    }
  }

  /**
   * Query the delegation audit log.
   *
   * @param {{ from?: Date, to?: Date, servicePrincipal?: string, limit?: number }} opts
   */
  async getDelegationAuditLog({ from, to, servicePrincipal, limit = 100 } = {}) {
    const conditions = [];
    const params = [];

    if (from) {
      params.push(from);
      conditions.push(`event_time >= $${params.length}`);
    }
    if (to) {
      params.push(to);
      conditions.push(`event_time <= $${params.length}`);
    }
    if (servicePrincipal) {
      params.push(servicePrincipal);
      conditions.push(`service_principal = $${params.length}`);
    }

    params.push(Math.min(limit, 1000));
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const { rows } = await this.db.query(
      `SELECT * FROM delegation_audit ${where} ORDER BY event_time DESC LIMIT $${params.length}`,
      params
    );
    return rows;
  }
}

module.exports = DelegationManager;
