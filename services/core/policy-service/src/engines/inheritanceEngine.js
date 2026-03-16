'use strict';

const { query } = require('../db/postgres');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * Manages the GPO inheritance chain.
 *
 * In Active Directory, group policies are inherited along the OU hierarchy:
 *   Domain -> Top-level OU -> Child OU -> Grandchild OU -> ...
 *
 * Two key flags modify this behaviour:
 *   - block_inheritance: set on a container to stop inheriting policies from above
 *   - enforce: set on a policy link to force the policy to apply even when
 *              block_inheritance is set on a child container
 */
class InheritanceEngine {
  /**
   * Build the full inheritance chain for a given target.
   * Returns policies ordered from most general (domain root) to most specific (target OU).
   *
   * @param {string} targetType - 'ou', 'site', 'domain', 'device', 'group'
   * @param {string} targetId   - The identifier of the target
   * @returns {{ chain: object[], effectivePolicies: object[] }}
   */
  async getInheritanceChain(targetType, targetId) {
    logger.info('Building inheritance chain', { targetType, targetId });

    // Get all links for this specific target
    const directLinks = await this._getLinksForTarget(targetType, targetId);

    // If targetType is 'ou', walk the OU hierarchy upward.
    // We rely on a convention where OU target_ids encode the path, e.g.
    //   "domain.com/Engineering/Backend" -> parent is "domain.com/Engineering"
    // or are stored as explicit parent references in the OU data.
    const chain = [];
    if (targetType === 'ou') {
      const ancestors = this._getAncestorOUs(targetId);
      for (const ancestorId of ancestors) {
        const ancestorLinks = await this._getLinksForTarget('ou', ancestorId);
        chain.push({
          targetType: 'ou',
          targetId: ancestorId,
          links: ancestorLinks,
          blockInheritance: await this._checkBlockInheritance(ancestorId)
        });
      }
    }

    // Also include domain-level policies
    const domainId = this._extractDomain(targetId);
    if (domainId) {
      const domainLinks = await this._getLinksForTarget('domain', domainId);
      if (domainLinks.length > 0) {
        chain.unshift({
          targetType: 'domain',
          targetId: domainId,
          links: domainLinks,
          blockInheritance: false
        });
      }
    }

    // Add the target itself at the end
    chain.push({
      targetType,
      targetId,
      links: directLinks,
      blockInheritance: await this._checkBlockInheritance(targetId)
    });

    // Compute effective policies respecting block_inheritance and enforce
    const effectivePolicies = this._computeEffective(chain);

    logger.info('Inheritance chain built', {
      targetType,
      targetId,
      chainLength: chain.length,
      effectiveCount: effectivePolicies.length
    });

    return { chain, effectivePolicies };
  }

  /**
   * Check if a target OU blocks inheritance.
   */
  async isBlocked(targetId) {
    return this._checkBlockInheritance(targetId);
  }

  /**
   * Check if a policy link is enforced.
   * Enforced policies override block_inheritance.
   */
  isEnforced(policyLink) {
    return !!(policyLink && policyLink.enforce);
  }

  /**
   * Given the inheritance chain, compute which policies actually apply,
   * accounting for block_inheritance and enforce flags.
   */
  _computeEffective(chain) {
    const effective = [];

    // Find the lowest level that blocks inheritance
    let blockIndex = -1;
    for (let i = chain.length - 1; i >= 0; i--) {
      if (chain[i].blockInheritance) {
        blockIndex = i;
        break;
      }
    }

    for (let i = 0; i < chain.length; i++) {
      const level = chain[i];
      for (const link of level.links) {
        // If block_inheritance is set at or below the current level,
        // only enforced links from higher levels pass through
        if (blockIndex >= 0 && i < blockIndex) {
          if (!this.isEnforced(link)) {
            continue; // blocked
          }
        }

        if (!link.enabled) continue;

        effective.push({
          policyId: link.policy_id,
          policyName: link.policy_name,
          policyType: link.policy_type,
          priority: link.policy_priority,
          targetType: level.targetType,
          targetId: level.targetId,
          enforce: this.isEnforced(link),
          linkOrder: link.link_order,
          level: i
        });
      }
    }

    // Sort: enforced policies first, then by level (ascending), then by link_order
    effective.sort((a, b) => {
      if (a.enforce !== b.enforce) return a.enforce ? -1 : 1;
      if (a.level !== b.level) return a.level - b.level;
      return a.linkOrder - b.linkOrder;
    });

    return effective;
  }

  /**
   * Get all policy links for a specific target.
   */
  async _getLinksForTarget(targetType, targetId) {
    const result = await query(
      `SELECT pl.*, p.name AS policy_name, p.type AS policy_type,
              p.priority AS policy_priority, p.status AS policy_status,
              p.settings AS policy_settings, p.enforce AS policy_enforce
       FROM policy_links pl
       JOIN policies p ON p.id = pl.policy_id
       WHERE pl.target_type = $1 AND pl.target_id = $2
         AND p.status = 'active'
       ORDER BY pl.link_order ASC`,
      [targetType, targetId]
    );
    return result.rows;
  }

  /**
   * Check if block_inheritance is set for any active policy linked to a target.
   */
  async _checkBlockInheritance(targetId) {
    const result = await query(
      `SELECT 1 FROM policy_links pl
       JOIN policies p ON p.id = pl.policy_id
       WHERE pl.target_id = $1 AND p.block_inheritance = true AND p.status = 'active'
       LIMIT 1`,
      [targetId]
    );
    return result.rows.length > 0;
  }

  /**
   * Parse the OU path to get ancestor OUs.
   * Convention: OUs are slash-separated, e.g. "corp.com/HQ/Engineering/Backend"
   * Returns ["corp.com/HQ", "corp.com/HQ/Engineering"] (excludes the target itself).
   */
  _getAncestorOUs(ouPath) {
    const parts = ouPath.split('/');
    const ancestors = [];
    for (let i = 2; i < parts.length; i++) {
      ancestors.push(parts.slice(0, i).join('/'));
    }
    return ancestors;
  }

  /**
   * Extract the domain portion from an OU path.
   */
  _extractDomain(ouPath) {
    const parts = ouPath.split('/');
    return parts.length > 0 ? parts[0] : null;
  }
}

module.exports = { InheritanceEngine };
