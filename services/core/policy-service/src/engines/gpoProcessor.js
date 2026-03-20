'use strict';

const { query } = require('../db/postgres');
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * GPO Processing Order (mirrors Windows Group Policy):
 *  1. Local policies
 *  2. Site policies
 *  3. Domain policies
 *  4. OU policies (nested – lowest OU wins)
 *
 * Enforce flag: an enforced link cannot be overridden by lower-level
 * policies, even when block_inheritance is set on the target container.
 */
const LINK_ORDER = ['local', 'site', 'domain', 'ou'];

/**
 * Setting key prefixes that belong to the computer-configuration half
 * of a GPO.  Everything else is considered user-configuration.
 */
const COMPUTER_PREFIXES = [
  'firewall.', 'encryption.', 'network.', 'kernel.', 'sysctl.',
  'updates.', 'antivirus.', 'audit.', 'ssh.', 'systemd.',
  'remoteDesktop.', 'software.', 'registry.', 'bitlocker.'
];

class RSOPEngine {
  /**
   * Calculate the Resultant Set of Policy for a given device/user.
   *
   * @param {string} deviceId  - Target device identifier
   * @param {string} userId    - Target user identifier (optional)
   * @param {object} context   - Additional context (groups, OS info, disabled flags, etc.)
   *   context.disabledHalves - optional map of policyId -> { computer: bool, user: bool }
   * @returns {{ settings: object, sources: object[], conflicts: object[], appliedPolicies: object[] }}
   */
  async calculateRSOP(deviceId, userId, context = {}) {
    logger.info('Calculating RSoP', { deviceId, userId });

    // 1. Collect all policy links ordered by hierarchy
    const links = await this._getOrderedLinks(deviceId, userId, context);

    // 2. Filter by WMI and security conditions
    const applicableLinks = [];
    for (const link of links) {
      if (!link.enabled) continue;

      const policy = link._policy;
      if (policy.status !== 'active') continue;

      // Platform filter
      if (policy.platform && policy.platform !== 'all') {
        const devicePlatform = (context.platform || '').toLowerCase();
        if (devicePlatform && devicePlatform !== policy.platform) continue;
      }

      // WMI filter
      if (policy.wmi_filter && !this.evaluateWMIFilter(policy.wmi_filter, context)) {
        logger.debug('Policy filtered out by WMI filter', { policyId: policy.id, policyName: policy.name });
        continue;
      }

      // Security filter
      if (policy.security_filter && !this.evaluateSecurityFilter(policy.security_filter, context.groups || [])) {
        logger.debug('Policy filtered out by security filter', { policyId: policy.id, policyName: policy.name });
        continue;
      }

      applicableLinks.push(link);
    }

    // 3. Apply disabled-half filtering (computer/user halves independently)
    const filteredLinks = this._applyDisabledHalves(applicableLinks, deviceId, userId, context);

    // 4. Merge policies respecting enforce / block flags
    const merged = this._mergePolicies(filteredLinks);

    logger.info('RSoP calculation complete', {
      deviceId,
      userId,
      appliedCount: merged.appliedPolicies.length,
      conflictCount: merged.conflicts.length
    });

    return merged;
  }

  /**
   * Apply disabled-half filtering.
   *
   * In Windows GPO, each GPO has two halves: Computer Configuration and
   * User Configuration.  Either half can be disabled independently.
   *
   * When the computer half is disabled, computer-scoped settings are stripped.
   * When the user half is disabled, user-scoped settings are stripped.
   *
   * The disabled state is read from:
   *   - context.disabledHalves[policyId] = { computer: true/false, user: true/false }
   *   - Or from the policy link itself: link.disabled_computer / link.disabled_user
   */
  _applyDisabledHalves(links, deviceId, userId, context) {
    const disabledMap = context.disabledHalves || {};

    return links.map(link => {
      const policy = link._policy;
      const disabled = disabledMap[policy.id] || {};
      const computerDisabled = disabled.computer || link.disabled_computer || false;
      const userDisabled = disabled.user || link.disabled_user || false;

      // If both halves disabled, skip entirely
      if (computerDisabled && userDisabled) {
        logger.debug('Policy fully disabled (both halves)', { policyId: policy.id });
        return null;
      }

      // If neither half disabled, pass through
      if (!computerDisabled && !userDisabled) return link;

      // Partially disabled: filter settings by half
      const settings = policy.settings || {};
      const filteredSettings = {};

      for (const [key, value] of Object.entries(this._flattenObject(settings))) {
        const isComputerSetting = COMPUTER_PREFIXES.some(p => key.startsWith(p));

        if (isComputerSetting && computerDisabled) {
          logger.debug('Stripping computer setting from disabled half', { policyId: policy.id, key });
          continue;
        }
        if (!isComputerSetting && userDisabled) {
          logger.debug('Stripping user setting from disabled half', { policyId: policy.id, key });
          continue;
        }

        filteredSettings[key] = value;
      }

      // Return a copy with filtered settings (un-flattened back to nested)
      return {
        ...link,
        _policy: {
          ...policy,
          settings: filteredSettings
        },
        _settingsPreFlattened: true
      };
    }).filter(Boolean);
  }

  /**
   * Retrieve all policy links that apply to the target, ordered by
   * the GPO processing hierarchy.
   */
  async _getOrderedLinks(deviceId, userId, context) {
    // Build target identifiers for each level
    const targets = [];

    // Local policies assigned directly to the device
    if (deviceId) {
      targets.push({ type: 'device', id: deviceId, level: 'local' });
    }

    // Site
    if (context.siteId) {
      targets.push({ type: 'site', id: context.siteId, level: 'site' });
    }

    // Domain
    if (context.domainId) {
      targets.push({ type: 'domain', id: context.domainId, level: 'domain' });
    }

    // OU hierarchy (from root OU down to the immediate OU of the device)
    if (context.ouPath && Array.isArray(context.ouPath)) {
      for (let i = 0; i < context.ouPath.length; i++) {
        targets.push({ type: 'ou', id: context.ouPath[i], level: 'ou', depth: i });
      }
    }

    // Group-based assignments
    if (context.groups && Array.isArray(context.groups)) {
      for (const groupId of context.groups) {
        targets.push({ type: 'group', id: groupId, level: 'domain' });
      }
    }

    if (targets.length === 0) {
      return [];
    }

    // Query all links matching these targets
    const placeholders = [];
    const params = [];
    targets.forEach((t, idx) => {
      const typeIdx = idx * 2 + 1;
      const idIdx = idx * 2 + 2;
      placeholders.push(`(pl.target_type = $${typeIdx} AND pl.target_id = $${idIdx})`);
      params.push(t.type, t.id);
    });

    const sql = `
      SELECT pl.*, p.name AS policy_name, p.description AS policy_description,
             p.type AS policy_type, p.platform, p.rules, p.settings, p.priority,
             p.status, p.version, p.enforce AS policy_enforce,
             p.block_inheritance, p.wmi_filter, p.security_filter
      FROM policy_links pl
      JOIN policies p ON p.id = pl.policy_id
      WHERE (${placeholders.join(' OR ')})
      ORDER BY pl.link_order ASC
    `;

    const result = await query(sql, params);

    // Attach level metadata and sort by hierarchy
    const levelOrder = { local: 0, site: 1, domain: 2, ou: 3 };
    const targetLookup = {};
    for (const t of targets) {
      targetLookup[`${t.type}:${t.id}`] = t;
    }

    const enriched = result.rows.map(row => {
      const target = targetLookup[`${row.target_type}:${row.target_id}`] || {};
      return {
        ...row,
        _level: target.level || 'domain',
        _depth: target.depth || 0,
        _policy: {
          id: row.policy_id,
          name: row.policy_name,
          description: row.policy_description,
          type: row.policy_type,
          platform: row.platform,
          rules: row.rules,
          settings: row.settings,
          priority: row.priority,
          status: row.status,
          version: row.version,
          enforce: row.policy_enforce,
          block_inheritance: row.block_inheritance,
          wmi_filter: row.wmi_filter,
          security_filter: row.security_filter
        }
      };
    });

    // Sort: local -> site -> domain -> ou (by depth)
    enriched.sort((a, b) => {
      const la = levelOrder[a._level] || 99;
      const lb = levelOrder[b._level] || 99;
      if (la !== lb) return la - lb;
      if (a._depth !== b._depth) return a._depth - b._depth;
      return a.link_order - b.link_order;
    });

    return enriched;
  }

  /**
   * Merge policy settings following GPO precedence rules.
   * Later (more specific) policies override earlier ones, unless
   * an earlier policy is marked as "enforced".
   */
  _mergePolicies(links) {
    const merged = {};           // final key -> value
    const sources = {};          // key -> { policyId, policyName, level }
    const enforced = {};         // keys locked by enforced policies
    const conflicts = [];
    const appliedPolicies = [];
    const seenPolicies = new Set();

    for (const link of links) {
      const policy = link._policy;
      const isEnforced = link.enforce || policy.enforce;

      if (!seenPolicies.has(policy.id)) {
        seenPolicies.add(policy.id);
        appliedPolicies.push({
          id: policy.id,
          name: policy.name,
          type: policy.type,
          priority: policy.priority,
          level: link._level,
          enforce: isEnforced
        });
      }

      const settings = policy.settings || {};
      this.mergeSettings(merged, sources, enforced, conflicts, settings, {
        policyId: policy.id,
        policyName: policy.name,
        level: link._level,
        enforce: isEnforced
      }, link._settingsPreFlattened || false);
    }

    return { settings: merged, sources, conflicts, appliedPolicies };
  }

  /**
   * Merge incoming settings into the existing merged result.
   * Enforced settings cannot be overridden by later policies.
   *
   * @param {object} existing  - Accumulated settings
   * @param {object} sources   - Source tracking map
   * @param {object} enforced  - Set of enforced keys
   * @param {object[]} conflicts - Array to push conflict records into
   * @param {object} incoming  - New settings to merge
   * @param {object} meta      - { policyId, policyName, level, enforce }
   */
  mergeSettings(existing, sources, enforced, conflicts, incoming, meta, preFlattened = false) {
    const flatIncoming = preFlattened ? incoming : this._flattenObject(incoming);

    for (const [key, value] of Object.entries(flatIncoming)) {
      // If this key is already locked by an enforced policy, record a conflict
      if (enforced[key]) {
        if (existing[key] !== value) {
          conflicts.push({
            key,
            winningValue: existing[key],
            winningPolicy: sources[key],
            losingValue: value,
            losingPolicy: { policyId: meta.policyId, policyName: meta.policyName, level: meta.level },
            reason: 'enforced'
          });
        }
        continue;
      }

      // Record conflict if value differs from current
      if (key in existing && existing[key] !== value) {
        conflicts.push({
          key,
          winningValue: value,
          winningPolicy: { policyId: meta.policyId, policyName: meta.policyName, level: meta.level },
          losingValue: existing[key],
          losingPolicy: sources[key],
          reason: 'overridden'
        });
      }

      existing[key] = value;
      sources[key] = { policyId: meta.policyId, policyName: meta.policyName, level: meta.level };

      if (meta.enforce) {
        enforced[key] = true;
      }
    }
  }

  /**
   * Evaluate a WMI-style filter against device context.
   * Filter format: { conditions: [{ property, operator, value }], logic: 'and' | 'or' }
   */
  evaluateWMIFilter(filter, deviceContext) {
    if (!filter || !filter.conditions || filter.conditions.length === 0) return true;

    const logic = (filter.logic || 'and').toLowerCase();
    const results = filter.conditions.map(cond => {
      const actual = deviceContext[cond.property];
      if (actual === undefined) return false;

      switch (cond.operator) {
        case 'eq':
        case '=':
        case '==':
          return String(actual).toLowerCase() === String(cond.value).toLowerCase();
        case 'neq':
        case '!=':
          return String(actual).toLowerCase() !== String(cond.value).toLowerCase();
        case 'gt':
        case '>':
          return Number(actual) > Number(cond.value);
        case 'gte':
        case '>=':
          return Number(actual) >= Number(cond.value);
        case 'lt':
        case '<':
          return Number(actual) < Number(cond.value);
        case 'lte':
        case '<=':
          return Number(actual) <= Number(cond.value);
        case 'contains':
          return String(actual).toLowerCase().includes(String(cond.value).toLowerCase());
        case 'startsWith':
          return String(actual).toLowerCase().startsWith(String(cond.value).toLowerCase());
        case 'in':
          return Array.isArray(cond.value) && cond.value.map(v => String(v).toLowerCase()).includes(String(actual).toLowerCase());
        default:
          logger.warn('Unknown WMI filter operator', { operator: cond.operator });
          return false;
      }
    });

    return logic === 'or' ? results.some(Boolean) : results.every(Boolean);
  }

  /**
   * Evaluate a security group filter.
   * Filter format: { include: [groupId, ...], exclude: [groupId, ...] }
   */
  evaluateSecurityFilter(filter, userGroups) {
    if (!filter) return true;

    const groups = new Set(userGroups.map(g => String(g).toLowerCase()));

    // If include list specified, user must be in at least one
    if (filter.include && filter.include.length > 0) {
      const hasIncluded = filter.include.some(g => groups.has(String(g).toLowerCase()));
      if (!hasIncluded) return false;
    }

    // If exclude list specified, user must not be in any
    if (filter.exclude && filter.exclude.length > 0) {
      const hasExcluded = filter.exclude.some(g => groups.has(String(g).toLowerCase()));
      if (hasExcluded) return false;
    }

    return true;
  }

  /**
   * Flatten a nested object into dot-separated keys.
   * e.g. { password: { minLength: 12 } } -> { 'password.minLength': 12 }
   */
  _flattenObject(obj, prefix = '') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.assign(result, this._flattenObject(value, fullKey));
      } else {
        result[fullKey] = value;
      }
    }
    return result;
  }
}

module.exports = { RSOPEngine };
