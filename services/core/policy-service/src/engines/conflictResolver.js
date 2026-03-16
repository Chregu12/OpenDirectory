'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

class ConflictResolver {
  /**
   * Resolve conflicts among a set of policies.
   * Returns a sorted list with conflict details and explanations.
   *
   * @param {object[]} policies - Array of policy objects with settings, priority, enforce flags
   * @returns {{ resolved: object, conflicts: object[], explanation: string[] }}
   */
  resolveConflicts(policies) {
    if (!policies || policies.length === 0) {
      return { resolved: {}, conflicts: [], explanation: [] };
    }

    // Sort by priority (lower number = higher priority)
    const sorted = [...policies].sort((a, b) => (a.priority || 100) - (b.priority || 100));

    const resolved = {};
    const sources = {};
    const conflicts = [];
    const explanation = [];

    for (const policy of sorted) {
      const settings = this._flattenObject(policy.settings || {});
      for (const [key, value] of Object.entries(settings)) {
        if (key in resolved) {
          const existing = resolved[key];
          if (existing !== value) {
            const conflict = this.detectConflicts(
              { id: sources[key].policyId, name: sources[key].policyName, settings: { [key]: existing } },
              { id: policy.id, name: policy.name, settings: { [key]: value } }
            );
            conflicts.push(...conflict);

            // Higher priority (lower number) wins; if equal, the one already
            // set wins (first-applied).  Enforced policies always win.
            const existingPriority = sources[key].priority;
            const incomingPriority = policy.priority || 100;

            if (policy.enforce && !sources[key].enforce) {
              resolved[key] = value;
              explanation.push(
                `Setting "${key}": policy "${policy.name}" (enforced) overrides ` +
                `"${sources[key].policyName}" – value changed from ${JSON.stringify(existing)} to ${JSON.stringify(value)}`
              );
              sources[key] = {
                policyId: policy.id,
                policyName: policy.name,
                priority: incomingPriority,
                enforce: true
              };
            } else if (!sources[key].enforce && incomingPriority < existingPriority) {
              resolved[key] = value;
              explanation.push(
                `Setting "${key}": policy "${policy.name}" (priority ${incomingPriority}) overrides ` +
                `"${sources[key].policyName}" (priority ${existingPriority}) – value changed from ${JSON.stringify(existing)} to ${JSON.stringify(value)}`
              );
              sources[key] = {
                policyId: policy.id,
                policyName: policy.name,
                priority: incomingPriority,
                enforce: !!policy.enforce
              };
            } else {
              explanation.push(
                `Setting "${key}": policy "${sources[key].policyName}" retains value ${JSON.stringify(existing)} – ` +
                `"${policy.name}" value ${JSON.stringify(value)} discarded ` +
                (sources[key].enforce ? '(existing is enforced)' : `(priority ${existingPriority} <= ${incomingPriority})`)
              );
            }
          }
        } else {
          resolved[key] = value;
          sources[key] = {
            policyId: policy.id,
            policyName: policy.name,
            priority: policy.priority || 100,
            enforce: !!policy.enforce
          };
        }
      }
    }

    logger.info('Conflict resolution complete', {
      policyCount: policies.length,
      settingCount: Object.keys(resolved).length,
      conflictCount: conflicts.length
    });

    return { resolved, conflicts, explanation, sources };
  }

  /**
   * Detect overlapping settings between two policies that have different values.
   *
   * @param {object} policyA - { id, name, settings }
   * @param {object} policyB - { id, name, settings }
   * @returns {object[]} Array of conflict objects
   */
  detectConflicts(policyA, policyB) {
    const settingsA = this._flattenObject(policyA.settings || {});
    const settingsB = this._flattenObject(policyB.settings || {});
    const conflicts = [];

    for (const key of Object.keys(settingsA)) {
      if (key in settingsB && settingsA[key] !== settingsB[key]) {
        conflicts.push({
          setting: key,
          policyA: { id: policyA.id, name: policyA.name, value: settingsA[key] },
          policyB: { id: policyB.id, name: policyB.name, value: settingsB[key] }
        });
      }
    }

    return conflicts;
  }

  /**
   * Flatten a nested object into dot-separated keys.
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

module.exports = { ConflictResolver };
