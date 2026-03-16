'use strict';

const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()]
});

/**
 * Merge strategies determine how conflicting values for the same setting
 * key are reconciled:
 *
 *   replace  - The winning value completely replaces the losing value (default).
 *   merge    - If both values are objects, deep-merge them; otherwise replace.
 *   append   - If both values are arrays, concatenate them; otherwise replace.
 *
 * Strategies can be specified per-setting key in a mergeStrategyMap provided
 * to resolveConflicts(), or via a policy-level `mergeStrategy` property that
 * applies to all of that policy's settings.
 */
const VALID_STRATEGIES = ['replace', 'merge', 'append'];
const DEFAULT_STRATEGY = 'replace';

class ConflictResolver {
  /**
   * Resolve conflicts among a set of policies.
   * Returns a sorted list with conflict details and explanations.
   *
   * @param {object[]} policies          - Array of policy objects with settings, priority, enforce flags
   * @param {object}   [mergeStrategyMap] - Optional map of setting key -> strategy ('replace'|'merge'|'append')
   * @returns {{ resolved: object, conflicts: object[], explanation: string[], sources: object }}
   */
  resolveConflicts(policies, mergeStrategyMap = {}) {
    if (!policies || policies.length === 0) {
      return { resolved: {}, conflicts: [], explanation: [], sources: {} };
    }

    // Sort by priority (lower number = higher priority)
    const sorted = [...policies].sort((a, b) => (a.priority || 100) - (b.priority || 100));

    const resolved = {};
    const sources = {};
    const conflicts = [];
    const explanation = [];

    for (const policy of sorted) {
      const settings = this._flattenObject(policy.settings || {});
      const policyStrategy = policy.mergeStrategy || DEFAULT_STRATEGY;

      for (const [key, value] of Object.entries(settings)) {
        const strategy = mergeStrategyMap[key] || policyStrategy;

        if (key in resolved) {
          const existing = resolved[key];

          // Check for a genuine difference (deep equality for objects/arrays)
          if (!this._deepEqual(existing, value)) {
            const conflict = this.detectConflicts(
              { id: sources[key].policyId, name: sources[key].policyName, settings: { [key]: existing } },
              { id: policy.id, name: policy.name, settings: { [key]: value } }
            );
            conflicts.push(...conflict);

            const existingPriority = sources[key].priority;
            const incomingPriority = policy.priority || 100;

            if (policy.enforce && !sources[key].enforce) {
              // Enforced incoming policy always wins
              resolved[key] = this._applyStrategy(strategy, existing, value);
              explanation.push(
                `Setting "${key}": policy "${policy.name}" (enforced, strategy=${strategy}) overrides ` +
                `"${sources[key].policyName}" – value changed from ${JSON.stringify(existing)} to ${JSON.stringify(resolved[key])}`
              );
              sources[key] = {
                policyId: policy.id,
                policyName: policy.name,
                priority: incomingPriority,
                enforce: true,
                strategy
              };
            } else if (!sources[key].enforce && incomingPriority < existingPriority) {
              // Higher priority incoming (lower number) wins
              resolved[key] = this._applyStrategy(strategy, existing, value);
              explanation.push(
                `Setting "${key}": policy "${policy.name}" (priority ${incomingPriority}, strategy=${strategy}) overrides ` +
                `"${sources[key].policyName}" (priority ${existingPriority}) – value changed from ${JSON.stringify(existing)} to ${JSON.stringify(resolved[key])}`
              );
              sources[key] = {
                policyId: policy.id,
                policyName: policy.name,
                priority: incomingPriority,
                enforce: !!policy.enforce,
                strategy
              };
            } else if (!sources[key].enforce && incomingPriority === existingPriority) {
              // Same priority: last-writer-wins (later in iteration = later applied)
              resolved[key] = this._applyStrategy(strategy, existing, value);
              explanation.push(
                `Setting "${key}": policy "${policy.name}" (same priority ${incomingPriority}, last-writer-wins, strategy=${strategy}) ` +
                `overrides "${sources[key].policyName}" – value changed from ${JSON.stringify(existing)} to ${JSON.stringify(resolved[key])}`
              );
              sources[key] = {
                policyId: policy.id,
                policyName: policy.name,
                priority: incomingPriority,
                enforce: !!policy.enforce,
                strategy
              };
            } else {
              explanation.push(
                `Setting "${key}": policy "${sources[key].policyName}" retains value ${JSON.stringify(existing)} – ` +
                `"${policy.name}" value ${JSON.stringify(value)} discarded ` +
                (sources[key].enforce ? '(existing is enforced)' : `(priority ${existingPriority} < ${incomingPriority})`)
              );
            }
          }
        } else {
          resolved[key] = value;
          sources[key] = {
            policyId: policy.id,
            policyName: policy.name,
            priority: policy.priority || 100,
            enforce: !!policy.enforce,
            strategy
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
      if (key in settingsB && !this._deepEqual(settingsA[key], settingsB[key])) {
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
   * Apply a merge strategy to combine existing and incoming values.
   *
   * @param {string} strategy  - 'replace', 'merge', or 'append'
   * @param {*}      existing  - The current value
   * @param {*}      incoming  - The new value
   * @returns {*} The merged result
   */
  _applyStrategy(strategy, existing, incoming) {
    switch (strategy) {
      case 'merge':
        // Deep-merge objects; for non-objects, incoming replaces
        if (this._isPlainObject(existing) && this._isPlainObject(incoming)) {
          return this._deepMerge(existing, incoming);
        }
        return incoming;

      case 'append':
        // Concatenate arrays; wrap non-arrays in arrays first
        if (Array.isArray(existing) && Array.isArray(incoming)) {
          return [...existing, ...incoming];
        }
        if (Array.isArray(existing)) {
          return [...existing, incoming];
        }
        if (Array.isArray(incoming)) {
          return [existing, ...incoming];
        }
        return incoming;

      case 'replace':
      default:
        return incoming;
    }
  }

  /**
   * Deep-merge two plain objects.  Incoming values override existing ones,
   * with recursive merging for nested objects.
   */
  _deepMerge(target, source) {
    const output = { ...target };
    for (const [key, value] of Object.entries(source)) {
      if (this._isPlainObject(value) && this._isPlainObject(target[key])) {
        output[key] = this._deepMerge(target[key], value);
      } else {
        output[key] = value;
      }
    }
    return output;
  }

  /**
   * Check if a value is a plain object (not an array, null, etc.)
   */
  _isPlainObject(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  /**
   * Deep equality check for two values.
   */
  _deepEqual(a, b) {
    if (a === b) return true;
    if (a === null || b === null) return false;
    if (typeof a !== typeof b) return false;

    if (Array.isArray(a) && Array.isArray(b)) {
      if (a.length !== b.length) return false;
      return a.every((val, idx) => this._deepEqual(val, b[idx]));
    }

    if (typeof a === 'object') {
      const keysA = Object.keys(a);
      const keysB = Object.keys(b);
      if (keysA.length !== keysB.length) return false;
      return keysA.every(key => this._deepEqual(a[key], b[key]));
    }

    return false;
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
