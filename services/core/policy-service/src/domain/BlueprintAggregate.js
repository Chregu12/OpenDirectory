'use strict';

const {
  BLUEPRINT_CREATED,
  BLUEPRINT_UPDATED,
  BLUEPRINT_DEPLOYED,
  BLUEPRINT_DELETED
} = require('./DomainEvents');

/**
 * BlueprintAggregate — Aggregate Root for a blueprint entity.
 *
 * A blueprint is a reusable collection of policies that can be deployed to
 * devices or device groups in a single operation.
 *
 * Domain events are collected in _domainEvents and dispatched externally by the
 * application service after persistence.  This aggregate does NOT extend
 * EventEmitter — it is a plain class.
 */
class BlueprintAggregate {
  /**
   * @param {object} data - raw blueprint data
   */
  constructor(data) {
    this._validate(data);
    this.id          = data.id || null;
    this.name        = data.name;
    this.description = data.description || '';
    this.platform    = data.platform || 'all';
    this.policies    = Array.isArray(data.policies) ? [...data.policies] : [];
    this.settings    = data.settings || {};
    this.version     = typeof data.version === 'number' ? data.version : 1;
    this.createdAt   = data.createdAt ? new Date(data.createdAt) : new Date();
    this.updatedAt   = data.updatedAt ? new Date(data.updatedAt) : new Date();
    this._domainEvents = [];
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Create a new blueprint and record a BlueprintCreated domain event.
   * @param {object} data
   * @returns {BlueprintAggregate}
   */
  static create(data) {
    const blueprint = new BlueprintAggregate(data);
    blueprint._addDomainEvent(BLUEPRINT_CREATED, {
      blueprintId: blueprint.id,
      name: blueprint.name,
      platform: blueprint.platform
    });
    return blueprint;
  }

  /**
   * Reconstitute a blueprint from a persisted DB row (no domain event emitted).
   * @param {object} row
   * @returns {BlueprintAggregate}
   */
  static fromRow(row) {
    return new BlueprintAggregate({
      id:          row.id,
      name:        row.name,
      description: row.description,
      platform:    row.platform,
      policies:    row.policies || [],
      settings:    row.settings || {},
      version:     row.version,
      createdAt:   row.created_at || row.createdAt,
      updatedAt:   row.updated_at || row.updatedAt
    });
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Update mutable blueprint fields and record a BlueprintUpdated event.
   * Bumps the version on every update.
   * @param {object} changes - partial fields to apply
   */
  update(changes) {
    const allowed = ['name', 'description', 'platform', 'settings'];
    const applied = {};
    for (const key of allowed) {
      if (key in changes) {
        this[key] = changes[key];
        applied[key] = changes[key];
      }
    }
    this.version += 1;
    this.updatedAt = new Date();
    this._addDomainEvent(BLUEPRINT_UPDATED, {
      blueprintId: this.id,
      version: this.version,
      changes: applied
    });
  }

  /**
   * Attach a policy ID to this blueprint.
   * @param {string} policyId
   */
  addPolicy(policyId) {
    if (!policyId) throw new Error('policyId is required');
    if (this.policies.includes(policyId)) return; // idempotent
    this.policies = [...this.policies, policyId];
    this.version += 1;
    this.updatedAt = new Date();
    this._addDomainEvent(BLUEPRINT_UPDATED, {
      blueprintId: this.id,
      version: this.version,
      changes: { addedPolicy: policyId }
    });
  }

  /**
   * Detach a policy ID from this blueprint.
   * @param {string} policyId
   */
  removePolicy(policyId) {
    if (!this.policies.includes(policyId)) return; // idempotent
    this.policies = this.policies.filter(id => id !== policyId);
    this.version += 1;
    this.updatedAt = new Date();
    this._addDomainEvent(BLUEPRINT_UPDATED, {
      blueprintId: this.id,
      version: this.version,
      changes: { removedPolicy: policyId }
    });
  }

  /**
   * Record a deployment of this blueprint to a target.
   * @param {string} target - deviceId, group name, or '*' for all
   * @param {string} deployedBy - actor identifier
   */
  deploy(target, deployedBy) {
    if (!target) throw new Error('Deploy target is required');
    this._addDomainEvent(BLUEPRINT_DEPLOYED, {
      blueprintId: this.id,
      version: this.version,
      target,
      deployedBy: deployedBy || 'system',
      deployedAt: new Date()
    });
  }

  // ── Domain events ──────────────────────────────────────────────────────────

  /**
   * Return and clear all pending domain events.
   * @returns {Array<{type: string, payload: object, occurredAt: Date}>}
   */
  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  // ── Serialisation ──────────────────────────────────────────────────────────

  /** Return a plain object suitable for persistence. */
  toJSON() {
    return {
      id:          this.id,
      name:        this.name,
      description: this.description,
      platform:    this.platform,
      policies:    this.policies,
      settings:    this.settings,
      version:     this.version,
      createdAt:   this.createdAt,
      updatedAt:   this.updatedAt
    };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _validate(data) {
    if (!data || typeof data !== 'object') throw new Error('Blueprint data must be an object');
    if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
      throw new Error('Blueprint name is required');
    }
  }

  _addDomainEvent(type, payload) {
    this._domainEvents.push({ type, payload, occurredAt: new Date() });
  }
}

module.exports = BlueprintAggregate;
