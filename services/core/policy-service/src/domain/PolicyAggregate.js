'use strict';

const {
  POLICY_CREATED,
  POLICY_UPDATED,
  POLICY_ENABLED,
  POLICY_DISABLED,
  POLICY_APPLIED,
  RULE_ADDED,
  RULE_REMOVED
} = require('./DomainEvents');

/**
 * PolicyAggregate — Aggregate Root for a policy entity.
 *
 * Encapsulates all validation rules, state transitions, and domain events for
 * a policy.  Consumers should always go through the public methods rather than
 * mutating properties directly so that domain events are recorded correctly.
 *
 * Domain events are collected in _domainEvents and dispatched externally by the
 * application service after persistence.  This aggregate does NOT extend
 * EventEmitter — it is a plain class.
 */
class PolicyAggregate {
  /**
   * @param {object} data - raw policy data (from DB row or creation payload)
   */
  constructor(data) {
    this._validate(data);
    this.id               = data.id || null;
    this.name             = data.name;
    this.type             = data.type;
    this.platform         = data.platform || 'all';
    this.rules            = Array.isArray(data.rules) ? [...data.rules] : [];
    this.settings         = data.settings || {};
    this.enabled          = data.enabled !== undefined ? !!data.enabled : true;
    this.priority         = typeof data.priority === 'number' ? data.priority : 50;
    this.status           = data.status || 'draft';
    this.description      = data.description || null;
    this.enforce          = data.enforce !== undefined ? !!data.enforce : false;
    this.block_inheritance = data.block_inheritance !== undefined ? !!data.block_inheritance : false;
    this.wmi_filter       = data.wmi_filter || null;
    this.security_filter  = data.security_filter || null;
    this.created_by       = data.created_by || null;
    this.activated_at     = data.activated_at || null;
    this.version          = data.version || 1;
    this.createdAt        = data.createdAt ? new Date(data.createdAt) : new Date();
    this.updatedAt        = data.updatedAt ? new Date(data.updatedAt) : new Date();
    this._domainEvents = [];
  }

  // ── Factory ────────────────────────────────────────────────────────────────

  /**
   * Create a new policy and record a PolicyCreated domain event.
   * @param {object} data
   * @returns {PolicyAggregate}
   */
  static create(data) {
    const policy = new PolicyAggregate(data);
    policy._addDomainEvent(POLICY_CREATED, {
      policyId: policy.id,
      name: policy.name,
      type: policy.type,
      platform: policy.platform
    });
    return policy;
  }

  /**
   * Reconstitute a policy from a persisted DB row (no domain event emitted).
   * @param {object} row
   * @returns {PolicyAggregate}
   */
  static fromRow(row) {
    return new PolicyAggregate({
      id:               row.id,
      name:             row.name,
      type:             row.type,
      platform:         row.platform,
      rules:            row.rules || [],
      settings:         row.settings || {},
      enabled:          row.enabled,
      priority:         row.priority,
      status:           row.status,
      description:      row.description,
      enforce:          row.enforce,
      block_inheritance: row.block_inheritance,
      wmi_filter:       row.wmi_filter,
      security_filter:  row.security_filter,
      created_by:       row.created_by,
      activated_at:     row.activated_at,
      version:          row.version,
      createdAt:        row.created_at || row.createdAt,
      updatedAt:        row.updated_at || row.updatedAt
    });
  }

  // ── Commands ───────────────────────────────────────────────────────────────

  /**
   * Update mutable policy fields and record a PolicyUpdated event.
   * @param {object} changes - partial fields to apply
   */
  update(changes) {
    const allowed = ['name', 'type', 'platform', 'settings', 'priority'];
    const applied = {};
    for (const key of allowed) {
      if (key in changes) {
        this[key] = changes[key];
        applied[key] = changes[key];
      }
    }
    this.updatedAt = new Date();
    this._addDomainEvent(POLICY_UPDATED, { policyId: this.id, changes: applied });
  }

  /** Enable the policy (idempotent). */
  enable() {
    if (this.enabled) return;
    this.enabled = true;
    this.updatedAt = new Date();
    this._addDomainEvent(POLICY_ENABLED, { policyId: this.id });
  }

  /** Disable the policy (idempotent). */
  disable() {
    if (!this.enabled) return;
    this.enabled = false;
    this.updatedAt = new Date();
    this._addDomainEvent(POLICY_DISABLED, { policyId: this.id });
  }

  /**
   * Add a rule to the policy.
   * @param {object} rule - must have at least a `type` field
   */
  addRule(rule) {
    if (!rule || !rule.type) throw new Error('Rule must have a type');
    this.rules = [...this.rules, rule];
    this.updatedAt = new Date();
    this._addDomainEvent(RULE_ADDED, { policyId: this.id, rule });
  }

  /**
   * Remove a rule by its index.
   * @param {number} index
   */
  removeRule(index) {
    if (index < 0 || index >= this.rules.length) {
      throw new Error(`Rule index ${index} out of bounds`);
    }
    const removed = this.rules[index];
    this.rules = this.rules.filter((_, i) => i !== index);
    this.updatedAt = new Date();
    this._addDomainEvent(RULE_REMOVED, { policyId: this.id, removed });
  }

  /**
   * Mark the policy as applied to a device/group.
   * @param {string} target - deviceId or group identifier
   */
  markApplied(target) {
    this._addDomainEvent(POLICY_APPLIED, { policyId: this.id, target, appliedAt: new Date() });
  }

  // ── Domain events ──────────────────────────────────────────────────────────

  /**
   * Return and clear all pending domain events.
   * Call this after persisting the aggregate to dispatch events.
   * @returns {Array<{type: string, payload: object, occurredAt: Date}>}
   */
  getAndClearDomainEvents() {
    const events = [...this._domainEvents];
    this._domainEvents = [];
    return events;
  }

  // ── Serialisation ──────────────────────────────────────────────────────────

  /** Return a plain object suitable for API responses and persistence. */
  toJSON() {
    return {
      id:               this.id,
      name:             this.name,
      type:             this.type,
      platform:         this.platform,
      rules:            this.rules,
      settings:         this.settings,
      enabled:          this.enabled,
      priority:         this.priority,
      status:           this.status,
      description:      this.description,
      enforce:          this.enforce,
      block_inheritance: this.block_inheritance,
      wmi_filter:       this.wmi_filter,
      security_filter:  this.security_filter,
      created_by:       this.created_by,
      activated_at:     this.activated_at,
      version:          this.version,
      created_at:       this.createdAt,
      updated_at:       this.updatedAt,
      createdAt:        this.createdAt,
      updatedAt:        this.updatedAt
    };
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _validate(data) {
    if (!data || typeof data !== 'object') throw new Error('Policy data must be an object');
    if (!data.name || typeof data.name !== 'string' || !data.name.trim()) {
      throw new Error('Policy name is required');
    }
    if (!data.type || typeof data.type !== 'string' || !data.type.trim()) {
      throw new Error('Policy type is required');
    }
  }

  _addDomainEvent(type, payload) {
    this._domainEvents.push({ type, payload, occurredAt: new Date() });
  }
}

module.exports = PolicyAggregate;
