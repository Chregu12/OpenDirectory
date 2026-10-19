'use strict';

const PolicyAggregate = require('../domain/PolicyAggregate');

/**
 * PolicyApplicationService — orchestrates policy use-cases.
 *
 * All persistence is delegated to the injected policyRepository.
 * No direct db.query() calls are allowed here.
 */
class PolicyApplicationService {
  /**
   * @param {object} deps
   * @param {object} deps.policyRepository  - PostgresPolicyRepository instance
   * @param {object} [deps.blueprintRepository] - optional BlueprintRepository
   * @param {object} [deps.messageBus]      - optional event bus
   * @param {object} [deps.logger]          - optional logger
   */
  constructor({ policyRepository, blueprintRepository, messageBus, logger } = {}) {
    if (!policyRepository) throw new Error('policyRepository is required');
    this._policyRepo      = policyRepository;
    this._blueprintRepo   = blueprintRepository || null;
    this._bus             = messageBus || null;
    this._log             = logger || console;
  }

  // ── Query methods ─────────────────────────────────────────────────────────

  /**
   * List policies with optional filters and pagination.
   * @param {object} filters   - { type, platform, status }
   * @param {object} pagination - { limit, offset }
   * @returns {Promise<{policies: object[], total: number}>}
   */
  async listPolicies(filters = {}, pagination = {}) {
    const { policies, total } = await this._policyRepo.findAll(filters, pagination);
    return { policies: policies.map(p => p.toJSON()), total };
  }

  /**
   * Get a single policy by id.
   * @param {string} id
   * @returns {Promise<object|null>}
   */
  async getPolicy(id) {
    const policy = await this._policyRepo.findById(id);
    return policy ? policy.toJSON() : null;
  }

  /**
   * Get all active policies.
   * @returns {Promise<object[]>}
   */
  async getActivePolicies() {
    const policies = await this._policyRepo.findActive();
    return policies.map(p => p.toJSON());
  }

  // ── Command methods ───────────────────────────────────────────────────────

  /**
   * Create a new policy.
   * @param {object} data - policy creation payload
   * @returns {Promise<object>} persisted policy as plain object
   */
  async createPolicy(data) {
    const aggregate = PolicyAggregate.create(data);
    // Copy extra fields not on the base aggregate that the DB schema expects
    aggregate.description      = data.description || null;
    aggregate.enforce          = data.enforce || false;
    aggregate.block_inheritance = data.block_inheritance || false;
    aggregate.wmi_filter       = data.wmi_filter || null;
    aggregate.security_filter  = data.security_filter || null;
    aggregate.created_by       = data.created_by || null;
    aggregate.status           = data.status || 'draft';

    const saved = await this._policyRepo.save(aggregate);
    await this._dispatchEvents(aggregate);
    return saved.toJSON();
  }

  /**
   * Update an existing policy.
   * @param {string} id
   * @param {object} changes
   * @returns {Promise<object>} updated policy as plain object
   * @throws {Error} if not found
   */
  async updatePolicy(id, changes) {
    const policy = await this._policyRepo.findById(id);
    if (!policy) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });

    // Apply domain changes for tracked fields
    const domainFields = ['name', 'type', 'platform', 'settings', 'priority'];
    const domainChanges = {};
    for (const key of domainFields) {
      if (key in changes) domainChanges[key] = changes[key];
    }
    if (Object.keys(domainChanges).length) policy.update(domainChanges);

    // Carry over all raw changes so the repository can persist them
    Object.assign(policy, changes);

    const saved = await this._policyRepo.save(policy);
    await this._dispatchEvents(policy);
    return saved.toJSON();
  }

  /**
   * Delete a policy by id.
   * @param {string} id
   * @returns {Promise<boolean>}
   * @throws {Error} if not found
   */
  async deletePolicy(id) {
    const deleted = await this._policyRepo.delete(id);
    if (!deleted) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });
    return true;
  }

  /**
   * Activate a policy.
   * @param {string} id
   * @returns {Promise<object>}
   * @throws {Error} if not found
   */
  async activatePolicy(id) {
    const policy = await this._policyRepo.activate(id);
    if (!policy) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });
    policy.enable();
    await this._dispatchEvents(policy);
    return policy.toJSON();
  }

  /**
   * Deactivate a policy.
   * @param {string} id
   * @returns {Promise<object>}
   * @throws {Error} if not found
   */
  async deactivatePolicy(id) {
    const policy = await this._policyRepo.deactivate(id);
    if (!policy) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });
    policy.disable();
    await this._dispatchEvents(policy);
    return policy.toJSON();
  }

  /**
   * Evaluate compliance for a device against all active enforce policies.
   * @param {object} params - { deviceId, devicePlatform, deviceProperties }
   * @returns {Promise<object>}
   */
  async evaluateCompliance({ deviceId, devicePlatform, deviceProperties }) {
    const policies = await this._policyRepo.findActive();

    const violations = [];
    for (const policy of policies) {
      const policyData = policy.toJSON();
      const rules = Array.isArray(policyData.rules) ? policyData.rules : [];
      for (const rule of rules) {
        const violated = this._checkRule(rule, deviceProperties || {});
        if (violated) {
          violations.push({
            policyId: policyData.id,
            policyName: policyData.name,
            rule: rule.type || rule.key,
            severity: rule.severity || 'medium'
          });
        }
      }
    }

    const isCompliant = violations.length === 0;

    if (!isCompliant) {
      this._publish('device.non_compliant', { deviceId, violations, checkedAt: new Date().toISOString() });
    } else {
      this._publish('device.compliant', { deviceId, checkedAt: new Date().toISOString() });
    }

    return { deviceId, isCompliant, violations, evaluatedAt: new Date().toISOString() };
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  _checkRule(rule, properties) {
    if (!rule || !rule.key) return false;
    const actual = properties[rule.key];
    if (rule.operator === 'equals') return actual !== rule.value;
    if (rule.operator === 'not_equals') return actual === rule.value;
    if (rule.operator === 'greater_than') return !(actual > rule.value);
    if (rule.operator === 'less_than') return !(actual < rule.value);
    if (rule.operator === 'contains') return !(typeof actual === 'string' && actual.includes(rule.value));
    if (rule.operator === 'exists') return actual === undefined || actual === null;
    return false;
  }

  _publish(routingKey, payload) {
    if (!this._bus) return;
    try { this._bus.publish(routingKey, { ...payload, _source: 'policy-service' }); } catch (_) {}
  }

  async _dispatchEvents(aggregate) {
    if (!this._bus) return;
    const events = aggregate.getAndClearDomainEvents();
    for (const event of events) {
      try {
        await this._bus.publish(event.type, event.payload);
      } catch (err) {
        this._log.error('Failed to publish domain event', { type: event.type, error: err.message });
      }
    }
  }
}

module.exports = PolicyApplicationService;
