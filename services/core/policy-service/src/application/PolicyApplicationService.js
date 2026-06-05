'use strict';

class PolicyApplicationService {
  constructor({ policyRepository, blueprintRepository, messageBus, db, logger }) {
    this._policyRepo = policyRepository;
    this._blueprintRepo = blueprintRepository;
    this._bus = messageBus;
    this._db = db;
    this._log = logger || console;
  }

  async createPolicy({ name, description, type, platform, rules, settings, priority, enforce, createdBy }) {
    // Use existing DB for persistence (repositories wrap the db)
    const result = await this._db.query(
      `INSERT INTO policies (name, description, type, platform, rules, settings, priority, enforce, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [name, description || null, type, platform || 'all',
       JSON.stringify(rules || []), JSON.stringify(settings || {}),
       priority || 100, enforce || false, createdBy || null]
    );
    const policy = result.rows[0];
    this._publish('policy.created', { policyId: policy.id, name: policy.name, type: policy.type, createdBy });
    return policy;
  }

  async evaluateCompliance({ deviceId, devicePlatform, deviceProperties }) {
    // Load all active enforce policies matching the platform
    const result = await this._db.query(
      `SELECT * FROM policies WHERE status = 'active' AND enforce = true AND (platform = $1 OR platform = 'all') ORDER BY priority ASC`,
      [devicePlatform || 'all']
    );

    const violations = [];
    for (const policy of result.rows) {
      const rules = Array.isArray(policy.rules) ? policy.rules : (JSON.parse(policy.rules || '[]'));
      for (const rule of rules) {
        const violated = this._checkRule(rule, deviceProperties || {});
        if (violated) {
          violations.push({ policyId: policy.id, policyName: policy.name, rule: rule.type || rule.key, severity: rule.severity || 'medium' });
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

  async deployBlueprint({ blueprintId, targetDeviceIds, targetGroupIds, appliedBy }) {
    const blueprint = await this._db.query('SELECT * FROM blueprints WHERE id = $1', [blueprintId]);
    if (!blueprint.rows[0]) throw new Error(`Blueprint not found: ${blueprintId}`);
    const bp = blueprint.rows[0];

    // Get policies linked to blueprint
    const linked = await this._db.query(
      'SELECT p.* FROM policies p JOIN blueprint_policies bp ON p.id = bp.policy_id WHERE bp.blueprint_id = $1',
      [blueprintId]
    );

    const results = [];
    for (const deviceId of (targetDeviceIds || [])) {
      for (const policy of linked.rows) {
        results.push({ deviceId, policyId: policy.id, policyName: policy.name, applied: true });
      }
    }

    this._publish('policy.applied', { blueprintId, name: bp.name, deviceCount: (targetDeviceIds || []).length, appliedBy });

    return { blueprintId, name: bp.name, results, appliedAt: new Date().toISOString() };
  }

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
    if (!this._bus || !this._bus.isConnected()) return;
    try { this._bus.publish(routingKey, { ...payload, _source: 'policy-service' }); } catch (_) {}
  }
}

module.exports = PolicyApplicationService;
