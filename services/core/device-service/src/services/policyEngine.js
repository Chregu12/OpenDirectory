'use strict';

const logger = require('../utils/logger');

class PolicyEngine {
  constructor(db, eventBus) {
    this.db = db;
    this.eventBus = eventBus;
  }

  async getPolicies({ page = 1, limit = 50 } = {}) {
    const policies = await this.db.find('policies', {});
    const total = policies.length;
    const start = (page - 1) * limit;
    return { policies: policies.slice(start, start + limit), pagination: { page, limit, total } };
  }

  async getPolicy(id) {
    return this.db.findById('policies', id);
  }

  async createPolicy(data, user) {
    const id = data.id || `pol-${Date.now()}`;
    const policy = await this.db.insert('policies', { ...data, id, createdBy: user?.id || 'system' });
    this.eventBus.emit('policy:created', { policy });
    return policy;
  }

  async updatePolicy(id, updates) {
    const policy = await this.db.update('policies', id, updates);
    if (policy) this.eventBus.emit('policy:updated', { policy });
    return policy;
  }

  async deletePolicy(id) {
    const ok = await this.db.delete('policies', id);
    if (ok) this.eventBus.emit('policy:deleted', { policyId: id });
    return ok;
  }

  async assignPolicy(policyId, { deviceIds = [], groupIds = [] } = {}) {
    const policy = await this.db.findById('policies', policyId);
    if (!policy) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });
    const assignment = await this.db.insert('policy_assignments', {
      id: `pa-${Date.now()}`,
      policyId,
      deviceIds,
      groupIds,
      assignedAt: new Date().toISOString()
    });
    this.eventBus.emit('policy:assigned', { policyId, deviceIds, groupIds });
    return assignment;
  }

  async deployPolicy(policyId, options = {}) {
    const policy = await this.db.findById('policies', policyId);
    if (!policy) throw Object.assign(new Error('Policy not found'), { statusCode: 404 });
    const deployment = await this.db.insert('policy_deployments', {
      id: `pd-${Date.now()}`,
      policyId,
      status: 'deployed',
      deployedAt: new Date().toISOString(),
      ...options
    });
    this.eventBus.emit('policy:deployed', { policy, deployment });
    return deployment;
  }

  async assignDefaultPolicies(deviceId) {
    const defaults = await this.db.find('policies', { isDefault: true });
    for (const policy of defaults) {
      await this.assignPolicy(policy.id, { deviceIds: [deviceId] });
    }
  }

  async getDevicePolicies(deviceId) {
    const assignments = await this.db.find('policy_assignments', {});
    const relevant = assignments.filter(a => (a.deviceIds || []).includes(deviceId));
    const policyIds = [...new Set(relevant.map(a => a.policyId))];
    const policies = await Promise.all(policyIds.map(id => this.db.findById('policies', id)));
    return policies.filter(Boolean);
  }
}

module.exports = PolicyEngine;
