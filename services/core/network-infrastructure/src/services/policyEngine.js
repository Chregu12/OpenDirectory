'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls: createPolicy (POST /api/network/policies, which now
// requires an authenticated JWT — see src/middleware/oidcAuth.js), and the
// 'policyViolation' / 'policyApplied' events it listens for.

const EventEmitter = require('events');

class PolicyEngine extends EventEmitter {
  constructor() {
    super();
    this.policies = new Map();
  }

  async createPolicy(data) {
    const policy = { id: this.policies.size + 1, ...data, createdAt: new Date().toISOString() };
    this.policies.set(policy.id, policy);
    this.emit('policyApplied', policy);
    return policy;
  }
}

module.exports = PolicyEngine;
