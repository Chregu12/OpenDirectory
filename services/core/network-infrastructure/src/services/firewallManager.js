'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls unconditionally at construction/health-check time
// (performOperation, getStatus, getHealthStatus) and the 'ruleAdded' /
// 'ruleBlocked' events it listens for. The actual firewall HTTP routes
// (getFirewallRules/createFirewallRule/etc., src/index.js ~1576-1581) are
// still explicit "implementation needed" placeholders and are NOT wired to
// this class — that's pre-existing, out of scope for the auth fix. Those
// routes now require an admin-scoped JWT (see src/middleware/oidcAuth.js)
// same as if they were fully implemented.

const EventEmitter = require('events');

class FirewallManager extends EventEmitter {
  constructor() {
    super();
    this.rules = new Map();
  }

  async performOperation(...args) {
    return { ok: true, service: 'firewall', args };
  }

  async getStatus() {
    return { rules: this.rules.size, activeRules: this.rules.size };
  }

  async getHealthStatus() {
    return { status: 'healthy', rules: this.rules.size };
  }
}

module.exports = FirewallManager;
