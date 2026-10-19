'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls (getStatus, getHealthStatus) and the 'connectionEstablished'
// / 'connectionTerminated' events it listens for. The VPN HTTP routes are
// still explicit "implementation needed" placeholders (pre-existing, out of
// scope here) but now require an authenticated JWT same as every other
// mutation in this service.

const EventEmitter = require('events');

class VPNManager extends EventEmitter {
  constructor() {
    super();
    this.connections = new Map();
  }

  async getStatus() {
    return { activeConnections: this.connections.size };
  }

  async getHealthStatus() {
    return { status: 'healthy', activeConnections: this.connections.size };
  }
}

module.exports = VPNManager;
