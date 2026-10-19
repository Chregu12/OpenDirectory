'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls: getPerformanceMetrics/getHealthStatus (health check +
// status broadcast), performHealthCheck (5-minute background interval),
// cleanup (graceful shutdown), and the 'performanceAlert' / 'outageDetected'
// events it listens for.

const EventEmitter = require('events');

class NetworkMonitoring extends EventEmitter {
  constructor() {
    super();
    this.lastCheck = null;
  }

  async performHealthCheck() {
    this.lastCheck = new Date().toISOString();
    return { status: 'ok', checkedAt: this.lastCheck };
  }

  async getPerformanceMetrics() {
    return { latencyMs: null, packetLoss: null, lastCheck: this.lastCheck };
  }

  async getHealthStatus() {
    return { status: 'healthy', lastCheck: this.lastCheck };
  }

  async cleanup() {
    // No timers/handles owned by this stand-in; nothing to release.
  }
}

module.exports = NetworkMonitoring;
