'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls: getHealthStatus (health check), getDetailedMetrics (GET
// /api/network/metrics), collectMetrics (1-minute background interval),
// cleanup (graceful shutdown), getDNSAnalytics (GET
// /api/network/dns/analytics), and recordDiscoveryEvent/recordDeviceEvent
// (WebSocket discovery handlers).

const EventEmitter = require('events');

class NetworkAnalytics extends EventEmitter {
  constructor() {
    super();
    this.events = [];
  }

  async collectMetrics() {
    return { collectedAt: new Date().toISOString() };
  }

  async getDetailedMetrics() {
    return { eventsRecorded: this.events.length };
  }

  async getDNSAnalytics() {
    return { queries: 0, topDomains: [] };
  }

  async getHealthStatus() {
    return { status: 'healthy', eventsRecorded: this.events.length };
  }

  async recordDiscoveryEvent(event) {
    this.events.push({ type: 'discovery', ...event });
  }

  recordDeviceEvent(kind, device) {
    this.events.push({ type: 'device', kind, device });
  }

  async cleanup() {
    // No timers/handles owned by this stand-in; nothing to release.
  }
}

module.exports = NetworkAnalytics;
