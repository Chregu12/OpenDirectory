'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls: getStatus (status broadcast), getUsageReport (GET
// /api/network/bandwidth/usage), and the 'bandwidthExceeded' event it
// listens for.

const EventEmitter = require('events');

class BandwidthManager extends EventEmitter {
  constructor() {
    super();
    this.limits = new Map();
  }

  async getStatus() {
    return { limitsConfigured: this.limits.size };
  }

  async getUsageReport(timeRange = '24h') {
    return { timeRange, usageMbps: null, samples: [] };
  }
}

module.exports = BandwidthManager;
