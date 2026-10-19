'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Minimal stand-in satisfying the interface
// index.js calls: getStatus/getHealthStatus (health check + status
// broadcast), performSecurityScan (5-minute background interval), cleanup
// (graceful shutdown), performScan (POST /api/network/security/scan, which
// now requires an authenticated JWT — see src/middleware/oidcAuth.js), and
// the 'vulnerabilityDetected' / 'intrusionDetected' events it listens for.

const EventEmitter = require('events');

class SecurityScanner extends EventEmitter {
  constructor() {
    super();
    this.lastScan = null;
  }

  async performSecurityScan() {
    this.lastScan = new Date().toISOString();
    return { status: 'ok', scannedAt: this.lastScan };
  }

  async performScan(target, scanType = 'vulnerability') {
    this.lastScan = new Date().toISOString();
    return { target, scanType, findings: [], scannedAt: this.lastScan };
  }

  async getStatus() {
    return { lastScan: this.lastScan };
  }

  async getHealthStatus() {
    return { status: 'healthy', lastScan: this.lastScan };
  }

  async cleanup() {
    // No timers/handles owned by this stand-in; nothing to release.
  }
}

module.exports = SecurityScanner;
