'use strict';

const axios = require('axios');
const logger = require('../utils/logger');
const config = require('../config');

/**
 * HealthChecker — pings internal services via HTTP and maintains a rolling
 * health-status map that the monitoring service exposes via the /health endpoint
 * and WebSocket subscriptions.
 */
class HealthChecker {
  constructor(eventBus) {
    this._bus = eventBus;
    this._status = new Map();   // serviceName → { status, latencyMs, lastCheck, error }
    this._closed = false;

    this._targets = Object.entries(config.services).map(([name, url]) => ({
      name,
      url: `${url}/health`,
    }));

    // Run checks every 30 seconds
    this._timer = setInterval(() => this._checkAll(), 30000);
    if (this._timer.unref) this._timer.unref();

    // Initial check
    this._checkAll();

    logger.info('HealthChecker initialised', { targets: this._targets.map((t) => t.name) });
  }

  // ---------------------------------------------------------------------------
  // Checking
  // ---------------------------------------------------------------------------

  async _checkAll() {
    await Promise.allSettled(this._targets.map((t) => this._checkOne(t)));
  }

  async _checkOne({ name, url }) {
    const start = Date.now();
    let result;
    try {
      const res = await axios.get(url, { timeout: 5000 });
      const latencyMs = Date.now() - start;
      result = {
        status: res.status < 400 ? 'healthy' : 'degraded',
        latencyMs,
        lastCheck: new Date().toISOString(),
        error: null,
        httpStatus: res.status,
      };
    } catch (err) {
      result = {
        status: 'unhealthy',
        latencyMs: Date.now() - start,
        lastCheck: new Date().toISOString(),
        error: err.message,
        httpStatus: null,
      };
    }

    const previous = this._status.get(name);
    this._status.set(name, result);

    if (!previous || previous.status !== result.status) {
      this._bus.emit('health:status_change', { service: name, ...result });
      logger.info('Health status change', { service: name, status: result.status });
    }
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  async getSystemHealth() {
    const services = {};
    for (const [name, data] of this._status.entries()) {
      services[name] = data;
    }

    const statuses = Object.values(services).map((s) => s.status);
    let overall;
    if (statuses.every((s) => s === 'healthy')) {
      overall = 'healthy';
    } else if (statuses.some((s) => s === 'unhealthy')) {
      overall = 'degraded';
    } else if (statuses.length === 0) {
      overall = 'healthy'; // No external deps configured
    } else {
      overall = 'healthy';
    }

    return {
      status: overall,
      services,
      checkedAt: new Date().toISOString(),
    };
  }

  async getCurrentHealthStatus() {
    return this.getSystemHealth();
  }
}

module.exports = HealthChecker;
