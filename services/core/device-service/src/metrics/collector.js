'use strict';

/**
 * MetricsCollector — lightweight in-process metrics store.
 */
class MetricsCollector {
  constructor() {
    this._responseTimes = new Map(); // path → [durations]
    this._counters = new Map();
  }

  recordResponseTime(path, durationMs) {
    if (!path) return;
    const times = this._responseTimes.get(path) || [];
    times.push(durationMs);
    if (times.length > 1000) times.shift(); // rolling window
    this._responseTimes.set(path, times);
  }

  increment(key, amount = 1) {
    this._counters.set(key, (this._counters.get(key) || 0) + amount);
  }

  getAll() {
    const result = {};
    this._counters.forEach((v, k) => { result[k] = v; });
    return result;
  }
}

module.exports = MetricsCollector;
