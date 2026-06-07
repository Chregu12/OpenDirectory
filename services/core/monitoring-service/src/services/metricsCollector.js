'use strict';

const os = require('os');
const logger = require('../utils/logger');

/**
 * MetricsCollector — collects OS / process metrics using built-in Node modules
 * and optionally exposes them in Prometheus text format via prom-client.
 */
class MetricsCollector {
  constructor(timeSeriesDB, metricsCache) {
    this._tsdb = timeSeriesDB;
    this._cache = metricsCache;
    this._apiMetrics = [];  // recent API calls
    this._totalMetrics = 0;

    // Try to load prom-client (listed in package.json)
    try {
      this._promClient = require('prom-client');
      this._promRegistry = new this._promClient.Registry();
      this._promClient.collectDefaultMetrics({ register: this._promRegistry });
    } catch {
      this._promClient = null;
    }

    // Start periodic collection
    this._collectionInterval = setInterval(() => this._collect(), 15000);
    if (this._collectionInterval.unref) this._collectionInterval.unref();

    // Seed with first reading immediately
    this._collect();

    logger.info('MetricsCollector initialised');
  }

  // ---------------------------------------------------------------------------
  // Collection
  // ---------------------------------------------------------------------------

  _collect() {
    const ts = Date.now();
    const cpus = os.cpus();
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;
    const memPct = (usedMem / totalMem) * 100;

    // CPU usage: average idle across all cores
    let totalIdle = 0;
    let totalTick = 0;
    cpus.forEach((cpu) => {
      for (const type in cpu.times) {
        totalTick += cpu.times[type];
      }
      totalIdle += cpu.times.idle;
    });
    const cpuPct = 100 - (totalIdle / totalTick) * 100;

    const load = os.loadavg(); // [1m, 5m, 15m]

    this._tsdb.insert('system.cpu_percent', Math.round(cpuPct * 100) / 100, {}, ts);
    this._tsdb.insert('system.mem_used_bytes', usedMem, {}, ts);
    this._tsdb.insert('system.mem_percent', Math.round(memPct * 100) / 100, {}, ts);
    this._tsdb.insert('system.load_1m', load[0], {}, ts);
    this._tsdb.insert('system.load_5m', load[1], {}, ts);
    this._tsdb.insert('system.load_15m', load[2], {}, ts);
    this._tsdb.insert('process.uptime_s', process.uptime(), {}, ts);
    this._tsdb.insert('process.heap_used', process.memoryUsage().heapUsed, {}, ts);
    this._tsdb.insert('process.rss', process.memoryUsage().rss, {}, ts);

    this._totalMetrics += 9;

    // Update cache
    this._cache.set('system.current', {
      cpu: cpuPct,
      memUsed: usedMem,
      memTotal: totalMem,
      memPercent: memPct,
      load1m: load[0],
      load5m: load[1],
      load15m: load[2],
      uptime: process.uptime(),
      ts,
    }, 30000);
  }

  // ---------------------------------------------------------------------------
  // Public API called by index.js
  // ---------------------------------------------------------------------------

  recordAPIMetric(method, path, statusCode, durationMs) {
    const ts = Date.now();
    this._apiMetrics.push({ method, path, statusCode, durationMs, ts });
    // Keep last 1000 only
    if (this._apiMetrics.length > 1000) this._apiMetrics.shift();

    this._tsdb.insert('api.request_duration_ms', durationMs, { method, path, statusCode: String(statusCode) }, ts);
    this._tsdb.insert('api.request_count', 1, { method, path }, ts);
  }

  async getRealTimeMetrics({ services, metrics, interval } = {}) {
    const current = this._cache.get('system.current') || {};
    return {
      timestamp: Date.now(),
      system: current,
      process: {
        uptime: process.uptime(),
        ...process.memoryUsage(),
      },
      api: {
        recent: this._apiMetrics.slice(-20),
      },
    };
  }

  async getHistoricalMetrics({ services, metrics, startTime, endTime, aggregation } = {}) {
    const end = endTime || Date.now();
    const start = startTime || end - 3600000; // default 1 hour
    const metricNames = metrics || this._tsdb.listMetrics();
    return this._tsdb.queryMultiple(metricNames, start, end);
  }

  async getCustomMetrics(query = {}) {
    return this.getRealTimeMetrics(query);
  }

  async queryMetrics(query = {}) {
    return this.getRealTimeMetrics(query);
  }

  async ingestMetrics(metricsData) {
    if (Array.isArray(metricsData)) {
      this._tsdb.insertBatch(metricsData);
      this._totalMetrics += metricsData.length;
    } else if (metricsData && metricsData.metric) {
      this._tsdb.insert(metricsData.metric, metricsData.value, metricsData.labels, metricsData.ts);
      this._totalMetrics++;
    }
  }

  async getTotalMetricsCount() {
    return this._totalMetrics;
  }

  async getPrometheusMetrics() {
    if (this._promClient && this._promRegistry) {
      return this._promRegistry.metrics();
    }
    // Fallback: minimal text format
    const cur = this._cache.get('system.current') || {};
    return [
      `# HELP system_cpu_percent CPU usage percentage`,
      `# TYPE system_cpu_percent gauge`,
      `system_cpu_percent ${cur.cpu || 0}`,
      `# HELP system_mem_percent Memory usage percentage`,
      `# TYPE system_mem_percent gauge`,
      `system_mem_percent ${cur.memPercent || 0}`,
    ].join('\n');
  }
}

module.exports = MetricsCollector;
