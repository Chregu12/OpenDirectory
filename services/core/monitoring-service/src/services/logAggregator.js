'use strict';

const logger = require('../utils/logger');
const config = require('../config');

/**
 * LogAggregator — collects, indexes, and queries log entries.
 * Stores logs in-memory with configurable retention and exposes search
 * and streaming capabilities.
 */
class LogAggregator {
  constructor(timeSeriesDB) {
    this._tsdb = timeSeriesDB;
    this._logs = [];        // Array of log entries
    this._maxLogs = 100000;
    this._retentionDays = config.logging.retentionDays;
    this._subscribers = new Set(); // SSE / WebSocket callbacks for live streaming

    logger.info('LogAggregator initialised');
  }

  // ---------------------------------------------------------------------------
  // Ingestion
  // ---------------------------------------------------------------------------

  ingest(entry) {
    const log = {
      id: `log-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      ts: entry.ts || entry.timestamp || Date.now(),
      level: entry.level || 'info',
      service: entry.service || 'unknown',
      message: entry.message || '',
      meta: entry.meta || entry.fields || {},
    };

    this._logs.push(log);
    if (this._logs.length > this._maxLogs) {
      this._logs.shift();
    }

    // Track counts in time-series
    this._tsdb.insert(`logs.count.${log.level}`, 1, { service: log.service }, log.ts);

    // Broadcast to subscribers
    for (const cb of this._subscribers) {
      try { cb(log); } catch { /* ignore */ }
    }

    return log;
  }

  ingestBatch(entries) {
    return entries.map((e) => this.ingest(e));
  }

  // ---------------------------------------------------------------------------
  // Search
  // ---------------------------------------------------------------------------

  search({ query, level, service, startTs, endTs, limit = 100, offset = 0 } = {}) {
    let results = this._logs;

    if (level)   results = results.filter((l) => l.level === level);
    if (service) results = results.filter((l) => l.service === service);
    if (startTs) results = results.filter((l) => l.ts >= startTs);
    if (endTs)   results = results.filter((l) => l.ts <= endTs);
    if (query) {
      const q = query.toLowerCase();
      results = results.filter((l) => l.message.toLowerCase().includes(q));
    }

    // Most recent first
    results = results.slice().reverse();
    return results.slice(offset, offset + limit);
  }

  // ---------------------------------------------------------------------------
  // Analysis
  // ---------------------------------------------------------------------------

  getAnalysis() {
    const byLevel = {};
    const byService = {};
    for (const l of this._logs) {
      byLevel[l.level] = (byLevel[l.level] || 0) + 1;
      byService[l.service] = (byService[l.service] || 0) + 1;
    }
    return {
      total: this._logs.length,
      byLevel,
      byService,
      topErrors: this._logs
        .filter((l) => l.level === 'error')
        .slice(-20)
        .reverse()
        .map((l) => ({ message: l.message, service: l.service, ts: l.ts })),
    };
  }

  // ---------------------------------------------------------------------------
  // Streaming
  // ---------------------------------------------------------------------------

  subscribe(callback) {
    this._subscribers.add(callback);
    return () => this._subscribers.delete(callback);
  }

  // ---------------------------------------------------------------------------
  // Retention cleanup (called by background job in index.js)
  // ---------------------------------------------------------------------------

  async cleanupOldLogs() {
    const cutoff = Date.now() - this._retentionDays * 24 * 60 * 60 * 1000;
    const before = this._logs.length;
    this._logs = this._logs.filter((l) => l.ts >= cutoff);
    const removed = before - this._logs.length;
    if (removed > 0) {
      logger.info('LogAggregator cleanup', { removed });
    }
  }
}

module.exports = LogAggregator;
