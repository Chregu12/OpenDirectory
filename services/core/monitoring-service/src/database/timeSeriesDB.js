'use strict';

const logger = require('../utils/logger');
const config = require('../config');

/**
 * TimeSeriesDB — in-memory time-series store with configurable retention.
 *
 * Data layout:
 *   this._series  Map<string, Array<{ ts: number, value: number, labels: object }>>
 *
 * Each key is a metric name (e.g. "cpu.usage.system_a").  Values are arrays of
 * data-points sorted by timestamp ascending.
 */
class TimeSeriesDB {
  constructor(options = {}) {
    this._series = new Map();
    this._retentionMs = options.retentionMs || config.timeSeries.defaultRetentionMs;
    this._closed = false;

    // Periodic cleanup
    this._cleanupTimer = setInterval(() => this._cleanup(), config.timeSeries.cleanupIntervalMs);
    // Allow the process to exit even if the interval is still running
    if (this._cleanupTimer.unref) this._cleanupTimer.unref();

    logger.info('TimeSeriesDB initialised (in-memory)', { retentionMs: this._retentionMs });
  }

  // ---------------------------------------------------------------------------
  // Write
  // ---------------------------------------------------------------------------

  /**
   * Insert one data-point.
   * @param {string} metric
   * @param {number} value
   * @param {object} [labels]
   * @param {number} [ts]  unix millisecond timestamp (defaults to now)
   */
  insert(metric, value, labels = {}, ts = Date.now()) {
    if (!this._series.has(metric)) {
      this._series.set(metric, []);
    }
    this._series.get(metric).push({ ts, value, labels });
  }

  /**
   * Batch insert.
   * @param {Array<{ metric, value, labels, ts }>} points
   */
  insertBatch(points) {
    for (const p of points) {
      this.insert(p.metric, p.value, p.labels, p.ts);
    }
  }

  // ---------------------------------------------------------------------------
  // Read
  // ---------------------------------------------------------------------------

  /**
   * Query data-points within a time range.
   * @param {string} metric
   * @param {number} [startTs]
   * @param {number} [endTs]
   * @returns {Array<{ ts, value, labels }>}
   */
  query(metric, startTs = 0, endTs = Date.now()) {
    const points = this._series.get(metric) || [];
    return points.filter((p) => p.ts >= startTs && p.ts <= endTs);
  }

  /**
   * Query multiple metrics.
   * @param {string[]} metrics
   * @param {number} [startTs]
   * @param {number} [endTs]
   * @returns {object}  { [metric]: Array<point> }
   */
  queryMultiple(metrics, startTs = 0, endTs = Date.now()) {
    const result = {};
    for (const m of metrics) {
      result[m] = this.query(m, startTs, endTs);
    }
    return result;
  }

  /**
   * Return the latest data-point for a metric (or null).
   */
  getLatest(metric) {
    const points = this._series.get(metric);
    if (!points || points.length === 0) return null;
    return points[points.length - 1];
  }

  /**
   * Return all known metric names.
   */
  listMetrics() {
    return Array.from(this._series.keys());
  }

  /**
   * Aggregate data-points within a time range.
   * @param {string} metric
   * @param {number} startTs
   * @param {number} endTs
   * @param {string} fn  'avg' | 'min' | 'max' | 'sum' | 'count'
   */
  aggregate(metric, startTs, endTs, fn = 'avg') {
    const points = this.query(metric, startTs, endTs);
    if (points.length === 0) return null;
    const values = points.map((p) => p.value);
    switch (fn) {
      case 'min': return Math.min(...values);
      case 'max': return Math.max(...values);
      case 'sum': return values.reduce((a, b) => a + b, 0);
      case 'count': return values.length;
      case 'avg':
      default: return values.reduce((a, b) => a + b, 0) / values.length;
    }
  }

  // ---------------------------------------------------------------------------
  // Maintenance
  // ---------------------------------------------------------------------------

  _cleanup() {
    const cutoff = Date.now() - this._retentionMs;
    let removed = 0;
    for (const [metric, points] of this._series.entries()) {
      const before = points.length;
      const filtered = points.filter((p) => p.ts >= cutoff);
      this._series.set(metric, filtered);
      removed += before - filtered.length;
    }
    if (removed > 0) {
      logger.debug('TimeSeriesDB cleanup', { removed });
    }
  }

  async close() {
    this._closed = true;
    if (this._cleanupTimer) clearInterval(this._cleanupTimer);
    logger.info('TimeSeriesDB closed');
  }
}

module.exports = TimeSeriesDB;
