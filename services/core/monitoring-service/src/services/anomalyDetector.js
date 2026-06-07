'use strict';

const logger = require('../utils/logger');
const config = require('../config');

/**
 * AnomalyDetector — applies a simple z-score / 3-sigma rule to detect
 * anomalies in time-series data and fires events via the AlertManager.
 */
class AnomalyDetector {
  constructor(timeSeriesDB, alertManager) {
    this._tsdb = timeSeriesDB;
    this._alertManager = alertManager;
    this._anomalyCount = 0;
    this._detected = [];    // ring buffer of recent anomalies
    this._maxDetected = 500;

    this._sensitivitySigma = config.anomalyDetection.sensitivitySigma;

    logger.info('AnomalyDetector initialised', { sigma: this._sensitivitySigma });
  }

  // ---------------------------------------------------------------------------
  // Background job (called by setInterval in index.js)
  // ---------------------------------------------------------------------------

  async detectAnomalies() {
    const metricsToCheck = ['system.cpu_percent', 'system.mem_percent', 'process.heap_used'];

    for (const metric of metricsToCheck) {
      const points = this._tsdb.query(metric, Date.now() - 3600000);
      if (points.length < 10) continue;

      const anomalies = this._zscore(metric, points);
      for (const anomaly of anomalies) {
        this._recordAnomaly(anomaly);
        await this._alertManager.trigger({
          name: `Anomaly: ${metric}`,
          service: 'monitoring',
          severity: 'warning',
          message: `Anomalous value detected for ${metric}: ${anomaly.value} (z-score: ${anomaly.zScore.toFixed(2)})`,
          metric,
          currentValue: anomaly.value,
        });
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Z-score analysis
  // ---------------------------------------------------------------------------

  _zscore(metric, points) {
    const values = points.map((p) => p.value);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const variance = values.reduce((a, v) => a + (v - mean) ** 2, 0) / values.length;
    const std = Math.sqrt(variance);

    if (std === 0) return [];

    const anomalies = [];
    for (const point of points) {
      const z = Math.abs((point.value - mean) / std);
      if (z > this._sensitivitySigma) {
        anomalies.push({ metric, value: point.value, ts: point.ts, zScore: z, mean, std });
      }
    }
    return anomalies;
  }

  _recordAnomaly(anomaly) {
    this._anomalyCount++;
    this._detected.push({ ...anomaly, detectedAt: Date.now() });
    if (this._detected.length > this._maxDetected) this._detected.shift();
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  async getAnomalyCount() {
    return this._anomalyCount;
  }

  async getAnomalies({ limit = 50 } = {}) {
    return this._detected.slice(-limit).reverse();
  }
}

module.exports = AnomalyDetector;
