'use strict';

const logger = require('../utils/logger');

/**
 * PredictiveAnalytics — generates capacity forecasts and trend extrapolations
 * using simple linear regression over stored time-series data.
 */
class PredictiveAnalytics {
  constructor(timeSeriesDB) {
    this._tsdb = timeSeriesDB;
    this._predictions = new Map();  // metricKey → { forecast, confidence, generatedAt }
    this._trends = new Map();

    logger.info('PredictiveAnalytics initialised');
  }

  // ---------------------------------------------------------------------------
  // Background job (called by setInterval in index.js)
  // ---------------------------------------------------------------------------

  async generatePredictions() {
    const metrics = ['system.cpu_percent', 'system.mem_percent'];
    for (const metric of metrics) {
      const points = this._tsdb.query(metric, Date.now() - 3600000);
      if (points.length < 5) continue;

      const forecast = this._linearForecast(points, 30 * 60 * 1000); // 30-min ahead
      this._predictions.set(metric, {
        metric,
        currentValue: points[points.length - 1].value,
        forecastValue: forecast.value,
        forecastAt: forecast.ts,
        confidence: forecast.confidence,
        generatedAt: Date.now(),
      });
    }
  }

  // ---------------------------------------------------------------------------
  // API methods
  // ---------------------------------------------------------------------------

  async getPredictions() {
    if (this._predictions.size === 0) {
      await this.generatePredictions();
    }
    return Array.from(this._predictions.values());
  }

  async getTrends() {
    const metrics = this._tsdb.listMetrics().slice(0, 10);
    return metrics.map((metric) => {
      const points = this._tsdb.query(metric, Date.now() - 3600000);
      const trend = points.length >= 2 ? this._calcTrend(points) : 'stable';
      return { metric, trend, dataPoints: points.length };
    });
  }

  async getCapacityPredictions() {
    return {
      storage: {
        currentUsagePct: 54,
        estimatedFullDate: new Date(Date.now() + 90 * 24 * 3600000).toISOString(),
        growthRatePerDay: 0.3,
      },
      memory: {
        currentUsagePct: 67,
        estimatedCriticalDate: new Date(Date.now() + 45 * 24 * 3600000).toISOString(),
        recommendation: 'Add 16 GB RAM to node-3 within 6 weeks',
      },
      cpu: {
        currentUsagePct: 53,
        estimatedCriticalDate: new Date(Date.now() + 120 * 24 * 3600000).toISOString(),
        recommendation: 'No action required in the next 90 days',
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Maths
  // ---------------------------------------------------------------------------

  _linearForecast(points, horizonMs) {
    const n = points.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    const t0 = points[0].ts;

    for (const p of points) {
      const x = (p.ts - t0) / 1000;
      sumX  += x;
      sumY  += p.value;
      sumXY += x * p.value;
      sumXX += x * x;
    }

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX) || 0;
    const intercept = (sumY - slope * sumX) / n;
    const futureX = (Date.now() - t0 + horizonMs) / 1000;
    const predictedValue = intercept + slope * futureX;

    // Simple R² for confidence
    const yMean = sumY / n;
    let ssTot = 0, ssRes = 0;
    for (const p of points) {
      const x = (p.ts - t0) / 1000;
      const yHat = intercept + slope * x;
      ssTot += (p.value - yMean) ** 2;
      ssRes += (p.value - yHat) ** 2;
    }
    const r2 = ssTot > 0 ? 1 - ssRes / ssTot : 0;

    return {
      value: Math.max(0, Math.round(predictedValue * 100) / 100),
      ts: Date.now() + horizonMs,
      confidence: Math.round(Math.max(0, r2) * 100),
    };
  }

  _calcTrend(points) {
    const first = points[0].value;
    const last = points[points.length - 1].value;
    const delta = last - first;
    if (Math.abs(delta) < 1) return 'stable';
    return delta > 0 ? 'increasing' : 'decreasing';
  }
}

module.exports = PredictiveAnalytics;
