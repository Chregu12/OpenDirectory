'use strict';

/**
 * TrendAnalyzer – stores daily compliance snapshots and computes trends
 * for devices and the overall fleet.
 */
class TrendAnalyzer {
  constructor({ pgPool, redis, logger }) {
    this.pgPool = pgPool;
    this.redis = redis;
    this.logger = logger;
  }

  // ---------------------------------------------------------------------------
  // Recording
  // ---------------------------------------------------------------------------

  /**
   * Record a compliance score snapshot.
   */
  async recordSnapshot(deviceId, score, baselineId) {
    try {
      // Get previous score for delta calculation
      const { rows: prev } = await this.pgPool.query(
        `SELECT score FROM compliance_history
         WHERE device_id = $1 ORDER BY recorded_at DESC LIMIT 1`,
        [deviceId]
      );
      const delta = prev.length > 0 ? score - parseFloat(prev[0].score) : 0;

      await this.pgPool.query(
        `INSERT INTO compliance_history (device_id, baseline_id, score, delta, recorded_at)
         VALUES ($1, $2, $3, $4, NOW())`,
        [deviceId, baselineId || null, score, Math.round(delta * 100) / 100]
      );
    } catch (err) {
      this.logger.error('Failed to record compliance snapshot', { error: err.message });
    }
  }

  // ---------------------------------------------------------------------------
  // Device trend
  // ---------------------------------------------------------------------------

  /**
   * Get compliance trend for a specific device.
   * @param {string} deviceId
   * @param {number} days - number of days to look back
   */
  async getDeviceTrend(deviceId, days = 30) {
    try {
      const { rows } = await this.pgPool.query(
        `SELECT
           DATE(recorded_at) AS date,
           ROUND(AVG(score)::numeric, 2) AS score,
           ROUND(AVG(delta)::numeric, 2) AS delta
         FROM compliance_history
         WHERE device_id = $1
           AND recorded_at >= NOW() - INTERVAL '1 day' * $2
         GROUP BY DATE(recorded_at)
         ORDER BY date ASC`,
        [deviceId, days]
      );

      const trend = this._calculateTrendDirection(rows);

      return {
        deviceId,
        days,
        dataPoints: rows,
        trend: trend.direction,
        averageScore: trend.average,
        changeRate: trend.changeRate,
        prediction: trend.prediction,
      };
    } catch (err) {
      this.logger.error('Failed to get device trend', { error: err.message });
      return { deviceId, days, dataPoints: [], trend: 'unknown' };
    }
  }

  // ---------------------------------------------------------------------------
  // Fleet trend
  // ---------------------------------------------------------------------------

  /**
   * Get fleet-wide compliance trend.
   * @param {number} days
   */
  async getFleetTrend(days = 30) {
    try {
      const { rows } = await this.pgPool.query(
        `SELECT
           DATE(recorded_at) AS date,
           ROUND(AVG(score)::numeric, 2) AS avg_score,
           COUNT(DISTINCT device_id) AS devices_evaluated,
           COUNT(DISTINCT device_id) FILTER (WHERE score = 100) AS fully_compliant,
           COUNT(DISTINCT device_id) FILTER (WHERE score < 70) AS at_risk
         FROM compliance_history
         WHERE recorded_at >= NOW() - INTERVAL '1 day' * $1
         GROUP BY DATE(recorded_at)
         ORDER BY date ASC`,
        [days]
      );

      const scorePoints = rows.map((r) => ({ date: r.date, score: parseFloat(r.avg_score) }));
      const trend = this._calculateTrendDirection(scorePoints);

      return {
        days,
        dataPoints: rows,
        trend: trend.direction,
        averageScore: trend.average,
        changeRate: trend.changeRate,
        prediction: trend.prediction,
      };
    } catch (err) {
      this.logger.error('Failed to get fleet trend', { error: err.message });
      return { days, dataPoints: [], trend: 'unknown' };
    }
  }

  // ---------------------------------------------------------------------------
  // Trend calculation
  // ---------------------------------------------------------------------------

  /**
   * Determine trend direction from data points.
   * Uses simple linear regression on score values.
   */
  _calculateTrendDirection(dataPoints) {
    if (!dataPoints || dataPoints.length < 2) {
      const score = dataPoints.length === 1 ? parseFloat(dataPoints[0].score || dataPoints[0].avg_score || 0) : 0;
      return { direction: 'insufficient_data', average: score, changeRate: 0, prediction: score };
    }

    const scores = dataPoints.map((p) => parseFloat(p.score || p.avg_score || 0));
    const n = scores.length;

    // Calculate average
    const average = Math.round((scores.reduce((a, b) => a + b, 0) / n) * 100) / 100;

    // Simple linear regression: y = mx + b
    const xMean = (n - 1) / 2;
    const yMean = average;

    let numerator = 0;
    let denominator = 0;
    for (let i = 0; i < n; i++) {
      numerator += (i - xMean) * (scores[i] - yMean);
      denominator += (i - xMean) ** 2;
    }

    const slope = denominator !== 0 ? numerator / denominator : 0;
    const changeRate = Math.round(slope * 100) / 100;

    // Predict next value
    const prediction = Math.min(100, Math.max(0, Math.round((scores[n - 1] + slope) * 100) / 100));

    // Classify direction
    let direction;
    if (Math.abs(slope) < 0.5) {
      direction = 'stable';
    } else if (slope > 0) {
      direction = 'improving';
    } else {
      direction = 'declining';
    }

    return { direction, average, changeRate, prediction };
  }
}

module.exports = TrendAnalyzer;
