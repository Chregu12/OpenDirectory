'use strict';

const logger = require('../utils/logger');

class TrendAnalyzer {
  constructor(db) {
    this.db = db;
  }

  /**
   * Analyze compliance trends over a given period and detect anomalies.
   * @param {object} options - Analysis options
   * @returns {object} Trend analysis report
   */
  async analyzeTrends(options = {}) {
    const { days = 30, framework, platform } = options;

    logger.info(`Analyzing compliance trends over ${days} days`);

    const [fleetTrend, regressions, improvements, topFailures] = await Promise.all([
      this._getFleetTrend(days, framework, platform),
      this._detectRegressions(days),
      this._detectImprovements(days),
      this._getTopFailedChecks(framework, platform),
    ]);

    return {
      period: { days, startDate: new Date(Date.now() - days * 86400000).toISOString(), endDate: new Date().toISOString() },
      fleetTrend,
      regressions,
      improvements,
      topFailures,
      predictions: await this._predictCompliance(days),
      analyzedAt: new Date().toISOString(),
    };
  }

  /**
   * Detect devices with declining compliance scores.
   */
  async _detectRegressions(days = 7) {
    const { rows } = await this.db.query(
      `WITH recent_scores AS (
         SELECT device_id, baseline_id, score, recorded_at,
                ROW_NUMBER() OVER (PARTITION BY device_id, baseline_id ORDER BY recorded_at DESC) AS rn
         FROM compliance_history
         WHERE recorded_at >= NOW() - INTERVAL '1 day' * $1
       )
       SELECT
         r1.device_id,
         r1.baseline_id,
         cb.name AS baseline_name,
         r1.score AS current_score,
         r2.score AS previous_score,
         (r1.score - r2.score) AS delta
       FROM recent_scores r1
       JOIN recent_scores r2 ON r1.device_id = r2.device_id
         AND r1.baseline_id = r2.baseline_id AND r2.rn = 2
       LEFT JOIN compliance_baselines cb ON r1.baseline_id = cb.id
       WHERE r1.rn = 1 AND (r1.score - r2.score) < -5
       ORDER BY delta ASC
       LIMIT 50`,
      [days]
    );

    return rows.map(r => ({
      deviceId: r.device_id,
      baselineId: r.baseline_id,
      baselineName: r.baseline_name,
      currentScore: parseFloat(r.current_score),
      previousScore: parseFloat(r.previous_score),
      delta: parseFloat(r.delta),
    }));
  }

  /**
   * Detect devices with improving compliance scores.
   */
  async _detectImprovements(days = 7) {
    const { rows } = await this.db.query(
      `WITH recent_scores AS (
         SELECT device_id, baseline_id, score, recorded_at,
                ROW_NUMBER() OVER (PARTITION BY device_id, baseline_id ORDER BY recorded_at DESC) AS rn
         FROM compliance_history
         WHERE recorded_at >= NOW() - INTERVAL '1 day' * $1
       )
       SELECT
         r1.device_id,
         r1.baseline_id,
         cb.name AS baseline_name,
         r1.score AS current_score,
         r2.score AS previous_score,
         (r1.score - r2.score) AS delta
       FROM recent_scores r1
       JOIN recent_scores r2 ON r1.device_id = r2.device_id
         AND r1.baseline_id = r2.baseline_id AND r2.rn = 2
       LEFT JOIN compliance_baselines cb ON r1.baseline_id = cb.id
       WHERE r1.rn = 1 AND (r1.score - r2.score) > 5
       ORDER BY delta DESC
       LIMIT 50`,
      [days]
    );

    return rows.map(r => ({
      deviceId: r.device_id,
      baselineId: r.baseline_id,
      baselineName: r.baseline_name,
      currentScore: parseFloat(r.current_score),
      previousScore: parseFloat(r.previous_score),
      delta: parseFloat(r.delta),
    }));
  }

  /**
   * Get fleet-wide compliance trend aggregation.
   */
  async _getFleetTrend(days, framework, platform) {
    let query = `
      SELECT
        DATE_TRUNC('day', ch.recorded_at) AS day,
        AVG(ch.score) AS avg_score,
        MIN(ch.score) AS min_score,
        MAX(ch.score) AS max_score,
        COUNT(DISTINCT ch.device_id) AS device_count
      FROM compliance_history ch
    `;

    const params = [days];
    const conditions = ['ch.recorded_at >= NOW() - INTERVAL \'1 day\' * $1'];

    if (framework) {
      params.push(framework);
      conditions.push(`ch.baseline_id IN (SELECT id FROM compliance_baselines WHERE framework = $${params.length})`);
    }

    if (platform) {
      params.push(platform);
      conditions.push(`ch.baseline_id IN (SELECT id FROM compliance_baselines WHERE platform = $${params.length})`);
    }

    query += ` WHERE ${conditions.join(' AND ')} GROUP BY day ORDER BY day ASC`;

    const { rows } = await this.db.query(query, params);

    return rows.map(r => ({
      date: r.day,
      averageScore: parseFloat(parseFloat(r.avg_score).toFixed(2)),
      minScore: parseFloat(parseFloat(r.min_score).toFixed(2)),
      maxScore: parseFloat(parseFloat(r.max_score).toFixed(2)),
      deviceCount: parseInt(r.device_count, 10),
    }));
  }

  /**
   * Get the most commonly failed compliance checks across the fleet.
   */
  async _getTopFailedChecks(framework, platform) {
    // Parse failed checks from the latest results
    let query = `
      SELECT
        detail->>'checkId' AS check_id,
        detail->>'title' AS title,
        detail->>'severity' AS severity,
        detail->>'category' AS category,
        COUNT(*) AS failure_count,
        COUNT(DISTINCT cr.device_id) AS affected_devices
      FROM compliance_results cr,
           jsonb_array_elements(cr.details) AS detail
      WHERE cr.scanned_at = (
        SELECT MAX(scanned_at) FROM compliance_results
        WHERE device_id = cr.device_id AND baseline_id = cr.baseline_id
      )
      AND (detail->>'passed')::boolean = false
      AND (detail->>'skipped')::boolean IS DISTINCT FROM true
    `;

    const params = [];

    if (framework) {
      params.push(framework);
      query += ` AND cr.baseline_id IN (SELECT id FROM compliance_baselines WHERE framework = $${params.length})`;
    }

    if (platform) {
      params.push(platform);
      query += ` AND cr.baseline_id IN (SELECT id FROM compliance_baselines WHERE platform = $${params.length})`;
    }

    query += `
      GROUP BY check_id, title, severity, category
      ORDER BY failure_count DESC
      LIMIT 20
    `;

    try {
      const { rows } = await this.db.query(query, params);
      return rows.map(r => ({
        checkId: r.check_id,
        title: r.title,
        severity: r.severity,
        category: r.category,
        failureCount: parseInt(r.failure_count, 10),
        affectedDevices: parseInt(r.affected_devices, 10),
      }));
    } catch (error) {
      logger.error(`Failed to get top failed checks: ${error.message}`);
      return [];
    }
  }

  /**
   * Simple linear regression to predict future compliance based on historical trend.
   */
  async _predictCompliance(historicalDays = 30) {
    const { rows } = await this.db.query(
      `SELECT
         DATE_TRUNC('day', recorded_at) AS day,
         AVG(score) AS avg_score
       FROM compliance_history
       WHERE recorded_at >= NOW() - INTERVAL '1 day' * $1
       GROUP BY day
       ORDER BY day ASC`,
      [historicalDays]
    );

    if (rows.length < 3) {
      return { available: false, message: 'Insufficient historical data for prediction' };
    }

    // Simple linear regression
    const n = rows.length;
    const xValues = rows.map((_, i) => i);
    const yValues = rows.map(r => parseFloat(r.avg_score));

    const sumX = xValues.reduce((a, b) => a + b, 0);
    const sumY = yValues.reduce((a, b) => a + b, 0);
    const sumXY = xValues.reduce((a, x, i) => a + x * yValues[i], 0);
    const sumXX = xValues.reduce((a, x) => a + x * x, 0);

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    // Predict 7, 14, 30 days ahead
    const predictions = [7, 14, 30].map(daysAhead => {
      const predicted = Math.min(100, Math.max(0, intercept + slope * (n + daysAhead)));
      return {
        daysAhead,
        predictedScore: parseFloat(predicted.toFixed(2)),
        date: new Date(Date.now() + daysAhead * 86400000).toISOString().split('T')[0],
      };
    });

    const direction = slope > 0.1 ? 'improving' : slope < -0.1 ? 'declining' : 'stable';

    return {
      available: true,
      direction,
      slopePerDay: parseFloat(slope.toFixed(4)),
      currentAverage: parseFloat(yValues[yValues.length - 1].toFixed(2)),
      predictions,
    };
  }

  /**
   * Get a summary of compliance changes for a specific device.
   */
  async getDeviceChangelog(deviceId, limit = 50) {
    const { rows } = await this.db.query(
      `SELECT
         ch.baseline_id,
         cb.name AS baseline_name,
         cb.framework,
         ch.score,
         ch.delta,
         ch.recorded_at
       FROM compliance_history ch
       LEFT JOIN compliance_baselines cb ON ch.baseline_id = cb.id
       WHERE ch.device_id = $1 AND ch.delta != 0
       ORDER BY ch.recorded_at DESC
       LIMIT $2`,
      [deviceId, limit]
    );

    return rows.map(r => ({
      baselineId: r.baseline_id,
      baselineName: r.baseline_name,
      framework: r.framework,
      score: parseFloat(r.score),
      delta: parseFloat(r.delta),
      direction: r.delta > 0 ? 'improved' : 'declined',
      recordedAt: r.recorded_at,
    }));
  }
}

module.exports = TrendAnalyzer;
