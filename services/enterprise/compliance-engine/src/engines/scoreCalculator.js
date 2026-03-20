'use strict';

const logger = require('../utils/logger');

const SEVERITY_WEIGHTS = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

class ScoreCalculator {
  constructor(db) {
    this.db = db;
  }

  /**
   * Calculate a weighted compliance score.
   * Severity weights: critical=4x, high=3x, medium=2x, low=1x
   * Waivered checks count as passed.
   *
   * @param {Array} checks - Check definitions from baseline
   * @param {Array} results - Evaluation results per check
   * @param {Array} waivers - Active waivers
   * @returns {object} Score breakdown
   */
  calculate(checks, results, waivers = []) {
    const breakdown = {
      critical: { total: 0, passed: 0, failed: 0, waived: 0, skipped: 0 },
      high: { total: 0, passed: 0, failed: 0, waived: 0, skipped: 0 },
      medium: { total: 0, passed: 0, failed: 0, waived: 0, skipped: 0 },
      low: { total: 0, passed: 0, failed: 0, waived: 0, skipped: 0 },
    };

    let totalWeight = 0;
    let passedWeight = 0;
    let totalCount = 0;
    let passedCount = 0;
    let failedCount = 0;
    let skippedCount = 0;
    let waivedCount = 0;

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const check = checks[i] || {};
      const severity = (result.severity || check.severity || 'medium').toLowerCase();
      const weight = SEVERITY_WEIGHTS[severity] || SEVERITY_WEIGHTS.medium;
      const severityKey = SEVERITY_WEIGHTS[severity] !== undefined ? severity : 'medium';

      totalCount++;
      breakdown[severityKey].total++;

      if (result.skipped) {
        skippedCount++;
        breakdown[severityKey].skipped++;
        // Skipped checks do not count toward score
        continue;
      }

      totalWeight += weight;

      if (result.waived) {
        // Waivered checks count as passed
        waivedCount++;
        passedCount++;
        passedWeight += weight;
        breakdown[severityKey].waived++;
        breakdown[severityKey].passed++;
      } else if (result.passed) {
        passedCount++;
        passedWeight += weight;
        breakdown[severityKey].passed++;
      } else {
        failedCount++;
        breakdown[severityKey].failed++;
      }
    }

    const score = totalWeight > 0
      ? parseFloat(((passedWeight / totalWeight) * 100).toFixed(2))
      : 0;

    return {
      score,
      totalWeight,
      passedWeight,
      totalCount,
      passedCount,
      failedCount,
      skippedCount,
      waivedCount,
      breakdown,
    };
  }

  /**
   * Get average compliance score for all devices in an OU.
   */
  async getOUScore(ouId) {
    // OU membership would typically come from the directory service.
    // Here we query compliance results for devices tagged with an OU.
    const { rows } = await this.db.query(
      `SELECT
         COUNT(DISTINCT cr.device_id) AS device_count,
         AVG(cr.score) AS avg_score,
         MIN(cr.score) AS min_score,
         MAX(cr.score) AS max_score,
         SUM(cr.critical_failures) AS total_critical,
         SUM(cr.high_failures) AS total_high
       FROM compliance_results cr
       WHERE cr.device_id IN (
         SELECT device_id FROM compliance_results
         WHERE details::text LIKE $1
       )
       AND cr.scanned_at = (
         SELECT MAX(scanned_at) FROM compliance_results
         WHERE device_id = cr.device_id AND baseline_id = cr.baseline_id
       )`,
      [`%${ouId}%`]
    );

    const row = rows[0];
    return {
      ouId,
      deviceCount: parseInt(row.device_count, 10) || 0,
      averageScore: row.avg_score ? parseFloat(parseFloat(row.avg_score).toFixed(2)) : 0,
      minScore: row.min_score ? parseFloat(parseFloat(row.min_score).toFixed(2)) : 0,
      maxScore: row.max_score ? parseFloat(parseFloat(row.max_score).toFixed(2)) : 0,
      totalCriticalFailures: parseInt(row.total_critical, 10) || 0,
      totalHighFailures: parseInt(row.total_high, 10) || 0,
    };
  }

  /**
   * Get domain-wide compliance score.
   */
  async getDomainScore() {
    const { rows } = await this.db.query(
      `SELECT
         COUNT(DISTINCT cr.device_id) AS device_count,
         AVG(cr.score) AS avg_score,
         MIN(cr.score) AS min_score,
         MAX(cr.score) AS max_score,
         PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY cr.score) AS median_score,
         COUNT(*) FILTER (WHERE cr.score >= 90) AS compliant_count,
         COUNT(*) FILTER (WHERE cr.score < 90 AND cr.score >= 70) AS partial_count,
         COUNT(*) FILTER (WHERE cr.score < 70) AS non_compliant_count
       FROM compliance_results cr
       WHERE cr.scanned_at = (
         SELECT MAX(scanned_at) FROM compliance_results
         WHERE device_id = cr.device_id AND baseline_id = cr.baseline_id
       )`
    );

    const row = rows[0];
    return {
      deviceCount: parseInt(row.device_count, 10) || 0,
      averageScore: row.avg_score ? parseFloat(parseFloat(row.avg_score).toFixed(2)) : 0,
      minScore: row.min_score ? parseFloat(parseFloat(row.min_score).toFixed(2)) : 0,
      maxScore: row.max_score ? parseFloat(parseFloat(row.max_score).toFixed(2)) : 0,
      medianScore: row.median_score ? parseFloat(parseFloat(row.median_score).toFixed(2)) : 0,
      compliantDevices: parseInt(row.compliant_count, 10) || 0,
      partiallyCompliant: parseInt(row.partial_count, 10) || 0,
      nonCompliant: parseInt(row.non_compliant_count, 10) || 0,
    };
  }

  /**
   * Get compliance score trend over time for a device.
   */
  async getTrend(deviceId, days = 30) {
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
       WHERE ch.device_id = $1
         AND ch.recorded_at >= NOW() - INTERVAL '1 day' * $2
       ORDER BY ch.recorded_at ASC`,
      [deviceId, days]
    );

    // Group by baseline
    const byBaseline = {};
    for (const row of rows) {
      const key = row.baseline_id || 'overall';
      if (!byBaseline[key]) {
        byBaseline[key] = {
          baselineId: row.baseline_id,
          baselineName: row.baseline_name,
          framework: row.framework,
          dataPoints: [],
        };
      }
      byBaseline[key].dataPoints.push({
        score: parseFloat(row.score),
        delta: parseFloat(row.delta),
        recordedAt: row.recorded_at,
      });
    }

    // Calculate trend direction for each baseline
    const trends = Object.values(byBaseline).map(b => {
      const points = b.dataPoints;
      let direction = 'stable';
      if (points.length >= 2) {
        const first = points[0].score;
        const last = points[points.length - 1].score;
        if (last > first + 2) direction = 'improving';
        else if (last < first - 2) direction = 'declining';
      }
      return { ...b, direction };
    });

    return {
      deviceId,
      days,
      trends,
    };
  }
}

module.exports = ScoreCalculator;
