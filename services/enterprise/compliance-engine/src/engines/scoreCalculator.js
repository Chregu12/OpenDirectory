'use strict';

/**
 * ScoreCalculator – computes weighted compliance scores at device, OU and
 * domain levels using severity-based weighting.
 *
 * Severity weights: critical=4, high=3, medium=2, low=1
 */
class ScoreCalculator {
  constructor({ pgPool, redis, logger }) {
    this.pgPool = pgPool;
    this.redis = redis;
    this.logger = logger;

    this.SEVERITY_WEIGHTS = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
    };
  }

  // ---------------------------------------------------------------------------
  // Per-device score
  // ---------------------------------------------------------------------------

  /**
   * Calculate weighted compliance score for a set of check results.
   * Score = (sum of weights of passed checks / sum of weights of all non-skipped checks) * 100
   * @param {Array} results - check result objects with { status, severity }
   * @returns {number} score 0-100 rounded to 2 decimals
   */
  calculateDeviceScore(results) {
    if (!results || results.length === 0) return 0;

    let totalWeight = 0;
    let passedWeight = 0;

    for (const result of results) {
      if (result.status === 'skipped' || result.status === 'waived') continue;
      const weight = this.SEVERITY_WEIGHTS[result.severity] || 1;
      totalWeight += weight;
      if (result.status === 'pass') {
        passedWeight += weight;
      }
    }

    if (totalWeight === 0) return 100; // all checks were skipped/waived
    const score = (passedWeight / totalWeight) * 100;
    return Math.round(score * 100) / 100;
  }

  // ---------------------------------------------------------------------------
  // Aggregated scores
  // ---------------------------------------------------------------------------

  /**
   * Get per-device scores from latest compliance results.
   */
  async getDeviceScores() {
    try {
      const { rows } = await this.pgPool.query(`
        SELECT DISTINCT ON (device_id)
          device_id,
          score,
          total_checks,
          passed_checks,
          failed_checks,
          critical_failures,
          high_failures,
          scanned_at
        FROM compliance_results
        ORDER BY device_id, scanned_at DESC
      `);
      return rows;
    } catch (err) {
      this.logger.error('Failed to get device scores', { error: err.message });
      return [];
    }
  }

  /**
   * Calculate per-OU scores.
   * Requires a device_ou mapping table or field in inventory.
   * Falls back to grouping by device_id prefix patterns.
   */
  async calculateOUScores() {
    try {
      // Try to join with a device inventory for OU info
      const { rows } = await this.pgPool.query(`
        SELECT
          COALESCE(
            SPLIT_PART(device_id, '.', 2),
            'default'
          ) AS ou,
          ROUND(AVG(score)::numeric, 2) AS avg_score,
          COUNT(*) AS device_count,
          SUM(critical_failures) AS critical_failures,
          SUM(high_failures) AS high_failures,
          MIN(score) AS min_score,
          MAX(score) AS max_score
        FROM (
          SELECT DISTINCT ON (device_id) device_id, score, critical_failures, high_failures
          FROM compliance_results
          ORDER BY device_id, scanned_at DESC
        ) latest
        GROUP BY ou
        ORDER BY avg_score ASC
      `);
      return rows;
    } catch (err) {
      this.logger.error('Failed to calculate OU scores', { error: err.message });
      return [];
    }
  }

  /**
   * Calculate a single OU score by OU identifier.
   */
  async calculateOUScore(ouId) {
    const ouScores = await this.calculateOUScores();
    return ouScores.find((s) => s.ou === ouId) || null;
  }

  /**
   * Calculate domain-level aggregate score.
   */
  async calculateDomainScore() {
    try {
      const { rows } = await this.pgPool.query(`
        SELECT
          ROUND(AVG(score)::numeric, 2) AS avg_score,
          COUNT(*) AS total_devices,
          COUNT(*) FILTER (WHERE score = 100) AS fully_compliant,
          COUNT(*) FILTER (WHERE score >= 80 AND score < 100) AS mostly_compliant,
          COUNT(*) FILTER (WHERE score >= 50 AND score < 80) AS partially_compliant,
          COUNT(*) FILTER (WHERE score < 50) AS non_compliant,
          ROUND(MIN(score)::numeric, 2) AS min_score,
          ROUND(MAX(score)::numeric, 2) AS max_score,
          ROUND(STDDEV(score)::numeric, 2) AS score_stddev
        FROM (
          SELECT DISTINCT ON (device_id) device_id, score
          FROM compliance_results
          ORDER BY device_id, scanned_at DESC
        ) latest
      `);
      return rows[0] || {};
    } catch (err) {
      this.logger.error('Failed to calculate domain score', { error: err.message });
      return {};
    }
  }
}

module.exports = ScoreCalculator;
