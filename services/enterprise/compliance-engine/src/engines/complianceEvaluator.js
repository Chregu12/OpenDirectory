'use strict';

const logger = require('../utils/logger');
const ScoreCalculator = require('./scoreCalculator');

class ComplianceEvaluator {
  constructor(db, redis, eventBus) {
    this.db = db;
    this.redis = redis;
    this.eventBus = eventBus;
    this.scoreCalculator = new ScoreCalculator(db);
  }

  /**
   * Evaluate a device against all applicable compliance baselines.
   * @param {string} deviceId - The device identifier
   * @param {object} inventoryData - Device inventory/telemetry data
   * @returns {object} Evaluation summary with per-baseline results
   */
  async evaluateDevice(deviceId, inventoryData) {
    const startTime = Date.now();
    logger.info(`Starting compliance evaluation for device ${deviceId}`);

    try {
      // 1. Determine device platform
      const platform = this._detectPlatform(inventoryData);

      // 2. Get all active baselines for device's platform
      const baselines = await this._getActiveBaselines(platform);
      if (baselines.length === 0) {
        logger.warn(`No active baselines found for platform "${platform}"`);
        return { deviceId, platform, baselines: [], overallScore: null };
      }

      // 3. Get applicable waivers for device
      const waivers = await this._getActiveWaivers(deviceId);
      const waiverMap = this._buildWaiverMap(waivers);

      const results = [];

      // 4. For each baseline: compare inventory data against checks
      for (const baseline of baselines) {
        const checkResults = [];
        const checks = baseline.checks || [];

        for (const check of checks) {
          const result = await this.evaluateCheck(check, inventoryData);
          // Apply waiver if one exists
          const waiverKey = `${baseline.id}:${check.id}`;
          if (waiverMap.has(waiverKey) || waiverMap.has(`*:${check.id}`)) {
            result.waived = true;
            result.waiverReason = (waiverMap.get(waiverKey) || waiverMap.get(`*:${check.id}`)).reason;
          }
          checkResults.push(result);
        }

        // 5. Calculate score per baseline
        const score = this.scoreCalculator.calculate(checks, checkResults, waivers);

        // 6. Store results in DB
        const resultRecord = await this._storeResult(deviceId, baseline, score, checkResults);

        // 7. Record history entry
        await this._recordHistory(deviceId, baseline.id, score.score);

        results.push({
          baselineId: baseline.id,
          baselineName: baseline.name,
          framework: baseline.framework,
          score: score.score,
          breakdown: score.breakdown,
          totalChecks: checks.length,
          passedChecks: score.passedCount,
          failedChecks: score.failedCount,
          skippedChecks: score.skippedCount,
          criticalFailures: score.breakdown.critical.failed,
          highFailures: score.breakdown.high.failed,
          mediumFailures: score.breakdown.medium.failed,
          lowFailures: score.breakdown.low.failed,
          details: checkResults,
        });

        // 8. Emit compliance event
        const previousScore = await this._getPreviousScore(deviceId, baseline.id);
        const event = this._buildComplianceEvent(deviceId, baseline, score, previousScore);
        await this._emitEvent(event);

        // If score drops significantly, trigger alert
        if (previousScore !== null && score.score < previousScore - 10) {
          await this._emitEvent({
            type: 'compliance.alert.regression',
            deviceId,
            baselineId: baseline.id,
            previousScore,
            currentScore: score.score,
            delta: score.score - previousScore,
            timestamp: new Date().toISOString(),
          });
          logger.warn(`Compliance regression detected for device ${deviceId}: ${previousScore} -> ${score.score}`);
        }
      }

      // Compute overall score across baselines
      const overallScore = results.length > 0
        ? parseFloat((results.reduce((sum, r) => sum + r.score, 0) / results.length).toFixed(2))
        : 0;

      // Cache the latest score
      if (this.redis) {
        await this.redis.setex(
          `compliance:score:${deviceId}`,
          3600,
          JSON.stringify({ score: overallScore, evaluatedAt: new Date().toISOString() })
        );
      }

      const duration = Date.now() - startTime;
      logger.info(`Compliance evaluation for device ${deviceId} completed in ${duration}ms. Overall score: ${overallScore}`);

      return {
        deviceId,
        platform,
        overallScore,
        baselines: results,
        evaluatedAt: new Date().toISOString(),
        durationMs: duration,
      };
    } catch (error) {
      logger.error(`Compliance evaluation failed for device ${deviceId}: ${error.message}`, { error });
      throw error;
    }
  }

  /**
   * Evaluate a single compliance check against device data.
   * @param {object} check - Check definition from baseline
   * @param {object} deviceData - Device inventory data
   * @returns {object} Check result
   */
  async evaluateCheck(check, deviceData) {
    const result = {
      checkId: check.id,
      title: check.title,
      category: check.category,
      severity: check.severity || 'medium',
      passed: false,
      waived: false,
      skipped: false,
      actual: null,
      expected: null,
      message: '',
    };

    try {
      const checkDef = check.check;
      if (!checkDef) {
        result.skipped = true;
        result.message = 'No check definition provided';
        return result;
      }

      switch (checkDef.type) {
        case 'registry':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['registry', checkDef.path, checkDef.key]);
          if (result.actual === undefined || result.actual === null) {
            result.actual = this._getNestedValue(deviceData, ['registrySettings', checkDef.key]);
          }
          result.passed = this._compareValues(result.actual, result.expected, checkDef.operator || '==');
          break;

        case 'policy':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['policies', checkDef.setting]);
          if (result.actual === undefined) {
            result.actual = this._getNestedValue(deviceData, ['securityPolicy', checkDef.setting]);
          }
          result.passed = this._compareValues(result.actual, result.expected, checkDef.operator || '==');
          break;

        case 'firewall':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['firewall', checkDef.profile, checkDef.setting]);
          result.passed = result.actual === checkDef.expected;
          break;

        case 'bitlocker':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['encryption', checkDef.drive || 'C:', 'status']);
          if (result.actual === undefined) {
            result.actual = this._getNestedValue(deviceData, ['bitlocker', checkDef.drive || 'C:']);
          }
          result.passed = result.actual === checkDef.expected;
          break;

        case 'defender':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['antivirus', checkDef.setting]);
          if (result.actual === undefined) {
            result.actual = this._getNestedValue(deviceData, ['defender', checkDef.setting]);
          }
          result.passed = result.actual === checkDef.expected;
          break;

        case 'system':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['system', checkDef.setting]);
          result.passed = result.actual === checkDef.expected;
          break;

        case 'service':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['services', checkDef.name, checkDef.property || 'status']);
          result.passed = result.actual === checkDef.expected;
          break;

        case 'file':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['files', checkDef.path, checkDef.property || 'exists']);
          if (checkDef.operator) {
            result.passed = this._compareValues(result.actual, result.expected, checkDef.operator);
          } else {
            result.passed = result.actual === checkDef.expected;
          }
          break;

        case 'command':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['commandResults', checkDef.command]);
          result.passed = result.actual === checkDef.expected;
          break;

        case 'plist':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['plist', checkDef.domain, checkDef.key]);
          if (checkDef.operator) {
            result.passed = this._compareValues(result.actual, result.expected, checkDef.operator);
          } else {
            result.passed = result.actual === result.expected;
          }
          break;

        case 'sysctl':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['sysctl', checkDef.key]);
          if (checkDef.operator) {
            result.passed = this._compareValues(result.actual, result.expected, checkDef.operator);
          } else {
            result.passed = result.actual === result.expected;
          }
          break;

        case 'config_file':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['configFiles', checkDef.path, checkDef.key]);
          if (checkDef.operator) {
            result.passed = this._compareValues(result.actual, result.expected, checkDef.operator);
          } else {
            result.passed = result.actual === result.expected;
          }
          break;

        case 'package':
          result.expected = checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['packages', checkDef.name, 'installed']);
          result.passed = result.actual === checkDef.expected;
          break;

        case 'permission':
          result.expected = checkDef.value !== undefined ? checkDef.value : checkDef.expected;
          result.actual = this._getNestedValue(deviceData, ['permissions', checkDef.path, 'mode']);
          if (checkDef.operator) {
            result.passed = this._compareValues(result.actual, result.expected, checkDef.operator);
          } else {
            result.passed = result.actual === result.expected;
          }
          break;

        default:
          result.skipped = true;
          result.message = `Unknown check type: ${checkDef.type}`;
          logger.warn(`Unknown check type "${checkDef.type}" in check ${check.id}`);
      }

      if (!result.skipped && result.actual === null || result.actual === undefined) {
        result.message = 'Data not available from device inventory';
      }
    } catch (error) {
      result.skipped = true;
      result.message = `Evaluation error: ${error.message}`;
      logger.error(`Error evaluating check ${check.id}: ${error.message}`);
    }

    return result;
  }

  /**
   * Get aggregated compliance score for a device across all baselines.
   */
  async getDeviceScore(deviceId) {
    // Check cache first
    if (this.redis) {
      const cached = await this.redis.get(`compliance:score:${deviceId}`);
      if (cached) {
        return JSON.parse(cached);
      }
    }

    const { rows } = await this.db.query(
      `SELECT cr.baseline_id, cb.name AS baseline_name, cb.framework,
              cr.score, cr.total_checks, cr.passed_checks, cr.failed_checks,
              cr.critical_failures, cr.high_failures, cr.medium_failures, cr.low_failures,
              cr.scanned_at
       FROM compliance_results cr
       JOIN compliance_baselines cb ON cr.baseline_id = cb.id
       WHERE cr.device_id = $1
         AND cr.scanned_at = (
           SELECT MAX(scanned_at) FROM compliance_results
           WHERE device_id = $1 AND baseline_id = cr.baseline_id
         )
       ORDER BY cb.framework, cb.name`,
      [deviceId]
    );

    if (rows.length === 0) {
      return { deviceId, overallScore: null, baselines: [] };
    }

    const overallScore = parseFloat(
      (rows.reduce((sum, r) => sum + parseFloat(r.score), 0) / rows.length).toFixed(2)
    );

    return {
      deviceId,
      overallScore,
      baselines: rows.map(r => ({
        baselineId: r.baseline_id,
        baselineName: r.baseline_name,
        framework: r.framework,
        score: parseFloat(r.score),
        totalChecks: r.total_checks,
        passedChecks: r.passed_checks,
        failedChecks: r.failed_checks,
        criticalFailures: r.critical_failures,
        highFailures: r.high_failures,
        mediumFailures: r.medium_failures,
        lowFailures: r.low_failures,
        scannedAt: r.scanned_at,
      })),
    };
  }

  /**
   * Get fleet-wide compliance score with optional filters.
   */
  async getFleetScore(filters = {}) {
    let query = `
      SELECT
        COUNT(DISTINCT cr.device_id) AS device_count,
        AVG(cr.score) AS avg_score,
        MIN(cr.score) AS min_score,
        MAX(cr.score) AS max_score,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY cr.score) AS median_score,
        SUM(cr.critical_failures) AS total_critical,
        SUM(cr.high_failures) AS total_high,
        SUM(cr.failed_checks) AS total_failures
      FROM compliance_results cr
      JOIN compliance_baselines cb ON cr.baseline_id = cb.id
      WHERE cr.scanned_at = (
        SELECT MAX(scanned_at) FROM compliance_results
        WHERE device_id = cr.device_id AND baseline_id = cr.baseline_id
      )
    `;

    const params = [];

    if (filters.framework) {
      params.push(filters.framework);
      query += ` AND cb.framework = $${params.length}`;
    }

    if (filters.platform) {
      params.push(filters.platform);
      query += ` AND cb.platform = $${params.length}`;
    }

    if (filters.baselineId) {
      params.push(filters.baselineId);
      query += ` AND cr.baseline_id = $${params.length}`;
    }

    const { rows } = await this.db.query(query, params);
    const row = rows[0];

    // Score distribution
    const distQuery = `
      SELECT
        CASE
          WHEN cr.score >= 90 THEN 'compliant'
          WHEN cr.score >= 70 THEN 'partially_compliant'
          WHEN cr.score >= 50 THEN 'at_risk'
          ELSE 'non_compliant'
        END AS status,
        COUNT(DISTINCT cr.device_id) AS count
      FROM compliance_results cr
      JOIN compliance_baselines cb ON cr.baseline_id = cb.id
      WHERE cr.scanned_at = (
        SELECT MAX(scanned_at) FROM compliance_results
        WHERE device_id = cr.device_id AND baseline_id = cr.baseline_id
      )
      GROUP BY status
    `;

    const { rows: distRows } = await this.db.query(distQuery);

    const distribution = {
      compliant: 0,
      partially_compliant: 0,
      at_risk: 0,
      non_compliant: 0,
    };
    for (const d of distRows) {
      distribution[d.status] = parseInt(d.count, 10);
    }

    return {
      deviceCount: parseInt(row.device_count, 10) || 0,
      averageScore: row.avg_score ? parseFloat(parseFloat(row.avg_score).toFixed(2)) : 0,
      minScore: row.min_score ? parseFloat(parseFloat(row.min_score).toFixed(2)) : 0,
      maxScore: row.max_score ? parseFloat(parseFloat(row.max_score).toFixed(2)) : 0,
      medianScore: row.median_score ? parseFloat(parseFloat(row.median_score).toFixed(2)) : 0,
      totalCriticalFailures: parseInt(row.total_critical, 10) || 0,
      totalHighFailures: parseInt(row.total_high, 10) || 0,
      totalFailures: parseInt(row.total_failures, 10) || 0,
      distribution,
      filters,
    };
  }

  // ─── Private helpers ──────────────────────────────────────────────

  _detectPlatform(inventoryData) {
    if (inventoryData.platform) return inventoryData.platform.toLowerCase();
    if (inventoryData.os) {
      const os = inventoryData.os.toLowerCase();
      if (os.includes('windows')) return 'windows';
      if (os.includes('macos') || os.includes('darwin')) return 'macos';
      if (os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('rhel')) return 'linux';
    }
    return 'unknown';
  }

  async _getActiveBaselines(platform) {
    const { rows } = await this.db.query(
      `SELECT * FROM compliance_baselines
       WHERE enabled = true AND (platform = $1 OR platform = 'all')
       ORDER BY framework, name`,
      [platform]
    );
    return rows;
  }

  async _getActiveWaivers(deviceId) {
    const { rows } = await this.db.query(
      `SELECT * FROM compliance_waivers
       WHERE (device_id = $1 OR device_id IS NULL)
         AND status = 'active'
         AND expires_at > NOW()`,
      [deviceId]
    );
    return rows;
  }

  _buildWaiverMap(waivers) {
    const map = new Map();
    for (const w of waivers) {
      const key = `${w.baseline_id || '*'}:${w.check_id}`;
      map.set(key, { reason: w.reason, approvedBy: w.approved_by, expiresAt: w.expires_at });
    }
    return map;
  }

  _compareValues(actual, expected, operator) {
    if (actual === null || actual === undefined) return false;

    const numActual = typeof actual === 'string' ? parseFloat(actual) : actual;
    const numExpected = typeof expected === 'string' ? parseFloat(expected) : expected;

    switch (operator) {
      case '==':
      case '===':
        return actual === expected || numActual === numExpected;
      case '!=':
      case '!==':
        return actual !== expected;
      case '>=':
        return numActual >= numExpected;
      case '<=':
        return numActual <= numExpected;
      case '>':
        return numActual > numExpected;
      case '<':
        return numActual < numExpected;
      case 'contains':
        return String(actual).includes(String(expected));
      case 'not_contains':
        return !String(actual).includes(String(expected));
      case 'regex':
        return new RegExp(expected).test(String(actual));
      default:
        return actual === expected;
    }
  }

  _getNestedValue(obj, keys) {
    let current = obj;
    for (const key of keys) {
      if (current === null || current === undefined) return undefined;
      current = current[key];
    }
    return current;
  }

  async _storeResult(deviceId, baseline, score, checkResults) {
    const { rows } = await this.db.query(
      `INSERT INTO compliance_results
        (device_id, baseline_id, score, total_checks, passed_checks, failed_checks,
         skipped_checks, critical_failures, high_failures, medium_failures, low_failures,
         details, scanned_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
       RETURNING id`,
      [
        deviceId,
        baseline.id,
        score.score,
        score.totalCount,
        score.passedCount,
        score.failedCount,
        score.skippedCount,
        score.breakdown.critical.failed,
        score.breakdown.high.failed,
        score.breakdown.medium.failed,
        score.breakdown.low.failed,
        JSON.stringify(checkResults),
      ]
    );
    return rows[0];
  }

  async _recordHistory(deviceId, baselineId, currentScore) {
    // Get previous score for delta calculation
    const { rows } = await this.db.query(
      `SELECT score FROM compliance_history
       WHERE device_id = $1 AND baseline_id = $2
       ORDER BY recorded_at DESC LIMIT 1`,
      [deviceId, baselineId]
    );
    const previousScore = rows.length > 0 ? parseFloat(rows[0].score) : currentScore;
    const delta = parseFloat((currentScore - previousScore).toFixed(2));

    await this.db.query(
      `INSERT INTO compliance_history (device_id, baseline_id, score, delta)
       VALUES ($1, $2, $3, $4)`,
      [deviceId, baselineId, currentScore, delta]
    );
  }

  async _getPreviousScore(deviceId, baselineId) {
    const { rows } = await this.db.query(
      `SELECT score FROM compliance_history
       WHERE device_id = $1 AND baseline_id = $2
       ORDER BY recorded_at DESC LIMIT 1 OFFSET 1`,
      [deviceId, baselineId]
    );
    return rows.length > 0 ? parseFloat(rows[0].score) : null;
  }

  _buildComplianceEvent(deviceId, baseline, score, previousScore) {
    let type;
    if (score.score >= 90) {
      type = 'compliance.passed';
    } else if (previousScore !== null && score.score !== previousScore) {
      type = 'compliance.changed';
    } else {
      type = 'compliance.failed';
    }

    return {
      type,
      deviceId,
      baselineId: baseline.id,
      baselineName: baseline.name,
      framework: baseline.framework,
      score: score.score,
      previousScore,
      passedChecks: score.passedCount,
      failedChecks: score.failedCount,
      criticalFailures: score.breakdown.critical.failed,
      timestamp: new Date().toISOString(),
    };
  }

  async _emitEvent(event) {
    try {
      if (this.eventBus) {
        await this.eventBus.publish('compliance.events', Buffer.from(JSON.stringify(event)));
      }
      logger.debug(`Emitted compliance event: ${event.type}`, { event });
    } catch (error) {
      logger.error(`Failed to emit compliance event: ${error.message}`);
    }
  }
}

module.exports = ComplianceEvaluator;
