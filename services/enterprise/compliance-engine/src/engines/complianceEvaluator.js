'use strict';

/**
 * ComplianceEvaluator – Central evaluation engine that compares device inventory
 * data against assigned baselines and produces a ComplianceResult.
 */
class ComplianceEvaluator {
  constructor({ pgPool, redis, logger, baselineManager, waiverManager, scoreCalculator, trendAnalyzer }) {
    this.pgPool = pgPool;
    this.redis = redis;
    this.logger = logger;
    this.baselineManager = baselineManager;
    this.waiverManager = waiverManager;
    this.scoreCalculator = scoreCalculator;
    this.trendAnalyzer = trendAnalyzer;
    this.scanners = {};
  }

  /**
   * Register a platform-specific scanner.
   */
  registerScanner(platform, scanner) {
    this.scanners[platform] = scanner;
  }

  /**
   * Evaluate a device against all applicable baselines.
   * @param {string} deviceId
   * @param {object|null} inventoryData - live inventory snapshot; null = use cached
   * @returns {object} ComplianceResult
   */
  async evaluateDevice(deviceId, inventoryData) {
    const timer = Date.now();
    this.logger.info('Evaluating device compliance', { deviceId });

    // Determine platform from inventory data
    const platform = this._detectPlatform(inventoryData);
    if (!platform) {
      this.logger.warn('Cannot determine platform for device', { deviceId });
      return null;
    }

    // Get applicable baselines
    const baselines = this.baselineManager.getBaselinesForDevice(deviceId, platform);
    if (baselines.length === 0) {
      this.logger.info('No applicable baselines for device', { deviceId, platform });
      return null;
    }

    // Retrieve previous results for change detection
    const previousResults = await this._getPreviousResults(deviceId);

    // Evaluate each baseline
    const allCheckResults = [];
    let totalPassed = 0;
    let totalFailed = 0;
    let totalSkipped = 0;
    let criticalFailures = 0;
    let highFailures = 0;
    let mediumFailures = 0;
    let lowFailures = 0;

    for (const baseline of baselines) {
      const scanner = this.scanners[platform];
      const checks = scanner ? scanner.getChecksForBaseline(baseline.id) : baseline.checks;

      for (const check of checks) {
        const result = await this._evaluateCheck(check, inventoryData, deviceId);
        allCheckResults.push({
          checkId: check.id,
          baselineId: baseline.id,
          title: check.title,
          category: check.category,
          severity: check.severity,
          status: result.status,
          actual: result.actual,
          expected: result.expected,
          message: result.message,
          remediation: check.remediation || null,
        });

        if (result.status === 'pass') {
          totalPassed++;
        } else if (result.status === 'fail') {
          totalFailed++;
          switch (check.severity) {
            case 'critical': criticalFailures++; break;
            case 'high': highFailures++; break;
            case 'medium': mediumFailures++; break;
            case 'low': lowFailures++; break;
          }
        } else {
          totalSkipped++;
        }
      }
    }

    const totalChecks = totalPassed + totalFailed + totalSkipped;
    const score = this.scoreCalculator.calculateDeviceScore(allCheckResults);

    // Detect changes from previous evaluation
    const { newViolations, resolvedViolations } = this._detectChanges(allCheckResults, previousResults);

    // Build result object
    const complianceResult = {
      deviceId,
      platform,
      baselineIds: baselines.map((b) => b.id),
      baselineId: baselines[0]?.id,
      score,
      totalChecks,
      passedChecks: totalPassed,
      failedChecks: totalFailed,
      skippedChecks: totalSkipped,
      criticalFailures,
      highFailures,
      mediumFailures,
      lowFailures,
      details: allCheckResults,
      newViolations,
      resolvedViolations,
      scannedAt: new Date().toISOString(),
      evaluationDurationMs: Date.now() - timer,
    };

    // Persist results
    await this._persistResult(complianceResult);

    // Record history snapshot for trend analysis
    await this.trendAnalyzer.recordSnapshot(deviceId, score, baselines[0]?.id);

    // Cache in Redis
    await this._cacheResult(deviceId, complianceResult);

    this.logger.info('Device compliance evaluation complete', {
      deviceId,
      score,
      passed: totalPassed,
      failed: totalFailed,
      duration: complianceResult.evaluationDurationMs,
    });

    return complianceResult;
  }

  /**
   * Evaluate a single check against inventory data.
   */
  async _evaluateCheck(check, inventoryData, deviceId) {
    // Check if waived
    const waived = await this.waiverManager.isWaived(deviceId, check.id);
    if (waived) {
      return { status: 'waived', actual: null, expected: null, message: 'Check waived' };
    }

    if (!inventoryData) {
      return { status: 'skipped', actual: null, expected: null, message: 'No inventory data available' };
    }

    try {
      return this._performCheck(check, inventoryData);
    } catch (err) {
      this.logger.error('Check evaluation error', { checkId: check.id, error: err.message });
      return { status: 'error', actual: null, expected: null, message: err.message };
    }
  }

  /**
   * Perform the actual comparison for a check.
   */
  _performCheck(check, inventoryData) {
    const checkDef = check.check || check;
    const type = checkDef.type;

    // Extract actual value from inventory data based on check type
    let actual;
    switch (type) {
      case 'registry':
        actual = this._getNestedValue(inventoryData, ['registry', checkDef.path, checkDef.key]);
        break;
      case 'service_status':
        actual = this._getNestedValue(inventoryData, ['services', checkDef.name, 'status']);
        break;
      case 'firewall':
        actual = this._getNestedValue(inventoryData, ['firewall', checkDef.profile || 'enabled']);
        break;
      case 'encryption':
        actual = this._getNestedValue(inventoryData, ['encryption', checkDef.target || 'enabled']);
        break;
      case 'software_update':
        actual = this._getNestedValue(inventoryData, ['updates', 'compliant']);
        break;
      case 'antivirus':
        actual = this._getNestedValue(inventoryData, ['antivirus', checkDef.property || 'enabled']);
        break;
      case 'defaults':
        actual = this._getNestedValue(inventoryData, ['defaults', checkDef.domain, checkDef.key]);
        break;
      case 'command':
        actual = this._getNestedValue(inventoryData, ['commands', checkDef.command]);
        break;
      case 'sysctl':
        actual = this._getNestedValue(inventoryData, ['sysctl', checkDef.key]);
        break;
      case 'file_content':
        actual = this._getNestedValue(inventoryData, ['files', checkDef.path, checkDef.key || 'content']);
        break;
      case 'file_permissions':
        actual = this._getNestedValue(inventoryData, ['files', checkDef.path, 'permissions']);
        break;
      case 'package':
        actual = this._getNestedValue(inventoryData, ['packages', checkDef.name, 'installed']);
        break;
      case 'pam':
        actual = this._getNestedValue(inventoryData, ['pam', checkDef.module, checkDef.key]);
        break;
      case 'gatekeeper':
        actual = this._getNestedValue(inventoryData, ['security', 'gatekeeper']);
        break;
      case 'sip':
        actual = this._getNestedValue(inventoryData, ['security', 'sip']);
        break;
      case 'filevault':
        actual = this._getNestedValue(inventoryData, ['encryption', 'filevault']);
        break;
      case 'selinux':
        actual = this._getNestedValue(inventoryData, ['security', 'selinux']);
        break;
      case 'apparmor':
        actual = this._getNestedValue(inventoryData, ['security', 'apparmor']);
        break;
      case 'audit_policy':
        actual = this._getNestedValue(inventoryData, ['audit', checkDef.category, checkDef.subcategory]);
        break;
      case 'uac':
        actual = this._getNestedValue(inventoryData, ['uac', checkDef.key]);
        break;
      case 'screen_lock':
        actual = this._getNestedValue(inventoryData, ['screenlock', checkDef.key || 'timeout']);
        break;
      default:
        actual = this._getNestedValue(inventoryData, [type, ...(checkDef.path ? [checkDef.path] : [])]);
    }

    const expected = checkDef.value;
    const operator = checkDef.operator || '==';

    if (actual === undefined || actual === null) {
      return { status: 'fail', actual: null, expected, message: 'Value not found in inventory data' };
    }

    const passed = this._compare(actual, operator, expected);
    return {
      status: passed ? 'pass' : 'fail',
      actual,
      expected,
      message: passed ? 'Check passed' : `Expected ${operator} ${expected}, got ${actual}`,
    };
  }

  /**
   * Compare values using the specified operator.
   */
  _compare(actual, operator, expected) {
    switch (operator) {
      case '==':
      case '===':
        return actual === expected;
      case '!=':
      case '!==':
        return actual !== expected;
      case '>=':
        return Number(actual) >= Number(expected);
      case '<=':
        return Number(actual) <= Number(expected);
      case '>':
        return Number(actual) > Number(expected);
      case '<':
        return Number(actual) < Number(expected);
      case 'contains':
        return String(actual).includes(String(expected));
      case 'not_contains':
        return !String(actual).includes(String(expected));
      case 'matches':
        return new RegExp(expected).test(String(actual));
      case 'in':
        return Array.isArray(expected) && expected.includes(actual);
      case 'not_in':
        return Array.isArray(expected) && !expected.includes(actual);
      case 'exists':
        return actual !== null && actual !== undefined;
      case 'not_exists':
        return actual === null || actual === undefined;
      default:
        return actual === expected;
    }
  }

  /**
   * Detect changes between current and previous evaluation.
   */
  _detectChanges(currentResults, previousResults) {
    const prevFailedIds = new Set(
      (previousResults || []).filter((r) => r.status === 'fail').map((r) => r.checkId || r.check_id)
    );
    const currFailedIds = new Set(
      currentResults.filter((r) => r.status === 'fail').map((r) => r.checkId)
    );

    const newViolations = currentResults.filter(
      (r) => r.status === 'fail' && !prevFailedIds.has(r.checkId)
    );
    const resolvedViolations = (previousResults || []).filter(
      (r) => (r.status === 'fail') && !currFailedIds.has(r.checkId || r.check_id)
    );

    return { newViolations, resolvedViolations };
  }

  /**
   * Get previous compliance results for a device.
   */
  async _getPreviousResults(deviceId) {
    try {
      const { rows } = await this.pgPool.query(
        `SELECT details FROM compliance_results WHERE device_id = $1 ORDER BY scanned_at DESC LIMIT 1`,
        [deviceId]
      );
      if (rows.length === 0) return [];
      return Array.isArray(rows[0].details) ? rows[0].details : [];
    } catch {
      return [];
    }
  }

  /**
   * Persist compliance result to PostgreSQL.
   */
  async _persistResult(result) {
    try {
      await this.pgPool.query(
        `INSERT INTO compliance_results
         (device_id, baseline_id, score, total_checks, passed_checks, failed_checks,
          skipped_checks, critical_failures, high_failures, medium_failures, low_failures,
          details, scanned_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          result.deviceId,
          null, // baseline_id is a UUID FK; we store baseline info in details instead
          result.score,
          result.totalChecks,
          result.passedChecks,
          result.failedChecks,
          result.skippedChecks,
          result.criticalFailures,
          result.highFailures,
          result.mediumFailures,
          result.lowFailures,
          JSON.stringify(result.details),
          result.scannedAt,
        ]
      );
    } catch (err) {
      this.logger.error('Failed to persist compliance result', { error: err.message });
    }
  }

  /**
   * Cache the latest result in Redis.
   */
  async _cacheResult(deviceId, result) {
    try {
      await this.redis.setex(
        `device:${deviceId}:latest`,
        3600,
        JSON.stringify(result)
      );
    } catch {
      // Redis cache is best-effort
    }
  }

  /**
   * Safely access nested properties.
   */
  _getNestedValue(obj, keys) {
    let current = obj;
    for (const key of keys) {
      if (current === null || current === undefined) return undefined;
      current = current[key];
    }
    return current;
  }
}

module.exports = ComplianceEvaluator;
