'use strict';

const logger = require('../utils/logger');

/**
 * ComplianceScanner — evaluates devices against compliance rules stored in DB.
 *
 * scanDevice(deviceId) is the primary entry-point called by the API route handler.
 * It returns a structured result including compliant flag, score, and violations.
 *
 * Uses IDeviceRepository (via deviceRepository) for device reads/writes.
 * The legacy db wrapper is kept only for compliance_results (no repo for that table yet).
 */
class ComplianceScanner {
  /**
   * @param {object} options
   * @param {object} options.db              - legacy db wrapper (for compliance_results / compliance_rules)
   * @param {object} options.deviceRepository - IDeviceRepository implementation
   * @param {object} options.eventBus
   */
  constructor({ db, deviceRepository, eventBus } = {}) {
    this.db = db;
    this.deviceRepository = deviceRepository || null;
    this.eventBus = eventBus;
  }

  /**
   * Scan a single device and persist the result.
   * @param {string} deviceId
   * @returns {{ deviceId, compliant, score, violations, scannedAt }}
   */
  async scanDevice(deviceId) {
    logger.info('Compliance scan started', { deviceId });

    // Load device via repository (falls back to legacy db if no repo)
    let device;
    if (this.deviceRepository) {
      device = await this.deviceRepository.findById(deviceId);
    } else {
      device = await this.db.findById('devices', deviceId);
    }

    if (!device) {
      const err = new Error(`Device not found: ${deviceId}`);
      err.statusCode = 404;
      throw err;
    }

    // Load applicable compliance rules for this device's platform
    const rules = await this._getRulesForDevice(device);
    const violations = [];
    let passedChecks = 0;

    for (const rule of rules) {
      const result = this._evaluateRule(rule, device);
      if (!result.passed) {
        violations.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity || 'medium',
          description: result.description,
          autoRemediable: rule.autoRemediable || false
        });
      } else {
        passedChecks++;
      }
    }

    const total = rules.length;
    const score = total > 0 ? Math.round((passedChecks / total) * 100) : 100;
    const compliant = violations.filter(v => v.severity === 'critical' || v.severity === 'high').length === 0;
    const scannedAt = new Date().toISOString();

    const scanResult = { deviceId, compliant, score, violations, scannedAt, totalChecks: total, passedChecks };

    // Persist compliance state via aggregate / repository
    if (this.deviceRepository) {
      if (compliant) {
        device.markCompliant();
      } else {
        device.markNonCompliant(violations);
      }
      await this.deviceRepository.save(device);

      // Dispatch domain events if eventBus supports it
      const domainEvents = device.getAndClearDomainEvents();
      for (const event of domainEvents) {
        this.eventBus.emit(event.type, event.payload);
      }
    } else {
      // Legacy fallback: update via db wrapper
      await this.db.update('devices', deviceId, {
        complianceStatus: compliant ? 'compliant' : 'non-compliant',
        lastComplianceScan: scannedAt,
        complianceScore: score
      });
    }

    // Store full scan result (no repo for compliance_results yet)
    await this.db.insert('compliance_results', { ...scanResult, id: `cres-${deviceId}-${Date.now()}` });

    // Emit violation events
    for (const violation of violations) {
      this.eventBus.emit('device:compliance_violation', { deviceId, violation });
    }

    logger.info('Compliance scan complete', { deviceId, compliant, score, violationCount: violations.length });
    return scanResult;
  }

  async _getRulesForDevice(device) {
    const rules = await this.db.find('compliance_rules', {});
    // Return rules that apply to this platform or all platforms
    const platform = device.platform !== undefined ? device.platform : (device._platform);
    return rules.filter(r => !r.platform || r.platform === platform || r.platform === 'all');
  }

  _evaluateRule(rule, device) {
    // Default: pass if no custom evaluator
    if (!rule.field) return { passed: true };

    // Support both plain objects and DeviceAggregate instances
    const value = device[rule.field] !== undefined ? device[rule.field] : (device.toJSON ? device.toJSON()[rule.field] : undefined);
    switch (rule.operator) {
      case 'exists': return { passed: value !== undefined && value !== null, description: `Field ${rule.field} must exist` };
      case 'eq':     return { passed: value === rule.expected, description: `${rule.field} must be ${rule.expected}, got ${value}` };
      case 'neq':    return { passed: value !== rule.expected, description: `${rule.field} must not be ${rule.expected}` };
      case 'gt':     return { passed: Number(value) > Number(rule.expected), description: `${rule.field} must be > ${rule.expected}` };
      case 'lt':     return { passed: Number(value) < Number(rule.expected), description: `${rule.field} must be < ${rule.expected}` };
      default:       return { passed: true };
    }
  }

  async updateComplianceStatus(deviceId, complianceData) {
    if (this.deviceRepository) {
      const device = await this.deviceRepository.findById(deviceId);
      if (device) {
        if (complianceData.compliant) {
          device.markCompliant();
        } else {
          device.markNonCompliant(complianceData.violations || []);
        }
        await this.deviceRepository.save(device);
      }
      return;
    }
    await this.db.update('devices', deviceId, {
      complianceStatus: complianceData.compliant ? 'compliant' : 'non-compliant',
      lastComplianceScan: new Date().toISOString()
    });
  }

  async autoRemediate(violationId) {
    logger.info('Auto-remediating compliance violation', { violationId });
    // Stub: mark violation as remediated
    await this.db.update('compliance_violations', violationId, {
      status: 'remediated',
      remediatedAt: new Date().toISOString()
    });
  }

  async getViolationCount() {
    if (this.deviceRepository) {
      // Count via repo: get all non-compliant devices
      const devices = await this.deviceRepository.findAll({ status: 'active' });
      return devices.filter(d => !d.isCompliant).length;
    }
    const devices = await this.db.find('devices', { complianceStatus: 'non-compliant' });
    return devices.length;
  }

  async getViolations({ page = 1, limit = 50, severity, deviceId } = {}) {
    let results = await this.db.find('compliance_results', {});
    let violations = results.flatMap(r => (r.violations || []).map(v => ({ ...v, deviceId: r.deviceId, scannedAt: r.scannedAt })));
    if (severity) violations = violations.filter(v => v.severity === severity);
    if (deviceId) violations = violations.filter(v => v.deviceId === deviceId);
    const total = violations.length;
    const start = (page - 1) * limit;
    return { violations: violations.slice(start, start + limit), pagination: { page, limit, total } };
  }

  async getReports({ page = 1, limit = 20 } = {}) {
    const results = await this.db.find('compliance_results', {});
    results.sort((a, b) => (b.scannedAt > a.scannedAt ? 1 : -1));
    const total = results.length;
    const start = (page - 1) * limit;
    return { reports: results.slice(start, start + limit), pagination: { page, limit, total } };
  }

  async performScheduledScan() {
    let devices;
    if (this.deviceRepository) {
      const aggregates = await this.deviceRepository.findAll({ status: 'active' });
      devices = aggregates.map(a => a.toJSON());
    } else {
      devices = await this.db.find('devices', { status: 'active' });
    }
    logger.info(`Scheduled compliance scan: ${devices.length} devices`);
    for (const device of devices) {
      try {
        await this.scanDevice(device.id);
      } catch (err) {
        logger.warn(`Scheduled scan failed for ${device.id}: ${err.message}`);
      }
    }
  }
}

module.exports = ComplianceScanner;
