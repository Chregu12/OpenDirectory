'use strict';

const logger = require('../utils/logger');

/**
 * ReportGenerator — generates on-demand and scheduled monitoring reports.
 * Reports are stored in-memory as serialised JSON; in production these would
 * be written to object storage (S3, Azure Blob, etc.).
 */
class ReportGenerator {
  constructor(timeSeriesDB) {
    this._tsdb = timeSeriesDB;
    this._reports = new Map();      // reportId → report
    this._scheduled = new Map();    // scheduleId → schedule
    this._nextId = 1;

    logger.info('ReportGenerator initialised');
  }

  // ---------------------------------------------------------------------------
  // On-demand generation
  // ---------------------------------------------------------------------------

  async generate(options = {}) {
    const {
      type = 'system-summary',
      timeRange = '24h',
      format = 'json',
      services,
    } = options;

    const reportId = `report-${Date.now()}-${this._nextId++}`;
    const rangeMs = this._rangeToMs(timeRange);
    const startTs = Date.now() - rangeMs;

    const metrics = this._tsdb.queryMultiple(
      this._tsdb.listMetrics().slice(0, 20),
      startTs,
    );

    const report = {
      id: reportId,
      type,
      timeRange,
      format,
      generatedAt: new Date().toISOString(),
      data: {
        summary: {
          metricsCollected: Object.values(metrics).reduce((a, v) => a + v.length, 0),
          services: services || ['all'],
        },
        metrics,
      },
      downloadUrl: `/api/reports/${reportId}/download`,
    };

    this._reports.set(reportId, report);
    logger.info('Report generated', { reportId, type });
    return report;
  }

  async getReport(reportId) {
    return this._reports.get(reportId) || null;
  }

  // ---------------------------------------------------------------------------
  // Scheduling
  // ---------------------------------------------------------------------------

  async schedule(scheduleData) {
    const id = `sched-${this._nextId++}`;
    const schedule = {
      id,
      name: scheduleData.name || 'Scheduled Report',
      type: scheduleData.type || 'system-summary',
      cron: scheduleData.cron || '0 8 * * *',  // Daily at 08:00
      recipients: scheduleData.recipients || [],
      enabled: scheduleData.enabled !== false,
      createdAt: Date.now(),
    };
    this._scheduled.set(id, schedule);
    return schedule;
  }

  async getScheduled() {
    return Array.from(this._scheduled.values());
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _rangeToMs(range) {
    const units = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
    const match = String(range).match(/^(\d+)([smhd])$/);
    if (!match) return 3600000;
    return parseInt(match[1], 10) * (units[match[2]] || 1000);
  }
}

module.exports = ReportGenerator;
