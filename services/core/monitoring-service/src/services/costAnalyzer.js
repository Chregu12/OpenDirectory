'use strict';

const logger = require('../utils/logger');
const config = require('../config');

/**
 * CostAnalyzer — tracks and reports on infrastructure / service costs.
 * Returns mock data in this stub implementation; wire in real billing APIs
 * (AWS Cost Explorer, Azure Cost Management, etc.) when ready.
 */
class CostAnalyzer {
  constructor(timeSeriesDB) {
    this._tsdb = timeSeriesDB;
    this._currency = config.costAnalysis.currency;
    this._reports = [];   // Historical cost reports

    logger.info('CostAnalyzer initialised', { currency: this._currency });
  }

  // ---------------------------------------------------------------------------
  // Background job (called by setInterval in index.js)
  // ---------------------------------------------------------------------------

  async generateCostReports() {
    const report = this._buildReport();
    this._reports.push(report);
    if (this._reports.length > 1000) this._reports.shift();

    // Store aggregate in TSDB
    this._tsdb.insert('cost.total_daily', report.totalCost, {}, Date.now());
    logger.debug('Cost report generated', { total: report.totalCost });
    return report;
  }

  // ---------------------------------------------------------------------------
  // API methods
  // ---------------------------------------------------------------------------

  async getCostAnalysis() {
    return this._buildReport();
  }

  async getCostOptimization() {
    return {
      potentialSavings: 847.50,
      recommendations: [
        { type: 'right-sizing', service: 'node-3', description: 'Downsize node-3 compute from 16 CPU to 8 CPU (60% idle)', monthlySaving: 320 },
        { type: 'reserved-instance', service: 'database', description: 'Convert on-demand DB to 1-year reserved', monthlySaving: 280 },
        { type: 'storage-cleanup', service: 'storage', description: 'Remove 1.2 TB of unreferenced snapshots', monthlySaving: 247.50 },
      ],
    };
  }

  async getCostTrends(period = '30d') {
    const days = period.endsWith('d') ? parseInt(period) : 30;
    const now = Date.now();
    return Array.from({ length: days }, (_, i) => ({
      date: new Date(now - (days - i) * 86400000).toISOString().slice(0, 10),
      cost: Math.round((1200 + Math.random() * 200) * 100) / 100,
      currency: this._currency,
    }));
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  _buildReport() {
    const services = [
      { name: 'Compute',  cost: 1240.80, change: +2.3 },
      { name: 'Storage',  cost: 380.50,  change: +1.1 },
      { name: 'Network',  cost: 210.20,  change: -0.5 },
      { name: 'Database', cost: 560.00,  change: 0    },
      { name: 'Backup',   cost: 95.30,   change: +4.2 },
    ];
    const totalCost = services.reduce((a, s) => a + s.cost, 0);
    return {
      generatedAt: new Date().toISOString(),
      period: 'current_month',
      currency: this._currency,
      totalCost: Math.round(totalCost * 100) / 100,
      byService: services,
      budget: 3000,
      budgetUsed: Math.round((totalCost / 3000) * 100),
    };
  }
}

module.exports = CostAnalyzer;
