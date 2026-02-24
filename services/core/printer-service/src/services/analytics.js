const { Pool } = require('pg');
const winston = require('winston');

class PrintAnalytics {
  constructor() {
    this.logger = winston.createLogger({
      level: 'info',
      format: winston.format.simple(),
      transports: [new winston.transports.Console()]
    });
    
    this.db = new Pool({
      connectionString: process.env.DATABASE_URL || 'postgres://opendirectory:changeme@localhost/printers'
    });
  }

  async getUsageStats(startDate, endDate, groupBy = 'day') {
    const groupByClause = this.getGroupByClause(groupBy);
    
    const result = await this.db.query(`
      SELECT 
        ${groupByClause} as period,
        COUNT(DISTINCT user_id) as unique_users,
        COUNT(*) as total_jobs,
        SUM(page_count * copies) as total_pages,
        SUM(CASE WHEN color = true THEN page_count * copies ELSE 0 END) as color_pages,
        SUM(CASE WHEN color = false THEN page_count * copies ELSE 0 END) as bw_pages,
        SUM(CASE WHEN duplex = true THEN 1 ELSE 0 END) as duplex_jobs,
        AVG(page_count) as avg_pages_per_job,
        SUM(cost) as total_cost
      FROM print_jobs
      WHERE submitted_at >= $1 AND submitted_at <= $2
        AND status IN ('completed', 'printed')
      GROUP BY ${groupByClause}
      ORDER BY period
    `, [startDate, endDate]);
    
    return result.rows.map(row => ({
      ...row,
      color_percentage: row.total_pages > 0 ? 
        Math.round((row.color_pages / row.total_pages) * 100) : 0,
      duplex_percentage: row.total_jobs > 0 ?
        Math.round((row.duplex_jobs / row.total_jobs) * 100) : 0
    }));
  }

  async getCosts(startDate, endDate, department = null) {
    let query = `
      SELECT 
        DATE(pj.submitted_at) as date,
        p.name as printer_name,
        COUNT(*) as job_count,
        SUM(pj.page_count * pj.copies) as total_pages,
        SUM(pj.cost) as total_cost,
        AVG(pj.cost) as avg_cost_per_job
      FROM print_jobs pj
      JOIN printers p ON pj.printer_id = p.id
      WHERE pj.submitted_at >= $1 AND pj.submitted_at <= $2
        AND pj.status IN ('completed', 'printed')
    `;
    
    const params = [startDate, endDate];
    
    if (department) {
      query += ` AND pj.user_id IN (
        SELECT user_id FROM user_departments WHERE department_id = $3
      )`;
      params.push(department);
    }
    
    query += ` GROUP BY DATE(pj.submitted_at), p.name
               ORDER BY date, total_cost DESC`;
    
    const result = await this.db.query(query, params);
    
    // Calculate totals
    const totals = result.rows.reduce((acc, row) => ({
      total_jobs: acc.total_jobs + parseInt(row.job_count),
      total_pages: acc.total_pages + parseInt(row.total_pages),
      total_cost: acc.total_cost + parseFloat(row.total_cost || 0)
    }), { total_jobs: 0, total_pages: 0, total_cost: 0 });
    
    return {
      daily: result.rows,
      summary: {
        ...totals,
        avg_cost_per_page: totals.total_pages > 0 ? 
          totals.total_cost / totals.total_pages : 0,
        avg_pages_per_job: totals.total_jobs > 0 ?
          totals.total_pages / totals.total_jobs : 0
      }
    };
  }

  async getPrinterUsage(printerId, startDate, endDate) {
    const result = await this.db.query(`
      SELECT 
        DATE(submitted_at) as date,
        EXTRACT(HOUR FROM submitted_at) as hour,
        COUNT(*) as jobs,
        SUM(page_count * copies) as pages,
        COUNT(DISTINCT user_id) as unique_users,
        AVG(EXTRACT(EPOCH FROM (completed_at - submitted_at))) as avg_processing_time
      FROM print_jobs
      WHERE printer_id = $1
        AND submitted_at >= $2 
        AND submitted_at <= $3
        AND status IN ('completed', 'printed')
      GROUP BY DATE(submitted_at), EXTRACT(HOUR FROM submitted_at)
      ORDER BY date, hour
    `, [printerId, startDate, endDate]);
    
    // Get printer details
    const printerResult = await this.db.query(
      'SELECT * FROM printers WHERE id = $1',
      [printerId]
    );
    
    const printer = printerResult.rows[0];
    
    // Calculate peak hours
    const hourlyUsage = {};
    result.rows.forEach(row => {
      const hour = parseInt(row.hour);
      if (!hourlyUsage[hour]) {
        hourlyUsage[hour] = { jobs: 0, pages: 0 };
      }
      hourlyUsage[hour].jobs += parseInt(row.jobs);
      hourlyUsage[hour].pages += parseInt(row.pages);
    });
    
    const peakHours = Object.entries(hourlyUsage)
      .sort((a, b) => b[1].pages - a[1].pages)
      .slice(0, 3)
      .map(([hour, usage]) => ({
        hour: parseInt(hour),
        ...usage
      }));
    
    return {
      printer,
      daily: result.rows,
      peakHours,
      totals: result.rows.reduce((acc, row) => ({
        jobs: acc.jobs + parseInt(row.jobs),
        pages: acc.pages + parseInt(row.pages),
        users: Math.max(acc.users, parseInt(row.unique_users))
      }), { jobs: 0, pages: 0, users: 0 })
    };
  }

  async getUserPrintingBehavior(userId, period = 30) {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - period);
    
    const result = await this.db.query(`
      SELECT 
        p.name as printer_name,
        COUNT(*) as job_count,
        SUM(pj.page_count * pj.copies) as total_pages,
        AVG(pj.page_count) as avg_pages,
        SUM(CASE WHEN pj.color = true THEN 1 ELSE 0 END) as color_jobs,
        SUM(CASE WHEN pj.duplex = true THEN 1 ELSE 0 END) as duplex_jobs,
        EXTRACT(HOUR FROM pj.submitted_at) as preferred_hour
      FROM print_jobs pj
      JOIN printers p ON pj.printer_id = p.id
      WHERE pj.user_id = $1
        AND pj.submitted_at >= $2
        AND pj.status IN ('completed', 'printed')
      GROUP BY p.name, EXTRACT(HOUR FROM pj.submitted_at)
      ORDER BY job_count DESC
    `, [userId, startDate]);
    
    // Analyze patterns
    const printerPreference = {};
    const timePreference = {};
    
    result.rows.forEach(row => {
      if (!printerPreference[row.printer_name]) {
        printerPreference[row.printer_name] = {
          jobs: 0,
          pages: 0
        };
      }
      printerPreference[row.printer_name].jobs += parseInt(row.job_count);
      printerPreference[row.printer_name].pages += parseInt(row.total_pages);
      
      const hour = parseInt(row.preferred_hour);
      if (!timePreference[hour]) {
        timePreference[hour] = 0;
      }
      timePreference[hour] += parseInt(row.job_count);
    });
    
    // Find most used printer
    const preferredPrinter = Object.entries(printerPreference)
      .sort((a, b) => b[1].jobs - a[1].jobs)[0];
    
    // Find preferred time
    const preferredTime = Object.entries(timePreference)
      .sort((a, b) => b[1] - a[1])[0];
    
    // Calculate sustainability score
    const totalJobs = result.rows.reduce((sum, row) => sum + parseInt(row.job_count), 0);
    const duplexJobs = result.rows.reduce((sum, row) => sum + parseInt(row.duplex_jobs), 0);
    const colorJobs = result.rows.reduce((sum, row) => sum + parseInt(row.color_jobs), 0);
    
    const sustainabilityScore = this.calculateSustainabilityScore({
      duplexPercentage: totalJobs > 0 ? (duplexJobs / totalJobs) * 100 : 0,
      colorPercentage: totalJobs > 0 ? (colorJobs / totalJobs) * 100 : 0,
      avgPages: result.rows[0]?.avg_pages || 0
    });
    
    return {
      userId,
      period,
      preferredPrinter: preferredPrinter ? preferredPrinter[0] : null,
      preferredTime: preferredTime ? {
        hour: parseInt(preferredTime[0]),
        jobs: preferredTime[1]
      } : null,
      statistics: {
        totalJobs,
        totalPages: result.rows.reduce((sum, row) => sum + parseInt(row.total_pages), 0),
        avgPagesPerJob: result.rows[0]?.avg_pages || 0,
        colorPercentage: Math.round((colorJobs / totalJobs) * 100),
        duplexPercentage: Math.round((duplexJobs / totalJobs) * 100)
      },
      sustainabilityScore,
      recommendations: this.generateRecommendations({
        duplexPercentage: (duplexJobs / totalJobs) * 100,
        colorPercentage: (colorJobs / totalJobs) * 100
      })
    };
  }

  async getEnvironmentalImpact(startDate, endDate) {
    const result = await this.db.query(`
      SELECT 
        COUNT(*) as total_jobs,
        SUM(page_count * copies) as total_pages,
        SUM(CASE WHEN duplex = true THEN page_count * copies ELSE 0 END) as duplex_pages,
        SUM(CASE WHEN color = true THEN page_count * copies ELSE 0 END) as color_pages
      FROM print_jobs
      WHERE submitted_at >= $1 AND submitted_at <= $2
        AND status IN ('completed', 'printed')
    `, [startDate, endDate]);
    
    const data = result.rows[0];
    const totalPages = parseInt(data.total_pages || 0);
    const duplexPages = parseInt(data.duplex_pages || 0);
    const colorPages = parseInt(data.color_pages || 0);
    
    // Environmental calculations
    const treesEquivalent = totalPages / 8333; // 1 tree = 8333 sheets
    const co2Emissions = totalPages * 0.0092; // kg CO2 per page
    const waterUsage = totalPages * 10; // liters per page
    const energyUsage = totalPages * 0.05; // kWh per page
    
    // Savings from duplex printing
    const pagesSaved = duplexPages / 2;
    const treesSaved = pagesSaved / 8333;
    const co2Saved = pagesSaved * 0.0092;
    
    return {
      impact: {
        totalPages,
        treesEquivalent: Math.round(treesEquivalent * 100) / 100,
        co2Emissions: Math.round(co2Emissions * 100) / 100,
        waterUsage: Math.round(waterUsage),
        energyUsage: Math.round(energyUsage * 100) / 100
      },
      savings: {
        pagesSaved,
        treesSaved: Math.round(treesSaved * 100) / 100,
        co2Saved: Math.round(co2Saved * 100) / 100,
        duplexPercentage: totalPages > 0 ? 
          Math.round((duplexPages / totalPages) * 100) : 0
      },
      recommendations: [
        'Enable duplex printing by default',
        'Use print preview to reduce misprints',
        'Consider digital alternatives when possible',
        'Set up print quotas to reduce waste'
      ]
    };
  }

  async getTopUsers(startDate, endDate, limit = 10) {
    const result = await this.db.query(`
      SELECT 
        user_id,
        user_name,
        COUNT(*) as job_count,
        SUM(page_count * copies) as total_pages,
        SUM(cost) as total_cost,
        AVG(page_count) as avg_pages_per_job
      FROM print_jobs
      WHERE submitted_at >= $1 AND submitted_at <= $2
        AND status IN ('completed', 'printed')
      GROUP BY user_id, user_name
      ORDER BY total_pages DESC
      LIMIT $3
    `, [startDate, endDate, limit]);
    
    return result.rows;
  }

  async getFailureAnalysis(startDate, endDate) {
    const result = await this.db.query(`
      SELECT 
        p.name as printer_name,
        COUNT(CASE WHEN pj.status = 'failed' THEN 1 END) as failed_jobs,
        COUNT(CASE WHEN pj.status = 'cancelled' THEN 1 END) as cancelled_jobs,
        COUNT(*) as total_jobs,
        pj.error_message,
        COUNT(DISTINCT pj.error_message) as unique_errors
      FROM print_jobs pj
      JOIN printers p ON pj.printer_id = p.id
      WHERE pj.submitted_at >= $1 AND pj.submitted_at <= $2
      GROUP BY p.name, pj.error_message
      ORDER BY failed_jobs DESC
    `, [startDate, endDate]);
    
    // Group by printer
    const printerFailures = {};
    
    result.rows.forEach(row => {
      if (!printerFailures[row.printer_name]) {
        printerFailures[row.printer_name] = {
          failed: 0,
          cancelled: 0,
          total: 0,
          errors: []
        };
      }
      
      printerFailures[row.printer_name].failed += parseInt(row.failed_jobs);
      printerFailures[row.printer_name].cancelled += parseInt(row.cancelled_jobs);
      printerFailures[row.printer_name].total += parseInt(row.total_jobs);
      
      if (row.error_message) {
        printerFailures[row.printer_name].errors.push(row.error_message);
      }
    });
    
    // Calculate failure rates
    Object.keys(printerFailures).forEach(printer => {
      const data = printerFailures[printer];
      data.failureRate = data.total > 0 ? 
        Math.round((data.failed / data.total) * 100) : 0;
      data.cancelRate = data.total > 0 ?
        Math.round((data.cancelled / data.total) * 100) : 0;
    });
    
    return printerFailures;
  }

  async generateMonthlyReport(month, year) {
    const startDate = new Date(year, month - 1, 1);
    const endDate = new Date(year, month, 0);
    
    const [usage, costs, environmental, topUsers, failures] = await Promise.all([
      this.getUsageStats(startDate, endDate, 'week'),
      this.getCosts(startDate, endDate),
      this.getEnvironmentalImpact(startDate, endDate),
      this.getTopUsers(startDate, endDate),
      this.getFailureAnalysis(startDate, endDate)
    ]);
    
    return {
      period: {
        month,
        year,
        startDate,
        endDate
      },
      usage,
      costs,
      environmental,
      topUsers,
      failures,
      generated: new Date().toISOString()
    };
  }

  getGroupByClause(groupBy) {
    switch (groupBy.toLowerCase()) {
      case 'hour':
        return "DATE_TRUNC('hour', submitted_at)";
      case 'day':
        return "DATE(submitted_at)";
      case 'week':
        return "DATE_TRUNC('week', submitted_at)";
      case 'month':
        return "DATE_TRUNC('month', submitted_at)";
      default:
        return "DATE(submitted_at)";
    }
  }

  calculateSustainabilityScore(metrics) {
    let score = 100;
    
    // Penalize low duplex usage
    if (metrics.duplexPercentage < 50) {
      score -= (50 - metrics.duplexPercentage) * 0.5;
    }
    
    // Penalize high color usage
    if (metrics.colorPercentage > 30) {
      score -= (metrics.colorPercentage - 30) * 0.3;
    }
    
    // Penalize high pages per job
    if (metrics.avgPages > 10) {
      score -= Math.min((metrics.avgPages - 10) * 2, 20);
    }
    
    return Math.max(0, Math.round(score));
  }

  generateRecommendations(metrics) {
    const recommendations = [];
    
    if (metrics.duplexPercentage < 50) {
      recommendations.push('Enable duplex printing by default to save paper');
    }
    
    if (metrics.colorPercentage > 50) {
      recommendations.push('Consider using grayscale for non-essential documents');
    }
    
    return recommendations;
  }
}

module.exports = PrintAnalytics;