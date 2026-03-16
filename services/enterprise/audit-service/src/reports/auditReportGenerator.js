'use strict';

const PDFDocument = require('pdfkit');
const { Parser: Json2CsvParser } = require('json2csv');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const REPORTS_DIR = process.env.REPORTS_DIR || path.join(__dirname, '../../reports');

const REPORT_TYPES = {
  daily_summary: 'Daily Summary Report',
  compliance_audit: 'Compliance Audit Report',
  user_activity: 'User Activity Report',
  device_activity: 'Device Activity Report',
  security_incidents: 'Security Incidents Report'
};

class AuditReportGenerator {
  constructor({ logger, pool }) {
    this.logger = logger;
    this.pool = pool;
    this.reports = new Map();

    // Ensure reports directory exists
    if (!fs.existsSync(REPORTS_DIR)) {
      fs.mkdirSync(REPORTS_DIR, { recursive: true });
    }
  }

  async generateReport(type, filters = {}, format = 'pdf') {
    if (!REPORT_TYPES[type]) {
      throw new Error(`Unknown report type: ${type}. Valid types: ${Object.keys(REPORT_TYPES).join(', ')}`);
    }

    if (!['pdf', 'csv'].includes(format)) {
      throw new Error('Format must be "pdf" or "csv"');
    }

    const reportId = uuidv4();
    const title = REPORT_TYPES[type];

    this.logger.info('Generating report', { reportId, type, format, filters });

    const data = await this._fetchReportData(type, filters);

    let filePath;
    if (format === 'pdf') {
      filePath = await this._generatePDF(reportId, title, type, data, filters);
    } else {
      filePath = await this._generateCSV(reportId, title, type, data, filters);
    }

    const reportMeta = {
      id: reportId,
      type,
      title,
      format,
      filters,
      filePath,
      generatedAt: new Date().toISOString(),
      eventCount: data.events ? data.events.length : 0
    };

    this.reports.set(reportId, reportMeta);
    this.logger.info('Report generated', { reportId, filePath });

    return reportMeta;
  }

  async _fetchReportData(type, filters) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (filters.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(filters.startTime);
    }
    if (filters.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(filters.endTime);
    }

    switch (type) {
      case 'daily_summary': {
        // Default to last 24 hours if no time range
        if (!filters.startTime && !filters.endTime) {
          conditions.push(`timestamp >= NOW() - INTERVAL '24 hours'`);
        }
        break;
      }
      case 'compliance_audit': {
        // Include policy and admin events
        conditions.push(`category IN ('policy', 'admin', 'security')`);
        break;
      }
      case 'user_activity': {
        conditions.push(`category = 'identity'`);
        if (filters.actorId) {
          conditions.push(`actor->>'id' = $${paramIndex++}`);
          params.push(filters.actorId);
        }
        break;
      }
      case 'device_activity': {
        conditions.push(`category = 'device'`);
        if (filters.targetId) {
          conditions.push(`target->>'id' = $${paramIndex++}`);
          params.push(filters.targetId);
        }
        break;
      }
      case 'security_incidents': {
        conditions.push(`(category = 'security' OR severity IN ('critical', 'high'))`);
        break;
      }
    }

    const whereClause = conditions.length > 0
      ? 'WHERE ' + conditions.join(' AND ')
      : '';

    const [eventsResult, statsResult] = await Promise.all([
      this.pool.query(
        `SELECT * FROM audit_events ${whereClause} ORDER BY timestamp DESC LIMIT 10000`,
        params
      ),
      this.pool.query(
        `SELECT
           COUNT(*) as total,
           COUNT(*) FILTER (WHERE severity = 'critical') as critical_count,
           COUNT(*) FILTER (WHERE severity = 'high') as high_count,
           COUNT(*) FILTER (WHERE severity = 'medium') as medium_count,
           COUNT(*) FILTER (WHERE severity = 'low') as low_count,
           COUNT(DISTINCT actor->>'id') as unique_actors,
           MIN(timestamp) as earliest,
           MAX(timestamp) as latest
         FROM audit_events ${whereClause}`,
        params
      )
    ]);

    return {
      events: eventsResult.rows,
      stats: statsResult.rows[0]
    };
  }

  async _generatePDF(reportId, title, type, data, filters) {
    const filePath = path.join(REPORTS_DIR, `${reportId}.pdf`);

    return new Promise((resolve, reject) => {
      const doc = new PDFDocument({ margin: 50 });
      const stream = fs.createWriteStream(filePath);

      stream.on('finish', () => resolve(filePath));
      stream.on('error', reject);
      doc.pipe(stream);

      // Header
      doc.fontSize(24).text('OpenDirectory Audit Report', { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(16).text(title, { align: 'center' });
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#666666')
        .text(`Generated: ${new Date().toISOString()}`, { align: 'center' });
      doc.moveDown(1);

      // Divider
      doc.moveTo(50, doc.y).lineTo(562, doc.y).stroke('#cccccc');
      doc.moveDown(1);

      // Filters applied
      doc.fontSize(12).fillColor('#333333').text('Report Parameters');
      doc.fontSize(9).fillColor('#666666');
      if (filters.startTime) doc.text(`From: ${filters.startTime}`);
      if (filters.endTime) doc.text(`To: ${filters.endTime}`);
      doc.text(`Report Type: ${type}`);
      doc.moveDown(1);

      // Summary statistics
      const stats = data.stats;
      doc.fontSize(14).fillColor('#333333').text('Summary');
      doc.moveDown(0.5);
      doc.fontSize(10).fillColor('#333333');
      doc.text(`Total Events: ${stats.total}`);
      doc.text(`Critical: ${stats.critical_count} | High: ${stats.high_count} | Medium: ${stats.medium_count} | Low: ${stats.low_count}`);
      doc.text(`Unique Actors: ${stats.unique_actors}`);
      if (stats.earliest) doc.text(`Time Range: ${stats.earliest} to ${stats.latest}`);
      doc.moveDown(1);

      // Events table
      doc.fontSize(14).fillColor('#333333').text('Events');
      doc.moveDown(0.5);

      const displayEvents = data.events.slice(0, 200);
      const tableTop = doc.y;

      // Table header
      doc.fontSize(8).fillColor('#ffffff');
      doc.rect(50, tableTop, 512, 15).fill('#333333');
      doc.fill('#ffffff');
      doc.text('Timestamp', 55, tableTop + 3, { width: 120 });
      doc.text('Action', 180, tableTop + 3, { width: 120 });
      doc.text('Category', 305, tableTop + 3, { width: 60 });
      doc.text('Severity', 370, tableTop + 3, { width: 50 });
      doc.text('Result', 425, tableTop + 3, { width: 50 });
      doc.text('Actor', 480, tableTop + 3, { width: 80 });

      let y = tableTop + 18;
      doc.fillColor('#333333');

      for (const event of displayEvents) {
        if (y > 720) {
          doc.addPage();
          y = 50;
        }

        const bgColor = y % 2 === 0 ? '#f9f9f9' : '#ffffff';
        doc.rect(50, y - 2, 512, 14).fill(bgColor);
        doc.fillColor('#333333');

        const ts = event.timestamp
          ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19)
          : '';
        const actorName = event.actor ? (event.actor.name || event.actor.id || '') : '';

        doc.text(ts, 55, y, { width: 120 });
        doc.text((event.action || '').slice(0, 25), 180, y, { width: 120 });
        doc.text(event.category || '', 305, y, { width: 60 });
        doc.text(event.severity || '', 370, y, { width: 50 });
        doc.text(event.result || '', 425, y, { width: 50 });
        doc.text(String(actorName).slice(0, 15), 480, y, { width: 80 });

        y += 14;
      }

      if (data.events.length > 200) {
        doc.moveDown(1);
        doc.fontSize(9).fillColor('#999999')
          .text(`... and ${data.events.length - 200} more events (truncated)`);
      }

      // Footer
      doc.moveDown(2);
      doc.fontSize(8).fillColor('#999999')
        .text('This report was generated by the OpenDirectory Audit Service. Hash chain integrity ensures tamper-evident logging.',
          { align: 'center' });

      doc.end();
    });
  }

  async _generateCSV(reportId, title, type, data) {
    const filePath = path.join(REPORTS_DIR, `${reportId}.csv`);

    const fields = [
      { label: 'ID', value: 'id' },
      { label: 'Timestamp', value: 'timestamp' },
      { label: 'Category', value: 'category' },
      { label: 'Severity', value: 'severity' },
      { label: 'Action', value: 'action' },
      { label: 'Result', value: 'result' },
      { label: 'Source', value: 'source' },
      { label: 'Actor ID', value: (row) => row.actor ? row.actor.id : '' },
      { label: 'Actor Name', value: (row) => row.actor ? row.actor.name : '' },
      { label: 'Target ID', value: (row) => row.target ? row.target.id : '' },
      { label: 'Target Type', value: (row) => row.target ? row.target.type : '' },
      { label: 'Details', value: (row) => JSON.stringify(row.details) },
      { label: 'Correlation ID', value: 'correlation_id' },
      { label: 'Hash', value: 'hash' }
    ];

    const parser = new Json2CsvParser({ fields });
    const csv = parser.parse(data.events);

    fs.writeFileSync(filePath, csv, 'utf8');
    return filePath;
  }

  getReport(reportId) {
    return this.reports.get(reportId) || null;
  }

  getReportFilePath(reportId) {
    const report = this.reports.get(reportId);
    if (!report) return null;
    if (!fs.existsSync(report.filePath)) return null;
    return report.filePath;
  }
}

module.exports = AuditReportGenerator;
