'use strict';

const PDFDocument = require('pdfkit');
const { Parser: Json2CsvParser } = require('json2csv');
const logger = require('../utils/logger');

const COMPLIANCE_FRAMEWORKS = {
  ISO27001: {
    name: 'ISO 27001',
    description: 'Information Security Management System',
    controls: [
      { id: 'A.9.2.1', name: 'User registration and de-registration', categories: ['identity'], actions: ['user.created', 'user.deleted', 'user.disabled'] },
      { id: 'A.9.2.2', name: 'User access provisioning', categories: ['identity', 'policy'], actions: ['role.assigned', 'permission.granted', 'access.granted'] },
      { id: 'A.9.2.3', name: 'Privileged access management', categories: ['admin', 'security'], actions: ['admin.login', 'privilege.escalated', 'role.admin.assigned'] },
      { id: 'A.9.4.1', name: 'Information access restriction', categories: ['policy', 'security'], actions: ['access.denied', 'policy.enforced'] },
      { id: 'A.9.4.2', name: 'Secure log-on procedures', categories: ['security', 'identity'], actions: ['login.success', 'login.failed', 'mfa.verified'] },
      { id: 'A.12.4.1', name: 'Event logging', categories: ['system'], actions: ['audit.enabled', 'log.configured'] },
      { id: 'A.12.4.3', name: 'Administrator and operator logs', categories: ['admin'], actions: ['admin.*'] },
    ],
  },
  SOC2: {
    name: 'SOC 2 Type II',
    description: 'Service Organization Control 2',
    controls: [
      { id: 'CC6.1', name: 'Logical access security', categories: ['identity', 'security'], actions: ['login.*', 'access.*', 'auth.*'] },
      { id: 'CC6.2', name: 'User authentication', categories: ['identity', 'security'], actions: ['login.*', 'mfa.*', 'password.*'] },
      { id: 'CC6.3', name: 'Authorization management', categories: ['policy', 'admin'], actions: ['role.*', 'permission.*', 'policy.*'] },
      { id: 'CC7.1', name: 'System monitoring', categories: ['system', 'security'], actions: ['monitor.*', 'alert.*', 'health.*'] },
      { id: 'CC7.2', name: 'Anomaly detection', categories: ['security'], actions: ['anomaly.*', 'threat.*', 'violation.*'] },
      { id: 'CC8.1', name: 'Change management', categories: ['admin', 'system'], actions: ['config.*', 'deploy.*', 'update.*'] },
    ],
  },
  DSGVO: {
    name: 'DSGVO (GDPR)',
    description: 'General Data Protection Regulation',
    controls: [
      { id: 'Art.5', name: 'Data processing principles', categories: ['compliance'], actions: ['data.processed', 'data.accessed'] },
      { id: 'Art.15', name: 'Right of access', categories: ['compliance', 'identity'], actions: ['data.export', 'data.accessed'] },
      { id: 'Art.17', name: 'Right to erasure', categories: ['compliance', 'identity'], actions: ['data.deleted', 'user.deleted', 'data.anonymized'] },
      { id: 'Art.20', name: 'Data portability', categories: ['compliance'], actions: ['data.export', 'data.transferred'] },
      { id: 'Art.25', name: 'Data protection by design', categories: ['security', 'compliance'], actions: ['encryption.*', 'privacy.*'] },
      { id: 'Art.30', name: 'Records of processing', categories: ['compliance'], actions: ['processing.recorded', 'consent.*'] },
      { id: 'Art.33', name: 'Breach notification', categories: ['security'], actions: ['breach.*', 'incident.*'] },
    ],
  },
};

class AuditReportGenerator {
  constructor(db) {
    this.db = db;
  }

  async generatePDF(filters, options = {}) {
    const events = await this._fetchEvents(filters);
    const stats = await this._calculateStats(filters);

    return new Promise((resolve, reject) => {
      try {
        const doc = new PDFDocument({ size: 'A4', margin: 50, bufferPages: true });
        const chunks = [];

        doc.on('data', (chunk) => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        // Header
        doc.fontSize(20).font('Helvetica-Bold').text('Audit Report', { align: 'center' });
        doc.moveDown(0.5);
        doc.fontSize(10).font('Helvetica').fillColor('#666666');
        doc.text(`Generated: ${new Date().toISOString()}`, { align: 'center' });
        if (filters.startTime || filters.endTime) {
          const range = `Period: ${filters.startTime || 'beginning'} to ${filters.endTime || 'now'}`;
          doc.text(range, { align: 'center' });
        }
        doc.moveDown(1);

        // Summary statistics
        doc.fillColor('#000000').fontSize(14).font('Helvetica-Bold').text('Summary');
        doc.moveDown(0.5);
        doc.fontSize(10).font('Helvetica');
        doc.text(`Total Events: ${stats.totalEvents}`);
        doc.text(`Categories: ${stats.categories.length}`);
        doc.text(`Unique Actors: ${stats.uniqueActors}`);
        doc.text(`Failed Actions: ${stats.failedActions}`);
        doc.text(`Critical/Error Events: ${stats.criticalEvents}`);
        doc.moveDown(1);

        // Category breakdown
        if (stats.categories.length > 0) {
          doc.fontSize(14).font('Helvetica-Bold').text('Events by Category');
          doc.moveDown(0.5);
          doc.fontSize(10).font('Helvetica');
          for (const cat of stats.categories) {
            doc.text(`  ${cat.category}: ${cat.count} events`);
          }
          doc.moveDown(1);
        }

        // Severity breakdown
        if (stats.severities.length > 0) {
          doc.fontSize(14).font('Helvetica-Bold').text('Events by Severity');
          doc.moveDown(0.5);
          doc.fontSize(10).font('Helvetica');
          for (const sev of stats.severities) {
            doc.text(`  ${sev.severity}: ${sev.count} events`);
          }
          doc.moveDown(1);
        }

        // Event table
        doc.fontSize(14).font('Helvetica-Bold').text('Event Details');
        doc.moveDown(0.5);

        const tableTop = doc.y;
        const colWidths = [120, 70, 60, 100, 140];
        const headers = ['Timestamp', 'Category', 'Severity', 'Actor', 'Action'];

        // Table header
        doc.fontSize(8).font('Helvetica-Bold');
        let xPos = 50;
        for (let i = 0; i < headers.length; i++) {
          doc.text(headers[i], xPos, tableTop, { width: colWidths[i], lineBreak: false });
          xPos += colWidths[i];
        }
        doc.moveDown(0.5);
        doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
        doc.moveDown(0.3);

        // Table rows
        doc.font('Helvetica').fontSize(7);
        const maxRows = options.maxRows || 500;
        const displayEvents = events.slice(0, maxRows);

        for (const event of displayEvents) {
          if (doc.y > 750) {
            doc.addPage();
          }

          const y = doc.y;
          xPos = 50;
          const ts = new Date(event.timestamp).toISOString().replace('T', ' ').substring(0, 19);
          doc.text(ts, xPos, y, { width: colWidths[0], lineBreak: false });
          xPos += colWidths[0];
          doc.text(event.category || '', xPos, y, { width: colWidths[1], lineBreak: false });
          xPos += colWidths[1];
          doc.text(event.severity || '', xPos, y, { width: colWidths[2], lineBreak: false });
          xPos += colWidths[2];
          doc.text((event.actor_name || event.actor_id || '').substring(0, 20), xPos, y, { width: colWidths[3], lineBreak: false });
          xPos += colWidths[3];
          doc.text((event.action || '').substring(0, 30), xPos, y, { width: colWidths[4], lineBreak: false });
          doc.moveDown(0.6);
        }

        if (events.length > maxRows) {
          doc.moveDown(1);
          doc.fontSize(9).font('Helvetica-Oblique')
            .text(`... and ${events.length - maxRows} more events (truncated)`, { align: 'center' });
        }

        // Footer on all pages
        const pages = doc.bufferedPageRange();
        for (let i = pages.start; i < pages.start + pages.count; i++) {
          doc.switchToPage(i);
          doc.fontSize(8).font('Helvetica').fillColor('#999999');
          doc.text(
            `Page ${i + 1} of ${pages.count} | OpenDirectory Audit Service`,
            50, 780,
            { align: 'center', width: 495 }
          );
        }

        doc.end();
      } catch (err) {
        logger.error('PDF generation failed', { error: err.message });
        reject(err);
      }
    });
  }

  async generateCSV(filters) {
    const events = await this._fetchEvents(filters);

    if (events.length === 0) {
      return 'No events found matching the specified filters.\n';
    }

    const fields = [
      'id', 'timestamp', 'category', 'severity',
      'actor_type', 'actor_id', 'actor_name', 'actor_ip',
      'target_type', 'target_id', 'target_name',
      'action', 'result', 'correlation_id', 'source',
      { label: 'details', value: (row) => JSON.stringify(row.details) },
    ];

    try {
      const parser = new Json2CsvParser({ fields });
      return parser.parse(events);
    } catch (err) {
      logger.error('CSV generation failed', { error: err.message });
      throw err;
    }
  }

  async generateComplianceReport(framework, filters = {}) {
    const frameworkDef = COMPLIANCE_FRAMEWORKS[framework];
    if (!frameworkDef) {
      throw new Error(`Unknown compliance framework: ${framework}. Supported: ${Object.keys(COMPLIANCE_FRAMEWORKS).join(', ')}`);
    }

    const report = {
      framework: frameworkDef.name,
      description: frameworkDef.description,
      generatedAt: new Date().toISOString(),
      period: {
        start: filters.startTime || null,
        end: filters.endTime || null,
      },
      controls: [],
      summary: {
        totalControls: frameworkDef.controls.length,
        controlsWithEvents: 0,
        totalRelevantEvents: 0,
      },
    };

    for (const control of frameworkDef.controls) {
      const controlReport = {
        id: control.id,
        name: control.name,
        categories: control.categories,
        events: [],
        eventCount: 0,
        status: 'no_data',
      };

      // Build query for this control
      const conditions = [];
      const params = [];
      let paramIndex = 1;

      if (control.categories.length > 0) {
        conditions.push(`category = ANY($${paramIndex++})`);
        params.push(control.categories);
      }

      if (filters.startTime) {
        conditions.push(`timestamp >= $${paramIndex++}`);
        params.push(filters.startTime);
      }
      if (filters.endTime) {
        conditions.push(`timestamp <= $${paramIndex++}`);
        params.push(filters.endTime);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      try {
        const countResult = await this.db.query(
          `SELECT COUNT(*) AS total FROM audit_events ${whereClause}`,
          params
        );
        controlReport.eventCount = parseInt(countResult.rows[0].total, 10);

        if (controlReport.eventCount > 0) {
          controlReport.status = 'monitored';
          report.summary.controlsWithEvents++;
          report.summary.totalRelevantEvents += controlReport.eventCount;

          // Get sample events (most recent 5)
          const sampleResult = await this.db.query(
            `SELECT id, timestamp, category, severity, action, actor_name, target_name, result
             FROM audit_events ${whereClause}
             ORDER BY timestamp DESC LIMIT 5`,
            params
          );
          controlReport.events = sampleResult.rows;
        }
      } catch (err) {
        logger.error('Compliance control query failed', {
          error: err.message,
          control: control.id,
          framework,
        });
        controlReport.status = 'error';
        controlReport.error = err.message;
      }

      report.controls.push(controlReport);
    }

    return report;
  }

  async _fetchEvents(filters) {
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
    if (filters.category) {
      conditions.push(`category = $${paramIndex++}`);
      params.push(filters.category);
    }
    if (filters.severity) {
      conditions.push(`severity = $${paramIndex++}`);
      params.push(filters.severity);
    }
    if (filters.actorId) {
      conditions.push(`actor_id = $${paramIndex++}`);
      params.push(filters.actorId);
    }
    if (filters.targetId) {
      conditions.push(`target_id = $${paramIndex++}`);
      params.push(filters.targetId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(parseInt(filters.limit, 10) || 10000, 50000);

    const result = await this.db.query(
      `SELECT * FROM audit_events ${whereClause} ORDER BY timestamp DESC LIMIT $${paramIndex}`,
      [...params, limit]
    );
    return result.rows;
  }

  async _calculateStats(filters) {
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
    if (filters.category) {
      conditions.push(`category = $${paramIndex++}`);
      params.push(filters.category);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const [totalResult, categoriesResult, severitiesResult, actorsResult, failedResult, criticalResult] =
      await Promise.all([
        this.db.query(`SELECT COUNT(*) AS total FROM audit_events ${whereClause}`, params),
        this.db.query(`SELECT category, COUNT(*) AS count FROM audit_events ${whereClause} GROUP BY category ORDER BY count DESC`, params),
        this.db.query(`SELECT severity, COUNT(*) AS count FROM audit_events ${whereClause} GROUP BY severity ORDER BY count DESC`, params),
        this.db.query(`SELECT COUNT(DISTINCT actor_id) AS unique_actors FROM audit_events ${whereClause}`, params),
        this.db.query(`SELECT COUNT(*) AS count FROM audit_events ${whereClause.length > 0 ? whereClause + ' AND' : 'WHERE'} result = 'failure'`, params),
        this.db.query(`SELECT COUNT(*) AS count FROM audit_events ${whereClause.length > 0 ? whereClause + ' AND' : 'WHERE'} severity IN ('critical', 'error')`, params),
      ]);

    return {
      totalEvents: parseInt(totalResult.rows[0].total, 10),
      categories: categoriesResult.rows,
      severities: severitiesResult.rows,
      uniqueActors: parseInt(actorsResult.rows[0].unique_actors, 10),
      failedActions: parseInt(failedResult.rows[0].count, 10),
      criticalEvents: parseInt(criticalResult.rows[0].count, 10),
    };
  }
}

module.exports = AuditReportGenerator;
