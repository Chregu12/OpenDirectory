'use strict';

const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');

class EventStore {
  constructor(db, integrityChecker) {
    this.db = db;
    this.integrityChecker = integrityChecker;
  }

  async store(event) {
    const timestamp = event.timestamp || new Date().toISOString();
    const eventWithHash = this.integrityChecker.calculateHash({
      ...event,
      timestamp,
    });

    const query = `
      INSERT INTO audit_events (
        id, timestamp, category, severity, actor_type, actor_id, actor_name, actor_ip,
        target_type, target_id, target_name, action, details, result,
        correlation_id, source, hash, previous_hash
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8,
        $9, $10, $11, $12, $13, $14,
        $15, $16, $17, $18
      )
      RETURNING *
    `;

    const id = event.id || uuidv4();
    const values = [
      id,
      timestamp,
      eventWithHash.category,
      eventWithHash.severity || 'info',
      eventWithHash.actor_type || null,
      eventWithHash.actor_id || null,
      eventWithHash.actor_name || null,
      eventWithHash.actor_ip || null,
      eventWithHash.target_type || null,
      eventWithHash.target_id || null,
      eventWithHash.target_name || null,
      eventWithHash.action,
      JSON.stringify(eventWithHash.details || {}),
      eventWithHash.result || 'success',
      eventWithHash.correlation_id || null,
      eventWithHash.source || null,
      eventWithHash.hash,
      eventWithHash.previous_hash,
    ];

    try {
      const result = await this.db.query(query, values);
      logger.debug('Audit event stored', { id, category: eventWithHash.category, action: eventWithHash.action });
      return result.rows[0];
    } catch (err) {
      logger.error('Failed to store audit event', { error: err.message, category: eventWithHash.category });
      throw err;
    }
  }

  async query(filters = {}) {
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
    if (filters.targetType) {
      conditions.push(`target_type = $${paramIndex++}`);
      params.push(filters.targetType);
    }
    if (filters.action) {
      conditions.push(`action ILIKE $${paramIndex++}`);
      params.push(`%${filters.action}%`);
    }
    if (filters.result) {
      conditions.push(`result = $${paramIndex++}`);
      params.push(filters.result);
    }
    if (filters.source) {
      conditions.push(`source = $${paramIndex++}`);
      params.push(filters.source);
    }
    if (filters.correlationId) {
      conditions.push(`correlation_id = $${paramIndex++}`);
      params.push(filters.correlationId);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(Math.max(parseInt(filters.limit, 10) || 50, 1), 1000);
    const offset = Math.max(parseInt(filters.offset, 10) || 0, 0);
    const sortDir = filters.sortDir === 'asc' ? 'ASC' : 'DESC';

    const countQuery = `SELECT COUNT(*) AS total FROM audit_events ${whereClause}`;
    const dataQuery = `
      SELECT * FROM audit_events
      ${whereClause}
      ORDER BY timestamp ${sortDir}
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;
    params.push(limit, offset);

    try {
      const [countResult, dataResult] = await Promise.all([
        this.db.query(countQuery, params.slice(0, params.length - 2)),
        this.db.query(dataQuery, params),
      ]);

      return {
        events: dataResult.rows,
        total: parseInt(countResult.rows[0].total, 10),
        limit,
        offset,
        hasMore: offset + limit < parseInt(countResult.rows[0].total, 10),
      };
    } catch (err) {
      logger.error('Failed to query audit events', { error: err.message, filters });
      throw err;
    }
  }

  async getById(id) {
    if (!id || typeof id !== 'string') {
      throw new Error('Valid event ID is required');
    }

    const result = await this.db.query('SELECT * FROM audit_events WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  async getByCorrelation(correlationId) {
    if (!correlationId || typeof correlationId !== 'string') {
      throw new Error('Valid correlation ID is required');
    }

    const result = await this.db.query(
      'SELECT * FROM audit_events WHERE correlation_id = $1 ORDER BY timestamp ASC',
      [correlationId]
    );
    return result.rows;
  }

  async getTimeline(targetId, options = {}) {
    if (!targetId || typeof targetId !== 'string') {
      throw new Error('Valid target ID is required');
    }

    const conditions = ['target_id = $1'];
    const params = [targetId];
    let paramIndex = 2;

    if (options.targetType) {
      conditions.push(`target_type = $${paramIndex++}`);
      params.push(options.targetType);
    }
    if (options.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(options.startTime);
    }
    if (options.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(options.endTime);
    }

    const limit = Math.min(Math.max(parseInt(options.limit, 10) || 100, 1), 1000);
    const offset = Math.max(parseInt(options.offset, 10) || 0, 0);

    const query = `
      SELECT * FROM audit_events
      WHERE ${conditions.join(' AND ')}
      ORDER BY timestamp DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;
    params.push(limit, offset);

    const result = await this.db.query(query, params);
    return result.rows;
  }

  async count(filters = {}) {
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

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const result = await this.db.query(`SELECT COUNT(*) AS total FROM audit_events ${whereClause}`, params);
    return parseInt(result.rows[0].total, 10);
  }

  async getCategories() {
    const result = await this.db.query(`
      SELECT category, COUNT(*) AS count
      FROM audit_events
      GROUP BY category
      ORDER BY count DESC
    `);
    return result.rows;
  }
}

module.exports = EventStore;
