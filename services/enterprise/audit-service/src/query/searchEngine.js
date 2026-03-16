'use strict';

const logger = require('../utils/logger');

class SearchEngine {
  constructor(db) {
    this.db = db;
  }

  async search(query) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    // Time range filters
    if (query.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(query.startTime);
    }
    if (query.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(query.endTime);
    }

    // Category filter
    if (query.category) {
      conditions.push(`category = $${paramIndex++}`);
      params.push(query.category);
    }

    // Severity filter
    if (query.severity) {
      if (Array.isArray(query.severity)) {
        conditions.push(`severity = ANY($${paramIndex++})`);
        params.push(query.severity);
      } else {
        conditions.push(`severity = $${paramIndex++}`);
        params.push(query.severity);
      }
    }

    // Actor filter
    if (query.actorId) {
      conditions.push(`actor_id = $${paramIndex++}`);
      params.push(query.actorId);
    }
    if (query.actorName) {
      conditions.push(`actor_name ILIKE $${paramIndex++}`);
      params.push(`%${query.actorName}%`);
    }

    // Target filter
    if (query.targetId) {
      conditions.push(`target_id = $${paramIndex++}`);
      params.push(query.targetId);
    }
    if (query.targetType) {
      conditions.push(`target_type = $${paramIndex++}`);
      params.push(query.targetType);
    }

    // Result filter
    if (query.result) {
      conditions.push(`result = $${paramIndex++}`);
      params.push(query.result);
    }

    // Free text search across action, details, actor_name, target_name
    if (query.text) {
      const textParam = `%${query.text}%`;
      conditions.push(`(
        action ILIKE $${paramIndex} OR
        actor_name ILIKE $${paramIndex} OR
        target_name ILIKE $${paramIndex} OR
        details::text ILIKE $${paramIndex}
      )`);
      params.push(textParam);
      paramIndex++;
    }

    // JSONB details filter
    if (query.detailsFilter && typeof query.detailsFilter === 'object') {
      conditions.push(`details @> $${paramIndex++}`);
      params.push(JSON.stringify(query.detailsFilter));
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(Math.max(parseInt(query.limit, 10) || 50, 1), 1000);
    const offset = Math.max(parseInt(query.offset, 10) || 0, 0);

    const countSql = `SELECT COUNT(*) AS total FROM audit_events ${whereClause}`;
    const dataSql = `
      SELECT * FROM audit_events
      ${whereClause}
      ORDER BY timestamp DESC
      LIMIT $${paramIndex++} OFFSET $${paramIndex++}
    `;
    params.push(limit, offset);

    try {
      const [countResult, dataResult] = await Promise.all([
        this.db.query(countSql, params.slice(0, params.length - 2)),
        this.db.query(dataSql, params),
      ]);

      const total = parseInt(countResult.rows[0].total, 10);

      // Add search highlights for free text matches
      let events = dataResult.rows;
      if (query.text) {
        events = events.map((event) => ({
          ...event,
          _highlights: this._findHighlights(event, query.text),
        }));
      }

      return {
        events,
        total,
        limit,
        offset,
        hasMore: offset + limit < total,
      };
    } catch (err) {
      logger.error('Search query failed', { error: err.message, query });
      throw err;
    }
  }

  _findHighlights(event, text) {
    const highlights = [];
    const lower = text.toLowerCase();

    if (event.action && event.action.toLowerCase().includes(lower)) {
      highlights.push({ field: 'action', value: event.action });
    }
    if (event.actor_name && event.actor_name.toLowerCase().includes(lower)) {
      highlights.push({ field: 'actor_name', value: event.actor_name });
    }
    if (event.target_name && event.target_name.toLowerCase().includes(lower)) {
      highlights.push({ field: 'target_name', value: event.target_name });
    }
    if (event.details) {
      const detailsStr = JSON.stringify(event.details);
      if (detailsStr.toLowerCase().includes(lower)) {
        highlights.push({ field: 'details', value: detailsStr.substring(0, 200) });
      }
    }

    return highlights;
  }

  async correlate(eventId) {
    if (!eventId || typeof eventId !== 'string') {
      throw new Error('Valid event ID is required');
    }

    // Get the source event
    const sourceResult = await this.db.query('SELECT * FROM audit_events WHERE id = $1', [eventId]);
    if (sourceResult.rows.length === 0) {
      return { source: null, related: [] };
    }

    const source = sourceResult.rows[0];
    const related = [];

    // Find by correlation_id
    if (source.correlation_id) {
      const corrResult = await this.db.query(
        'SELECT * FROM audit_events WHERE correlation_id = $1 AND id != $2 ORDER BY timestamp ASC',
        [source.correlation_id, eventId]
      );
      for (const row of corrResult.rows) {
        related.push({ ...row, _relation: 'correlation_id' });
      }
    }

    // Find by same actor within time window (5 minutes)
    if (source.actor_id) {
      const actorResult = await this.db.query(
        `SELECT * FROM audit_events
         WHERE actor_id = $1 AND id != $2
         AND timestamp BETWEEN $3::timestamptz - interval '5 minutes' AND $3::timestamptz + interval '5 minutes'
         ORDER BY timestamp ASC
         LIMIT 20`,
        [source.actor_id, eventId, source.timestamp]
      );
      for (const row of actorResult.rows) {
        if (!related.find((r) => r.id === row.id)) {
          related.push({ ...row, _relation: 'same_actor' });
        }
      }
    }

    // Find by same target within time window
    if (source.target_id) {
      const targetResult = await this.db.query(
        `SELECT * FROM audit_events
         WHERE target_id = $1 AND id != $2
         AND timestamp BETWEEN $3::timestamptz - interval '5 minutes' AND $3::timestamptz + interval '5 minutes'
         ORDER BY timestamp ASC
         LIMIT 20`,
        [source.target_id, eventId, source.timestamp]
      );
      for (const row of targetResult.rows) {
        if (!related.find((r) => r.id === row.id)) {
          related.push({ ...row, _relation: 'same_target' });
        }
      }
    }

    return { source, related };
  }

  async aggregate(groupBy, filters = {}) {
    const validGroupBy = ['category', 'severity', 'actor_id', 'target_type', 'result', 'source'];
    if (!validGroupBy.includes(groupBy)) {
      throw new Error(`Invalid groupBy field. Must be one of: ${validGroupBy.join(', ')}`);
    }

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

    // Standard aggregation
    const query = `
      SELECT ${groupBy} AS key, COUNT(*) AS count
      FROM audit_events
      ${whereClause}
      GROUP BY ${groupBy}
      ORDER BY count DESC
      LIMIT 100
    `;

    const result = await this.db.query(query, params);

    // Daily breakdown if time range is provided
    let daily = null;
    if (filters.startTime && filters.endTime) {
      const dailyQuery = `
        SELECT DATE(timestamp) AS date, COUNT(*) AS count
        FROM audit_events
        ${whereClause}
        GROUP BY DATE(timestamp)
        ORDER BY date ASC
      `;
      const dailyResult = await this.db.query(dailyQuery, params);
      daily = dailyResult.rows;
    }

    return {
      groupBy,
      buckets: result.rows,
      daily,
    };
  }
}

module.exports = SearchEngine;
