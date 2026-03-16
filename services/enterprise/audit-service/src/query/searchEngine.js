'use strict';

class SearchEngine {
  constructor({ logger, pool }) {
    this.logger = logger;
    this.pool = pool;
  }

  async search(query, filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    // Full-text search
    if (query && query.trim()) {
      conditions.push(
        `to_tsvector('english', COALESCE(action, '') || ' ' || COALESCE(details::text, ''))
         @@ plainto_tsquery('english', $${paramIndex++})`
      );
      params.push(query.trim());
    }

    // Time range filter
    if (filters.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(filters.startTime);
    }
    if (filters.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(filters.endTime);
    }

    // Category filter
    if (filters.category) {
      if (Array.isArray(filters.category)) {
        conditions.push(`category = ANY($${paramIndex++})`);
        params.push(filters.category);
      } else {
        conditions.push(`category = $${paramIndex++}`);
        params.push(filters.category);
      }
    }

    // Severity filter
    if (filters.severity) {
      if (Array.isArray(filters.severity)) {
        conditions.push(`severity = ANY($${paramIndex++})`);
        params.push(filters.severity);
      } else {
        conditions.push(`severity = $${paramIndex++}`);
        params.push(filters.severity);
      }
    }

    // Actor filter
    if (filters.actorId) {
      conditions.push(`actor->>'id' = $${paramIndex++}`);
      params.push(filters.actorId);
    }
    if (filters.actorName) {
      conditions.push(`actor->>'name' ILIKE $${paramIndex++}`);
      params.push(`%${filters.actorName}%`);
    }

    // Target filter
    if (filters.targetId) {
      conditions.push(`target->>'id' = $${paramIndex++}`);
      params.push(filters.targetId);
    }
    if (filters.targetType) {
      conditions.push(`target->>'type' = $${paramIndex++}`);
      params.push(filters.targetType);
    }

    // Result filter
    if (filters.result) {
      conditions.push(`result = $${paramIndex++}`);
      params.push(filters.result);
    }

    // Source filter
    if (filters.source) {
      conditions.push(`source = $${paramIndex++}`);
      params.push(filters.source);
    }

    // Action pattern filter
    if (filters.action) {
      conditions.push(`action LIKE $${paramIndex++}`);
      params.push(`%${filters.action}%`);
    }

    // Cursor-based pagination
    if (pagination.cursor) {
      conditions.push(`created_at < $${paramIndex++}`);
      params.push(pagination.cursor);
    }

    const whereClause = conditions.length > 0
      ? 'WHERE ' + conditions.join(' AND ')
      : '';

    // Sorting
    const sortField = filters.sortBy === 'severity' ? 'severity' : 'timestamp';
    const sortDir = filters.sortDir === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(parseInt(pagination.limit, 10) || 50, 500);

    // Execute count and data queries in parallel
    const countParams = params.slice();
    const dataParams = [...params, limit];

    const countQuery = `SELECT COUNT(*) as total FROM audit_events ${whereClause}`;
    const dataQuery = `
      SELECT * FROM audit_events
      ${whereClause}
      ORDER BY ${sortField} ${sortDir}, created_at DESC
      LIMIT $${paramIndex}
    `;

    const [countResult, dataResult] = await Promise.all([
      this.pool.query(countQuery, countParams),
      this.pool.query(dataQuery, dataParams)
    ]);

    const events = dataResult.rows;
    const total = parseInt(countResult.rows[0].total, 10);
    const nextCursor = events.length === limit
      ? events[events.length - 1].created_at.toISOString()
      : null;

    return {
      events,
      total,
      limit,
      cursor: nextCursor,
      query: query || null,
      filters
    };
  }

  async aggregate(filters = {}) {
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

    const whereClause = conditions.length > 0
      ? 'WHERE ' + conditions.join(' AND ')
      : '';

    const [byCategory, bySeverity, byActor, byHour] = await Promise.all([
      this.pool.query(
        `SELECT category, COUNT(*) as count
         FROM audit_events ${whereClause}
         GROUP BY category ORDER BY count DESC`,
        params
      ),
      this.pool.query(
        `SELECT severity, COUNT(*) as count
         FROM audit_events ${whereClause}
         GROUP BY severity ORDER BY count DESC`,
        params
      ),
      this.pool.query(
        `SELECT actor->>'id' as actor_id, actor->>'name' as actor_name, COUNT(*) as count
         FROM audit_events ${whereClause}
         GROUP BY actor->>'id', actor->>'name'
         ORDER BY count DESC LIMIT 20`,
        params
      ),
      this.pool.query(
        `SELECT date_trunc('hour', timestamp) as hour, COUNT(*) as count
         FROM audit_events ${whereClause}
         GROUP BY date_trunc('hour', timestamp)
         ORDER BY hour DESC LIMIT 168`,
        params
      )
    ]);

    return {
      byCategory: byCategory.rows,
      bySeverity: bySeverity.rows,
      topActors: byActor.rows,
      byHour: byHour.rows
    };
  }
}

module.exports = SearchEngine;
