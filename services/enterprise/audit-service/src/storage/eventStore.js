'use strict';

const { Pool } = require('pg');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    actor JSONB,
    target JSONB,
    action TEXT NOT NULL,
    details JSONB,
    result VARCHAR(32),
    correlation_id UUID,
    hash VARCHAR(64) NOT NULL,
    source VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events (category);
  CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events (severity);
  CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events (action);
  CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON audit_events (correlation_id);
  CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events USING GIN (actor);
  CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events USING GIN (target);
  CREATE INDEX IF NOT EXISTS idx_audit_events_details ON audit_events USING GIN (details);
  CREATE INDEX IF NOT EXISTS idx_audit_events_result ON audit_events (result);
  CREATE INDEX IF NOT EXISTS idx_audit_events_source ON audit_events (source);
  CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events (created_at DESC);
`;

const FULLTEXT_INDEX_SQL = `
  CREATE INDEX IF NOT EXISTS idx_audit_events_fulltext
  ON audit_events USING GIN (
    to_tsvector('english', COALESCE(action, '') || ' ' || COALESCE(details::text, ''))
  );
`;

class EventStore {
  constructor({ logger }) {
    this.logger = logger;
    this.lastHash = null;
    this.pool = new Pool({
      host: process.env.PG_HOST || 'localhost',
      port: parseInt(process.env.PG_PORT, 10) || 5432,
      database: process.env.PG_DATABASE || 'audit_service',
      user: process.env.PG_USER || 'postgres',
      password: process.env.PG_PASSWORD || 'postgres',
      max: parseInt(process.env.PG_POOL_MAX, 10) || 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });

    this.pool.on('error', (err) => {
      this.logger.error('Unexpected PostgreSQL pool error', { error: err.message });
    });
  }

  async initialize() {
    const client = await this.pool.connect();
    try {
      await client.query(CREATE_TABLE_SQL);
      await client.query(FULLTEXT_INDEX_SQL);
      this.logger.info('Audit events table and indexes created');

      // Load last hash for chain continuity
      const result = await client.query(
        'SELECT hash FROM audit_events ORDER BY created_at DESC LIMIT 1'
      );
      if (result.rows.length > 0) {
        this.lastHash = result.rows[0].hash;
        this.logger.info('Resumed hash chain', { lastHash: this.lastHash });
      } else {
        this.lastHash = '0'.repeat(64);
        this.logger.info('Starting new hash chain');
      }
    } finally {
      client.release();
    }
  }

  _computeHash(previousHash, event) {
    const payload = previousHash + JSON.stringify({
      id: event.id,
      timestamp: event.timestamp,
      category: event.category,
      severity: event.severity,
      actor: event.actor,
      target: event.target,
      action: event.action,
      details: event.details,
      result: event.result,
      correlation_id: event.correlation_id,
      source: event.source
    });
    return crypto.createHash('sha256').update(payload).digest('hex');
  }

  async storeEvent(event) {
    const id = event.id || uuidv4();
    const hash = this._computeHash(this.lastHash, event);

    const query = `
      INSERT INTO audit_events
        (id, timestamp, category, severity, actor, target, action, details, result, correlation_id, hash, source)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `;

    const values = [
      id,
      event.timestamp || new Date().toISOString(),
      event.category || 'system',
      event.severity || 'low',
      JSON.stringify(event.actor || {}),
      JSON.stringify(event.target || {}),
      event.action,
      JSON.stringify(event.details || {}),
      event.result || 'success',
      event.correlation_id || null,
      hash,
      event.source || 'unknown'
    ];

    const result = await this.pool.query(query, values);
    this.lastHash = hash;

    return result.rows[0];
  }

  async getEvents(filters = {}, pagination = {}) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (filters.category) {
      conditions.push(`category = $${paramIndex++}`);
      params.push(filters.category);
    }
    if (filters.severity) {
      conditions.push(`severity = $${paramIndex++}`);
      params.push(filters.severity);
    }
    if (filters.action) {
      conditions.push(`action LIKE $${paramIndex++}`);
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
    if (filters.actorId) {
      conditions.push(`actor->>'id' = $${paramIndex++}`);
      params.push(filters.actorId);
    }
    if (filters.targetId) {
      conditions.push(`target->>'id' = $${paramIndex++}`);
      params.push(filters.targetId);
    }
    if (filters.startTime) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(filters.startTime);
    }
    if (filters.endTime) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(filters.endTime);
    }
    if (filters.correlationId) {
      conditions.push(`correlation_id = $${paramIndex++}`);
      params.push(filters.correlationId);
    }

    // Cursor-based pagination
    if (pagination.cursor) {
      conditions.push(`created_at < $${paramIndex++}`);
      params.push(pagination.cursor);
    }

    const whereClause = conditions.length > 0
      ? 'WHERE ' + conditions.join(' AND ')
      : '';

    const sortField = filters.sortBy === 'severity' ? 'severity' : 'timestamp';
    const sortDir = filters.sortDir === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(parseInt(pagination.limit, 10) || 50, 500);

    const countQuery = `SELECT COUNT(*) as total FROM audit_events ${whereClause}`;
    const dataQuery = `
      SELECT * FROM audit_events
      ${whereClause}
      ORDER BY ${sortField} ${sortDir}, created_at DESC
      LIMIT $${paramIndex}
    `;
    params.push(limit);

    const [countResult, dataResult] = await Promise.all([
      this.pool.query(countQuery, params.slice(0, -1)),
      this.pool.query(dataQuery, params)
    ]);

    const events = dataResult.rows;
    const nextCursor = events.length === limit
      ? events[events.length - 1].created_at.toISOString()
      : null;

    return {
      events,
      total: parseInt(countResult.rows[0].total, 10),
      limit,
      cursor: nextCursor
    };
  }

  async getEventById(id) {
    const result = await this.pool.query(
      'SELECT * FROM audit_events WHERE id = $1',
      [id]
    );
    return result.rows[0] || null;
  }

  async verifyIntegrity(startId, endId) {
    const query = `
      SELECT id, timestamp, category, severity, actor, target, action,
             details, result, correlation_id, hash, source, created_at
      FROM audit_events
      WHERE created_at >= (SELECT created_at FROM audit_events WHERE id = $1)
        AND created_at <= (SELECT created_at FROM audit_events WHERE id = $2)
      ORDER BY created_at ASC
    `;
    const result = await this.pool.query(query, [startId, endId]);
    const events = result.rows;

    if (events.length === 0) {
      return { valid: true, checked: 0, errors: [] };
    }

    // Get hash of event just before the range
    const prevResult = await this.pool.query(
      `SELECT hash FROM audit_events
       WHERE created_at < $1
       ORDER BY created_at DESC LIMIT 1`,
      [events[0].created_at]
    );
    let previousHash = prevResult.rows.length > 0
      ? prevResult.rows[0].hash
      : '0'.repeat(64);

    const errors = [];
    for (const event of events) {
      const expectedHash = this._computeHash(previousHash, event);
      if (expectedHash !== event.hash) {
        errors.push({
          eventId: event.id,
          timestamp: event.timestamp,
          expected: expectedHash,
          actual: event.hash
        });
      }
      previousHash = event.hash;
    }

    return {
      valid: errors.length === 0,
      checked: events.length,
      errors
    };
  }

  async getStats(filters = {}) {
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

    const queries = [
      `SELECT category, COUNT(*) as count FROM audit_events ${whereClause} GROUP BY category ORDER BY count DESC`,
      `SELECT severity, COUNT(*) as count FROM audit_events ${whereClause} GROUP BY severity ORDER BY count DESC`,
      `SELECT actor->>'id' as actor_id, actor->>'name' as actor_name, COUNT(*) as count
       FROM audit_events ${whereClause} GROUP BY actor->>'id', actor->>'name' ORDER BY count DESC LIMIT 20`,
      `SELECT COUNT(*) as total FROM audit_events ${whereClause}`
    ];

    const [byCategory, bySeverity, byActor, totalResult] = await Promise.all(
      queries.map(q => this.pool.query(q, params))
    );

    return {
      total: parseInt(totalResult.rows[0].total, 10),
      byCategory: byCategory.rows,
      bySeverity: bySeverity.rows,
      topActors: byActor.rows
    };
  }

  async shutdown() {
    await this.pool.end();
    this.logger.info('EventStore PostgreSQL pool closed');
  }
}

module.exports = EventStore;
