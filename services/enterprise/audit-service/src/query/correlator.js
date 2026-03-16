'use strict';

class Correlator {
  constructor({ logger, pool }) {
    this.logger = logger;
    this.pool = pool;
  }

  async getCorrelatedEvents(correlationId) {
    if (!correlationId) {
      throw new Error('correlationId is required');
    }

    const result = await this.pool.query(
      `SELECT * FROM audit_events
       WHERE correlation_id = $1
       ORDER BY timestamp ASC`,
      [correlationId]
    );

    const events = result.rows;
    if (events.length === 0) {
      return { correlationId, events: [], timeline: [] };
    }

    const timeline = events.map((event, index) => ({
      sequence: index + 1,
      id: event.id,
      timestamp: event.timestamp,
      action: event.action,
      category: event.category,
      severity: event.severity,
      actor: event.actor,
      target: event.target,
      result: event.result,
      timeSincePrevious: index > 0
        ? new Date(event.timestamp) - new Date(events[index - 1].timestamp)
        : 0
    }));

    const duration = events.length > 1
      ? new Date(events[events.length - 1].timestamp) - new Date(events[0].timestamp)
      : 0;

    return {
      correlationId,
      eventCount: events.length,
      startTime: events[0].timestamp,
      endTime: events[events.length - 1].timestamp,
      durationMs: duration,
      categories: [...new Set(events.map(e => e.category))],
      severities: [...new Set(events.map(e => e.severity))],
      events,
      timeline
    };
  }

  async findRelatedEvents(eventId, timeWindowMinutes = 5) {
    if (!eventId) {
      throw new Error('eventId is required');
    }

    // Get the source event
    const sourceResult = await this.pool.query(
      'SELECT * FROM audit_events WHERE id = $1',
      [eventId]
    );

    if (sourceResult.rows.length === 0) {
      throw new Error(`Event not found: ${eventId}`);
    }

    const sourceEvent = sourceResult.rows[0];
    const windowMs = timeWindowMinutes * 60 * 1000;
    const startTime = new Date(new Date(sourceEvent.timestamp).getTime() - windowMs);
    const endTime = new Date(new Date(sourceEvent.timestamp).getTime() + windowMs);

    // Find related events within the time window that share attributes
    const conditions = [
      'id != $1',
      'timestamp BETWEEN $2 AND $3'
    ];
    const params = [eventId, startTime.toISOString(), endTime.toISOString()];
    let paramIndex = 4;

    // Build OR conditions for related attributes
    const relatedConditions = [];

    // Same correlation ID
    if (sourceEvent.correlation_id) {
      relatedConditions.push(`correlation_id = $${paramIndex++}`);
      params.push(sourceEvent.correlation_id);
    }

    // Same actor
    if (sourceEvent.actor && sourceEvent.actor.id) {
      relatedConditions.push(`actor->>'id' = $${paramIndex++}`);
      params.push(sourceEvent.actor.id);
    }

    // Same target
    if (sourceEvent.target && sourceEvent.target.id) {
      relatedConditions.push(`target->>'id' = $${paramIndex++}`);
      params.push(sourceEvent.target.id);
    }

    // Same source
    if (sourceEvent.source) {
      relatedConditions.push(`source = $${paramIndex++}`);
      params.push(sourceEvent.source);
    }

    if (relatedConditions.length > 0) {
      conditions.push('(' + relatedConditions.join(' OR ') + ')');
    }

    const result = await this.pool.query(
      `SELECT * FROM audit_events
       WHERE ${conditions.join(' AND ')}
       ORDER BY timestamp ASC
       LIMIT 100`,
      params
    );

    return {
      sourceEvent,
      timeWindowMinutes,
      relatedEvents: result.rows,
      relatedCount: result.rows.length
    };
  }
}

module.exports = Correlator;
