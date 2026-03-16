'use strict';

const logger = require('../utils/logger');

class Correlator {
  constructor(db) {
    this.db = db;
  }

  async getCorrelatedEvents(correlationId) {
    if (!correlationId || typeof correlationId !== 'string') {
      throw new Error('Valid correlationId is required');
    }

    const result = await this.db.query(
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
      actor_id: event.actor_id,
      actor_name: event.actor_name,
      target_id: event.target_id,
      target_name: event.target_name,
      result: event.result,
      timeSincePrevious: index > 0
        ? new Date(event.timestamp) - new Date(events[index - 1].timestamp)
        : 0,
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
      timeline,
    };
  }

  async findRelatedEvents(eventId, timeWindowMinutes = 5) {
    if (!eventId || typeof eventId !== 'string') {
      throw new Error('Valid eventId is required');
    }

    // Get the source event
    const sourceResult = await this.db.query(
      'SELECT * FROM audit_events WHERE id = $1',
      [eventId]
    );

    if (sourceResult.rows.length === 0) {
      throw new Error(`Event not found: ${eventId}`);
    }

    const sourceEvent = sourceResult.rows[0];
    const related = [];

    // Find by correlation_id
    if (sourceEvent.correlation_id) {
      const corrResult = await this.db.query(
        'SELECT * FROM audit_events WHERE correlation_id = $1 AND id != $2 ORDER BY timestamp ASC',
        [sourceEvent.correlation_id, eventId]
      );
      for (const row of corrResult.rows) {
        related.push({ ...row, _relation: 'correlation_id' });
      }
    }

    // Find by same actor within time window
    if (sourceEvent.actor_id) {
      const actorResult = await this.db.query(
        `SELECT * FROM audit_events
         WHERE actor_id = $1 AND id != $2
         AND timestamp BETWEEN $3::timestamptz - interval '${timeWindowMinutes} minutes'
         AND $3::timestamptz + interval '${timeWindowMinutes} minutes'
         ORDER BY timestamp ASC
         LIMIT 20`,
        [sourceEvent.actor_id, eventId, sourceEvent.timestamp]
      );
      for (const row of actorResult.rows) {
        if (!related.find((r) => r.id === row.id)) {
          related.push({ ...row, _relation: 'same_actor' });
        }
      }
    }

    // Find by same target within time window
    if (sourceEvent.target_id) {
      const targetResult = await this.db.query(
        `SELECT * FROM audit_events
         WHERE target_id = $1 AND id != $2
         AND timestamp BETWEEN $3::timestamptz - interval '${timeWindowMinutes} minutes'
         AND $3::timestamptz + interval '${timeWindowMinutes} minutes'
         ORDER BY timestamp ASC
         LIMIT 20`,
        [sourceEvent.target_id, eventId, sourceEvent.timestamp]
      );
      for (const row of targetResult.rows) {
        if (!related.find((r) => r.id === row.id)) {
          related.push({ ...row, _relation: 'same_target' });
        }
      }
    }

    return {
      sourceEvent,
      timeWindowMinutes,
      relatedEvents: related,
      relatedCount: related.length,
    };
  }
}

module.exports = Correlator;
