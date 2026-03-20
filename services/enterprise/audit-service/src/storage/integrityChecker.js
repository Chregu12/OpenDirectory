'use strict';

const crypto = require('crypto');
const logger = require('../utils/logger');

class IntegrityChecker {
  constructor(db) {
    this.db = db;
    this.lastHash = null;
  }

  async initialize() {
    try {
      const result = await this.db.query(
        'SELECT hash FROM audit_events ORDER BY timestamp DESC LIMIT 1'
      );
      this.lastHash = result.rows[0]?.hash || '0'.repeat(64);
      logger.info('Integrity checker initialized', {
        lastHash: this.lastHash.substring(0, 16) + '...',
      });
    } catch (err) {
      logger.warn('Could not load last hash, starting fresh chain', {
        error: err.message,
      });
      this.lastHash = '0'.repeat(64);
    }
  }

  calculateHash(event) {
    const payload = JSON.stringify({
      timestamp: event.timestamp,
      category: event.category,
      actor_id: event.actor_id,
      target_id: event.target_id,
      action: event.action,
      details: event.details,
      previous_hash: this.lastHash,
    });

    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    event.hash = hash;
    event.previous_hash = this.lastHash;
    this.lastHash = hash;
    return event;
  }

  async verifyChain(startTime, endTime) {
    const query = `
      SELECT id, timestamp, category, actor_id, target_id, action, details, hash, previous_hash
      FROM audit_events
      WHERE timestamp >= $1 AND timestamp <= $2
      ORDER BY timestamp ASC
    `;

    const result = await this.db.query(query, [startTime, endTime]);
    const events = result.rows;

    if (events.length === 0) {
      return { valid: true, brokenAt: null, eventsChecked: 0 };
    }

    let previousHash = events[0].previous_hash;
    let eventsChecked = 0;

    for (const event of events) {
      eventsChecked++;

      if (event.previous_hash !== previousHash) {
        logger.error('Hash chain broken: previous_hash mismatch', {
          eventId: event.id,
          timestamp: event.timestamp,
          expected: previousHash,
          actual: event.previous_hash,
        });
        return {
          valid: false,
          brokenAt: event.timestamp,
          brokenEventId: event.id,
          eventsChecked,
        };
      }

      const payload = JSON.stringify({
        timestamp: event.timestamp.toISOString(),
        category: event.category,
        actor_id: event.actor_id,
        target_id: event.target_id,
        action: event.action,
        details: event.details,
        previous_hash: event.previous_hash,
      });

      const computedHash = crypto.createHash('sha256').update(payload).digest('hex');

      if (computedHash !== event.hash) {
        logger.error('Hash chain broken: computed hash mismatch', {
          eventId: event.id,
          timestamp: event.timestamp,
          expected: event.hash,
          computed: computedHash,
        });
        return {
          valid: false,
          brokenAt: event.timestamp,
          brokenEventId: event.id,
          eventsChecked,
          reason: 'hash_mismatch',
        };
      }

      previousHash = event.hash;
    }

    logger.info('Hash chain verified successfully', { eventsChecked });
    return { valid: true, brokenAt: null, eventsChecked };
  }
}

module.exports = IntegrityChecker;
