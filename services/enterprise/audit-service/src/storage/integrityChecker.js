'use strict';

const crypto = require('crypto');

class IntegrityChecker {
  constructor({ logger, pool }) {
    this.logger = logger;
    this.pool = pool;
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

  async verifyChain(fromTimestamp, toTimestamp) {
    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (fromTimestamp) {
      conditions.push(`timestamp >= $${paramIndex++}`);
      params.push(fromTimestamp);
    }
    if (toTimestamp) {
      conditions.push(`timestamp <= $${paramIndex++}`);
      params.push(toTimestamp);
    }

    const whereClause = conditions.length > 0
      ? 'WHERE ' + conditions.join(' AND ')
      : '';

    // Fetch events ordered by creation for chain verification
    const result = await this.pool.query(
      `SELECT * FROM audit_events ${whereClause} ORDER BY created_at ASC`,
      params
    );
    const events = result.rows;

    if (events.length === 0) {
      return {
        valid: true,
        checked: 0,
        from: fromTimestamp,
        to: toTimestamp,
        brokenLinks: []
      };
    }

    // Get the hash prior to the first event in range
    let previousHash;
    const prevResult = await this.pool.query(
      `SELECT hash FROM audit_events
       WHERE created_at < $1
       ORDER BY created_at DESC LIMIT 1`,
      [events[0].created_at]
    );
    previousHash = prevResult.rows.length > 0
      ? prevResult.rows[0].hash
      : '0'.repeat(64);

    const brokenLinks = [];
    let verified = 0;

    for (const event of events) {
      const expectedHash = this._computeHash(previousHash, event);
      if (expectedHash !== event.hash) {
        brokenLinks.push({
          eventId: event.id,
          timestamp: event.timestamp,
          action: event.action,
          expectedHash,
          actualHash: event.hash,
          position: verified
        });
      }
      previousHash = event.hash;
      verified++;
    }

    return {
      valid: brokenLinks.length === 0,
      checked: verified,
      from: fromTimestamp || events[0].timestamp,
      to: toTimestamp || events[events.length - 1].timestamp,
      brokenLinks
    };
  }

  async detectTampering() {
    this.logger.info('Starting full chain tampering scan');

    const batchSize = 5000;
    let offset = 0;
    let previousHash = '0'.repeat(64);
    let totalChecked = 0;
    const brokenLinks = [];

    while (true) {
      const result = await this.pool.query(
        `SELECT * FROM audit_events ORDER BY created_at ASC LIMIT $1 OFFSET $2`,
        [batchSize, offset]
      );

      if (result.rows.length === 0) break;

      for (const event of result.rows) {
        const expectedHash = this._computeHash(previousHash, event);
        if (expectedHash !== event.hash) {
          brokenLinks.push({
            eventId: event.id,
            timestamp: event.timestamp,
            action: event.action,
            position: totalChecked
          });
        }
        previousHash = event.hash;
        totalChecked++;
      }

      offset += batchSize;

      if (result.rows.length < batchSize) break;
    }

    const tampered = brokenLinks.length > 0;
    this.logger.info('Tampering scan complete', {
      totalChecked,
      tampered,
      brokenLinks: brokenLinks.length
    });

    return {
      tampered,
      totalChecked,
      brokenLinks,
      scannedAt: new Date().toISOString()
    };
  }

  async getChainStatus() {
    const totalResult = await this.pool.query(
      'SELECT COUNT(*) as total FROM audit_events'
    );
    const total = parseInt(totalResult.rows[0].total, 10);

    const firstResult = await this.pool.query(
      'SELECT id, timestamp, hash FROM audit_events ORDER BY created_at ASC LIMIT 1'
    );
    const lastResult = await this.pool.query(
      'SELECT id, timestamp, hash FROM audit_events ORDER BY created_at DESC LIMIT 1'
    );

    const first = firstResult.rows[0] || null;
    const last = lastResult.rows[0] || null;

    // Spot-check: verify last 100 events
    let spotCheckValid = true;
    if (total > 0) {
      const sampleResult = await this.pool.query(
        'SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 101'
      );
      const sampleEvents = sampleResult.rows.reverse();

      if (sampleEvents.length > 1) {
        // Get hash before the sample
        let prevHash;
        const beforeResult = await this.pool.query(
          `SELECT hash FROM audit_events
           WHERE created_at < $1
           ORDER BY created_at DESC LIMIT 1`,
          [sampleEvents[0].created_at]
        );
        prevHash = beforeResult.rows.length > 0
          ? beforeResult.rows[0].hash
          : '0'.repeat(64);

        for (const event of sampleEvents) {
          const expected = this._computeHash(prevHash, event);
          if (expected !== event.hash) {
            spotCheckValid = false;
            break;
          }
          prevHash = event.hash;
        }
      }
    }

    return {
      totalEvents: total,
      chainStart: first ? { id: first.id, timestamp: first.timestamp, hash: first.hash } : null,
      chainEnd: last ? { id: last.id, timestamp: last.timestamp, hash: last.hash } : null,
      spotCheckValid,
      spotCheckSize: Math.min(total, 100),
      checkedAt: new Date().toISOString()
    };
  }
}

module.exports = IntegrityChecker;
