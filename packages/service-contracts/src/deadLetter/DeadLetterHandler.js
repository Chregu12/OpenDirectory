'use strict';

/**
 * DeadLetterHandler — consumes messages from the DLX (dead-letter exchange).
 *
 * Messages land in the DLX after 2 failed delivery attempts (NACK + !requeue).
 * This handler:
 *   - Logs the failed message with full context
 *   - Publishes an admin alert
 *   - Optionally stores in a dead_letter_log table for manual inspection
 */
class DeadLetterHandler {
  constructor(messageBus, { db, logger } = {}) {
    this._bus = messageBus;
    this._db = db;
    this._log = logger || console;
  }

  async start() {
    if (!this._bus) return;

    const trySubscribe = async () => {
      if (!this._bus.isConnected()) {
        setTimeout(trySubscribe, 5000);
        return;
      }
      try {
        // DLX queue name by convention
        const ch = this._bus._channel;
        if (!ch) { setTimeout(trySubscribe, 3000); return; }

        await ch.assertExchange('opendirectory.dlx', 'fanout', { durable: true });
        await ch.assertQueue('dead.letter.log', {
          durable: true,
          arguments: { 'x-message-ttl': 7 * 24 * 60 * 60 * 1000 }, // 7 days
        });
        await ch.bindQueue('dead.letter.log', 'opendirectory.dlx', '#');
        ch.prefetch(1);

        ch.consume('dead.letter.log', async (msg) => {
          if (!msg) return;
          let payload;
          try { payload = JSON.parse(msg.content.toString()); } catch (_) { payload = {}; }

          const routingKey = msg.fields.routingKey;
          const source = payload._source || 'unknown';
          const deathReason = msg.properties.headers?.['x-death']?.[0]?.reason || 'unknown';

          this._log.error(`[DeadLetterHandler] Dead message: key=${routingKey} source=${source} reason=${deathReason}`);

          // Persist to dead_letter_log table if DB available
          if (this._db) {
            try {
              await this._db.query(
                `INSERT INTO dead_letter_log (routing_key, source, payload, death_reason, received_at)
                 VALUES ($1, $2, $3, $4, NOW())
                 ON CONFLICT DO NOTHING`,
                [routingKey, source, JSON.stringify(payload), deathReason]
              );
            } catch (_) { /* table may not exist — non-fatal */ }
          }

          // Publish admin alert
          if (this._bus.isConnected()) {
            try {
              this._bus.publish('admin.dead.letter', {
                routingKey,
                source,
                reason: deathReason,
                payloadSummary: JSON.stringify(payload).substring(0, 200),
                _source: 'dead-letter-handler',
              });
            } catch (_) {}
          }

          ch.ack(msg);
        });

        this._log.info('[DeadLetterHandler] listening on dead.letter.log queue');
      } catch (e) {
        this._log.warn(`[DeadLetterHandler] setup error: ${e.message} — retrying in 10s`);
        setTimeout(trySubscribe, 10000);
      }
    };

    setTimeout(trySubscribe, 5000); // Wait for bus to be ready
  }
}

module.exports = DeadLetterHandler;
