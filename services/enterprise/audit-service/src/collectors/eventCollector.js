'use strict';

const logger = require('../utils/logger');

const ROUTING_KEYS = [
  'policy.#',
  'device.#',
  'identity.#',
  'app.#',
  'security.#',
  'compliance.#',
  'admin.#',
  'system.#',
];

class EventCollector {
  constructor(db, channel, integrityChecker, eventStore, alertEngine, wsClients, metrics) {
    this.db = db;
    this.channel = channel;
    this.integrityChecker = integrityChecker;
    this.eventStore = eventStore;
    this.alertEngine = alertEngine;
    this.wsClients = wsClients;
    this.metrics = metrics;
    this.queueName = 'audit-service-events';
    this.exchangeName = 'opendirectory.events';
  }

  async start() {
    try {
      await this.channel.assertExchange(this.exchangeName, 'topic', { durable: true });
      await this.channel.assertQueue(this.queueName, {
        durable: true,
        arguments: {
          'x-message-ttl': 86400000, // 24 hours
          'x-max-length': 100000,
        },
      });

      for (const key of ROUTING_KEYS) {
        await this.channel.bindQueue(this.queueName, this.exchangeName, key);
        logger.info('Bound queue to routing key', { queue: this.queueName, routingKey: key });
      }

      this.channel.prefetch(10);

      this.channel.consume(this.queueName, async (msg) => {
        if (!msg) return;

        try {
          await this._processMessage(msg);
          this.channel.ack(msg);
        } catch (err) {
          logger.error('Failed to process audit event message', {
            error: err.message,
            routingKey: msg.fields.routingKey,
          });
          // Requeue on first failure, dead-letter on subsequent
          this.channel.nack(msg, false, !msg.fields.redelivered);
        }
      });

      logger.info('Event collector started', { queue: this.queueName, routingKeys: ROUTING_KEYS });
    } catch (err) {
      logger.error('Failed to start event collector', { error: err.message });
      throw err;
    }
  }

  async _processMessage(msg) {
    const routingKey = msg.fields.routingKey;
    let event;

    try {
      event = JSON.parse(msg.content.toString());
    } catch (err) {
      logger.error('Invalid JSON in audit event message', { routingKey, error: err.message });
      return;
    }

    // Derive category from routing key if not present
    if (!event.category) {
      event.category = routingKey.split('.')[0];
    }
    if (!event.action) {
      event.action = routingKey;
    }
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString();
    }

    // Store event with hash chain
    const storedEvent = await this.eventStore.store(event);

    // Check alert rules
    if (this.alertEngine) {
      try {
        await this.alertEngine.evaluate(storedEvent);
      } catch (err) {
        logger.error('Alert evaluation failed', { error: err.message, eventId: storedEvent.id });
      }
    }

    // Broadcast to WebSocket clients
    this._broadcastToWebSocket(storedEvent);

    // Update Prometheus metrics
    this._updateMetrics(storedEvent);

    logger.debug('Audit event processed', {
      id: storedEvent.id,
      category: storedEvent.category,
      action: storedEvent.action,
    });
  }

  _broadcastToWebSocket(event) {
    if (!this.wsClients || this.wsClients.size === 0) return;

    const payload = JSON.stringify({
      type: 'audit_event',
      data: {
        id: event.id,
        timestamp: event.timestamp,
        category: event.category,
        severity: event.severity,
        action: event.action,
        actor_name: event.actor_name,
        target_name: event.target_name,
        result: event.result,
      },
    });

    let sent = 0;
    for (const client of this.wsClients) {
      if (client.readyState === 1) { // WebSocket.OPEN
        try {
          client.send(payload);
          sent++;
        } catch (err) {
          logger.debug('Failed to send to WebSocket client', { error: err.message });
        }
      }
    }

    if (sent > 0) {
      logger.debug('Broadcast audit event to WebSocket clients', { eventId: event.id, clients: sent });
    }
  }

  _updateMetrics(event) {
    if (!this.metrics) return;

    try {
      this.metrics.eventsProcessed.inc({
        category: event.category,
        severity: event.severity,
        result: event.result,
      });
    } catch (err) {
      logger.debug('Failed to update metrics', { error: err.message });
    }
  }
}

module.exports = EventCollector;
