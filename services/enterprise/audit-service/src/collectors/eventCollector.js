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
  // AD / directory events (publisher: enterprise-directory)
  'directory.#',
  // Kerberos events (publisher: kerberos-kdc)
  'kerberos.#',
  // Trust, LAPS, and domain events (publisher: samba-ad-dc)
  'ad.#',
];

/**
 * Derive the appropriate severity for a routing key when the event payload
 * does not already carry a severity field.
 *
 * Severity ladder: info < warning < error < critical
 */
function _deriveSeverity(routingKey) {
  if (routingKey.startsWith('security.breakglass.')) return 'critical';
  if (routingKey.startsWith('security.elevation.')) return 'warning';
  if (routingKey === 'directory.object.deleted') return 'warning';
  if (routingKey === 'ad.replication.failed') return 'error';
  if (routingKey.startsWith('ad.trust.')) return 'warning';
  if (routingKey === 'ad.laps.password.retrieved') return 'warning';
  if (routingKey === 'ad.bitlocker.key.retrieved') return 'warning';
  return 'info';
}

class EventCollector {
  constructor(db, bus, integrityChecker, eventStore, alertEngine, wsClients, metrics, publishFn) {
    this.db = db;
    this._bus = bus;
    this.integrityChecker = integrityChecker;
    this.publishFn = publishFn || null;
    this.eventStore = eventStore;
    this.alertEngine = alertEngine;
    this.wsClients = wsClients;
    this.metrics = metrics;
    this.queueName = 'audit-service-events';
  }

  async start() {
    try {
      await this._bus.subscribe(this.queueName, ROUTING_KEYS, async (payload, meta) => {
        try {
          await this._processMessagePayload(payload, meta.routingKey || meta.routing_key || '');
          if (meta.ack) await meta.ack();
        } catch (err) {
          logger.error('Failed to process audit event message', {
            error: err.message,
            routingKey: meta.routingKey || '',
          });
          if (meta.nack) await meta.nack(false);
        }
      });
      logger.info('Event collector started', { queue: this.queueName, routingKeys: ROUTING_KEYS });
    } catch (err) {
      logger.error('Failed to start event collector', { error: err.message });
      throw err;
    }
  }

  async _processMessagePayload(payload, routingKey) {
    let event = typeof payload === 'string' ? JSON.parse(payload) : payload;

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

    // Derive severity from routing key when not supplied by the publisher
    if (!event.severity) {
      event.severity = _deriveSeverity(routingKey);
    }

    // Attach routing_key for traceability
    event.routing_key = routingKey;

    // Store event with hash chain
    const storedEvent = await this.eventStore.store(event);

    // Publish audit.event.logged to generic event bus
    if (this.publishFn) {
      this.publishFn('audit.event.logged', {
        id: storedEvent.id,
        category: storedEvent.category,
        severity: storedEvent.severity,
        action: storedEvent.action,
        actor_id: storedEvent.actor_id,
        target_id: storedEvent.target_id,
        result: storedEvent.result,
        timestamp: storedEvent.timestamp,
      });
    }

    // Escalate critical and error events via notification bus
    const severity = storedEvent.severity || event.severity;
    if (this.publishFn && (severity === 'critical' || severity === 'error')) {
      try {
        this.publishFn('notification.alert.critical', {
          alertType: routingKey,
          severity,
          message: `Critical security event: ${routingKey}`,
          payload: event,
          timestamp: new Date().toISOString(),
        });
        logger.warn('Critical/error event escalated to notification bus', { routingKey, severity });
      } catch (err) {
        logger.error('Failed to publish escalation alert', { error: err.message, routingKey });
      }
    }

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
      severity: storedEvent.severity,
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
