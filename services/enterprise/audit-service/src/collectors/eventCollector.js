'use strict';

const amqplib = require('amqplib');
const { v4: uuidv4 } = require('uuid');

const EXCHANGE_NAME = 'opendirectory.events';
const QUEUE_NAME = 'audit-service-events';
const ROUTING_KEY = '#';

const EVENT_CATEGORIES = [
  'identity', 'device', 'policy', 'app',
  'security', 'admin', 'system'
];

class EventCollector {
  constructor({ logger, eventStore, onEvent }) {
    this.logger = logger;
    this.eventStore = eventStore;
    this.onEvent = onEvent;
    this.connection = null;
    this.channel = null;
    this.connected = false;
    this.reconnectTimer = null;
    this.reconnectDelay = 5000;
    this.maxReconnectDelay = 60000;
    this.rabbitmqUrl = process.env.RABBITMQ_URL || 'amqp://localhost:5672';
  }

  async connect() {
    try {
      this.connection = await amqplib.connect(this.rabbitmqUrl);
      this.channel = await this.connection.createChannel();

      await this.channel.assertExchange(EXCHANGE_NAME, 'topic', {
        durable: true,
        autoDelete: false
      });

      await this.channel.assertQueue(QUEUE_NAME, {
        durable: true,
        arguments: {
          'x-message-ttl': 86400000,       // 24h TTL
          'x-max-length': 1000000,          // max 1M messages
          'x-queue-type': 'classic'
        }
      });

      await this.channel.bindQueue(QUEUE_NAME, EXCHANGE_NAME, ROUTING_KEY);

      await this.channel.prefetch(100);

      this.channel.consume(QUEUE_NAME, async (msg) => {
        if (!msg) return;
        try {
          await this._processMessage(msg);
          this.channel.ack(msg);
        } catch (err) {
          this.logger.error('Failed to process audit event', {
            error: err.message,
            routingKey: msg.fields.routingKey
          });
          // Reject and requeue once, then discard
          const redelivered = msg.fields.redelivered;
          this.channel.nack(msg, false, !redelivered);
        }
      });

      this.connection.on('close', () => {
        this.connected = false;
        this.logger.warn('RabbitMQ connection closed, scheduling reconnect');
        this._scheduleReconnect();
      });

      this.connection.on('error', (err) => {
        this.logger.error('RabbitMQ connection error', { error: err.message });
      });

      this.connected = true;
      this.reconnectDelay = 5000;
      this.logger.info('EventCollector connected to RabbitMQ', {
        exchange: EXCHANGE_NAME,
        queue: QUEUE_NAME,
        routingKey: ROUTING_KEY
      });
    } catch (err) {
      this.logger.error('Failed to connect to RabbitMQ', { error: err.message });
      this._scheduleReconnect();
    }
  }

  async _processMessage(msg) {
    const routingKey = msg.fields.routingKey;
    const content = JSON.parse(msg.content.toString());

    const category = this._extractCategory(routingKey);
    const severity = this._determineSeverity(routingKey, content);

    const auditEvent = {
      id: content.id || uuidv4(),
      timestamp: content.timestamp || new Date().toISOString(),
      category,
      severity,
      actor: this._extractActor(content),
      target: this._extractTarget(content),
      action: routingKey,
      details: content.data || content.details || content,
      result: content.result || 'success',
      correlation_id: content.correlationId || content.correlation_id || null,
      source: content.source || this._extractSource(routingKey)
    };

    await this.eventStore.storeEvent(auditEvent);

    if (typeof this.onEvent === 'function') {
      this.onEvent(auditEvent);
    }

    this.logger.debug('Audit event stored', {
      id: auditEvent.id,
      action: auditEvent.action,
      category: auditEvent.category,
      severity: auditEvent.severity
    });
  }

  _extractCategory(routingKey) {
    const parts = routingKey.split('.');
    const prefix = parts[0];
    if (EVENT_CATEGORIES.includes(prefix)) {
      return prefix;
    }
    return 'system';
  }

  _determineSeverity(routingKey, content) {
    if (content.severity) return content.severity;

    const key = routingKey.toLowerCase();

    if (key.includes('security.breach') || key.includes('security.intrusion')) {
      return 'critical';
    }
    if (key.includes('security.') || key.includes('policy.violation') || key.includes('admin.delete')) {
      return 'high';
    }
    if (key.includes('admin.') || key.includes('policy.') || key.includes('identity.delete')) {
      return 'medium';
    }
    if (key.includes('.error') || key.includes('.failed')) {
      return 'medium';
    }
    return 'low';
  }

  _extractActor(content) {
    if (content.actor) return content.actor;
    return {
      id: content.userId || content.actorId || null,
      type: content.actorType || 'user',
      name: content.userName || content.actorName || null,
      ip: content.ip || content.sourceIp || null
    };
  }

  _extractTarget(content) {
    if (content.target) return content.target;
    return {
      id: content.targetId || content.resourceId || null,
      type: content.targetType || content.resourceType || null,
      name: content.targetName || content.resourceName || null
    };
  }

  _extractSource(routingKey) {
    const parts = routingKey.split('.');
    if (parts.length >= 2) {
      return `${parts[0]}-service`;
    }
    return 'unknown';
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      this.logger.info('Attempting RabbitMQ reconnection', { delay: this.reconnectDelay });
      await this.connect();
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay);
    }, this.reconnectDelay);
  }

  async disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    try {
      if (this.channel) await this.channel.close();
      if (this.connection) await this.connection.close();
    } catch (err) {
      this.logger.error('Error closing RabbitMQ connection', { error: err.message });
    }
    this.connected = false;
    this.logger.info('EventCollector disconnected');
  }

  isConnected() {
    return this.connected;
  }
}

module.exports = EventCollector;
