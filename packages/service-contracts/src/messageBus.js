'use strict';

/**
 * Shared RabbitMQ MessageBus for OpenDirectory microservices.
 *
 * Topology:
 *   Exchange: opendirectory.events (topic, durable) — domain events
 *   Exchange: od.device.commands   (direct, durable) — per-device command queues
 *
 * Usage (publisher):
 *   const bus = new MessageBus();
 *   await bus.connect();
 *   await bus.publish('device.enrolled', { deviceId, hostname, platform });
 *
 * Usage (subscriber):
 *   await bus.subscribe('notification.alerts', ['*.failed', 'security.#'], handler);
 *
 * Usage (device command queue):
 *   await bus.queueDeviceCommand(deviceId, commandPayload);
 *   await bus.consumeDeviceCommands(deviceId, handler); // agent-side polling
 */

let amqplib;
try {
  amqplib = require('amqplib');
} catch (_) {
  amqplib = null;
}

const EVENTS_EXCHANGE   = 'opendirectory.events';
const COMMANDS_EXCHANGE = 'od.device.commands';

const MIN_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30000;

/** Minimal logger shim — replaced by the service's own logger when possible. */
const log = {
  info:  (...a) => console.log('[MessageBus]',  ...a),
  warn:  (...a) => console.warn('[MessageBus]',  ...a),
  error: (...a) => console.error('[MessageBus]', ...a),
  debug: (...a) => process.env.NODE_ENV !== 'production' && console.debug('[MessageBus]', ...a),
};

class MessageBus {
  constructor() {
    /** @type {import('amqplib').Connection|null} */
    this._connection  = null;
    /** @type {import('amqplib').Channel|null} */
    this._channel     = null;
    this._url         = null;
    this._connected   = false;
    this._closing     = false;
    this._reconnectTimer = null;
    this._reconnectDelay = MIN_RECONNECT_DELAY_MS;

    /**
     * Subscriptions to re-bind after reconnect.
     * Each entry: { queueName, routingKeys, handler }
     */
    this._subscriptions = [];
  }

  // ── Singleton ──────────────────────────────────────────────────────────────

  static getInstance() {
    if (!MessageBus._instance) {
      MessageBus._instance = new MessageBus();
    }
    return MessageBus._instance;
  }

  // ── Connection ─────────────────────────────────────────────────────────────

  /**
   * Connect to RabbitMQ.  Safe to call multiple times — no-ops if already
   * connected.  Resolves once the channel is ready.
   *
   * @param {string} [url] - amqp:// URL (defaults to RABBITMQ_URL env var or amqp://rabbitmq:5672)
   * @returns {Promise<void>}
   */
  async connect(url) {
    if (this._connected) return;

    if (!amqplib) {
      log.warn('amqplib not installed — MessageBus is a no-op stub.  Install amqplib to enable RabbitMQ.');
      return;
    }

    this._url = url || process.env.RABBITMQ_URL || 'amqp://rabbitmq:5672';
    await this._doConnect();
  }

  async _doConnect() {
    if (this._closing || !amqplib) return;

    try {
      log.info(`Connecting to RabbitMQ at ${this._url} …`);
      const conn = await amqplib.connect(this._url);

      conn.on('error', (err) => {
        log.warn('RabbitMQ connection error', err.message);
        this._handleDisconnect();
      });
      conn.on('close', () => {
        if (!this._closing) {
          log.warn('RabbitMQ connection closed unexpectedly — will reconnect');
          this._handleDisconnect();
        }
      });

      const ch = await conn.createChannel();
      ch.on('error', (err) => {
        log.warn('RabbitMQ channel error', err.message);
      });

      // Assert both exchanges up-front so all services work regardless of order.
      await ch.assertExchange(EVENTS_EXCHANGE,   'topic',  { durable: true });
      await ch.assertExchange(COMMANDS_EXCHANGE, 'direct', { durable: true });

      this._connection = conn;
      this._channel    = ch;
      this._connected  = true;
      this._reconnectDelay = MIN_RECONNECT_DELAY_MS; // reset backoff on success

      log.info('RabbitMQ connected and exchanges asserted.');

      // Re-bind any subscriptions that were registered before / after reconnect.
      for (const sub of this._subscriptions) {
        await this._bindSubscription(sub).catch((err) => {
          log.warn(`Failed to rebind subscription '${sub.queueName}': ${err.message}`);
        });
      }
    } catch (err) {
      log.warn(`RabbitMQ connect failed: ${err.message} — retrying in ${this._reconnectDelay}ms`);
      this._scheduleReconnect();
    }
  }

  _handleDisconnect() {
    this._connected  = false;
    this._connection = null;
    this._channel    = null;
    if (!this._closing) {
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect() {
    if (this._reconnectTimer || this._closing) return;

    this._reconnectTimer = setTimeout(async () => {
      this._reconnectTimer = null;
      // Exponential backoff capped at MAX_RECONNECT_DELAY_MS
      this._reconnectDelay = Math.min(this._reconnectDelay * 2, MAX_RECONNECT_DELAY_MS);
      await this._doConnect();
    }, this._reconnectDelay);
  }

  /**
   * Returns true when a live channel is available.
   */
  isConnected() {
    return this._connected && this._channel !== null;
  }

  // ── Publishing ─────────────────────────────────────────────────────────────

  /**
   * Publish a domain event to the opendirectory.events exchange.
   *
   * @param {string} routingKey  e.g. 'device.enrolled'
   * @param {object} payload     Plain JS object — will be JSON-serialised
   * @param {object} [options]   Extra amqplib publish options
   * @returns {boolean}          true if published, false if not connected
   */
  publish(routingKey, payload, options) {
    if (!this.isConnected()) {
      log.warn(`MessageBus.publish: not connected, dropping event '${routingKey}'`);
      return false;
    }

    try {
      const content = Buffer.from(JSON.stringify({
        ...payload,
        _meta: { routingKey, ts: new Date().toISOString() },
      }));
      this._channel.publish(EVENTS_EXCHANGE, routingKey, content, {
        persistent:  true,
        contentType: 'application/json',
        ...options,
      });
      log.debug(`Published '${routingKey}'`);
      return true;
    } catch (err) {
      log.warn(`MessageBus.publish error for '${routingKey}': ${err.message}`);
      return false;
    }
  }

  // ── Subscribing ────────────────────────────────────────────────────────────

  /**
   * Assert a durable queue, bind it to one or more routing-key patterns on the
   * opendirectory.events exchange, and start consuming.
   *
   * Dead-lettering: messages that fail on the second delivery are nack'd with
   * requeue=false so they land in the DLX (if configured on the broker).
   *
   * @param {string}   queueName   Durable queue name
   * @param {string[]} routingKeys Array of topic patterns
   * @param {Function} handler     async (parsedPayload, rawMsg) => void
   * @returns {Promise<void>}
   */
  async subscribe(queueName, routingKeys, handler) {
    const sub = { queueName, routingKeys, handler };

    // Remember so we can re-bind after reconnect.
    if (!this._subscriptions.find(s => s.queueName === queueName)) {
      this._subscriptions.push(sub);
    }

    if (!this.isConnected()) {
      log.warn(`MessageBus.subscribe: not connected — '${queueName}' will be bound on next connect`);
      return;
    }

    await this._bindSubscription(sub);
  }

  async _bindSubscription({ queueName, routingKeys, handler }) {
    const ch = this._channel;

    await ch.assertQueue(queueName, {
      durable: true,
      arguments: {
        'x-message-ttl':  86400000, // 24 h
        'x-max-length':   100000,
      },
    });

    for (const key of routingKeys) {
      await ch.bindQueue(queueName, EVENTS_EXCHANGE, key);
      log.debug(`Bound '${queueName}' to '${key}'`);
    }

    ch.prefetch(10);

    ch.consume(queueName, async (msg) => {
      if (!msg) return; // consumer cancelled

      let payload;
      try {
        payload = JSON.parse(msg.content.toString());
      } catch (parseErr) {
        log.warn(`MessageBus: invalid JSON in '${queueName}', dropping message`);
        ch.nack(msg, false, false);
        return;
      }

      try {
        await handler(payload, msg);
        ch.ack(msg);
      } catch (err) {
        log.warn(`MessageBus handler error in '${queueName}': ${err.message}`);
        // Requeue on first delivery, dead-letter on redelivery (same pattern as audit-service)
        ch.nack(msg, false, !msg.fields.redelivered);
      }
    });

    log.info(`Subscribed: queue='${queueName}' keys=[${routingKeys.join(', ')}]`);
  }

  // ── Device Command Queue ───────────────────────────────────────────────────

  /**
   * Assert the per-device durable queue (once, idempotent) and publish a command.
   *
   * @param {string} deviceId
   * @param {object} command
   * @returns {Promise<boolean>}
   */
  async queueDeviceCommand(deviceId, command) {
    if (!this.isConnected()) {
      log.warn(`MessageBus.queueDeviceCommand: not connected for device '${deviceId}'`);
      return false;
    }

    try {
      const queueName = `device.commands.${deviceId}`;
      await this._assertDeviceCommandQueue(queueName);

      const content = Buffer.from(JSON.stringify({
        ...command,
        _meta: { deviceId, ts: new Date().toISOString() },
      }));

      this._channel.publish(COMMANDS_EXCHANGE, deviceId, content, {
        persistent:  true,
        contentType: 'application/json',
      });

      log.debug(`Queued command for device '${deviceId}'`);
      return true;
    } catch (err) {
      log.warn(`MessageBus.queueDeviceCommand error for '${deviceId}': ${err.message}`);
      return false;
    }
  }

  /**
   * Consume commands from the per-device queue.
   *
   * @param {string}   deviceId
   * @param {Function} handler     async (command) => void
   * @param {object}   [opts]
   * @param {boolean}  [opts.once] If true, drain the queue then cancel the consumer
   * @returns {Promise<void>}
   */
  async consumeDeviceCommands(deviceId, handler, opts) {
    if (!this.isConnected()) {
      log.warn(`MessageBus.consumeDeviceCommands: not connected for device '${deviceId}'`);
      return;
    }

    const once      = opts && opts.once;
    const queueName = `device.commands.${deviceId}`;
    const ch        = this._channel;

    try {
      await this._assertDeviceCommandQueue(queueName);

      let consumerTag;

      const { consumerTag: tag } = await ch.consume(queueName, async (msg) => {
        if (!msg) return;

        let command;
        try {
          command = JSON.parse(msg.content.toString());
        } catch (_) {
          ch.nack(msg, false, false);
          return;
        }

        try {
          await handler(command);
          ch.ack(msg);
        } catch (err) {
          log.warn(`MessageBus.consumeDeviceCommands handler error for '${deviceId}': ${err.message}`);
          ch.nack(msg, false, false);
        }

        // In "once" mode cancel after each message and re-check queue depth.
        if (once) {
          const info = await ch.checkQueue(queueName).catch(() => ({ messageCount: 0 }));
          if (info.messageCount === 0) {
            ch.cancel(consumerTag).catch(() => {});
          }
        }
      });

      consumerTag = tag;
      log.debug(`Consuming device commands for '${deviceId}' (once=${once})`);
    } catch (err) {
      log.warn(`MessageBus.consumeDeviceCommands error for '${deviceId}': ${err.message}`);
    }
  }

  async _assertDeviceCommandQueue(queueName) {
    await this._channel.assertQueue(queueName, {
      durable: true,
      arguments: {
        'x-message-ttl': 86400000, // 24 h
        'x-max-length':  1000,
      },
    });
    // Bind the queue to the commands exchange using deviceId as routing key.
    const deviceId = queueName.replace('device.commands.', '');
    await this._channel.bindQueue(queueName, COMMANDS_EXCHANGE, deviceId);
  }

  // ── Monitoring ─────────────────────────────────────────────────────────────

  /**
   * Returns the number of ready messages in a queue (for monitoring / health checks).
   *
   * @param {string} queueName
   * @returns {Promise<number|null>}  null if not connected or queue doesn't exist
   */
  async getQueueDepth(queueName) {
    if (!this.isConnected()) return null;
    try {
      const info = await this._channel.checkQueue(queueName);
      return info.messageCount;
    } catch (err) {
      log.warn(`MessageBus.getQueueDepth error for '${queueName}': ${err.message}`);
      return null;
    }
  }

  // ── Shutdown ───────────────────────────────────────────────────────────────

  /**
   * Gracefully close the channel and connection.
   */
  async close() {
    this._closing = true;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    try {
      if (this._channel) {
        await this._channel.close();
        this._channel = null;
      }
    } catch (_) { /* ignore */ }

    try {
      if (this._connection) {
        await this._connection.close();
        this._connection = null;
      }
    } catch (_) { /* ignore */ }

    this._connected = false;
    log.info('RabbitMQ connection closed gracefully.');
  }
}

/** Singleton storage */
MessageBus._instance = null;

module.exports = MessageBus;
