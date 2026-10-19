'use strict';

let amqplib;
try { amqplib = require('amqplib'); } catch (_) { amqplib = null; }

class RabbitMQTransport {
  constructor(config) {
    this._url        = config.rabbitmqUrl;
    this._exchange   = config.exchange;
    this._prefetch   = config.prefetch;
    this._delay      = config.reconnectDelayMs;
    this._conn       = null;
    this._ch         = null;
    this._subs       = []; // { queueName, patterns, handler }
    this.connected   = false;
  }

  async connect() {
    if (!amqplib) throw new Error('amqplib not installed');
    try {
      this._conn = await amqplib.connect(this._url);
      this._ch   = await this._conn.createChannel();
      await this._ch.assertExchange(this._exchange, 'topic', { durable: true });
      this._ch.prefetch(this._prefetch);
      this.connected = true;

      this._conn.on('error', () => this._reconnect());
      this._conn.on('close', () => this._reconnect());

      // Re-bind any pending subscriptions
      for (const sub of this._subs) await this._bindSub(sub);
    } catch (e) {
      this.connected = false;
      setTimeout(() => this.connect(), this._delay);
    }
  }

  async publish(routingKey, payload) {
    if (!this._ch) return;
    const buf = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload));
    this._ch.publish(this._exchange, routingKey, buf, { persistent: true });
  }

  async subscribe(queueName, patterns, handler) {
    const sub = { queueName, patterns, handler };
    this._subs.push(sub);
    if (this.connected) await this._bindSub(sub);
  }

  async _bindSub({ queueName, patterns, handler }) {
    if (!this._ch) return;
    await this._ch.assertQueue(queueName, { durable: true });
    for (const p of patterns) await this._ch.bindQueue(queueName, this._exchange, p);
    await this._ch.consume(queueName, (msg) => {
      if (!msg) return;
      try {
        const payload = JSON.parse(msg.content.toString());
        handler(payload, {
          routingKey: msg.fields.routingKey,
          ack:  () => this._ch.ack(msg),
          nack: (requeue = false) => this._ch.nack(msg, false, requeue),
        });
      } catch (e) {
        this._ch.nack(msg, false, false);
      }
    });
  }

  async _reconnect() {
    this.connected = false;
    this._ch = null;
    this._conn = null;
    setTimeout(() => this.connect(), this._delay);
  }

  async close() {
    this.connected = false;
    try { await this._conn?.close(); } catch (_) {}
  }
}

module.exports = RabbitMQTransport;
