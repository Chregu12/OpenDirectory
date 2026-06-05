'use strict';
const { EventEmitter } = require('events');

class MemoryTransport extends EventEmitter {
  constructor() {
    super();
    this._handlers = new Map(); // queueName → [{ patterns, handler }]
    this.connected = false;
  }

  async connect() { this.connected = true; }

  async publish(routingKey, payload) {
    const event = typeof payload === 'string' ? payload : JSON.stringify(payload);
    // Deliver to all matching subscriptions
    for (const [, subs] of this._handlers) {
      for (const { patterns, handler } of subs) {
        if (patterns.some(p => this._match(p, routingKey))) {
          setImmediate(() => handler(JSON.parse(event), { routingKey, ack: () => {}, nack: () => {} }));
        }
      }
    }
  }

  async subscribe(queueName, patterns, handler) {
    if (!this._handlers.has(queueName)) this._handlers.set(queueName, []);
    this._handlers.get(queueName).push({ patterns, handler });
  }

  async close() { this.connected = false; this._handlers.clear(); }

  // AMQP-style wildcard matching: * = one word, # = zero or more words
  _match(pattern, key) {
    const re = '^' + pattern
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '.+')
      .replace(/\*/g, '[^.]+')
      .replace(/#/g, '.*') + '$';
    return new RegExp(re).test(key);
  }
}

module.exports = MemoryTransport;
