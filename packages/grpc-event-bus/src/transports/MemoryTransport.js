'use strict';
const { EventEmitter } = require('events');

// Shared handler map used when shared: true — all MemoryTransport instances
// created with the same sharedKey read/write the same subscription registry.
const _sharedBuses = new Map(); // sharedKey → Map<queueName, [{patterns, handler}]>

class MemoryTransport extends EventEmitter {
  /**
   * @param {object} [opts]
   * @param {boolean} [opts.shared=false]  When true, all instances with the
   *   same sharedKey share subscriptions (simulates a real broker).
   * @param {string}  [opts.sharedKey='default']
   */
  constructor(opts = {}) {
    super();
    const shared    = !!opts.shared;
    const sharedKey = opts.sharedKey || 'default';

    if (shared) {
      if (!_sharedBuses.has(sharedKey)) _sharedBuses.set(sharedKey, new Map());
      this._handlers = _sharedBuses.get(sharedKey);
      this._shared   = true;
    } else {
      this._handlers = new Map(); // queueName → [{ patterns, handler }]
      this._shared   = false;
    }
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

  async close() {
    this.connected = false;
    if (!this._shared) this._handlers.clear();
  }

  // AMQP-style wildcard matching: * = one word, # = zero or more words
  _match(pattern, key) {
    const re = '^' + pattern
      .replace(/\./g, '\\.')
      .replace(/\*\*/g, '.+')
      .replace(/\*/g, '[^.]+')
      .replace(/#/g, '.*') + '$';
    return new RegExp(re).test(key);
  }

  /** Reset the shared bus for a given key (useful in tests). */
  static resetShared(sharedKey = 'default') {
    _sharedBuses.delete(sharedKey);
  }
}

module.exports = MemoryTransport;
