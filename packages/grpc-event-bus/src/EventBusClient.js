'use strict';

const { loadConfig } = require('./config');
const { createTransport } = require('./transports');

class EventBusClient {
  constructor(overrides = {}) {
    this._config    = loadConfig(overrides);
    this._transport = createTransport(this._config);
    this._source    = process.env.SERVICE_NAME || overrides.source || 'unknown';
  }

  /**
   * Connect to the underlying transport. Call once at startup.
   * Resolves when connected (or first attempt made — reconnect runs in background).
   */
  async connect() {
    await this._transport.connect();
    return this;
  }

  /**
   * Publish an event.
   * @param {string} routingKey  e.g. 'device.enrolled'
   * @param {object} payload
   */
  async publish(routingKey, payload) {
    await this._transport.publish(routingKey, {
      ...payload,
      _source: this._source,
      _ts: Date.now(),
    });
  }

  /**
   * Subscribe to events matching the given routing-key patterns.
   * @param {string}   queueName   Durable queue name for this consumer
   * @param {string[]} patterns    e.g. ['device.*', 'policy.#']
   * @param {Function} handler     async (payload, { routingKey, ack, nack }) => void
   */
  async subscribe(queueName, patterns, handler) {
    await this._transport.subscribe(queueName, patterns, handler);
  }

  /** Close the connection gracefully. */
  async close() {
    await this._transport.close();
  }

  get transport() { return this._config.transport; }

  /**
   * Returns true when the underlying transport is connected.
   * Exposed as a regular method (not a getter) so that legacy call-sites
   * using `bus.isConnected()` work alongside code that reads the boolean
   * directly via `bus.isConnected`.  Calling it as `isConnected()` returns
   * the boolean; reading it as a property also returns the boolean.
   */
  isConnected() { return this._transport.connected; }

  /** Create and connect a client in one call. */
  static async create(overrides = {}) {
    const client = new EventBusClient(overrides);
    await client.connect();
    return client;
  }

  /** Singleton instance (lazily created). */
  static getInstance(overrides = {}) {
    if (!EventBusClient._instance) {
      EventBusClient._instance = new EventBusClient(overrides);
    }
    return EventBusClient._instance;
  }
  static _instance = null;
}

module.exports = EventBusClient;
