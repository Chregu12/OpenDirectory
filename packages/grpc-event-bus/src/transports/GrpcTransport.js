'use strict';

let grpc, protoLoader;
try {
  grpc        = require('@grpc/grpc-js');
  protoLoader = require('@grpc/proto-loader');
} catch (_) { grpc = null; }

const path = require('path');
const { randomUUID } = require('crypto');

const PROTO_PATH = path.resolve(__dirname, '../../../proto/protos/event_bus.proto');

class GrpcTransport {
  constructor(config) {
    this._address  = config.grpcAddress;
    this._delay    = config.reconnectDelayMs;
    this._subs     = [];
    this._client   = null;
    this.connected = false;
  }

  async connect() {
    if (!grpc) throw new Error('@grpc/grpc-js not installed');
    const def = protoLoader.loadSync(PROTO_PATH, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
    const pkg  = grpc.loadPackageDefinition(def);
    const Svc  = pkg.opendirectory.eventbus.EventBusService;
    this._client = new Svc(this._address, grpc.credentials.createInsecure());

    // Verify connectivity
    await new Promise((res, rej) => {
      this._client.Health({}, (err) => err ? rej(err) : res());
    }).catch(() => {
      setTimeout(() => this.connect(), this._delay);
      return;
    });
    this.connected = true;

    // Re-attach pending subscriptions
    for (const sub of this._subs) this._attachStream(sub);
  }

  async publish(routingKey, payload) {
    if (!this._client) return;
    const event = {
      id: randomUUID(),
      routing_key: routingKey,
      payload: Buffer.from(JSON.stringify(payload)),
      source: process.env.SERVICE_NAME || 'unknown',
      timestamp: Date.now(),
    };
    return new Promise((res) => {
      this._client.Publish({ event }, (err, resp) => res(resp));
    });
  }

  async subscribe(queueName, patterns, handler) {
    const sub = { queueName, patterns, handler };
    this._subs.push(sub);
    if (this.connected) this._attachStream(sub);
  }

  _attachStream({ queueName, patterns, handler }) {
    const stream = this._client.Subscribe({
      consumer_group: queueName,
      patterns,
      durable: true,
    });
    stream.on('data', (event) => {
      try {
        const payload = JSON.parse(event.payload.toString());
        handler(payload, {
          routingKey: event.routing_key,
          ack:  () => this._client.Ack({ event_id: event.id, consumer_group: queueName, requeue: false }, () => {}),
          nack: (requeue = false) => this._client.Ack({ event_id: event.id, consumer_group: queueName, requeue }, () => {}),
        });
      } catch (_) {}
    });
    stream.on('error', () => setTimeout(() => this._attachStream({ queueName, patterns, handler }), this._delay));
    stream.on('end',   () => setTimeout(() => this._attachStream({ queueName, patterns, handler }), this._delay));
  }

  async close() {
    this.connected = false;
    this._client?.close?.();
  }
}

module.exports = GrpcTransport;
