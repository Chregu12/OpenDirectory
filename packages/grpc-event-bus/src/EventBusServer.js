'use strict';

let grpc, protoLoader;
try { grpc = require('@grpc/grpc-js'); protoLoader = require('@grpc/proto-loader'); } catch (_) { grpc = null; }

const path  = require('path');
const { randomUUID } = require('crypto');
const { loadConfig } = require('./config');
const { createTransport } = require('./transports');

const PROTO_PATH = path.resolve(__dirname, '../../proto/protos/event_bus.proto');

class EventBusServer {
  constructor(overrides = {}) {
    this._config    = loadConfig(overrides);
    this._transport = createTransport({ ...this._config, transport: this._config.backendTransport || 'rabbitmq' });
    this._server    = null;
    this._streams   = new Map(); // consumer_group → Set<call>
  }

  async start() {
    if (!grpc) throw new Error('@grpc/grpc-js is required for EventBusServer');

    await this._transport.connect();

    const def = protoLoader.loadSync(PROTO_PATH, { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true });
    const pkg  = grpc.loadPackageDefinition(def);

    this._server = new grpc.Server();
    this._server.addService(pkg.opendirectory.eventbus.EventBusService.service, {
      Publish:       this._handlePublish.bind(this),
      Subscribe:     this._handleSubscribe.bind(this),
      Ack:           this._handleAck.bind(this),
      PublishStream: this._handlePublishStream.bind(this),
      Health:        this._handleHealth.bind(this),
    });

    const port = this._config.grpcServerPort;
    await new Promise((res, rej) => {
      this._server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), (err, p) => {
        if (err) return rej(err);
        console.log(`[EventBusServer] gRPC server listening on port ${p}`);
        res(p);
      });
    });
    this._server.start();
    return this;
  }

  _handlePublish(call, callback) {
    const ev = call.request.event;
    this._transport.publish(ev.routing_key, JSON.parse(ev.payload.toString()))
      .then(() => callback(null, { ok: true, event_id: ev.id || randomUUID() }))
      .catch(e  => callback(null, { ok: false, error: e.message }));
  }

  _handleSubscribe(call) {
    const { consumer_group, patterns } = call.request;

    const streams = this._streams.get(consumer_group) || new Set();
    streams.add(call);
    this._streams.set(consumer_group, streams);

    this._transport.subscribe(consumer_group, patterns, (payload, meta) => {
      const ev = {
        id:          randomUUID(),
        routing_key: meta.routingKey,
        payload:     Buffer.from(JSON.stringify(payload)),
        source:      payload._source || 'unknown',
        timestamp:   Date.now(),
        headers:     {},
      };
      streams.forEach(s => { try { s.write(ev); } catch (_) { streams.delete(s); } });
      meta.ack();
    });

    call.on('cancelled', () => { streams.delete(call); });
  }

  _handleAck(call, callback) {
    // ACK is handled in the subscribe flow; no-op here
    callback(null, { ok: true });
  }

  _handlePublishStream(call) {
    call.on('data', (req) => {
      const ev = req.event;
      this._transport.publish(ev.routing_key, JSON.parse(ev.payload.toString()))
        .then(() => call.write({ ok: true, event_id: ev.id || randomUUID() }))
        .catch(e  => call.write({ ok: false, error: e.message }));
    });
    call.on('end', () => call.end());
  }

  _handleHealth(call, callback) {
    callback(null, { ok: true, version: '1.0.0', transport: this._config.backendTransport || 'rabbitmq' });
  }

  async stop() {
    await new Promise(res => this._server?.tryShutdown(res) ?? res());
    await this._transport.close();
  }
}

module.exports = EventBusServer;
