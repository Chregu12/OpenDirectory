'use strict';

let MessageBus;
try { MessageBus = require('../../../../../packages/service-contracts/src/messageBus'); }
catch (_) { MessageBus = null; }

let _bus = null;

async function connect() {
  if (!MessageBus) return;
  const url = process.env.RABBITMQ_URL || process.env.AMQP_URL;
  if (!url) return;
  try {
    _bus = new MessageBus();
    await _bus.connect(url);
  } catch (err) {
    console.warn('[eventPublisher] Bus not available:', err.message);
    _bus = null;
  }
}

async function publish(routingKey, payload) {
  if (!_bus || !_bus.isConnected()) return;
  try { await _bus.publish(routingKey, payload); } catch (_) {}
}

module.exports = { connect, publish };
