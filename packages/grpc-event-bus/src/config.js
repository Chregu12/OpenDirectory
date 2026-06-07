'use strict';
const path = require('path');
const fs = require('fs');

const DEFAULTS = {
  transport: 'rabbitmq',                    // 'rabbitmq' | 'grpc' | 'memory'
  rabbitmqUrl: 'amqp://opendirectory:changeme@rabbitmq:5672/',
  grpcAddress: 'event-bus:50050',
  grpcServerPort: 50050,
  exchange: 'opendirectory.events',
  tls: false,
  prefetch: 10,
  reconnectDelayMs: 2000,
  routingConfigPath: process.env.EVENT_ROUTING_CONFIG
    || path.resolve(__dirname, '../../../config/event-routing.yaml'),
};

function loadConfig(overrides = {}) {
  return {
    // Known / env-mapped fields
    transport:           process.env.EVENT_BUS_TRANSPORT      || overrides.transport      || DEFAULTS.transport,
    rabbitmqUrl:         process.env.RABBITMQ_URL              || overrides.rabbitmqUrl    || DEFAULTS.rabbitmqUrl,
    grpcAddress:         process.env.EVENT_BUS_GRPC_ADDRESS   || overrides.grpcAddress    || DEFAULTS.grpcAddress,
    grpcServerPort: parseInt(process.env.EVENT_BUS_GRPC_PORT  || overrides.grpcServerPort || DEFAULTS.grpcServerPort, 10),
    exchange:            process.env.EVENT_BUS_EXCHANGE        || overrides.exchange       || DEFAULTS.exchange,
    tls:                 process.env.EVENT_BUS_TLS === 'true'  || overrides.tls           || DEFAULTS.tls,
    prefetch:       parseInt(process.env.EVENT_BUS_PREFETCH   || overrides.prefetch       || DEFAULTS.prefetch, 10),
    reconnectDelayMs: parseInt(process.env.EVENT_BUS_RECONNECT_MS || overrides.reconnectDelayMs || DEFAULTS.reconnectDelayMs, 10),
    // Pass-through extras (e.g. shared / sharedKey for MemoryTransport in tests)
    ...(overrides.shared    !== undefined && { shared:    overrides.shared }),
    ...(overrides.sharedKey !== undefined && { sharedKey: overrides.sharedKey }),
  };
}

module.exports = { loadConfig, DEFAULTS };
