'use strict';

function createTransport(config) {
  const type = config.transport;
  if (type === 'memory')   return new (require('./MemoryTransport'))(config);
  if (type === 'grpc')     return new (require('./GrpcTransport'))(config);
  if (type === 'rabbitmq') return new (require('./RabbitMQTransport'))(config);
  throw new Error(`Unknown EVENT_BUS_TRANSPORT: "${type}". Use rabbitmq | grpc | memory`);
}

module.exports = { createTransport };
