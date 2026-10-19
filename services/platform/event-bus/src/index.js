'use strict';
const express = require('express');
const EventBusServer = require('../../../../packages/grpc-event-bus/src/EventBusServer');

const app = express();
const server = new EventBusServer({
  backendTransport: process.env.BACKEND_TRANSPORT || 'rabbitmq',
  grpcServerPort: parseInt(process.env.GRPC_PORT || '50050', 10),
});

app.get('/health', (req, res) => res.json({ status: 'ok', transport: process.env.BACKEND_TRANSPORT || 'rabbitmq' }));
app.get('/metrics', (req, res) => res.set('Content-Type', 'text/plain').send('# event-bus metrics\n'));

const HTTP_PORT = parseInt(process.env.PORT || '3030', 10);

server.start()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log(`[event-bus] HTTP health on :${HTTP_PORT}, gRPC on :${process.env.GRPC_PORT || 50050}`);
    });
  })
  .catch((err) => {
    console.error('[event-bus] Failed to start:', err.message);
    process.exit(1);
  });
