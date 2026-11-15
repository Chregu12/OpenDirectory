'use strict';
const { createServer } = require('node:http');

async function listenLoopback(app) {
  const server = typeof app === 'function' ? createServer(app) : app;
  // Supertest calls 127.0.0.1; an IPv6 wildcard may share its port with another IPv4 fixture on macOS.
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
  });
  return server;
}
async function closeServer(server) {
  await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}
module.exports = { listenLoopback, closeServer };
