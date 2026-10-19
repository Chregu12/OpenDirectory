'use strict';
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');

const LOAD_OPTIONS = { keepCase: true, longs: String, enums: String, defaults: true, oneofs: true };

function createServer() {
  return new grpc.Server();
}

function loadService(protoFile, serviceName) {
  const protoPath = path.join(__dirname, '..', 'protos', protoFile);
  const pkg = grpc.loadPackageDefinition(protoLoader.loadSync(protoPath, LOAD_OPTIONS)).opendirectory;
  return pkg[serviceName].service;
}

function startServer(server, port) {
  return new Promise((resolve, reject) => {
    server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
      if (err) return reject(err);
      server.start();
      resolve(boundPort);
    });
  });
}

module.exports = { createServer, loadService, startServer };
