'use strict';
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const path = require('path');

const LOAD_OPTIONS = {
  keepCase: true,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
};

function loadProto(filename) {
  const protoPath = path.join(__dirname, '..', 'protos', filename);
  const packageDef = protoLoader.loadSync(protoPath, LOAD_OPTIONS);
  return grpc.loadPackageDefinition(packageDef).opendirectory;
}

function loadProtoNs(filename, namespace) {
  const protoPath = path.join(__dirname, '..', 'protos', filename);
  const packageDef = protoLoader.loadSync(protoPath, LOAD_OPTIONS);
  const def = grpc.loadPackageDefinition(packageDef);
  // namespace can be "opendirectory.eventbus" → traverse
  return namespace.split('.').reduce((o, k) => o[k], def);
}

function createClient(ServiceClass, address) {
  return new ServiceClass(address, grpc.credentials.createInsecure());
}

// Promisify a gRPC unary call
function call(client, method, request) {
  return new Promise((resolve, reject) => {
    client[method](request, (err, response) => {
      if (err) reject(err);
      else resolve(response);
    });
  });
}

// Service address helpers (use K8s DNS names)
const addresses = {
  device:     process.env.DEVICE_SERVICE_GRPC   || 'device-service:50051',
  auth:       process.env.AUTH_SERVICE_GRPC     || 'authentication-service:50051',
  policy:     process.env.POLICY_SERVICE_GRPC   || 'policy-service:50051',
  appstore:   process.env.APPSTORE_SERVICE_GRPC || 'app-store:50051',
  event_bus:  process.env.EVENT_BUS_GRPC_ADDRESS || 'event-bus:50050',
};

// Lazy-loaded singletons
let _clients = {};

// Proto files that use a nested namespace (not just "opendirectory")
const nsMap = {
  event_bus: 'opendirectory.eventbus',
};

function getClient(name) {
  if (_clients[name]) return _clients[name];

  const protoMap   = { device: 'device.proto', auth: 'auth.proto', policy: 'policy.proto', appstore: 'appstore.proto', event_bus: 'event_bus.proto' };
  const serviceMap = { device: 'DeviceService', auth: 'AuthService', policy: 'PolicyService', appstore: 'AppStoreService', event_bus: 'EventBusService' };

  const pkg = nsMap[name]
    ? loadProtoNs(protoMap[name], nsMap[name])
    : loadProto(protoMap[name]);
  _clients[name] = createClient(pkg[serviceMap[name]], addresses[name]);
  return _clients[name];
}

function getEventBusClient() {
  return getClient('event_bus');
}

module.exports = {
  getClient,
  getEventBusClient,
  call,
  addresses,
  // Convenience getters
  get device()    { return getClient('device'); },
  get auth()      { return getClient('auth'); },
  get policy()    { return getClient('policy'); },
  get appstore()  { return getClient('appstore'); },
  get event_bus() { return getClient('event_bus'); },
};
