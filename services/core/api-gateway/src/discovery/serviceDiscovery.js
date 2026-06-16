'use strict';

const logger = require('../config/logger');

/**
 * Lightweight service discovery stub.
 * Services self-register via the proxy setup in index.js.
 * This module can be extended later to support Consul, etcd, or DNS-SD.
 */
const serviceDiscovery = {
  start() {
    logger.info('Service discovery started (static configuration mode)');
  }
};

module.exports = serviceDiscovery;
