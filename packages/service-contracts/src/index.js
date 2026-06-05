'use strict';

/**
 * @opendirectory/service-contracts
 *
 * Barrel export for all service contract utilities.
 * Import the sub-module directly for tree-shaking in environments that support it.
 */

const eventsModule = require('./events');
const MessageBus   = require('./messageBus');

module.exports = {
  events:     eventsModule,
  errors:     require('./errors'),
  httpClient: require('./httpClient'),
  MessageBus,

  // Convenience re-export: destructure Events directly from the top level
  // e.g.  const { Events } = require('@opendirectory/service-contracts');
  Events: eventsModule.Events,
};
