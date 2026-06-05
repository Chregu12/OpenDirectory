'use strict';

/**
 * @opendirectory/service-contracts
 *
 * Barrel export for all service contract utilities.
 * Import the sub-module directly for tree-shaking in environments that support it.
 */

const eventsModule = require('./events');
const MessageBus   = require('./messageBus');

const eventBusPkg = (() => {
  try { return require('@opendirectory/grpc-event-bus'); }
  catch (_) {
    try { return require('../../grpc-event-bus/src'); }
    catch (_) { return { EventBusClient: null, EventBusServer: null }; }
  }
})();

const SagaBase           = require('./sagas/SagaBase');
const StoreInstallSaga   = require('./sagas/StoreInstallSaga');
const UserOnboardingSaga = require('./sagas/UserOnboardingSaga');
const DeadLetterHandler  = require('./deadLetter/DeadLetterHandler');

module.exports = {
  events:     eventsModule,
  errors:     require('./errors'),
  httpClient: require('./httpClient'),
  MessageBus,

  // Convenience re-export: destructure Events directly from the top level
  // e.g.  const { Events } = require('@opendirectory/service-contracts');
  Events: eventsModule.Events,

  // Saga orchestration
  SagaBase,
  StoreInstallSaga,
  UserOnboardingSaga,
  DeadLetterHandler,

  // Generic event bus (grpc-event-bus package, falls back gracefully)
  EventBusClient: eventBusPkg.EventBusClient,
  EventBusServer: eventBusPkg.EventBusServer,
};
