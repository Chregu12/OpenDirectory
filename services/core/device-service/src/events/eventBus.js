'use strict';

const { EventEmitter } = require('events');
const logger = require('../utils/logger');

/**
 * EventBus — internal pub/sub bus backed by Node EventEmitter.
 * All device-service events flow through here so services remain decoupled.
 */
class EventBus extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(50);
  }

  async healthCheck() {
    return { status: 'healthy', listenerCount: this.eventNames().length };
  }
}

module.exports = EventBus;
