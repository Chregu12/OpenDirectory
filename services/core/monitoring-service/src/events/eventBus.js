'use strict';

const { EventEmitter } = require('events');

/**
 * EventBus — simple pub/sub wrapper around Node's EventEmitter.
 * The monitoring service wires all internal components through this bus so
 * that services remain decoupled from one another.
 */
class EventBus extends EventEmitter {
  constructor() {
    super();
    // Increase the default listener limit; monitoring services register many handlers.
    this.setMaxListeners(50);
    this._history = [];
    this._maxHistory = 1000;
  }

  /**
   * Emit an event and keep a ring-buffer of recent events for debugging.
   */
  emit(event, ...args) {
    this._history.push({ event, args, ts: Date.now() });
    if (this._history.length > this._maxHistory) {
      this._history.shift();
    }
    return super.emit(event, ...args);
  }

  /**
   * Return the most recent N events from the ring-buffer.
   */
  getHistory(n = 100) {
    return this._history.slice(-n);
  }
}

module.exports = EventBus;
