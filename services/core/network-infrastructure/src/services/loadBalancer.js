'use strict';

// NOTE: This file was missing from the repo entirely — see vlanManager.js
// for the full explanation. Unlike the other stand-ins, index.js never
// actually calls a method on `this.loadBalancer` (the load-balancer HTTP
// routes are static "implementation needed" placeholders that don't touch
// the manager at all) — this class exists purely so `new LoadBalancer()`
// in the service constructor doesn't throw on a missing module.

const EventEmitter = require('events');

class LoadBalancer extends EventEmitter {
  constructor() {
    super();
    this.pools = new Map();
  }
}

module.exports = LoadBalancer;
