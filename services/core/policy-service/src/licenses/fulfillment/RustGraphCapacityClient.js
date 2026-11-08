'use strict';

const { spawn } = require('node:child_process');
const { runConnector } = require('./rustConnector');
const { GraphCapacityClient, snapshot } = require('./GraphCapacityClient');

// The existing reviewed token source and database observer remain authoritative;
// the Rust process performs the read-only Microsoft Graph request over stdin/stdout.
class RustGraphCapacityClient extends GraphCapacityClient {
  constructor(options) {
    super(options);
    this.binary = options.binary || '/usr/local/bin/opendirectory-connectors';
    this.spawn = options.spawnImpl || spawn;
  }

  async inspect(signal) {
    const controller = new AbortController(); const abort = () => controller.abort();
    signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    const timer = setTimeout(abort, 10000);
    try {
      const token = await this.tokens.get(controller.signal);
      const result = await this.run(token, controller.signal);
      return snapshot(result);
    } catch (error) { this.tokens.clear(); throw error; }
    finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
  }

  run(token, signal) {
    return runConnector({ binary: this.binary, spawnImpl: this.spawn, request: { accessToken: token }, signal, stage: 'graph_capacity', field: 'rows' });
  }
}
module.exports = { RustGraphCapacityClient };
