'use strict';

/**
 * Simple circuit breaker to wrap calls to external services.
 * Falls through (no-op protection) in development / when threshold not hit.
 */
class CircuitBreaker {
  constructor(options = {}) {
    this.threshold = options.threshold || 5;
    this.timeout = options.timeout || 60000;
    this.state = {}; // key → { failures, lastFailure, open }
  }

  async execute(key, fn) {
    const circuit = this.state[key] || { failures: 0, open: false };

    if (circuit.open) {
      const elapsed = Date.now() - circuit.lastFailure;
      if (elapsed < this.timeout) {
        throw new Error(`Circuit open for ${key}`);
      }
      // Half-open: try again
      circuit.open = false;
    }

    try {
      const result = await fn();
      circuit.failures = 0;
      this.state[key] = circuit;
      return result;
    } catch (err) {
      circuit.failures++;
      circuit.lastFailure = Date.now();
      if (circuit.failures >= this.threshold) {
        circuit.open = true;
      }
      this.state[key] = circuit;
      throw err;
    }
  }
}

module.exports = CircuitBreaker;
