'use strict';

/**
 * Base HTTP client with timeout, retry, and simple circuit-breaker logic.
 *
 * Services can extend or compose this to create their own typed clients
 * without duplicating the plumbing code.
 *
 * Example usage:
 *
 *   const { HttpClient } = require('@opendirectory/service-contracts/httpClient');
 *   const client = new HttpClient('http://policy-service:3004', { retries: 2 });
 *   const data = await client.get('/api/policies');
 */

const { ServiceUnavailableError } = require('./errors');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_RETRIES     = 1;
const DEFAULT_RETRY_DELAY = 200; // ms between retries

/**
 * Simple circuit-breaker state per client instance.
 *
 * States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (probing)
 */
const CLOSED    = 'CLOSED';
const OPEN      = 'OPEN';
const HALF_OPEN = 'HALF_OPEN';

class HttpClient {
  /**
   * @param {string} baseUrl - scheme + host + optional port, no trailing slash
   * @param {object} options
   * @param {number} [options.timeoutMs=5000]      - per-request timeout
   * @param {number} [options.retries=1]           - extra attempts on network error
   * @param {number} [options.retryDelayMs=200]    - delay between retries
   * @param {number} [options.circuitThreshold=5]  - consecutive failures before OPEN
   * @param {number} [options.circuitResetMs=30000]- ms before OPEN → HALF_OPEN probe
   * @param {string} [options.serviceName]         - used in error messages
   */
  constructor(baseUrl, options = {}) {
    this.baseUrl     = baseUrl.replace(/\/$/, '');
    this.timeoutMs   = options.timeoutMs   || DEFAULT_TIMEOUT_MS;
    this.retries     = options.retries     !== undefined ? options.retries : DEFAULT_RETRIES;
    this.retryDelay  = options.retryDelayMs || DEFAULT_RETRY_DELAY;
    this.serviceName = options.serviceName  || baseUrl;

    // Circuit breaker state
    this._cbState      = CLOSED;
    this._cbFailures   = 0;
    this._cbThreshold  = options.circuitThreshold || 5;
    this._cbResetMs    = options.circuitResetMs   || 30000;
    this._cbOpenedAt   = null;
  }

  // ── Public HTTP methods ────────────────────────────────────────────────────

  async get(path, headers = {}) {
    return this._request('GET', path, undefined, headers);
  }

  async post(path, body, headers = {}) {
    return this._request('POST', path, body, headers);
  }

  async put(path, body, headers = {}) {
    return this._request('PUT', path, body, headers);
  }

  async patch(path, body, headers = {}) {
    return this._request('PATCH', path, body, headers);
  }

  async delete(path, headers = {}) {
    return this._request('DELETE', path, undefined, headers);
  }

  // ── Internal request with timeout + retry + circuit breaker ───────────────

  async _request(method, path, body, extraHeaders = {}) {
    this._checkCircuit();

    const url = `${this.baseUrl}${path}`;
    let lastError;

    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt > 0) {
        await this._sleep(this.retryDelay);
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);

      try {
        const opts = {
          method,
          signal: controller.signal,
          headers: {
            'Content-Type': 'application/json',
            ...extraHeaders
          }
        };
        if (body !== undefined) opts.body = JSON.stringify(body);

        const res = await fetch(url, opts);

        if (!res.ok) {
          // 4xx / 5xx from the downstream service
          const text = await res.text().catch(() => '');
          const err = new Error(`HTTP ${res.status} from ${this.serviceName}: ${text}`);
          err.statusCode = res.status;

          // Only treat 5xx as circuit-breaker failure
          if (res.status >= 500) {
            this._recordFailure();
          } else {
            this._recordSuccess();
          }
          throw err;
        }

        this._recordSuccess();
        const contentType = res.headers.get('content-type') || '';
        if (contentType.includes('application/json')) {
          return await res.json();
        }
        return await res.text();

      } catch (err) {
        if (err.name === 'AbortError') {
          lastError = new Error(`Request to ${this.serviceName} timed out after ${this.timeoutMs}ms`);
        } else {
          lastError = err;
        }
        // Only record failure for network errors (not 4xx)
        if (!err.statusCode || err.statusCode >= 500) {
          this._recordFailure();
        }
      } finally {
        clearTimeout(timer);
      }
    }

    console.error(`[HttpClient] ${method} ${url} failed after ${this.retries + 1} attempt(s):`, lastError.message);
    throw new ServiceUnavailableError(this.serviceName, lastError.message);
  }

  // ── Circuit breaker helpers ────────────────────────────────────────────────

  _checkCircuit() {
    if (this._cbState === OPEN) {
      const elapsed = Date.now() - this._cbOpenedAt;
      if (elapsed >= this._cbResetMs) {
        this._cbState = HALF_OPEN;
        console.warn(`[HttpClient:${this.serviceName}] circuit HALF_OPEN — probing`);
      } else {
        throw new ServiceUnavailableError(
          this.serviceName,
          `circuit breaker open (${Math.round((this._cbResetMs - elapsed) / 1000)}s until probe)`
        );
      }
    }
  }

  _recordSuccess() {
    this._cbFailures = 0;
    if (this._cbState !== CLOSED) {
      this._cbState = CLOSED;
      console.info(`[HttpClient:${this.serviceName}] circuit CLOSED`);
    }
  }

  _recordFailure() {
    this._cbFailures += 1;
    if (this._cbState === HALF_OPEN || this._cbFailures >= this._cbThreshold) {
      this._cbState    = OPEN;
      this._cbOpenedAt = Date.now();
      console.error(`[HttpClient:${this.serviceName}] circuit OPEN after ${this._cbFailures} failure(s)`);
    }
  }

  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = { HttpClient };
