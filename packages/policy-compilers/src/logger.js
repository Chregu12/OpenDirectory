'use strict';
// =============================================================================
// Minimal dependency-free logger for the shared policy-compilers package.
//
// This package intentionally ships with zero npm dependencies so that any
// service (enterprise-directory, policy-service, integration-service, ...)
// can require it without pulling in a logging framework. Consumers that want
// structured logs (winston, pino, ...) should log around the call site;
// this only emits a single-line JSON record, gated behind LOG_LEVEL, so the
// RSoP-style compilers keep the same observability they had as local copies.
// =============================================================================
function logInfo(message, meta) {
  const level = (process.env.LOG_LEVEL || 'info').toLowerCase();
  if (level === 'silent' || level === 'error' || level === 'warn') return;
  try {
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() }));
  } catch (_) {
    // Never let logging break policy compilation.
  }
}

module.exports = { logInfo };
