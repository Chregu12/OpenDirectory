'use strict';

const { currentOperator } = require('./delegation');
const SERVICES = Object.freeze({
  auth: process.env.AUTH_SERVICE_URL || 'http://authentication-service',
  directory: process.env.DIRECTORY_SERVICE_URL || 'http://enterprise-directory',
  kerberos: process.env.KERBEROS_SERVICE_URL || 'http://kerberos-kdc',
  samba: process.env.SAMBA_SERVICE_URL || 'http://samba-ad-dc',
  device: process.env.DEVICE_SERVICE_URL || 'http://device-service',
  policy: process.env.POLICY_SERVICE_URL || 'http://policy-service',
  pim: process.env.PIM_SERVICE_URL || 'http://conditional-access',
  mdm: process.env.MDM_SERVICE_URL || 'http://mobile-management',
  appStore: process.env.APP_STORE_SERVICE_URL || 'http://app-store',
});
function failure(message, status = 502, code = 'DOWNSTREAM_UNAVAILABLE') { return Object.assign(new Error(message), { status, code }); }
function createServiceClient({ services = SERVICES, timeoutMs = 10000, maxResponseBytes = 1048576 } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000 || !Number.isInteger(maxResponseBytes) || maxResponseBytes < 1024 || maxResponseBytes > 1048576) throw new Error('Invalid downstream bounds');
  const bases = new Map(Object.entries(services).map(([name, value]) => {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || url.pathname !== '/') throw new Error('Invalid downstream service URL');
    return [name, url];
  }));
  function target(service, path) {
    const base = bases.get(service); if (!base) throw failure('Unknown downstream service', 400);
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\u0000-\u0020\u007f\\]/.test(path)) throw failure('Invalid downstream path', 400);
    const url = new URL(path, base); if (url.origin !== base.origin || url.hash) throw failure('Invalid downstream target', 400);
    return url;
  }
  async function send(url, method, body, context) {
    const { default: fetch } = await import('node-fetch'); const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { method, redirect: 'error', signal: context ? AbortSignal.any([controller.signal, context.signal]) : controller.signal,
        headers: { Accept: 'application/json', ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
          ...(context ? { Authorization: context.authorization, 'X-OD-Operation-Id': context.operationId } : {}) },
        ...(body !== undefined && !['GET', 'HEAD'].includes(method) ? { body: JSON.stringify(body) } : {}) });
      if (!response.ok) {
        response.body?.destroy();
        const error = failure('Downstream rejected delegated operation', response.status);
        if ([401, 403].includes(response.status)) context?.block(error);
        throw error;
      }
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > maxResponseBytes) { controller.abort(); throw failure('Downstream response exceeded bounds'); } chunks.push(Buffer.from(chunk)); }
      if (response.status === 204) return {};
      const text = Buffer.concat(chunks).toString('utf8');
      const data = response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : { _raw: text };
      if (data?.success === false) throw failure('Downstream operation was not confirmed');
      return data;
    } catch (error) {
      if (context?.signal.aborted) throw context.signal.reason;
      if (error.code === 'DOWNSTREAM_UNAVAILABLE') throw error;
      if (controller.signal.aborted) throw failure('Downstream operation timed out; outcome is unknown', 504, 'ETIMEOUT');
      throw failure('Downstream operation unavailable; outcome is unknown');
    } finally { clearTimeout(timer); }
  }
  async function call(service, method, path, body, { authorization } = {}) {
    const context = currentOperator();
    if (authorization !== undefined && authorization !== context.authorization) throw failure('Delegated authorization cannot be replaced', 403);
    if (typeof method !== 'string' || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method.toUpperCase())) throw failure('Invalid downstream method', 400);
    const url = target(service, path); await context.check();
    return send(url, method.toUpperCase(), body, context);
  }
  async function ping(service) {
    const started = Date.now();
    try { await send(target(service, '/health'), 'GET'); return { healthy: true, latencyMs: Date.now() - started }; }
    catch { return { healthy: false, latencyMs: Date.now() - started, error: 'Health probe unavailable' }; }
  }
  return { call, ping };
}
async function getServiceToken() { throw failure('Implicit service credentials are retired; a verified operator is required', 401); }
module.exports = { ...createServiceClient(), createServiceClient, getServiceToken, SERVICES };
