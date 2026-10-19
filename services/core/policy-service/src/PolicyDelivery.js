'use strict';

const { randomUUID } = require('node:crypto');
const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { freshPolicyAuthentication } = require('./middleware/policyAccess');
const commandContract = require('../../../../packages/policy-command-contract');

class PolicyDeliveryError extends Error {
  constructor(status, code, attempted = false) {
    super(code); this.status = status; this.code = code; this.deliveryMayHaveOccurred = attempted;
  }
}

function endpoint(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Fixed policy delivery origin required');
  return url.origin;
}

class PolicyDelivery {
  constructor({ authority = createAccessStateClient(), fetchImpl = (...args) => fetch(...args),
    deviceUrl = process.env.OAUTH_PROVIDER_URL || 'http://oauth-provider:3010', certificateUrl = process.env.CA_SERVICE_URL || 'http://certificate-authority', timeoutMs = 5000 } = {}) {
    this.authority = authority; this.fetch = fetchImpl; this.origins = { devices: endpoint(deviceUrl), certificates: endpoint(certificateUrl) }; this.timeoutMs = timeoutMs;
    this.contexts = new WeakMap();
  }
  context(req, res) {
    if (!this.contexts.has(req)) {
      const verified = req.verifiedAccess;
      if (!verified || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(verified.authorization) || !verified.claims?.jti
        || !freshPolicyAuthentication(verified.claims)) throw new PolicyDeliveryError(403, 'verified_policy_operator_required');
      const controller = new AbortController();
      const context = { authorization: verified.authorization, claims: structuredClone(verified.claims), controller, operationId: randomUUID(), sourceCheck: req.policyConfigurationCheck,
        source: structuredClone(req.policyDeliverySource), binding: structuredClone(req.policyPublicationBinding), payloads: structuredClone(req.policyCommandPayloads), receiverConfirmed: false };
      res.once('finish', () => controller.abort()); res.once('close', () => controller.abort()); this.contexts.set(req, context);
    }
    return this.contexts.get(req);
  }
  async request(req, res, service, pathname, { method = 'GET', body } = {}) {
    if (!(service === 'devices' && (method === 'GET' && ['/api/devices/registry','/api/devices/policy-registry','/api/devices/policy-command-access'].includes(pathname)
      || method === 'POST' && /^\/api\/devices\/(?!\.{1,2}\/)[A-Za-z0-9._~-]{1,255}\/commands$/.test(pathname))
      || service === 'certificates' && method === 'POST' && pathname === '/api/certificates/issue')) throw new PolicyDeliveryError(403, 'policy_delivery_path_forbidden');
    const context = this.context(req, res); const controller = new AbortController();
    if (service === 'devices' && method === 'POST') {
      try {
        commandContract.fields(body, ['command','reference']); commandContract.reference(body.reference);
        if (body.command !== 'update_policy' || !context.receiverConfirmed || !context.source || !context.binding || !context.payloads
          || Object.entries(context.source).some(([key,value]) => body.reference[key] !== value) || !context.payloads[body.reference.configurationId || 'gpo']) throw new PolicyDeliveryError(409, 'policy_receiver_handshake_required');
      } catch (error) {
        context.controller.abort(); throw new PolicyDeliveryError(error.status || 409, error.code || 'policy_receiver_handshake_required', context.attemptedWrite === true);
      }
    }
    const close = () => controller.abort(); context.controller.signal.addEventListener('abort', close, { once: true });
    const timer = setTimeout(close, this.timeoutMs); let attempted = false;
    try {
      if (context.controller.signal.aborted || controller.signal.aborted) throw new Error('Closed policy operation');
      await this.authority(context.authorization, context.claims);
      if (context.sourceCheck) await context.sourceCheck();
      if (context.controller.signal.aborted || controller.signal.aborted || !freshPolicyAuthentication(context.claims)) throw new Error('Expired policy operation');
      attempted = true;
      if(method==='POST')context.attemptedWrite=true;
      const response = await this.fetch(this.origins[service] + pathname, { method, redirect: 'error', cache: 'no-store', signal: controller.signal,
        headers: { Authorization: context.authorization, Accept: 'application/json', 'X-OD-Operation-Id': context.operationId, ...(body ? { 'Content-Type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}) });
      if (!response.ok) throw new PolicyDeliveryError([401, 403, 428].includes(response.status) ? response.status : 502, 'policy_delivery_rejected', true);
      if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('Invalid delivery response');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 2 * 1024 * 1024) throw new Error('Oversized delivery response'); chunks.push(Buffer.from(chunk)); }
      const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (service === 'devices' && method === 'GET' && pathname === '/api/devices/policy-command-access') {
        if (response.status !== 200) throw new Error('Unconfirmed policy receiver');
        commandContract.protocol(data, context.claims); context.receiverConfirmed = true;
      }
      if (service === 'devices' && method === 'GET' && ['/api/devices/registry','/api/devices/policy-registry'].includes(pathname) && (response.status !== 200 || !Array.isArray(data) || data.length > 10000
        || data.some(device => !device || typeof device.id !== 'string' || !/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(device.id)))) throw new Error('Invalid device inventory');
      if (service === 'devices' && method === 'POST') {
        if (response.status !== 201 || data?.command !== 'update_policy' || data.status !== 'pending' || data.enforcementConfirmed !== false
          || !commandContract.same(data.payload, context.payloads[body.reference.configurationId || 'gpo'])) throw new Error('Unconfirmed queued command');
        commandContract.receipt(data.policyReceipt, { reference: body.reference, commandId: data.id, operationId: context.operationId, deviceId: pathname.split('/')[3],
          operatorUserId: context.claims.identity_authorization.userId, configurationHash: context.binding.configurationHash, configurationVersion: context.binding.configurationVersion, publicationVersion: context.binding.version });
        if (Date.parse(data.policyReceipt.expiresAt) <= Date.now() || Date.parse(data.policyReceipt.expiresAt) > Math.min(context.claims.exp, context.claims.auth_time + 300) * 1000) throw new Error('Invalid queued command deadline');
      }
      if (context.controller.signal.aborted || controller.signal.aborted) throw new Error('Closed policy operation');
      await this.authority(context.authorization, context.claims);
      if (context.sourceCheck) await context.sourceCheck();
      if (context.controller.signal.aborted || controller.signal.aborted || !freshPolicyAuthentication(context.claims)) throw new Error('Expired policy operation');
      return { status: response.status, body: data };
    } catch (error) {
      context.controller.abort();
      if (error instanceof PolicyDeliveryError) { error.deliveryMayHaveOccurred=error.deliveryMayHaveOccurred||context.attemptedWrite===true;throw error; }
      throw new PolicyDeliveryError([401, 403, 409, 412, 428].includes(error.status) ? error.status : 503, 'policy_delivery_unconfirmed', attempted||context.attemptedWrite===true);
    } finally { clearTimeout(timer); controller.abort(); context.controller.signal.removeEventListener('abort', close); }
  }
}

module.exports = { PolicyDelivery, PolicyDeliveryError };
