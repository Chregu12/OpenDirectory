'use strict';

const contract = require('../../../../packages/policy-command-contract');

class PolicyCommandSource {
  constructor({ baseUrl = process.env.OAUTH_POLICY_SOURCE_URL || 'http://policy-service:3004', fetchImpl = (...args) => fetch(...args), timeoutMs = 5000 } = {}) {
    const origin = new URL(baseUrl);
    if (!['http:','https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('Fixed canonical policy origin required');
    this.origin = origin.origin; this.fetch = fetchImpl; this.timeoutMs = timeoutMs;
  }
  async frame(body, user, authorization, signal) {
    if (typeof authorization !== 'string' || !/^Bearer [^\r\n]+$/.test(authorization) || !contract.uuid(user?.identity_authorization?.userId)) contract.fail(503, 'original_policy_source_credentials_required');
    const controller = new AbortController(); const close = () => controller.abort(); const timer = setTimeout(close, this.timeoutMs);
    if (signal?.aborted) close(); signal?.addEventListener('abort', close, { once: true });
    try {
      const response = await this.fetch(this.origin + '/api/policies/delivery/frame', {
        method: 'POST', headers: { Authorization: authorization, Accept: 'application/json', 'Content-Type': 'application/json' },
        redirect: 'error', cache: 'no-store', signal: controller.signal, body: JSON.stringify(body),
      });
      if (response.status !== 200) contract.fail([400,401,403,404,409,412,428].includes(response.status) ? response.status : 503, 'canonical_policy_source_rejected');
      if (!response.headers.get('content-type')?.includes('application/json')) contract.fail(503, 'canonical_policy_source_invalid');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > contract.MAX_PAYLOAD_BYTES + 16384) contract.fail(503, 'canonical_policy_source_invalid'); chunks.push(Buffer.from(chunk)); }
      const result = contract.frame(JSON.parse(Buffer.concat(chunks).toString('utf8')), { ...body, operatorUserId: user.identity_authorization.userId });
      if (controller.signal.aborted) contract.fail(503, 'canonical_policy_source_unavailable'); return result;
    } catch (error) { if (error.status) throw error; contract.fail(503, 'canonical_policy_source_unavailable'); }
    finally { clearTimeout(timer); controller.abort(); signal?.removeEventListener('abort', close); }
  }
}
module.exports = { PolicyCommandSource };
