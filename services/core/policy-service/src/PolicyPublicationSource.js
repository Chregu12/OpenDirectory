'use strict';

const { validRevision } = require('../../../../packages/identity-authorization-contract');
const { identifier, fail } = require('./PolicyConfiguration');

class PolicyPublicationSource {
  constructor({ baseUrl = process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', fetchImpl = (...args) => fetch(...args), timeoutMs = 5000 } = {}) {
    const origin = new URL(baseUrl);
    if (!['http:', 'https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash || origin.pathname !== '/') throw new Error('Fixed policy authority origin required');
    this.origin = origin.origin; this.fetch = fetchImpl; this.timeoutMs = timeoutMs;
  }
  async actor(id, authorization, signal) {
    identifier(id);
    if (typeof authorization !== 'string' || !/^Bearer [^\r\n]+$/.test(authorization)) fail(503, 'policy_publication_source_unavailable');
    const controller = new AbortController(); const close = () => controller.abort();
    if (signal?.aborted) close(); signal?.addEventListener('abort', close, { once: true });
    const timer = setTimeout(close, this.timeoutMs);
    try {
      const response = await this.fetch(`${this.origin}/api/policy-publication-actors/${id}/snapshot`, {
        headers: { Authorization: authorization, Accept: 'application/json' }, redirect: 'error', cache: 'no-store', signal: controller.signal,
      });
      if(response.status===200 && response.headers.get('x-od-license-snapshot-protocol')!=='1')fail(503,'tenant_bound_publication_source_required');
      if (response.status !== 200) fail([401, 403, 404].includes(response.status) ? response.status : 503, 'policy_publication_source_unavailable');
      if (!response.headers.get('content-type')?.includes('application/json')) fail(503, 'policy_publication_source_invalid');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { length += chunk.length; if (length > 4096) fail(503, 'policy_publication_source_invalid'); chunks.push(Buffer.from(chunk)); }
      const row = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!row || Object.keys(row).length !== 7 || row.schemaVersion !== 1 || row.userId !== id || !validRevision(row.revision)
        || typeof row.enabled !== 'boolean' || typeof row.linked !== 'boolean'
        || ['requestRevision', 'reviewRevision'].some(field => row[field] !== null && (typeof row[field] !== 'string' || !/^[a-f0-9]{64}$/.test(row[field]) || !row.enabled || !row.linked))) fail(503, 'policy_publication_source_invalid');
      if (controller.signal.aborted) fail(503, 'policy_publication_source_unavailable'); return row;
    } catch (error) { if (error.status) throw error; fail(503, 'policy_publication_source_unavailable'); }
    finally { clearTimeout(timer); controller.abort(); signal?.removeEventListener('abort', close); }
  }
}
module.exports = { PolicyPublicationSource };
