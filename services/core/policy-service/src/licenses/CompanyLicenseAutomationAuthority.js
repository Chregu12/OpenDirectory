'use strict';
const { SOURCE_PATH, validSource } = require('../../../../../packages/company-license-automation-contract');
const { identifier, workload, fail } = require('../../../../../packages/company-automation-contract');
class CompanyLicenseAutomationAuthority {
  constructor(context, { endpoint = (process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001') + SOURCE_PATH, fetchImpl = (...args) => fetch(...args) } = {}) {
    for (const key of ['grantId', 'jobId', 'leaseToken', 'ruleId']) identifier(context[key]); if (context.groupId !== null) identifier(context.groupId);
    this.context = { ...context }; this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.pathname !== SOURCE_PATH || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash) throw new Error('Pinned company automation source origin required');
  }
  async read(authorization, user, userId = null) {
    workload(user, user?.iss); if (userId !== null) identifier(userId);
    if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || authorization.length > 16384) fail(401, 'Original automation app bearer required');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 2500);
    try {
      const { ruleId, ...context } = this.context;
      const response = await this.fetchImpl(this.endpoint, { method: 'POST', headers: { Authorization: authorization, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ ...context, userId }), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404].includes(response.status)) throw Object.assign(new Error('Original app grant or job lease rejected'), { status: response.status, authorityDenied: true });
      if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('Canonical automation source unavailable');
      const chunks = []; let length = 0;
      for await (const chunk of response.body) { if (controller.signal.aborted) throw new Error('Source deadline expired'); length += chunk.length; if (length > 4 * 1024 * 1024 + 8192) throw new Error('Source exceeds complete group limit'); chunks.push(Buffer.from(chunk)); }
      const source = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (controller.signal.aborted || !validSource(source, user, userId) || source.ruleId !== ruleId || source.grantId !== context.grantId || source.jobId !== context.jobId || source.leaseToken !== context.leaseToken || (source.group?.groupId || null) !== context.groupId) throw new Error('Original app source substituted');
      return source;
    } catch (error) { if (error.status) throw error; fail(503, 'Canonical app license source unavailable'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyLicenseAutomationAuthority };
