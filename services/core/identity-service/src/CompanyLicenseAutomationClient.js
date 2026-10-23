'use strict';
const { exact, identifier, fail } = require('../../../../packages/company-automation-contract');
const STEP_PATH = '/api/licenses/automation/groups/step';
class CompanyLicenseAutomationClient {
  constructor({ endpoint = (process.env.POLICY_SERVICE_URL || 'http://policy-service:3004') + STEP_PATH, fetchImpl = (...args) => fetch(...args) } = {}) {
    this.endpoint = new URL(endpoint); this.fetchImpl = fetchImpl;
    if (!['http:', 'https:'].includes(this.endpoint.protocol) || this.endpoint.pathname !== STEP_PATH || this.endpoint.username || this.endpoint.password || this.endpoint.search || this.endpoint.hash) throw new Error('Pinned license automation receiver required');
  }
  async observe(plan,user,authorization){
    const contract=require('../../../../packages/company-automation-change-contract');const endpoint=new URL(this.endpoint);endpoint.pathname=contract.OBSERVE_PATH;
    return contract.observation(await contract.exchange(endpoint,contract.OBSERVE_PATH,{grantId:plan.grant_id,scheduleId:plan.id,ruleId:plan.rule_id},authorization,this.fetchImpl),plan,user);
  }
  async step(job, user, authorization) {
    const input = { grantId: job.grant_id, jobId: job.id, leaseToken: job.lease_token, ruleId: job.rule_id };
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await this.fetchImpl(this.endpoint, { method: 'POST', headers: { Authorization: authorization, Accept: 'application/json', 'Content-Type': 'application/json' }, body: JSON.stringify(input), redirect: 'error', cache: 'no-store', signal: controller.signal });
      if ([400, 401, 403, 404, 409, 412].includes(response.status)) fail(response.status, 'License automation rejected; earlier member steps may be committed');
      if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') || '')) throw new Error('License receiver unavailable');
      const chunks = []; let bytes = 0;
      for await (const chunk of response.body) { if (controller.signal.aborted) throw new Error('License step expired'); bytes += chunk.length; if (bytes > 4 * 1024 * 1024) throw new Error('License result exceeds boundary'); chunks.push(Buffer.from(chunk)); }
      const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      exact(value, ['schemaVersion', 'companyLicenseAutomationProtocol', 'grantId', 'jobId', 'ruleId', 'actor', 'progress', 'finished', 'hasBlocked', 'results']);
      exact(value.actor, ['kind', 'id', 'clientId', 'clientRevision']); exact(value.progress, ['runId', 'retryCount', 'cycle', 'completed', 'total', 'blocked']);
      if (value.schemaVersion !== 1 || value.companyLicenseAutomationProtocol !== 1 || value.grantId !== input.grantId || value.jobId !== input.jobId || value.ruleId !== input.ruleId
        || value.actor.kind !== 'application' || value.actor.id !== input.grantId || value.actor.clientId !== user.client_id || value.actor.clientRevision !== user.client_revision
        || value.progress.runId !== input.jobId || value.progress.retryCount !== job.retry_count || !Number.isInteger(value.progress.cycle) || value.progress.cycle < 1 || value.progress.cycle > 5
        || ['completed', 'total', 'blocked'].some(key => !Number.isInteger(value.progress[key]) || value.progress[key] < 0 || value.progress[key] > 10000)
        || value.progress.completed > value.progress.total || value.progress.blocked > value.progress.completed || value.finished !== (value.progress.completed === value.progress.total)
        || value.hasBlocked !== (value.progress.blocked > 0) || !Array.isArray(value.results) || value.results.length !== (value.finished ? value.progress.total : 0)) throw new Error('License progress unconfirmed');
      const seen = new Set();
      for (const item of value.results) { exact(item, ['userId', 'status', 'code']); identifier(item.userId); if (seen.has(item.userId) || !['assigned', 'retained', 'removed', 'blocked'].includes(item.status) || (item.status === 'blocked' ? ![403, 404, 409].includes(item.code) : item.code !== null)) throw new Error('License member result unconfirmed'); seen.add(item.userId); }
      if (controller.signal.aborted || value.finished && value.results.filter(item => item.status === 'blocked').length !== value.progress.blocked) throw new Error('License result unconfirmed');
      return value;
    } catch (error) { if (error.status) throw error; fail(503, 'License step unconfirmed; durable member receipts may already exist'); }
    finally { clearTimeout(timer); controller.abort(); }
  }
}
module.exports = { CompanyLicenseAutomationClient, STEP_PATH };
