import { randomUUID, createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import contract from '../../packages/company-automation-contract.js';
const base = '/api/identity/automation';
function checked(response, statuses = [200], kind = 'application') {
  if (!statuses.includes(response.status) || response.data?.schemaVersion !== 1 || response.data?.companyAutomationProtocol !== 1) throw new Error('Automation result unconfirmed; inspect stored jobs before retrying');
  const principal = response.data.principal;
  if (principal?.kind !== kind) throw new Error('Automation principal unconfirmed');
  if (kind === 'owner') { contract.identifier(principal.userId); contract.identifier(principal.tenantId); }
  else if (typeof principal.clientId !== 'string' || !contract.CLIENT_ID.test(principal.clientId) || typeof principal.clientRevision !== 'string' || !/^[1-9][0-9]*$/.test(principal.clientRevision)) throw new Error('Automation principal unconfirmed');
  return response.data;
}
function grant(value, principal) {
  if (!value || typeof value.clientRevision !== 'string' || !/^[1-9][0-9]*$/.test(value.clientRevision) || !['active','revoked'].includes(value.status)
    || value.revision !== (value.status === 'active' ? '1' : '2') || !Number.isFinite(Date.parse(value.expiresAt))) throw new Error('Grant unconfirmed');
  for (const field of ['id','enrollmentId','tenantId']) contract.identifier(value[field]); contract.actions(value.actions);
  if (principal.kind === 'owner' ? value.tenantId !== principal.tenantId : value.clientId !== principal.clientId || value.clientRevision !== principal.clientRevision) throw new Error('Grant principal unconfirmed');
  return value;
}
function job(value, grantId) {
  for (const field of ['id','grantId','tenantId']) contract.identifier(value?.[field]);
  if (value.grantId !== grantId || !contract.ACTIONS.includes(value.action) || !['json','csv'].includes(value.format) || !['queued','running','retry_wait','succeeded','partial','failed','cancelled'].includes(value.status)
    || typeof value.revision !== 'string' || !/^[1-9][0-9]*$/.test(value.revision) || !Number.isInteger(value.attemptCount) || value.attemptCount < 0 || value.attemptCount > 5) throw new Error('Job target unconfirmed');
  if(contract.reconciliation(value.action)){contract.identifier(value.ruleId);if(value.format!=='json'||value.progress===undefined||!Number.isSafeInteger(value.retryCount)||value.retryCount<0)throw new Error('License job target unconfirmed');
    if(value.progress!==null){const progress=value.progress;contract.exact(progress,['runId','retryCount','cycle','completed','total','blocked']);if(progress.runId!==value.id||!Number.isInteger(progress.retryCount)||progress.retryCount<0||progress.retryCount>value.retryCount||!Number.isInteger(progress.cycle)||progress.cycle<1||progress.cycle>5||['completed','total','blocked'].some(key=>!Number.isInteger(progress[key])||progress[key]<0||progress[key]>10000)||progress.blocked>progress.completed||progress.completed>progress.total)throw new Error('License progress unconfirmed');}
    if(['succeeded','partial'].includes(value.status)&&(!value.progress||value.progress.retryCount!==value.retryCount||value.progress.completed!==value.progress.total||value.rowCount!==value.progress.total||(value.status==='partial')!==(value.progress.blocked>0)||typeof value.artifactSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.artifactSha256)))throw new Error('License completion unconfirmed');
  }else if(value.ruleId!==undefined||value.progress!==undefined||value.status==='partial')throw new Error('Unexpected license progress');
  return value;
}
export async function runAutomationWorker(automation, grantId, { once = false, signal, onResult = () => {}, onRetry = () => {} } = {}) {
  contract.identifier(grantId); let failures = 0;
  while (!signal?.aborted) {
    let seconds = 5;
    try { const value = await automation.run(grantId); if (value) onResult(value); failures = 0; }
    catch (error) {
      if (once || error.status && error.status >= 400 && error.status < 500 && error.status !== 429) throw error;
      seconds = Math.min(300, 5 * 2 ** Math.min(6, failures++)); onRetry(seconds);
    }
    if (once || signal?.aborted) break;
    try { await delay(seconds * 1000, undefined, { signal }); } catch (error) { if (!signal?.aborted) throw error; }
  }
}
export function createAutomationClient(client) {
  const request = (method, path, body, administrative = false, etag) => client.request(method, base + path, body, { administrative, etag });
  return {
    async enroll(name) {
      const input = { id: randomUUID(), name: contract.text(name, 1, 160) }; const value = checked(await request('POST', '/enrollments', input), [201]);
      if (value.id !== input.id || value.name !== input.name || value.clientId !== value.principal.clientId || value.clientRevision !== value.principal.clientRevision || value.requestedScope !== contract.SCOPE || Date.parse(value.expiresAt) <= Date.now() || !Number.isFinite(Date.parse(value.expiresAt))) throw new Error('Enrollment unconfirmed'); return value;
    },
    async enrollment(id) { contract.identifier(id); const value = checked(await request('GET', '/enrollments/' + id, undefined, true), [200], 'owner'); if (value.id !== id) throw new Error('Enrollment target unconfirmed'); return value; },
    async approve(enrollmentId, clientId, clientRevision, actions, durationSeconds = 86400) {
      const input = contract.grantInput({ id: randomUUID(), enrollmentId, clientId, clientRevision, actions, expiresAt: new Date(Date.now() + durationSeconds * 1000).toISOString(), reason: 'Explizite eigene App-Automationsfreigabe über CLI', confirm: true });
      const value = checked(await request('POST', '/grants', input, true), [201], 'owner'); const actual = grant(value.grant, value.principal);
      if (actual.id !== input.id || actual.enrollmentId !== input.enrollmentId || actual.clientId !== input.clientId || actual.clientRevision !== input.clientRevision || JSON.stringify(actual.actions) !== JSON.stringify(input.actions) || actual.expiresAt !== input.expiresAt || actual.status !== 'active') throw new Error('Approval unconfirmed'); return value;
    },
    async grants(administrative = false, page = 1) { if (!Number.isInteger(page) || page < 1) throw new Error('Positive page required'); const value = checked(await request('GET', '/grants?page=' + page, undefined, administrative), [200], administrative ? 'owner' : 'application'); if (value.page !== page || !Array.isArray(value.grants) || value.grants.length > 25) throw new Error('Grant page unconfirmed'); value.grants.forEach(row => grant(row,value.principal)); return value; },
    async enqueue(grantId, action, format = 'json', ruleId) {
      const input = contract.jobInput({ id: randomUUID(), grantId, action, format, ...(ruleId === undefined ? {} : { ruleId }) }); const value = checked(await request('POST', '/jobs', input), [201]); const actual = job(value.job, grantId);
      if (actual.id !== input.id || actual.action !== action || actual.format !== format || actual.status !== 'queued' || actual.ruleId !== ruleId) throw new Error('Queueing unconfirmed'); return value;
    },
    async schedule(grantId, action, intervalSeconds, format = 'json', ruleId) {
      const input = contract.jobInput({ id: randomUUID(), grantId, action, format, intervalSeconds, ...(ruleId === undefined ? {} : { ruleId }) }, true); const value = checked(await request('POST', '/schedules', input), [201]); const actual = value.schedule;
      if (!actual || actual.id !== input.id || actual.grantId !== grantId || actual.action !== action || actual.format !== format || actual.ruleId !== ruleId || actual.intervalSeconds !== intervalSeconds || actual.enabled !== true) throw new Error('Schedule unconfirmed'); contract.identifier(actual.tenantId); return value;
    },
    async jobs(grantId, page = 1, administrative = false) { contract.identifier(grantId); if (!Number.isInteger(page) || page < 1) throw new Error('Positive page required'); const value = checked(await request('GET', '/jobs?grantId=' + grantId + '&page=' + page, undefined, administrative), [200], administrative ? 'owner' : 'application'); if (value.page !== page || value.grantId !== grantId || !Array.isArray(value.jobs) || value.jobs.length > 25) throw new Error('Job page unconfirmed'); value.jobs.forEach(row => job(row,grantId)); return value; },
    async schedules(grantId, page = 1) { contract.identifier(grantId); if (!Number.isInteger(page) || page < 1) throw new Error('Positive page required'); return checked(await request('GET', '/schedules?grantId=' + grantId + '&page=' + page)); },
    async run(grantId) { contract.identifier(grantId); const result = await request('POST', '/run', { grantId }); if (result.status === 204) return null; const value = checked(result); job(value.job,grantId); return value; },
    async result(jobId) {
      // JSON escaping can expand a valid four-MiB CSV artifact by up to six times.
      contract.identifier(jobId); const result = checked(await client.request('GET', base + '/jobs/' + jobId + '/result', undefined, { maxResponseBytes: 32 * 1024 * 1024 }));
      if (result.jobId !== jobId || typeof result.content !== 'string' || Buffer.byteLength(result.content) > 4194304 || !['application/json', 'text/csv;charset=utf-8'].includes(result.contentType)
        || createHash('sha256').update(result.content).digest('hex') !== result.sha256) throw new Error('Artifact target or hash unconfirmed'); return result;
    },
    async history(jobId, page = 1) { contract.identifier(jobId); if (!Number.isInteger(page) || page < 1) throw new Error('Positive page required'); const result = checked(await request('GET', '/jobs/' + jobId + '/history?page=' + page)); if (result.jobId !== jobId) throw new Error('History target unconfirmed'); return result; },
    async revoke(grantId, revision) { contract.identifier(grantId); if (!/^[1-9][0-9]*$/.test(revision)) throw new Error('Observed grant revision required'); const value = checked(await request('POST', '/grants/' + grantId + '/revoke', { confirm: true }, true, `"company-automation-grant-${grantId}-${revision}"`), [200], 'owner'); const actual = grant(value.grant,value.principal); if (actual.id !== grantId || actual.status !== 'revoked') throw new Error('Revocation unconfirmed'); return value; },
  };
}
