'use strict';
const { randomUUID, createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { v5 } = require('uuid');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority');
const { ownerState } = require('./CompanyOwner');
const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { SCOPE, ACTIONS, LICENSE_ACTION, GROUP_ACTION, reconciliation, fail, exact, identifier, text, workload, grantInput, jobInput } = require('../../../../packages/company-automation-contract');
const hash = value => createHash('sha256').update(value).digest('hex');
const iso = value => new Date(value).toISOString();
const base = { schemaVersion: 1, companyAutomationProtocol: 1 };
function pageNumber(value) { if (value === undefined) return 1; if (typeof value !== 'string' || !/^[1-9][0-9]{0,5}$/.test(value)) fail(400, 'Positive scalar page required'); return Number(value); }
const grantView = row => ({ id: row.id, enrollmentId: row.enrollment_id, tenantId: row.tenant_id, clientId: row.client_id, clientRevision: String(row.client_revision), actions: row.actions,
  expiresAt: iso(row.expires_at), status: row.status, revision: String(row.revision), createdAt: iso(row.created_at) });
const jobView = row => ({ id: row.id, grantId: row.grant_id, tenantId: row.tenant_id, scheduleId: row.schedule_id, action: row.action, format: row.format, status: row.status,
  revision: String(row.revision), attemptCount: row.attempt_count, retryCount: row.retry_count, availableAt: iso(row.available_at), leaseUntil: row.lease_until ? iso(row.lease_until) : null,
  errorCode: row.error_code, rowCount: row.row_count, artifactSha256: row.artifact_sha256, createdAt: iso(row.created_at), updatedAt: iso(row.updated_at),
  ...(reconciliation(row.action) ? { ruleId: row.rule_id, progress: row.progress } : {}), ...(row.event_source ? {trigger:{kind:'change',groupId:row.event_source.identity.groupId,sourceRevision:row.event_source.identity.revision,deadlineRevision:row.event_source.identity.deadlineRevision,...(row.event_source.policy?{poolId:row.event_source.policy.poolId,poolRevision:row.event_source.policy.poolRevision,availableSeats:row.event_source.policy.availableSeats}:{})}} : {}) });
const scheduleView = row => ({ id: row.id, grantId: row.grant_id, tenantId: row.tenant_id, action: row.action, format: row.format, intervalSeconds: row.interval_seconds,
  enabled: row.enabled, nextRunAt: iso(row.next_run_at), revision: String(row.revision), createdAt: iso(row.created_at), ...(reconciliation(row.action) ? { ruleId: row.rule_id } : {}), ...(row.on_change ? {onChange:true,lastSourceRevision:row.source_checkpoint?.identity.revision||null,lastDeadlineRevision:row.source_checkpoint?.identity.deadlineRevision??null} : {}) });
function csv(rows, columns) {
  const cell = value => '"' + String(value ?? '').replace(/^(?=\s*[=+@\-\t\r\n])/, "'").replaceAll('"', '""') + '"';
  return [columns.map(cell).join(','), ...rows.map(row => columns.map(column => cell(row[column])).join(','))].join('\r\n') + '\r\n';
}
class CompanyAutomation {
  constructor(database, { authority = new CompanyLicenseAuthority(database), issuer = process.env.OIDC_ISSUER || 'http://localhost:3001', revalidate = createAccessStateClient(), licenseClient = new (require('./CompanyLicenseAutomationClient').CompanyLicenseAutomationClient)() } = {}) {
    Object.assign(this, { database, authority, issuer, revalidate, licenseClient });
  }
  async actor(user, authorization, ownerOnly = false) {
    if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization) || authorization.length > 16384) fail(401, 'Original automation bearer required');
    if (user?.actor_type === 'application' && !ownerOnly) {
      const proof = workload(user, this.issuer); await this.revalidate(authorization, user); workload(user, this.issuer); return proof;
    }
    const source = await this.authority.read(user, authorization);
    const owner = await this.database.transaction(client => ownerState(client, source.actorUserId), { readOnly: true });
    if (!owner?.active || owner.tenant_id !== source.tenant.id || owner.issuer !== source.issuer || owner.subject !== source.subject) fail(403, 'Actual company owner required for automation approval');
    return { kind: 'owner', source };
  }
  async unchanged(actor, user, authorization) {
    if (!isDeepStrictEqual(actor, await this.actor(user, authorization, actor.kind === 'owner'))) fail(401, 'Original automation authority changed');
  }
  async transaction(user, authorization, operation, { ownerOnly = false, readOnly = false } = {}) {
    const actor = await this.actor(user, authorization, ownerOnly);
    const result = await this.database.transaction(async client => {
      await client.query("SET LOCAL timezone='UTC'"); await client.query('SELECT identity_automation_receiving()');
      await client.query("SELECT set_config('opendirectory.company_automation',$1,true)", [JSON.stringify(actor)]);
      const result = await operation(client, actor); await this.unchanged(actor, user, authorization); return result;
    }, { readOnly });
    await this.unchanged(actor, user, authorization);
    return result?.companyAutomationProtocol === 1 ? { ...result, principal: actor.kind === 'owner'
      ? { kind: 'owner', userId: actor.source.actorUserId, tenantId: actor.source.tenant.id }
      : { kind: 'application', clientId: actor.clientId, clientRevision: actor.clientRevision } } : result;
  }
  async grant(client, id, actor, { live = true, lock = 'SHARE' } = {}) {
    identifier(id);
    const row = (await client.query(`SELECT permission.*,identity_automation_grant_live(permission.id) AS live FROM identity_automation_grants permission WHERE id=$1${lock ? ' FOR ' + lock : ''}`, [id])).rows[0];
    if (!row || (actor.kind === 'owner' ? row.tenant_id !== actor.source.tenant.id : row.issuer !== actor.issuer || row.client_id !== actor.clientId || String(row.client_revision) !== actor.clientRevision)) fail(404, 'Own automation grant not found');
    await this.retained(client, 'grant', id);
    if (live && row.live !== true) fail(403, 'Automation grant revoked, expired or original company authority changed'); return row;
  }
  async retained(client, entity, id) {
    const table = { grant: 'identity_automation_grants', job: 'identity_automation_jobs', schedule: 'identity_automation_schedules' }[entity];
    if (!table) fail(503, 'Unsupported automation evidence');
    const valid = (await client.query(`SELECT EXISTS(SELECT 1 FROM ${table} target JOIN identity_automation_events event ON event.entity=$2 AND event.entity_id=target.id AND event.revision=target.revision
      JOIN identity_automation_outbox box ON box.id=event.id AND box.status='pending' WHERE target.id=$1 AND event.snapshot=identity_automation_snapshot(to_jsonb(target))) AS valid`, [id, entity])).rows[0].valid;
    if (valid !== true) fail(503, 'Retained original automation evidence unavailable');
  }
  async enroll(body, user, authorization) {
    exact(body, ['id', 'name']); identifier(body.id); const name = text(body.name, 1, 160); workload(user, this.issuer);
    return this.transaction(user, authorization, async (client, actor) => {
      const previous = (await client.query('SELECT * FROM identity_automation_enrollments WHERE id=$1', [body.id])).rows[0];
      if (previous) {
        if (previous.issuer !== actor.issuer || previous.client_id !== actor.clientId || String(previous.client_revision) !== actor.clientRevision || previous.name !== name || previous.expires_at <= new Date()) fail(409, 'Enrollment key changed or expired');
        return this.enrollmentView(previous);
      }
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', ['automation-enrollment:' + actor.issuer + ':' + actor.clientId]);
      if (Number((await client.query('SELECT count(*) AS n FROM identity_automation_enrollments WHERE issuer=$1 AND client_id=$2 AND expires_at>clock_timestamp()', [actor.issuer, actor.clientId])).rows[0].n) >= 10) fail(429, 'Too many pending enrollments');
      const row = (await client.query("INSERT INTO identity_automation_enrollments(id,issuer,client_id,client_revision,name,expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '5 minutes') RETURNING *", [body.id, actor.issuer, actor.clientId, actor.clientRevision, name])).rows[0];
      return this.enrollmentView(row);
    });
  }
  enrollmentView(row) { return { ...base, id: row.id, clientId: row.client_id, clientRevision: String(row.client_revision), name: row.name, expiresAt: iso(row.expires_at), requestedScope: SCOPE }; }
  async enrollment(id, user, authorization) {
    identifier(id); return this.transaction(user, authorization, async client => {
      const row = (await client.query('SELECT * FROM identity_automation_enrollments WHERE id=$1 AND expires_at>clock_timestamp()', [id])).rows[0];
      if (!row) fail(404, 'Current enrollment not found'); return this.enrollmentView(row);
    }, { ownerOnly: true, readOnly: true });
  }
  async watchSource(body,user,authorization){
    const contract=require('../../../../packages/company-automation-change-contract');contract.input(body);workload(user,this.issuer);
    return this.transaction(user,authorization,async(client,actor)=>{
      const permission=await this.grant(client,body.grantId,actor,{lock:''});
      if(!permission.actions.includes(LICENSE_ACTION))fail(403,'License change observation not delegated');
      const plan=(await client.query("SELECT * FROM identity_automation_schedules WHERE id=$1 AND grant_id=$2 AND enabled AND on_change AND action=$3 AND rule_id=$4",[body.scheduleId,permission.id,LICENSE_ACTION,body.ruleId])).rows[0];
      if(!plan)fail(404,'Current own license change subscription required');await this.retained(client,'schedule',plan.id);
      return{schemaVersion:1,companyAutomationChangeProtocol:1,grantId:permission.id,scheduleId:plan.id,scheduleRevision:String(plan.revision),ruleId:plan.rule_id,tenant:permission.approval.tenant,
       issuer:actor.issuer,subject:actor.clientId,clientRevision:actor.clientRevision,tokenIdentifierHash:contract.tokenHash(user),validUntil:Math.min(user.exp,Math.floor(permission.expires_at.getTime()/1000))};
    },{readOnly:true});
  }
  async licenseSource(body, user, authorization) {
    exact(body, ['grantId', 'jobId', 'leaseToken', 'groupId', 'userId']);
    for (const key of ['grantId', 'jobId', 'leaseToken']) identifier(body[key]); if (body.groupId !== null) identifier(body.groupId); if (body.userId !== null) { identifier(body.userId); if (body.groupId === null) fail(400, 'Group-bound license recipient required'); }
    workload(user, this.issuer);
    return this.transaction(user, authorization, async (client, actor) => {
      const permission = await this.grant(client, body.grantId, actor, { lock: '' });
      const job = (await client.query('SELECT * FROM identity_automation_jobs WHERE id=$1 AND grant_id=$2', [body.jobId, permission.id])).rows[0];
      if (!job || job.action !== LICENSE_ACTION || job.status !== 'running' || job.lease_token !== body.leaseToken || job.lease_until <= new Date()) fail(403, 'Current original license job lease required');
      await this.retained(client, 'job', job.id);
      if ((await client.query("SELECT identity_tenant_id('user',$1::uuid) AS human,identity_tenant_id('group',$2::uuid) AS group_owner", [permission.id, body.groupId])).rows.some(row => row.human !== null || body.groupId !== null && row.group_owner !== permission.tenant_id)) fail(404, 'Own license job source unavailable');
      let group = null;
      if (body.groupId !== null) {
        const snapshot = await new (require('./GroupSnapshotStore').GroupSnapshotStore)(this.database).readSnapshot(client, body.groupId, { refreshReviews: false });
        const { viewerUserId, viewerEnabled, sourceAuthorization, observedAt, validUntil, ...content } = snapshot; group = content;
      }
      let target = null;
      if (body.userId !== null) {
        if ((await client.query("SELECT identity_tenant_id('user',$1::uuid) AS tenant", [body.userId])).rows[0]?.tenant !== permission.tenant_id) fail(404, 'Own license recipient unavailable');
        const account = (await client.query('SELECT id,authorization_revision,eligibility_revision,identity_tenant_user_enabled(id) AS enabled FROM users WHERE id=$1', [body.userId])).rows[0];
        if (account) target = { id: account.id, revision: String(account.authorization_revision), eligibilityRevision: String(account.eligibility_revision), enabled: account.enabled, deleted: false };
        else {
          const deleted = (await client.query('SELECT revision FROM identity_deleted_users WHERE user_id=$1', [body.userId])).rows[0]; if (!deleted) fail(404, 'Own license recipient unavailable');
          target = { id: body.userId, revision: null, eligibilityRevision: String(deleted.revision), enabled: false, deleted: true };
        }
      }
      const deadline = Math.floor(Math.min(job.lease_until.getTime(), permission.expires_at.getTime(), user.exp * 1000,
        ...(group?.memberships || []).filter(member => member.reviewDeadlineAt !== null).map(member => Date.parse(member.reviewDeadlineAt))) / 1000);
      if (deadline * 1000 <= Date.now()) fail(403, 'Original license source deadline expired');
      return { schemaVersion: 1, companyLicenseAutomationProtocol: 1, kind: 'application', issuer: actor.issuer, subject: actor.clientId, tokenId: actor.tokenId, expiresAt: user.exp,
        clientRevision: actor.clientRevision, tenant: permission.approval.tenant, grantId: permission.id, jobId: job.id, leaseToken: body.leaseToken, ruleId: job.rule_id, retryCount: job.retry_count,
        validUntil: deadline, permissions: [LICENSE_ACTION], target, group };
    }, { readOnly: true });
  }
  async approve(body, user, authorization) {
    const input = grantInput(body);
    return this.transaction(user, authorization, async (client, actor) => {
      const existing = (await client.query('SELECT * FROM identity_automation_grants WHERE id=$1', [input.id])).rows[0];
      if (existing) {
        if (existing.tenant_id !== actor.source.tenant.id || existing.created_by !== actor.source.actorUserId || existing.enrollment_id !== input.enrollmentId || existing.client_id !== input.clientId
          || String(existing.client_revision) !== input.clientRevision || !isDeepStrictEqual(existing.actions, input.actions) || iso(existing.expires_at) !== input.expiresAt || existing.reason !== input.reason) fail(409, 'Original approval key changed');
        return { ...base, grant: grantView(existing) };
      }
      const row = (await client.query(`INSERT INTO identity_automation_grants(id,enrollment_id,tenant_id,issuer,client_id,client_revision,actions,created_by,approval,reason,expires_at,status)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'active') RETURNING *`, [input.id, input.enrollmentId, actor.source.tenant.id, actor.source.issuer, input.clientId,
        input.clientRevision, input.actions, actor.source.actorUserId, actor.source, input.reason, input.expiresAt])).rows[0];
      return { ...base, grant: grantView(row) };
    }, { ownerOnly: true });
  }
  async grants(user, authorization, query = {}) {
    if (Object.keys(query).some(key => key !== 'page')) fail(400, 'Exact grant page required');
    const page = pageNumber(query.page);
    return this.transaction(user, authorization, async (client, actor) => {
      const values = [actor.source?.tenant.id || null, actor.issuer || '', actor.clientId || '', actor.clientRevision || '0'];
      const where = ' WHERE ($1::uuid IS NOT NULL AND tenant_id=$1) OR ($1::uuid IS NULL AND issuer=$2 AND client_id=$3 AND client_revision=$4)';
      const total = Number((await client.query('SELECT count(*) AS n FROM identity_automation_grants' + where, values)).rows[0].n);
      const rows = (await client.query('SELECT * FROM identity_automation_grants' + where + ' ORDER BY created_at DESC,id LIMIT 25 OFFSET $5', [...values, (page - 1) * 25])).rows;
      for (const row of rows) await this.retained(client, 'grant', row.id);
      return { ...base, grants: rows.map(grantView), page, limit: 25, total, supportedActions: [...ACTIONS] };
    }, { readOnly: true });
  }
  version(entity, row, expected) {
    if (!expected) fail(428, 'Current automation If-Match required');
    if (expected !== `"company-automation-${entity}-${row.id}-${row.revision}"`) fail(412, 'Automation version changed');
  }
  async revoke(id, body, expected, user, authorization) {
    exact(body, ['confirm']); if (body.confirm !== true) fail(400, 'Confirm automation revocation');
    return this.transaction(user, authorization, async (client, actor) => {
      const original = await this.grant(client, id, actor, { live: false, lock: 'UPDATE' }); this.version('grant', original, expected);
      if (original.status !== 'active') fail(409, 'Already revoked');
      await client.query("UPDATE identity_automation_jobs SET status='cancelled',lease_token=NULL,lease_until=NULL,error_code='grant_revoked',revision=revision+1,updated_at=clock_timestamp() WHERE grant_id=$1 AND status IN('queued','retry_wait','running')", [id]);
      await client.query('UPDATE identity_automation_schedules SET enabled=false,revision=revision+1,updated_at=clock_timestamp() WHERE grant_id=$1 AND enabled', [id]);
      const row = (await client.query("UPDATE identity_automation_grants SET status='revoked',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *", [id])).rows[0];
      return { ...base, grant: grantView(row) };
    }, { ownerOnly: true });
  }
  async enqueue(body, user, authorization, scheduled = false) {
    const input = jobInput(body, scheduled);
    return this.transaction(user, authorization, async (client, actor) => {
      const permission = await this.grant(client, input.grantId, actor); if (!permission.actions.includes(input.action)) fail(403, 'Action not delegated');
      const table = scheduled ? 'identity_automation_schedules' : 'identity_automation_jobs';
      const previous = (await client.query('SELECT * FROM ' + table + ' WHERE id=$1', [input.id])).rows[0];
      if (previous) {
        if (previous.grant_id !== input.grantId || previous.action !== input.action || previous.format !== input.format || previous.rule_id !== (input.ruleId || null) || scheduled && (previous.interval_seconds !== (input.onChange ? null : input.intervalSeconds) || previous.on_change !== !!input.onChange)) fail(409, 'Original job key changed');
        return { ...base, [scheduled ? 'schedule' : 'job']: scheduled ? scheduleView(previous) : jobView(previous) };
      }
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', ['automation-quota:' + input.grantId]);
      const count = Number((await client.query('SELECT count(*) AS n FROM ' + table + (scheduled ? ' WHERE grant_id=$1 AND enabled' : " WHERE grant_id=$1 AND status IN('queued','retry_wait','running')"), [input.grantId])).rows[0].n);
      if (count >= (scheduled ? 100 : 1000)) fail(429, 'Automation pending capacity reached');
      if(scheduled&&input.onChange&&Number((await client.query('SELECT count(*) AS n FROM identity_automation_schedules WHERE grant_id=$1 AND enabled AND on_change',[input.grantId])).rows[0].n)>=25)fail(429,'At most 25 active change subscriptions per grant');
      const row = (await client.query(scheduled
        ? `INSERT INTO identity_automation_schedules(id,grant_id,tenant_id,action,format,rule_id,interval_seconds,on_change) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`
        : `INSERT INTO identity_automation_jobs(id,grant_id,tenant_id,action,format,rule_id,status) VALUES($1,$2,$3,$4,$5,$6,'queued') RETURNING *`,
      [input.id, input.grantId, permission.tenant_id, input.action, input.format, input.ruleId || null, ...(scheduled ? [input.onChange ? null : input.intervalSeconds,!!input.onChange] : [])])).rows[0];
      return { ...base, [scheduled ? 'schedule' : 'job']: scheduled ? scheduleView(row) : jobView(row) };
    });
  }
  async list(query, user, authorization, scheduled = false) {
    if (Object.keys(query).some(key => !['grantId', 'page'].includes(key))) fail(400, 'Exact automation page required'); identifier(query.grantId);
    const page = pageNumber(query.page);
    return this.transaction(user, authorization, async (client, actor) => {
      const permission = await this.grant(client, query.grantId, actor, { live: false, lock: '' }); const table = scheduled ? 'identity_automation_schedules' : 'identity_automation_jobs';
      const total = Number((await client.query('SELECT count(*) AS n FROM ' + table + ' WHERE grant_id=$1', [permission.id])).rows[0].n);
      const rows = (await client.query('SELECT * FROM ' + table + ' WHERE grant_id=$1 ORDER BY created_at DESC,id LIMIT 25 OFFSET $2', [permission.id, (page - 1) * 25])).rows;
      for (const row of rows) await this.retained(client, scheduled ? 'schedule' : 'job', row.id);
      return { ...base, grantId: permission.id, tenantId: permission.tenant_id, page, limit: 25, total, [scheduled ? 'schedules' : 'jobs']: rows.map(scheduled ? scheduleView : jobView) };
    }, { readOnly: true });
  }
  async job(client, id, actor, lock = '') {
    identifier(id); const candidate = (await client.query('SELECT grant_id FROM identity_automation_jobs WHERE id=$1', [id])).rows[0]; if (!candidate) fail(404, 'Job not found');
    await this.grant(client, candidate.grant_id, actor, { live: actor.kind === 'application', lock: lock ? 'SHARE' : '' });
    const row = (await client.query('SELECT * FROM identity_automation_jobs WHERE id=$1' + lock, [id])).rows[0]; await this.retained(client, 'job', row.id); return row;
  }
  async result(id, user, authorization) {
    return this.transaction(user, authorization, async (client, actor) => {
      const row = await this.job(client, id, actor); if (!['succeeded', 'partial'].includes(row.status)) fail(409, 'Job has no confirmed artifact');
      if (hash(row.artifact_content) !== row.artifact_sha256) fail(503, 'Artifact evidence unavailable');
      return { ...base, jobId: row.id, grantId: row.grant_id, tenantId: row.tenant_id, rowCount: row.row_count, sha256: row.artifact_sha256,
        contentType: row.artifact_type, filename: row.action.replaceAll('.', '-') + '-' + row.id + '.' + row.format, content: row.artifact_content };
    }, { readOnly: true });
  }
  async history(id, user, authorization, query = {}) {
    if (Object.keys(query).some(key => key !== 'page')) fail(400, 'Exact history page required');
    const page = pageNumber(query.page);
    return this.transaction(user, authorization, async (client, actor) => {
      const job = await this.job(client, id, actor);
      const total = Number((await client.query("SELECT count(*) AS n FROM identity_automation_events WHERE entity='job' AND entity_id=$1", [id])).rows[0].n);
      const rows = (await client.query("SELECT revision,actor,snapshot,created_at FROM identity_automation_events WHERE entity='job' AND entity_id=$1 ORDER BY revision LIMIT 25 OFFSET $2", [id, (page - 1) * 25])).rows;
      return { ...base, jobId: job.id, tenantId: job.tenant_id, page, limit: 25, total, events: rows.map(row => ({ revision: String(row.revision), actor: row.actor.kind === 'owner'
        ? { kind: 'owner', userId: row.actor.source.actorUserId } : { kind: 'application', clientId: row.actor.clientId, clientRevision: row.actor.clientRevision },
        status: row.snapshot.status, attemptCount: row.snapshot.attempt_count, errorCode: row.snapshot.error_code, createdAt: iso(row.created_at) })) };
    }, { readOnly: true });
  }
  async changeJob(id, action, expected, user, authorization) {
    return this.transaction(user, authorization, async (client, actor) => {
      const original = await this.job(client, id, actor, ' FOR UPDATE'); this.version('job', original, expected);
      const cancelling = action === 'cancel'; if (cancelling ? !['queued', 'retry_wait', 'running'].includes(original.status) : action !== 'retry' || !['failed', 'partial'].includes(original.status)) fail(409, 'Job transition unavailable');
      const row = (await client.query(cancelling
        ? "UPDATE identity_automation_jobs SET status='cancelled',lease_token=NULL,lease_until=NULL,error_code='cancelled',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *"
        : "UPDATE identity_automation_jobs SET status='queued',attempt_count=0,retry_count=retry_count+1,error_code=NULL,artifact_content=NULL,artifact_type=NULL,artifact_sha256=NULL,row_count=NULL,available_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *", [id])).rows[0];
      return { ...base, job: jobView(row) };
    });
  }
  async disableSchedule(id, expected, user, authorization) {
    identifier(id); return this.transaction(user, authorization, async (client, actor) => {
      const candidate = (await client.query('SELECT grant_id FROM identity_automation_schedules WHERE id=$1', [id])).rows[0]; if (!candidate) fail(404, 'Schedule not found');
      await this.grant(client, candidate.grant_id, actor, { live: actor.kind === 'application' });
      const original = (await client.query('SELECT * FROM identity_automation_schedules WHERE id=$1 FOR UPDATE', [id])).rows[0]; this.version('schedule', original, expected);
      await this.retained(client, 'schedule', original.id);
      if (!original.enabled) fail(409, 'Schedule already stopped');
      const row = (await client.query('UPDATE identity_automation_schedules SET enabled=false,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *', [id])).rows[0]; return { ...base, schedule: scheduleView(row) };
    });
  }
  async export(client, permission, action, format) {
    if (reconciliation(action)) fail(503, 'License reconciliation requires its own receiving handler');
    let rows, columns;
    if (action === 'directory.users.export') {
      rows = (await client.query("SELECT id,username,email,display_name,department,title,enabled FROM users WHERE identity_tenant_id('user',id)=$1 ORDER BY id LIMIT 10001", [permission.tenant_id])).rows;
      columns = ['id', 'username', 'email', 'display_name', 'department', 'title', 'enabled'];
    } else if (action === 'directory.groups.export') {
      rows = await new (require('./DirectoryReader').DirectoryReader)(this.database).readGroups(client, permission.tenant_id);
      rows = rows.map(row => ({ id: row.id, name: row.name, description: row.description || '', members: JSON.stringify(row.members), revision: row.revision }));
      columns = ['id', 'name', 'description', 'members', 'revision'];
    } else {
      rows = await new (require('./DirectoryReader').DirectoryReader)(this.database).readOus(client, permission.tenant_id);
      rows = rows.map(row => ({ id: row.id, name: row.name, description: row.description || '', parent_id: row.parentId || null, revision: row.revision }));
      columns = ['id', 'name', 'description', 'parent_id', 'revision'];
    }
    if (rows.length > 10000) fail(409, 'Export exceeds the complete 10000-row limit');
    const content = format === 'json' ? JSON.stringify({ action, tenantId: permission.tenant_id, rows }) : csv(rows, columns);
    if (Buffer.byteLength(content) > 4194304) fail(409, 'Export exceeds artifact size limit');
    return { content, contentType: format === 'json' ? 'application/json' : 'text/csv;charset=utf-8', rowCount: rows.length, sha256: hash(content) };
  }
  async run(body, user, authorization) {
    exact(body, ['grantId']); identifier(body.grantId); workload(user, this.issuer);
    const changes=new(require('./CompanyAutomationChanges').CompanyAutomationChanges)(this);const collected=await changes.collect(body.grantId,user,authorization);
    const claimed = await this.transaction(user, authorization, async (client, actor) => {
      const permission = await this.grant(client, body.grantId, actor);
      await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', ['automation-quota:' + permission.id]);
      await changes.dispatch(client,permission,collected);
      const schedules = (await client.query('SELECT * FROM identity_automation_schedules WHERE grant_id=$1 AND enabled AND NOT on_change AND next_run_at<=clock_timestamp() ORDER BY next_run_at,id FOR UPDATE SKIP LOCKED LIMIT 10', [permission.id])).rows;
      for (const schedule of schedules) {
        await this.retained(client, 'schedule', schedule.id);
        if (Number((await client.query("SELECT count(*) AS n FROM identity_automation_jobs WHERE grant_id=$1 AND status IN('queued','running','retry_wait')", [permission.id])).rows[0].n) >= 1000) break;
        const id = v5(iso(schedule.next_run_at), schedule.id);
        const continuing = reconciliation(schedule.action) && (await client.query("SELECT EXISTS(SELECT 1 FROM identity_automation_jobs WHERE schedule_id=$1 AND status IN('queued','running','retry_wait')) AS pending", [schedule.id])).rows[0].pending;
        if (!continuing) await client.query("INSERT INTO identity_automation_jobs(id,grant_id,tenant_id,schedule_id,action,format,rule_id,status) VALUES($1,$2,$3,$4,$5,$6,$7,'queued') ON CONFLICT DO NOTHING", [id, permission.id, permission.tenant_id, schedule.id, schedule.action, schedule.format, schedule.rule_id]);
        await client.query("UPDATE identity_automation_schedules SET next_run_at=clock_timestamp()+interval_seconds*interval '1 second',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1", [schedule.id]);
      }
      const expired = (await client.query("UPDATE identity_automation_jobs SET status='failed',lease_token=NULL,lease_until=NULL,error_code='lease_expired',revision=revision+1,updated_at=clock_timestamp() WHERE grant_id=$1 AND status='running' AND lease_until<=clock_timestamp() AND attempt_count=5 RETURNING *", [permission.id])).rows;
      const candidate = (await client.query(`SELECT * FROM identity_automation_jobs WHERE grant_id=$1 AND attempt_count<5 AND
        (status IN('queued','retry_wait') AND available_at<=clock_timestamp() OR status='running' AND lease_until<=clock_timestamp()) ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1`, [permission.id])).rows[0];
      if (!candidate) return expired.length ? { ...base, job: jobView(expired[0]) } : null;
      await this.retained(client, 'job', candidate.id);
      return (await client.query(`UPDATE identity_automation_jobs SET status='running',attempt_count=attempt_count+1,lease_token=$2,
        lease_until=LEAST(clock_timestamp()+interval '45 seconds',to_timestamp($3),$4::timestamptz),revision=revision+1,error_code=NULL,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,
      [candidate.id, randomUUID(), user.exp, permission.expires_at])).rows[0];
    });
    if (!claimed){if(collected.errors.length)fail(503,'Change sources unavailable; checkpoints retained for '+collected.errors.map(item=>item.scheduleId).join(','));return null;}
    if (claimed.companyAutomationProtocol === 1) return claimed;
    try {
      return await this.transaction(user, authorization, async (client, actor) => {
        const permission = await this.grant(client, claimed.grant_id, actor);
        const row = (await client.query('SELECT * FROM identity_automation_jobs WHERE id=$1 FOR NO KEY UPDATE', [claimed.id])).rows[0];
        await this.retained(client, 'job', row.id);
        if (row.status !== 'running' || row.lease_token !== claimed.lease_token || row.lease_until <= new Date()) fail(409, 'Worker lease changed');
        if (reconciliation(row.action)) {
          const outcome = row.action === GROUP_ACTION ? await new (require('./CompanyGroupRuleWorker').CompanyGroupRuleWorker)(this).step(row,user,authorization) : await this.licenseClient.step(row, user, authorization);
          const content = outcome.finished ? JSON.stringify(outcome) : null;
          if (content !== null && Buffer.byteLength(content) > 4194304) fail(409, 'Complete license report exceeds artifact limit');
          const finished = (await client.query(`UPDATE identity_automation_jobs SET status=$2,lease_token=NULL,lease_until=NULL,progress=$3,
            attempt_count=CASE WHEN $2='queued' THEN 0 ELSE attempt_count END,available_at=clock_timestamp(),error_code=$4,artifact_content=$5,
            artifact_type=CASE WHEN $5::text IS NULL THEN NULL ELSE 'application/json' END,artifact_sha256=$6,row_count=$7,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`,
          [row.id, outcome.finished ? outcome.hasBlocked ? 'partial' : 'succeeded' : 'queued', outcome.progress, outcome.finished && outcome.hasBlocked ? row.action === GROUP_ACTION ? 'group_members_require_attention' : 'license_members_blocked' : null,
            content, content === null ? null : hash(content), content === null ? null : outcome.results.length])).rows[0];
          return { ...base, job: jobView(finished) };
        }
        const artifact = await this.export(client, permission, row.action, row.format);
        const finished = (await client.query(`UPDATE identity_automation_jobs SET status='succeeded',lease_token=NULL,lease_until=NULL,
          artifact_content=$2,artifact_type=$3,artifact_sha256=$4,row_count=$5,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`, [row.id, artifact.content, artifact.contentType, artifact.sha256, artifact.rowCount])).rows[0];
        return { ...base, job: jobView(finished) };
      });
    } catch (error) {
      if ([401, 403].includes(error.status)) throw error;
      return this.transaction(user, authorization, async (client, actor) => {
        await this.grant(client, claimed.grant_id, actor);
        const row = (await client.query('SELECT * FROM identity_automation_jobs WHERE id=$1 FOR NO KEY UPDATE', [claimed.id])).rows[0];
        if (row.status !== 'running' || row.lease_token !== claimed.lease_token || row.lease_until <= new Date()) fail(409, 'Worker lease changed; inspect durable job');
        const licensing = reconciliation(claimed.action);
        const permanent = (licensing ? [400, 404, 409, 412].includes(error.status) : error.status === 409) || claimed.attempt_count >= 5;
        const failed = (await client.query(`UPDATE identity_automation_jobs SET status=$2,lease_token=NULL,lease_until=NULL,error_code=$3,
          available_at=clock_timestamp()+$4*interval '1 second',revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING *`, [row.id, permanent ? 'failed' : 'retry_wait',
          licensing ? claimed.action === GROUP_ACTION ? permanent ? 'group_reconciliation_blocked' : 'group_step_unconfirmed' : permanent ? 'license_reconciliation_blocked' : 'license_step_unconfirmed' : error.status === 409 ? 'export_limit' : 'export_unavailable', Math.min(3600, 30 * 2 ** (claimed.attempt_count - 1))])).rows[0];
        return { ...base, job: jobView(failed) };
      });
    }
  }
}
module.exports = { CompanyAutomation, grantView, jobView, scheduleView, csv };
