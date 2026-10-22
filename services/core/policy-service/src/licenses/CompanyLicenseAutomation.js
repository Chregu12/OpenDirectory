'use strict';
const { isDeepStrictEqual } = require('node:util');
const { exact, identifier, workload, fail } = require('../../../../../packages/company-automation-contract');
const { CompanyLicenseAutomationAuthority } = require('./CompanyLicenseAutomationAuthority');
const { LicenseAllocator } = require('./LicenseAllocator');
const { CompanyLicenses } = require('./CompanyLicenses');
const { CompanyLicenseGroups } = require('./CompanyLicenseGroups');
const { CompanyBlueprintAssignments } = require('./CompanyBlueprintAssignments');
class CompanyLicenseAutomation {
  constructor(database, { allocator = new LicenseAllocator(database), authority = context => new CompanyLicenseAutomationAuthority(context) } = {}) {
    Object.assign(this, { database, allocator, authority });
  }
  async current(authority, source, user, authorization) {
    const current = await authority.read(authorization, user);
    if (!isDeepStrictEqual(current, source)) fail(412, 'Original license group observation changed'); return current;
  }
  async journal(authority, source, user, authorization, operation) {
    const client = await this.database.getClient();
    try {
      await client.query('BEGIN'); await client.query("SET LOCAL timezone='UTC';SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='5s'");
      await client.query('SELECT company_blueprint_assignment_automation_receiving()'); await this.current(authority, source, user, authorization);
      await client.query("SELECT set_config('opendirectory.company_license_automation',$1,true)", [JSON.stringify(source)]);
      const result = await operation(client); await this.current(authority, source, user, authorization); await client.query('COMMIT');
      await this.current(authority, source, user, authorization); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
  }
  async cycle(source) {
    await this.database.query('SELECT company_blueprint_assignment_automation_receiving()');
    const row = (await this.database.query(`SELECT cycle.*,EXISTS(SELECT 1 FROM company_license_automation_outbox box
      WHERE box.job_id=cycle.job_id AND box.retry_count=cycle.retry_count AND box.cycle=cycle.cycle AND box.page=0 AND box.status='pending'
      AND box.created_at=cycle.created_at AND box.fingerprint=company_blueprint_assignment_automation_fingerprint(cycle.job_id,cycle.retry_count,cycle.cycle,0)) AS valid
      FROM company_license_automation_cycles cycle WHERE job_id=$1 AND retry_count=$2 AND tenant_id=$3 ORDER BY cycle DESC LIMIT 1`, [source.jobId, source.retryCount, source.tenant.id])).rows[0];
    if (row && (row.valid !== true || row.grant_id !== source.grantId || row.rule_id !== source.ruleId || !isDeepStrictEqual(row.authority.tenant, source.tenant))) fail(503, 'Retained original license cycle unavailable');
    return row || null;
  }
  async pages(cycle) {
    const rows = (await this.database.query(`SELECT page.*,EXISTS(SELECT 1 FROM company_license_automation_outbox box
      WHERE box.job_id=page.job_id AND box.retry_count=page.retry_count AND box.cycle=page.cycle AND box.page=page.page AND box.status='pending'
      AND box.created_at=page.created_at AND box.fingerprint=company_blueprint_assignment_automation_fingerprint(page.job_id,page.retry_count,page.cycle,page.page)) AS valid
      FROM company_license_automation_pages page WHERE job_id=$1 AND retry_count=$2 AND cycle=$3 ORDER BY page`, [cycle.job_id, cycle.retry_count, cycle.cycle])).rows;
    let completed = 0;
    for (const [index, page] of rows.entries()) {
      if (page.valid !== true || page.page !== index + 1 || !Array.isArray(page.results) || page.results.length !== Math.min(25, cycle.targets.length - completed)
        || page.results.some((item, offset) => item.userId !== cycle.targets[completed + offset])) fail(503, 'Retained ordered license page unavailable');
      completed += page.results.length;
    }
    if (completed > cycle.targets.length) fail(503, 'License page exceeds captured manifest'); return rows;
  }
  async capture(rule, source, previous, authority, user, authorization, groups) {
    const iteration = previous ? previous.cycle + 1 : 1; if (iteration > 5) fail(409, 'Group kept changing; explicit new reconciliation required');
    return this.journal(authority, source, user, authorization, async client => {
      await client.query('SELECT id FROM company_license_groups WHERE id=$1 FOR SHARE', [rule.id]);
      const current = await groups.rule(client, rule.id, source); if (String(current.revision) !== String(rule.revision)) fail(412, 'Original rule changed');
      const bindings = await groups.bindings(client, rule);
      const desired = rule.status === 'active' && !source.group.deleted ? source.group.memberIds : [];
      const targets = [...new Set([...desired, ...bindings.map(binding => binding.user_id)])].sort(); if (targets.length > 10000) fail(409, 'Complete license manifest exceeds 10000 targets');
      const row = (await client.query(`INSERT INTO company_license_automation_cycles(job_id,retry_count,cycle,tenant_id,grant_id,rule_id,rule_revision,group_snapshot,targets,authority)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,company_blueprint_assignment_automation_authority($10::jsonb)) RETURNING *`,
      [source.jobId, source.retryCount, iteration, source.tenant.id, source.grantId, rule.id, rule.revision, source.group, targets, source])).rows[0];
      await client.query(`INSERT INTO company_license_automation_outbox SELECT job_id,retry_count,cycle,0,'pending',company_blueprint_assignment_automation_fingerprint(job_id,retry_count,cycle,0),created_at
        FROM company_license_automation_cycles WHERE job_id=$1 AND retry_count=$2 AND cycle=$3`, [row.job_id, row.retry_count, row.cycle]); return row;
    });
  }
  result(source, cycle, pages) {
    const results = pages.flatMap(page => page.results); const blocked = results.filter(item => item.status === 'blocked').length;
    const finished = results.length === cycle.targets.length;
    return { schemaVersion: 1, companyLicenseAutomationProtocol: 1, grantId: source.grantId, jobId: source.jobId, ruleId: source.ruleId,
      actor: { kind: 'application', id: source.grantId, clientId: source.subject, clientRevision: source.clientRevision },
      progress: { runId: source.jobId, retryCount: source.retryCount, cycle: cycle.cycle, completed: results.length, total: cycle.targets.length, blocked }, finished, hasBlocked: blocked > 0, results: finished ? results : [] };
  }
  async step(input, user, authorization) {
    exact(input, ['grantId', 'jobId', 'leaseToken', 'ruleId']); Object.values(input).forEach(identifier); workload(user, user?.iss);
    const base = this.authority({ ...input, groupId: null }); const approved = await base.read(authorization, user);
    const companies = new CompanyLicenses(this.allocator, { authority: base }); const lookup = new CompanyLicenseGroups(companies);
    let rule = await lookup.rule(this.database, input.ruleId, approved);
    const authority = this.authority({ ...input, groupId: rule.group_id }); const linked = new CompanyLicenses(this.allocator, { authority });
    const groups = new CompanyLicenseGroups(linked, { assignments: new CompanyBlueprintAssignments(this.database, { allocator: this.allocator, authority, applicationAuthority: authority }),
      groups: { machineSnapshot: bearer => authority.read(bearer, user) }, correlationId: input.jobId });
    const lock = await this.database.getClient(); let locked = false;
    try {
      locked = (await lock.query('SELECT pg_try_advisory_lock(hashtextextended($1,290029)) AS locked', ['company-license-job:' + input.jobId])).rows[0].locked;
      if (!locked) fail(429, 'Original license job already processing');
      for (let retry = 0; retry < 5; retry++) {
        const source = await authority.read(authorization, user); rule = await groups.rule(this.database, input.ruleId, source);
        let cycle = await this.cycle(source);
        try {
          if (!cycle || String(cycle.rule_revision) !== String(rule.revision) || !isDeepStrictEqual(cycle.group_snapshot, source.group)) cycle = await this.capture(rule, source, cycle, authority, user, authorization, groups);
          let pages = await this.pages(cycle); const completed = pages.reduce((sum, page) => sum + page.results.length, 0);
          if (completed < cycle.targets.length) {
            const selected = cycle.targets.slice(completed, completed + 25);
            const result = await groups.sync(rule.id, { groupRevision: rule.status === 'active' ? source.group.revision : null, cursor: null, reason: 'Ausdrücklich freigegebener App-Lizenzgruppenabgleich', confirm: true }, user, authorization, selected);
            await this.journal(authority, source, user, authorization, async client => {
              await client.query('SELECT id FROM company_license_groups WHERE id=$1 FOR SHARE', [rule.id]);
              await client.query(`INSERT INTO company_license_automation_pages(job_id,retry_count,cycle,page,results,authority) VALUES($1,$2,$3,$4,$5,company_blueprint_assignment_automation_authority($6::jsonb))`,
                [source.jobId, source.retryCount, cycle.cycle, pages.length + 1, JSON.stringify(result.results), source]);
              await client.query(`INSERT INTO company_license_automation_outbox SELECT job_id,retry_count,cycle,page,'pending',company_blueprint_assignment_automation_fingerprint(job_id,retry_count,cycle,page),created_at
                FROM company_license_automation_pages WHERE job_id=$1 AND retry_count=$2 AND cycle=$3 AND page=$4`, [source.jobId, source.retryCount, cycle.cycle, pages.length + 1]);
            });
            pages = await this.pages(cycle);
          }
          await this.current(authority, source, user, authorization);
          const outcome = this.result(source, cycle, pages);
          if (outcome.finished) {
            const actual = await groups.bindings(this.database, rule); const wanted = new Map((rule.status === 'active' && !source.group.deleted ? source.group.memberships : []).map(member => [member.userId, member.eligibilityRevision]));
            const positive = new Set(outcome.results.filter(item => ['assigned', 'retained'].includes(item.status)).map(item => item.userId));
            const blocked = new Set(outcome.results.filter(item => item.status === 'blocked').map(item => item.userId));
            const changed = [...positive].some(id => !actual.some(binding => binding.user_id === id && String(binding.eligibility_revision) === wanted.get(id)))
              || actual.some(binding => !wanted.has(binding.user_id) || String(binding.eligibility_revision) !== wanted.get(binding.user_id) || blocked.has(binding.user_id));
            const pool = outcome.results.some(item => item.status === 'blocked' && item.code === 409) && cycle.cycle < 5 ? await linked.ownPool(this.database, rule.pool_id, source.tenant.id) : null;
            const capacityFreed = pool && pool.total_seats > pool.active_seats;
            if (changed || capacityFreed) { cycle = await this.capture(rule, source, cycle, authority, user, authorization, groups); return this.result(source, cycle, []); }
          }
          return outcome;
        } catch (error) { if (error.status !== 412 || retry === 4) throw error; }
      }
      fail(409, 'License group did not stabilize');
    } finally {
      if (locked) { try { await lock.query('SELECT pg_advisory_unlock(hashtextextended($1,290029))', ['company-license-job:' + input.jobId]); } catch { lock.release(true); locked = null; } }
      if (locked !== null) lock.release();
    }
  }
}
module.exports = { CompanyLicenseAutomation };
