'use strict';
const { createHash, randomUUID } = require('node:crypto'); const { isDeepStrictEqual } = require('node:util');
const { CompanyLicenseAuthority } = require('./CompanyLicenseAuthority'); const { ownerState } = require('./CompanyOwner');
const { identifier, exact, text } = require('../../../../packages/company-license-contract'); const contract = require('../../../../packages/company-group-rule-contract'); const { fail } = contract;
const { GroupMutator, groupEtag } = require('./GroupMutator');
const view = row => ({ groupId: row.group_id, tenantId: row.tenant_id, revision: String(row.revision), enabled: row.enabled, draft: row.draft, createdBy: row.created_by,
 createdAt: new Date(row.created_at).toISOString(), updatedAt: new Date(row.updated_at).toISOString() });
const envelope = source => ({ schemaVersion: 1, companyGroupRuleProtocol: 1, actorUserId: source.actorUserId, tenantId: source.tenant.id });
class CompanyGroupRules {
 constructor(database, { authority = new CompanyLicenseAuthority(database) } = {}) { this.database = database; this.authority = authority; }
 async unchanged(source, user, authorization) { if (!isDeepStrictEqual(source, await this.authority.read(user, authorization))) fail(401, 'Original group-rule authority changed'); }
 async transaction(groupId, user, authorization, operation, { readOnly = false } = {}) {
  identifier(groupId); const source = await this.authority.read(user, authorization);
  const result = await this.database.transaction(async client => {
   await client.query("SET LOCAL timezone='UTC';SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='10s'");
   await client.query('SELECT identity_company_group_rule_receiving()');
   const owner = await ownerState(client, source.actorUserId);
   if (!owner?.active || owner.tenant_id !== source.tenant.id || owner.issuer !== source.issuer || owner.subject !== source.subject) fail(403, 'Actual company owner required for group rules');
   const group = (await client.query("SELECT id,name,revision FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2", [groupId, source.tenant.id])).rows[0];
   if (!group) fail(404, 'Own group not found');
   const result = await operation(client, source, group); await this.unchanged(source, user, authorization); return result;
  }, { readOnly }); await this.unchanged(source, user, authorization); return result;
 }
 async rule(client, groupId, tenantId, lock = '') {
  const row = (await client.query('SELECT * FROM identity_company_group_rules WHERE group_id=$1 AND tenant_id=$2' + (lock ? ' FOR ' + lock : ''), [groupId, tenantId])).rows[0];
  if (row) {
   const valid = (await client.query(`SELECT EXISTS(SELECT 1 FROM identity_company_group_rule_events event JOIN identity_company_group_rule_outbox box ON box.id=event.id
    JOIN identity_company_group_rules actual ON actual.group_id=event.group_id AND actual.last_event_id=event.id AND actual.revision=event.revision AND actual.tenant_id=event.tenant_id
    WHERE actual.group_id=$1 AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex') AND event.result=to_jsonb(actual)
     AND (SELECT count(*) FROM identity_company_group_rule_events history WHERE history.group_id=actual.group_id)=actual.revision
     AND NOT EXISTS(SELECT 1 FROM identity_company_group_rule_events history LEFT JOIN identity_company_group_rule_outbox pending ON pending.id=history.id WHERE history.group_id=actual.group_id AND (pending.status IS DISTINCT FROM 'pending' OR pending.fingerprint IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(history)::text,'UTF8')),'hex')))) AS valid`, [groupId])).rows[0]?.valid;
   if (valid !== true) fail(503, 'Retained original group rule unavailable');
  } return row || null;
 }
 get(groupId, user, authorization) {
  return this.transaction(groupId, user, authorization, async (client, source) => {
   const row = await this.rule(client, groupId, source.tenant.id); return { ...envelope(source), groupId, rule: row ? view(row) : null, etag: contract.etag(groupId, row ? String(row.revision) : null), executionMode: 'manual' };
  }, { readOnly: true });
 }
 async save(groupId, input, match, operationId, user, authorization) {
  identifier(groupId); identifier(operationId); const values = contract.command(input); const expectedRevision = contract.expected(groupId, match);
  if (values.draft.childGroupIds.includes(groupId)) fail(409, 'A group cannot contain itself');
  return this.transaction(groupId, user, authorization, async (client, source) => {
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,500050))', ['company-group-rule:' + source.tenant.id]);
   const previous = (await client.query(`SELECT command,result||jsonb_build_object('revision',result->>'revision') AS result,
    EXISTS(SELECT 1 FROM identity_company_group_rule_outbox box WHERE box.id=event.id AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex')) AS valid
    FROM identity_company_group_rule_events event WHERE id=$1 AND tenant_id=$2`, [operationId, source.tenant.id])).rows[0];
   if (previous) {
    if (previous.valid !== true) fail(503, 'Retained original group-rule receipt unavailable');
    if (previous.command.groupId !== groupId || previous.command.source.actorUserId !== source.actorUserId || previous.command.expectedRevision !== expectedRevision || !isDeepStrictEqual(previous.command.values, values)) fail(409, 'Original group-rule operation changed');
    return { ...envelope(source), outcome: 'already_applied', rule: view(previous.result) };
   }
   const row = await this.rule(client, groupId, source.tenant.id, 'UPDATE');
   if ((row ? String(row.revision) : null) !== expectedRevision) fail(412, 'Group rule changed; reload before saving');
   if (row && row.enabled === values.enabled && isDeepStrictEqual(row.draft, values.draft)) fail(409, 'Group rule already has the requested configuration');
   const scope = { kind: 'configure', id: operationId, source, groupId, expectedRevision, values };
   await client.query("SELECT set_config('opendirectory.company_group_rule',$1,true)", [JSON.stringify(scope)]);
   if (row) await client.query('UPDATE identity_company_group_rules SET revision=revision+1,enabled=$2,draft=$3,approval=$4,last_event_id=$5,updated_at=clock_timestamp() WHERE group_id=$1', [groupId, values.enabled, values.draft, source, operationId]);
   else await client.query('INSERT INTO identity_company_group_rules(group_id,tenant_id,revision,enabled,draft,approval,created_by,last_event_id) VALUES($1,$2,1,$3,$4,$5,$6,$7)', [groupId, source.tenant.id, values.enabled, values.draft, source, source.actorUserId, operationId]);
   const result = (await client.query('SELECT * FROM identity_company_group_rules WHERE group_id=$1', [groupId])).rows[0];
   await client.query(`INSERT INTO identity_company_group_rule_events(id,group_id,tenant_id,revision,command,result) SELECT $1,group_id,tenant_id,revision,$2,to_jsonb(actual) FROM identity_company_group_rules actual WHERE group_id=$3`, [operationId, scope, groupId]);
   await client.query("INSERT INTO identity_company_group_rule_outbox SELECT id,'pending',encode(sha256(convert_to(to_jsonb(actual)::text,'UTF8')),'hex'),created_at FROM identity_company_group_rule_events actual WHERE id=$1", [operationId]);
   return { ...envelope(source), outcome: 'applied', rule: view(result) };
  });
 }
 async desired(client, row, tenantId) {
  if (!row.enabled) return [];
  const rows = (await client.query(`SELECT account.id,account.eligibility_revision FROM users account CROSS JOIN identity_company_group_rules setting
   WHERE setting.group_id=$1 AND setting.tenant_id=$2 AND identity_tenant_id('user',account.id)=$2 AND identity_company_group_rule_wants(setting,account.id) ORDER BY account.id LIMIT 10001`, [row.group_id, tenantId])).rows;
  if (rows.length > 10000) fail(409, 'Complete group-rule result exceeds 10000 users'); return rows.map(row => ({ userId: row.id, eligibilityRevision: String(row.eligibility_revision) }));
 }
 preview(groupId, user, authorization) {
  return this.transaction(groupId, user, authorization, async (client, source, group) => {
   const row = await this.rule(client, groupId, source.tenant.id); if (!row) fail(404, 'Group rule not configured');
   const desired = await this.desired(client, row, source.tenant.id);
   const existing = await this.members(client, groupId, source.tenant.id);
   if (existing.length > 10000) fail(409, 'Complete group-rule membership inventory exceeds 10000 users');
   const observation = this.observation(row, desired);
   return { ...envelope(source), groupId, groupName: group.name, groupRevision: String(group.revision), ruleRevision: String(row.revision), enabled: row.enabled, observation, executionMode: 'manual',
    desired, existing: existing.map(item => ({ userId: item.user_id, membershipId: item.membership_id, managed: !!item.rule_revision })), additions: desired.filter(item => !existing.some(member => member.user_id === item.userId)).length };
  }, { readOnly: true });
 }
 observation(row, desired) { return createHash('sha256').update(JSON.stringify({ revision: String(row.revision), desired })).digest('hex'); }
 async members(client, groupId, tenantId) {
  await this.effectsValid(client, groupId, tenantId);
  const coherent = (await client.query(`SELECT NOT EXISTS(SELECT 1 FROM group_members membership LEFT JOIN users account ON account.id::text=membership.user_id
   LEFT JOIN identity_membership_origins origin ON origin.membership_id=membership.membership_id WHERE membership.group_id=$1
    AND(account.id IS NULL OR identity_tenant_id('user',account.id) IS DISTINCT FROM $2::uuid OR origin.group_id IS DISTINCT FROM membership.group_id OR origin.user_id IS DISTINCT FROM account.id)) AS coherent`, [groupId, tenantId])).rows[0]?.coherent;
  if (coherent !== true) fail(503, 'Complete own canonical group-rule membership inventory unavailable');
  return (await client.query(`SELECT membership.user_id,membership.membership_id,origin.eligibility_revision,effect.rule_revision FROM group_members membership JOIN users account ON account.id::text=membership.user_id
   JOIN identity_membership_origins origin ON origin.membership_id=membership.membership_id
   LEFT JOIN identity_company_group_rule_effects effect ON effect.membership_id=membership.membership_id AND effect.action='member-add' AND effect.group_id=membership.group_id
   WHERE membership.group_id=$1 AND identity_tenant_id('user',account.id)=$2 ORDER BY membership.user_id LIMIT 10001`, [groupId, tenantId])).rows;
 }
 async effectsValid(client, groupId, tenantId) {
  const valid = (await client.query(`SELECT NOT EXISTS(SELECT 1 FROM identity_company_group_rule_effects effect
   LEFT JOIN identity_company_group_rule_effect_outbox box ON box.id=effect.id LEFT JOIN identity_directory_group_events actual ON actual.id=effect.id
   LEFT JOIN identity_directory_group_outbox actual_box ON actual_box.id=actual.id LEFT JOIN identity_company_group_rule_events configured ON configured.group_id=effect.group_id AND configured.revision=effect.rule_revision
   LEFT JOIN identity_membership_origins origin ON origin.membership_id=effect.membership_id
   WHERE effect.group_id=$1 AND(effect.tenant_id<>$2 OR box.status IS DISTINCT FROM 'pending' OR box.created_at IS DISTINCT FROM effect.created_at
    OR box.fingerprint IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(effect)::text,'UTF8')),'hex') OR actual.id IS NULL OR actual.tenant_id<>effect.tenant_id OR actual.group_id<>effect.group_id OR actual.action<>effect.action
    OR actual.transaction_id<>effect.transaction_id OR actual.scope_sha256<>effect.group_scope_sha256 OR actual_box.status IS DISTINCT FROM 'pending' OR configured.id IS NULL OR origin.group_id IS DISTINCT FROM effect.group_id OR origin.user_id IS DISTINCT FROM effect.user_id
    OR actual.actor IS DISTINCT FROM jsonb_build_object('issuer',effect.source#>>'{authority,issuer}','subject',effect.source#>>'{authority,subject}','userId',effect.source#>>'{authority,actorUserId}'))) AS valid`, [groupId, tenantId])).rows[0]?.valid;
  if (valid !== true) fail(503, 'Retained original group-rule membership effects unavailable');
 }
 history(groupId, query, user, authorization) {
  if (!query || Object.keys(query).some(key => key !== 'page') || query.page !== undefined && (typeof query.page !== 'string' || !/^[1-9][0-9]{0,5}$/.test(query.page))) fail(400, 'One bounded group-rule history page required');
  const page = query.page ? Number(query.page) : 1;
  return this.transaction(groupId, user, authorization, async (client, source) => {
   if (!await this.rule(client, groupId, source.tenant.id)) fail(404, 'Group rule not configured'); await this.effectsValid(client, groupId, source.tenant.id);
   const relation = `FROM(SELECT id,'configuration' AS kind,'configured' AS action,NULL::uuid AS user_id,NULL::uuid AS membership_id,revision AS rule_revision,command#>>'{source,actorUserId}' AS actor_user_id,command#>>'{values,reason}' AS reason,created_at
     FROM identity_company_group_rule_events WHERE group_id=$1 AND tenant_id=$2 UNION ALL SELECT id,'membership',action,user_id,membership_id,rule_revision,source#>>'{authority,actorUserId}',source->>'reason',created_at FROM identity_company_group_rule_effects WHERE group_id=$1 AND tenant_id=$2) history`;
   const parameters = [groupId, source.tenant.id]; const total = (await client.query('SELECT count(*)::integer AS total ' + relation, parameters)).rows[0].total;
   const rows = (await client.query('SELECT * ' + relation + ' ORDER BY created_at DESC,id DESC LIMIT 25 OFFSET $3', [...parameters, (page-1)*25])).rows;
   return { ...envelope(source), groupId, page, limit: 25, total, events: rows.map(row => ({ id: row.id, kind: row.kind, action: row.action, userId: row.user_id, membershipId: row.membership_id, ruleRevision: String(row.rule_revision), actorUserId: row.actor_user_id, reason: row.reason, createdAt: row.created_at.toISOString(), deliveryStatus: 'pending' })) };
  }, { readOnly: true });
 }
 async apply(action, group, userId, row, observation, authority, user, authorization, reason) {
  const operationId = randomUUID();
  const database = { ...this.database, transaction: (operation, options) => this.database.transaction(async client => { await client.query("SET LOCAL timezone='UTC'"); return operation(client); }, options) };
  const revalidate = async (bearer, actor) => (await this.authority.read(actor, bearer)).tenant;
  const mutator = new GroupMutator(database, { issuer: authority.issuer, revalidate, revalidateAccess: (actor, bearer) => revalidate(bearer, actor), newOperationId: () => operationId,
   afterMutation: async (client, captured) => {
    await client.query('SELECT identity_company_group_rule_receiving()'); const current = await this.rule(client, group.id, authority.tenant.id, 'SHARE');
    if (!current || String(current.revision) !== String(row.revision) || this.observation(current, await this.desired(client, current, authority.tenant.id)) !== observation) fail(412, 'Original group rule observation changed');
    await client.query('SELECT id FROM groups WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE', [current.draft.childGroupIds]);
    await this.unchanged(authority, user, authorization);
    const membershipId = action === 'member-add' ? (await client.query("SELECT current_setting('opendirectory.group_mutation_membership') AS id")).rows[0].id : captured.proof.target.member.id;
    const scope = { authority, groupId: group.id, ruleRevision: String(row.revision), operationId, observation, reason };
    await client.query("SELECT set_config('opendirectory.company_group_rule_effect',$1,true)", [JSON.stringify(scope)]);
    await client.query(`INSERT INTO identity_company_group_rule_effects(id,group_id,tenant_id,membership_id,user_id,rule_revision,action,source,group_scope_sha256)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,encode(sha256(convert_to($9::jsonb::text,'UTF8')),'hex'))`, [operationId, group.id, authority.tenant.id, membershipId, userId, row.revision, action, scope, captured.proof]);
    await client.query("INSERT INTO identity_company_group_rule_effect_outbox SELECT id,'pending',encode(sha256(convert_to(to_jsonb(actual)::text,'UTF8')),'hex'),created_at FROM identity_company_group_rule_effects actual WHERE id=$1", [operationId]);
   } });
  return action === 'member-add' ? mutator.add(group.id, { userId }, groupEtag(group), user, authorization) : mutator.removeMember(group.id, userId, groupEtag(group), user, authorization);
 }
 async sync(groupId, input, user, authorization) {
  exact(input, ['observation', 'cursor', 'reason', 'confirm']); if (input.confirm !== true || typeof input.observation !== 'string' || !/^[a-f0-9]{64}$/.test(input.observation)) fail(400, 'Confirmed captured group-rule observation required');
  if (input.cursor !== null) identifier(input.cursor); const reason = text(input.reason, 10, 500);
  const capture = await this.transaction(groupId, user, authorization, async (client, source) => {
   const row = await this.rule(client, groupId, source.tenant.id); if (!row) fail(404, 'Group rule not configured'); const desired = await this.desired(client, row, source.tenant.id); const members = await this.members(client, groupId, source.tenant.id);
   if (members.length > 10000 || this.observation(row, desired) !== input.observation) fail(412, 'Group rule observation changed');
   const targets = [...new Set([...desired.map(item => item.userId), ...members.filter(item => item.rule_revision).map(item => item.user_id)])].sort(); if (targets.length > 10000) fail(409, 'Group rule reconciliation exceeds 10000 targets');
   return { source, row, desired, targets };
  }, { readOnly: true });
  const selected = capture.targets.filter(id => !input.cursor || id > input.cursor).slice(0, 25); const results = [];
  for (const userId of selected) {
   try {
    let state = await this.transaction(groupId, user, authorization, async (client, source, group) => ({ group: { id: group.id, revision: String(group.revision) }, member: (await this.members(client, groupId, source.tenant.id)).find(item => item.user_id === userId) }), { readOnly: true });
    const desired = capture.desired.find(item => item.userId === userId);
    if (state.member && !state.member.rule_revision) { results.push({ userId, status: 'manual-retained', code: null }); continue; }
    if (state.member && (!desired || String(state.member.rule_revision) !== String(capture.row.revision) || String(state.member.eligibility_revision) !== desired.eligibilityRevision)) {
     state.group = await this.apply('member-remove', state.group, userId, capture.row, input.observation, capture.source, user, authorization, reason); state.member = undefined;
    }
    if (desired && !state.member) {
     const added = await this.apply('member-add', state.group, userId, capture.row, input.observation, capture.source, user, authorization, reason);
     results.push({ userId, status: added.membershipReview?.effective === false ? 'awaiting-review' : 'added', code: null });
    } else results.push({ userId, status: desired ? 'retained' : 'removed', code: null });
   } catch (error) {
    if (![403,404,409,428].includes(error.status)) throw error; results.push({ userId, status: 'blocked', code: error.status });
   }
  }
  await this.unchanged(capture.source, user, authorization);
  const last = selected.at(-1); return { ...envelope(capture.source), groupId, ruleRevision: String(capture.row.revision), observation: input.observation, results,
   nextCursor: last && capture.targets.some(id => id > last) ? last : null, hasBlocked: results.some(item => item.status === 'blocked') };
 }
}
module.exports = { CompanyGroupRules };
