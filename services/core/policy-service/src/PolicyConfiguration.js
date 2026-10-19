'use strict';

const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { validContext } = require('../../../../packages/identity-authorization-contract');
const { getPolicyPermissions, freshPolicyAuthentication } = require('../../../../packages/policy-authorization-contract');
const PolicyApplicationService = require('./application/PolicyApplicationService');
const PostgresPolicyRepository = require('./infrastructure/repositories/PostgresPolicyRepository');
const PolicyAggregate = require('./domain/PolicyAggregate');
const { previewValues, resolveConfigurations, readConfigurations } = require('./BlueprintPreview');
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const TYPES = ['security','software','registry','network','firewall','encryption','password','compliance','gpo','update-ring'];
const PLATFORMS = ['windows','macos','linux','all'];
const CONFIG_TYPES = ['wifi','vpn','filevault','gatekeeper','software_update','screen_lock','certificate','webfilter','airdrop'];
function fail(status, code) { throw Object.assign(new Error(code), { status, code }); }
function identifier(value) { if (typeof value !== 'string' || !UUID.test(value)) fail(400, 'canonical_policy_id_required'); return value; }
function text(value, maximum = 255) { return typeof value === 'string' && value.trim().length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value); }
function fields(body, allowed) { if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !allowed.includes(key))) fail(400, 'exact_policy_fields_required'); }
function json(value, depth = 0) {
  if (depth > 20 || typeof value === 'number' && !Number.isFinite(value) || ![null, 'string','number','boolean','object'].includes(value === null ? null : typeof value)) fail(400, 'bounded_policy_json_required');
  if (Array.isArray(value)) value.forEach(item => json(item, depth + 1));
  else if (value && typeof value === 'object') for (const [key, item] of Object.entries(value)) { if (['__proto__','prototype','constructor'].includes(key)) fail(400, 'safe_policy_json_required'); json(item, depth + 1); }
  if (depth === 0 && Buffer.byteLength(JSON.stringify(value)) > 262144) fail(400, 'bounded_policy_json_required');
  return value;
}
function object(value) { if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, 'policy_settings_object_required'); return json(value); }
function metadata(body, allowed) { fields(body, [...allowed,'reason','acknowledgeScope']); if (body.acknowledgeScope !== true || !text(body.reason, 500) || body.reason.trim().length < 10) fail(400, 'policy_reason_and_scope_required'); return body.reason.trim(); }
function etag(kind, row) { return `"od-${kind}:${row.id}:${row.version}"`; }
function table(kind) { if (!['policy','blueprint'].includes(kind)) fail(400, 'policy_resource_kind_required'); return kind === 'policy' ? 'policies' : 'blueprints'; }
function policy(row) { return PolicyAggregate.fromRow(row).toJSON(); }
function normalize(body, before) {
  const allowed = ['name','description','type','platform','rules','settings','priority','enforce','block_inheritance','wmi_filter','security_filter'];
  metadata(body, allowed); const next = Object.fromEntries(allowed.filter(key => Object.hasOwn(body, key)).map(key => [key, body[key]]));
  if ((!before || Object.hasOwn(next,'name')) && !text(next.name)) fail(400, 'policy_name_required');
  if ((!before || Object.hasOwn(next,'type')) && !TYPES.includes(next.type)) fail(400, 'policy_type_required');
  if (before && next.type !== undefined && next.type !== before.type) fail(409, 'policy_type_immutable');
  if (next.platform !== undefined && !PLATFORMS.includes(next.platform)) fail(400, 'policy_platform_required');
  if (next.description !== undefined && next.description !== null && (typeof next.description !== 'string' || next.description.length > 4000)) fail(400, 'bounded_policy_description_required');
  if (next.settings !== undefined) object(next.settings);
  if (next.rules !== undefined && (!Array.isArray(next.rules) || next.rules.length > 1000)) fail(400, 'policy_rules_array_required');
  for (const key of ['rules','wmi_filter','security_filter']) if (next[key] !== undefined) json(next[key]);
  if (next.priority !== undefined && (!Number.isInteger(next.priority) || next.priority < 0 || next.priority > 1000000)) fail(400, 'bounded_policy_priority_required');
  for (const key of ['enforce','block_inheritance']) if (next[key] !== undefined && typeof next[key] !== 'boolean') fail(400, 'policy_boolean_required');
  const kind = next.type || before?.type; const settings = next.settings ?? before?.settings ?? {};
  if (kind === 'update-ring') {
    fields(settings, ['deferralDays']); fields(settings.deferralDays, ['windows','macos','linux']);
    if (Object.keys(settings.deferralDays).length !== 3 || Object.values(settings.deferralDays).some(value => !Number.isInteger(value) || value < 0 || value > 365)) fail(400, 'bounded_ring_deferrals_required');
  }
  if (kind === 'gpo') {
    fields(settings, ['configuration','platforms','gpoType']); object(settings.configuration);
    if (!text(settings.gpoType,100) || !Array.isArray(settings.platforms) || !settings.platforms.length || settings.platforms.length > 3 || new Set(settings.platforms).size !== settings.platforms.length || settings.platforms.some(value => !['windows','macos','linux'].includes(value))) fail(400, 'exact_gpo_platforms_required');
  }
  return next;
}
function context(user, permission, resourceKind, resourceId, version, action, reason) {
  const identity = user.identity_authorization;
  return { resourceKind, resourceId, expectedVersion: String(version), permission, action, reason, acknowledgeScope: true,
    actor: { issuer: user.iss, subject: user.sub, userId: identity.userId, revision: identity.revision, linkRevision: identity.linkRevision, rolesRevision: identity.rolesRevision,
      clientId: user.client_id, tokenId: user.jti, expiresAt: user.exp, mfaRevision: user.mfa_authorization?.revision, authTime: user.auth_time } };
}
class PolicyConfiguration {
  constructor(database, { authority = createAccessStateClient(), publicationSource } = {}) {
    this.database = database; this.authority = authority;
    this.publications = new (require('./PolicyPublication').PolicyPublication)(this, { source: publicationSource });
  }
  async check(user, authorization, permission, signal, write = false) {
    if (signal?.aborted) fail(409, 'policy_operation_closed');
    if (user?.actor_type !== 'user' || user.token_use !== 'access' || !Number.isSafeInteger(user.exp) || user.exp <= 0 || !validContext(user.identity_authorization) || !text(user.iss,2048) || !text(user.sub) || !text(user.client_id) || !text(user.jti) || !getPolicyPermissions(user).includes(permission)) fail(403, 'policy_operation_forbidden');
    if (write && !freshPolicyAuthentication(user)) fail(428, 'fresh_mfa_required');
    await this.authority(authorization, user);
    if (signal?.aborted) fail(409, 'policy_operation_closed');
    if (write && !freshPolicyAuthentication(user)) fail(428, 'fresh_mfa_required');
  }
  async transaction(user, authorization, permission, signal, operation, { write = false } = {}) {
    let client;
    try {
      await this.check(user, authorization, permission, signal, write); client = await this.database.getClient();
      await client.query(write ? 'BEGIN' : 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await client.query("SET LOCAL statement_timeout='7000ms';SET LOCAL lock_timeout='5000ms'");
      const result = await operation(client); await this.check(user, authorization, permission, signal, write); await client.query('COMMIT'); return result;
    } catch (error) {
      if (client) await client.query('ROLLBACK').catch(() => {});
      if (error.status) throw error;
      if (error.constraint === 'policy_configuration_version') fail(412, 'policy_configuration_changed');
      if (error.constraint === 'policy_configuration_lease') fail(428, 'fresh_mfa_required');
      if (error.constraint === 'policy_configuration_token_expired') fail(401, 'policy_operator_token_expired');
      if (['policy_publication_version', 'policy_publication_configuration'].includes(error.constraint)) fail(412, 'policy_publication_changed');
      if (['policy_publication_expired', 'policy_publication_required'].includes(error.constraint)) fail(409, 'current_independent_policy_publication_required');
      if (['23505','23514','40P01'].includes(error.code)) fail(409, 'policy_configuration_conflict');
      fail(503, 'policy_configuration_unavailable');
    } finally { client?.release(); }
  }
  observe(user, authorization, permission, signal, operation) { return this.transaction(user, authorization, permission, signal, operation); }
  async lock(client, kind, id, expected, user, authorization, permission, signal, alias) {
    identifier(id); if (!expected) fail(428, 'policy_version_required');
    const row = (await client.query(`SELECT * FROM ${table(kind)} WHERE id=$1 FOR UPDATE`, [id])).rows[0];
    if (!row || alias && row.type !== alias) fail(404, 'policy_resource_not_found');
    if (expected !== etag(kind,row)) fail(412, 'policy_configuration_changed');
    await this.check(user, authorization, permission, signal, true); return row;
  }
  async proof(client, proof) { await client.query("SELECT set_config('opendirectory.policy_configuration',$1,true),set_config('opendirectory.policy_scope','',true)", [JSON.stringify(proof)]); }
  async create(body, user, authorization, signal) {
    const values = normalize(body); const reason = body.reason.trim();
    return this.transaction(user, authorization, 'policies.manage', signal, async client => {
      await this.check(user, authorization, 'policies.manage', signal, true);
      await this.proof(client, context(user,'policies.manage','policy',null,0,'created',reason));
      const application = new PolicyApplicationService({ policyRepository: new PostgresPolicyRepository(client) });
      return application.createPolicy({ ...values, created_by: user.identity_authorization.userId, status: 'draft' });
    }, { write: true });
  }
  async mutate(id, expected, body, user, authorization, action, signal, alias) {
    identifier(id);if(!expected)fail(428,'policy_version_required');
    const permission = ['activated','deactivated'].includes(action) ? 'policies.deploy' : 'policies.manage';
    if (!['updated','activated','deactivated','deleted'].includes(action)) fail(400, 'policy_action_required');
    const reason = metadata(body, action === 'updated' ? ['name','description','type','platform','rules','settings','priority','enforce','block_inheritance','wmi_filter','security_filter'] : action === 'activated' ? ['publicationId'] : []);
    if (action === 'activated') identifier(body.publicationId);
    return this.transaction(user, authorization, permission, signal, async client => {
      const before = await this.lock(client,'policy',id,expected,user,authorization,permission,signal,alias);
      if (action === 'activated') await this.publications.checkUse(client,'policy',id,body.publicationId,user,authorization,signal);
      await this.proof(client,{...context(user,permission,'policy',id,before.version,action,reason),...(action==='activated'?{publicationId:body.publicationId}:{})});
      const application = new PolicyApplicationService({ policyRepository: new PostgresPolicyRepository(client) });
      if (action === 'updated') return application.updatePolicy(id, normalize(body,before));
      if (action === 'activated') {
        const changed = await application.activatePolicy(id);
        await this.publications.checkUse(client,'policy',id,body.publicationId,user,authorization,signal);return changed;
      }
      if (action === 'deactivated') return application.deactivatePolicy(id);
      await application.deletePolicy(id); return { id, deleted: true, version: before.version + 1 };
    }, { write: true });
  }
  async child(kind, id, expected, body, user, authorization, action, signal, childId, alias) {
    identifier(id);if(!expected)fail(428,'policy_version_required');
    const configuration = ['configuration_added','configuration_removed'].includes(action); const permission = configuration ? 'policies.manage' : 'policies.deploy';
    const allowed = action === 'configuration_added' ? ['config_type','config_name','payload'] : ['unlinked','configuration_removed'].includes(action) ? []
      : action === 'linked' ? ['target_type','target_id','target_name','enforce','link_order'] : kind === 'policy' ? ['targetType','targetId'] : ['target_type','target_id'];
    const reason = metadata(body, allowed); let targetType; let targetId;
    if (action === 'configuration_added') { if (!CONFIG_TYPES.includes(body.config_type) || !text(body.config_name)) fail(400,'blueprint_configuration_required'); object(body.payload || {}); }
    if (['linked','assigned'].includes(action)) {
      targetType = body.targetType ?? body.target_type; targetId = body.targetId ?? body.target_id;
      if (!['device','group','ou','site','domain'].includes(targetType) || !text(targetId) || /[/?#]/.test(targetId) || kind === 'blueprint' && !['device','group'].includes(targetType)) fail(400,'exact_policy_target_required');
      if (body.target_name !== undefined && !text(body.target_name) || body.enforce !== undefined && typeof body.enforce !== 'boolean' || body.link_order !== undefined && (!Number.isInteger(body.link_order) || body.link_order < 0 || body.link_order > 1000000)) fail(400,'exact_policy_link_required');
    }
    if (childId) identifier(childId);
    return this.transaction(user, authorization, permission, signal, async client => {
      const before = await this.lock(client,kind,id,expected,user,authorization,permission,signal,alias);
      await this.proof(client,context(user,permission,kind,id,before.version,action,reason)); let result;
      if (action === 'configuration_added') result = await client.query('INSERT INTO blueprint_configurations(blueprint_id,config_type,config_name,payload) VALUES($1,$2,$3,$4) RETURNING *',[id,body.config_type,body.config_name,JSON.stringify(body.payload || {})]);
      else if (action === 'configuration_removed') result = await client.query('DELETE FROM blueprint_configurations WHERE blueprint_id=$1 AND id=$2 RETURNING *',[id,childId]);
      else if (action === 'linked') result = await client.query('INSERT INTO policy_links(policy_id,target_type,target_id,target_name,enforce,link_order) VALUES($1,$2,$3,$4,$5,$6) RETURNING *',[id,targetType,targetId,body.target_name || null,body.enforce || false,body.link_order || 0]);
      else if (action === 'unlinked') result = await client.query('DELETE FROM policy_links WHERE policy_id=$1 AND id=$2 RETURNING *',[id,childId]);
      else if (action === 'assigned') result = await client.query(`INSERT INTO ${kind === 'policy' ? 'policy_assignments' : 'blueprint_assignments'}(${kind === 'policy' ? 'policy_id' : 'blueprint_id'},target_type,target_id,assigned_by) VALUES($1,$2,$3,$4) RETURNING *`,[id,targetType,targetId,user.identity_authorization.userId]);
      else fail(400,'policy_child_action_required');
      if (!result.rows.length) fail(404,'policy_child_not_found');
      const parent = (await client.query(`SELECT * FROM ${table(kind)} WHERE id=$1`,[id])).rows[0]; return { row: result.rows[0], parent };
    }, { write: true });
  }
  async blueprint(body, user, authorization, signal, id, expected, action = 'created') {
    if(!['created','updated','deleted'].includes(action)||action==='created'&&id||action!=='created'&&!id)fail(400,'blueprint_action_required');
    if(id){identifier(id);if(!expected)fail(428,'policy_version_required');}
    const reason = metadata(body, action === 'deleted' ? [] : ['name','description','platform']);
    if (action === 'created' || Object.hasOwn(body,'name')) if (!text(body.name)) fail(400,'blueprint_name_required');
    if (body.platform !== undefined && !PLATFORMS.includes(body.platform) || body.description !== undefined && body.description !== null && (typeof body.description !== 'string' || body.description.length > 4000)) fail(400,'blueprint_metadata_required');
    return this.transaction(user,authorization,'policies.manage',signal,async client => {
      const before = id ? await this.lock(client,'blueprint',id,expected,user,authorization,'policies.manage',signal) : null;
      await this.proof(client,context(user,'policies.manage','blueprint',id || null,before?.version || 0,action,reason));
      if (action === 'deleted') { const deleted=await client.query('DELETE FROM blueprints WHERE id=$1 RETURNING id',[id]);if(deleted.rows.length!==1)fail(409,'blueprint_deletion_unconfirmed');return { id, deleted: true, version: before.version + 1 }; }
      if (action === 'created') return (await client.query('INSERT INTO blueprints(name,description,platform,created_by) VALUES($1,$2,$3,$4) RETURNING *',[body.name,body.description || null,body.platform || 'all',user.identity_authorization.userId])).rows[0];
      return (await client.query('UPDATE blueprints SET name=COALESCE($2,name),description=COALESCE($3,description),platform=COALESCE($4,platform) WHERE id=$1 RETURNING *',[id,body.name || null,body.description,body.platform || null])).rows[0];
    },{write:true});
  }
  async snapshot(kind,id,user,authorization,signal,alias) {
    identifier(id);
    return this.observe(user,authorization,'policies.read',signal,async client => {
      const row = (await client.query(`SELECT * FROM ${table(kind)} WHERE id=$1`,[id])).rows[0]; if (!row || alias && row.type !== alias) fail(404,'policy_resource_not_found');
      const assignments = (await client.query(`SELECT * FROM ${kind === 'policy' ? 'policy_assignments' : 'blueprint_assignments'} WHERE ${kind === 'policy' ? 'policy_id' : 'blueprint_id'}=$1 ORDER BY id LIMIT 1001`,[id])).rows;
      if (assignments.length > 1000) fail(409,'policy_scope_limit_reached');
      if(new Set(assignments.map(item=>item.target_type+':'+item.target_id)).size!==assignments.length)fail(409,'ambiguous_policy_scope');
      if (kind === 'policy') { const links=(await client.query('SELECT * FROM policy_links WHERE policy_id=$1 ORDER BY link_order,id LIMIT 1001',[id])).rows;if(links.length>1000)fail(409,'policy_scope_limit_reached');return { row: policy(row), assignments, links }; }
      const configurations = (await client.query('SELECT * FROM blueprint_configurations WHERE blueprint_id=$1 ORDER BY created_at,id LIMIT 1001',[id])).rows;
      if (configurations.length > 1000) fail(409,'policy_configuration_limit_reached'); return { row, assignments, configurations };
    });
  }
  async previewBlueprints(body, user, authorization, signal) {
    const values = previewValues(body);
    return this.observe(user, authorization, 'policies.preview', signal, async client => {
      const identifiers = values.blueprints.map(item => item.id);
      const retained = (await client.query('SELECT id,name,platform,version FROM blueprints WHERE id=ANY($1::uuid[])', [identifiers])).rows;
      const blueprints = values.blueprints.map(item => {
        const row = retained.find(candidate => candidate.id === item.id);
        if (!row) fail(404, 'policy_resource_not_found');
        if (row.version !== item.version) fail(412, 'policy_configuration_changed');
        if (!text(row.name) || !PLATFORMS.includes(row.platform)) fail(503, 'blueprint_preview_source_unavailable');
        if (row.platform !== 'all' && row.platform !== values.platform) fail(409, 'blueprint_platform_mismatch');
        return { id: row.id, name: row.name, platform: row.platform, version: row.version };
      });
      const configurations = await readConfigurations(client, identifiers);
      return { schemaVersion: 1, scope: 'selected-blueprint-versions', comparison: 'whole-config-type', platform: values.platform,
        previewOnly: true, enforcementConfirmed: false, licenseReservations: 0, blueprints, ...resolveConfigurations(configurations) };
    });
  }
  async assertVersion(kind,id,version) {
    const row = (await this.database.query(`SELECT version FROM ${table(kind)} WHERE id=$1`,[id])).rows[0];
    if (!row || row.version !== version) fail(412,'policy_configuration_changed');
  }
}
module.exports = { PolicyConfiguration, identifier, metadata, fields, object, json, text, etag, policy, context, TYPES, PLATFORMS, fail };
