'use strict';

const { identifier, metadata, etag, context, fail } = require('./PolicyConfiguration');
const { PolicyPublicationSource } = require('./PolicyPublicationSource');
const publicationTag = row => `"od-policy-publication:${row.id}:${row.version}"`;
const resourceTable = kind => {
  if (!['policy', 'blueprint'].includes(kind)) fail(400, 'policy_resource_kind_required');
  return kind === 'policy' ? 'policies' : 'blueprints';
};
const view = row => ({ id: row.id, resourceKind: row.resource_kind, resourceId: row.resource_id, resourceVersion: row.resource_version,
  configurationVersion: row.configuration_version, configurationHash: row.configuration_hash, requestedBy: row.requested_by, reviewerUserId: row.reviewer_user_id,
  state: row.state, version: row.version, expiresAt: new Date(row.expires_at).toISOString(), decidedBy: row.decided_by || null, current: row.current === true });

class PolicyPublication {
  constructor(store, { source = new PolicyPublicationSource() } = {}) { this.store = store; this.source = source; }
  async actor(id, authorization, signal, duty, expected) {
    const row = await this.source.actor(id, authorization, signal); const revision = row[duty];
    if (!row.enabled || !row.linked || typeof revision !== 'string' || !/^[a-f0-9]{64}$/.test(revision) || expected && revision !== expected) fail(409, 'policy_publication_authority_changed');
    return revision;
  }
  async sources(row, authorization, signal) {
    await this.actor(row.requested_by, authorization, signal, 'requestRevision', row.requester_revision);
    await this.actor(row.reviewer_user_id, authorization, signal, 'reviewRevision', row.reviewer_revision);
  }
  async frame(client, kind, id) {
    identifier(id);
    const row = (await client.query(`SELECT resource.version,head.configuration_version,head.verified_origin,
      policy_publication_hash($2,resource.id) AS configuration_hash,policy_publication_frame($2,resource.id) AS frame
      FROM ${resourceTable(kind)} resource JOIN policy_publication_heads head ON head.resource_kind=$2 AND head.resource_id=resource.id WHERE resource.id=$1`, [id, kind])).rows[0];
    if (!row) fail(404, 'policy_resource_not_found');
    return row;
  }
  async get(kind, id, user, authorization, signal) {
    return this.store.observe(user, authorization, 'policies.read', signal, async client => {
      const frame = await this.frame(client, kind, id);
      const rows = (await client.query(`SELECT publication.*,policy_publication_usable(publication.id,$1,$2) AS current FROM policy_publications publication
        WHERE resource_kind=$1 AND resource_id=$2 ORDER BY (expires_at>policy_configuration_now() AND state IN('pending','approved')) DESC,created_at DESC,id LIMIT 50`, [kind, id])).rows;
      const contributors = (await client.query(`SELECT DISTINCT actor->>'userId' AS id FROM policy_configuration_audit
        WHERE resource_kind=$1 AND resource_id=$2 AND action NOT IN('activated','deactivated','deleted') ORDER BY id LIMIT 1001`, [kind, id])).rows.map(row => row.id);
      if (contributors.length > 1000) fail(409, 'policy_contributor_limit_reached');
      const total = (await client.query('SELECT count(*)::int AS count FROM policy_publications WHERE resource_kind=$1 AND resource_id=$2', [kind, id])).rows[0].count;
      return { schemaVersion: 1, resourceKind: kind, resourceId: id, resourceVersion: frame.version, configurationVersion: frame.configuration_version,
        configurationHash: frame.configuration_hash, frame: frame.frame, verifiedOrigin: frame.verified_origin, contributors, publications: rows.map(view), total, limit: 50 };
    });
  }
  async proof(client, proof) { await client.query("SELECT set_config('opendirectory.policy_publication',$1,true)", [JSON.stringify(proof)]); }
  async request(kind, id, expected, body, user, authorization, signal) {
    identifier(id); resourceTable(kind); if (!expected) fail(428, 'policy_version_required');
    const reason = metadata(body, ['reviewerUserId', 'validitySeconds', 'configurationHash']); identifier(body.reviewerUserId);
    if (!Number.isInteger(body.validitySeconds) || body.validitySeconds < 300 || body.validitySeconds > 28800 || !/^[a-f0-9]{64}$/.test(body.configurationHash)) fail(400, 'bounded_publication_confirmation_required');
    return this.store.transaction(user, authorization, 'policies.publication.request', signal, async client => {
      const parent = await this.store.lock(client, kind, id, expected, user, authorization, 'policies.publication.request', signal);
      const frame = await this.frame(client, kind, id);
      if (!frame.verified_origin) fail(409, 'verified_policy_origin_required');
      if (frame.configuration_hash !== body.configurationHash) fail(412, 'policy_configuration_changed');
      const requester = user.identity_authorization.userId;
      if (requester === body.reviewerUserId || !(await client.query('SELECT policy_publication_independent($1,$2,$3) AS independent', [kind, id, body.reviewerUserId])).rows[0].independent) fail(403, 'independent_policy_reviewer_required');
      const requesterRevision = await this.actor(requester, authorization, signal, 'requestRevision');
      const reviewerRevision = await this.actor(body.reviewerUserId, authorization, signal, 'reviewRevision');
      await this.proof(client, { ...context(user, 'policies.publication.request', kind, id, 0, 'requested', reason), requesterRevision, reviewerRevision });
      const row = (await client.query(`INSERT INTO policy_publications(resource_kind,resource_id,resource_version,configuration_version,configuration_hash,issuer,
        requested_by,reviewer_user_id,requester_revision,reviewer_revision,validity_seconds,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,policy_configuration_now()) RETURNING *`,
      [kind, id, parent.version, frame.configuration_version, frame.configuration_hash, user.iss, requester, body.reviewerUserId, requesterRevision, reviewerRevision, body.validitySeconds])).rows[0];
      await this.sources(row, authorization, signal); return view(row);
    }, { write: true });
  }
  async transition(kind, id, publicationId, expected, body, user, authorization, signal) {
    identifier(id); identifier(publicationId); resourceTable(kind); if (!expected) fail(428, 'policy_publication_version_required');
    const reason = metadata(body, ['decision', 'resourceVersion', 'configurationHash']);
    if (!['approved', 'denied', 'withdrawn'].includes(body.decision) || !Number.isSafeInteger(body.resourceVersion) || body.resourceVersion < 1 || !/^[a-f0-9]{64}$/.test(body.configurationHash)) fail(400, 'exact_publication_decision_required');
    const preliminary = await this.store.observe(user, authorization, 'policies.read', signal, async client =>
      (await client.query('SELECT requested_by FROM policy_publications WHERE id=$1 AND resource_kind=$2 AND resource_id=$3', [publicationId, kind, id])).rows[0]);
    if (!preliminary) fail(404, 'policy_publication_not_found');
    const permission = body.decision === 'withdrawn' && preliminary.requested_by === user.identity_authorization.userId ? 'policies.publication.request' : 'policies.publication.review';
    if (permission === 'policies.publication.review' && !user.roles?.includes('policy-publication-reviewer')) fail(403, 'explicit_policy_reviewer_required');
    return this.store.transaction(user, authorization, permission, signal, async client => {
      await this.store.lock(client, kind, id, etag(kind, { id, version: body.resourceVersion }), user, authorization, permission, signal);
      const row = (await client.query('SELECT * FROM policy_publications WHERE id=$1 AND resource_kind=$2 AND resource_id=$3 FOR UPDATE', [publicationId, kind, id])).rows[0];
      if (!row || row.issuer !== user.iss) fail(404, 'policy_publication_not_found');
      if (expected !== publicationTag(row)) fail(412, 'policy_publication_changed');
      if (body.decision === 'withdrawn' ? !['pending','approved'].includes(row.state) : row.state !== 'pending' || new Date(row.expires_at).getTime() <= Date.now()) fail(409, 'policy_publication_terminal_or_expired');
      if (body.configurationHash !== row.configuration_hash) fail(412, 'policy_configuration_changed');
      if (body.decision === 'withdrawn') {
        if (![row.requested_by, row.reviewer_user_id].includes(user.identity_authorization.userId)) fail(403, 'original_publication_actor_required');
      } else {
        if (row.reviewer_user_id !== user.identity_authorization.userId || row.requested_by === row.reviewer_user_id) fail(403, 'independent_assigned_policy_reviewer_required');
        await this.sources(row, authorization, signal);
      }
      await this.proof(client, { ...context(user, permission, kind, id, row.version, body.decision, reason), publicationId,
        requesterRevision: row.requester_revision, reviewerRevision: row.reviewer_revision });
      const changed = (await client.query('UPDATE policy_publications SET state=$2 WHERE id=$1 RETURNING *', [publicationId, body.decision])).rows[0];
      if (body.decision !== 'withdrawn') await this.sources(row, authorization, signal); return view(changed);
    }, { write: true });
  }
  async checkUse(client, kind, id, publicationId, user, authorization, signal) {
    identifier(publicationId);
    const row = (await client.query('SELECT *,policy_publication_usable(id,$2,$3) AS current FROM policy_publications WHERE id=$1 AND resource_kind=$2 AND resource_id=$3', [publicationId, kind, id])).rows[0];
    if (!row || row.issuer !== user.iss || !row.current) fail(409, 'current_independent_policy_publication_required');
    await this.sources(row, authorization, signal); return row;
  }
  async assertUse(kind, id, version, publicationId, user, authorization, signal) {
    identifier(id); resourceTable(kind); identifier(publicationId);
    return this.store.transaction(user, authorization, 'policies.deploy', signal, async client => {
      await this.store.lock(client, kind, id, etag(kind, { id, version }), user, authorization, 'policies.deploy', signal);
      return view(await this.checkUse(client, kind, id, publicationId, user, authorization, signal));
    }, { write: true });
  }
  async deliveryFrame(body, user, authorization, signal) {
    const contract = require('../../../../packages/policy-command-contract');
    contract.fields(body, ['reference','deviceId','platform','operationId']);
    const reference = contract.reference(body.reference);
    if (!contract.deviceId(body.deviceId) || !['windows','macos','linux'].includes(body.platform) || !contract.uuid(body.operationId)) fail(400, 'exact_policy_device_scope_required');
    const kind = reference.resourceKind; const id = reference.resourceId;
    return this.store.transaction(user, authorization, 'policies.deploy', signal, async client => {
      const parent = await this.store.lock(client, kind, id, etag(kind, { id, version: reference.resourceVersion }), user, authorization, 'policies.deploy', signal);
      const approval = await this.checkUse(client, kind, id, reference.publicationId, user, authorization, signal);
      const targets = (await client.query(`SELECT id FROM ${kind === 'policy' ? 'policy_assignments' : 'blueprint_assignments'}
        WHERE ${kind === 'policy' ? 'policy_id' : 'blueprint_id'}=$1 AND target_type='device' AND target_id=$2 LIMIT 2`, [id, body.deviceId])).rows;
      if (targets.length !== 1) fail(409, 'explicit_unique_policy_device_target_required');
      let payload;
      if (kind === 'policy') {
        if (parent.type !== 'gpo' || parent.status !== 'active' || !parent.settings?.platforms?.includes(body.platform)) fail(409, 'active_matching_gpo_required');
        payload = { gpoId: id, gpoName: parent.name, configurationVersion: parent.version, settings: parent.settings.configuration };
      } else {
        if (parent.platform !== 'all' && parent.platform !== body.platform) fail(409, 'matching_blueprint_platform_required');
        const { readConfigurations, resolveConfigurations } = require('./BlueprintPreview');
        if (resolveConfigurations(await readConfigurations(client, [id])).hasConflicts) fail(409, 'blueprint_configuration_conflict');
        const configuration = (await client.query('SELECT * FROM blueprint_configurations WHERE blueprint_id=$1 AND id=$2', [id, reference.configurationId])).rows[0];
        if (!configuration) fail(404, 'blueprint_configuration_not_found');
        const lossless = (await client.query('SELECT payload=$2::jsonb AS lossless FROM blueprint_configurations WHERE id=$1', [configuration.id, JSON.stringify(configuration.payload)])).rows[0];
        if (lossless?.lossless !== true) fail(503, 'blueprint_payload_not_lossless');
        payload = { blueprintId: id, blueprintName: parent.name, configurationId: configuration.id, configurationVersion: parent.version,
          configType: configuration.config_type, configName: configuration.config_name, settings: configuration.payload };
      }
      contract.json(payload);
      const observed = (await client.query("SELECT policy_configuration_now() AS observed_at,encode(sha256(convert_to($1::jsonb::text,'UTF8')),'hex') AS payload_hash", [JSON.stringify(payload)])).rows[0];
      const now = new Date(observed.observed_at).getTime();
      const deliverUntil = Math.min(now + contract.DELIVERY_SECONDS * 1000, new Date(approval.expires_at).getTime(), user.exp * 1000, (user.auth_time + 300) * 1000);
      const result = { schemaVersion: 1, reference, deviceId: body.deviceId, platform: body.platform, operatorUserId: user.identity_authorization.userId, operationId: body.operationId,
        configurationVersion: approval.configuration_version, configurationHash: approval.configuration_hash, publicationVersion: approval.version,
        publicationExpiresAt: new Date(approval.expires_at).toISOString(), observedAt: new Date(now).toISOString(),
        admissionValidUntil: new Date(Math.min(now + contract.ADMISSION_SECONDS * 1000, deliverUntil)).toISOString(), deliverUntil: new Date(deliverUntil).toISOString(), payload, payloadHash: observed.payload_hash };
      await this.sources(approval, authorization, signal);
      return contract.frame(result, { ...body, operatorUserId: user.identity_authorization.userId });
    }, { write: true });
  }
}
module.exports = { PolicyPublication, publicationTag };
