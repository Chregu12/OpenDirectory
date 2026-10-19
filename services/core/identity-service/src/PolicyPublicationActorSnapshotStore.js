'use strict';

const { createHash } = require('node:crypto');
const { validUuid, validRevision } = require('../../../../packages/identity-authorization-contract');
const { readRoleState } = require('./RoleState');

class PolicyPublicationActorSnapshotStore {
  constructor(database) { this.database = database; }
  async snapshot(userId, issuer) {
    if (!validUuid(userId) || userId !== userId.toLowerCase()) throw Object.assign(new Error('Canonical policy actor required'), { status: 400 });
    return this.database.transaction(async client => {
      const row = (await client.query(`SELECT identity_tenant_user_enabled(users.id) AS enabled,users.eligibility_revision,users.authorization_revision,link.authorization_revision AS link_revision,
        link.user_id IS NOT NULL AS linked FROM users LEFT JOIN identity_subject_links link ON link.user_id=users.id AND link.issuer=$2
        WHERE users.id=$1`, [userId, issuer])).rows[0];
      if (!row) throw Object.assign(new Error('Policy actor not found'), { status: 404 });
      if (!validRevision(String(row.eligibility_revision)) || !validRevision(String(row.authorization_revision)) || row.linked && !validRevision(String(row.link_revision))) throw new Error('Policy actor authority unavailable');
      const state = await readRoleState(client, userId, { publicationEvidence: true });
      const revision = value => row.enabled && row.linked && value ? createHash('sha256')
        .update(JSON.stringify(['policy-publication-actor-v1', issuer, String(row.eligibility_revision), String(row.authorization_revision), String(row.link_revision), value])).digest('hex') : null;
      return { schemaVersion: 1, userId, revision: String(row.eligibility_revision), enabled: row.enabled, linked: row.linked,
        requestRevision: revision(state.publicationRequestRevision), reviewRevision: revision(state.publicationReviewRevision) };
    }, { readOnly: true });
  }
}
module.exports = { PolicyPublicationActorSnapshotStore };
