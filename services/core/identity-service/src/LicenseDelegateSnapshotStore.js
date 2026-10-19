'use strict';

const { readRoleState } = require('./RoleState');
const { createHash } = require('crypto');
const { validRevision } = require('../../../../packages/identity-authorization-contract');
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
class LicenseDelegateSnapshotStore {
  constructor(database) { this.database = database; }
  async snapshot(userId, viewer, canReadAny) {
    if (typeof userId !== 'string' || !UUID.test(userId)) throw Object.assign(new Error('Canonical delegate UUID required'), { status: 400 });
    return this.database.transaction(async client => {
      if (!canReadAny && (await client.query('SELECT user_id FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [viewer.issuer, viewer.subject])).rows[0]?.user_id !== userId) throw Object.assign(new Error('Delegate snapshot denied'), { status: 403 });
      const user = (await client.query('SELECT identity_tenant_user_enabled(users.id) AS enabled,users.eligibility_revision,link.authorization_revision AS link_revision,link.user_id IS NOT NULL AS linked FROM users LEFT JOIN identity_subject_links link ON link.user_id=users.id AND link.issuer=$2 WHERE users.id=$1', [userId, viewer.issuer])).rows[0];
      if (!user) throw Object.assign(new Error('Delegate not found'), { status: 404 });
      if (user.linked && !validRevision(String(user.link_revision))) throw Object.assign(new Error('Delegate link authority unavailable'), { status: 503 });
      const state = await readRoleState(client, userId, { delegateEvidence: true });
      return { schemaVersion: 1, userId, revision: String(user.eligibility_revision), enabled: user.enabled, linked: user.linked,
        delegationRevision: user.enabled && user.linked && state.delegationRevision ? createHash('sha256').update(JSON.stringify(['license-delegate-link-v1',viewer.issuer,String(user.link_revision),state.delegationRevision])).digest('hex') : null };
    }, { readOnly: true });
  }
}
module.exports = { LicenseDelegateSnapshotStore };
