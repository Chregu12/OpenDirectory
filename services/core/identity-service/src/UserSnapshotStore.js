'use strict';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

class UserSnapshotStore {
  constructor(database) { this.database = database; }

  async snapshot(userId, viewer, canReadAny = false) {
    if (typeof userId !== 'string' || !UUID.test(userId)) throw Object.assign(new Error('A canonical user UUID is required'), { status: 400 });
    return this.database.transaction(async client => {
      if (!canReadAny) {
        const link = await client.query('SELECT user_id FROM identity_subject_links WHERE issuer=$1 AND subject=$2', [viewer?.issuer, viewer?.subject]);
        if (link.rows[0]?.user_id !== userId) throw Object.assign(new Error('User eligibility read is not permitted'), { status: 403 });
      }
      const result = await client.query('SELECT id,identity_tenant_user_enabled(id) AS enabled,eligibility_revision FROM users WHERE id=$1', [userId]);
      if (result.rows.length) return { schemaVersion: 1, userId, revision: String(result.rows[0].eligibility_revision), enabled: result.rows[0].enabled, deleted: false };
      const tombstone = await client.query('SELECT revision FROM identity_deleted_users WHERE user_id=$1', [userId]);
      if (!tombstone.rows.length) throw Object.assign(new Error('Identity user not found'), { status: 404 });
      return { schemaVersion: 1, userId, revision: String(tombstone.rows[0].revision), enabled: false, deleted: true };
    }, { readOnly: true });
  }
}

module.exports = { UserSnapshotStore };
