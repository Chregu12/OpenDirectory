'use strict';

const { readRoleState } = require('./RoleState');
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

class LicenseReviewerSnapshotStore {
  constructor(database, roles = ['admin', 'license-reviewer']) { this.database = database; this.roles = roles; }
  async snapshot(userId, issuer) {
    if (typeof userId !== 'string' || !UUID.test(userId)) throw Object.assign(new Error('Canonical reviewer UUID required'), { status: 400 });
    return this.database.transaction(async client => {
      const user = (await client.query('SELECT identity_tenant_user_enabled(users.id) AS enabled,EXISTS(SELECT 1 FROM identity_subject_links WHERE user_id=users.id AND issuer=$2) AS linked FROM users WHERE id=$1', [userId, issuer])).rows[0];
      if (!user) throw Object.assign(new Error('Reviewer not found'), { status: 404 });
      const state = await readRoleState(client, userId);
      return { schemaVersion: 1, userId, enabled: user.enabled, linked: user.linked,
        canReview: user.enabled && user.linked && state.roles.some(role => this.roles.includes(role)) };
    }, { readOnly: true });
  }
}

module.exports = { LicenseReviewerSnapshotStore };
