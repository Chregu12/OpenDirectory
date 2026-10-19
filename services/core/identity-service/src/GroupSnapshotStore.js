'use strict';
const{SCHEMA_VERSION,LEASE_SECONDS,MAX_MEMBERS}=require('../../../../packages/group-license-lease-contract');

class GroupSnapshotStore {
  constructor(database) { this.database = database; }

  async resolveSubject(client, viewer) {
    const link = viewer ? await client.query(`SELECT account.id,identity_tenant_user_enabled(account.id) AS enabled FROM identity_subject_links links JOIN users account ON account.id=links.user_id
      WHERE links.issuer=$1 AND links.subject=$2`, [viewer.issuer, viewer.subject]) : { rows: [] };
    return { userId: link.rows[0]?.id || null, enabled: link.rows[0]?.enabled ?? null };
  }

  async subject(viewer) {
    return this.database.transaction(async client => ({ schemaVersion: 1, issuer: viewer.issuer, subject: viewer.subject, ...await this.resolveSubject(client, viewer) }), { readOnly: true });
  }

  async snapshot(groupId, viewer, {authorize}={}) {
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(groupId)) {
      throw Object.assign(new Error('Invalid group identifier'), { status: 400 });
    }
    return this.database.transaction(async client => {
      const link = await this.resolveSubject(client, viewer);
      const viewerState = { viewerUserId: link.userId, viewerEnabled: link.enabled };
      const sourceAuthorization=authorize?await authorize(client):null;
      await client.query('SELECT identity_membership_review_refresh($1)',[groupId]);
      const observed=(await client.query("SELECT date_trunc('milliseconds',identity_group_snapshot_now()) AS observed_at")).rows[0].observed_at;
      const observation={observedAt:observed.toISOString(),validUntil:new Date(observed.getTime()+LEASE_SECONDS*1000).toISOString()};
      const result = await client.query("SELECT id, name, revision FROM groups WHERE id = $1 AND identity_tenant_id('group',id) IS NOT NULL", [groupId]);
      if (!result.rows.length) {
        const tombstone = await client.query('SELECT group_id, revision FROM identity_deleted_groups WHERE group_id = $1', [groupId]);
        if (!tombstone.rows.length) throw Object.assign(new Error('Group not found'), { status: 404 });
        if(authorize&&JSON.stringify(sourceAuthorization)!==JSON.stringify(await authorize(client)))throw Object.assign(new Error('Source consent changed'),{status:409});
        return { schemaVersion:SCHEMA_VERSION,groupId:tombstone.rows[0].group_id,name:null,revision:String(tombstone.rows[0].revision),deleted:true,memberIds:[],inactiveMemberIds:[],unresolvedMemberIds:[],memberships:[],sourceAuthorization,...observation,...viewerState };
      }
      const group = result.rows[0];
      const coherent=(await client.query(`SELECT NOT EXISTS(SELECT 1 FROM group_members member
        WHERE member.group_id=$1
        AND identity_tenant_id('user',CASE WHEN member.user_id ~* '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN member.user_id::uuid END) IS NOT NULL
        AND identity_tenant_id('user',CASE WHEN member.user_id ~* '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN member.user_id::uuid END) IS DISTINCT FROM identity_tenant_id('group',member.group_id)) AS coherent`,[groupId])).rows[0]?.coherent;
      if(coherent!==true)throw Object.assign(new Error('Group contains foreign retained identities'),{status:503});
      const members = await client.query(`SELECT membership.user_id,membership.membership_id,account.id,
        (identity_tenant_user_enabled(account.id) AND identity_tenant_id('user',account.id)=identity_tenant_id('group',membership.group_id)) AS enabled,account.eligibility_revision,
        review.deadline_at AS review_deadline_at,identity_membership_review_allowed(membership.membership_id) AS review_allowed FROM group_members membership
        LEFT JOIN users account ON account.id::text=membership.user_id LEFT JOIN identity_membership_review_leases review ON review.membership_id=membership.membership_id
        WHERE membership.group_id=$1 ORDER BY membership.user_id LIMIT ${MAX_MEMBERS+1}`, [groupId]);
      if (members.rows.length > MAX_MEMBERS) throw Object.assign(new Error('Group exceeds the snapshot size limit'), { status: 413 });
      const active=member=>member.id&&member.enabled&&member.review_allowed===true&&(!member.review_deadline_at||member.review_deadline_at>observed);
      if(authorize&&JSON.stringify(sourceAuthorization)!==JSON.stringify(await authorize(client)))throw Object.assign(new Error('Source consent changed'),{status:409});
      return {
        schemaVersion:SCHEMA_VERSION,groupId:group.id,name:group.name,revision:String(group.revision),deleted:false,sourceAuthorization,...viewerState,...observation,
        memberIds:members.rows.filter(active).map(member=>member.id),
        inactiveMemberIds:members.rows.filter(member=>member.id&&!active(member)).map(member=>member.id),
        unresolvedMemberIds: members.rows.filter(member => !member.id).map(member => member.user_id),
        memberships:members.rows.filter(active).map(member=>({userId:member.id,membershipId:member.membership_id,eligibilityRevision:String(member.eligibility_revision),reviewDeadlineAt:member.review_deadline_at?.toISOString()||null})),
      };
    });
  }
}

module.exports = { GroupSnapshotStore };
