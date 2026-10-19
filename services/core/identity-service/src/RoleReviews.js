'use strict';

const { ROLES, PROTECTED } = require('../../../../packages/directory-role-contract');
const { sameContext } = require('../../../../packages/identity-authorization-contract');
const { acceptsRoleAuthentication } = require('../../../../packages/role-authentication-contract');
const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { authority, uuid, fields, reason } = require('./PrivilegedActivation');
const { readRoleState } = require('./RoleState');
const { getIdentityPermissions } = require('./middleware/identityAccess');
const { beginAuthorityCheckpoint, checkpointError } = require('./AuthorityCheckpoint');
function fail(status, code) { throw Object.assign(new Error(code),{ status,code }); }
const fresh = user => acceptsRoleAuthentication({ required:true,maxAgeSeconds:300 },user);
const iso = value => value ? new Date(value).toISOString() : null;
const policyTag = row => `"od-role-review-policy:${row.id}:${row.version}"`;
const reviewTag = row => `"od-role-review:${row.id}:${row.version}:${row.policyVersion || row.review_policy_version}"`;
const TARGETS = Object.freeze({ assignment:'identity_role_assignments',eligibility:'identity_pim_eligibilities' });
const REVIEW_SELECT = `SELECT lease.*,policy.role,policy.version AS review_policy_version,policy.interval_seconds,policy.window_seconds,policy.reviewer_user_ids,policy.retired_at AS policy_retired_at,
 users.enabled AS user_enabled,CASE WHEN lease.target_kind='assignment' THEN assignment.id IS NOT NULL ELSE eligibility.id IS NOT NULL END AS source_exists,
 CASE WHEN lease.target_kind='assignment' THEN assignment.expires_at ELSE eligibility.expires_at END AS source_expires_at,
 CASE WHEN lease.target_kind='assignment' THEN assignment.revoked_at ELSE eligibility.revoked_at END AS source_revoked_at,
 CASE WHEN lease.target_kind='assignment' THEN assignment.policy_version=activation.version AND (NOT activation.activation_required OR assignment.activation_request_id IS NOT NULL)
  AND (assignment.activation_request_id IS NULL OR identity_role_review_eligible(request.eligibility_id)) ELSE true END AS source_current,
 clock_timestamp() AS source_now,identity_role_review_now() AS observed_at FROM identity_role_review_leases lease
 JOIN identity_role_review_policies policy ON policy.id=lease.policy_id LEFT JOIN users ON users.id=lease.user_id
 LEFT JOIN identity_role_assignments assignment ON lease.target_kind='assignment' AND assignment.id=lease.target_id
 LEFT JOIN identity_role_activation_policies activation ON activation.role=assignment.role
 LEFT JOIN identity_pim_requests request ON request.id=assignment.activation_request_id
 LEFT JOIN identity_pim_eligibilities eligibility ON lease.target_kind='eligibility' AND eligibility.id=lease.target_id`;

class RoleReviews {
  constructor(database,{ revalidate }={}) {
    this.database=database;
    const accessState=createAccessStateClient(); this.revalidate=revalidate || ((user,authorization)=>accessState(authorization,user));
  }
  actor(user,permission,write=false) {
    const proof=authority(user);
    if(permission && !getIdentityPermissions(user).includes(permission))fail(403,'forbidden');
    if(write && !fresh(user))fail(428,'fresh_mfa_required');
    return proof;
  }
  async currentActor(client,user,permission) {
    const row=(await client.query(`SELECT users.id,users.enabled,users.authorization_revision AS revision,link.authorization_revision AS link_revision
      FROM users JOIN identity_subject_links link ON link.user_id=users.id WHERE issuer=$1 AND subject=$2`,[user.iss,user.sub])).rows[0];
    if(!row?.enabled)fail(401,'authorization_changed');
    const state=await readRoleState(client,row.id);
    if(!sameContext({ userId:row.id,revision:String(row.revision),linkRevision:String(row.link_revision),rolesRevision:state.rolesRevision },user.identity_authorization)
      || !getIdentityPermissions({ roles:state.roles }).includes(permission) || !acceptsRoleAuthentication(state.authentication,user))fail(401,'authorization_changed');
  }
  async lock(client,role) { await client.query("SELECT pg_advisory_xact_lock(hashtextextended('od-role-reviews:'||$1,0))",[role]); }
  async context(client,explanation,action,proof) {
    await client.query("SELECT set_config('opendirectory.review_reason',$1,true),set_config('opendirectory.review_action',$2,true),set_config('opendirectory.review_proof',$3,true)",
      [explanation,action,proof ? JSON.stringify({ userId:proof.identity_authorization.userId,authTime:proof.auth_time,factorRevision:proof.mfa_authorization.revision }) : '']);
  }
  management(role,user) {
    return role!=='user' && getIdentityPermissions(user).includes('reviews.policies.manage') && (!PROTECTED.includes(role) || user.roles?.includes('admin'));
  }
  policyView(row,user) {
    const allowed=this.management(row.role,user) && !row.retired_at;
    return { id:row.id,role:row.role,version:String(row.version),intervalSeconds:row.interval_seconds,windowSeconds:row.window_seconds,
      reviewerUserIds:row.reviewer_user_ids,createdAt:iso(row.created_at),retiredAt:iso(row.retired_at),protected:PROTECTED.includes(row.role),
      canRetire:!!allowed && fresh(user),requiresFreshMfa:!!allowed && !fresh(user) };
  }
  async policy(role,user) {
    this.actor(user,'reviews.policies.read'); if(!ROLES.includes(role))fail(400,'catalog_role_required');
    return this.database.transaction(async client=>{
      const row=(await client.query('SELECT * FROM identity_role_review_policies WHERE role=$1 ORDER BY (retired_at IS NULL) DESC,created_at DESC,id LIMIT 1',[role])).rows[0];
      const allowed=this.management(role,user) && (!row || !!row.retired_at);
      return { role,policy:row ? this.policyView(row,user) : null,canCreate:allowed && fresh(user),requiresFreshMfa:allowed && !fresh(user) };
    },{ readOnly:true });
  }
  async create(body,user,authorization) {
    const proof=this.actor(user,'reviews.policies.manage',true);
    fields(body,['role','intervalSeconds','windowSeconds','reviewerUserIds','reason','acknowledgeDeadlines']); const explanation=reason(body.reason);
    if(!ROLES.includes(body.role) || body.role==='user' || !Number.isInteger(body.intervalSeconds) || body.intervalSeconds<3600 || body.intervalSeconds>31536000
      || !Number.isInteger(body.windowSeconds) || body.windowSeconds<60 || body.windowSeconds>604800 || body.windowSeconds>=body.intervalSeconds
      || body.acknowledgeDeadlines!==true || !Array.isArray(body.reviewerUserIds) || !body.reviewerUserIds.length || body.reviewerUserIds.length>20
      || body.reviewerUserIds.some((identifier,index)=>uuid(identifier)!==identifier || index>0 && body.reviewerUserIds[index-1]>=identifier))fail(400,'invalid_review_policy');
    if(!this.management(body.role,user))fail(403,'global_administrator_required');
    return this.database.transaction(async client=>{
      const checkpoint=await beginAuthorityCheckpoint(client,user);
      await this.lock(client,body.role); await this.currentActor(client,user,'reviews.policies.manage'); await this.revalidate(user,authorization);
      if((await client.query('SELECT id FROM identity_role_review_policies WHERE role=$1 AND retired_at IS NULL',[body.role])).rows.length)fail(409,'review_policy_exists');
      for(const identifier of body.reviewerUserIds) {
        const recipient=(await client.query('SELECT id FROM users WHERE id=$1 AND enabled AND EXISTS(SELECT 1 FROM identity_subject_links WHERE user_id=users.id AND issuer=$2) FOR SHARE',[identifier,user.iss])).rows[0];
        const state=recipient ? await readRoleState(client,identifier) : null;
        if(!state || !getIdentityPermissions({ roles:state.roles }).includes('reviews.decide'))fail(409,'reviewer_unavailable');
      }
      await this.context(client,explanation,'configured',user);
      const row=(await client.query(`INSERT INTO identity_role_review_policies(role,interval_seconds,window_seconds,reviewer_user_ids)
        VALUES($1,$2,$3,$4) RETURNING *`,[body.role,body.intervalSeconds,body.windowSeconds,body.reviewerUserIds])).rows[0];
      await this.revalidate(user,authorization); if(!fresh(user))fail(428,'fresh_mfa_required');
      await checkpoint({ required:true,maxAgeSeconds:300 });
      return this.policyView(row,user);
    },{ actor:JSON.stringify(proof) }).catch(checkpointError);
  }
  async retire(id,etag,body,user,authorization) {
    id=uuid(id); const proof=this.actor(user,'reviews.policies.manage',true); fields(body,['reason','acknowledgeDeadlines']); const explanation=reason(body.reason);
    if(body.acknowledgeDeadlines!==true)fail(400,'deadline_acknowledgement_required'); if(!etag)fail(428,'version_required');
    return this.database.transaction(async client=>{
      const checkpoint=await beginAuthorityCheckpoint(client,user);
      const peek=(await client.query('SELECT role FROM identity_role_review_policies WHERE id=$1',[id])).rows[0]; if(!peek)fail(404,'review_policy_not_found');
      await this.lock(client,peek.role);
      const row=(await client.query('SELECT * FROM identity_role_review_policies WHERE id=$1 FOR UPDATE',[id])).rows[0];
      if(etag!==policyTag(row))fail(412,'review_policy_changed'); if(row.retired_at)fail(409,'review_policy_retired');
      if(!this.management(row.role,user))fail(403,'global_administrator_required');
      await this.currentActor(client,user,'reviews.policies.manage'); await this.revalidate(user,authorization);
      await this.context(client,explanation,'retired',user);
      const changed=(await client.query('UPDATE identity_role_review_policies SET retired_at=identity_role_review_now(),version=version+1 WHERE id=$1 RETURNING *',[id])).rows[0];
      await this.revalidate(user,authorization); if(!fresh(user))fail(428,'fresh_mfa_required'); await checkpoint({ required:true,maxAgeSeconds:300 }); return this.policyView(changed,user);
    },{ actor:JSON.stringify(proof) }).catch(checkpointError);
  }
  state(row) {
    if(row.state==='denied')return 'denied';
    if(!row.source_exists || !row.user_enabled || !row.source_current || row.source_revoked_at || row.source_expires_at && new Date(row.source_expires_at)<=new Date(row.source_now))return 'obsolete';
    if(row.deadline_at && new Date(row.deadline_at)<=new Date(row.observed_at))return 'expired';
    if(row.state==='exempt')return 'exempt';
    return new Date(row.due_at)>new Date(row.observed_at) ? 'scheduled' : 'pending';
  }
  view(row,user) {
    const proof=this.actor(user); const permissions=getIdentityPermissions(user); const assigned=row.reviewer_user_ids.includes(proof.userId);
    if(!permissions.includes('reviews.all.read') && !(permissions.includes('reviews.assigned.read') && assigned))fail(404,'review_not_found');
    const state=this.state(row); const self=proof.userId===row.user_id;
    const allowed=assigned && permissions.includes('reviews.decide') && !self && state==='pending';
    return { id:row.id,policyId:row.policy_id,role:row.role,targetKind:row.target_kind,targetId:row.target_id,userId:row.user_id,
      version:String(row.version),policyVersion:String(row.review_policy_version),cycle:String(row.cycle),dueAt:iso(row.due_at),deadlineAt:iso(row.deadline_at),baseExpiresAt:iso(row.source_expires_at),
      state,policyRetired:!!row.policy_retired_at,canDecide:allowed && fresh(user),requiresFreshMfa:allowed && !fresh(user),selfReview:self };
  }
  async get(id,user) {
    id=uuid(id); this.actor(user);
    const permissions=getIdentityPermissions(user);
    if(!permissions.includes('reviews.all.read') && !permissions.includes('reviews.assigned.read'))fail(404,'review_not_found');
    return this.database.transaction(async client=>{
      const row=(await client.query(REVIEW_SELECT+' WHERE lease.id=$1',[id])).rows[0]; if(!row)fail(404,'review_not_found'); return this.view(row,user);
    },{ readOnly:true });
  }
  async self(user) {
    const proof=this.actor(user,'reviews.assigned.read');
    return this.database.transaction(async client=>{
      const rows=(await client.query(`SELECT * FROM (${REVIEW_SELECT} WHERE policy.reviewer_user_ids @> ARRAY[$1::uuid]) current
        ORDER BY (current.state='pending' AND current.due_at<=current.observed_at AND current.deadline_at>current.observed_at
          AND current.source_exists AND current.user_enabled AND current.source_current AND current.source_revoked_at IS NULL
          AND (current.source_expires_at IS NULL OR current.source_expires_at>current.source_now)) IS TRUE DESC,current.deadline_at,current.id LIMIT 101`,[proof.userId])).rows;
      return { userId:proof.userId,reviews:rows.slice(0,100).map(row=>this.view(row,user)),truncated:rows.length>100 };
    },{ readOnly:true });
  }
  async decide(id,etag,body,user,authorization) {
    id=uuid(id); const proof=this.actor(user,'reviews.decide',true); fields(body,['decision','reason','acknowledgeScope']); const explanation=reason(body.reason);
    if(!['retain','revoke'].includes(body.decision) || body.acknowledgeScope!==true)fail(400,'invalid_review_decision'); if(!etag)fail(428,'version_required');
    return this.database.transaction(async client=>{
      const checkpoint=await beginAuthorityCheckpoint(client,user);
      const peek=(await client.query(REVIEW_SELECT+' WHERE lease.id=$1',[id])).rows[0]; if(!peek)fail(404,'review_not_found');
      this.view(peek,user); if(peek.user_id===proof.userId)fail(403,'independent_reviewer_required');
      await this.lock(client,peek.role);
      await client.query('SELECT id FROM users WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE',[[proof.userId,peek.user_id].sort()]);
      if(!Object.hasOwn(TARGETS,peek.target_kind))fail(503,'review_source_unavailable');
      await client.query(`SELECT id FROM ${TARGETS[peek.target_kind]} WHERE id=$1 FOR UPDATE`,[peek.target_id]);
      await client.query('SELECT id FROM identity_role_review_leases WHERE id=$1 FOR UPDATE',[id]);
      const row=(await client.query(REVIEW_SELECT+' WHERE lease.id=$1',[id])).rows[0];
      if(etag!==reviewTag(row))fail(412,'review_changed');
      if(!this.view(row,user).canDecide)fail(409,'review_not_pending');
      await this.currentActor(client,user,'reviews.decide'); await this.revalidate(user,authorization);
      await this.context(client,explanation,body.decision,user);
      if(body.decision==='revoke')await client.query(`UPDATE ${TARGETS[row.target_kind]} SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`,[row.target_id]);
      if(body.decision==='retain') {
        await client.query(`UPDATE identity_role_review_leases SET version=version+1,cycle=cycle+1,
          state=CASE WHEN $2 THEN 'exempt' ELSE 'pending' END,due_at=CASE WHEN $2 THEN NULL ELSE due_at+$3*interval '1 second' END,
          deadline_at=CASE WHEN $2 THEN NULL ELSE due_at+($3+$4)*interval '1 second' END WHERE id=$1`,[id,!!row.policy_retired_at,row.interval_seconds,row.window_seconds]);
      } else await client.query("UPDATE identity_role_review_leases SET version=version+1,state='denied' WHERE id=$1",[id]);
      await this.revalidate(user,authorization); if(!fresh(user))fail(428,'fresh_mfa_required');
      const result=this.view((await client.query(REVIEW_SELECT+' WHERE lease.id=$1',[id])).rows[0],user);
      await checkpoint({ required:true,maxAgeSeconds:300 }); return result;
    },{ actor:JSON.stringify(proof) }).catch(checkpointError);
  }
}
module.exports={ RoleReviews,policyTag,reviewTag,REVIEW_SELECT };
