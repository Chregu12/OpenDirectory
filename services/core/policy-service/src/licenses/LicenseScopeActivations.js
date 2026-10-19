'use strict';

const { LicenseDelegations, DUTIES, fields, uuid } = require('./LicenseDelegations');
const { getLicensePermissions } = require('../middleware/licenseAccess');
const { scopeContext } = require('./LicenseScopeContext');
const { LicenseError } = require('./LicenseError');
const fail = (status,code) => { throw new LicenseError(status,code); };
const eligibilityTag = row => `"od-license-scope-eligibility:${row.id}:${row.version}"`;
const activationTag = row => `"od-license-scope-activation:${row.id}:${row.version}"`;
const ELIGIBILITY = 'SELECT eligible.*,license_scope_eligibility_usable(eligible.id,eligible.version) AS policy_usable,license_now() AS observed_at FROM license_scope_eligibilities eligible JOIN license_catalog catalog ON catalog.id=eligible.license_id AND catalog.business_tenant_id IS NULL';
const REQUEST = `SELECT request.*,eligible.license_id,eligible.user_id,eligible.issuer,eligible.duty,eligible.created_by,eligible.reviewer_user_ids,
 eligible.eligibility_revision,eligible.delegation_revision,license_scope_request_current(request.id) AS eligibility_usable,
 grants.id AS grant_id,grants.expires_at AS grant_expires_at,license_now() AS observed_at FROM license_scope_activation_requests request
 JOIN license_scope_eligibilities eligible ON eligible.id=request.eligibility_id JOIN license_catalog catalog ON catalog.id=eligible.license_id AND catalog.business_tenant_id IS NULL
 LEFT JOIN license_scope_grants grants ON grants.activation_request_id=request.id`;
const matches = (row,snapshot) => snapshot?.enabled && snapshot.linked && row.eligibility_revision === snapshot.revision && row.delegation_revision === snapshot.delegationRevision;
function eligibilityView(row,snapshot) {
  return {id:row.id,licenseId:row.license_id,userId:row.user_id,duty:row.duty,version:String(row.version),maxDurationSeconds:row.max_duration_seconds,
    reviewerUserIds:row.reviewer_user_ids,createdAt:row.created_at.toISOString(),expiresAt:row.expires_at.toISOString(),revokedAt:row.revoked_at?.toISOString()||null,
    state:row.revoked_at?'revoked':row.expires_at<=row.observed_at?'expired':row.policy_usable===false||snapshot&&!matches(row,snapshot)?'stale':'active'};
}
function requestView(row,actor,reviewer=false,snapshot) {
  const owner=row.user_id===actor; const available=row.eligibility_usable&&(!snapshot||matches(row,snapshot)); const timely=row.approval_deadline>row.observed_at;
  return {id:row.id,eligibilityId:row.eligibility_id,licenseId:row.license_id,userId:row.user_id,duty:row.duty,version:String(row.version),status:row.status,
    requestedDurationSeconds:row.requested_duration_seconds,requestedAt:row.requested_at.toISOString(),approvalDeadline:row.approval_deadline.toISOString(),
    reviewedAt:row.reviewed_at?.toISOString()||null,activatedAt:row.activated_at?.toISOString()||null,grantId:row.grant_id||null,grantExpiresAt:row.grant_expires_at?.toISOString()||null,
    canReview:!!(reviewer&&available&&timely&&row.status==='pending'&&row.reviewer_user_ids.includes(actor)&&actor!==row.user_id&&actor!==row.created_by),
    canActivate:!!(owner&&available&&timely&&row.status==='approved'),canCancel:owner&&['pending','approved'].includes(row.status),canDeactivate:owner&&row.status==='activated'};
}
class LicenseScopeActivations {
  constructor(allocator, options={}) { this.allocator=allocator;this.database=allocator.database;this.delegations=options.delegations||new LicenseDelegations(allocator,options);this.source=this.delegations.source; }
  actor(kind,user,principal,write=false) {
    if(scopeContext.getStore())fail(403,'scope_activation_control_not_delegated');
    const actor=this.delegations.actor(user,principal,null,write);const permissions=getLicensePermissions(user);
    if(kind==='review' ? !permissions.includes('licenses.scopepim.review')||!user.roles?.includes('license-scope-activation-reviewer') : !permissions.includes('licenses.delegations.'+kind))fail(403,'scope_activation_forbidden');
    return actor;
  }
  async fresh(kind,user,principal,authorization) { await this.delegations.revalidate(authorization,user);this.actor(kind,user,principal,true); }
  async target(row,authorization) { const snapshot=await this.delegations.subject(row.user_id,authorization);if(!matches(row,snapshot))fail(409,'scope_eligibility_origin_changed');return snapshot; }
  async reviewAuthority(identifier,authorization,expected) {await this.allocator.assertLegacySubject(identifier);const row=await this.source.activationReviewer(identifier,authorization);if(!row.enabled||!row.linked||!row.reviewRevision
    ||expected&&(row.revision!==expected.reviewer_eligibility_revision||row.reviewRevision!==expected.reviewer_role_revision))fail(409,'scope_reviewer_unavailable');return row;}
  async reviewers(identifiers,authorization) {for(const identifier of identifiers)await this.reviewAuthority(identifier,authorization);}
  async eligible(client,id,version) { if(!(await client.query('SELECT 1 WHERE license_scope_eligibility_usable($1,$2)',[id,version])).rows.length)fail(409,'scope_eligibility_unavailable'); }
  async timely(client,id) { if(!(await client.query('SELECT 1 FROM license_scope_activation_requests WHERE id=$1 AND approval_deadline>license_now() AND license_scope_request_current(id)',[id])).rows.length)fail(409,'scope_activation_deadline_or_policy_changed'); }
  async change(kind,action,body,user,principal,authorization,resource,operation) {
    const actor=this.actor(kind,user,principal,true);
    await this.allocator.assertPoolAccess(resource.license_id,this.database,{legacyOnly:true});
    return this.allocator.transaction(async client=>{
      await this.allocator.assertPoolAccess(resource.license_id,client,{legacyOnly:true});
      await this.allocator.lockSubjects(client,actor,[resource.user_id]);await this.allocator.lockLicense(client,resource.license_id);
      await this.fresh(kind,user,principal,authorization);await this.delegations.context(client,body,user,principal);
      await client.query("SELECT set_config('opendirectory.scope_pim_action',$1,true)",[action]);
      const result=await operation(client);await this.fresh(kind,user,principal,authorization);if(result.check)await result.check();return result.value;
    });
  }
  async peek(id,request=false) {
    uuid(id);const row=(await this.database.query(request?REQUEST+' WHERE request.id=$1':ELIGIBILITY+' WHERE eligible.id=$1',[id])).rows[0];
    if(!row)fail(404,'scope_activation_not_found');return row;
  }
  async locked(client,id,expected,request=false) {
    const row=(await client.query((request?REQUEST+' WHERE request.id=$1 FOR UPDATE OF request,eligible':ELIGIBILITY+' WHERE eligible.id=$1 FOR UPDATE'),[id])).rows[0];
    if(!row)fail(404,'scope_activation_not_found');if(!expected)fail(428,'scope_activation_version_required');
    if(expected!==(request?activationTag(row):eligibilityTag(row)))fail(412,'scope_activation_changed');return row;
  }
  async create(body,user,principal,authorization) {
    const actor=this.actor('manage',user,principal,true);fields(body,['licenseId','userId','duty','durationSeconds','maxDurationSeconds','reviewerUserIds','reason','confirm']);uuid(body.licenseId);uuid(body.userId);
    if(actor===body.userId||!Object.hasOwn(DUTIES,body.duty)||!Number.isInteger(body.durationSeconds)||body.durationSeconds<300||body.durationSeconds>2592000
      ||!Number.isInteger(body.maxDurationSeconds)||body.maxDurationSeconds<60||body.maxDurationSeconds>Math.min(28800,body.durationSeconds)
      ||!Array.isArray(body.reviewerUserIds)||body.reviewerUserIds.length<1||body.reviewerUserIds.length>10||new Set(body.reviewerUserIds).size!==body.reviewerUserIds.length)fail(400,'independent_scope_eligibility_required');
    body.reviewerUserIds.forEach(uuid);if(body.reviewerUserIds.includes(actor)||body.reviewerUserIds.includes(body.userId))fail(400,'independent_scope_reviewers_required');
    await this.allocator.assertPoolAccess(body.licenseId,this.database,{legacyOnly:true});
    const target=await this.delegations.subject(body.userId,authorization);await this.reviewers(body.reviewerUserIds,authorization);
    return this.change('manage','eligibility.create',body,user,principal,authorization,{license_id:body.licenseId,user_id:body.userId},async client=>{
      const row=(await client.query(`INSERT INTO license_scope_eligibilities(license_id,user_id,issuer,duty,eligibility_revision,delegation_revision,created_by,reviewer_user_ids,max_duration_seconds,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,date_trunc('milliseconds',license_now())+$10*interval '1 second') RETURNING *,license_now() AS observed_at`,
      [body.licenseId,body.userId,principal.issuer,body.duty,target.revision,target.delegationRevision,actor,[...body.reviewerUserIds].sort(),body.maxDurationSeconds,body.durationSeconds])).rows[0];
      await this.target(row,authorization);await this.reviewers(row.reviewer_user_ids,authorization);
      return {value:eligibilityView(row),check:()=>this.eligible(client,row.id,row.version)};
    });
  }
  async revoke(id,expected,body,user,principal,authorization) {
    this.actor('manage',user,principal,true);fields(body,['reason','confirm']);const resource=await this.peek(id);
    return this.change('manage','eligibility.revoke',body,user,principal,authorization,resource,async client=>{
      const row=await this.locked(client,id,expected);if(row.revoked_at)fail(409,'scope_eligibility_revoked');
      return {value:eligibilityView((await client.query('UPDATE license_scope_eligibilities SET revoked_at=license_now(),version=version+1 WHERE id=$1 RETURNING *,license_now() AS observed_at',[id])).rows[0])};
    });
  }
  async request(id,expected,body,user,principal,authorization) {
    const actor=this.actor('self',user,principal,true);fields(body,['durationSeconds','reason','confirm']);if(!Number.isInteger(body.durationSeconds)||body.durationSeconds<60||body.durationSeconds>28800)fail(400,'bounded_scope_activation_required');
    const resource=await this.peek(id);if(resource.user_id!==actor||resource.issuer!==principal.issuer)fail(404,'scope_activation_not_found');
    return this.change('self','request',body,user,principal,authorization,resource,async client=>{
      const row=await this.locked(client,id,expected);await this.eligible(client,id,row.version);await this.target(row,authorization);
      if(body.durationSeconds>row.max_duration_seconds)fail(400,'scope_activation_duration_exceeded');
      if((await client.query('SELECT 1 FROM license_scope_grants WHERE license_id=$1 AND user_id=$2 AND duty=$3 AND revoked_at IS NULL',[row.license_id,actor,row.duty])).rows.length)fail(409,'retire_existing_scope_grant');
      const request=(await client.query(`INSERT INTO license_scope_activation_requests(eligibility_id,eligibility_version,requested_duration_seconds,approval_deadline)
        VALUES($1,$2,$3,LEAST($4,date_trunc('milliseconds',license_now())+interval '15 minutes')) RETURNING id`,[id,row.version,body.durationSeconds,row.expires_at])).rows[0];
      const snapshot=await this.target(row,authorization);const created=(await client.query(REQUEST+' WHERE request.id=$1',[request.id])).rows[0];
      return {value:requestView(created,actor,false,snapshot),check:async()=>{await this.eligible(client,id,row.version);await this.timely(client,request.id);}};
    });
  }
  async transition(id,expected,body,action,user,principal,authorization) {
    const review=action==='decide';const kind=review?'review':'self';const actor=this.actor(kind,user,principal,true);
    fields(body,review?['decision','reason','confirm']:['reason','confirm']);if(review&&!['approved','denied'].includes(body.decision))fail(400,'scope_activation_decision_required');
    const resource=await this.peek(id,true);
    if(resource.issuer!==principal.issuer||(review ? !resource.reviewer_user_ids.includes(actor)||actor===resource.user_id||actor===resource.created_by : resource.user_id!==actor))fail(403,'independent_assigned_scope_actor_required');
    return this.change(kind,review?'review.'+body.decision:action,body,user,principal,authorization,resource,async client=>{
      const row=await this.locked(client,id,expected,true);let snapshot;let positive=false;
      if(review||action==='activate') {
        if(row.status!==(review?'pending':'approved'))fail(409,'scope_activation_state_changed');
        await this.eligible(client,row.eligibility_id,row.eligibility_version);await this.timely(client,id);snapshot=await this.target(row,authorization);positive=true;
        if(review){const authority=await this.reviewAuthority(actor,authorization);await client.query('UPDATE license_scope_activation_requests SET status=$2,reviewed_by=$3,reviewed_at=license_now(),reviewer_eligibility_revision=$4,reviewer_role_revision=$5,version=version+1 WHERE id=$1',[id,body.decision,actor,authority.revision,authority.reviewRevision]);}
        else {
          await this.reviewAuthority(row.reviewed_by,authorization,row);
          await client.query(`INSERT INTO license_scope_grants(license_id,user_id,issuer,duty,eligibility_revision,delegation_revision,activation_request_id,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,LEAST((SELECT expires_at FROM license_scope_eligibilities WHERE id=$8),date_trunc('milliseconds',license_now())+$9*interval '1 second'))`,
          [row.license_id,actor,row.issuer,row.duty,row.eligibility_revision,row.delegation_revision,id,row.eligibility_id,row.requested_duration_seconds]);
          await client.query("UPDATE license_scope_activation_requests SET status='activated',activated_at=license_now(),version=version+1 WHERE id=$1",[id]);
        }
        snapshot=await this.target(row,authorization);
        if(action==='activate')await this.reviewAuthority(row.reviewed_by,authorization,row);
      } else if(action==='cancel') {
        if(!['pending','approved'].includes(row.status))fail(409,'scope_activation_state_changed');
        await client.query("UPDATE license_scope_activation_requests SET status='cancelled',version=version+1 WHERE id=$1",[id]);
      } else if(action==='deactivate') {
        if(row.status!=='activated')fail(409,'scope_activation_state_changed');
        await client.query('UPDATE license_scope_grants SET revoked_at=license_now(),version=version+1 WHERE activation_request_id=$1 AND revoked_at IS NULL',[id]);
        await client.query("UPDATE license_scope_activation_requests SET status='deactivated',version=version+1 WHERE id=$1",[id]);
      } else fail(400,'scope_activation_action_required');
      const changed=(await client.query(REQUEST+' WHERE request.id=$1',[id])).rows[0];
      return {value:requestView(changed,actor,review,snapshot),check:positive?async()=>{await this.eligible(client,row.eligibility_id,row.eligibility_version);await this.timely(client,id);
        if(action==='activate'&&!(await client.query('SELECT 1 WHERE license_scope_grant_usable($1)',[changed.grant_id])).rows.length)fail(409,'scope_activation_unavailable');}:null};
    });
  }
  async self(user,principal,authorization) {
    const actor=this.actor('self',user,principal);await this.allocator.assertLegacySubject(actor);const snapshot=await this.source.delegate(actor,authorization);
    const eligible=(await this.database.query(ELIGIBILITY+' WHERE user_id=$1 AND issuer=$2 AND revoked_at IS NULL ORDER BY expires_at,eligible.id LIMIT 101',[actor,principal.issuer])).rows;
    const requests=(await this.database.query(REQUEST+' WHERE eligible.user_id=$1 AND eligible.issuer=$2 ORDER BY requested_at DESC,request.id DESC LIMIT 101',[actor,principal.issuer])).rows;
    return {userId:actor,eligibilities:eligible.slice(0,100).map(row=>eligibilityView(row,snapshot)),requests:requests.slice(0,100).map(row=>requestView(row,actor,false,snapshot)),truncated:eligible.length>100||requests.length>100};
  }
  async assigned(user,principal) {
    const actor=this.actor('review',user,principal);const rows=(await this.database.query(REQUEST+" WHERE $1=ANY(eligible.reviewer_user_ids) AND eligible.user_id<>$1 AND eligible.created_by<>$1 AND request.status='pending' AND approval_deadline>license_now() AND license_scope_eligibility_usable(eligible.id,request.eligibility_version) ORDER BY approval_deadline,request.id LIMIT 101",[actor])).rows;
    return {userId:actor,requests:rows.slice(0,100).map(row=>requestView(row,actor,true)),truncated:rows.length>100};
  }
  async list(licenseId,after,user,principal) {
    this.actor('read',user,principal);uuid(licenseId);if(after!==undefined)uuid(after);
    await this.allocator.assertPoolAccess(licenseId,this.database,{legacyOnly:true});
    const rows=(await this.database.query(ELIGIBILITY+' WHERE license_id=$1 AND ($2::uuid IS NULL OR eligible.id>$2) ORDER BY eligible.id LIMIT 101',[licenseId,after||null])).rows;
    return {licenseId,eligibilities:rows.slice(0,100).map(row=>eligibilityView(row)),hasMore:rows.length>100,nextAfter:rows.length>100?rows[99].id:null};
  }
}
module.exports={LicenseScopeActivations,eligibilityTag,activationTag};
