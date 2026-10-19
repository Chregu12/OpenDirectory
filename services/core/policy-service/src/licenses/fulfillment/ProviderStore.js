'use strict';

const crypto=require('crypto');
const { provenMfa }=require('../../../../../../packages/mfa-authorization-contract');
const { validContext }=require('../../../../../../packages/identity-authorization-contract');
const { getLicensePermissions }=require('../../middleware/licenseAccess');
const { requirePrincipal }=require('../LicensePrincipal');
const { normalizeUserSnapshot }=require('../GroupSnapshotClient');
const { createAccessStateClient }=require('../../../../../../packages/oidc-access-state');
const { fail,uuid,fields,reason,plans,conditional }=require('./contracts');
const TABLES=Object.freeze({ connectors:'license_provider_connectors',products:'license_provider_products',subjects:'license_provider_subjects' });
const TARGET=`SELECT target.*,product.license_id,catalog.business_tenant_id,product.connector_id,product.sku_id,product.disabled_plans,subject.user_id,subject.object_id,connector.tenant_id,
  EXISTS(SELECT 1 FROM license_assignments assignment WHERE assignment.license_id=product.license_id AND assignment.assignee_type='user' AND assignment.assignee_id=subject.user_id::text AND (assignment.expires_at IS NULL OR assignment.expires_at>license_now())) AS local_desired,
  connector.enabled AND product.enabled AND subject.enabled AS enabled FROM license_fulfillment_targets target
  JOIN license_provider_products product ON product.id=target.product_id JOIN license_provider_subjects subject ON subject.id=target.subject_id
  JOIN license_catalog catalog ON catalog.id=product.license_id AND catalog.business_tenant_id IS NULL
  JOIN license_provider_connectors connector ON connector.id=product.connector_id
  WHERE NOT EXISTS(SELECT 1 FROM license_subjects owned_subject WHERE owned_subject.user_id=subject.user_id::text AND owned_subject.business_tenant_id IS NOT NULL)`;
function binding(kind,row) {
  if (!row) fail(404,'provider_binding_not_found');
  const base={ id:row.id,version:String(row.version),enabled:row.enabled };
  if (kind==='connectors') return { ...base,tenantId:row.tenant_id };
  if (kind==='products') return { ...base,licenseId:row.license_id,connectorId:row.connector_id,skuId:row.sku_id,disabledPlans:row.disabled_plans };
  return { ...base,connectorId:row.connector_id,userId:row.user_id,objectId:row.object_id };
}
class ProviderStore {
  constructor(allocator,{ revalidate }={}) {
    this.allocator=allocator; this.database=allocator.database; const accessState=createAccessStateClient();
    this.revalidate=revalidate||((user,authorization)=>accessState(authorization,user));
  }
  actor(user,principal,permission,write=false) {
    requirePrincipal(principal);
    if (user?.actor_type!=='user' || user.iss!==principal.issuer || user.sub!==principal.subject || !validContext(user.identity_authorization) || user.identity_authorization.userId!==principal.userId
      || !getLicensePermissions(user).includes(permission)) fail(403,'fulfillment_authority_required');
    if (write && (!provenMfa(user) || user.auth_time>Math.floor(Date.now()/1000)+5 || Math.floor(Date.now()/1000)-user.auth_time>300)) fail(428,'fresh_mfa_required');
    return { issuer:user.iss,subject:user.sub,userId:principal.userId };
  }
  async evidence(client,target,action,actor,details) {
    await client.query('INSERT INTO license_fulfillment_events(target_id,version,action,actor,details) VALUES($1,$2,$3,$4,$5)',[target?.id||null,target?.version||null,action,JSON.stringify(actor),JSON.stringify(details)]);
  }
  async context(client,actor,explanation) {
    await client.query("SELECT set_config('opendirectory.provider_actor',$1,true),set_config('opendirectory.provider_reason',$2,true)",[JSON.stringify(actor),explanation]);
  }
  async legacySubject(userId,client=this.database) {
    if ((await client.query('SELECT 1 FROM license_subjects WHERE user_id=$1 AND business_tenant_id IS NOT NULL',[userId])).rows.length) fail(404,'legacy_provider_subject_not_found');
  }
  async requireTarget(row,client=this.database,lock=false) {
    const current=await this.row(row.id,client,lock);
    if (!current || current.license_id!==row.license_id || current.user_id!==row.user_id) fail(404,'fulfillment_target_not_found');
    return current;
  }
  bindingQuery(kind) {
    const join=kind==='products'?' JOIN license_catalog catalog ON catalog.id=binding.license_id AND catalog.business_tenant_id IS NULL':kind==='subjects'?' LEFT JOIN license_subjects local_subject ON local_subject.user_id=binding.user_id::text':'';
    return `SELECT binding.* FROM ${TABLES[kind]} binding${join} WHERE binding.id=$1${kind==='subjects'?' AND local_subject.business_tenant_id IS NULL':''}`;
  }
  async create(kind,body,user,principal,authorization) {
    const actor=this.actor(user,principal,'licenses.fulfillment.configure',true);
    const allowed=kind==='connectors'?['tenantId','reason']:kind==='products'?['connectorId','licenseId','skuId','disabledPlans','exclusiveDirectManagement','reason']:['connectorId','userId','objectId','exclusiveDirectManagement','reason'];
    if (!Object.hasOwn(TABLES,kind)) fail(400,'invalid_provider_binding'); fields(body,allowed); const explanation=reason(body.reason);
    if (kind==='connectors') uuid(body.tenantId);
    else {
      uuid(body.connectorId); if (body.exclusiveDirectManagement!==true) fail(400,'exclusive_direct_management_review_required');
      if (kind==='products') { uuid(body.licenseId); uuid(body.skuId); plans(body.disabledPlans); await this.allocator.assertPoolAccess(body.licenseId,this.database,{legacyOnly:true}); }
      else {
        uuid(body.userId); uuid(body.objectId); await this.legacySubject(body.userId); const snapshot=await this.allocator.users.read(body.userId,authorization);
        if (!snapshot.enabled || snapshot.deleted) fail(403,'active_canonical_target_required');
      }
    }
    return this.allocator.transaction(async client=>{
      if(kind==='products')await this.allocator.assertPoolAccess(body.licenseId,client,{legacyOnly:true});
      if(kind==='subjects')await this.legacySubject(body.userId,client);
      await this.revalidate(user,authorization); this.actor(user,principal,'licenses.fulfillment.configure',true); await this.context(client,actor,explanation);
      let result;
      if (kind==='connectors') result=await client.query('INSERT INTO license_provider_connectors(tenant_id) VALUES($1) RETURNING *',[body.tenantId]);
      else if (kind==='products') {
        const pool=(await client.query('SELECT license_type FROM license_catalog WHERE id=$1 AND business_tenant_id IS NULL FOR SHARE',[body.licenseId])).rows[0];
        if (!pool || !['per_user','subscription'].includes(pool.license_type)) fail(409,'user_license_pool_required');
        result=await client.query('INSERT INTO license_provider_products(connector_id,license_id,sku_id,disabled_plans) VALUES($1,$2,$3,$4) RETURNING *',[body.connectorId,body.licenseId,body.skuId,JSON.stringify(body.disabledPlans)]);
      }
      else result=await client.query('INSERT INTO license_provider_subjects(connector_id,user_id,object_id) VALUES($1,$2,$3) RETURNING *',[body.connectorId,body.userId,body.objectId]);
      await this.revalidate(user,authorization); this.actor(user,principal,'licenses.fulfillment.configure',true);
      return binding(kind,result.rows[0]);
    });
  }
  async get(kind,id) { if (!Object.hasOwn(TABLES,kind)) fail(400,'invalid_provider_binding'); uuid(id); return binding(kind,(await this.database.query(this.bindingQuery(kind),[id])).rows[0]); }
  async enable(kind,id,etag,body,user,principal,authorization) {
    if (!Object.hasOwn(TABLES,kind)) fail(400,'invalid_provider_binding'); uuid(id); fields(body,['enabled','reason']); if (typeof body.enabled!=='boolean') fail(400,'boolean_enablement_required');
    const actor=this.actor(user,principal,'licenses.fulfillment.configure',true); const explanation=reason(body.reason);
    return this.allocator.transaction(async client=>{
      const row=(await client.query(this.bindingQuery(kind)+' FOR UPDATE OF binding',[id])).rows[0]; if (!row) fail(404,'provider_binding_not_found');
      conditional(etag,kind,row); await this.revalidate(user,authorization); this.actor(user,principal,'licenses.fulfillment.configure',true); await this.context(client,actor,explanation);
      const result=await client.query(`UPDATE ${TABLES[kind]} SET enabled=$2,version=version+1 WHERE id=$1 RETURNING *`,[id,body.enabled]);
      await this.revalidate(user,authorization); this.actor(user,principal,'licenses.fulfillment.configure',true); return binding(kind,result.rows[0]);
    });
  }
  async row(id,client=this.database,lock=false) { return (await client.query(TARGET+' AND target.id=$1'+(lock?' FOR UPDATE OF target':''),[uuid(id)])).rows[0]; }
  target(row,user) {
    if (!row) fail(404,'fulfillment_target_not_found'); const permissions=getLicensePermissions(user);
    const recent=row.checked_at && Date.now()-new Date(row.checked_at).getTime()<=300000;
    const eligible=row.eligibility_revision!==null && row.authority_revision!==null && row.authority_enabled===true && row.authority_deleted===false && String(row.authority_revision)===String(row.eligibility_revision);
    const cleanup=!row.desired && !!(row.uncertain_add_id || row.attempt_desired===true && row.attempt_id);
    const canAdopt=permissions.includes('licenses.fulfillment.adopt') && !!recent && (row.desired && row.local_desired && eligible || cleanup) && !row.owned && row.observation?.direct===true && (cleanup || row.observation?.active===true) && row.observation?.plansMatch===true && row.observation?.inherited===false;
    return { id:row.id,licenseId:row.license_id,userId:row.user_id,objectId:row.object_id,connectorId:row.connector_id,version:String(row.version),desired:row.desired,localDesired:row.local_desired,
      eligibilityBlocked:row.local_desired && (!row.desired || row.eligibility_revision===null),
      status:row.status,owned:row.owned,paused:!row.enabled,observation:row.observation,checkedAt:row.checked_at?new Date(row.checked_at).toISOString():null,error:row.error,
      canRetry:permissions.includes('licenses.fulfillment.retry') && ['failed','unknown','conflict'].includes(row.status),
      canAdopt:!!canAdopt,adoptionPurpose:canAdopt?row.desired?'fulfill':'cleanup':null };
  }
  async lookup(licenseId,userId,user) {
    uuid(licenseId); uuid(userId); await this.allocator.assertPoolAccess(licenseId,this.database,{legacyOnly:true}); const row=(await this.database.query(TARGET+' AND product.license_id=$1 AND subject.user_id=$2',[licenseId,userId])).rows[0]; return this.target(row,user);
  }
  async resolve(id,action,etag,body,user,principal,authorization) {
    if (!['retry','adopt'].includes(action)) fail(400,'invalid_resolution');
    fields(body,['reason',action==='retry'?'acknowledgeUncertainOutcome':'acknowledgeExclusiveManagement']); const explanation=reason(body.reason);
    const permission='licenses.fulfillment.'+action; const actor=this.actor(user,principal,permission,true); uuid(id);
    if (action==='adopt') {
      const target=await this.row(id); if (!target) fail(404,'fulfillment_target_not_found');
      const snapshot=await this.allocator.users.read(target.user_id,authorization);
      if ((!snapshot.enabled || snapshot.deleted) && !(!target.desired && (target.uncertain_add_id || target.attempt_desired===true && target.attempt_id))) fail(403,'active_canonical_target_required');
      await this.checkpoint(target,snapshot,actor);
    }
    return this.allocator.transaction(async client=>{
      let row=await this.row(id,client,true); if (!row) fail(404,'fulfillment_target_not_found');
      await client.query('SELECT license_fulfillment_refresh($1,$2,$3,false)',[row.license_id,row.user_id,JSON.stringify({ type:'resolution-expiry-check' })]); row=await this.row(id,client); conditional(etag,'targets',row);
      const view=this.target(row,user); if (action==='retry' && (!view.canRetry || typeof body.acknowledgeUncertainOutcome!=='boolean' || row.status==='unknown' && body.acknowledgeUncertainOutcome!==true)) fail(409,'uncertain_outcome_review_required');
      if (action==='adopt' && (!view.canAdopt || body.acknowledgeExclusiveManagement!==true)) fail(409,'fresh_exclusive_direct_assignment_review_required');
      await this.revalidate(user,authorization); this.actor(user,principal,permission,true);
      await client.query('SELECT license_fulfillment_refresh($1,$2,$3)',[row.license_id,row.user_id,JSON.stringify({ type:'reviewed-'+action,actor,reason:explanation })]);
      const changed=(await client.query("UPDATE license_fulfillment_targets SET owned=CASE WHEN $2 THEN true ELSE owned END,status='pending',error=NULL,attempt_count=0,next_attempt_at=clock_timestamp() WHERE id=$1 RETURNING *",[id,action==='adopt'])).rows[0];
      await this.evidence(client,changed,'reviewed-'+action,actor,{ reason:explanation,uncertainAcknowledged:body.acknowledgeUncertainOutcome===true,purpose:action==='adopt'?row.desired?'fulfill':'cleanup':null });
      await this.revalidate(user,authorization); this.actor(user,principal,permission,true); return this.target(await this.row(id,client),user);
    });
  }
  async candidates(connectorId) {
    return (await this.database.query(`SELECT target.id FROM license_fulfillment_targets target JOIN license_provider_products product ON product.id=target.product_id
      JOIN license_provider_subjects subject ON subject.id=target.subject_id JOIN license_provider_connectors connector ON connector.id=product.connector_id
      JOIN license_catalog catalog ON catalog.id=product.license_id AND catalog.business_tenant_id IS NULL
      LEFT JOIN license_provider_limits limits ON limits.connector_id=connector.id WHERE connector.id=$1 AND connector.enabled AND product.enabled AND subject.enabled
      AND NOT EXISTS(SELECT 1 FROM license_subjects owned_subject WHERE owned_subject.user_id=subject.user_id::text AND owned_subject.business_tenant_id IS NOT NULL)
      AND target.next_attempt_at<=clock_timestamp() AND (limits.not_before IS NULL OR limits.not_before<=clock_timestamp()) ORDER BY target.next_attempt_at,target.id LIMIT 50`,[uuid(connectorId)])).rows;
  }
  async refresh(row) { await this.requireTarget(row); await this.database.query('SELECT license_fulfillment_refresh($1,$2,$3,false)',[row.license_id,row.user_id,JSON.stringify({ type:'worker-expiry-check' })]); }
  async checkpoint(row,snapshot,actor) {
    normalizeUserSnapshot(snapshot,row.user_id);
    await this.allocator.transaction(async client=>{
      await this.requireTarget(row,client,true);
      await client.query('UPDATE license_fulfillment_targets SET authority_revision=$2,authority_enabled=$3,authority_deleted=$4 WHERE id=$1',[row.id,snapshot.revision,snapshot.enabled,snapshot.deleted]);
      await this.evidence(client,row,'canonical-checkpoint',actor,snapshot);
      await client.query('SELECT license_fulfillment_refresh($1,$2,$3,false)',[row.license_id,row.user_id,JSON.stringify({ type:'canonical-eligibility',revision:snapshot.revision,enabled:snapshot.enabled,deleted:snapshot.deleted })]);
    });
  }
  async defer(connectorId,seconds) {
    await this.database.query(`INSERT INTO license_provider_limits(connector_id,not_before) VALUES($1,clock_timestamp()+$2*interval '1 second')
      ON CONFLICT(connector_id) DO UPDATE SET not_before=GREATEST(license_provider_limits.not_before,EXCLUDED.not_before)`,[connectorId,seconds]);
  }
  async available(connectorId) { return !(await this.database.query('SELECT 1 FROM license_provider_limits WHERE connector_id=$1 AND not_before>clock_timestamp()',[connectorId])).rows.length; }
  async writeIntent(row,actor) {
    try { return await this.allocator.transaction(async client=>{
      const current=await this.requireTarget(row,client,true);
      await client.query('SELECT license_fulfillment_refresh($1,$2,$3,false)',[row.license_id,row.user_id,JSON.stringify({ type:'dispatch-expiry-check' })]);
      const dispatched=await this.row(row.id,client);
      const blocked=(await client.query('SELECT 1 FROM license_provider_limits WHERE connector_id=$1 AND not_before>clock_timestamp()',[row.connector_id])).rows.length;
      if (!dispatched.enabled || String(dispatched.version)!==String(row.version) || current.status==='unknown' || blocked) return null;
      const attemptId=crypto.randomUUID();
      await this.evidence(client,current,'write-intent',actor,{ attemptId,desired:row.desired,objectId:row.object_id,skuId:row.sku_id });
      await client.query("SELECT set_config('opendirectory.capacity_protocol','1',true)");
      await client.query("UPDATE license_fulfillment_targets SET status='in_flight',attempt_id=$2,attempt_desired=desired,attempt_version=version,attempt_count=attempt_count+1 WHERE id=$1",[row.id,attemptId]); return attemptId;
    }); } catch(error) { if(error.code==='23514' && /^capacity_[a-z_]+$/.test(error.message)) fail(409,error.message);throw error; }
  }
  async dispatch(row,attemptId) {
    await this.requireTarget(row);
    if(!row.desired)return true;
    return this.allocator.transaction(async client=>(await client.query('SELECT license_capacity_dispatch($1,$2) AS admitted',[attemptId,row.id])).rows[0]?.admitted===true);
  }
  async settle(row,actor,{ status,error=null,observation=null,owned=row.owned,delay=60,attemptId=null,knownWrite=false }) {
    return this.allocator.transaction(async client=>{
      const current=await this.row(row.id,client,true); if (!current) return;
      if (attemptId && current.attempt_id!==attemptId) fail(409,'fulfillment_attempt_changed');
      const unchanged=String(current.version)===String(row.version);
      const nextStatus=unchanged?status:knownWrite?status==='unknown'?'unknown':current.status==='unknown'?'unknown':'pending':current.status;
      const uncertainAdd=current.uncertain_add_id || (status==='unknown' && (attemptId?row.desired:row.attempt_desired) ? attemptId||row.attempt_id : null);
      await this.evidence(client,current,knownWrite?'write-receipt':'observation',actor,{ attemptId,attemptVersion:String(row.version),status,error,observation,owned });
      await client.query(`UPDATE license_fulfillment_targets SET status=$2,error=$3,owned=$4,observation=COALESCE($5,observation),
        checked_at=CASE WHEN $5::jsonb IS NULL THEN checked_at ELSE clock_timestamp() END,next_attempt_at=clock_timestamp()+$6*interval '1 second',uncertain_add_id=$7 WHERE id=$1`,
      [row.id,nextStatus,unchanged||knownWrite?error:current.error,knownWrite||unchanged?owned:current.owned,observation?JSON.stringify(observation):null,unchanged?delay:0,uncertainAdd]);
    });
  }
}
module.exports = { ProviderStore,binding,TARGET };
