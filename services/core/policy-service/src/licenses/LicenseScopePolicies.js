'use strict';
const {LicenseDelegations,DUTIES,fields,uuid}=require('./LicenseDelegations');
const {getLicensePermissions}=require('../middleware/licenseAccess');
const {scopeContext}=require('./LicenseScopeContext');
const {LicenseError}=require('./LicenseError');
const fail=(status,code)=>{throw new LicenseError(status,code);};
const policyTag=row=>`"od-license-scope-policy:${row.licenseId}:${row.duty}:${row.version}"`;
function view(row,licenseId,duty){return row?{licenseId:row.license_id,duty:row.duty,version:String(row.version),activationRequired:row.activation_required,maxDurationSeconds:row.max_duration_seconds,preparedEligibilityIds:row.prepared_eligibility_ids,updatedAt:row.updated_at.toISOString(),configured:true}
 :{licenseId,duty,version:'1',activationRequired:false,maxDurationSeconds:28800,preparedEligibilityIds:[],updatedAt:null,configured:false};}
class LicenseScopePolicies{
 constructor(allocator,options={}){this.allocator=allocator;this.database=allocator.database;this.delegations=options.delegations||new LicenseDelegations(allocator,options);}
 actor(user,principal,write=false){if(scopeContext.getStore())fail(403,'pool_policy_not_delegated');const actor=this.delegations.actor(user,principal,null,write);
  if(!getLicensePermissions(user).includes('licenses.scopepolicies.'+(write?'manage':'read'))||write&&!user.roles?.includes('license-scope-policy-administrator'))fail(403,'pool_policy_forbidden');return actor;}
 target(licenseId,duty){uuid(licenseId);if(!Object.hasOwn(DUTIES,duty))fail(400,'pool_policy_duty_required');}
 async read(licenseId,duty,client=this.database){await this.allocator.assertPoolAccess(licenseId,client,{legacyOnly:true});const pool=(await client.query('SELECT license_type FROM license_catalog WHERE id=$1 AND business_tenant_id IS NULL',[licenseId])).rows[0];if(!pool)fail(404,'license_not_found');if(!['per_user','subscription'].includes(pool.license_type))fail(400,'human_license_pool_required');
  return view((await client.query('SELECT * FROM license_scope_activation_policies WHERE license_id=$1 AND duty=$2',[licenseId,duty])).rows[0],licenseId,duty);}
 async get(licenseId,duty,user,principal){this.actor(user,principal);this.target(licenseId,duty);return this.read(licenseId,duty);}
 async prepare(client,licenseId,duty,identifiers,actor,issuer,authorization,maximum){
  await this.allocator.assertPoolAccess(licenseId,client,{legacyOnly:true});
  const rows=(await client.query('SELECT eligible.* FROM license_scope_eligibilities eligible JOIN license_catalog catalog ON catalog.id=eligible.license_id AND catalog.business_tenant_id IS NULL WHERE eligible.id=ANY($1::uuid[]) AND eligible.license_id=$2 ORDER BY eligible.id',[identifiers,licenseId])).rows;if(rows.length!==identifiers.length)fail(409,'prepared_pool_path_unavailable');
  for(const row of rows){if(row.license_id!==licenseId||row.duty!==duty||row.issuer!==issuer||row.user_id===actor||row.created_by===actor||row.reviewer_user_ids.includes(actor)||row.revoked_at||row.max_duration_seconds>maximum)fail(409,'independent_prepared_pool_path_required');
   if(!(await client.query("SELECT 1 FROM license_scope_eligibilities eligible LEFT JOIN license_subjects subject ON subject.user_id=eligible.user_id::text WHERE eligible.id=$1 AND LEAST(eligible.expires_at,license_scope_review_deadline('eligibility',eligible.id))>license_now()+interval '5 minutes' AND license_scope_review_allowed('eligibility',eligible.id) AND NOT COALESCE(subject.disabled,false) AND subject.directory_enabled IS DISTINCT FROM false",[row.id])).rows.length)fail(409,'prepared_pool_path_unavailable');
   const snapshot=await this.delegations.subject(row.user_id,authorization);if(snapshot.revision!==row.eligibility_revision||snapshot.delegationRevision!==row.delegation_revision)fail(409,'prepared_pool_path_origin_changed');
   for(const reviewer of row.reviewer_user_ids){await this.allocator.assertLegacySubject(reviewer,client);const current=await this.delegations.source.activationReviewer(reviewer,authorization);if(!current.enabled||!current.linked||!current.reviewRevision)fail(409,'prepared_pool_reviewer_unavailable');}
  }return rows;
 }
 async set(licenseId,duty,expected,body,user,principal,authorization){const actor=this.actor(user,principal,true);this.target(licenseId,duty);
  fields(body,['activationRequired','maxDurationSeconds','preparedEligibilityIds','acknowledgeInvalidation','reason','confirm']);
  if(body.acknowledgeInvalidation!==true||typeof body.activationRequired!=='boolean'||!Number.isInteger(body.maxDurationSeconds)||body.maxDurationSeconds<60||body.maxDurationSeconds>28800
   ||!Array.isArray(body.preparedEligibilityIds)||body.preparedEligibilityIds.length>10||new Set(body.preparedEligibilityIds).size!==body.preparedEligibilityIds.length||body.activationRequired&&!body.preparedEligibilityIds.length)fail(400,'confirmed_bounded_prepared_policy_required');
  body.preparedEligibilityIds.forEach(uuid);if(!expected)fail(428,'pool_policy_version_required');
  const paths=await this.prepare(this.database,licenseId,duty,body.preparedEligibilityIds,actor,principal.issuer,authorization,body.maxDurationSeconds);
  return this.allocator.transaction(async client=>{
   await this.allocator.assertPoolAccess(licenseId,client,{legacyOnly:true});
   await this.allocator.lockSubjects(client,actor,paths.map(row=>row.user_id));await this.allocator.lockLicense(client,licenseId);const current=await this.read(licenseId,duty,client);if(expected!==policyTag(current))fail(412,'pool_policy_changed');
   await this.delegations.revalidate(authorization,user);this.actor(user,principal,true);await this.prepare(client,licenseId,duty,body.preparedEligibilityIds,actor,principal.issuer,authorization,body.maxDurationSeconds);
   await this.delegations.context(client,body,user,principal);await client.query("SELECT set_config('opendirectory.scope_policy_action','set',true)");
   const row=(await client.query(`INSERT INTO license_scope_activation_policies(license_id,duty,version,activation_required,max_duration_seconds,prepared_eligibility_ids,updated_by)
    VALUES($1,$2,2,$3,$4,$5,$6) ON CONFLICT(license_id,duty) DO UPDATE SET version=license_scope_activation_policies.version+1,activation_required=EXCLUDED.activation_required,max_duration_seconds=EXCLUDED.max_duration_seconds,prepared_eligibility_ids=EXCLUDED.prepared_eligibility_ids,updated_by=EXCLUDED.updated_by RETURNING *`,
   [licenseId,duty,body.activationRequired,body.maxDurationSeconds,[...body.preparedEligibilityIds].sort(),actor])).rows[0];
   await this.prepare(client,licenseId,duty,body.preparedEligibilityIds,actor,principal.issuer,authorization,body.maxDurationSeconds);await this.delegations.revalidate(authorization,user);this.actor(user,principal,true);
   await this.prepare(client,licenseId,duty,body.preparedEligibilityIds,actor,principal.issuer,authorization,body.maxDurationSeconds);
   await this.delegations.revalidate(authorization,user);this.actor(user,principal,true);
   if((await client.query("SELECT count(*)::int AS count FROM license_scope_eligibilities WHERE id=ANY($1::uuid[]) AND revoked_at IS NULL AND LEAST(expires_at,license_scope_review_deadline('eligibility',id))>license_now()+interval '5 minutes' AND license_scope_review_allowed('eligibility',id)",[body.preparedEligibilityIds])).rows[0].count!==body.preparedEligibilityIds.length)fail(409,'prepared_pool_path_unavailable');return view(row);
  });
 }
}
module.exports={LicenseScopePolicies,policyTag};
