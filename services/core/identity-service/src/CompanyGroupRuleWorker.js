'use strict';
const { randomUUID } = require('node:crypto');
const { CompanyGroupRules } = require('./CompanyGroupRules');
const { GROUP_ACTION, fail } = require('../../../../packages/company-automation-contract');
class CompanyGroupRuleWorker {
 constructor(automation) { this.automation = automation; this.database = automation.database; this.rules = new CompanyGroupRules(this.database); }
 async transaction(job, user, authorization, operation) {
  const actor = await this.automation.actor(user, authorization); if (actor.kind !== 'application') fail(403, 'Actual group-rule app required');
  return this.database.transaction(async client => {
   await client.query("SET LOCAL timezone='UTC';SET LOCAL lock_timeout='3s';SET LOCAL statement_timeout='15s'");
   await client.query('SELECT identity_company_group_rule_app_receiving()');
   const permission = await this.automation.grant(client, job.grant_id, actor);
   const current = (await client.query('SELECT * FROM identity_automation_jobs WHERE id=$1 AND grant_id=$2',[job.id, permission.id])).rows[0];
   if (!current || current.action !== GROUP_ACTION || current.status !== 'running' || current.lease_token !== job.lease_token || current.lease_until <= new Date()) fail(403, 'Current group-rule job lease required');
   await this.automation.retained(client, 'job', current.id);
   const row = await this.rules.rule(client, current.rule_id, permission.tenant_id, 'SHARE'); if (!row) fail(404, 'Own group rule unavailable');
   const source = { kind:'application', issuer:actor.issuer, clientId:actor.clientId, clientRevision:actor.clientRevision, grantId:permission.id, jobId:current.id,
    leaseToken:current.lease_token, tokenId:actor.tokenId, validUntil:Math.floor(Math.min(actor.validUntil*1000,current.lease_until.getTime(),permission.expires_at.getTime())/1000),
    tenant:permission.approval.tenant, ruleId:row.group_id, ruleRevision:String(row.revision), retryCount:String(current.retry_count) };
   await client.query('SELECT identity_company_group_rule_app_source($1)',[source]);
   const result = await operation(client, source, row); await this.automation.unchanged(actor,user,authorization); return result;
  });
 }
 async inventory(client,row,tenantId) {
  const desired = await this.rules.desired(client,row,tenantId); const members = await this.rules.members(client,row.group_id,tenantId);
  const targets = [...new Set([...desired.map(item=>item.userId),...members.filter(item=>item.rule_revision).map(item=>item.user_id)])].sort();
  if (members.length>10000 || targets.length>10000) fail(409,'Complete group-rule work exceeds 10000 targets');
  return {desired,members,targets,observation:this.rules.observation(row,desired)};
 }
 async retained(client,run) {
  const valid=(await client.query(`SELECT EXISTS(SELECT 1 FROM identity_company_group_rule_runs actual JOIN identity_company_group_rule_work_outbox box ON box.id=actual.id AND box.entity='run' AND box.status='pending'
   AND box.fingerprint=encode(sha256(convert_to(to_jsonb(actual)::text,'UTF8')),'hex') WHERE actual.id=$1) AND NOT EXISTS(SELECT 1 FROM identity_company_group_rule_steps step LEFT JOIN identity_company_group_rule_work_outbox box ON box.id=step.id
    WHERE step.run_id=$1 AND(box.entity IS DISTINCT FROM 'step' OR box.status IS DISTINCT FROM 'pending' OR box.fingerprint IS DISTINCT FROM encode(sha256(convert_to(to_jsonb(step)::text,'UTF8')),'hex'))) AS valid`,[run.id])).rows[0]?.valid;
  if(valid!==true)fail(503,'Original group-rule work receipts unavailable');
 }
 async outbox(client,table,id,entity) {
  await client.query(`INSERT INTO identity_company_group_rule_work_outbox SELECT id,$2,encode(sha256(convert_to(to_jsonb(actual)::text,'UTF8')),'hex'),'pending',created_at FROM ${table} actual WHERE id=$1`,[id,entity]);
 }
 async capture(job,user,authorization,force=false) {
  return this.transaction(job,user,authorization,async(client,source,row)=>{
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,500051))',[job.id]);
   const inventory=await this.inventory(client,row,source.tenant.id);
   const old=(await client.query('SELECT * FROM identity_company_group_rule_runs WHERE job_id=$1 AND retry_count=$2 ORDER BY cycle DESC LIMIT 1',[job.id,job.retry_count])).rows[0];
   if(old){await this.retained(client,old);if(!force&&old.observation===inventory.observation)return old;if(old.cycle===5)fail(409,'Group sources did not converge within five captured cycles');}
   const id=randomUUID();await client.query("SELECT set_config('opendirectory.company_group_rule_work',$1,true)",[JSON.stringify({kind:'capture',source,runId:id})]);
   const run=(await client.query(`INSERT INTO identity_company_group_rule_runs(id,job_id,grant_id,tenant_id,group_id,retry_count,cycle,rule_revision,observation,desired,targets,source)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,[id,job.id,source.grantId,source.tenant.id,row.group_id,job.retry_count,(old?.cycle||0)+1,row.revision,inventory.observation,JSON.stringify(inventory.desired),inventory.targets,source])).rows[0];
   await this.outbox(client,'identity_company_group_rule_runs',id,'run');return run;
  });
 }
 async mutate(client,source,row,userId,action,member,beforeMembers) {
  const before=(await client.query('SELECT identity_directory_group_state(to_jsonb(actual)) AS state FROM groups actual WHERE id=$1',[row.group_id])).rows[0]?.state;
  if(!before)fail(404,'Own group unavailable');
  if(action==='member-add'&&beforeMembers.length>=10000)fail(409,'Canonical group capacity reached');
  const policy=action==='member-add'?(await client.query('SELECT id,version,window_seconds,retired_at,identity_directory_group_policy_owned(id,$2) AS coherent FROM identity_membership_review_policies WHERE group_id=$1 ORDER BY (retired_at IS NULL) DESC,created_at DESC,id LIMIT 1',[row.group_id,source.tenant.id])).rows[0]:null;
  if(policy?.retired_at)fail(409,'Governed group needs a replacement review policy');if(policy&&!policy.coherent)fail(503,'Own group review source unavailable');
  const operationId=randomUUID();const eligibility=(await client.query('SELECT eligibility_revision FROM users WHERE id=$1',[userId])).rows[0]?.eligibility_revision;if(!eligibility)fail(404,'Own group recipient unavailable');
  const proof={operationId,issuer:source.issuer,subject:source.clientId,tenant:source.tenant,application:source,validUntil:source.validUntil,
   target:{id:row.group_id,action,before,beforeMembers,expectedValues:{name:before.name,description:before.description??null},
    member:{id:member?.membership_id||null,userId,before:member||null,eligibilityRevision:String(eligibility)},governance:policy?{id:policy.id,version:String(policy.version),windowSeconds:policy.window_seconds}:null}};
  await client.query("SELECT set_config('opendirectory.group_mutation',$1,true),set_config('opendirectory.actor',$2,true)",[JSON.stringify(proof),source.clientId]);
  await client.query('SAVEPOINT group_rule_member');
  try {
   if(action==='member-add')await client.query('INSERT INTO group_members(group_id,user_id) VALUES($1,$2)',[row.group_id,userId]);
   else await client.query('DELETE FROM group_members WHERE group_id=$1 AND membership_id=$2 AND user_id=$3',[row.group_id,member.membership_id,userId]);
   await client.query('SELECT identity_directory_group_finish()');
   const membershipId=member?.membership_id||(await client.query("SELECT current_setting('opendirectory.group_mutation_membership') AS id")).rows[0].id;
   const scope={authority:source,groupId:row.group_id,ruleRevision:String(row.revision),operationId,observation:null,reason:'Explicitly delegated app reconciles the saved own-company group rule'};
   await client.query("SELECT set_config('opendirectory.company_group_rule_effect',$1,true)",[JSON.stringify(scope)]);
   await client.query(`INSERT INTO identity_company_group_rule_effects(id,group_id,tenant_id,membership_id,user_id,rule_revision,action,source,group_scope_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,encode(sha256(convert_to($9::jsonb::text,'UTF8')),'hex'))`,[operationId,row.group_id,source.tenant.id,membershipId,userId,row.revision,action,scope,proof]);
   await client.query("INSERT INTO identity_company_group_rule_effect_outbox SELECT id,'pending',encode(sha256(convert_to(to_jsonb(actual)::text,'UTF8')),'hex'),created_at FROM identity_company_group_rule_effects actual WHERE id=$1",[operationId]);
   await client.query('RELEASE SAVEPOINT group_rule_member');return {operationId,status:action==='member-remove'?'removed':policy?'awaiting-review':'added'};
  } catch(error) {
   await client.query('ROLLBACK TO SAVEPOINT group_rule_member');await client.query('RELEASE SAVEPOINT group_rule_member');throw error;
  }
 }
 async process(job,run,userId,user,authorization) {
  return this.transaction(job,user,authorization,async(client,source,row)=>{
   await this.retained(client,run);
   await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,500051))',[run.id+':'+userId]);
   const previous=(await client.query('SELECT result FROM identity_company_group_rule_steps WHERE run_id=$1 AND user_id=$2',[run.id,userId])).rows[0];if(previous)return previous.result;
   if(String(row.revision)!==String(run.rule_revision)||this.rules.observation(row,await this.rules.desired(client,row,source.tenant.id))!==run.observation)fail(412,'Captured group-rule source changed');
   await client.query("SELECT id FROM users WHERE id=$1 AND identity_tenant_id('user',id)=$2 FOR UPDATE",[userId,source.tenant.id]);
   if(!(await client.query("SELECT id FROM groups WHERE id=$1 AND identity_tenant_id('group',id)=$2 FOR UPDATE",[row.group_id,source.tenant.id])).rows.length)fail(404,'Own group unavailable');
   await client.query('SELECT id FROM groups WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE',[row.draft.childGroupIds]);
   const inventory=await this.inventory(client,row,source.tenant.id);if(inventory.observation!==run.observation)fail(412,'Captured group-rule source changed');
   const existing=inventory.members.find(item=>item.user_id===userId);const desired=inventory.desired.find(item=>item.userId===userId);
   await client.query("SELECT set_config('opendirectory.company_group_rule_work',$1,true)",[JSON.stringify({kind:'step',source,runId:run.id,userId})]);
   let status;let code=null;let effectId=null;
   if(existing&&!existing.rule_revision)status='manual-retained';
   else {
    const remove=existing&&(!desired||String(existing.rule_revision)!==String(row.revision)||String(existing.eligibility_revision)!==desired.eligibilityRevision);
    const action=remove?'member-remove':desired&&!existing?'member-add':null;
    if(action){
     const members=(await client.query('SELECT to_jsonb(member) AS state FROM group_members member WHERE group_id=$1 ORDER BY membership_id',[row.group_id])).rows.map(item=>item.state);
     try { const outcome=await this.mutate(client,source,row,userId,action,action==='member-remove'?members.find(item=>item.user_id===userId):null,members);status=outcome.status;effectId=outcome.operationId; }
     catch(error){if(![403,404,409,428].includes(error.status))throw error;status='blocked';code=error.status;}
    }else status=desired?(await client.query('SELECT identity_membership_review_allowed($1) AS allowed',[existing.membership_id])).rows[0].allowed?'retained':'awaiting-review':'removed';
   }
   const result={userId,status,code};const id=randomUUID();
   await client.query('INSERT INTO identity_company_group_rule_steps(id,run_id,user_id,result,source,effect_id) VALUES($1,$2,$3,$4,$5,$6)',[id,run.id,userId,result,source,effectId]);
   await this.outbox(client,'identity_company_group_rule_steps',id,'step');return result;
  });
 }
 async step(job,user,authorization) {
  let run=await this.capture(job,user,authorization);
  const pending=await this.transaction(job,user,authorization,async client=>(await client.query('SELECT target.user_id AS id FROM unnest($1::uuid[]) AS target(user_id) WHERE NOT EXISTS(SELECT 1 FROM identity_company_group_rule_steps step WHERE step.run_id=$2 AND step.user_id=target.user_id) ORDER BY target.user_id LIMIT 25',[run.targets,run.id])).rows.map(row=>row.id));
  try{for(const id of pending)await this.process(job,run,id,user,authorization);}catch(error){if(error.status!==412)throw error;run=await this.capture(job,user,authorization,true);}
  return this.transaction(job,user,authorization,async(client,source,row)=>{
   await this.retained(client,run);const results=(await client.query('SELECT result FROM identity_company_group_rule_steps WHERE run_id=$1 ORDER BY user_id',[run.id])).rows.map(item=>item.result);
   let finished=results.length===run.targets.length;
   if(finished){
    const inventory=await this.inventory(client,row,source.tenant.id);
    const blocked=results.some(item=>item.status==='blocked');
    const converged=inventory.observation===run.observation&&inventory.desired.every(item=>inventory.members.some(member=>member.user_id===item.userId))
     &&inventory.members.filter(item=>item.rule_revision).every(member=>inventory.desired.some(item=>item.userId===member.user_id&&item.eligibilityRevision===String(member.eligibility_revision))&&String(member.rule_revision)===String(row.revision));
    if(inventory.observation!==run.observation||!blocked&&!converged){if(run.cycle===5)fail(409,'Group-rule sources did not converge in five cycles');return {needsRescan:true};}
   }
   const blocked=results.filter(item=>['blocked','awaiting-review'].includes(item.status)).length;
   return {schemaVersion:1,companyGroupRuleAutomationProtocol:1,grantId:source.grantId,jobId:job.id,ruleId:row.group_id,
    actor:{kind:'application',id:source.grantId,clientId:source.clientId,clientRevision:source.clientRevision},
    progress:{runId:job.id,retryCount:job.retry_count,cycle:run.cycle,completed:results.length,total:run.targets.length,blocked},
    finished,hasBlocked:blocked>0,results:finished?results:[]};
  }).then(async outcome=>{
   if(outcome.needsRescan){const next=await this.capture(job,user,authorization,true);if(next.targets.length===0)return this.step(job,user,authorization);return {schemaVersion:1,companyGroupRuleAutomationProtocol:1,grantId:job.grant_id,jobId:job.id,ruleId:job.rule_id,
    actor:{kind:'application',id:job.grant_id,clientId:user.client_id,clientRevision:user.client_revision},progress:{runId:job.id,retryCount:job.retry_count,cycle:next.cycle,completed:0,total:next.targets.length,blocked:0},finished:false,hasBlocked:false,results:[]};}return outcome;
  });
 }
}
module.exports={CompanyGroupRuleWorker};
