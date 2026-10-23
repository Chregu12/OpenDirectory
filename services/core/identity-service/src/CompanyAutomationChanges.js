'use strict';
const {v5}=require('uuid');const {LICENSE_ACTION,GROUP_ACTION,fail}=require('../../../../packages/company-automation-contract');
class CompanyAutomationChanges{
 constructor(store){this.store=store;}
 async collect(grantId,user,authorization){
  const plans=await this.store.transaction(user,authorization,async(client,actor)=>{
   await this.store.grant(client,grantId,actor,{lock:''});
   const rows=(await client.query(`SELECT plan.* FROM identity_automation_schedules plan WHERE grant_id=$1 AND enabled AND on_change
    AND NOT EXISTS(SELECT 1 FROM identity_automation_jobs job WHERE job.schedule_id=plan.id AND job.status IN('queued','running','retry_wait')) ORDER BY created_at,id LIMIT 26`,[grantId])).rows;
   if(rows.length>25)fail(503,'Complete change subscription limit exceeded');for(const row of rows)await this.store.retained(client,'schedule',row.id);return rows;
  },{readOnly:true});
  const observations=[];const errors=[];
  for(let offset=0;offset<plans.length;offset+=5){
   const settled=await Promise.allSettled(plans.slice(offset,offset+5).map(async plan=>{
    const policy=plan.action===LICENSE_ACTION?await this.store.licenseClient.observe(plan,user,authorization):null;
    if(policy)require('../../../../packages/company-automation-change-contract').observation(policy,plan,user);
    const groupId=policy?.groupId||plan.rule_id;
    const identity=await this.store.database.transaction(async client=>{
     await client.query("SET LOCAL timezone='UTC';SET LOCAL statement_timeout='5s'");
     if(plan.action===GROUP_ACTION&&!await new(require('./CompanyGroupRules').CompanyGroupRules)(this.store.database).rule(client,groupId,plan.tenant_id))fail(404,'Saved own group rule required');
     return(await client.query('SELECT identity_automation_change_identity($1,$2) AS source',[groupId,plan.tenant_id])).rows[0].source;
    },{readOnly:true});return{plan,source:{schemaVersion:1,scheduleRevision:String(plan.revision),identity,policy}};
   }));
   settled.forEach((result,index)=>{if(result.status==='fulfilled')observations.push(result.value);else errors.push({scheduleId:plans[offset+index].id,status:result.reason.status||503});});
  }
  return{observations,errors};
 }
 async dispatch(client,permission,collected){
  let count=Number((await client.query("SELECT count(*) AS n FROM identity_automation_jobs WHERE grant_id=$1 AND status IN('queued','running','retry_wait')",[permission.id])).rows[0].n);let admitted=0;
  for(const item of collected.observations){
   if(count>=1000||admitted>=5)break;
   const plan=(await client.query('SELECT * FROM identity_automation_schedules WHERE id=$1 AND grant_id=$2 AND enabled AND on_change FOR UPDATE',[item.plan.id,permission.id])).rows[0];
   if(!plan||String(plan.revision)!==item.source.scheduleRevision)continue;
   if((await client.query("SELECT 1 FROM identity_automation_jobs WHERE schedule_id=$1 AND status IN('queued','running','retry_wait') LIMIT 1",[plan.id])).rows.length)continue;
   const source={...item.source,identity:(await client.query('SELECT identity_automation_change_identity($1,$2) AS source',[item.source.identity.groupId,permission.tenant_id])).rows[0].source};
   if((await client.query('SELECT identity_automation_change_key($1::jsonb) IS NOT DISTINCT FROM identity_automation_change_key($2::jsonb) AS same',[plan.source_checkpoint,source])).rows[0].same)continue;
   const id=v5(String(plan.revision),plan.id);
   await client.query("INSERT INTO identity_automation_jobs(id,grant_id,tenant_id,schedule_id,action,format,rule_id,status,event_source) VALUES($1,$2,$3,$4,$5,'json',$6,'queued',$7)",[id,permission.id,permission.tenant_id,plan.id,plan.action,plan.rule_id,source]);
   await client.query('UPDATE identity_automation_schedules SET source_checkpoint=$2,source_job_id=$3,next_run_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE id=$1',[plan.id,source,id]);count++;admitted++;
  }
 }
}
module.exports={CompanyAutomationChanges};
