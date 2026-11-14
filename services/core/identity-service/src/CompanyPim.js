'use strict';
const {randomUUID}=require('node:crypto');
const C=require('./CompanyRoleContract');const A=require('./CompanyRoleAuthority');const {CompanyRoles,role,grant}=require('./CompanyRoles');
const {acceptsRoleAuthentication}=require('../../../../packages/role-authentication-contract');
const iso=value=>value?new Date(value).toISOString():null;
function eligible(row){const value=grant(row);return {...value,status:value.status==='active'?'eligible':value.status};}
function activation(row){return {id:row.id,tenantId:row.tenant_id,eligibilityId:row.eligibility_id,userId:row.user_id,revision:String(row.revision),createdAt:iso(row.created_at),expiresAt:iso(row.expires_at),endedAt:iso(row.ended_at),endedBy:row.ended_by,status:row.ended_at?'ended':row.expired?'expired':row.effective?'active':'invalid'};}
const eligibleColumns=`eligible.*,role.enabled AND role.revision=eligible.role_revision AS definition_current,eligible.expires_at<=clock_timestamp() AS expired,identity_company_role_pim_eligibility_current(eligible.id) AS effective`;
const activationColumns=`activation.*,activation.expires_at<=clock_timestamp() AS expired,EXISTS(SELECT 1 FROM jsonb_array_elements(identity_company_role_pim_sources(activation.user_id,activation.tenant_id,role.permissions[1],NULL,NULL)) source WHERE source->>'activationId'=activation.id::text) AS effective`;
function failure(error){if(!error.status&&['23503','23505','23514','42501','28000','40P01','55P03'].includes(error.code))error.status=({23503:404,23505:409,23514:409,42501:503,28000:401,'40P01':409,'55P03':409})[error.code];throw error;}
class CompanyPim {
 constructor(database,options={}){this.database=database;this.roles=new CompanyRoles(database,options);}
 async read(user,bearer,operation){user=structuredClone(user);const commands=this.roles.commands(user);await commands.revalidate(user,bearer);let deadline;
  const result=await this.database.transaction(async client=>{const proof=await A.actorProof(client,user,{fresh:false});deadline=proof.validUntil;await A.receiving(client);return operation(client,proof.tenant.id);},{readOnly:true});
  await commands.revalidate(user,bearer);if(deadline*1000<=Date.now())C.fail(401,'company_pim_actor_expired');return result;
 }
 async eligibilities(id,query,user,bearer){C.identifier(id);const page=C.page(query);if(page.search)C.fail(400,'eligibility_search_not_supported');
  return this.roles.read(user,bearer,async(client,tenant)=>{
   if(!(await client.query('SELECT 1 FROM identity_company_roles WHERE id=$1 AND tenant_id=$2',[id,tenant])).rows.length)C.fail(404,'company_role_not_found');
   const total=Number((await client.query('SELECT count(*) AS count FROM identity_company_role_eligibilities WHERE role_id=$1 AND tenant_id=$2',[id,tenant])).rows[0].count);
   const rows=(await client.query(`SELECT ${eligibleColumns} FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id WHERE eligible.role_id=$1 AND eligible.tenant_id=$2 ORDER BY eligible.created_at DESC,eligible.id DESC LIMIT 25 OFFSET $3`,[id,tenant,(page.page-1)*25])).rows;
   return {schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:tenant,roleId:id,eligibilities:rows.map(eligible),total,page:page.page,limit:25};
  }).catch(failure);
 }
 async self(query,user,bearer){const {tab='eligible',...selectors}=query;if(!['eligible','active'].includes(tab))C.fail(400,'invalid_company_pim_tab');const page=C.page(selectors);
  return this.read(user,bearer,async(client,tenant)=>{
   const actor=user.identity_authorization.userId;const candidates=(await client.query('SELECT identity_company_role_pim_candidates($1,$2) AS candidates',[actor,tenant])).rows[0].candidates;
   if(!Array.isArray(candidates)||candidates.length>1000)C.fail(503,'company_pim_candidate_limit');
   const where=tab==='eligible'?`eligible.id=ANY($3::uuid[])`:`activation.user_id=$1 AND activation.ended_at IS NULL AND activation.expires_at>clock_timestamp()`;
   const join=tab==='eligible'?`LEFT JOIN LATERAL (SELECT live.* FROM identity_company_role_activations live WHERE live.eligibility_id=eligible.id AND live.user_id=$1 AND live.ended_at IS NULL AND live.expires_at>clock_timestamp() ORDER BY live.created_at DESC,live.id DESC LIMIT 1) activation ON true`:`JOIN identity_company_role_activations activation ON activation.eligibility_id=eligible.id`;
   const from=`FROM identity_company_role_eligibilities eligible JOIN identity_company_roles role ON role.id=eligible.role_id ${join} WHERE eligible.tenant_id=$2 AND ${where} AND ($4='' OR strpos(lower(concat_ws(' ',role.name,role.description)),lower($4))>0)`;
   const params=[actor,tenant,candidates.map(item=>item.id),page.search];
   // $3 stays typed even in the active branch, where the original candidate set may be empty.
   const typed=tab==='active'?' AND $3::uuid[] IS NOT NULL':'';
   const total=Number((await client.query('SELECT count(*) AS count '+from+typed,params)).rows[0].count);
   const rows=(await client.query(`SELECT to_jsonb(eligible)||jsonb_build_object('revision',eligible.revision::text,'role_revision',eligible.role_revision::text) AS eligibility,to_jsonb(role)||jsonb_build_object('revision',role.revision::text) AS definition,CASE WHEN activation.id IS NULL THEN NULL ELSE to_jsonb(activation)||jsonb_build_object('revision',activation.revision::text) END AS activation,
    identity_company_role_pim_eligibility_current(eligible.id) AS eligibility_current,identity_company_role_pim_sources($1,$2,role.permissions[1],NULL,NULL) AS sources,
    (SELECT name FROM groups WHERE id=eligible.target_id AND eligible.target_type='group') AS group_name,(SELECT name FROM ous WHERE id=eligible.ou_id) AS ou_name ${from+typed} ORDER BY lower(role.name),eligible.id,activation.created_at DESC LIMIT 25 OFFSET $5`,[...params,(page.page-1)*25])).rows;
   const now=Math.floor(Date.now()/1000);
   return {schemaVersion:1,companyPimProtocol:1,actorUserId:actor,tenantId:tenant,canActivate:acceptsRoleAuthentication(A.FRESH,user),tab,total,page:page.page,limit:25,items:rows.map(row=>{
    const candidate=candidates.find(item=>item.id===row.eligibility.id);return {eligibility:eligible({...row.eligibility,definition_current:row.definition.enabled&&String(row.definition.revision)===String(row.eligibility.role_revision),expired:new Date(row.eligibility.expires_at).getTime()<=Date.now(),effective:row.eligibility_current}),role:role(row.definition),groupName:row.group_name,ouName:row.ou_name,
     maximumDurationSeconds:Math.max(0,Math.min(row.definition.max_duration_seconds,candidate?Number(candidate.validUntil)-now:0)),activation:row.activation?activation({...row.activation,expired:new Date(row.activation.expires_at).getTime()<=Date.now(),effective:row.sources.some(source=>source.activationId===row.activation.id&&A.accepted(user,source))}):null};})};
  }).catch(failure);
 }
 async history(query,user,bearer){const page=C.page(query);if(page.search)C.fail(400,'pim_history_search_not_supported');return this.read(user,bearer,async(client,tenant)=>{
  const where="event.tenant_id=$1 AND event.action IN('activation-create','activation-cancel','activation-revoke') AND event.after_state->>'user_id'=$2";
  const params=[tenant,user.identity_authorization.userId];const total=Number((await client.query('SELECT count(*) AS count FROM identity_company_role_events event WHERE '+where,params)).rows[0].count);
  const rows=(await client.query('SELECT event.*,outbox.status AS delivery_status FROM identity_company_role_events event LEFT JOIN identity_company_role_outbox outbox USING(id) WHERE '+where+' ORDER BY event.created_at DESC,event.id DESC LIMIT 25 OFFSET $3',[...params,(page.page-1)*25])).rows;
  if(rows.some(row=>row.delivery_status!=='pending'))C.fail(503,'company_pim_history_receipt_unavailable');return {schemaVersion:1,actorUserId:user.identity_authorization.userId,tenantId:tenant,total,page:page.page,limit:25,events:rows.map(row=>({id:row.id,action:row.action,resourceId:row.resource_id,actorUserId:row.actor.context.userId,reason:row.reason,createdAt:iso(row.created_at),deliveryStatus:'pending'}))};
 }).catch(failure);}
 async change(action,id,values,expected,user,bearer,parentId=null){user=structuredClone(user);const self=action==='activation-create'||action==='activation-cancel';const fresh=action!=='activation-cancel';
  const body=action==='eligibility-create'?C.eligibility(values):action==='activation-create'?C.activation(values):C.decision(values);
  const kind=action==='eligibility-create'?'role':action==='activation-create'||action==='eligibility-revoke'?'eligibility':'activation';const revision=C.expected(kind,expected,parentId||id);
  return this.roles.commands(user).run(user,bearer,async client=>{
   const proof=await (self?A.actorProof(client,user,{fresh}):A.managerProof(client,user));await A.receiving(client);
   const table=kind==='role'?'identity_company_roles':kind==='eligibility'?'identity_company_role_eligibilities':'identity_company_role_activations';
   const row=(await client.query('SELECT * FROM '+table+' WHERE id=$1 AND tenant_id=$2',[parentId||id,proof.tenant.id])).rows[0];if(!row)C.fail(404,'company_pim_target_not_found');
   if(row.revision.toString()!==revision)C.fail(412,'company_pim_target_changed');
   if(action==='activation-cancel'&&row.user_id!==proof.context.userId)C.fail(404,'company_pim_target_not_found');
   if(action==='activation-revoke'&&row.user_id===proof.context.userId)C.fail(403,'independent_activation_revocation_required');
   if(action==='activation-create'&&!(await client.query("SELECT 1 FROM jsonb_array_elements(identity_company_role_pim_candidates($1,$2)) candidate WHERE candidate->>'id'=$3",[proof.context.userId,proof.tenant.id,parentId])).rows.length)C.fail(404,'company_pim_eligibility_not_found');
   if(action==='eligibility-create'&&(body.targetType==='user'&&body.targetId===proof.context.userId||body.targetType==='group'&&(await client.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2',[body.targetId,proof.context.userId])).rows.length))C.fail(403,'independent_company_role_recipient_required');
   const command={action,id,eventId:randomUUID(),actor:proof,values:body,expectedRevision:revision,...(action==='eligibility-create'?{roleId:parentId}:action==='activation-create'?{eligibilityId:parentId}:{})};
   const eventId=(await client.query('SELECT identity_company_role_pim_change($1::jsonb) AS id',[JSON.stringify(command)])).rows[0]?.id;
   const event=(await client.query("SELECT event.* FROM identity_company_role_events event JOIN identity_company_role_outbox outbox USING(id) WHERE event.id=$1 AND event.tenant_id=$2 AND event.actor=$3::jsonb AND event.transaction_id=txid_current() AND outbox.tenant_id=event.tenant_id AND outbox.status='pending'",[eventId,proof.tenant.id,JSON.stringify(proof)])).rows[0];
   if(!event||event.action!==action||event.resource_id!==id)C.fail(503,'company_pim_receipt_unavailable');
   const target=action.startsWith('eligibility-')?'identity_company_role_eligibilities':'identity_company_role_activations';const actual=(await client.query('SELECT * FROM '+target+' WHERE id=$1 AND tenant_id=$2',[id,proof.tenant.id])).rows[0];
   if(!actual||(await client.query("SELECT to_jsonb(row)=(event.after_state"+(action.startsWith('activation-')?"-'role_id'":"")+") AS confirmed FROM "+target+" row JOIN identity_company_role_events event ON event.resource_id=row.id WHERE row.id=$1 AND event.id=$2",[id,eventId])).rows[0]?.confirmed!==true)C.fail(503,'company_pim_effect_unavailable');
   return {schemaVersion:1,actorUserId:proof.context.userId,tenantId:proof.tenant.id,eventId,action,...(action.startsWith('eligibility-')?{eligibility:eligible({...actual,definition_current:true,expired:false,effective:!actual.revoked_at})}:{activation:activation({...actual,expired:false,effective:!actual.ended_at})})};
  },{actor:user.sub},fresh?A.FRESH:undefined).catch(failure);
 }
 assign(id,values,expected,user,bearer){C.identifier(id);return this.change('eligibility-create',randomUUID(),values,expected,user,bearer,id);}
 revokeEligibility(id,values,expected,user,bearer){C.identifier(id);return this.change('eligibility-revoke',id,values,expected,user,bearer);}
 activate(id,values,expected,user,bearer){C.identifier(id);return this.change('activation-create',randomUUID(),values,expected,user,bearer,id);}
 end(id,values,expected,user,bearer,manager=false){C.identifier(id);return this.change(manager?'activation-revoke':'activation-cancel',id,values,expected,user,bearer);}
}
module.exports={CompanyPim,eligible,activation};
