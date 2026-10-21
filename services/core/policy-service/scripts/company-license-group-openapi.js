'use strict';
function companyLicenseGroupOpenApi() {
  const uuid={type:'string',format:'uuid',pattern:'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'};
  const revision={type:'string',pattern:'^[1-9][0-9]{0,18}$',description:'Exact PostgreSQL BIGINT string.'};
  const nullable=value=>({oneOf:[value,{type:'null'}]});const ref=name=>({$ref:'#/components/schemas/'+name});
  const object=properties=>({type:'object',additionalProperties:false,required:Object.keys(properties),properties});
  const json=schema=>({content:{'application/json':{schema}}});
  const context={schemaVersion:{const:1},companyLicenseGroupsProtocol:{const:1},actorUserId:uuid,tenantId:uuid,allocationMode:{const:'local-only'}};
  const rule=ref('CompanyLicenseGroup');const count={type:'integer',minimum:0,maximum:10000};
  const schemas={
    CompanyLicenseGroup:object({id:uuid,tenantId:uuid,groupId:uuid,poolId:uuid,blueprintId:uuid,status:{enum:['active','unlinked']},revision:{enum:['1','2']},createdAt:{type:'string',format:'date-time'},updatedAt:{type:'string',format:'date-time'}}),
    CompanyLicenseGroups:object({...context,rules:{type:'array',maxItems:100,items:rule},truncated:{type:'boolean'}}),
    CompanyLicenseGroupReceipt:object({...context,rule}),
    CompanyLicenseGroupPreview:object({...context,rule,groupRevision:nullable(revision),groupName:nullable({type:'string'}),eligibleMembers:count,assignedMembers:count,pendingMembers:count,removalMembers:count}),
    CompanyLicenseGroupSync:object({...context,rule,groupRevision:nullable(revision),results:{type:'array',maxItems:25,items:object({userId:uuid,status:{enum:['assigned','removed','retained','blocked']},code:nullable({type:'integer',minimum:400,maximum:499})})},nextCursor:nullable(uuid),hasBlocked:{type:'boolean'}}),
  };
  const errors=Object.fromEntries([400,401,403,404,409,412,428,503].map(code=>[code,{description:'Request rejected or unconfirmed. Earlier member operations may already be committed; read actual state before retrying.'}]));
  const description='Original own-company human bearer with current owner or canonical home-admin authority and independently bound MFA at most 300 seconds old. No API key, workload, caller tenant or authority replacement. One license-only immutable blueprint per group/pool link; existing allocator deduplicates seats per pool/user and preserves other direct/blueprint sources. Eligible effective canonical members only; independent group review remains required. No background worker or external provider provisioning. A sync processes at most 25 sorted user UUIDs and may commit some users before a later error. Cursor pages pin one directory revision; changed content, eligibility, pool versions or original authority can stop a run. Shortage is reported per user as blocked, never as full success.';
  const param={name:'id',in:'path',required:true,schema:uuid};const op={name:'Idempotency-Key',in:'header',required:true,schema:uuid};
  const reason={type:'string',minLength:10,maxLength:500};const confirmation={reason,confirm:{const:true}};
  const read=(operationId,schema,parameters=[])=>({operationId,description,security:[{bearerAuth:[]}],parameters,responses:{200:{description:'Actual own local state',...json(ref(schema)),headers:{'Cache-Control':{schema:{const:'no-store'}}}},...errors}});
  const write=(operationId,schema,body,parameters=[],status=200)=>({...read(operationId,schema,parameters),requestBody:{required:true,...json(object(body))},responses:{[status]:{description:'Confirmed local linkage or bounded member results, with pending delivery only',...json(ref(schema)),headers:{ETag:{schema:{type:'string',pattern:'^"company-license-group-[a-f0-9-]{36}-[12]"$'}},'Cache-Control':{schema:{const:'no-store'}}}},...errors}});
  const base='/api/licenses/company/groups';
  const paths={
    [base]:{get:read('listOwnCompanyLicenseGroups','CompanyLicenseGroups',[{name:'groupId',in:'query',schema:uuid}]),post:write('linkOwnCompanyLicenseGroup','CompanyLicenseGroupReceipt',{groupId:uuid,poolId:uuid,...confirmation},[op],201)},
    [base+'/{id}/preview']:{get:read('previewOwnCompanyLicenseGroup','CompanyLicenseGroupPreview',[param])},
    [base+'/{id}/sync']:{post:write('syncOwnCompanyLicenseGroup','CompanyLicenseGroupSync',{groupRevision:nullable(revision),cursor:nullable(uuid),...confirmation},[param])},
    [base+'/{id}/unlink']:{post:write('unlinkOwnCompanyLicenseGroup','CompanyLicenseGroupReceipt',confirmation,[param,op,{name:'If-Match',in:'header',required:true,schema:{type:'string',pattern:'^"company-license-group-[a-f0-9-]{36}-[12]"$'}}])},
    '/api/identity/company-license-groups/{id}/snapshot':{get:read('readOriginalCompanyLicenseGroupSnapshot','LicenseGroupSnapshot',[param])},
  };
  paths['/api/identity/company-license-groups/{id}/snapshot'].get.responses[200].headers['X-OD-License-Snapshot-Protocol']={required:true,schema:{const:'1'}};
  return{paths,components:{schemas}};
}
module.exports={companyLicenseGroupOpenApi};
