'use strict';
const { ATTRIBUTES, OPERATORS } = require('../../../../packages/company-group-rule-contract');
function companyGroupRuleOpenApi() {
 const uuid={type:'string',format:'uuid',pattern:'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'};const revision={type:'string',pattern:'^[1-9][0-9]{0,18}$'};const timestamp={type:'string',format:'date-time'};
 const object=properties=>({type:'object',additionalProperties:false,required:Object.keys(properties),properties});const nullable=schema=>({oneOf:[schema,{type:'null'}]});const array=(items,maxItems)=>({type:'array',maxItems,items});
 const ref=name=>({$ref:'#/components/schemas/'+name});const json=schema=>({content:{'application/json':{schema}}});
 const reason={type:'string',minLength:10,maxLength:500};const base={schemaVersion:{const:1},companyGroupRuleProtocol:{const:1},actorUserId:uuid,tenantId:uuid};const sha={type:'string',pattern:'^[a-f0-9]{64}$'};
 const conditions=array(object({attribute:{enum:[...ATTRIBUTES]},operator:{enum:[...OPERATORS]},value:{type:'string',minLength:1,maxLength:160}}),8);conditions.minItems=1;conditions.uniqueItems=true;
 const draft=object({dynamic:nullable(object({all:conditions})),childGroupIds:{...array(uuid,25),uniqueItems:true},excludedUserIds:{...array(uuid,10000),uniqueItems:true}});
 draft.anyOf=[{properties:{dynamic:{type:'object'}}},{properties:{childGroupIds:{minItems:1}}}];
 const rule=object({groupId:uuid,tenantId:uuid,revision,enabled:{type:'boolean'},draft:ref('CompanyGroupRuleDraft'),createdBy:uuid,createdAt:timestamp,updatedAt:timestamp});
 const memberResult={oneOf:[object({userId:uuid,status:{enum:['added','retained','manual-retained','removed','awaiting-review']},code:{type:'null'}}),object({userId:uuid,status:{const:'blocked'},code:{enum:[403,404,409,428]}})]};
 const schemas={
  CompanyGroupRuleDraft:draft,CompanyGroupRule:rule,
  CompanyGroupRulePage:object({...base,groupId:uuid,rule:nullable(ref('CompanyGroupRule')),etag:{type:'string'},executionMode:{const:'manual'}}),
  CompanyGroupRuleReceipt:object({...base,outcome:{enum:['applied','already_applied']},rule:ref('CompanyGroupRule')}),
  CompanyGroupRulePreview:object({...base,groupId:uuid,groupName:{type:'string',maxLength:255},groupRevision:revision,ruleRevision:revision,enabled:{type:'boolean'},observation:sha,executionMode:{const:'manual'},
   desired:array(object({userId:uuid,eligibilityRevision:revision}),10000),existing:array(object({userId:uuid,membershipId:uuid,managed:{type:'boolean'}}),10000),additions:{type:'integer',minimum:0,maximum:10000}}),
  CompanyGroupRuleSync:object({...base,groupId:uuid,ruleRevision:revision,observation:sha,results:array(memberResult,25),nextCursor:nullable(uuid),hasBlocked:{type:'boolean'}}),
  CompanyGroupRuleHistory:object({...base,groupId:uuid,page:{type:'integer',minimum:1,maximum:999999},limit:{const:25},total:{type:'integer',minimum:0},events:array(object({id:uuid,kind:{enum:['configuration','membership']},action:{enum:['configured','member-add','member-remove']},userId:nullable(uuid),membershipId:nullable(uuid),ruleRevision:revision,actorUserId:uuid,reason,createdAt:timestamp,deliveryStatus:{const:'pending'}}),25)}),
 };
 const description='Actual own-company owner and original canonical human bearer with fresh verified MFA at most 300 seconds. No tenant selectors, API keys, global role shortcut or machine impersonation. Typed literal case-insensitive AND predicates; OR effective canonical child groups; exclusions apply only to the rule source. Edges must be own, acyclic and at most 16 links deep. One standing versioned configuration per own canonical group. Saving configures; explicit sync creates real canonical memberships with original GroupMutator evidence and pending fingerprints. Independent initial group reviews remain pending and nested parents use only effective child members. Unattended rule execution and event dispatch remain open. Local group changes do not confirm manufacturer licenses, mailboxes or device effects.';
 const errors=Object.fromEntries([400,401,403,404,409,412,428,503].map(status=>[status,{description:'Rejected or unconfirmed. Earlier confirmed member transactions remain committed; inspect current own state and retained history before another explicit attempt.'}]));
 const group={name:'id',in:'path',required:true,schema:uuid};const read=(operationId,schema,parameters=[])=>({operationId,description,security:[{bearerAuth:[]}],parameters:[group,...parameters],responses:{200:{description:'Actual current own state or retained original receipt',...json(ref(schema))},...errors}});
 const root='/api/groups/{id}/rule';
 const paths={
  [root]:{get:read('readOwnCompanyGroupRule','CompanyGroupRulePage'),put:{...read('configureOwnCompanyGroupRule','CompanyGroupRuleReceipt',[{name:'If-Match',in:'header',required:true,schema:{type:'string'},description:'Exact captured group-rule UUID/revision, or absent for initial creation.'},{name:'Idempotency-Key',in:'header',required:true,schema:uuid}]),requestBody:{required:true,...json(object({draft:ref('CompanyGroupRuleDraft'),enabled:{type:'boolean'},reason,confirm:{const:true}}))}}},
  [root+'/preview']:{get:read('previewOwnCompanyGroupRule','CompanyGroupRulePreview')},
  [root+'/sync']:{post:{...read('reconcileOwnCompanyGroupRule','CompanyGroupRuleSync'),description:description+' At most 25 sorted captured targets per page and 10000 overall. Keep the exact observation and follow nextCursor. Direct manual memberships are preserved. Only actual rule-created membership UUIDs can be removed. A changed rule version or recipient generation requires removal/reissue; no silent review renewal. No atomic transaction over all members and no automatic uncertain write retry.',requestBody:{required:true,...json(object({observation:sha,cursor:nullable(uuid),reason,confirm:{const:true}}))}}},
  [root+'/history']:{get:read('readOwnCompanyGroupRuleHistory','CompanyGroupRuleHistory',[{name:'page',in:'query',schema:{type:'integer',minimum:1,maximum:999999,default:1}}])},
 };
 return{paths,components:{schemas}};
}
module.exports={companyGroupRuleOpenApi};
