'use strict';
const { randomUUID } = require('node:crypto'); const contract = require('../../../../../packages/company-group-rule-contract');
const input = () => ({ dynamic: { all: [{ attribute:'department',operator:'equals',value:'Engineering' }] },childGroupIds:[],excludedUserIds:[] });
test('group rule input is a bounded typed predicate and canonical group references, never executable code or caller-selected tenancy', () => {
 expect(contract.draft(input())).toEqual(input());
 for (const patch of [{ dynamic:{all:[{attribute:'roles',operator:'equals',value:'admin'}]} },{ dynamic:{all:[{attribute:'department',operator:'sql',value:'true'}]} },{ childGroupIds:['legacy'] },{ tenantId:randomUUID() },{ dynamic:null }]) expect(()=>contract.draft({...input(),...patch})).toThrow();
 expect(()=>contract.draft({...input(),childGroupIds:Array.from({length:26},()=>randomUUID())})).toThrow();
 expect(()=>contract.command({draft:input(),enabled:true,reason:'Actual own group rule',confirm:false})).toThrow();
});
test('group rule ETags keep exact revision strings and absence is a distinct captured state',()=>{
 const id=randomUUID();expect(contract.expected(id,contract.etag(id,null))).toBeNull();expect(contract.expected(id,contract.etag(id,'9007199254740993'))).toBe('9007199254740993');
 for(const tag of [undefined,'*','W/'+contract.etag(id,'1'),contract.etag(randomUUID(),'1')])expect(()=>contract.expected(id,tag)).toThrow();
});
test('generated group-rule contract describes actual manual effects, original conditional versions and bounded canonical sources',()=>{
 const spec=require('../../scripts/company-group-rule-openapi').companyGroupRuleOpenApi();const base='/api/groups/{id}/rule';
 expect(spec.paths[base].put.parameters.map(row=>row.name)).toEqual(['id','If-Match','Idempotency-Key']);
 expect(spec.components.schemas.CompanyGroupRulePreview.properties.executionMode.const).toBe('manual');
 expect(spec.paths[base+'/sync'].post.requestBody.content['application/json'].schema.required).toEqual(['observation','cursor','reason','confirm']);
 expect(spec.components.schemas.CompanyGroupRuleDraft.properties.childGroupIds.maxItems).toBe(25);expect(spec.paths[base+'/history'].get.parameters.map(row=>row.name)).toEqual(['id','page']);
});
