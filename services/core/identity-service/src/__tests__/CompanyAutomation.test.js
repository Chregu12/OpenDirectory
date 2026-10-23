'use strict';
const { randomUUID } = require('node:crypto'); const { csv } = require('../CompanyAutomation');
const { workload, grantInput, jobInput, SCOPE } = require('../../../../../packages/company-automation-contract');
const app = () => ({ actor_type: 'application', token_use: 'access', iss: 'https://automation.test', sub: 'worker', client_id: 'worker', client_revision: '1', jti: randomUUID(), exp: Math.floor(Date.now()/1000)+300, scope: SCOPE, permissions: [SCOPE] });
test('dedicated app purpose grants no human role or caller-selected tenant',()=>{expect(workload(app(),'https://automation.test')).toMatchObject({kind:'application',clientId:'worker',clientRevision:'1'});});
test.each([{actor_type:'user'},{scope:'company.automation users.delete'},{permissions:['users.delete']},{roles:[]},{identity_authorization:{}},{client_revision:'0'},{sub:'other'},{exp:1}])('rejects mismatched app evidence %j',change=>expect(()=>workload({...app(),...change},'https://automation.test')).toThrow());
test('approval names exact fixed actions, app generation, consent and bounded expiry',()=>{
 const input={id:randomUUID(),enrollmentId:randomUUID(),clientId:'worker',clientRevision:'2',actions:['directory.groups.export','directory.users.export'],expiresAt:new Date(Date.now()+3600000).toISOString(),reason:'Approve actual own directory exports',confirm:true};
 expect(grantInput(input).actions).toEqual(['directory.groups.export','directory.users.export']);
 for(const change of [{tenantId:randomUUID()},{confirm:false},{actions:['*']},{actions:['directory.users.export','directory.users.export']},{expiresAt:new Date(Date.now()+31*86400000).toISOString()},{clientRevision:'0'}])expect(()=>grantInput({...input,...change})).toThrow();
});
test('job request cannot choose a tenant, arbitrary script, target URL or extra key',()=>{
 const input={id:randomUUID(),grantId:randomUUID(),action:'directory.users.export',format:'csv'};expect(jobInput(input)).toEqual(input);
 for(const change of [{tenantId:randomUUID()},{script:'rm -rf /'},{action:'users.delete'},{format:'html'}])expect(()=>jobInput({...input,...change})).toThrow();
 expect(()=>jobInput({...input,intervalSeconds:59},true)).toThrow();
});
test('CSV quotes cells, escapes formulas and preserves embedded commas, quotes and newlines',()=>{
 expect(csv([{name:'=HYPERLINK("https://bad")',email:'a,b\nc'}],['name','email'])).toBe('"name","email"\r\n"\'=HYPERLINK(""https://bad"")","a,b\nc"\r\n');
 for(const value of ['+SUM(1)','-1+2','@evil','\t=evil','\r=evil'])expect(csv([{value}],['value']).split('\r\n')[1].startsWith('"\'')).toBe(true);
});
test('generated automation contract describes real scope, conditional writes and the actual fixed actions',()=>{
 const spec=require('../../scripts/company-automation-openapi').companyAutomationOpenApi();const base='/api/identity/automation';
 expect(spec.paths[base+'/run'].post.responses[204]).toBeDefined();
 expect(spec.paths[base+'/grants/{id}/revoke'].post.parameters.map(row=>row.name)).toEqual(['id','If-Match']);
 expect(spec.components.schemas.CompanyAutomationGrant.properties.actions.items.enum).toEqual(['directory.users.export','directory.groups.export','directory.ous.export','licenses.groups.reconcile','directory.groups.reconcile']);
 expect(spec.paths[base+'/jobs'].post.requestBody.content['application/json'].schema.oneOf.every(schema=>schema.additionalProperties===false)).toBe(true);
 expect(spec.paths[base+'/license-source'].post.requestBody.content['application/json'].schema.required).toEqual(['grantId','jobId','leaseToken','groupId','userId']);
 expect(spec.components.schemas.CompanyLicenseAutomationSource.required).toHaveLength(18);
 expect(spec.components.schemas.CompanyLicenseAutomationSource.properties.context).toBeUndefined();
 expect(spec.paths['/api/licenses/automation/groups/step'].post.requestBody.content['application/json'].schema.required).toEqual(['grantId','jobId','leaseToken','ruleId']);
});
