'use strict';
const {randomUUID}=require('node:crypto');const express=require('express');const request=require('supertest');
jest.mock('../CompanyLicenseGroups',()=>({CompanyLicenseGroups:jest.fn()}));
const methods=Object.fromEntries(['list','link','preview','sync','unlink'].map(key=>[key,jest.fn()]));
require('../CompanyLicenseGroups').CompanyLicenseGroups.mockImplementation(()=>methods);
const {companyGroupRoutes}=require('../companyGroupRoutes');const id=randomUUID();const op=randomUUID();
let app;
beforeEach(()=>{jest.clearAllMocks();for(const fn of Object.values(methods))fn.mockResolvedValue({rule:{id,revision:'1'}});app=express();app.use(express.json());app.use((req,_res,next)=>{req.user={sub:'original'};next();});app.use('/groups',companyGroupRoutes({}));});
test('link forwards the original actor, bearer, exact body and idempotency key',async()=>{
 const body={groupId:randomUUID(),poolId:randomUUID(),reason:'Actual requested group link',confirm:true};const result=await request(app).post('/groups').set('Authorization','Bearer original').set('Idempotency-Key',op).send(body);
 expect(result.status).toBe(201);expect(result.headers.etag).toBe('"company-license-group-'+id+'-1"');expect(methods.link).toHaveBeenCalledWith(body,op,{sub:'original'},'Bearer original');
});
test('unlink forwards the exact captured ETag',async()=>{await request(app).post('/groups/'+id+'/unlink').set('Idempotency-Key',op).set('If-Match','"captured"').send({});expect(methods.unlink).toHaveBeenCalledWith(id,{},'"captured"',op,{sub:'original'},undefined);});
test('API keys, unexpected queries and GET bodies cannot reach a writer',async()=>{
 for(const attempt of [request(app).post('/groups').query({tenantId:id}),request(app).post('/groups').set('X-API-Key',''),request(app).get('/groups').send({})])expect((await attempt).status).toBe(400);
 expect(methods.link).not.toHaveBeenCalled();expect(methods.list).not.toHaveBeenCalled();
});
test('an unavailable source stays unconfirmed and never falls through to legacy routes',async()=>{methods.sync.mockRejectedValue({status:503});const result=await request(app).post('/groups/'+id+'/sync').send({});expect(result.status).toBe(503);expect(result.body.error).toMatch(/may be committed/);});
test('exact mutation contracts reject caller authority, implicit confirmations and unsafe cursors',()=>{
 const {linkValues,syncValues,unlinkValues}=require('../../../../../../packages/company-license-group-contract');
 const value={groupId:id,poolId:op,reason:'Actual requested group link',confirm:true};expect(linkValues(value)).toEqual(value);
 for(const change of [{tenantId:id},{confirm:false},{poolId:'foreign'},{reason:'short'}])expect(()=>linkValues({...value,...change})).toThrow();
 for(const change of [{cursor:'../other'},{groupRevision:2},{groupRevision:'9223372036854775808'},{source:{actor:id}}])expect(()=>syncValues({groupRevision:'1',cursor:null,reason:value.reason,confirm:true,...change})).toThrow();
 expect(()=>unlinkValues({reason:value.reason,confirm:true,tenantId:id})).toThrow();
});
test('HEAD never reads a private group projection',async()=>{expect((await request(app).head('/groups')).status).toBe(404);expect(methods.list).not.toHaveBeenCalled();});
test('published API describes bounded pages, original sources and exact unlink conditions',()=>{
 const {paths,components}=require('../../../scripts/company-license-group-openapi').companyLicenseGroupOpenApi();
 expect(paths['/api/licenses/company/groups/{id}/sync'].post.requestBody.content['application/json'].schema.required).toEqual(['groupRevision','cursor','reason','confirm']);
 expect(components.schemas.CompanyLicenseGroupSync.properties.results.maxItems).toBe(25);
 expect(paths['/api/licenses/company/groups/{id}/unlink'].post.parameters.map(row=>row.name)).toEqual(['id','Idempotency-Key','If-Match']);
});
