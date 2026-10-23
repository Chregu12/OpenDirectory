'use strict';
const express=require('express');const request=require('supertest');const {randomUUID}=require('node:crypto');
jest.mock('../CompanyGroupRules',()=>({CompanyGroupRules:jest.fn()}));const methods=Object.fromEntries(['get','save','preview','sync','history'].map(key=>[key,jest.fn()]));
require('../CompanyGroupRules').CompanyGroupRules.mockImplementation(()=>methods);const {companyGroupRuleRoutes}=require('../CompanyGroupRuleRoutes');let app;const id=randomUUID();
beforeEach(()=>{jest.clearAllMocks();for(const method of Object.values(methods))method.mockResolvedValue({groupId:id,etag:'captured',rule:{groupId:id,revision:'1'}});app=express();app.use(express.json());app.use((req,_res,next)=>{req.user={sub:'actual-human'};next();});app.use('/groups/:id/rule',companyGroupRuleRoutes({}));});
test('configuration preserves the original human bearer, actual parent, ETag and idempotency key',async()=>{
 const key=randomUUID();expect((await request(app).put('/groups/'+id+'/rule').set('Authorization','Bearer original').set('If-Match','captured').set('Idempotency-Key',key).send({confirm:true})).status).toBe(200);
 expect(methods.save).toHaveBeenCalledWith(id,{confirm:true},'captured',key,{sub:'actual-human'},'Bearer original');
});
test('unknown selectors, API keys, GET bodies and unsupported methods never enter group-rule actions',async()=>{
 for(const attempt of [request(app).head('/groups/'+id+'/rule'),request(app).get('/groups/'+id+'/rule?tenantId=foreign'),request(app).get('/groups/'+id+'/rule').send({}),request(app).post('/groups/'+id+'/rule/sync').set('X-API-Key','key')])expect([400,404]).toContain((await attempt).status);
 expect(methods.get).not.toHaveBeenCalled();expect(methods.sync).not.toHaveBeenCalled();
});
test('history accepts only its explicit page selector and retains authorization errors',async()=>{
 expect((await request(app).get('/groups/'+id+'/rule/history?page=2')).status).toBe(200);expect(methods.history).toHaveBeenCalledWith(id,{page:'2'},{sub:'actual-human'},undefined);
 methods.preview.mockRejectedValueOnce({status:403,message:'Actual owner required'});expect((await request(app).get('/groups/'+id+'/rule/preview')).status).toBe(403);
});
