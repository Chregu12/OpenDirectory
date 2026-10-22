'use strict';
const express=require('express');const request=require('supertest');const {randomUUID}=require('node:crypto');
jest.mock('../CompanyAutomation',()=>({CompanyAutomation:jest.fn()}));
const methods=Object.fromEntries(['enroll','enrollment','approve','grants','revoke','enqueue','list','run','result','history','changeJob','disableSchedule'].map(name=>[name,jest.fn()]));
require('../CompanyAutomation').CompanyAutomation.mockImplementation(()=>methods);const {companyAutomationRoutes}=require('../CompanyAutomationRoutes');let app;
beforeEach(()=>{jest.clearAllMocks();for(const method of Object.values(methods))method.mockResolvedValue({schemaVersion:1});app=express();app.use(express.json());app.use((req,_res,next)=>{req.user={sub:'actual-app'};next();});app.use('/automation',companyAutomationRoutes({}));});
test('enrollment forwards the exact original bearer and body and never supplies a human alias',async()=>{const body={id:randomUUID(),name:'Worker'};const result=await request(app).post('/automation/enrollments').set('Authorization','Bearer original').send(body);expect(result.status).toBe(201);expect(methods.enroll).toHaveBeenCalledWith(body,{sub:'actual-app'},'Bearer original');});
test('worker run reports no due job as 204 and preserves returned durable errors',async()=>{methods.run.mockResolvedValueOnce(null);expect((await request(app).post('/automation/run').send({grantId:randomUUID()})).status).toBe(204);methods.run.mockRejectedValueOnce({status:403,message:'Grant revoked'});expect((await request(app).post('/automation/run').send({})).status).toBe(403);});
test('HEAD, API keys, GET bodies and write queries never enter an automation action',async()=>{
 for(const attempt of [request(app).head('/automation/grants'),request(app).get('/automation/grants').send({}),request(app).post('/automation/run').query({tenantId:randomUUID()}),request(app).post('/automation/run').set('X-API-Key','')])expect([400,404]).toContain((await attempt).status);
 expect(methods.run).not.toHaveBeenCalled();expect(methods.grants).not.toHaveBeenCalled();
});
test('job mutations demand explicit confirmation and forward the captured ETag',async()=>{const id=randomUUID();expect((await request(app).post('/automation/jobs/'+id+'/cancel').send({})).status).toBe(400);await request(app).post('/automation/jobs/'+id+'/cancel').set('If-Match','"captured"').send({confirm:true});expect(methods.changeJob).toHaveBeenCalledWith(id,'cancel','"captured"',{sub:'actual-app'},undefined);});
