'use strict';
jest.mock('../db',()=>({isAvailable:()=>true,pool:{end:jest.fn()}}));
jest.mock('../middleware/oidcAuth',()=>({oidcAuth:()=>(req,_res,next)=>{req.user={sub:'original',actor_type:'user'};next();}}));
jest.mock('../DeviceOuAuthority',()=>({DeviceOuAuthority:jest.fn()}));
jest.mock('@opendirectory/grpc-event-bus',()=>({EventBusClient:jest.fn(()=>({connect:jest.fn(),publish:jest.fn(async()=>{})}))}),{virtual:true});
const {DeviceOuAuthority}=require('../DeviceOuAuthority');
const units=jest.fn(),unitsScoped=jest.fn(),resolve=jest.fn(),resolveScoped=jest.fn();
DeviceOuAuthority.mockImplementation(()=>({units,unitsScoped,resolve,resolveScoped}));
const expressApp=require('../index'),request=require('supertest');
const {listenLoopback,closeServer}=require('../../../../../scripts/lib/loopback-test-server.cjs');
let app;beforeAll(async()=>{app=await listenLoopback(expressApp);});afterAll(()=>closeServer(app));
const route='/api/identity/device-organizational-units';
beforeEach(()=>{for(const mock of [units,unitsScoped,resolve,resolveScoped])mock.mockReset().mockResolvedValue({confirmed:true});});
for(const method of ['get','post'])test(method+' preserves genuine legacy routing and selects scoped authority only by explicit private version',async()=>{
 let response=await request(app)[method](route).set('Authorization','Bearer original');expect(response.status).toBe(200);
 const legacy=method==='get'?units:resolve,scoped=method==='get'?unitsScoped:resolveScoped;expect(legacy).toHaveBeenCalledTimes(1);expect(scoped).not.toHaveBeenCalled();
 response=await request(app)[method](route).set('Authorization','Bearer original').set('X-OD-Device-Scope-Protocol','1');expect(response.status).toBe(200);expect(response.headers['cache-control']).toBe('no-store');expect(scoped).toHaveBeenCalledWith({}, {sub:'original',actor_type:'user'},'Bearer original');expect(legacy).toHaveBeenCalledTimes(1);
});
for(const method of ['get','post'])test.each(['2','true','1, 1'])(method+' rejects unknown private version %s before selecting any authority',async protocol=>{
 const response=await request(app)[method](route).set('X-OD-Device-Scope-Protocol',protocol);expect(response.status).toBe(400);for(const mock of [units,unitsScoped,resolve,resolveScoped])expect(mock).not.toHaveBeenCalled();
});
test('private scoped selection preserves the original body and refuses API key or query substitution',async()=>{
 const body={ouId:null,device:{deviceId:'11111111-1111-4111-8111-111111111111',deviceRevision:'1',revision:'0',ou:null}};
 expect((await request(app).post(route).set('Authorization','Bearer original').set('X-OD-Device-Scope-Protocol','1').send(body)).status).toBe(200);
 expect(resolveScoped).toHaveBeenCalledWith(body,{sub:'original',actor_type:'user'},'Bearer original');resolveScoped.mockClear();
 expect((await request(app).post(route).query({tenantId:'foreign'}).set('X-OD-Device-Scope-Protocol','1').send(body)).status).toBe(400);
 expect((await request(app).get(route).set('X-API-Key','')).status).toBe(400);expect(resolveScoped).not.toHaveBeenCalled();expect(units).not.toHaveBeenCalled();
});
