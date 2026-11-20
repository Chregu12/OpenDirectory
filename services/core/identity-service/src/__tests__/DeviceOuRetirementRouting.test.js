'use strict';
jest.mock('../db',()=>({isAvailable:()=>true,pool:{end:jest.fn()}}));
jest.mock('../middleware/oidcAuth',()=>({oidcAuth:()=>(req,_res,next)=>{req.user={actor_type:'user',sub:'original'};next();}}));
jest.mock('../DeviceOuRetirementAuthority',()=>({DeviceOuRetirementAuthority:jest.fn()}));
jest.mock('@opendirectory/grpc-event-bus',()=>({EventBusClient:jest.fn(()=>({connect:jest.fn(),publish:jest.fn(async()=>{})}))}),{virtual:true});
const {DeviceOuRetirementAuthority}=require('../DeviceOuRetirementAuthority');
const read=jest.fn(),check=jest.fn();DeviceOuRetirementAuthority.mockImplementation(()=>({read,check}));
const expressApp=require('../index'),request=require('supertest');const {listenLoopback,closeServer}=require('../../../../../scripts/lib/loopback-test-server.cjs');let app;
beforeAll(async()=>{app=await listenLoopback(expressApp);});afterAll(()=>closeServer(app));beforeEach(()=>{read.mockReset().mockResolvedValue({actual:true});check.mockReset().mockResolvedValue({actual:true});});
const root='/api/identity/device-ou-retirement',header='X-OD-Device-Ou-Retirement-Protocol';
for(const suffix of ['','/check'])test('only the explicit retirement purpose reaches '+(suffix||'initial source'),async()=>{
 const body={action:'cancel',ouId:'11111111-1111-4111-8111-111111111111',generation:'1',revision:'2',fenceRevision:'4'};
 const result=await request(app).post(root+suffix).set(header,'1').set('Authorization','Bearer original').send(body);expect(result.status).toBe(200);expect(result.headers['cache-control']).toBe('no-store');expect(suffix?check:read).toHaveBeenCalledWith(body,{actor_type:'user',sub:'original'},'Bearer original');expect(suffix?read:check).not.toHaveBeenCalled();
});
for(const suffix of ['','/check'])test.each([null,'2','true','1, 1'])('private '+suffix+' rejects unknown/missing version %s',async value=>{
 let pending=request(app).post(root+suffix);if(value!==null)pending=pending.set(header,value);expect((await pending.send({})).status).toBe(400);expect(read).not.toHaveBeenCalled();expect(check).not.toHaveBeenCalled();
});
test('API keys and query selectors cannot replace original source selection',async()=>{
 expect((await request(app).post(root).set(header,'1').set('X-API-Key','').send({})).status).toBe(400);expect((await request(app).post(root+'/check').set(header,'1').query({tenantId:'other'}).send({})).status).toBe(400);expect(read).not.toHaveBeenCalled();expect(check).not.toHaveBeenCalled();
});
