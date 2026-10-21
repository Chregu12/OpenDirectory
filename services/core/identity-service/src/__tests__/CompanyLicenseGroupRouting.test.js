'use strict';
const {randomUUID}=require('node:crypto');
jest.mock('../db',()=>({isAvailable:()=>true,pool:{end:jest.fn()}}));
jest.mock('../middleware/oidcAuth',()=>({oidcAuth:()=>(req,_res,next)=>{req.user={sub:'owner',iss:'https://identity.test',actor_type:req.headers['x-test-actor']||'user',roles:[]};next();}}));
jest.mock('../CompanyLicenseAuthority',()=>({CompanyLicenseAuthority:jest.fn()}));
jest.mock('../SnapshotBoundary',()=>({SnapshotBoundary:jest.fn()}));
jest.mock('../GroupSnapshotStore',()=>({GroupSnapshotStore:jest.fn()}));
jest.mock('@opendirectory/grpc-event-bus',()=>({EventBusClient:jest.fn(()=>({connect:jest.fn(),publish:jest.fn(async()=>{})}))}),{virtual:true});
const read=jest.fn();const snapshot=jest.fn();const scoped=jest.fn(()=>({}));
require('../CompanyLicenseAuthority').CompanyLicenseAuthority.mockImplementation(()=>({read}));
require('../SnapshotBoundary').SnapshotBoundary.mockImplementation(()=>({scoped}));
require('../GroupSnapshotStore').GroupSnapshotStore.mockImplementation(()=>({snapshot}));
const app=require('../index');const request=require('supertest');const id=randomUUID();const route='/api/identity/company-license-groups/'+id+'/snapshot';
beforeEach(()=>{jest.clearAllMocks();read.mockResolvedValue({});snapshot.mockResolvedValue({groupId:id});});
test('original roleless human passes the actual own-group boundary and is checked again after reading',async()=>{
 const result=await request(app).get(route).set('Authorization','Bearer original');expect(result.status).toBe(200);expect(result.headers['cache-control']).toBe('no-store');
 expect(read).toHaveBeenCalledTimes(2);expect(read).toHaveBeenCalledWith(expect.objectContaining({actor_type:'user',roles:[]}), 'Bearer original');
 expect(scoped).toHaveBeenCalledWith(expect.objectContaining({id,kind:'group',permission:'groups.read',companyGroup:true,authorization:'Bearer original',write:true}));
});
test.each(['application','workload'])('%s never reaches the private company source',async actor=>{expect((await request(app).get(route).set('X-Test-Actor',actor)).status).toBe(403);expect(read).not.toHaveBeenCalled();});
test('query, body and even an empty API-key selector fail before source data',async()=>{
 for(const action of [req=>req.query({tenantId:id}),req=>req.send({}),req=>req.send([]),req=>req.set('X-API-Key','')])expect((await action(request(app).get(route))).status).toBe(400);
 expect(read).not.toHaveBeenCalled();expect(snapshot).not.toHaveBeenCalled();
});
test.each(['head','post','put','delete'])('%s has no implicit source route',async method=>{expect((await request(app)[method](route)).status).toBe(404);expect(read).not.toHaveBeenCalled();});
test('a late withdrawal never returns the computed snapshot',async()=>{read.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('withdrawn'),{status:401}));expect((await request(app).get(route)).status).toBe(401);});
