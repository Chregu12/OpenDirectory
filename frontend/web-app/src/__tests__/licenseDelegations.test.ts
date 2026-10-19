import { api } from '../lib/api';
import { LicenseDelegation, licenseDelegations } from '../lib/licenseDelegations';
const licenseId='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const delegationId='33333333-3333-4333-8333-333333333333';
const row=(extra={}):LicenseDelegation=>({id:delegationId,licenseId,userId,duty:'allocator',version:'1',createdAt:'2026-10-18T10:00:00.000Z',expiresAt:'2026-10-18T11:00:00.000Z',revokedAt:null,state:'active',...extra});
const response=(data:LicenseDelegation,status=200)=>({status,headers:{etag:`"od-license-delegation:${data.id}:${data.version}"`},data});
beforeEach(()=>jest.clearAllMocks());
test('creation and conditional revocation require exact canonical resource, recipient, role and versions',async()=>{
  (api.post as jest.Mock).mockResolvedValueOnce(response(row(),201)).mockResolvedValueOnce(response(row({version:'2',revokedAt:'2026-10-18T10:30:00.000Z',state:'revoked'})));
  const body={licenseId,userId,duty:'allocator',durationSeconds:3600,reason:'Explicit bounded single-pool authority',confirm:true as const};
  const created=await licenseDelegations.create(body);await licenseDelegations.revoke(created,'Independently retire resource authority');
  expect(api.post).toHaveBeenLastCalledWith('/api/licenses/delegations/'+delegationId+'/revoke',{confirm:true,reason:'Independently retire resource authority'},{headers:{'If-Match':`"od-license-delegation:${delegationId}:1"`}});
});
test.each([row({licenseId:userId}),row({userId:licenseId}),row({duty:'approver'}),row({version:'2'}),row({state:'revoked',revokedAt:'2026-10-18T10:30:00.000Z'}),row({extra:true})])('creation rejects ambiguous or retargeted receipts: %j',async data=>{
  (api.post as jest.Mock).mockResolvedValue(response(data,201));await expect(licenseDelegations.create({licenseId,userId,duty:'allocator',durationSeconds:3600,reason:'Exact resource delegation',confirm:true})).rejects.toThrow();
});
test.each([{status:202}, {headers:{etag:'wrong'}}, {data:row({version:'9223372036854775808'})}, {data:row({expiresAt:'invalid'})}, {data:row({revokedAt:'2026-10-18T10:30:00.000Z'})}])('uncertain receipt status, tag and state fail closed: %j',async change=>{
  (api.post as jest.Mock).mockResolvedValue({...response(row(),201),...change});await expect(licenseDelegations.create({licenseId,userId,duty:'allocator',durationSeconds:3600,reason:'Exact resource delegation',confirm:true})).rejects.toThrow();
});
test.each([{userId:licenseId,delegations:[row()],truncated:false},{userId,delegations:[row(),row()],truncated:false},{userId,delegations:[row({state:'expired'})],truncated:false}])('own leases are canonical, active and unique: %j',async data=>{
  (api.get as jest.Mock).mockResolvedValue({status:200,data});await expect(licenseDelegations.self(userId)).rejects.toThrow();
});
test.each([{hasMore:true,nextAfter:delegationId},{hasMore:false,nextAfter:delegationId}])('bounded pool lists reject contradictory cursors: %j',async cursor=>{
  (api.get as jest.Mock).mockResolvedValue({status:200,data:{licenseId,delegations:[row()],...cursor}});await expect(licenseDelegations.list(licenseId)).rejects.toThrow();
});
test('pool reads reject global/private catalog material rather than exposing an expanded response',async()=>{
  const data={id:licenseId,name:'Scoped pool',vendor:null,licenseType:'per_user',totalSeats:2,usedSeats:1};
  (api.get as jest.Mock).mockResolvedValueOnce({status:200,data}).mockResolvedValueOnce({status:200,data:{...data,notes:'private'}});
  expect(await licenseDelegations.pool(licenseId)).toEqual(data);await expect(licenseDelegations.pool(licenseId)).rejects.toThrow();
});
test('all allocation calls use only the scoped namespace and require an exact local-only receipt',async()=>{
  const data={licenseId,assigneeType:'user',assigneeId:userId,localOnly:true,status:'assigned'};
  (api.post as jest.Mock).mockResolvedValueOnce({status:201,data}).mockResolvedValueOnce({status:201,data:{...data,licenseId:userId}});
  expect(await licenseDelegations.assign(licenseId,'user',userId,'Confirm actual single pool allocation')).toBe('assigned');
  expect(api.post).toHaveBeenCalledWith('/api/licenses/scoped/pools/'+licenseId+'/assign',{assigneeType:'user',assigneeId:userId,expiresAt:null,reason:'Confirm actual single pool allocation',confirm:true});
  await expect(licenseDelegations.assign(licenseId,'user',userId,'Do not claim another pool')).rejects.toThrow();
});
test('capacity-blocked group configuration remains distinct from a successful user allocation',async()=>{
  const data={licenseId,assigneeType:'group',assigneeId:userId,localOnly:true,status:'capacity-blocked'};(api.post as jest.Mock).mockResolvedValue({status:201,data});
  expect(await licenseDelegations.assign(licenseId,'group',userId,'Review actual group capacity')).toBe('capacity-blocked');
  (api.post as jest.Mock).mockResolvedValue({status:201,data:{...data,assigneeType:'user'}});await expect(licenseDelegations.assign(licenseId,'user',userId,'Do not claim an impossible state')).rejects.toThrow();
});
test('invalid canonical input cannot start a scoped request',async()=>{await expect(licenseDelegations.pool('alias')).rejects.toThrow();expect(api.get).not.toHaveBeenCalled();});
test('a legacy pending device does not fabricate a canonical human target or prevent reading valid pending requests',async()=>{
  const request={id:delegationId,assigneeType:'device',assigneeId:'legacy-device',requesterId:userId,identityBound:true,justification:null,requestedAt:row().createdAt};
  (api.get as jest.Mock).mockResolvedValueOnce({status:200,data:{licenseId,requests:[request],hasMore:false,nextAfter:null}}).mockResolvedValueOnce({status:200,data:{licenseId,requests:[{...request,assigneeType:'user'}],hasMore:false,nextAfter:null}});
  expect((await licenseDelegations.requests(licenseId)).requests).toEqual([request]);await expect(licenseDelegations.requests(licenseId)).rejects.toThrow();
});
test.each([{id:'alias'},{licenseId:userId}])('scoped source lists reject invalid identity or a foreign pool: %j',async change=>{
  const grant={id:delegationId,licenseId,kind:'direct',recipientId:userId,version:'1',origin:'allocated',createdAt:row().createdAt,expiresAt:null,state:'active',sourceUsers:1,...change};
  (api.get as jest.Mock).mockResolvedValue({status:200,data:{grants:[grant],hasMore:false,nextAfter:null}});await expect(licenseDelegations.grants(licenseId)).rejects.toThrow();
});
test('a denied request cannot report a successful allocation',async()=>{
  const request={id:delegationId,assigneeType:'user',assigneeId:userId,requesterId:userId,identityBound:true,justification:null,requestedAt:row().createdAt};
  (api.post as jest.Mock).mockResolvedValue({status:200,data:{id:delegationId,licenseId,status:'denied',localOnly:true,allocationStatus:'active'}});await expect(licenseDelegations.review(licenseId,request,'denied','Independent denied allocation')).rejects.toThrow();
});
test('an approved group receipt preserves capacity-blocked meaning',async()=>{
  const request={id:delegationId,assigneeType:'group',assigneeId:userId,requesterId:userId,identityBound:true,justification:null,requestedAt:row().createdAt};
  (api.post as jest.Mock).mockResolvedValue({status:200,data:{id:delegationId,licenseId,status:'approved',localOnly:true,allocationStatus:'capacity-blocked'}});expect(await licenseDelegations.review(licenseId,request,'approved','Independent bounded group approval')).toBe('capacity-blocked');
});
