import {api}from'../lib/api';
import {ScopeEligibility,ScopeActivation,scopeActivations}from'../lib/licenseScopeActivations';
const licenseId='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const eligibilityId='33333333-3333-4333-8333-333333333333';const reviewer='44444444-4444-4444-8444-444444444444';const requestId='55555555-5555-4555-8555-555555555555';const grantId='66666666-6666-4666-8666-666666666666';
const eligible=(extra={}):ScopeEligibility=>({id:eligibilityId,licenseId,userId,duty:'allocator',version:'1',maxDurationSeconds:300,reviewerUserIds:[reviewer],createdAt:'2026-10-18T10:00:00.000Z',expiresAt:'2026-10-18T11:00:00.000Z',revokedAt:null,state:'active',...extra});
const request=(extra={}):ScopeActivation=>({id:requestId,eligibilityId,licenseId,userId,duty:'allocator',version:'1',status:'pending',requestedDurationSeconds:60,requestedAt:'2026-10-18T10:01:00.000Z',approvalDeadline:'2026-10-18T10:16:00.000Z',reviewedAt:null,activatedAt:null,grantId:null,grantExpiresAt:null,canReview:false,canActivate:false,canCancel:true,canDeactivate:false,...extra});
const approved=()=>request({version:'2',status:'approved',reviewedAt:'2026-10-18T10:02:00.000Z',canActivate:true});
const active=()=>request({...approved(),version:'3',status:'activated',activatedAt:'2026-10-18T10:03:00.000Z',grantId,grantExpiresAt:'2026-10-18T10:04:00.000Z',canActivate:false,canCancel:false,canDeactivate:true});
const receipt=(value:ScopeActivation,status=200)=>({status,data:value,headers:{etag:`"od-license-scope-activation:${value.id}:${value.version}"`}});
beforeEach(()=>jest.clearAllMocks());
test('a request confirms only its captured eligibility and never grants an active scope',async()=>{
 (api.post as jest.Mock).mockResolvedValue(receipt(request(),201));expect((await scopeActivations.request(eligible(),60,'Independent actual activation request')).status).toBe('pending');
 expect(api.post).toHaveBeenCalledWith('/api/licenses/delegations/pim/eligibilities/'+eligibilityId+'/requests',{durationSeconds:60,reason:'Independent actual activation request',confirm:true},{headers:{'If-Match':`"od-license-scope-eligibility:${eligibilityId}:1"`}});
});
test.each([request({licenseId:userId}),request({userId:licenseId}),request({eligibilityId:reviewer}),request({status:'approved',reviewedAt:'2026-10-18T10:02:00.000Z'}),request({requestedDurationSeconds:61}),request({version:'2'})])('request receipts cannot retarget, silently approve or change the requested duration: %j',async value=>{
 (api.post as jest.Mock).mockResolvedValue(receipt(value,201));await expect(scopeActivations.request(eligible(),60,'Exact independent request')).rejects.toThrow();
});
test('activation and deactivation are separately versioned and preserve their original approval and resource',async()=>{
 (api.post as jest.Mock).mockResolvedValueOnce(receipt(active())).mockResolvedValueOnce(receipt({...active(),version:'4',status:'deactivated',canDeactivate:false}));
 const value=await scopeActivations.transition(approved(),'activate','Owner confirms actual scope activation');await scopeActivations.transition(value,'deactivate','Retire this exact administrative activation');
 expect((api.post as jest.Mock).mock.calls[0][2].headers['If-Match']).toBe(`"od-license-scope-activation:${requestId}:2"`);
});
test.each([{...receipt(active()),status:202},{...receipt(active()),headers:{etag:'wrong'}},receipt({...active(),licenseId:userId}),receipt({...active(),reviewedAt:'2026-10-18T10:03:00.000Z'}),receipt({...active(),version:'4'}),receipt({...active(),canActivate:true})])('ambiguous activation evidence is rejected: %j',async result=>{
 (api.post as jest.Mock).mockResolvedValue(result);await expect(scopeActivations.transition(approved(),'activate','Exact current activation')).rejects.toThrow();
});
test('an assigned queue is bound to the current canonical reviewer and cannot expose owner actions',async()=>{
 const value=request({canReview:true,canCancel:false});(api.get as jest.Mock).mockResolvedValueOnce({status:200,data:{userId:reviewer,requests:[value],truncated:false}}).mockResolvedValueOnce({status:200,data:{userId,requests:[value],truncated:false}});
 expect((await scopeActivations.assigned(reviewer)).requests[0].canReview).toBe(true);await expect(scopeActivations.assigned(reviewer)).rejects.toThrow();
});
test('own queues reject another beneficiary and duplicate resource identities',async()=>{
 (api.get as jest.Mock).mockResolvedValueOnce({status:200,data:{userId,eligibilities:[eligible({userId:reviewer})],requests:[],truncated:false}}).mockResolvedValueOnce({status:200,data:{userId,eligibilities:[eligible(),eligible()],requests:[],truncated:false}});
 await expect(scopeActivations.self(userId)).rejects.toThrow();await expect(scopeActivations.self(userId)).rejects.toThrow();
});
test('eligibility creation requires exact independent reviewer identity and the conditional returned version',async()=>{
 const body={licenseId,userId,duty:'allocator',durationSeconds:3600,maxDurationSeconds:300,reviewerUserIds:[reviewer],reason:'Independent explicit scope eligibility',confirm:true as const};
 (api.post as jest.Mock).mockResolvedValue({status:201,data:eligible(),headers:{etag:`"od-license-scope-eligibility:${eligibilityId}:1"`}});expect(await scopeActivations.create(body)).toEqual(eligible());
 (api.post as jest.Mock).mockResolvedValue({status:201,data:eligible({reviewerUserIds:[licenseId]}),headers:{etag:`"od-license-scope-eligibility:${eligibilityId}:1"`}});await expect(scopeActivations.create(body)).rejects.toThrow();
});
test('eligibility revocation cannot silently extend the administrative lifetime',async()=>{
 const row=eligible({version:'2',revokedAt:'2026-10-18T10:30:00.000Z',state:'revoked',expiresAt:'2026-10-18T12:00:00.000Z'});(api.post as jest.Mock).mockResolvedValue({status:200,data:row,headers:{etag:`"od-license-scope-eligibility:${eligibilityId}:2"`}});
 await expect(scopeActivations.revoke(eligible(),'Retire only the original eligibility')).rejects.toThrow();
});
test('noncanonical resources cannot start a lookup',async()=>{await expect(scopeActivations.list('alias')).rejects.toThrow();expect(api.get).not.toHaveBeenCalled();});
