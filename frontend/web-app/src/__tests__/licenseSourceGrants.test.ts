import{api}from'../lib/api';
import{licenseSourceGrants,LicenseSourceGrant}from'../lib/licenseSourceGrants';
const mock=api as jest.Mocked<typeof api>;const groupId='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const id='33333333-3333-4333-8333-333333333333';
const grant:LicenseSourceGrant={id,groupId,issuer:'https://source.test',clientId:'group-worker',clientRevision:'2',version:'1',createdBy:userId,createdAt:'2026-10-18T00:00:00.000Z',expiresAt:'2026-10-19T00:00:00.000Z',revokedAt:null,state:'configured'};
const binding={schemaVersion:1 as const,clientId:grant.clientId,revision:'2',enabled:true,canReadGroupSources:true};const tag=(row:LicenseSourceGrant)=>`"od-group-source:${row.id}:${row.version}"`;
const result=(data:unknown,status=200,etag?:string)=>({data,status,headers:etag?{etag}:{}} as any);
beforeEach(()=>jest.clearAllMocks());
test('known-group consent reads are exact, bounded and do not fetch general directory profiles',async()=>{
 mock.get=jest.fn().mockResolvedValue(result({groupId,grants:[grant],truncated:false}));expect((await licenseSourceGrants.list(groupId)).grants).toEqual([grant]);expect(mock.get).toHaveBeenCalledWith('/api/identity/license-sources/groups/'+groupId);
});
test.each([null,{}, {...grant,version:'0'},{...grant,clientRevision:'9223372036854775808'},{...grant,createdBy:'alias'}, {...grant,groupId:userId}, {...grant,expiresAt:grant.createdAt}, {...grant,revokedAt:grant.createdAt}, {...grant,extra:true}])('malformed or retargeted consent evidence cannot be presented as a known scope: %j',async value=>{
 mock.get=jest.fn().mockResolvedValue(result({groupId,grants:[value],truncated:false}));await expect(licenseSourceGrants.list(groupId)).rejects.toThrow();
});
test.each([{...binding,enabled:false},{...binding,clientId:'other'},{...binding,revision:2},{...binding,secret:'never-render'},{...binding,schemaVersion:2}])('client discovery cannot silently broaden a read grant: %j',async value=>{
 mock.get=jest.fn().mockResolvedValue(result(value));await expect(licenseSourceGrants.client(binding.clientId)).rejects.toThrow();
});
test('creation sends the independently loaded exact client-generation precondition and confirms the canonical actor and deadline',async()=>{
 const body={groupId,clientId:grant.clientId,expiresAt:grant.expiresAt,reason:'Actual narrow source grant confirmation',acknowledgeReadScope:true as const};mock.post=jest.fn().mockResolvedValue(result(grant,201,tag(grant)));
 expect(await licenseSourceGrants.create(body,binding,userId)).toEqual(grant);expect(mock.post).toHaveBeenCalledWith('/api/identity/license-sources',{...body,expectedClientRevision:'2'});
});
test.each([{...grant,clientRevision:'3'},{...grant,createdBy:id},{...grant,expiresAt:'2026-10-20T00:00:00.000Z'},{...grant,version:'2'},{...grant,state:'revoked',revokedAt:grant.createdAt}])('an uncertain or mismatched creation receipt is never called success: %j',async value=>{
 mock.post=jest.fn().mockResolvedValue(result(value,201,tag(value as LicenseSourceGrant)));await expect(licenseSourceGrants.create({groupId,clientId:grant.clientId,expiresAt:grant.expiresAt,reason:'Actual exact source consent evidence',acknowledgeReadScope:true},binding,userId)).rejects.toThrow();expect(mock.post).toHaveBeenCalledTimes(1);
});
test('withdrawal requires the captured exact consent version and cannot change its original scope',async()=>{
 const revoked={...grant,version:'2',revokedAt:'2026-10-18T01:00:00.000Z',state:'revoked' as const};mock.post=jest.fn().mockResolvedValue(result(revoked,200,tag(revoked)));expect(await licenseSourceGrants.revoke(grant,'Explicit narrowly scoped withdrawal')).toEqual(revoked);
 expect(mock.post).toHaveBeenCalledWith('/api/identity/license-sources/'+id+'/revoke',{reason:'Explicit narrowly scoped withdrawal',acknowledgeReadScope:true},{headers:{'If-Match':tag(grant)}});
});
test.each([{version:'3'},{groupId:userId},{clientRevision:'3'},{expiresAt:'2026-10-20T00:00:00.000Z'},{issuer:'https://other.test'}])('a stale or retargeted withdrawal cannot pass receipt validation: %j',async change=>{
 const value={...grant,version:'2',revokedAt:'2026-10-18T01:00:00.000Z',state:'revoked' as const,...change};mock.post=jest.fn().mockResolvedValue(result(value,200,tag(value as LicenseSourceGrant)));await expect(licenseSourceGrants.revoke(grant,'Exact source withdrawal evidence')).rejects.toThrow();expect(mock.post).toHaveBeenCalledTimes(1);
});
