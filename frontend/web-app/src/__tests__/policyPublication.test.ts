jest.mock('@/lib/api',()=>({api:{get:jest.fn(),post:jest.fn()}}));
import {api} from '@/lib/api';
import {Publication,PublicationFrame,policyPublication,publicationTag} from '@/lib/policyPublication';
const mock=api as jest.Mocked<typeof api>;
const id='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const reviewerId='33333333-3333-4333-8333-333333333333';const publicationId='44444444-4444-4444-8444-444444444444';
const row:Publication={id:publicationId,resourceKind:'policy',resourceId:id,resourceVersion:3,configurationVersion:3,configurationHash:'a'.repeat(64),requestedBy:userId,reviewerUserId:reviewerId,state:'pending',version:1,expiresAt:'2030-01-01T00:00:00.000Z',decidedBy:null,current:false};
const frame:PublicationFrame={schemaVersion:1,resourceKind:'policy',resourceId:id,resourceVersion:3,configurationVersion:3,configurationHash:row.configurationHash,frame:{resource:{id,name:'Owned actual policy'},configurationVersion:3,assignments:[],children:[]},verifiedOrigin:true,contributors:[userId],publications:[row],total:1,limit:50};
const reason='Exact publication content and targets confirmed';
beforeEach(()=>jest.resetAllMocks());
test('accepts an exact coherent persisted frame and known original actors',async()=>{mock.get.mockResolvedValue({status:200,data:frame});expect(await policyPublication.get('policy',id,3)).toEqual(frame);});
test.each([{resourceVersion:4},{configurationHash:'unknown'},{frame:{...frame.frame,configurationVersion:2}},{contributors:[userId,userId]},{publications:[row,row]},{publications:[{...row,requestedBy:reviewerId}]},{publications:[{...row,decidedBy:'alias'}]}])('rejects incoherent or invented review data: %j',async change=>{mock.get.mockResolvedValue({status:200,data:{...frame,...change}});await expect(policyPublication.get('policy',id,3)).rejects.toThrow();});
test('request captures the exact resource version, content hash, assigned reviewer and bounded lifetime, without a caller-selected actor',async()=>{
 mock.post.mockResolvedValue({status:201,data:row,headers:{etag:publicationTag(row)}});expect(await policyPublication.request(frame,reviewerId,3600,reason,userId)).toEqual(row);
 expect(mock.post).toHaveBeenCalledWith(`/api/policies/${id}/publications`,{reviewerUserId:reviewerId,validitySeconds:3600,configurationHash:frame.configurationHash,reason,acknowledgeScope:true},{headers:{'If-Match':`"od-policy:${id}:3"`}});
});
test.each([{...row,requestedBy:reviewerId},{...row,resourceVersion:2},{...row,configurationHash:'b'.repeat(64)},{...row,state:'approved'},{...row,decidedBy:reviewerId}])('a mismatched request receipt never reports success: %j',async changed=>{mock.post.mockResolvedValue({status:201,data:changed,headers:{etag:publicationTag(changed as Publication)}});await expect(policyPublication.request(frame,reviewerId,3600,reason,userId)).rejects.toThrow();expect(mock.post).toHaveBeenCalledTimes(1);});
test.each([userId,'alias'])('does not send a self/contributor or uncanonical review request: %s',async reviewer=>{await expect(policyPublication.request(frame,reviewer,3600,reason,userId)).rejects.toThrow();expect(mock.post).not.toHaveBeenCalled();});
test('decision retains request identity, scope and deadline and verifies original deciding actor and exact conditional receipt',async()=>{
 const changed:Publication={...row,state:'approved',version:2,decidedBy:reviewerId};mock.post.mockResolvedValue({status:200,data:changed,headers:{etag:publicationTag(changed)}});
 expect((await policyPublication.decide(frame,row,'approved',reason,reviewerId)).state).toBe('approved');
 expect(mock.post).toHaveBeenCalledWith(`/api/policies/${id}/publications/${row.id}/decisions`,{decision:'approved',resourceVersion:3,configurationHash:row.configurationHash,reason,acknowledgeScope:true},{headers:{'If-Match':publicationTag(row)}});
});
test.each([{version:1},{decidedBy:userId},{expiresAt:'2031-01-01T00:00:00.000Z'},{reviewerUserId:userId}])('wrong-version, actor, deadline or reviewer receipts cannot acknowledge a decision: %j',async change=>{const changed={...row,state:'approved',version:2,decidedBy:reviewerId,...change} as Publication;mock.post.mockResolvedValue({status:200,data:changed,headers:{etag:publicationTag(changed)}});await expect(policyPublication.decide(frame,row,'approved',reason,reviewerId)).rejects.toThrow();expect(mock.post).toHaveBeenCalledTimes(1);});
