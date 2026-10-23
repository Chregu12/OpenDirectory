import { api } from '@/lib/api';import { companyGroupRules } from '@/lib/companyGroupRules';
jest.mock('@/lib/api',()=>({api:{get:jest.fn(),put:jest.fn(),post:jest.fn()}}));
const id=(n:number)=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');const base={schemaVersion:1,companyGroupRuleProtocol:1,actorUserId:id(1),tenantId:id(2)};
const draft={dynamic:{all:[{attribute:'department' as const,operator:'equals' as const,value:'Engineering'}]},childGroupIds:[],excludedUserIds:[]};
const rule={groupId:id(3),tenantId:id(2),revision:'1',enabled:true,draft,createdBy:id(1),createdAt:'2026-10-23T00:00:00.000Z',updatedAt:'2026-10-23T00:00:00.000Z'};
const page:any={...base,groupId:id(3),rule,etag:`"group-rule-${id(3)}-1"`,executionMode:'manual'};
beforeEach(()=>{jest.resetAllMocks();Object.defineProperty(crypto,'randomUUID',{configurable:true,value:()=>id(99)});});
test('owner get binds actual group, tenant and captured revision without a write',async()=>{
 (api.get as jest.Mock).mockResolvedValue({status:200,data:page});expect((await companyGroupRules.get(id(3),id(1))).rule.revision).toBe('1');expect(api.put).not.toHaveBeenCalled();
 await expect(companyGroupRules.get(id(3),id(8))).rejects.toThrow();(api.get as jest.Mock).mockResolvedValue({status:200,data:{...page,etag:'invented'}});await expect(companyGroupRules.get(id(3),id(1))).rejects.toThrow();
});
test('configuration uses a captured version and exact confirmation without claiming member execution',async()=>{
 (api.put as jest.Mock).mockResolvedValue({status:200,data:{...base,outcome:'applied',rule:{...rule,revision:'2'}}});await companyGroupRules.save(page,draft,true,'Explicit actual group configuration');
 expect(api.put).toHaveBeenCalledWith('/api/groups/'+id(3)+'/rule',{draft,enabled:true,reason:'Explicit actual group configuration',confirm:true},{headers:{'If-Match':page.etag,'Idempotency-Key':id(99)}});
});
test('reconciliation verifies the complete ordered captured target page and preserves waiting reviews',async()=>{
 const preview:any={...base,groupId:id(3),ruleRevision:'1',observation:'a'.repeat(64),desired:[{userId:id(4),eligibilityRevision:'1'}],existing:[]};
 (api.post as jest.Mock).mockResolvedValue({status:200,data:{...base,groupId:id(3),ruleRevision:'1',observation:preview.observation,results:[{userId:id(4),status:'awaiting-review',code:null}],nextCursor:null,hasBlocked:false}});
 expect((await companyGroupRules.sync(preview,'Confirm actual reviewed membership'))[0].status).toBe('awaiting-review');
 (api.post as jest.Mock).mockResolvedValue({status:200,data:{...base,groupId:id(3),ruleRevision:'1',observation:preview.observation,results:[],nextCursor:null,hasBlocked:false}});await expect(companyGroupRules.sync(preview,'Confirm actual reviewed membership')).rejects.toThrow();
});
test('history distinguishes an original app grant from a missing or substituted human actor',async()=>{
 const event={id:id(10),kind:'membership',action:'member-add',userId:id(4),membershipId:id(5),ruleRevision:'1',actorUserId:null,application:{grantId:id(6),clientId:'actual-app',clientRevision:'1'},reason:'Actual app membership event',createdAt:rule.createdAt,deliveryStatus:'pending'};
 const history={...base,groupId:id(3),page:1,limit:25,total:1,events:[event]};(api.get as jest.Mock).mockResolvedValue({status:200,data:history});expect((await companyGroupRules.history(page)).events[0].application.clientId).toBe('actual-app');
 (api.get as jest.Mock).mockResolvedValue({status:200,data:{...history,events:[{...event,application:undefined}]}});await expect(companyGroupRules.history(page)).rejects.toThrow();
 (api.get as jest.Mock).mockResolvedValue({status:200,data:{...history,events:[{...event,actorUserId:id(1)}]}});await expect(companyGroupRules.history(page)).rejects.toThrow();
});

test('preview requires explicit effective state and a finite ISO source deadline without inventing an inactive grant',async()=>{
 const preview={...base,groupId:id(3),groupName:'Actual source',groupRevision:'9007199254740993',ruleRevision:'1',enabled:true,observation:'a'.repeat(64),executionMode:'manual',desired:[],existing:[{userId:id(4),membershipId:id(5),managed:true,effective:false,validUntil:null}],additions:0};
 (api.get as jest.Mock).mockResolvedValue({status:200,data:preview});expect((await companyGroupRules.preview(page)).existing[0].effective).toBe(false);
 for(const replacement of [{effective:undefined},{effective:'false'},{validUntil:'infinity'},{validUntil:rule.createdAt}]){(api.get as jest.Mock).mockResolvedValue({status:200,data:{...preview,existing:[{...preview.existing[0],...replacement}]}});await expect(companyGroupRules.preview(page)).rejects.toThrow();}
});
