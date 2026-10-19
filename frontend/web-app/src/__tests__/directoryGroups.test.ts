import {api} from '../lib/api';
import {directoryGroups,parseGroup,groupEtag,DirectoryGroup} from '../lib/directoryGroups';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),put:jest.fn(),delete:jest.fn()}}));
const groupId='11111111-1111-4111-8111-111111111111';const userId='22222222-2222-4222-8222-222222222222';const membershipId='33333333-3333-4333-8333-333333333333';
const group:DirectoryGroup={id:groupId,name:'Actual group',members:[],revision:'2',createdAt:'2026-10-18T00:00:00Z'};
const access={subject:'actual',userId,permissions:['groups.read','groups.create','groups.update','groups.members.manage','groups.delete'],demoMode:false,directoryReadProtocol:1,directoryCreationProtocol:1,directoryGroupMutationProtocol:1};
beforeEach(()=>{jest.resetAllMocks();(api.get as jest.Mock).mockImplementation(async(url:string)=>({data:url.endsWith('/access')?access:url==='/api/groups'?{groups:[group],total:1}:group}));});
test.each([undefined,0,2,'1',true,{}])('missing or malformed group receiving protocol %j sends no mutation',async protocol=>{
 (api.get as jest.Mock).mockResolvedValue({data:{...access,directoryGroupMutationProtocol:protocol}});for(const operation of[()=>directoryGroups.update(group,{name:'Changed'}),()=>directoryGroups.remove(group),()=>directoryGroups.add(group,userId),()=>directoryGroups.removeMember(group,userId)])await expect(operation()).rejects.toThrow('Gruppenfunktion nicht bestätigt');expect(api.put).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();
});
test.each([{userId:null},{demoMode:true}])('unbound or demo principals cannot use a default tenant for group reads or writes: %j',async change=>{
 (api.get as jest.Mock).mockResolvedValue({data:{...access,...change}});await expect(directoryGroups.list()).rejects.toThrow('Gruppenfunktion nicht bestätigt');await expect(directoryGroups.create({name:'No fallback'})).rejects.toThrow('Gruppenfunktion nicht bestätigt');await expect(directoryGroups.remove(group)).rejects.toThrow('Gruppenfunktion nicht bestätigt');expect((api.get as jest.Mock).mock.calls.every(([url])=>url==='/api/identity/access')).toBe(true);expect(api.post).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();
});
test('confirmed collections use canonical groups only, retain actual empty results and never call a legacy auth or user-profile path',async()=>{
 expect((await directoryGroups.list()).groups).toEqual([group]);expect(await directoryGroups.get(groupId)).toEqual(group);expect((api.get as jest.Mock).mock.calls.every(([url])=>['/api/identity/access','/api/groups','/api/groups/'+groupId].includes(url))).toBe(true);
 (api.get as jest.Mock).mockImplementation(async(url:string)=>({data:url.endsWith('/access')?access:{groups:[],total:0}}));expect(await directoryGroups.list()).toEqual({groups:[],total:0});
});
test.each([{groups:[group],total:2},{groups:[group,group],total:2},{groups:[{...group,id:'legacy'}],total:1},{groups:[{...group,members:[userId,userId]}],total:1},{groups:[{...group,revision:'9223372036854775808'}],total:1}])('malformed or duplicate canonical groups are not normalized into invented rows: %j',async body=>{
 (api.get as jest.Mock).mockImplementation(async(url:string)=>({data:url.endsWith('/access')?access:body}));await expect(directoryGroups.list()).rejects.toThrow();
});
test('creation requires creation protocol rather than unrelated profile or mutation permission and confirms an actual empty group',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{...access,permissions:['groups.create'],directoryReadProtocol:undefined,directoryGroupMutationProtocol:undefined}});(api.post as jest.Mock).mockResolvedValue({data:group});expect(await directoryGroups.create({name:group.name})).toEqual(group);expect(api.post).toHaveBeenCalledWith('/api/groups',{name:group.name});(api.post as jest.Mock).mockResolvedValue({data:{...group,members:[userId]}});await expect(directoryGroups.create({name:group.name})).rejects.toThrow('Leere neue Gruppe');
});
test('actual conditional metadata update uses the displayed strong group version and validates requested content',async()=>{
 (api.put as jest.Mock).mockResolvedValue({data:{...group,name:'Changed',description:'Exact',revision:'3'}});expect((await directoryGroups.update(group,{name:' Changed ',description:'Exact'})).name).toBe('Changed');expect(api.put).toHaveBeenCalledWith('/api/groups/'+groupId,{name:' Changed ',description:'Exact'},{headers:{'If-Match':groupEtag(group)}});
 (api.put as jest.Mock).mockResolvedValue({data:{...group,name:'Other result',revision:'4'}});await expect(directoryGroups.update(group,{name:'Changed'})).rejects.toThrow('Gruppenfelder nicht bestätigt');
});
test.each(['1','2'])('a non-advancing receiving revision %s cannot confirm an edit',async revision=>{(api.put as jest.Mock).mockResolvedValue({data:{...group,revision}});await expect(directoryGroups.update(group,{name:group.name})).rejects.toThrow('Gruppenänderung nicht bestätigt');});
test('membership captures exact known UUID and reports actual pending first approval without claiming effective access',async()=>{
 (api.post as jest.Mock).mockResolvedValue({data:{...group,members:[userId],revision:'3',membershipReview:{required:true,membershipId,effective:false}}});const result=await directoryGroups.add(group,userId);expect(result.membershipReview?.effective).toBe(false);expect(api.post).toHaveBeenCalledWith('/api/groups/'+groupId+'/members',{userId},{headers:{'If-Match':groupEtag(group)}});
 (api.post as jest.Mock).mockResolvedValue({data:{...group,members:[userId],revision:'3',membershipReview:{required:true,membershipId,effective:'pending'}}});await expect(directoryGroups.add(group,userId)).rejects.toThrow('Gruppenprüfstatus');
});
test('member removal and whole-group deletion are distinct conditional operations and reject unconfirmed status or state',async()=>{
 const linked={...group,members:[userId]};(api.delete as jest.Mock).mockResolvedValue({data:{...group,revision:'3'},status:200});expect((await directoryGroups.removeMember(linked,userId)).members).toEqual([]);expect(api.delete).toHaveBeenCalledWith('/api/groups/'+groupId+'/members/'+userId,{headers:{'If-Match':groupEtag(linked)}});await expect(directoryGroups.remove(group)).rejects.toThrow('Gruppenlöschung nicht bestätigt');(api.delete as jest.Mock).mockResolvedValue({status:204});await directoryGroups.remove(group);expect(api.delete).toHaveBeenCalledWith('/api/groups/'+groupId,{headers:{'If-Match':groupEtag(group)}});
});
test('invalid canonical targets fail before any capability or write request, while bigint versions stay exact',async()=>{
 expect(parseGroup({...group,revision:'9007199254740993'}).revision).toBe('9007199254740993');for(const operation of[()=>directoryGroups.get('legacy'),()=>directoryGroups.add(group,'legacy'),()=>directoryGroups.remove({...group,id:'legacy'})])await expect(operation()).rejects.toThrow('kanonische');expect(api.get).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();
});
