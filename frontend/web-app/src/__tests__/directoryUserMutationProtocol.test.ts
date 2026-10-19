import {api} from '../lib/api';
import {directoryUsers,userEtag} from '../lib/directoryUsers';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),put:jest.fn(),delete:jest.fn()}}));
const userId='11111111-1111-4111-8111-111111111111';
const person={id:userId,username:'owned',email:'owned@test.invalid',enabled:true,revision:'2',createdAt:'2026-10-18T00:00:00Z'};
const access={subject:'original',userId,permissions:['users.update','users.delete','users.sessions.invalidate'],demoMode:false,directoryUserMutationProtocol:1};
beforeEach(()=>{jest.resetAllMocks();});
const operations=[()=>directoryUsers.update(person,{title:'Changed'}),()=>directoryUsers.remove(person),()=>directoryUsers.invalidate(userId)];
test.each([undefined,0,2,'1',true,{}])('no mutation request is sent without an exact receiver capability: %j',async protocol=>{
 (api.get as jest.Mock).mockResolvedValue({data:{...access,directoryUserMutationProtocol:protocol}});
 for(const operation of operations)await expect(operation()).rejects.toThrow('Benutzeränderung nicht bestätigt');
 expect(api.put).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();
});
test.each([{userId:null},{demoMode:true}])('unbound or demo authority cannot negotiate durable user mutation: %j',async change=>{
 (api.get as jest.Mock).mockResolvedValue({data:{...access,...change}});for(const operation of operations)await expect(operation()).rejects.toThrow('Benutzeränderung nicht bestätigt');expect(api.put).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();
});
test('confirmed edits and deletion preserve strong ETags and send no client-selected tenant',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:access});(api.put as jest.Mock).mockResolvedValue({data:{...person,title:'Changed',revision:'3'}});(api.delete as jest.Mock).mockResolvedValue({status:204});
 expect((await directoryUsers.update(person,{title:'Changed'})).revision).toBe('3');await directoryUsers.remove(person);
 expect(api.put).toHaveBeenCalledWith('/api/users/'+userId,{title:'Changed'},{headers:{'If-Match':userEtag(person)}});expect(api.delete).toHaveBeenCalledWith('/api/users/'+userId,{headers:{'If-Match':userEtag(person)}});expect(api.get).toHaveBeenCalledTimes(2);
});
test('security reset negotiates the same boundary while retaining its monotonic empty-body contract',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:access});(api.post as jest.Mock).mockResolvedValue({data:{userId,revision:'4'}});expect((await directoryUsers.invalidate(userId)).revision).toBe('4');expect(api.post).toHaveBeenCalledWith('/api/users/'+userId+'/authorization/invalidate',{});
});
test('invalid target IDs are rejected before any protocol or write request',async()=>{
 for(const operation of[()=>directoryUsers.update({...person,id:'legacy'},{title:'Changed'}),()=>directoryUsers.remove({...person,id:'legacy'}),()=>directoryUsers.invalidate('legacy')])await expect(operation()).rejects.toThrow('Verzeichnis-ID');expect(api.get).not.toHaveBeenCalled();expect(api.put).not.toHaveBeenCalled();expect(api.delete).not.toHaveBeenCalled();expect(api.post).not.toHaveBeenCalled();
});
