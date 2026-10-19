import { api } from '../lib/api';
import { directoryUsers } from '../lib/directoryUsers';
import { directoryRoles } from '../lib/directoryRoles';

jest.mock('../lib/api',()=>({api:{get:jest.fn()}}));
const userId='11111111-1111-4111-8111-111111111111';
const profile={id:userId,username:'owned',email:'owned@test.invalid',enabled:true,revision:'1',createdAt:'2026-10-18T00:00:00Z'};
beforeEach(()=>{jest.resetAllMocks();});
test.each([undefined,0,2,'1',true,{}])('no profile request is sent to a down-level or malformed receiver protocol: %j',async protocol=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId,permissions:['users.read'],demoMode:false,directoryReadProtocol:protocol}});
 await expect(directoryUsers.list()).rejects.toThrow('Mandantengebundene');expect(api.get).toHaveBeenCalledTimes(1);expect(api.get).toHaveBeenCalledWith('/api/identity/access');
});
test('an unbound demo principal cannot infer a company merely from a receiver capability',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId:null,permissions:['users.read'],demoMode:true,directoryReadProtocol:1}});
 await expect(directoryUsers.get(userId)).rejects.toThrow('Mandantengebundene');expect(api.get).toHaveBeenCalledTimes(1);
});
test('profile list and detail negotiate the original receiver before reading without adding a caller tenant selector',async()=>{
 (api.get as jest.Mock).mockImplementation(async(url:string)=>({data:url.endsWith('/access')?{subject:'original',userId,permissions:['users.read'],demoMode:false,directoryReadProtocol:1}:url==='/api/users'?{users:[profile],total:1,page:1,limit:25}:profile}));
 expect((await directoryUsers.list()).users[0].id).toBe(userId);expect((await directoryUsers.get(userId)).id).toBe(userId);
 expect((api.get as jest.Mock).mock.calls.map(call=>call[0])).toEqual(['/api/identity/access','/api/users','/api/identity/access','/api/users/'+userId]);
});
test('role history does not send a target request to a receiver without tenant-bound read capability',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId,permissions:['identities.roles.read'],demoMode:false}});
 await expect(directoryRoles.list(userId)).rejects.toThrow('Mandantengebundene');expect(api.get).toHaveBeenCalledTimes(1);expect(api.get).toHaveBeenCalledWith('/api/identity/access');
});
test('confirmed role history uses the same negotiated original receiver without requiring profile permission',async()=>{
 (api.get as jest.Mock).mockImplementation(async(url:string)=>({data:url.endsWith('/access')?{subject:'original',userId,permissions:['identities.roles.read'],demoMode:false,directoryReadProtocol:1}:{userId,assignments:[],truncated:false}}));
 expect(await directoryRoles.list(userId)).toEqual({userId,assignments:[],truncated:false});expect((api.get as jest.Mock).mock.calls.map(call=>call[0])).toEqual(['/api/identity/access','/api/users/'+userId+'/roles']);
});
test('a malformed profile identifier is rejected before even negotiating receiver metadata',async()=>{
 await expect(directoryUsers.get('legacy-user')).rejects.toThrow('Verzeichnis-ID');expect(api.get).not.toHaveBeenCalled();
});
