import {api} from '../lib/api';
import {directoryUsers} from '../lib/directoryUsers';
jest.mock('../lib/api',()=>({api:{get:jest.fn(),post:jest.fn()}}));
const userId='11111111-1111-4111-8111-111111111111';const profile={username:'new-owned',email:'new@test.invalid'};
beforeEach(()=>{jest.resetAllMocks();});
test.each([undefined,0,2,'1',true,{}])('no creation POST is sent to a missing or malformed receiver capability: %j',async protocol=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId,permissions:['users.create'],demoMode:false,directoryReadProtocol:1,directoryCreationProtocol:protocol}});
 await expect(directoryUsers.create(profile)).rejects.toThrow('Verzeichniserstellung nicht bestätigt');expect(api.post).not.toHaveBeenCalled();
});
test('an unbound demo principal cannot infer an owner for a new record',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId:null,permissions:['users.create'],demoMode:true,directoryCreationProtocol:1}});await expect(directoryUsers.create(profile)).rejects.toThrow('Verzeichniserstellung nicht bestätigt');expect(api.post).not.toHaveBeenCalled();
});
test('confirmed creation negotiates first and sends only profile fields without a client-selected tenant',async()=>{
 (api.get as jest.Mock).mockResolvedValue({data:{subject:'original',userId,permissions:['users.create'],demoMode:false,directoryCreationProtocol:1}});(api.post as jest.Mock).mockResolvedValue({data:{...profile,id:userId,enabled:false,revision:'1',createdAt:'2026-10-18T00:00:00Z'}});
 expect((await directoryUsers.create(profile)).enabled).toBe(false);expect(api.get).toHaveBeenCalledWith('/api/identity/access');expect(api.post).toHaveBeenCalledWith('/api/users',profile);
});
