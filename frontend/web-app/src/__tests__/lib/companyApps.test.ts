import {api} from '@/lib/api';import {companyApps} from '@/lib/companyApps';
jest.mock('@/lib/api',()=>({api:{get:jest.fn(),post:jest.fn(),put:jest.fn(),delete:jest.fn()}}));
const id=(n:number)=>'00000000-0000-4000-8000-'+String(n).padStart(12,'0');const tenant={id:id(2),version:'1',generation:'2'};const stamp='2026-10-23T10:00:00.000Z';const principal={actorUserId:id(1),tenantId:id(2)};
const row:any={clientId:id(3),name:'Actual own app',enabled:false,version:'1',purpose:'none',tenant,createdAt:stamp,updatedAt:stamp,deletedAt:null};const envelope=(value:any)=>({schemaVersion:1,companyAppProtocol:1,actorUserId:id(1),tenant,...value});
beforeEach(()=>jest.resetAllMocks());
test('actual own pages reject foreign namespaces, duplicate records and unexpected credentials',async()=>{
 for(const change of [{clients:[row,{...row}]},{actorUserId:id(9)},{clients:[{...row,tenant:{...tenant,id:id(8)}}]},{clients:[{...row,clientSecret:'unexpected'}]}]){(api.get as jest.Mock).mockResolvedValue({status:200,data:envelope({page:1,status:'active',hasMore:false,clients:[row],...change})});await expect(companyApps.list(id(1))).rejects.toThrow();}
});
test('creation accepts exactly the original disabled new app or a confirmed replay without another secret',async()=>{
 const input={requestId:row.clientId,name:row.name,purpose:'none' as const,reason:'Create an actual own app account',confirm:true as const};(api.post as jest.Mock).mockResolvedValue({status:201,data:envelope({client:row,created:true,clientSecret:'a'.repeat(43)})});expect((await companyApps.create(input,principal)).created).toBe(true);
 (api.post as jest.Mock).mockResolvedValue({status:201,data:envelope({client:row,created:false,clientSecret:'a'.repeat(43)})});await expect(companyApps.create(input,principal)).rejects.toThrow();
});
test('updates preserve the original If-Match and reject substituted client generations',async()=>{
 const input={name:row.name,enabled:true,purpose:'none' as const,reason:'Enable the original owned app account',confirm:true as const};(api.put as jest.Mock).mockResolvedValue({status:200,data:envelope({client:{...row,enabled:true,version:'2'}})});await companyApps.update(row,input,principal);expect(api.put).toHaveBeenCalledWith('/api/clients/company/'+row.clientId,input,{headers:{'If-Match':`"od-client:${row.clientId}:1"`}});
 (api.put as jest.Mock).mockResolvedValue({status:200,data:envelope({client:{...row,enabled:true,version:'3'}})});await expect(companyApps.update(row,input,principal)).rejects.toThrow();
});
test('rotation cannot silently change purpose and deletion cannot leave an enabled account',async()=>{
 (api.post as jest.Mock).mockResolvedValue({status:200,data:envelope({client:{...row,version:'2',purpose:'company-automation'},clientSecret:'r'.repeat(43)})});await expect(companyApps.rotate(row,'Replace an original own secret',principal)).rejects.toThrow();
 (api.delete as jest.Mock).mockResolvedValue({status:200,data:envelope({client:{...row,version:'2',enabled:true,deletedAt:stamp}})});await expect(companyApps.remove(row,'Retire an original own app',principal)).rejects.toThrow();
});
