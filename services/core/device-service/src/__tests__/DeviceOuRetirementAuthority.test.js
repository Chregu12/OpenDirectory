'use strict';
const {randomUUID}=require('node:crypto');
const {DeviceOuRetirementAuthority}=require('../DeviceOuRetirementAuthority');
let user,selected,source,fetchImpl,client;
beforeEach(()=>{
 const now=Math.floor(Date.now()/1000),actor=randomUUID();user={actor_type:'user',iss:'https://retirement.test',sub:'original',jti:randomUUID(),exp:now+900,auth_time:now,identity_authorization:{userId:actor,revision:'1',linkRevision:'1',rolesRevision:'a'.repeat(64)},amr:['pwd','otp'],mfa_authorization:{schemaVersion:1,userId:actor,revision:'1',authTime:now,methods:['pwd','otp']}};
 selected={action:'cancel',ouId:randomUUID(),generation:'9007199254740993',revision:'2',fenceRevision:'4'};
 source={schemaVersion:1,deviceOuRetirementProtocol:1,issuer:user.iss,subject:user.sub,tokenId:user.jti,expiresAt:user.exp,context:{...user.identity_authorization},tenant:{id:randomUUID(),version:'1',generation:'1'},actorUserId:actor,permissions:['ous.delete'],validUntil:now+90,action:'cancel',target:{id:selected.ouId,generation:selected.generation,revision:'2'},fenceRevision:'4',protected:true,delegation:null};
 fetchImpl=jest.fn(async()=>Response.json(source));client=new DeviceOuRetirementAuthority({endpoint:'https://identity.test/api/identity/device-ou-retirement',fetchImpl});
});
afterEach(()=>jest.useRealTimers());
test('initial cancellation and final check have distinct private routes and retain only original human authorization',async()=>{
 await expect(client.read('Bearer original',user,selected)).resolves.toEqual(source);await expect(client.check('Bearer original',user,selected)).resolves.toEqual(source);
 expect(String(fetchImpl.mock.calls[0][0])).toBe('https://identity.test/api/identity/device-ou-retirement');expect(String(fetchImpl.mock.calls[1][0])).toBe('https://identity.test/api/identity/device-ou-retirement/check');
 expect(fetchImpl.mock.calls[0][1]).toMatchObject({method:'POST',body:JSON.stringify(selected),headers:{Authorization:'Bearer original',Accept:'application/json','Content-Type':'application/json','X-OD-Device-Ou-Retirement-Protocol':'1'},redirect:'error',cache:'no-store'});
 expect(fetchImpl.mock.calls[0][1].signal.aborted).toBe(true);
});
test.each(['actor','token','OU generation','OU revision','fence revision','purpose','permissions','extra'])('a changed %s source never confirms retirement authority',async field=>{
 if(field==='actor')source.actorUserId=randomUUID();if(field==='token')source.tokenId=randomUUID();if(field==='OU generation')source.target.generation='1';if(field==='OU revision')source.target.revision='3';if(field==='fence revision')source.fenceRevision='5';if(field==='purpose')delete source.deviceOuRetirementProtocol;if(field==='permissions')source.permissions=['devices.inventory.create'];if(field==='extra')source.ready=true;
 await expect(client.read('Bearer original',user,selected)).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test.each([400,401,403,404,412,428])('an actual authority denial %i has no fallback or retry',async status=>{
 fetchImpl.mockResolvedValueOnce(Response.json({error:'Actual source rejected'},{status}));await expect(client.read('Bearer original',user,selected)).rejects.toMatchObject({status});expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('alternate origins paths credentials body overrides and nonhuman callers fail before sending',async()=>{
 for(const endpoint of ['https://identity.test/api/identity/device-inventory','https://user:secret@identity.test/api/identity/device-ou-retirement','https://identity.test/api/identity/device-ou-retirement?tenant=other'])expect(()=>new DeviceOuRetirementAuthority({endpoint})).toThrow();
 await expect(client.read('Bearer original',{...user,actor_type:'application'},selected)).rejects.toMatchObject({status:401});await expect(client.read('Bearer original',user,{...selected,tenantId:randomUUID()})).rejects.toMatchObject({status:400});expect(fetchImpl).not.toHaveBeenCalled();
});
test('a body cannot change its requested fence revision while the response is in flight',async()=>{
 const expected=JSON.stringify(selected);fetchImpl.mockImplementation(async()=>{selected.fenceRevision='99';return Response.json(source);});await expect(client.read('Bearer original',user,selected)).resolves.toEqual(source);expect(fetchImpl.mock.calls[0][1].body).toBe(expected);
});
test('unconfirmed oversized malformed and stale replies cannot act as a source',async()=>{
 for(const response of [Response.json({padding:'x'.repeat(65537)}),new Response('bad',{headers:{'Content-Type':'application/json'}}),Response.json({}, {status:501})]){fetchImpl.mockResolvedValueOnce(response);await expect(client.read('Bearer original',user,selected)).rejects.toMatchObject({status:503});}
 jest.useFakeTimers().setSystemTime(user.auth_time*1000);source.validUntil=user.auth_time+1;fetchImpl.mockImplementation(async()=>({status:200,headers:new Headers({'Content-Type':'application/json'}),body:(async function*(){jest.setSystemTime((user.auth_time+2)*1000);yield Buffer.from(JSON.stringify(source));})()}));await expect(client.read('Bearer original',user,selected)).rejects.toMatchObject({status:503});
});
