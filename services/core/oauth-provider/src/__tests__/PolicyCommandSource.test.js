'use strict';
const {randomUUID}=require('node:crypto');
const {PolicyCommandSource}=require('../PolicyCommandSource');
const user={identity_authorization:{userId:randomUUID()}};
const reference={resourceKind:'blueprint',resourceId:randomUUID(),resourceVersion:3,publicationId:randomUUID(),configurationId:randomUUID()};
const request={reference,deviceId:'owned-device',platform:'windows',operationId:randomUUID()};
function frame(){const now=Date.now();return{schemaVersion:1,...request,operatorUserId:user.identity_authorization.userId,configurationVersion:3,configurationHash:'a'.repeat(64),publicationVersion:2,
 publicationExpiresAt:new Date(now+300000).toISOString(),observedAt:new Date(now).toISOString(),admissionValidUntil:new Date(now+30000).toISOString(),deliverUntil:new Date(now+200000).toISOString(),
 payload:{blueprintId:reference.resourceId,blueprintName:'Owned blueprint',configurationId:reference.configurationId,configurationVersion:3,configType:'screen_lock',configName:'Owned screen lock',settings:{minutes:5}},payloadHash:'b'.repeat(64)};}
test('fetches only the fixed canonical source with the original bearer, no internal token, cache, redirect or caller-selected content',async()=>{
 const reply=frame();const fetchImpl=jest.fn().mockResolvedValue(Response.json(reply));const source=new PolicyCommandSource({baseUrl:'https://policy.test',fetchImpl});expect(await source.frame(request,user,'Bearer original.operator')).toEqual(reply);
 expect(fetchImpl).toHaveBeenCalledWith('https://policy.test/api/policies/delivery/frame',expect.objectContaining({method:'POST',body:JSON.stringify(request),headers:{Authorization:'Bearer original.operator',Accept:'application/json','Content-Type':'application/json'},redirect:'error',cache:'no-store'}));
});
test.each([401,403,404,409,412,428,429,503])('source status %s is never replaced with a cached or ambient privileged success',async status=>{
 const fetchImpl=jest.fn().mockResolvedValue(Response.json({},{status}));await expect(new PolicyCommandSource({fetchImpl}).frame(request,user,'Bearer original.operator')).rejects.toMatchObject({status:status===429?503:status});expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test.each([{operatorUserId:randomUUID()},{deviceId:'different-device'},{operationId:randomUUID()},{reference:{...reference,publicationId:randomUUID()}},{configurationVersion:4},{payloadHash:'not-a-hash'},{schemaVersion:0}])('misbound source evidence is refused before receiver DML: %j',async change=>{
 const fetchImpl=jest.fn().mockResolvedValue(Response.json({...frame(),...change}));await expect(new PolicyCommandSource({fetchImpl}).frame(request,user,'Bearer original.operator')).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('oversized or HTML replies are not interpreted as an empty/current approved configuration',async()=>{
 for(const response of [Response.json({oversized:'x'.repeat(300000)}),new Response('<html>unavailable</html>',{headers:{'Content-Type':'text/html'}})]){const source=new PolicyCommandSource({fetchImpl:async()=>response});await expect(source.frame(request,user,'Bearer original.operator')).rejects.toMatchObject({status:503});}
});
test.each(['https://name:secret@policy.test','https://policy.test/other','file:///tmp/source'])('rejects an unsafe authority origin: %s',baseUrl=>{expect(()=>new PolicyCommandSource({baseUrl})).toThrow();});
test('missing original credentials and an expired request signal cannot borrow a service token',async()=>{
 const fetchImpl=jest.fn();const source=new PolicyCommandSource({fetchImpl});await expect(source.frame(request,user,undefined)).rejects.toMatchObject({status:503});expect(fetchImpl).not.toHaveBeenCalled();
 const controller=new AbortController();controller.abort();fetchImpl.mockImplementation(async(url,options)=>{if(options.signal.aborted)throw new Error('Owned closed request');return Response.json(frame());});await expect(source.frame(request,user,'Bearer original.operator',controller.signal)).rejects.toMatchObject({status:503});
});
