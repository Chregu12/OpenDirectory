'use strict';
const {PolicyPublicationSource}=require('../PolicyPublicationSource');
const userId='11111111-1111-4111-8111-111111111111';
const row={schemaVersion:1,userId,revision:'3',enabled:true,linked:true,requestRevision:null,reviewRevision:'a'.repeat(64)};
const answer=value=>({status:200,headers:new Headers({'Content-Type':'application/json','X-OD-License-Snapshot-Protocol':'1'}),body:(async function*(){yield Buffer.from(JSON.stringify(value));})()});
test('reads only one fixed known actor endpoint with the original bearer and no ambient credentials or cache',async()=>{
 const fetchImpl=jest.fn().mockResolvedValue(answer(row));const source=new PolicyPublicationSource({baseUrl:'https://identity.test',fetchImpl});expect(await source.actor(userId,'Bearer original.operator')).toEqual(row);
 expect(fetchImpl).toHaveBeenCalledWith(`https://identity.test/api/policy-publication-actors/${userId}/snapshot`,expect.objectContaining({headers:{Authorization:'Bearer original.operator',Accept:'application/json'},redirect:'error',cache:'no-store'}));
});
test.each([undefined,'2'])('rejects protocol %j on a fresh bearer after a valid actor response',async protocol=>{
 const obsolete=answer(row);if(protocol===undefined)obsolete.headers.delete('X-OD-License-Snapshot-Protocol');else obsolete.headers.set('X-OD-License-Snapshot-Protocol',protocol);
 const fetchImpl=jest.fn().mockResolvedValueOnce(answer(row)).mockResolvedValueOnce(obsolete);const source=new PolicyPublicationSource({fetchImpl});
 expect(await source.actor(userId,'Bearer original.operator')).toEqual(row);
 await expect(source.actor(userId,'Bearer fresh.operator')).rejects.toMatchObject({status:503,code:'tenant_bound_publication_source_required'});
 expect(fetchImpl).toHaveBeenCalledTimes(2);expect(fetchImpl.mock.calls.map(([,options])=>options.headers.Authorization)).toEqual(['Bearer original.operator','Bearer fresh.operator']);
});
test('preserves a headerless 404 with a fresh bearer and reads again without cached actor evidence',async()=>{
 const fetchImpl=jest.fn().mockResolvedValueOnce(answer(row)).mockResolvedValueOnce({status:404}).mockResolvedValueOnce(answer(row));const source=new PolicyPublicationSource({fetchImpl});
 expect(await source.actor(userId,'Bearer original.operator')).toEqual(row);await expect(source.actor(userId,'Bearer fresh.operator')).rejects.toMatchObject({status:404});expect(await source.actor(userId,'Bearer renewed.operator')).toEqual(row);
 expect(fetchImpl).toHaveBeenCalledTimes(3);expect(fetchImpl.mock.calls.map(([,options])=>options.headers.Authorization)).toEqual(['Bearer original.operator','Bearer fresh.operator','Bearer renewed.operator']);
});
test.each([{userId:'alias'},{schemaVersion:2},{enabled:false},{reviewRevision:'unknown'},{revision:'0'},{password:'unexpected'},{requestRevision:true}])('rejects malformed or unexpectedly broad authority: %j',async change=>{const source=new PolicyPublicationSource({fetchImpl:async()=>answer({...row,...change})});await expect(source.actor(userId,'Bearer original.operator')).rejects.toMatchObject({status:503});});
test.each([401,403,404,429,500])('source rejection %s never substitutes a local/ambient success',async status=>{const fetchImpl=jest.fn().mockResolvedValue({status});const source=new PolicyPublicationSource({fetchImpl});await expect(source.actor(userId,'Bearer original.operator')).rejects.toMatchObject({status:[401,403,404].includes(status)?status:503});expect(fetchImpl).toHaveBeenCalledTimes(1);});
test('oversized authority is bounded before parsing and never replayed',async()=>{const fetchImpl=jest.fn().mockResolvedValue({status:200,headers:new Headers({'Content-Type':'application/json','X-OD-License-Snapshot-Protocol':'1'}),body:(async function*(){yield Buffer.alloc(4097);})()});await expect(new PolicyPublicationSource({fetchImpl}).actor(userId,'Bearer original.operator')).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(1);});
test.each(['https://user:secret@identity.test','https://identity.test/borrowed','file:///tmp/source'])('does not admit an arbitrary authority URL: %s',baseUrl=>{expect(()=>new PolicyPublicationSource({baseUrl})).toThrow();});
