'use strict';
const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {configuration,sources,SourceCredential,sourceRequest}=require('../SourceCredentials');
const scope='licenses.groups.derive';let directory;let filename;
const data=()=>({enabled:true,tokenUrl:'https://issuer.test/oauth/token',groups:{clientId:'group-only-client',clientSecret:'owned-group-source-secret'},users:{clientId:'user-only-client',clientSecret:'owned-user-source-secret'}});
const write=value=>fs.writeFileSync(filename,typeof value==='string'?value:JSON.stringify(value),{mode:0o600});
beforeEach(()=>{directory=fs.mkdtempSync(path.join(os.tmpdir(),'od-source-credentials-'));filename=path.join(directory,'sources.json');});
afterEach(()=>{jest.restoreAllMocks();fs.rmSync(directory,{recursive:true,force:true});});
test('protected source configuration creates separate fixed-purpose providers, not a human administrator bearer',()=>{
 write(data());const loaded=sources(filename,{accessStateUrl:'https://issuer.test/oauth/access-state'});expect(loaded.groups.purpose).toBe(scope);expect(loaded.users.purpose).toBe('licenses.users.read');expect(sources(undefined)).toBeNull();
});
test.each([{enabled:false},{enabled:true,tokenUrl:'https://issuer.test/oauth/token',groups:false},{...data(),extra:true},{...data(),tokenUrl:'https://other.test/oauth/token'},
 {...data(),tokenUrl:'https://issuer.test/oauth/token?client_id=other'},{...data(),groups:{clientId:'valid',clientSecret:'tiny'}},{...data(),groups:{clientId:'valid',clientSecret:'owned-source-secret',scope:'identity.admin'}},
 {...data(),users:{clientId:'group-only-client',clientSecret:'owned-user-source-secret'}}])('invalid or ambiguous source configuration is rejected: %j',value=>{
 write(value);expect(()=>configuration(filename,{accessStateUrl:'https://issuer.test/oauth/access-state'})).toThrow(/configuration rejected/);
});
test('world-readable, symbolic or malformed protected configuration cannot leak its embedded secret in a startup error',()=>{
 write(data());fs.chmodSync(filename,0o644);expect(()=>configuration(filename)).toThrow(/configuration rejected/);fs.chmodSync(filename,0o600);fs.symlinkSync(filename,path.join(directory,'alias.json'));expect(()=>configuration(path.join(directory,'alias.json'))).toThrow(/configuration rejected/);
 write('{"clientSecret":"DO-NOT-DISCLOSE-OWNED-SECRET",broken');let error;try{configuration(filename);}catch(failure){error=failure;}expect(String(error)).not.toContain('DO-NOT-DISCLOSE');expect(String(error)).toContain('configuration rejected');
});
function credential(fetchImpl){return new SourceCredential({tokenUrl:'https://issuer.test/oauth/token',...data().groups},scope,{fetchImpl});}
const response=(patch={})=>new Response(JSON.stringify({access_token:'owned-source-token',token_type:'Bearer',expires_in:60,scope,...patch}),{headers:{'Content-Type':'application/json'}});
test('concurrent readers share a bounded client-credentials request with only the fixed purpose and renew before expiry',async()=>{
 let now=Date.now();jest.spyOn(Date,'now').mockImplementation(()=>now);const fetchImpl=jest.fn(async()=>response());const source=credential(fetchImpl);
 expect(await Promise.all([source.authorization(),source.authorization()])).toEqual(['Bearer owned-source-token','Bearer owned-source-token']);expect(fetchImpl).toHaveBeenCalledTimes(1);
 const sent=new URLSearchParams(fetchImpl.mock.calls[0][1].body);expect(Object.fromEntries(sent)).toEqual({grant_type:'client_credentials',client_id:'group-only-client',client_secret:'owned-group-source-secret',scope});expect(fetchImpl.mock.calls[0][1].redirect).toBe('manual');
 now+=31000;await source.authorization();expect(fetchImpl).toHaveBeenCalledTimes(2);
});
test.each([{scope:'licenses.groups.read'},{scope:undefined},{scope:scope+' roles'},{expires_in:0},{expires_in:86401},{token_type:'basic'},{access_token:'invalid token'}])('a widened, malformed or unbounded token response is never cached: %j',async patch=>{
 const source=credential(async()=>response(patch));await expect(source.authorization()).rejects.toMatchObject({status:503});expect(source.tokens.cached).toBeNull();
});
test('a denied group consent does not discard a still-valid credential for another explicitly permitted group',async()=>{
 const fetchImpl=jest.fn(async()=>response());const source=credential(fetchImpl);await source.authorization();await expect(sourceRequest(source,null,async()=>{throw{status:403,upstreamStatus:403};})).rejects.toMatchObject({status:403});await source.authorization();expect(fetchImpl).toHaveBeenCalledTimes(1);
});
test('a revoked access token clears the cache but cannot replay a failed source request or borrow an ambient bearer',async()=>{
 let now=Date.now();jest.spyOn(Date,'now').mockImplementation(()=>now);const fetchImpl=jest.fn(async()=>response());const source=credential(fetchImpl);const operation=jest.fn(async()=>{throw{status:403,upstreamStatus:401};});
 await expect(sourceRequest(source,'Bearer forbidden-human-fallback',operation)).rejects.toMatchObject({status:403});expect(operation).toHaveBeenCalledTimes(1);expect(operation).toHaveBeenCalledWith('Bearer owned-source-token');expect(source.tokens.cached).toBeNull();await expect(source.authorization()).rejects.toMatchObject({status:503});
 now+=31000;await source.authorization();expect(fetchImpl).toHaveBeenCalledTimes(2);
});
test('issuer throttling is respected across source calls without logging or returning the client secret',async()=>{
 let now=Date.now();jest.spyOn(Date,'now').mockImplementation(()=>now);const fetchImpl=jest.fn(async()=>new Response('{}',{status:429,headers:{'Retry-After':'120'}}));const source=credential(fetchImpl);
 await expect(source.authorization()).rejects.toThrow('license_source_credentials_unavailable');now+=60000;await expect(source.authorization()).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(1);now+=61000;await expect(source.authorization()).rejects.toMatchObject({status:503});expect(fetchImpl).toHaveBeenCalledTimes(2);
});
test('stopping while a token response is outstanding prevents any subsequent source call',async()=>{
 let release;const source=credential(()=>new Promise(resolve=>{release=resolve;}));const operation=jest.fn();const pending=sourceRequest(source,null,operation);source.stop();release(response());await expect(pending).rejects.toMatchObject({status:503});expect(operation).not.toHaveBeenCalled();expect(source.tokens.cached).toBeNull();
});
