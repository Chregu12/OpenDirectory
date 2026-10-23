'use strict';
const http=require('node:http');const {randomUUID}=require('node:crypto');
const contract=require('../../../../../packages/company-automation-change-contract');
const {CompanyAutomationWatchAuthority}=require('../../../policy-service/src/licenses/CompanyAutomationWatchAuthority');
const {CompanyLicenseAutomationClient}=require('../CompanyLicenseAutomationClient');
const app={actor_type:'application',token_use:'access',iss:'https://changes.test',sub:'change-app',client_id:'change-app',client_revision:'1',jti:'actual-original-token',exp:Math.floor(Date.now()/1000)+3600,scope:'company.automation',permissions:['company.automation']};
const input={grantId:randomUUID(),scheduleId:randomUUID(),ruleId:randomUUID()};const tenantId=randomUUID();
let server,origin,replacement,status,seen;
const proof=()=>({schemaVersion:1,companyAutomationChangeProtocol:1,...input,scheduleRevision:'1',tenant:{id:tenantId,version:'1',generation:'1'},issuer:app.iss,subject:app.sub,clientRevision:'1',tokenIdentifierHash:contract.tokenHash(app),validUntil:app.exp});
const observation=()=>({schemaVersion:1,companyAutomationChangeProtocol:1,allocationMode:'local-only',...input,scheduleRevision:'1',tenantId,groupId:input.ruleId,poolId:tenantId,ruleRevision:'1',ruleStatus:'active',poolRevision:'9007199254740993',availableSeats:1,validUntil:app.exp,tokenIdentifierHash:contract.tokenHash(app)});
beforeAll(async()=>{server=http.createServer(async(req,res)=>{const chunks=[];for await(const chunk of req)chunks.push(chunk);seen={authorization:req.headers.authorization,body:JSON.parse(Buffer.concat(chunks))};res.writeHead(status,{'Content-Type':'application/json'});res.end(JSON.stringify(replacement|| (req.url===contract.WATCH_PATH?proof():observation())));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;});
afterAll(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});beforeEach(()=>{status=200;replacement=null;seen=null;});
test('the current change authority uses only the pinned original subscription and app bearer',async()=>{
 const authority=new CompanyAutomationWatchAuthority({endpoint:origin+contract.WATCH_PATH});expect((await authority.read(input,'Bearer actual.original',app)).scheduleRevision).toBe('1');expect(seen).toEqual({authorization:'Bearer actual.original',body:input});
});
test.each([{scheduleId:randomUUID()},{clientRevision:'2'},{tokenIdentifierHash:'a'.repeat(64)},{validUntil:1},{extra:true}])('a substituted or expired change authority cannot be accepted: %j',async change=>{
 replacement={...proof(),...change};await expect(new CompanyAutomationWatchAuthority({endpoint:origin+contract.WATCH_PATH}).read(input,'Bearer actual.original',app)).rejects.toBeDefined();
});
test('local capacity observation stays bound to tenant, target, schedule generation and original app token',async()=>{
 const client=new CompanyLicenseAutomationClient({endpoint:origin+'/api/licenses/automation/groups/step'});const plan={id:input.scheduleId,grant_id:input.grantId,rule_id:input.ruleId,tenant_id:tenantId,revision:'1'};
 expect((await client.observe(plan,app,'Bearer actual.original')).poolRevision).toBe('9007199254740993');expect(seen.body).toEqual(input);
 for(const change of [{tenantId:randomUUID()},{scheduleRevision:'2'},{allocationMode:'provider-confirmed'},{availableSeats:-1},{poolRevision:'9223372036854775808'},{tokenIdentifierHash:'b'.repeat(64)}]){replacement={...observation(),...change};await expect(client.observe(plan,app,'Bearer actual.original')).rejects.toBeDefined();}
});
test.each([401,403,404,503])('rejected or unavailable source %i cannot become an empty successful observation',async code=>{status=code;await expect(new CompanyAutomationWatchAuthority({endpoint:origin+contract.WATCH_PATH}).read(input,'Bearer actual.original',app)).rejects.toMatchObject({status:code});});
