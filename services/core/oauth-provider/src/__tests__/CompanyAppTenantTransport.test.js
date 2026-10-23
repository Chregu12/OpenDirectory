'use strict';
const express=require('express');const http=require('node:http');const jwt=require('jsonwebtoken');const {generateKeyPairSync,randomUUID}=require('node:crypto');
const {authorizationRequest}=require('../../../identity-service/src/AuthorizationState');const {IdentityAuthority}=require('../IdentityAuthority');
const contract=require('../../../../../packages/company-app-contract');const {TYPE,AUDIENCE}=require('../../../../../packages/identity-authorization-contract');
let server;let origin;let privateKey;let tenant;let clientId;let received;let reader;const issuer='https://company-tenant-transport.test';
beforeAll(async()=>{
 const pair=generateKeyPairSync('rsa',{modulusLength:2048});privateKey=pair.privateKey.export({type:'pkcs8',format:'pem'});const publicKey={...pair.publicKey.export({format:'jwk'}),kid:'company-tenant-test',alg:'RS256',use:'sig'};
 const app=express();app.use(express.json());app.get('/jwks',(_req,res)=>res.json({keys:[publicKey]}));let validate;
 app.post(contract.TENANT_PATH,(req,res,next)=>validate(req,res,next),(req,res)=>{received++;res.json({schemaVersion:1,companyAppProtocol:1,clientId:req.body.clientId,tenant:req.body.tenant,active:true});});
 server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin='http://127.0.0.1:'+server.address().port;
 validate=authorizationRequest({issuer,jwksUri:origin+'/jwks',companyAppTenant:true});reader=new IdentityAuthority({signingKeys:{privateKey,kid:'company-tenant-test'},issuer,endpoint:origin+'/internal/identity/authorization-state'});
});
beforeEach(()=>{tenant={id:randomUUID(),version:'1',generation:'2'};clientId=randomUUID();received=0;});afterAll(async()=>new Promise(resolve=>server.close(resolve)));
function assertion(change={}){return jwt.sign({iss:issuer,sub:'oauth-provider',aud:AUDIENCE,actor_type:'workload',token_use:contract.TENANT_PURPOSE,scope:'identity.company-app-tenant.read',htm:'POST',htu:contract.TENANT_PATH,app_client_id:clientId,app_tenant:tenant,jti:randomUUID(),...change},privateKey,{algorithm:'RS256',keyid:'company-tenant-test',header:{typ:TYPE},expiresIn:30});}
test('the actual signed issuer producer reaches only its body-bound private tenant receiver',async()=>{expect(await reader.companyAppTenant(clientId,tenant)).toBe(true);expect(received).toBe(1);});
test.each([{actor_type:'application',token_use:'access'},{scope:'identity.company-app-tenant.read identity.authorization.read'},{htu:'/internal/identity/authorization-state'},{app_client_id:'foreign-client'},{app_tenant:{id:'foreign',version:'1',generation:'2'}}])('a valid signature cannot replace the original receiver purpose or selected namespace: %j',async change=>{
 const response=await fetch(origin+contract.TENANT_PATH,{method:'POST',headers:{Authorization:'Bearer '+assertion(change),'Content-Type':'application/json'},body:JSON.stringify({clientId,tenant})});expect(response.status).toBe(401);expect(received).toBe(0);
});
test('a modified namespace body cannot reuse an earlier correctly signed assertion',async()=>{const response=await fetch(origin+contract.TENANT_PATH,{method:'POST',headers:{Authorization:'Bearer '+assertion(),'Content-Type':'application/json'},body:JSON.stringify({clientId,tenant:{...tenant,generation:'3'}})});expect(response.status).toBe(401);expect(received).toBe(0);});
test('query selectors and a legacy API key cannot accompany an otherwise valid original workload',async()=>{
 for(const suffix of ['?tenant=foreign','']){const response=await fetch(origin+contract.TENANT_PATH+suffix,{method:'POST',headers:{Authorization:'Bearer '+assertion(),'Content-Type':'application/json',...(suffix?{}:{'X-API-Key':'legacy'})},body:JSON.stringify({clientId,tenant})});expect(response.status).toBe(401);}expect(received).toBe(0);
});
