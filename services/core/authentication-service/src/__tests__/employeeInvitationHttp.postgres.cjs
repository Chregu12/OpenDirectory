'use strict';
const {test,beforeEach,afterEach,after}=require('node:test');const assert=require('node:assert/strict');
const {randomUUID,generateKeyPairSync}=require('node:crypto');const {once}=require('node:events');const fs=require('node:fs');const path=require('node:path');
const express=require('express');const jwt=require('jsonwebtoken');const {Pool}=require('pg');
const {activeCompany}=require('../../../../../scripts/lib/company-owner-fixture.cjs');const {DirectoryCreator}=require('../../../identity-service/src/DirectoryCreator');
const {AuthorizationState}=require('../../../identity-service/src/AuthorizationState');const {EmployeeInvitationAuthority}=require('../../../identity-service/src/EmployeeInvitationAuthority');
const {EmployeeInvitationObserver}=require('../../../identity-service/src/EmployeeInvitationObserver');const {invitationRequest}=require('../../../identity-service/src/EmployeeInvitationRequest');
const {startAuthenticationService}=require('./fixtures/server.cjs');const contract=require('../../../../../packages/employee-invitation-contract');
const administration=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,max:1});const issuer='https://employee.http.native';
const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});const signingKey=privateKey.export({type:'pkcs8',format:'pem'});
let authPool,identityPool,identityServer,service,employee,owner,authorization,authSchema,identitySchema,environment,databaseUrl,identityBodies;
const route=contract.AUTH_BASE;
function signed(operation,body,{ownerAuthorization=null,extra={},type=contract.TYPE,htu}={}){const now=Math.floor(Date.now()/1000);
 return jwt.sign({iss:issuer,sub:'oauth-provider',aud:contract.AUDIENCE,actor_type:'workload',token_use:contract.PURPOSE,scope:'employees.invitations.'+operation,
  htm:'POST',htu:htu||(['observe','complete'].includes(operation)?contract.IDENTITY_BASE:route)+'/'+operation,
  body_sha256:contract.digest(body),owner_sha256:ownerAuthorization?contract.digest(ownerAuthorization):null,jti:randomUUID(),iat:now,exp:now+30,...extra},signingKey,{algorithm:'RS256',keyid:'employee-http-key',header:{typ:type}});
}
async function call(operation,body,options={}){const token=options.token||signed(operation,body,{ownerAuthorization:options.ownerAuthorization});
 const response=await fetch(service.url+route+'/'+(options.path||operation),{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',
  ...(options.ownerAuthorization?{'x-opendirectory-owner-authorization':options.ownerAuthorization}:{}),...options.headers},body:JSON.stringify(body)});
 return{status:response.status,body:await response.json(),cache:response.headers.get('cache-control')};
}
beforeEach(async()=>{
 authSchema='employee_http_auth_'+randomUUID().replaceAll('-','');identitySchema='employee_http_identity_'+randomUUID().replaceAll('-','');await administration.query('CREATE SCHEMA '+authSchema);await administration.query('CREATE SCHEMA '+identitySchema);
 authPool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,options:'-c search_path='+authSchema+',public -c timezone=UTC'});identityPool=new Pool({connectionString:process.env.AUTH_TEST_DATABASE_URL,options:'-c search_path='+identitySchema+',public -c timezone=UTC'});
 const database={isAvailable:()=>true,query:(...args)=>identityPool.query(...args),getClient:()=>identityPool.connect(),transaction:async(operation,options={})=>{const client=await identityPool.connect();try{await client.query(options.readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN');if(options.actor)await client.query("SELECT set_config('opendirectory.actor',$1,true)",[options.actor]);const value=await operation(client);await client.query('COMMIT');return value;}catch(error){await client.query('ROLLBACK');throw error;}finally{client.release();}}};
 const migrations=path.join(__dirname,'../../../identity-service/migrations');for(const file of fs.readdirSync(migrations).filter(file=>file.endsWith('.sql')).sort())await identityPool.query(fs.readFileSync(path.join(migrations,file),'utf8'));
 owner=await activeCompany(database,identitySchema,issuer);authorization='Bearer '+jwt.sign(owner.user,signingKey,{algorithm:'RS256',keyid:'employee-http-key'});
 const revalidate=async(_authorization,user)=>(await new AuthorizationState(database).state(issuer,user.sub)).tenant;
 employee=await new DirectoryCreator(database,{issuer,revalidate}).user({username:'http-employee',email:randomUUID()+'@example.invalid'},owner.user,authorization);
 const authority=new EmployeeInvitationAuthority(database,{issuer,revalidate});const observer=new EmployeeInvitationObserver(database);
 const app=express();identityBodies=[];app.use(express.json({limit:'32kb'}));
 app.get('/jwks',(_req,res)=>res.json({keys:[{...publicKey.export({format:'jwk'}),kid:'employee-http-key',alg:'RS256',use:'sig'}]}));
 app.post(contract.SOURCE_PATH,async(req,res)=>{try{const user=jwt.verify(req.headers.authorization?.slice(7),publicKey,{issuer,algorithms:['RS256']});identityBodies.push(req.body);res.json(await authority.read(user,req.headers.authorization,req.body));}catch(error){res.status(error.status||401).json({error:error.code||'source_rejected'});}});
 identityServer=app.listen(0,'127.0.0.1');await once(identityServer,'listening');const origin='http://127.0.0.1:'+identityServer.address().port;
 app.post(contract.IDENTITY_BASE+'/observe',invitationRequest({issuer,jwksUri:origin+'/jwks'})('observe',contract.IDENTITY_BASE+'/observe'),async(req,res)=>{try{identityBodies.push(req.body);res.json(await observer.read(req.body,req.employeeInvitationProof));}catch(error){res.status(error.status||503).json({error:error.code||'observation_unavailable'});}});
 environment={OIDC_ISSUER:issuer,JWKS_URI:origin+'/jwks',IDENTITY_SERVICE_URL:origin};databaseUrl=new URL(process.env.AUTH_TEST_DATABASE_URL);databaseUrl.searchParams.set('options','-c search_path='+authSchema+',public');
 service=await startAuthenticationService(databaseUrl.href,false,environment);
});
afterEach(async()=>{if(service)await service.stop();if(identityServer)await new Promise(resolve=>identityServer.close(resolve));await authPool.end();await identityPool.end();await administration.query('DROP SCHEMA '+authSchema+' CASCADE');await administration.query('DROP SCHEMA '+identitySchema+' CASCADE');});after(()=>administration.end());
async function create(){const request={id:randomUUID(),userId:employee.id,userRevision:employee.revision,loginName:'http-'+randomUUID(),durationHours:24,reason:'Explicit invitation through the actual credential service',confirm:true};
 const result=await call('create',request,{ownerAuthorization:authorization});assert.equal(result.status,201,JSON.stringify(result.body));return{request,...result.body};}
test('actual production Auth HTTP verifies both original signatures and retains the locked invitation across restart',{timeout:45000},async()=>{
 const created=await create();assert.equal(created.invitationToken.length,80);assert.equal(created.invitation.status,'pending');
 const replay=await call('create',created.request,{ownerAuthorization:authorization});assert.equal(replay.status,200);assert.equal(replay.body.invitationToken,null);assert.equal(replay.cache,'no-store');
 const inspection=await call('inspect',{token:created.invitationToken});assert.equal(inspection.status,200);const witness=inspection.body.witness;
 const body={token:created.invitationToken,password:'Actual-HTTP-Employee-Password-321!',observationAssertion:signed('observe',{witness})};
 const established=await call('credential',body);assert.equal(established.status,200,JSON.stringify(established.body));assert.equal(established.body.invitation.status,'credential_pending');
 assert.equal((await authPool.query('SELECT is_locked FROM users')).rows[0].is_locked,true);assert.equal((await identityPool.query('SELECT enabled FROM users WHERE id=$1',[employee.id])).rows[0].enabled,false);
 assert.ok(identityBodies.some(value=>value.witness?.id===created.invitation.id));assert.ok(identityBodies.every(value=>!JSON.stringify(value).includes(body.password)));
 await service.stop();service=null;service=await startAuthenticationService(databaseUrl.href,false,environment);
 const recovered=await call('credential',body);assert.equal(recovered.status,200);assert.deepEqual(recovered.body,established.body);assert.equal((await authPool.query('SELECT count(*) AS n FROM users')).rows[0].n,'1');
 const revoke={id:created.invitation.id,revision:established.body.invitation.revision,reason:'Revoke the actual incomplete HTTP invitation',confirm:true};
 assert.equal((await call('revoke',revoke,{ownerAuthorization:authorization})).status,200);assert.equal((await call('credential',body)).status,401);
 await assert.rejects(authPool.query('UPDATE users SET is_locked=false'),{code:'42501'});
 const evidence=await authPool.query('SELECT * FROM auth_employee_invitation_events');assert.equal(evidence.rows.length,3);assert.ok(evidence.rows.every(event=>!JSON.stringify(event).includes(body.password)&&!JSON.stringify(event).includes(created.invitationToken)));
});
test('the actual HTTP receiver rejects changed bodies, human tokens, substituted owners and wrong private token purposes',{timeout:30000},async()=>{
 const created=await create();const body={id:created.invitation.id};const token=signed('get',body,{ownerAuthorization:authorization});
 const forged=token.split('.');forged[2]=(forged[2][0]==='A'?'B':'A')+forged[2].slice(1);
 const forbidden=[
  {token:forged.join('.'),ownerAuthorization:authorization},
  {token:authorization.slice(7),ownerAuthorization:authorization},
  {token,ownerAuthorization:'Bearer substituted-owner'},
  {token,ownerAuthorization:authorization,headers:{'x-api-key':'forbidden'}},
  {token,ownerAuthorization:authorization,path:'get?unexpected=1'},
  {token:signed('get',body,{ownerAuthorization:authorization,type:'JWT'}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{scope:'identity.authorization.read'}}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{unexpected:true}}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,htu:contract.IDENTITY_BASE+'/get'}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{aud:'opendirectory-api'}}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{iss:'https://foreign-issuer.invalid'}}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{exp:Math.floor(Date.now()/1000)-1,iat:Math.floor(Date.now()/1000)-15}}),ownerAuthorization:authorization},
  {token:signed('get',body,{ownerAuthorization:authorization,extra:{exp:Math.floor(Date.now()/1000)+60}}),ownerAuthorization:authorization}
 ];
 for(const options of forbidden){const response=await call('get',body,options);assert.equal(response.status,401,JSON.stringify(options));assert.equal(response.cache,'no-store');}
 const changed=await call('get',{id:randomUUID()},{token,ownerAuthorization:authorization});assert.equal(changed.status,401);
 const inspection={token:created.invitationToken};assert.equal((await call('inspect',inspection,{headers:{'x-opendirectory-owner-authorization':authorization}})).status,401);
 assert.equal((await authPool.query('SELECT count(*) AS n FROM auth_employee_invitation_events')).rows[0].n,'1');
});
