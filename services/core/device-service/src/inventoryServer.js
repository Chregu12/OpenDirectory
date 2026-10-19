'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { randomUUID } = require('node:crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const { createAccessStateClient } = require('../../../../packages/oidc-access-state');
const { deviceEtag, deviceReturnEtag } = require('../../../../packages/device-inventory-contract');
const { DeviceInventory } = require('./DeviceInventory');
const { DeviceReturns } = require('./DeviceReturns');
const database = require('./db');

function createInventoryApp({ db = database, inventory = new DeviceInventory(db), returns = new DeviceReturns(db, { inventory }) } = {}) {
  const app=express();const issuer=process.env.OIDC_ISSUER || 'http://localhost:3001';const jwks=createRemoteJWKSet(new URL(process.env.JWKS_URI || 'http://localhost:3001/jwks'));const accessState=createAccessStateClient();
  app.disable('x-powered-by');app.use(helmet());app.use(cors({origin:(process.env.CORS_ORIGINS || 'http://localhost:3000').split(',')}));
  app.use(express.json({limit:'16kb',strict:true}));app.use(rateLimit({windowMs:60000,max:1000,standardHeaders:true,legacyHeaders:false}));
  app.use((req,res,next)=>{req.correlationId=randomUUID();res.set('Cache-Control','no-store').set('X-Correlation-ID',req.correlationId);next();});
  app.get('/health',async(req,res)=>{const health=await db.healthCheck();res.status(health.status==='healthy'?200:503).json({service:'device-service',mode:'inventory-only',storage:health.status});});
  app.use(async(req,res,next)=>{
    const authorization=req.headers.authorization;
    if(req.headers['x-api-key'] || req.headers['x-enrollment-token'] || typeof authorization!=='string' || authorization.length>16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(authorization))return res.status(401).json({error:'Original inventory access token required'});
    try{
      const {payload}=await jwtVerify(authorization.slice(7),jwks,{issuer,audience:process.env.OIDC_AUDIENCE || 'opendirectory-api',algorithms:['RS256'],requiredClaims:['sub','exp','iat','jti']});
      if(payload.token_use!=='access' || payload.actor_type!=='user')return res.status(403).json({error:'Human inventory access required'});
      await accessState(authorization,payload);req.user=payload;next();
    }catch(error){res.status(error.status || 401).json({error:error.status===503?'Inventory token authority unavailable':'Inventory access token rejected'});}
  });
  function route(operation){return(req,res,next)=>Promise.resolve().then(()=>{
    if(req.method==='GET' && (Array.isArray(req.body) || Object.keys(req.body || {}).length) || req.method!=='GET' && Object.keys(req.query).length)throw Object.assign(new Error('Exact inventory request required'),{status:400});
    return operation(req,res);
  }).catch(next);}
  function result(res,value,status=200){res.set('ETag',deviceEtag(value)).status(status).json(value);}
  function noQuery(req){if(Object.keys(req.query).length)throw Object.assign(new Error('No device return selectors'),{status:400});}
  app.get('/api/devices/returns/capabilities',route(async(req,res)=>{noQuery(req);res.json(await returns.capabilities(req.user,req.headers.authorization));}));
  app.get('/api/devices/returns',route(async(req,res)=>res.json(await returns.list(req.query,req.user,req.headers.authorization))));
  app.get('/api/devices/returns/:id/history',route(async(req,res)=>res.json(await returns.history(req.params.id,req.query,req.user,req.headers.authorization))));
  app.get('/api/devices/returns/:id',route(async(req,res)=>{noQuery(req);const value=await returns.get(req.params.id,req.user,req.headers.authorization);res.set('ETag',deviceReturnEtag(value)).json(value);}));
  app.post('/api/devices/returns/:id/decision',route(async(req,res)=>{const value=await returns.decide(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization,req.correlationId);res.set('ETag',deviceReturnEtag(value.request)).json(value);}));
  app.get('/api/devices/users/:userId/offboarding-returns/capabilities',route(async(req,res)=>res.json(await returns.offboardingCapabilities(req.params.userId,req.query,req.user,req.headers.authorization))));
  app.get('/api/devices/users/:userId/offboarding-returns/history',route(async(req,res)=>res.json(await returns.offboardingHistory(req.params.userId,req.query,req.user,req.headers.authorization))));
  app.get('/api/devices/users/:userId/offboarding-returns',route(async(req,res)=>res.json(await returns.offboardingList(req.params.userId,req.query,req.user,req.headers.authorization))));
  app.post('/api/devices/users/:userId/offboarding-returns',route(async(req,res)=>{const value=await returns.request(req.params.userId,req.body,req.user,req.headers.authorization,req.correlationId);res.status(value.results.some(item=>['unconfirmed','not_attempted'].includes(item.status))?207:200).json(value);}));
  app.get('/api/devices/capabilities',route(async(req,res)=>{
    if(Object.keys(req.query).length)throw Object.assign(new Error('No inventory capability selectors'),{status:400});res.json(await inventory.capabilities(req.user,req.headers.authorization));
  }));
  app.get('/api/devices',route(async(req,res)=>res.json(await inventory.list(req.query,req.user,req.headers.authorization))));
  app.post('/api/devices',route(async(req,res)=>result(res,await inventory.create(req.body,req.user,req.headers.authorization,req.correlationId),201)));
  app.get('/api/devices/:id/history',route(async(req,res)=>res.json(await inventory.history(req.params.id,req.query,req.user,req.headers.authorization))));
  app.get('/api/devices/:id',route(async(req,res)=>{
    if(Object.keys(req.query).length)throw Object.assign(new Error('No inventory device selectors'),{status:400});result(res,await inventory.get(req.params.id,req.user,req.headers.authorization));
  }));
  app.put('/api/devices/:id/assignment',route(async(req,res)=>result(res,await inventory.assign(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization,req.correlationId))));
  app.use('/api',(req,res)=>res.status(501).json({error:'unsupported',managementMode:'inventory-only',message:'No enrolled provider or remote device action is implemented by this inventory receiver.'}));
  app.use((error,req,res,_next)=>{
    const status=error.status || ({23505:409,23514:409,23503:409,42501:503,'22P02':400,'22003':409,'55P03':409,'57014':503}[error.code]) || 503;
    res.status(status).json({error:status===503?'Persistent inventory or receiving evidence unavailable':status>=500?'Inventory operation unavailable':error.message,correlationId:req.correlationId});
  });
  return app;
}
async function start(){await database.initDb();await database.transaction(client=>client.query('SELECT device_returns_receiving()'),{readOnly:true});return createInventoryApp().listen(Number(process.env.PORT || 3003));}
if(require.main===module)start().then(server=>{
  const close=()=>{server.closeAllConnections();server.close(()=>database.pool.end().then(()=>process.exit(0)));};process.once('SIGTERM',close);process.once('SIGINT',close);
}).catch(()=>{process.stderr.write('Device inventory startup requires migrated PostgreSQL and configured receiving dependencies.\n');process.exitCode=1;database.pool.end().catch(()=>{});});
module.exports={createInventoryApp,start};
