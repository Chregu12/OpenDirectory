'use strict';

const express=require('express');
const {LicenseScopeActivations,eligibilityTag,activationTag}=require('./LicenseScopeActivations');
function activationRoutes(allocator) {
  const router=express.Router();const store=new LicenseScopeActivations(allocator);
  router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(Object.keys(req.query).some(key=>key!=='after')||req.method!=='GET'&&Object.keys(req.query).length||req.method==='GET'&&Object.keys(req.body||{}).length)return res.status(400).json({error:'invalid_scope_activation_fields'});next();});
  const route=handler=>(req,res,next)=>Promise.resolve(handler(req,res)).catch(next);
  router.get('/self',route(async(req,res)=>{if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_scope_activation_fields'});res.json(await store.self(req.user,req.licensePrincipal,req.headers.authorization));}));
  router.get('/assigned',route(async(req,res)=>{if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_scope_activation_fields'});res.json(await store.assigned(req.user,req.licensePrincipal));}));
  router.get('/pools/:id',route(async(req,res)=>res.json(await store.list(req.params.id,req.query.after,req.user,req.licensePrincipal))));
  router.post('/eligibilities',route(async(req,res)=>{const result=await store.create(req.body,req.user,req.licensePrincipal,req.headers.authorization);res.status(201).set('ETag',eligibilityTag(result)).json(result);}));
  router.post('/eligibilities/:id/revoke',route(async(req,res)=>{const result=await store.revoke(req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization);res.set('ETag',eligibilityTag(result)).json(result);}));
  router.post('/eligibilities/:id/requests',route(async(req,res)=>{const result=await store.request(req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization);res.status(201).set('ETag',activationTag(result)).json(result);}));
  for(const [path,action]of [['decisions','decide'],['activate','activate'],['cancel','cancel'],['deactivate','deactivate']])router.post('/requests/:id/'+path,route(async(req,res)=>{
    const result=await store.transition(req.params.id,req.headers['if-match'],req.body,action,req.user,req.licensePrincipal,req.headers.authorization);res.set('ETag',activationTag(result)).json(result);
  }));
  router.use((_req,res)=>res.status(404).json({error:'scope_activation_route_not_found'}));
  router.use((error,_req,res,_next)=>res.status(error.status||(['23503','23505','23514','42501','55P03','40P01'].includes(error.code)?409:503)).json({error:error.status?error.message:'scope_activation_unavailable'}));
  return router;
}
module.exports={activationRoutes};
