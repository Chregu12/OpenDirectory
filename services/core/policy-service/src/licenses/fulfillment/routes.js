'use strict';

const express=require('express');
const { ProviderStore }=require('./ProviderStore');
const { etag }=require('./contracts');
function fulfillmentRoutes(allocator) {
  const router=express.Router(); const store=new ProviderStore(allocator);
  const capacity=new(require('./CapacityReports').CapacityReports)(allocator);
  router.use((req,res,next)=>{
    res.set('Cache-Control','no-store');
    try { store.actor(req.user,req.licensePrincipal,'licenses.fulfillment.read'); if (Object.keys(req.query).length) return res.status(400).json({ error:'invalid_fulfillment_query' }); next(); }
    catch (error) { next(error); }
  });
  const route=handler=>(req,res,next)=>Promise.resolve(handler(req,res)).catch(next);
  router.get('/connectors/:id/capacity',route(async(req,res)=>{
    if(Object.keys(req.body||{}).length)return res.status(400).json({error:'invalid_fulfillment_fields'});
    res.json(await capacity.get(req.params.id,req.user,req.licensePrincipal,req.headers.authorization));
  }));
  for (const kind of ['connectors','products','subjects']) {
    router.post('/'+kind,route(async(req,res)=>{
      const result=await store.create(kind,req.body,req.user,req.licensePrincipal,req.headers.authorization); res.set('ETag',etag(kind,result.id,result.version)).status(201).json(result);
    }));
    router.get('/'+kind+'/:id',route(async(req,res)=>{
      if (Object.keys(req.body||{}).length) return res.status(400).json({ error:'invalid_fulfillment_fields' });
      const result=await store.get(kind,req.params.id); res.set('ETag',etag(kind,result.id,result.version)).json(result);
    }));
    router.put('/'+kind+'/:id',route(async(req,res)=>{
      const result=await store.enable(kind,req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization); res.set('ETag',etag(kind,result.id,result.version)).json(result);
    }));
  }
  router.get('/targets/:licenseId/:userId',route(async(req,res)=>{
    if (Object.keys(req.body||{}).length) return res.status(400).json({ error:'invalid_fulfillment_fields' });
    const result=await store.lookup(req.params.licenseId,req.params.userId,req.user); res.set('ETag',etag('targets',result.id,result.version)).json(result);
  }));
  router.post('/targets/:id/:action',route(async(req,res)=>{
    const result=await store.resolve(req.params.id,req.params.action,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization); res.set('ETag',etag('targets',result.id,result.version)).json(result);
  }));
  router.use((_req,res)=>res.status(404).json({ error:'fulfillment_route_not_found' }));
  router.use((error,_req,res,_next)=>res.status(error.status||(['23505','23503','23514'].includes(error.code)?409:503)).json({ error:error.status?error.message:'fulfillment_storage_unavailable' }));
  return router;
}
module.exports = { fulfillmentRoutes };
