'use strict';

const express=require('express');
const { authority }=require('./PrivilegedActivation');
const { policyTag,reviewTag }=require('./RoleReviews');
const asyncRoute=handler=>(request,response,next)=>Promise.resolve(handler(request,response)).catch(next);
function roleReviewRoutes(reviews) {
  const router=express.Router();
  router.use((request,response,next)=>{
    response.set('Cache-Control','no-store');
    try {
      authority(request.user);
      if(Object.keys(request.query).length || request.method==='GET' && Object.keys(request.body || {}).length)return response.status(400).json({ error:'invalid_fields' });
      next();
    } catch(error) { next(error); }
  });
  router.get('/policies/:role',asyncRoute(async(request,response)=>{
    const result=await reviews.policy(request.params.role,request.user);
    if(result.policy)response.set('ETag',policyTag(result.policy)); response.json(result);
  }));
  router.post('/policies',asyncRoute(async(request,response)=>{
    const result=await reviews.create(request.body,request.user,request.headers.authorization);
    response.status(201).set('ETag',policyTag(result)).json(result);
  }));
  router.post('/policies/:id/retire',asyncRoute(async(request,response)=>{
    const result=await reviews.retire(request.params.id,request.headers['if-match'],request.body,request.user,request.headers.authorization);
    response.set('ETag',policyTag(result)).json(result);
  }));
  router.get('/self',asyncRoute(async(request,response)=>response.json(await reviews.self(request.user))));
  router.get('/:id',asyncRoute(async(request,response)=>{
    const result=await reviews.get(request.params.id,request.user); response.set('ETag',reviewTag(result)).json(result);
  }));
  router.post('/:id/decisions',asyncRoute(async(request,response)=>{
    const result=await reviews.decide(request.params.id,request.headers['if-match'],request.body,request.user,request.headers.authorization);
    response.set('ETag',reviewTag(result)).json(result);
  }));
  router.use((_request,response)=>response.status(404).json({ error:'review_operation_not_found' }));
  router.use((error,_request,response,_next)=>{
    const status=error.status || ({ '23505':409,'23514':409,'23503':409,'22P02':400,'42501':403 }[error.code]) || 503;
    response.status(status).json({ error:error.status && typeof error.code==='string' ? error.code : status===503 ? 'role_reviews_unavailable' : 'review_operation_rejected' });
  });
  return router;
}
module.exports={ roleReviewRoutes };
