'use strict';
const express=require('express');const{authority}=require('./PrivilegedActivation');const{policyTag,reviewTag}=require('./GroupMembershipReviews');
function groupMembershipReviewRoutes(store){const router=express.Router();const route=operation=>(request,response,next)=>Promise.resolve(operation(request,response)).catch(next);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');try{authority(req.user);if(Object.keys(req.query).length||req.method==='GET'&&Object.keys(req.body||{}).length)return res.status(400).json({error:'unsupported_membership_review_fields'});next();}catch(error){next(error);}});
 router.get('/policies/groups/:id',route(async(req,res)=>res.json(await store.policy(req.params.id,req.user,req.headers.authorization))));
 router.post('/policies',route(async(req,res)=>{const row=await store.create(req.body,req.user,req.headers.authorization);res.status(201).set('ETag',policyTag(row)).json(row);}));
 router.post('/policies/:id/retire',route(async(req,res)=>{const row=await store.retire(req.params.id,req.headers['if-match'],req.body,req.user,req.headers.authorization);res.set('ETag',policyTag(row)).json(row);}));
 router.get('/self',route(async(req,res)=>res.json(await store.list(true,req.user,req.headers.authorization))));router.get('/assigned',route(async(req,res)=>res.json(await store.list(false,req.user,req.headers.authorization))));
 router.get('/:id',route(async(req,res)=>{const row=await store.get(req.params.id,req.user,req.headers.authorization);res.set('ETag',reviewTag(row)).json(row);}));
 router.post('/:id/decisions',route(async(req,res)=>{const row=await store.decide(req.params.id,req.headers['if-match'],req.body,req.user,req.headers.authorization);res.set('ETag',reviewTag(row)).json(row);}));
 router.use((_req,res)=>res.status(404).json({error:'membership_review_route_not_found'}));router.use((error,_req,res,_next)=>res.status(error.status||({'23505':409,'23514':409,'23503':409,'42501':403,'22P02':400}[error.code])||503).json({error:error.status?error.code||'membership_review_rejected':'membership_review_unavailable'}));return router;
}
module.exports={groupMembershipReviewRoutes};
