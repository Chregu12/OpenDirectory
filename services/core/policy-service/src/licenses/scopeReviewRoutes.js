'use strict';
const express=require('express');const{LicenseScopeReviews,policyTag,reviewTag}=require('./LicenseScopeReviews');
function scopeReviewRoutes(allocator){const router=express.Router();const store=new LicenseScopeReviews(allocator);const route=handler=>(req,res,next)=>Promise.resolve(handler(req,res)).catch(next);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(Object.keys(req.query).length||req.method==='GET'&&Object.keys(req.body||{}).length)return res.status(400).json({error:'unsupported_scope_review_fields'});next();});
 router.get('/policies/pools/:id/:duty/:kind',route(async(req,res)=>res.json(await store.policy(req.params.id,req.params.duty,req.params.kind,req.user,req.licensePrincipal))));
 router.post('/policies',route(async(req,res)=>{const row=await store.create(req.body,req.user,req.licensePrincipal,req.headers.authorization);res.status(201).set('ETag',policyTag(row)).json(row);}));
 router.post('/policies/:id/retire',route(async(req,res)=>{const row=await store.retire(req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization);res.set('ETag',policyTag(row)).json(row);}));
 router.get('/self',route(async(req,res)=>res.json(await store.list(true,req.user,req.licensePrincipal))));router.get('/assigned',route(async(req,res)=>res.json(await store.list(false,req.user,req.licensePrincipal))));
 router.get('/:id',route(async(req,res)=>{const row=await store.get(req.params.id,req.user,req.licensePrincipal);res.set('ETag',reviewTag(row)).json(row);}));
 router.post('/:id/decisions',route(async(req,res)=>{const row=await store.decide(req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization);res.set('ETag',reviewTag(row)).json(row);}));
 router.use((_req,res)=>res.status(404).json({error:'scope_review_route_not_found'}));router.use((error,_req,res,_next)=>res.status(error.status||(['23503','23505','23514','42501','55P03','40P01'].includes(error.code)?409:503)).json({error:error.status?error.message:'scope_review_unavailable'}));return router;}
module.exports={scopeReviewRoutes};
