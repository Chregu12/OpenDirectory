'use strict';
const express=require('express');const{LicenseScopePolicies,policyTag}=require('./LicenseScopePolicies');
function scopePolicyRoutes(allocator){const router=express.Router();const store=new LicenseScopePolicies(allocator);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(Object.keys(req.query).length||req.method==='GET'&&Object.keys(req.body||{}).length)return res.status(400).json({error:'unsupported_pool_policy_fields'});next();});
 const route=handler=>(req,res,next)=>Promise.resolve(handler(req,res)).catch(next);
 router.get('/pools/:id/:duty',route(async(req,res)=>{const row=await store.get(req.params.id,req.params.duty,req.user,req.licensePrincipal);res.set('ETag',policyTag(row)).json(row);}));
 router.put('/pools/:id/:duty',route(async(req,res)=>{const row=await store.set(req.params.id,req.params.duty,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization);res.set('ETag',policyTag(row)).json(row);}));
 router.use((_req,res)=>res.status(404).json({error:'pool_policy_route_not_found'}));router.use((error,_req,res,_next)=>res.status(error.status||(['23503','23505','23514','42501','55P03','40P01'].includes(error.code)?409:503)).json({error:error.status?error.message:'pool_policy_unavailable'}));return router;}
module.exports={scopePolicyRoutes};
