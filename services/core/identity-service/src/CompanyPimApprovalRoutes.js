'use strict';
const express=require('express');const {CompanyPimApprovals}=require('./CompanyPimApprovals');const C=require('./CompanyRoleContract');
function companyPimApprovalRoutes(database){const router=express.Router(),service=new CompanyPimApprovals(database);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(req.user?.actor_type!=='user'||req.headers['x-api-key']!==undefined)return res.status(403).json({error:'company_pim_human_required'});if(req.method!=='GET'&&Object.keys(req.query).length||req.method==='GET'&&(Array.isArray(req.body)||Object.keys(req.body||{}).length||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding']!==undefined))return res.status(400).json({error:'exact_company_pim_request_required'});next();});
 const route=operation=>(req,res,next)=>Promise.resolve().then(()=>operation(req,res)).catch(next);
 router.get('/self',route(async(req,res)=>res.json(await service.list(req.query,req.user,req.headers.authorization))));
 router.get('/requests',route(async(req,res)=>res.json(await service.list(req.query,req.user,req.headers.authorization,true))));
 router.get('/eligibilities/:id',route(async(req,res)=>{if(Object.keys(req.query).length)throw Object.assign(new Error('exact_company_pim_request_required'),{status:400});res.json(await service.options(req.params.id,req.user,req.headers.authorization));}));
 router.post('/eligibilities/:id/requests',route(async(req,res)=>{const value=await service.create(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',C.etag('request',value.request)).status(201).json(value);}));
 for(const action of ['approve','deny','cancel'])router.post('/requests/:id/'+action,route(async(req,res)=>{const value=await service.decide(req.params.id,action,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',C.etag('request',value.request)).json(value);}));
 router.post('/requests/:id/activate',route(async(req,res)=>{const value=await service.activate(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',C.etag('activation',value.activation)).status(201).json(value);}));
 return router;
}
module.exports={companyPimApprovalRoutes};
