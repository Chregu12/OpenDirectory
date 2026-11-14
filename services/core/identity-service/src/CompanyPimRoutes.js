'use strict';
const express=require('express');const {CompanyPim}=require('./CompanyPim');const C=require('./CompanyRoleContract');
function companyPimRoutes(database){const router=express.Router(),service=new CompanyPim(database);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(req.user?.actor_type!=='user'||req.headers['x-api-key']!==undefined)return res.status(403).json({error:'company_pim_human_required'});
  if(req.method!=='GET'&&Object.keys(req.query).length||req.method==='GET'&&(Array.isArray(req.body)||Object.keys(req.body||{}).length||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding']!==undefined))return res.status(400).json({error:'exact_company_pim_request_required'});next();});
 const route=operation=>(req,res,next)=>Promise.resolve().then(()=>operation(req,res)).catch(next);
 router.get('/',route(async(req,res)=>res.json(await service.self(req.query,req.user,req.headers.authorization))));
 router.get('/history',route(async(req,res)=>res.json(await service.history(req.query,req.user,req.headers.authorization))));
 router.post('/eligibilities/:id/activate',route(async(req,res)=>{const value=await service.activate(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',C.etag('activation',value.activation)).status(201).json(value);}));
 router.post('/activations/:id/end',route(async(req,res)=>{const value=await service.end(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',C.etag('activation',value.activation)).json(value);}));
 return router;
}
module.exports={companyPimRoutes};
