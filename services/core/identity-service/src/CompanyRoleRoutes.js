'use strict';
const express=require('express');const {CompanyRoles}=require('./CompanyRoles');const Contract=require('./CompanyRoleContract');
function companyRoleRoutes(database){
 const router=express.Router();const service=new CompanyRoles(database);const pim=new(require('./CompanyPim').CompanyPim)(database);
 router.use((req,res,next)=>{res.set('Cache-Control','no-store');if(req.user?.actor_type!=='user'||req.headers['x-api-key']!==undefined)return res.status(403).json({error:'company_role_human_required'});if(req.method!=='GET'&&Object.keys(req.query).length||req.method==='GET'&&(Array.isArray(req.body)||Object.keys(req.body||{}).length||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding']!==undefined))return res.status(400).json({error:'exact_company_role_request_required'});next();});
 const route=operation=>(req,res,next)=>Promise.resolve().then(()=>operation(req,res)).catch(next);
 router.get('/',route(async(req,res)=>res.json(await service.list(req.query,req.user,req.headers.authorization))));
 router.post('/',route(async(req,res)=>{const value=await service.create(req.body,req.user,req.headers.authorization);res.set('ETag',Contract.etag('role',value.role)).status(201).json(value);}));
 router.post('/groups',route(async(req,res)=>res.status(201).json(await service.createGroup(req.body,req.user,req.headers.authorization))));
 router.get('/:id',route(async(req,res)=>{const value=await service.detail(req.params.id,req.query,req.user,req.headers.authorization);res.set('ETag',Contract.etag('role',value.role)).json(value);}));
 router.get('/:id/history',route(async(req,res)=>res.json(await service.history(req.params.id,req.query,req.user,req.headers.authorization))));
 router.put('/:id',route(async(req,res)=>{const value=await service.update(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',Contract.etag('role',value.role)).json(value);}));
 router.post('/:id/grants',route(async(req,res)=>{const value=await service.assign(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',Contract.etag('grant',value.grant)).status(201).json(value);}));
 router.post('/grants/:id/revoke',route(async(req,res)=>{const value=await service.revoke(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',Contract.etag('grant',value.grant)).json(value);}));
 router.get('/:id/eligibilities',route(async(req,res)=>res.json(await pim.eligibilities(req.params.id,req.query,req.user,req.headers.authorization))));
 router.post('/:id/eligibilities',route(async(req,res)=>{const value=await pim.assign(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',Contract.etag('eligibility',value.eligibility)).status(201).json(value);}));
 router.post('/eligibilities/:id/revoke',route(async(req,res)=>{const value=await pim.revokeEligibility(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization);res.set('ETag',Contract.etag('eligibility',value.eligibility)).json(value);}));
 router.post('/activations/:id/revoke',route(async(req,res)=>{const value=await pim.end(req.params.id,req.body,req.headers['if-match'],req.user,req.headers.authorization,true);res.set('ETag',Contract.etag('activation',value.activation)).json(value);}));
 return router;
}
module.exports={companyRoleRoutes};
