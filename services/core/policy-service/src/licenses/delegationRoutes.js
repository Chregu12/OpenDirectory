'use strict';

const express = require('express');
const { LicenseDelegations, fields, uuid, tag } = require('./LicenseDelegations');
const { LicenseGrants, etag } = require('./LicenseGrants');
const route = handler => (req,res,next) => Promise.resolve(handler(req,res)).catch(next);
function errors(router) {
  router.use((_req,res)=>res.status(404).json({ error:'delegation_route_not_found' }));
  router.use((error,_req,res,_next)=>res.status(error.status || (['23503','23505','23514','42501','55P03','40P01'].includes(error.code)?409:503)).json({ error:error.status?error.message:'license_delegation_unavailable' }));
  return router;
}
function delegationRoutes(allocator) {
  const router=express.Router(); const store=new LicenseDelegations(allocator);
  router.use((req,res,next)=>{ res.set('Cache-Control','no-store'); if(Object.keys(req.query).some(key=>key!=='after') || req.method==='GET' && Object.keys(req.body||{}).length)return res.status(400).json({error:'invalid_delegation_fields'}); next(); });
  router.get('/self',route(async(req,res)=>{ if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'}); res.json(await store.self(req.user,req.licensePrincipal,req.headers.authorization)); }));
  router.get('/pools/:id',route(async(req,res)=>res.json(await store.list(req.params.id,req.query.after,req.user,req.licensePrincipal))));
  router.post('/',route(async(req,res)=>{ if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'}); const result=await store.create(req.body,req.user,req.licensePrincipal,req.headers.authorization); res.status(201).set('ETag',tag(result)).json(result); }));
  router.post('/:id/revoke',route(async(req,res)=>{ if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'}); const result=await store.revoke(req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization); res.set('ETag',tag(result)).json(result); }));
  return errors(router);
}
function scopedLicenseRoutes(allocator) {
  const router=express.Router({mergeParams:true}); const store=new LicenseDelegations(allocator); const grants=new LicenseGrants(allocator);
  router.use((req,res,next)=>{ res.set('Cache-Control','no-store'); if(Object.keys(req.query).some(key=>key!=='after') || req.method==='GET' && Object.keys(req.body||{}).length)return res.status(400).json({error:'invalid_delegation_fields'}); next(); });
  const run=(req,permission,reason,operation)=>store.run(req.params.licenseId,permission,reason,req.user,req.licensePrincipal,req.headers.authorization,operation);
  const read=(req,permission,operation)=>run(req,permission,null,()=>store.read(req.params.licenseId,operation,req.licensePrincipal.userId));
  router.get('/',route(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'});
    res.json(await read(req,'pool.read',async client=>(await client.query(`SELECT id,name,vendor,license_type AS "licenseType",total_seats AS "totalSeats",
      (SELECT COUNT(*)::int FROM license_assignments WHERE license_id=catalog.id AND (expires_at IS NULL OR expires_at>license_now())) AS "usedSeats" FROM license_catalog catalog WHERE id=$1 AND business_tenant_id IS NULL`,[req.params.licenseId])).rows[0]));
  }));
  router.get('/grants',route(async(req,res)=>res.json(await read(req,'grants.read',client=>grants.list(req.params.licenseId,req.query.after,client)))));
  router.post('/assign',route(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'});
    fields(req.body,['assigneeType','assigneeId','expiresAt','reason','confirm']); uuid(req.body.assigneeId);
    if(!['user','group'].includes(req.body.assigneeType))return res.status(400).json({error:'canonical_human_target_required'});
    const result=await run(req,'assignments.manage',req.body.reason.trim(),()=>allocator.assign(req.params.licenseId,{assignee_type:req.body.assigneeType,assignee_id:req.body.assigneeId,expires_at:req.body.expiresAt},req.licensePrincipal.userId,{principal:req.licensePrincipal,authorization:req.headers.authorization}));
    res.status(201).json({licenseId:req.params.licenseId,assigneeType:req.body.assigneeType,assigneeId:req.body.assigneeId,localOnly:true,status:result.kind==='group'?result.rule.status:'assigned'});
  }));
  router.post('/grants/:id/revoke',route(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'}); fields(req.body,['reason','confirm']);
    const result=await run(req,'assignments.manage',req.body.reason.trim(),()=>grants.revoke(req.params.licenseId,req.params.id,req.headers['if-match'],req.body,req.user,req.licensePrincipal,req.headers.authorization));
    res.set('ETag',etag(result.grant)).json(result);
  }));
  router.get('/requests',route(async(req,res)=>{
    if(req.query.after!==undefined)uuid(req.query.after);
    const rows=await read(req,'requests.read',async client=>(await client.query(`SELECT id,assignee_type AS "assigneeType",assignee_id AS "assigneeId",requester_id AS "requesterId",identity_bound AS "identityBound",justification,requested_at AS "requestedAt"
      FROM license_requests WHERE license_id=$1 AND status='pending' AND ($2::uuid IS NULL OR id>$2) AND EXISTS(SELECT 1 FROM license_catalog catalog WHERE catalog.id=license_requests.license_id AND catalog.business_tenant_id IS NULL) ORDER BY id LIMIT 101`,[req.params.licenseId,req.query.after||null])).rows);
    res.json({licenseId:req.params.licenseId,requests:rows.slice(0,100),hasMore:rows.length>100,nextAfter:rows.length>100?rows[99].id:null});
  }));
  router.post('/requests/:id/decisions',route(async(req,res)=>{
    if(Object.keys(req.query).length)return res.status(400).json({error:'invalid_delegation_fields'}); fields(req.body,['decision','reason','confirm']); uuid(req.params.id);
    if(!['approved','denied'].includes(req.body.decision))return res.status(400).json({error:'request_decision_required'});
    const result=await run(req,'requests.review',req.body.reason.trim(),async()=>{
      if(!(await allocator.database.query('SELECT 1 FROM license_requests request JOIN license_catalog catalog ON catalog.id=request.license_id AND catalog.business_tenant_id IS NULL WHERE request.id=$1 AND request.license_id=$2',[req.params.id,req.params.licenseId])).rows.length)throw Object.assign(new Error('request_not_found'),{status:404});
      return allocator.review(req.params.id,req.licensePrincipal.userId,req.body.decision,{principal:req.licensePrincipal,authorization:req.headers.authorization});
    });
    res.json({id:result.id,licenseId:result.license_id,status:result.status,localOnly:true,allocationStatus:result.allocation_status||null});
  }));
  return errors(router);
}
module.exports={delegationRoutes,scopedLicenseRoutes};
