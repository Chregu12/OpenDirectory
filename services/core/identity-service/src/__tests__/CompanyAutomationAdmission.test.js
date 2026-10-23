'use strict';
const express=require('express');const request=require('supertest');const rateLimit=require('express-rate-limit');
const {automationAdmission}=require('../../../../../packages/company-automation-admission');const issuer='https://admission.test';const path='/private/run';
const principal=client=>({actor_type:'application',token_use:'access',iss:issuer,sub:client,client_id:client,client_revision:'1',jti:'original-token',exp:Math.floor(Date.now()/1000)+3600,scope:'company.automation',permissions:['company.automation']});
function app(options={}){const limits=automationAdmission(rateLimit,{paths:[path],issuer,ingressMax:20,verifiedMax:2,...options});const app=express();app.use(limits.ingress);app.use(rateLimit({windowMs:60000,max:1,skip:limits.matches}));
 app.use((req,_res,next)=>{req.user=req.headers['x-human']?{actor_type:'user'}:principal(req.headers['x-client']||'app');next();});app.use(limits.verified);app.post(path,(_req,res)=>res.json({actual:true}));app.get('/ordinary',(_req,res)=>res.json({actual:true}));return app;}
test('authorized private polling has a separate bounded client budget while ordinary admission is preserved',async()=>{
 const server=app();expect((await request(server).get('/ordinary')).status).toBe(200);expect((await request(server).get('/ordinary')).status).toBe(429);
 expect((await request(server).post(path)).status).toBe(200);expect((await request(server).post(path)).status).toBe(200);expect((await request(server).post(path)).status).toBe(429);
 expect((await request(server).post(path).set('X-Client','second')).status).toBe(200);
});
test('human or unauthenticated caller claims cannot borrow the verified app budget and raw ingress remains bounded',async()=>{
 const server=app({ingressMax:2});const denied=await request(server).post(path).set('X-Human','true');expect(denied.status).toBe(403);expect(denied.headers['cache-control']).toBe('no-store');
 expect((await request(server).post(path).set('X-Human','true')).status).toBe(403);expect((await request(server).post(path)).status).toBe(429);
});
