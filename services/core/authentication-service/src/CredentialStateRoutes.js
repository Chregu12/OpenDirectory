'use strict';
const express=require('express');const rateLimit=require('express-rate-limit');const contract=require('../../../../packages/credential-authorization-contract');const {CredentialState}=require('./CredentialState');
function credentialStateRoutes(database,{issuer=process.env.OIDC_ISSUER||'http://localhost:3001',jwksUri=process.env.JWKS_URI||'http://oauth-provider:3010/.well-known/jwks.json'}={}){
 const router=express.Router();const state=new CredentialState(database);const verify=contract.credentialStateRequest({issuer,jwksUri,loadJose:()=>import('jose')});
 router.post(contract.PATH,(_req,res,next)=>{res.set('Cache-Control','no-store');next();},rateLimit({windowMs:60000,max:6000,standardHeaders:true,legacyHeaders:false,message:{error:'credential_state_rate_limited'}}),verify,async(req,res)=>{
  try{res.json(await state.read(req.body,req.credentialStateProof));}catch(error){res.status(error.status||503).json({error:error.code||'credential_state_unavailable'});}
 });return router;
}
module.exports={credentialStateRoutes};
