'use strict';
const express=require('express');const rateLimit=require('express-rate-limit');
const contract=require('../../../../packages/employee-invitation-contract');
const {EmployeeInvitations}=require('./EmployeeInvitations');const {EmployeeInvitationAuthorityClient}=require('./EmployeeInvitationAuthorityClient');
const {invitationRequest}=require('./EmployeeInvitationRequest');
function employeeInvitationRoutes(database,{invitations,verify=invitationRequest()}={}){
 const router=express.Router();
 if(!invitations){const authority=new EmployeeInvitationAuthorityClient();invitations=new EmployeeInvitations(database,{authority,observe:(...args)=>authority.observe(...args),accepted:(...args)=>authority.accepted(...args)});}
 const ingress=rateLimit({windowMs:60000,max:1200,standardHeaders:true,legacyHeaders:false,message:{error:'employee_invitation_rate_limited'}});
 const endpoints=[...['create','list','get','revoke','inspect','credential','activate','state'].map(operation=>({operation,path:operation,method:operation})),
  {operation:'complete',path:'identity-source',method:'identitySource'},{operation:'withdraw',path:'revoked-source',method:'revokedSource'}];
 for(const endpoint of endpoints){const path=contract.AUTH_BASE+'/'+endpoint.path;
  router.post(path,(_req,res,next)=>{res.set('Cache-Control','no-store');next();},ingress,verify(endpoint.operation,path),async(req,res)=>{
   try{const result=await invitations[endpoint.method](req.body,req.employeeInvitationProof,
     ['create','list','get','revoke'].includes(endpoint.operation)?req.headers['x-opendirectory-owner-authorization']:req.headers.authorization);
    res.status(endpoint.operation==='create'&&result.created?201:200).json(result);
   }catch(error){res.status(error.status||503).json({error:error.code||'employee_invitation_outcome_unconfirmed'});}
  });
 }
 return router;
}
module.exports={employeeInvitationRoutes};
