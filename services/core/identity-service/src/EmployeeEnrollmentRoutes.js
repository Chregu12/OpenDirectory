'use strict';
const express=require('express');const {EmployeeEnrollments}=require('./EmployeeEnrollments');const {EmployeeInvitationObserver}=require('./EmployeeInvitationObserver');
const {invitationRequest}=require('./EmployeeInvitationRequest');const contract=require('../../../../packages/employee-invitation-contract');
function employeeEnrollmentRoutes(database,{credentials,verify=invitationRequest(),ingress=(_req,_res,next)=>next()}={}){
 const router=express.Router();const enrollments=new EmployeeEnrollments(database,{credentials});const observer=new EmployeeInvitationObserver(database);
 for(const endpoint of [{operation:'complete',path:'complete',method:'complete'},{operation:'withdraw',path:'withdraw',method:'withdraw'},
  {operation:'activate',path:'accepted-source',method:'acceptedSource'},{operation:'observe',path:'observe',method:'read'}]){
  const path=contract.IDENTITY_BASE+'/'+endpoint.path;
  router.post(path,ingress,express.json({limit:'32kb'}),verify(endpoint.operation,path),async(req,res)=>{
   try{const receiver=endpoint.operation==='observe'?observer:enrollments;
    res.set('Cache-Control','no-store').json(await receiver[endpoint.method](req.body,req.employeeInvitationProof,req.headers.authorization));
   }catch(error){res.set('Cache-Control','no-store').status(error.status||503).json({error:error.code||'employee_enrollment_unavailable'});}
  });
 }
 return router;
}
module.exports={employeeEnrollmentRoutes};
