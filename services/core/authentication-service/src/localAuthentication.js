'use strict';
const config=require('./utils/config');const logger=require('./utils/logger');
function localAuthentication(services){
 return async(req,username,password,done)=>{
  try{
   let user;
   try{user=(await services.authAppService.login({username,password,ip:req.ip,userAgent:req.headers['user-agent']}))?.user;}
   catch(error){
    if(error.status===401||error.status===403)user=null;
    else throw Object.assign(new Error(error.status===409?'Credential record changed':'Credential storage unavailable'),{status:error.status===409?409:503});
   }
   if(!user)return done(null,false,{message:'Invalid credentials'});
   if(await services.zeroTrust.evaluateTrust(req,user)<config.zeroTrust.minTrustScore){
    await services.auditService.logFailedAuth(username,req,'Low trust score');return done(null,false,{message:'Additional verification required'});
   }
   return done(null,user);
  }catch(error){logger.warn('Local credential authentication unavailable',{status:error.status||503});return done(error);}
 };
}
module.exports={localAuthentication};
