'use strict';
const {workload}=require('./company-automation-contract');
function automationAdmission(rateLimit,{paths,issuer,windowMs=60000,ingressMax=4000,verifiedMax=1200}){
 for(const value of [windowMs,ingressMax,verifiedMax])if(!Number.isSafeInteger(value)||value<1)throw new Error('Invalid automation admission limit');
 const matches=req=>req.method==='POST'&&paths.includes(req.path);
 const options={windowMs,standardHeaders:true,legacyHeaders:false,message:{error:'automation_rate_limited'}};
 const ingressLimit=rateLimit({...options,max:ingressMax});
 const verifiedLimit=rateLimit({...options,max:verifiedMax,keyGenerator:req=>JSON.stringify([req.user.iss,req.user.client_id,req.user.client_revision])});
 return{matches,ingress(req,res,next){if(!matches(req))return next();res.set('Cache-Control','no-store');return ingressLimit(req,res,next);},verified(req,res,next){
  if(!matches(req))return next();try{workload(req.user,issuer);}catch{return res.status(403).json({error:'dedicated_automation_app_required'});}return verifiedLimit(req,res,next);
 }};
}
module.exports={automationAdmission};
