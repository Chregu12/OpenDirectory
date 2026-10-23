'use strict';
const {Router}=require('express');
function companyAppRoutes({store,authenticate}){
 const router=Router();router.use((_req,res,next)=>{res.set('Cache-Control','no-store');next();});router.use(authenticate);
 router.use((req,res,next)=>{
  if(!['GET','POST','PUT','DELETE'].includes(req.method)||req.headers['x-api-key']!==undefined||req.method!=='GET'&&Object.keys(req.query).length
   ||req.method==='GET'&&(Object.keys(req.body||{}).length||Number(req.headers['content-length']||0)||req.headers['transfer-encoding']))return res.status(400).json({error:'exact_company_app_request_required'});next();
 });
 const route=(operation,status=200)=>(req,res,next)=>Promise.resolve().then(()=>operation(req)).then(value=>{if(value.client)res.set('ETag',`"od-client:${value.client.clientId}:${value.client.version}"`);res.status(status).json(value);}).catch(next);
 const credentials=req=>[req.user,req.headers.authorization];
 router.get('/',route(req=>store.list(req.query,...credentials(req))));
 router.get('/:id/history',route(req=>store.history(req.params.id,req.query,...credentials(req))));
 router.get('/:id',route(req=>{if(Object.keys(req.query).length)throw Object.assign(new Error('exact_company_app_request_required'),{status:400});return store.read(req.params.id,...credentials(req));}));
 router.post('/',route(req=>store.create(req.body,...credentials(req)),201));
 router.put('/:id',route(req=>store.mutate(req.params.id,req.headers['if-match'],req.body,...credentials(req))));
 router.post('/:id/rotate-secret',route(req=>store.mutate(req.params.id,req.headers['if-match'],req.body,...credentials(req),'rotated')));
 router.delete('/:id',route(req=>store.mutate(req.params.id,req.headers['if-match'],req.body,...credentials(req),'deleted')));
 router.use((_req,res)=>res.status(404).json({error:'company_app_operation_unavailable'}));
 router.use((error,_req,res,_next)=>res.status(error.status||503).json({error:error.status&&error.status<500?error.code||error.message:'company_app_outcome_unconfirmed'}));return router;
}
module.exports={companyAppRoutes};
