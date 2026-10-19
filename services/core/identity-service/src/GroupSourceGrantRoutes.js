'use strict';
const {Router}=require('express');
const {tag}=require('./GroupSourceGrants');
function groupSourceGrantRoutes(store){const router=Router();const route=operation=>async(req,res,next)=>{try{if(Object.keys(req.query).length||req.method==='GET'&&Object.keys(req.body||{}).length)throw Object.assign(new Error('Source selectors are not supported'),{status:400});res.set('Cache-Control','no-store');const result=await operation(req,res);if(result===undefined)return;if(result.id)res.set('ETag',tag(result));res.json(result);}catch(error){next(error);}};
 router.get('/clients/:clientId',route(req=>store.client(req.params.clientId,req.user,req.headers.authorization)));
 router.get('/groups/:groupId',route(req=>store.list(req.params.groupId,req.user,req.headers.authorization)));
 router.get('/:id',route(req=>store.get(req.params.id,req.user,req.headers.authorization)));
 router.post('/',route(async(req,res)=>{const result=await store.create(req.body,req.user,req.headers.authorization);res.status(201);return result;}));
 router.post('/:id/revoke',route(req=>store.revoke(req.params.id,req.headers['if-match'],req.body,req.user,req.headers.authorization)));
 return router;
}
module.exports={groupSourceGrantRoutes};
