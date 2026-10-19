'use strict';

const {validUuid,validContext}=require('../../../../../packages/identity-authorization-contract');
const {INVENTORY_PERMISSIONS}=require('../../../../../packages/device-inventory-contract');
function deviceInventoryReceiver(target,{fetchImpl=(...args)=>global.fetch(...args)}={}){
  const origin=new URL(target);
  if(!['http:','https:'].includes(origin.protocol) || origin.username || origin.password || origin.search || origin.hash || origin.pathname!=='/')throw new Error('Invalid inventory receiver URL');
  const inventoryEndpoint=new URL('/api/devices/capabilities',target);
  const returnsEndpoint=new URL('/api/devices/returns/capabilities',target);
  return async(req,res,next)=>{
    const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),5000);
    try{
      if(req.user?.actor_type!=='user' || !validContext(req.user.identity_authorization))return res.status(403).json({error:'Canonical inventory human required'});
      if(typeof req.headers.authorization!=='string' || req.headers.authorization.length>16384 || !/^Bearer [A-Za-z0-9._~-]+$/.test(req.headers.authorization))return res.status(401).json({error:'Original inventory bearer required'});
      const path=(req.originalUrl || req.url || '').split('?')[0];
      const returns=/^\/(?:api\/devices\/)?(?:returns(?:\/|$)|users\/[^/]+\/offboarding-returns(?:\/|$))/i.test(path);
      const endpoint=returns?returnsEndpoint:inventoryEndpoint;
      const response=await fetchImpl(endpoint,{method:'GET',headers:{Authorization:req.headers.authorization,Accept:'application/json'},redirect:'error',cache:'no-store',signal:controller.signal});
      if([401,403,428].includes(response.status))return res.status(response.status).json({error:'Original inventory authority rejected'});
      if(response.status!==200 || !response.headers.get('content-type')?.includes('application/json'))throw new Error('Unconfirmed inventory receiver');
      const chunks=[];let length=0;for await(const chunk of response.body){length+=chunk.length;if(length>4096)throw new Error('Oversized inventory capabilities');chunks.push(Buffer.from(chunk));}
      const data=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if(returns){
        if(Object.keys(data).length!==6 || data.schemaVersion!==1 || data.deviceReturnsProtocol!==1 || data.actorUserId!==req.user.identity_authorization.userId
          || !validUuid(data.tenantId) || data.managementMode!=='inventory-only' || JSON.stringify(data.permissions)!==JSON.stringify(INVENTORY_PERMISSIONS))throw new Error('Mismatched device returns receiver');
      }else if(data.schemaVersion!==1 || data.inventoryProtocol!==1 || data.userId!==req.user.identity_authorization.userId || !validUuid(data.tenantId) || data.managementMode!=='inventory-only'
        || !Array.isArray(data.supportedActions) || data.supportedActions.length || !Array.isArray(data.permissions) || !data.permissions.includes('devices.inventory.read'))throw new Error('Mismatched inventory receiver');
      next();
    }catch(error){res.status(503).json({error:'Canonical inventory receiver unavailable'});}
    finally{clearTimeout(timer);controller.abort();}
  };
}
module.exports={deviceInventoryReceiver};
