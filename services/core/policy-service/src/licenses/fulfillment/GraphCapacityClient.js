'use strict';

const { uuid }=require('./contracts');
const { ProviderError,jsonRequest,ClientCredentialToken }=require('./transport');
const SELECT='skuId,skuPartNumber,appliesTo,capabilityStatus,prepaidUnits,consumedUnits';
const INITIAL='https://graph.microsoft.com/v1.0/subscribedSkus?$select='+SELECT;
function snapshot(rows) {
  try {
    if(!Array.isArray(rows)||rows.length>1000)throw new Error();const seen=new Set();
    return rows.map(row=>{
      const skuId=uuid(typeof row?.skuId==='string'?row.skuId.toLowerCase():row?.skuId);
      if(seen.has(skuId)||typeof row.skuPartNumber!=='string'||!row.skuPartNumber.trim()||row.skuPartNumber.length>255||/[\u0000-\u001f\u007f]/.test(row.skuPartNumber)
       ||!['User','Company'].includes(row.appliesTo)||!['Enabled','Warning','Suspended','Deleted','LockedOut'].includes(row.capabilityStatus))throw new Error();seen.add(skuId);
      const integer=value=>Number.isInteger(value)&&value>=0&&value<=2147483647;
      if(!integer(row.consumedUnits)||!row.prepaidUnits||['enabled','warning','suspended','lockedOut'].some(key=>!integer(row.prepaidUnits[key])))throw new Error();
      return{skuId,skuPartNumber:row.skuPartNumber,appliesTo:row.appliesTo,capabilityStatus:row.capabilityStatus,prepaidUnits:Object.fromEntries(['enabled','warning','suspended','lockedOut'].map(key=>[key,row.prepaidUnits[key]])),consumedUnits:row.consumedUnits};
    }).sort((first,second)=>first.skuId.localeCompare(second.skuId));
  }catch{throw new ProviderError('graph_capacity_invalid_response');}
}
function continuation(value) {
  try {
    if(typeof value!=='string'||value.length>4096)throw new Error();const url=new URL(value);
    if(url.origin!=='https://graph.microsoft.com'||url.pathname!=='/v1.0/subscribedSkus'||url.username||url.password||url.hash
      ||!url.searchParams.get('$skiptoken')||url.searchParams.get('$skiptoken').length>2048
      ||[...url.searchParams.keys()].some(key=>!['$skiptoken','$select'].includes(key))
      ||new Set(url.searchParams.keys()).size!==[...url.searchParams.keys()].length
      ||url.searchParams.has('$select')&&url.searchParams.get('$select')!==SELECT)throw new Error();return url.href;
  }catch{throw new ProviderError('graph_capacity_invalid_continuation');}
}
class GraphCapacityClient {
  constructor({tenantId,clientId,clientSecret,fetchImpl=(...args)=>fetch(...args)}){
    uuid(tenantId);uuid(clientId);this.fetch=fetchImpl;this.tokens=new ClientCredentialToken({url:`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,clientId,clientSecret,scope:'https://graph.microsoft.com/.default',fetchImpl,stage:'graph_capacity_token'});
  }
  async inspect(signal){
    const controller=new AbortController();const abort=()=>controller.abort();signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)controller.abort();const timer=setTimeout(abort,10000);
    try{
      const token=await this.tokens.get(controller.signal);let url=INITIAL;const visited=new Set();const rows=[];
      while(url){
        if(controller.signal.aborted||visited.size>=16||visited.has(url))throw new ProviderError('graph_capacity_incomplete');visited.add(url);
        const data=await jsonRequest(this.fetch,url,{method:'GET',headers:{Authorization:'Bearer '+token},signal:controller.signal},'graph_capacity');
        if(!data||!Array.isArray(data.value)||data.value.length+rows.length>1000||Object.hasOwn(data,'@odata.deltaLink'))throw new ProviderError('graph_capacity_invalid_response');
        rows.push(...data.value);url=Object.hasOwn(data,'@odata.nextLink')?continuation(data['@odata.nextLink']):null;
      }
      if(controller.signal.aborted)throw new ProviderError('graph_capacity_incomplete');return snapshot(rows);
    }catch(error){this.tokens.clear();throw error;}finally{clearTimeout(timer);signal?.removeEventListener('abort',abort);}
  }
}
module.exports={GraphCapacityClient,snapshot,continuation,INITIAL,SELECT};
