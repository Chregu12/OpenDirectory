'use strict';

const { uuid,plans }=require('./contracts');
const { ProviderError,jsonRequest,ClientCredentialToken }=require('./transport');
function normalizedPlans(value) {
  if (!Array.isArray(value)) throw new Error('invalid_plans');
  return plans(value.map(item=>typeof item==='string'?item.toLowerCase():item).sort());
}
function observation(data,objectId,skuId,disabledPlans) {
  try {
    if (typeof data?.id!=='string' || data.id.toLowerCase()!==objectId || typeof data.accountEnabled!=='boolean'
      || !Array.isArray(data.assignedLicenses) || data.assignedLicenses.length>512 || !Array.isArray(data.licenseAssignmentStates) || data.licenseAssignmentStates.length>1024) throw new Error('invalid_user');
    const licenses=data.assignedLicenses.map(item=>({ skuId:uuid(item.skuId.toLowerCase()),plans:normalizedPlans(item.disabledPlans) }));
    if (new Set(licenses.map(item=>item.skuId)).size!==licenses.length) throw new Error('duplicate_sku');
    const states=data.licenseAssignmentStates.map(item=>{
      const group=item.assignedByGroup===null ? null : uuid(item.assignedByGroup.toLowerCase());
      if (!['Active','ActiveWithError','Disabled','Error'].includes(item.state) || item.error!==null && typeof item.error!=='string') throw new Error('invalid_assignment');
      return { skuId:uuid(item.skuId.toLowerCase()),group,plans:normalizedPlans(item.disabledPlans),active:item.state==='Active' && [null,'None'].includes(item.error) };
    });
    const matching=states.filter(item=>item.skuId===skuId); const direct=matching.filter(item=>item.group===null); const license=licenses.find(item=>item.skuId===skuId);
    if (direct.length>1) throw new Error('duplicate_direct');
    const plansMatch=!!direct.length && JSON.stringify(direct[0].plans)===JSON.stringify(disabledPlans);
    return { present:!!license || matching.length>0,direct:direct.length===1,active:!!license && !!direct[0]?.active,plansMatch,inherited:matching.some(item=>item.group!==null),accountEnabled:data.accountEnabled };
  } catch { throw new ProviderError('graph_read_invalid_response'); }
}
class GraphLicenseClient {
  constructor({ tenantId,clientId,clientSecret,fetchImpl=(...args)=>fetch(...args) }) {
    this.tenantId=uuid(tenantId); uuid(clientId); this.fetch=fetchImpl;
    this.tokens=new ClientCredentialToken({ url:`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,clientId,clientSecret,scope:'https://graph.microsoft.com/.default',fetchImpl,stage:'graph_token' });
  }
  async inspect(objectId,skuId,disabledPlans) {
    uuid(objectId); uuid(skuId); plans(disabledPlans); const token=await this.tokens.get();
    const data=await jsonRequest(this.fetch,`https://graph.microsoft.com/v1.0/users/${objectId}?$select=id,accountEnabled,assignedLicenses,licenseAssignmentStates`,{ method:'GET',headers:{ Authorization:'Bearer '+token } },'graph_read');
    const observed=observation(data,objectId,skuId,disabledPlans);
    const direct=data.licenseAssignmentStates.find(item=>item.skuId.toLowerCase()===skuId && item.assignedByGroup===null);
    if (direct && (direct.state!=='Active' || ![null,'None'].includes(direct.error))) {
      const error=new ProviderError('graph_assignment_error'); error.observation=observed; throw error;
    }
    return observed;
  }
  async mutate(objectId,skuId,disabledPlans,desired,token,attemptId) {
    uuid(objectId); uuid(skuId); plans(disabledPlans); uuid(attemptId);
    const data=await jsonRequest(this.fetch,`https://graph.microsoft.com/v1.0/users/${objectId}/assignLicense`,{ method:'POST',headers:{ Authorization:'Bearer '+token,'Content-Type':'application/json','client-request-id':attemptId },
      body:JSON.stringify({ addLicenses:desired?[{ skuId,disabledPlans }]:[],removeLicenses:desired?[]:[skuId] }) },'graph_write');
    if (typeof data?.id!=='string' || data.id.toLowerCase()!==objectId) throw new ProviderError('graph_write_invalid_response',{ uncertain:true });
  }
}
module.exports = { GraphLicenseClient,observation };
