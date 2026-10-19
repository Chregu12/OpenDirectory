import {api}from'./api';
export interface LicenseScopePolicy{licenseId:string;duty:string;version:string;activationRequired:boolean;maxDurationSeconds:number;preparedEligibilityIds:string[];updatedAt:string|null;configured:boolean}
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;const bad=()=>{throw new Error('Unbestätigte Pool-PIM-Richtlinie. Neu laden, nicht blind wiederholen.');};
const tag=(row:LicenseScopePolicy)=>`"od-license-scope-policy:${row.licenseId}:${row.duty}:${row.version}"`;
const path=(licenseId:string,duty:string)=>{if(!UUID.test(licenseId)||!['reader','allocator','approver'].includes(duty))return bad();return`/api/licenses/delegations/policies/pools/${licenseId}/${duty}`;};
function parse(value:unknown,licenseId:string,duty:string):LicenseScopePolicy{
 if(!value||typeof value!=='object'||Array.isArray(value))return bad();const row=value as LicenseScopePolicy;
 if(Object.keys(row).length!==8||row.licenseId!==licenseId||row.duty!==duty||typeof row.version!=='string'||!/^[1-9]\d{0,18}$/.test(row.version)||BigInt(row.version)>BigInt('9223372036854775807')
  ||typeof row.activationRequired!=='boolean'||typeof row.configured!=='boolean'||!Number.isInteger(row.maxDurationSeconds)||row.maxDurationSeconds<60||row.maxDurationSeconds>28800
  ||!Array.isArray(row.preparedEligibilityIds)||row.preparedEligibilityIds.length>10||new Set(row.preparedEligibilityIds).size!==row.preparedEligibilityIds.length||row.preparedEligibilityIds.some(value=>!UUID.test(value))
  ||row.activationRequired&&!row.preparedEligibilityIds.length||row.configured&&(row.version==='1'||typeof row.updatedAt!=='string'||!Number.isFinite(Date.parse(row.updatedAt)))
  ||!row.configured&&(row.version!=='1'||row.updatedAt!==null||row.activationRequired||row.maxDurationSeconds!==28800||row.preparedEligibilityIds.length>0))return bad();return row;
}
export const licenseScopePolicies={
 async get(licenseId:string,duty:string){const result=await api.get(path(licenseId,duty));const row=parse(result.data,licenseId,duty);if(result.status!==200||result.headers?.etag!==tag(row))return bad();return row;},
 async set(row:LicenseScopePolicy,body:{activationRequired:boolean;maxDurationSeconds:number;preparedEligibilityIds:string[];reason:string;confirm:true;acknowledgeInvalidation:true}){
  const result=await api.put(path(row.licenseId,row.duty),body,{headers:{'If-Match':tag(row)}});const changed=parse(result.data,row.licenseId,row.duty);
  if(result.status!==200||result.headers?.etag!==tag(changed)||!changed.configured||BigInt(changed.version)!==BigInt(row.version)+BigInt(1)||changed.activationRequired!==body.activationRequired||changed.maxDurationSeconds!==body.maxDurationSeconds
   ||JSON.stringify([...changed.preparedEligibilityIds].sort())!==JSON.stringify([...body.preparedEligibilityIds].sort()))return bad();return changed;
 },
};
