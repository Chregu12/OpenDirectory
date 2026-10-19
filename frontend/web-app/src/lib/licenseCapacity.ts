import {api} from './api';
import {fulfillmentId} from './licenseFulfillment';
export interface CapacitySku {skuId:string;skuPartNumber:string;appliesTo:'User'|'Company';capabilityStatus:'Enabled'|'Warning'|'Suspended'|'Deleted'|'LockedOut';prepaidUnits:{enabled:number;warning:number;suspended:number;lockedOut:number};consumedUnits:number}
export interface CapacityReport {schemaVersion:2;connectorId:string;tenantId:string;connectorVersion:string;enabled:boolean;source:{id:string;graphClientId:string;version:string}|null;
 observation:{id:string;status:'checking'|'complete'|'failed';startedAt:string;finishedAt:string|null;validUntil:string;payloadHash:string|null;current:boolean;error:string|null}|null;
 products:{productId:string;licenseId:string;skuId:string;version:string;enabled:boolean;name:string;local:{configuredSeats:number;unlimited:boolean;unexpiredAssignments:number};vendor:CapacitySku|null;admission:{budgetId:string;reviewedUnits:number;chargedUnits:number;remainingUnits:number;generationCurrent:boolean}|null;conservativeHeadroom:number|null;issues:string[]}[];
 readOnly:true;allocationChanged:false;providerFulfillmentConfirmed:false}
const fail=():never=>{throw new Error('Herstellerkapazität nicht bestätigt. Keine Nullkapazität und keine freien Plätze annehmen.');};
const revision=(value:unknown)=>typeof value==='string'&&/^[1-9][0-9]{0,18}$/.test(value)&&BigInt(value)<=BigInt('9223372036854775807');
const date=(value:unknown):value is string=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
const integer=(value:unknown):value is number=>typeof value==='number'&&Number.isInteger(value)&&value>=0&&value<=2147483647;
function fields(value:any,names:string[]){if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==names.length||names.some(name=>!Object.hasOwn(value,name)))return fail();}
function sku(value:CapacitySku,id:string){
 fields(value,['skuId','skuPartNumber','appliesTo','capabilityStatus','prepaidUnits','consumedUnits']);fields(value.prepaidUnits,['enabled','warning','suspended','lockedOut']);
 if(value.skuId!==id||typeof value.skuPartNumber!=='string'||!value.skuPartNumber.trim()||value.skuPartNumber.length>255||!['User','Company'].includes(value.appliesTo)||!['Enabled','Warning','Suspended','Deleted','LockedOut'].includes(value.capabilityStatus)
  ||!integer(value.consumedUnits)||Object.values(value.prepaidUnits).some(units=>!integer(units)))return fail();
}
export const licenseCapacity={
 async get(id:string,signal?:AbortSignal):Promise<CapacityReport>{
  fulfillmentId(id);const result=await api.get(`/api/licenses/fulfillment/connectors/${id}/capacity`,{signal});const value=result.data as CapacityReport;
  fields(value,['schemaVersion','connectorId','tenantId','connectorVersion','enabled','source','observation','products','readOnly','allocationChanged','providerFulfillmentConfirmed']);
  if(result.status!==200||value.schemaVersion!==2||value.connectorId!==id||!revision(value.connectorVersion)||typeof value.enabled!=='boolean'||value.readOnly!==true||value.allocationChanged!==false||value.providerFulfillmentConfirmed!==false||!Array.isArray(value.products)||value.products.length>1000)return fail();fulfillmentId(value.tenantId);
  if(value.source!==null){fields(value.source,['id','graphClientId','version']);fulfillmentId(value.source.id);fulfillmentId(value.source.graphClientId);if(!revision(value.source.version))return fail();}
  const observed=value.observation;
  if(observed!==null){
   fields(observed,['id','status','startedAt','finishedAt','validUntil','payloadHash','current','error']);fulfillmentId(observed.id);
   if(!['checking','complete','failed'].includes(observed.status)||!date(observed.startedAt)||!date(observed.validUntil)||Date.parse(observed.validUntil)!==Date.parse(observed.startedAt)+300000||typeof observed.current!=='boolean'
    ||observed.status==='checking'&&(observed.finishedAt!==null||observed.payloadHash!==null||observed.error!==null)
    ||observed.status!=='checking'&&!date(observed.finishedAt)||observed.status==='complete'&&(typeof observed.payloadHash!=='string'||!/^([a-f0-9]{64})$/.test(observed.payloadHash)||observed.error!==null||Date.parse(observed.finishedAt!)>Date.parse(observed.startedAt)+30000)
    ||observed.status==='failed'&&(observed.payloadHash!==null||typeof observed.error!=='string'||!/^[a-z][a-z0-9_]{0,99}$/.test(observed.error))
    ||observed.current&&(!value.enabled||!value.source||observed.status!=='complete'||Date.parse(observed.validUntil)<=Date.now()||Date.parse(observed.startedAt)>Date.now()+5000))return fail();
  }
  for(const product of value.products){
   fields(product,['productId','licenseId','skuId','version','enabled','name','local','vendor','admission','conservativeHeadroom','issues']);fields(product.local,['configuredSeats','unlimited','unexpiredAssignments']);
   fulfillmentId(product.productId);fulfillmentId(product.licenseId);fulfillmentId(product.skuId);
   if(!revision(product.version)||typeof product.enabled!=='boolean'||typeof product.name!=='string'||!integer(product.local.configuredSeats)||!integer(product.local.unexpiredAssignments)||product.local.unlimited!==(product.local.configuredSeats===0)||!Array.isArray(product.issues))return fail();
   if(product.vendor!==null){sku(product.vendor,product.skuId);if(observed?.status!=='complete')return fail();}
   if(product.admission!==null){const budget=product.admission;fields(budget,['budgetId','reviewedUnits','chargedUnits','remainingUnits','generationCurrent']);fulfillmentId(budget.budgetId);
    if(!integer(budget.reviewedUnits)||!integer(budget.chargedUnits)||!integer(budget.remainingUnits)||budget.chargedUnits>budget.reviewedUnits||budget.remainingUnits!==budget.reviewedUnits-budget.chargedUnits||typeof budget.generationCurrent!=='boolean'
     ||budget.generationCurrent&&(!value.enabled||!value.source||!product.enabled))return fail();}
   const expected=observed?.current&&product.enabled&&product.vendor?.appliesTo==='User'&&product.vendor.capabilityStatus==='Enabled'?Math.max(0,product.vendor.prepaidUnits.enabled-product.vendor.consumedUnits):null;
   if(product.conservativeHeadroom!==expected)return fail();const issues:string[]=[];
   if(!observed?.current)issues.push('observation-unavailable');if(!product.enabled)issues.push('product-paused');if(!product.vendor)issues.push('sku-not-observed');
   if(product.vendor&&product.vendor.appliesTo!=='User')issues.push('company-sku');if(product.vendor&&product.vendor.capabilityStatus!=='Enabled')issues.push('vendor-status-not-enabled');
   if(product.local.unlimited)issues.push('local-unlimited');if(product.vendor&&product.local.configuredSeats>product.vendor.prepaidUnits.enabled)issues.push('local-capacity-exceeds-enabled');
   if(product.vendor&&product.local.unexpiredAssignments>product.vendor.prepaidUnits.enabled)issues.push('local-assignments-exceed-enabled');if(JSON.stringify(product.issues)!==JSON.stringify(issues))return fail();
  }
  if(new Set(value.products.map(row=>row.productId)).size!==value.products.length||new Set(value.products.map(row=>row.skuId)).size!==value.products.length||new Set(value.products.map(row=>row.licenseId)).size!==value.products.length)return fail();return value;
 },
};
