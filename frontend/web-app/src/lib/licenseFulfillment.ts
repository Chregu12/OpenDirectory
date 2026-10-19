import { api } from './api';

export interface FulfillmentState {
  id:string; licenseId:string; userId:string; objectId:string; connectorId:string; version:string; desired:boolean; localDesired:boolean; eligibilityBlocked:boolean;
  status:'pending'|'checking'|'in_flight'|'verifying'|'confirmed'|'unknown'|'conflict'|'failed'; owned:boolean; paused:boolean;
  observation:{ present:boolean; direct:boolean; active:boolean; plansMatch:boolean; inherited:boolean; accountEnabled:boolean }|null;
  checkedAt:string|null; error:string|null; canRetry:boolean; canAdopt:boolean; adoptionPurpose:'fulfill'|'cleanup'|null;
}
export function fulfillmentId(value:string) {
  if (typeof value!=='string' || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value)) throw new Error('Kanonische UUID erforderlich.'); return value;
}
function unconfirmed():never { throw new Error('Bereitstellungsstand nicht bestätigt. Stand neu prüfen; nicht automatisch wiederholen.'); }
function state(data:any):FulfillmentState {
  const fields=['id','licenseId','userId','objectId','connectorId','version','desired','localDesired','eligibilityBlocked','status','owned','paused','observation','checkedAt','error','canRetry','canAdopt','adoptionPurpose'];
  if (!data || typeof data!=='object' || Array.isArray(data) || Object.keys(data).length!==fields.length || fields.some(field=>!Object.hasOwn(data,field))) return unconfirmed();
  for (const field of ['id','licenseId','userId','objectId','connectorId']) fulfillmentId(data[field]);
  if (typeof data.version!=='string' || !/^[1-9][0-9]{0,18}$/.test(data.version) || BigInt(data.version)>BigInt('9223372036854775807')
    || ['desired','localDesired','eligibilityBlocked','owned','paused','canRetry','canAdopt'].some(field=>typeof data[field]!=='boolean')
    || !['pending','checking','in_flight','verifying','confirmed','unknown','conflict','failed'].includes(data.status)
    || data.checkedAt!==null && (typeof data.checkedAt!=='string' || !Number.isFinite(Date.parse(data.checkedAt)))
    || data.error!==null && (typeof data.error!=='string' || !/^[a-z0-9_]{1,120}$/.test(data.error))) return unconfirmed();
  if (data.observation!==null && (!data.observation || typeof data.observation!=='object' || Array.isArray(data.observation) || Object.keys(data.observation).length!==6
    || ['present','direct','active','plansMatch','inherited','accountEnabled'].some(field=>typeof data.observation[field]!=='boolean'))) return unconfirmed();
  if (data.status==='confirmed' && (data.error!==null || !data.checkedAt || !data.observation || data.desired && (!data.owned || !data.observation.active || !data.observation.direct || !data.observation.plansMatch) || !data.desired && data.observation.present)) return unconfirmed();
  if (data.canRetry && !['unknown','failed','conflict'].includes(data.status)) return unconfirmed();
  if (data.adoptionPurpose!==(data.canAdopt?data.desired?'fulfill':'cleanup':null)) return unconfirmed();
  if (data.canAdopt && (data.owned || data.desired && data.eligibilityBlocked || !data.observation?.direct || data.desired && !data.observation.active || !data.observation.plansMatch || data.observation.inherited)) return unconfirmed();
  return data;
}
export const licenseFulfillment={
  async get(licenseId:string,userId:string,signal?:AbortSignal):Promise<FulfillmentState> {
    const { data,status }=await api.get(`/api/licenses/fulfillment/targets/${fulfillmentId(licenseId)}/${fulfillmentId(userId)}`,{ signal }); if (status!==200) return unconfirmed();
    const result=state(data); if (result.licenseId!==licenseId || result.userId!==userId) return unconfirmed(); return result;
  },
  async resolve(before:FulfillmentState,action:'retry'|'adopt',reason:string):Promise<FulfillmentState> {
    const body=action==='adopt'?{ reason,acknowledgeExclusiveManagement:true }:{ reason,acknowledgeUncertainOutcome:true };
    const { data,status }=await api.post(`/api/licenses/fulfillment/targets/${fulfillmentId(before.id)}/${action}`,body,{ headers:{ 'If-Match':`"od-fulfillment:targets:${before.id}:${before.version}"` } });
    if (status!==200) return unconfirmed(); const result=state(data);
    if (result.id!==before.id || result.licenseId!==before.licenseId || result.userId!==before.userId || result.connectorId!==before.connectorId || result.objectId!==before.objectId
      || BigInt(result.version)!==BigInt(before.version)+BigInt(1) || result.status!=='pending' || result.desired!==before.desired || action==='adopt' && !result.owned) return unconfirmed(); return result;
  },
};
export function fulfillmentError(error:any):string {
  if (error?.response?.data?.error==='fresh_mfa_required') return 'Frische Anmeldung mit Passwort und OpenDirectory-TOTP erforderlich (höchstens fünf Minuten).';
  if (error?.response?.status===412) return 'Der Auftrag wurde inzwischen geändert. Stand neu prüfen; nicht automatisch wiederholen.';
  if (error?.response?.status===403) return 'Keine Berechtigung für diese Bereitstellungsaktion.';
  if (error?.response?.status===404) return 'Keine konfigurierte Provider-Verknüpfung für diese Lizenz und Verzeichnis-ID.';
  return error?.response?'Bereitstellungsquelle nicht bestätigt. Nicht automatisch wiederholen.':error?.message||'Bereitstellungsstand nicht verfügbar.';
}
