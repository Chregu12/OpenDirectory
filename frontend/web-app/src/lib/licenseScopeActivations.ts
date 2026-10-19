import { api } from './api';
export interface ScopeEligibility {id:string;licenseId:string;userId:string;duty:string;version:string;maxDurationSeconds:number;reviewerUserIds:string[];createdAt:string;expiresAt:string;revokedAt:string|null;state:'active'|'expired'|'revoked'|'stale'}
export interface ScopeActivation {id:string;eligibilityId:string;licenseId:string;userId:string;duty:string;version:string;status:string;requestedDurationSeconds:number;requestedAt:string;approvalDeadline:string;reviewedAt:string|null;activatedAt:string|null;grantId:string|null;grantExpiresAt:string|null;canReview:boolean;canActivate:boolean;canCancel:boolean;canDeactivate:boolean}
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;const base='/api/licenses/delegations/pim';
const bad=()=>{throw new Error('Unbestätigte Pool-Aktivierung. Neu laden, nicht blind wiederholen.');};
const id=(value:string)=>UUID.test(value)?value:bad();const date=(value:unknown)=>typeof value==='string'&&Number.isFinite(Date.parse(value));
const version=(value:unknown)=>typeof value==='string'&&/^[1-9]\d{0,18}$/.test(value)&&BigInt(value)<=BigInt('9223372036854775807');
const duration=(value:number)=>Number.isInteger(value)&&value>=60&&value<=28800;
const eligibilityTag=(row:ScopeEligibility)=>`"od-license-scope-eligibility:${row.id}:${row.version}"`;const activationTag=(row:ScopeActivation)=>`"od-license-scope-activation:${row.id}:${row.version}"`;
function accepted(result:{status:number;headers?:Record<string,unknown>},status=200,tag?:string){if(result.status!==status||tag&&result.headers?.etag!==tag)bad();}
function eligibility(value:unknown):ScopeEligibility{
  if(!value||typeof value!=='object'||Array.isArray(value))return bad();const row=value as ScopeEligibility;
  if(Object.keys(row).length!==11||[row.id,row.licenseId,row.userId].some(value=>!UUID.test(value))||!version(row.version)||!['reader','allocator','approver'].includes(row.duty)||!duration(row.maxDurationSeconds)
    ||!date(row.createdAt)||!date(row.expiresAt)||Date.parse(row.createdAt)>=Date.parse(row.expiresAt)||row.revokedAt!==null&&!date(row.revokedAt)||!['active','expired','revoked','stale'].includes(row.state)||(row.state==='revoked')!==(row.revokedAt!==null)
    ||!Array.isArray(row.reviewerUserIds)||row.reviewerUserIds.length<1||row.reviewerUserIds.length>10||new Set(row.reviewerUserIds).size!==row.reviewerUserIds.length||row.reviewerUserIds.some(value=>!UUID.test(value)||value===row.userId))return bad();return row;
}
function activation(value:unknown):ScopeActivation{
  if(!value||typeof value!=='object'||Array.isArray(value))return bad();const row=value as ScopeActivation;const activated=['activated','deactivated'].includes(row.status);
  if(Object.keys(row).length!==18||[row.id,row.eligibilityId,row.licenseId,row.userId].some(value=>!UUID.test(value))||!version(row.version)||!['reader','allocator','approver'].includes(row.duty)
    ||!['pending','approved','denied','activated','deactivated','cancelled'].includes(row.status)||!duration(row.requestedDurationSeconds)||!date(row.requestedAt)||!date(row.approvalDeadline)||Date.parse(row.requestedAt)>=Date.parse(row.approvalDeadline)
    ||[row.canReview,row.canActivate,row.canCancel,row.canDeactivate].some(value=>typeof value!=='boolean')||row.reviewedAt!==null&&!date(row.reviewedAt)
    ||(row.activatedAt!==null)!==activated||(row.grantId!==null)!==activated||(row.grantExpiresAt!==null)!==activated||activated&&(!date(row.activatedAt)||!UUID.test(row.grantId!)||!date(row.grantExpiresAt))
    ||['approved','denied','activated','deactivated'].includes(row.status)&&row.reviewedAt===null||row.status==='pending'&&row.reviewedAt!==null
    ||row.canReview&&(row.status!=='pending'||row.canCancel)||row.canActivate&&(row.status!=='approved'||!row.canCancel)||row.canCancel&&!['pending','approved'].includes(row.status)||row.canDeactivate&&row.status!=='activated')return bad();return row;
}
function rows<T extends {id:string}>(value:unknown,parse:(value:unknown)=>T):T[]{if(!Array.isArray(value)||value.length>100)return bad();const result=value.map(parse);if(new Set(result.map(row=>row.id)).size!==result.length)return bad();return result;}
export const scopeActivations={
  async self(userId:string){const result=await api.get(base+'/self');accepted(result);const value=result.data;
    if(!value||Object.keys(value).length!==4||value.userId!==id(userId)||typeof value.truncated!=='boolean')return bad();const eligible=rows(value.eligibilities,eligibility);const requests=rows(value.requests,activation);
    if(eligible.some(row=>row.userId!==userId)||requests.some(row=>row.userId!==userId||row.canReview))return bad();return{eligibilities:eligible,requests,truncated:value.truncated as boolean};},
  async assigned(userId:string){const result=await api.get(base+'/assigned');accepted(result);const value=result.data;
    if(!value||Object.keys(value).length!==3||value.userId!==id(userId)||typeof value.truncated!=='boolean')return bad();const requests=rows(value.requests,activation);if(requests.some(row=>!row.canReview||row.userId===userId||row.canActivate||row.canDeactivate||row.canCancel))return bad();return{requests,truncated:value.truncated as boolean};},
  async list(licenseId:string){const result=await api.get(base+'/pools/'+id(licenseId));accepted(result);const value=result.data;
    if(!value||Object.keys(value).length!==4||value.licenseId!==licenseId||typeof value.hasMore!=='boolean')return bad();const eligible=rows(value.eligibilities,eligibility);
    if(eligible.some(row=>row.licenseId!==licenseId)||(value.hasMore?eligible.length!==100||value.nextAfter!==eligible[99].id:value.nextAfter!==null))return bad();return{eligibilities:eligible,hasMore:value.hasMore as boolean};},
  async create(body:{licenseId:string;userId:string;duty:string;durationSeconds:number;maxDurationSeconds:number;reviewerUserIds:string[];reason:string;confirm:true}){
    const result=await api.post(base+'/eligibilities',body);const row=eligibility(result.data);accepted(result,201,eligibilityTag(row));
    if(row.licenseId!==body.licenseId||row.userId!==body.userId||row.duty!==body.duty||row.maxDurationSeconds!==body.maxDurationSeconds||row.version!=='1'||row.state!=='active'||JSON.stringify([...row.reviewerUserIds].sort())!==JSON.stringify([...body.reviewerUserIds].sort()))return bad();return row;},
  async revoke(row:ScopeEligibility,reason:string){const result=await api.post(base+'/eligibilities/'+row.id+'/revoke',{reason,confirm:true},{headers:{'If-Match':eligibilityTag(row)}});const changed=eligibility(result.data);accepted(result,200,eligibilityTag(changed));
    if(changed.state!=='revoked'||BigInt(changed.version)!==BigInt(row.version)+BigInt(1)||['id','licenseId','userId','duty','maxDurationSeconds','createdAt','expiresAt'].some(key=>changed[key as keyof ScopeEligibility]!==row[key as keyof ScopeEligibility])||JSON.stringify(changed.reviewerUserIds)!==JSON.stringify(row.reviewerUserIds))return bad();return changed;},
  async request(row:ScopeEligibility,durationSeconds:number,reason:string){const result=await api.post(base+'/eligibilities/'+row.id+'/requests',{durationSeconds,reason,confirm:true},{headers:{'If-Match':eligibilityTag(row)}});const value=activation(result.data);accepted(result,201,activationTag(value));
    if(value.eligibilityId!==row.id||value.licenseId!==row.licenseId||value.userId!==row.userId||value.duty!==row.duty||value.requestedDurationSeconds!==durationSeconds||value.status!=='pending'||value.version!=='1')return bad();return value;},
  async transition(row:ScopeActivation,action:'activate'|'cancel'|'deactivate'|'approved'|'denied',reason:string){const review=['approved','denied'].includes(action);const suffix=review?'decisions':action;
    const result=await api.post(base+'/requests/'+row.id+'/'+suffix,{...(review?{decision:action}:{}),reason,confirm:true},{headers:{'If-Match':activationTag(row)}});const changed=activation(result.data);accepted(result,200,activationTag(changed));
    const expected=action==='activate'?'activated':action==='cancel'?'cancelled':action==='deactivate'?'deactivated':action;
    if(changed.status!==expected||BigInt(changed.version)!==BigInt(row.version)+BigInt(1)||['id','eligibilityId','licenseId','userId','duty','requestedDurationSeconds','requestedAt','approvalDeadline'].some(key=>changed[key as keyof ScopeActivation]!==row[key as keyof ScopeActivation])
      ||!review&&changed.reviewedAt!==row.reviewedAt||action==='deactivate'&&(changed.grantId!==row.grantId||changed.grantExpiresAt!==row.grantExpiresAt||changed.activatedAt!==row.activatedAt))return bad();return changed;},
};
