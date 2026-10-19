import { api } from './api';
import { authenticationRole } from './roleAuthentication';
import { canonicalRoleUser } from './directoryRoles';
import { directoryError } from './directoryUsers';

export interface RoleReviewPolicy { id: string; role: string; version: string; intervalSeconds: number; windowSeconds: number; reviewerUserIds: string[]; createdAt: string; retiredAt: string | null; protected: boolean; canRetire: boolean; requiresFreshMfa: boolean }
export interface RoleReviewPolicyPage { role: string; policy: RoleReviewPolicy | null; canCreate: boolean; requiresFreshMfa: boolean }
export interface RoleReview { id: string; policyId: string; role: string; targetKind: 'assignment' | 'eligibility'; targetId: string; userId: string; version: string; policyVersion: string; cycle: string; dueAt: string | null; deadlineAt: string | null; baseExpiresAt: string | null; state: 'pending' | 'scheduled' | 'expired' | 'denied' | 'exempt' | 'obsolete'; policyRetired: boolean; canDecide: boolean; requiresFreshMfa: boolean; selfReview: boolean }
export interface ReviewPolicyInput { role: string; intervalSeconds: number; windowSeconds: number; reviewerUserIds: string[]; reason: string; acknowledgeDeadlines: true }
export interface ReviewDecision { decision: 'retain' | 'revoke'; reason: string; acknowledgeScope: true }
function unconfirmed(): never { throw new Error('Zugriffsprüfung nicht bestätigt. Stand prüfen; nicht automatisch wiederholen.'); }
function exact(data: any,fields: string[]) { return !!data && typeof data==='object' && !Array.isArray(data) && Object.keys(data).length===fields.length && fields.every(key=>Object.hasOwn(data,key)); }
function version(value: unknown) { return typeof value==='string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value)<=BigInt('9223372036854775807'); }
function date(value: unknown) { return typeof value==='string' && Number.isFinite(Date.parse(value)); }
function canonical(value: string) { if(canonicalRoleUser(value)!==value)unconfirmed(); }
function policy(data: any): RoleReviewPolicy {
  const fields=['id','role','version','intervalSeconds','windowSeconds','reviewerUserIds','createdAt','retiredAt','protected','canRetire','requiresFreshMfa'];
  if(!exact(data,fields) || !version(data.version) || !Number.isInteger(data.intervalSeconds) || data.intervalSeconds<3600 || data.intervalSeconds>31536000
    || !Number.isInteger(data.windowSeconds) || data.windowSeconds<60 || data.windowSeconds>604800 || data.windowSeconds>=data.intervalSeconds
    || !date(data.createdAt) || data.retiredAt!==null && !date(data.retiredAt) || !Array.isArray(data.reviewerUserIds) || !data.reviewerUserIds.length || data.reviewerUserIds.length>20
    || ['protected','canRetire','requiresFreshMfa'].some(key=>typeof data[key]!=='boolean') || data.canRetire && data.requiresFreshMfa
    || data.retiredAt!==null && (data.canRetire || data.requiresFreshMfa))return unconfirmed();
  canonical(data.id); authenticationRole(data.role); if(data.role==='user')return unconfirmed();
  data.reviewerUserIds.forEach((identifier: string,index: number)=>{ canonical(identifier); if(index>0 && data.reviewerUserIds[index-1]>=identifier)unconfirmed(); });
  return data;
}
function review(data: any): RoleReview {
  const fields=['id','policyId','role','targetKind','targetId','userId','version','policyVersion','cycle','dueAt','deadlineAt','baseExpiresAt','state','policyRetired','canDecide','requiresFreshMfa','selfReview'];
  if(!exact(data,fields) || !version(data.version) || !version(data.policyVersion) || !version(data.cycle) || !['assignment','eligibility'].includes(data.targetKind)
    || !['pending','scheduled','expired','denied','exempt','obsolete'].includes(data.state) || ['policyRetired','canDecide','requiresFreshMfa','selfReview'].some(key=>typeof data[key]!=='boolean')
    || data.baseExpiresAt!==null && !date(data.baseExpiresAt) || (data.dueAt===null)!==(data.deadlineAt===null)
    || data.dueAt!==null && (!date(data.dueAt) || !date(data.deadlineAt) || Date.parse(data.deadlineAt)<=Date.parse(data.dueAt))
    || ['pending','scheduled','expired','denied'].includes(data.state) && data.dueAt===null || data.state==='exempt' && (data.dueAt!==null || !data.policyRetired)
    || data.canDecide && (data.state!=='pending' || data.selfReview || data.requiresFreshMfa) || data.requiresFreshMfa && (data.state!=='pending' || data.selfReview))return unconfirmed();
  for(const key of ['id','policyId','targetId','userId'])canonical(data[key]); authenticationRole(data.role); return data;
}
const base='/api/identity/reviews';
export const roleReviews={
  async policy(role: string,signal?: AbortSignal): Promise<RoleReviewPolicyPage> {
    authenticationRole(role); const { data,status }=await api.get(base+'/policies/'+encodeURIComponent(role),{ signal });
    if(status!==200 || !exact(data,['role','policy','canCreate','requiresFreshMfa']) || data.role!==role
      || typeof data.canCreate!=='boolean' || typeof data.requiresFreshMfa!=='boolean' || data.canCreate && data.requiresFreshMfa)return unconfirmed();
    const current=data.policy===null ? null : policy(data.policy);
    if(current && (current.role!==role || !current.retiredAt && data.canCreate))return unconfirmed();
    return { ...data,policy:current };
  },
  async create(input: ReviewPolicyInput): Promise<RoleReviewPolicy> {
    const { data,status }=await api.post(base+'/policies',input); if(status!==201)return unconfirmed(); const result=policy(data);
    if(result.version!=='1' || result.role!==input.role || result.intervalSeconds!==input.intervalSeconds || result.windowSeconds!==input.windowSeconds
      || result.retiredAt!==null || JSON.stringify(result.reviewerUserIds)!==JSON.stringify(input.reviewerUserIds))return unconfirmed(); return result;
  },
  async retire(before: RoleReviewPolicy,reason: string): Promise<RoleReviewPolicy> {
    const { data,status }=await api.post(`${base}/policies/${before.id}/retire`,{ reason,acknowledgeDeadlines:true },{ headers:{ 'If-Match':`"od-role-review-policy:${before.id}:${before.version}"` } });
    if(status!==200)return unconfirmed(); const result=policy(data);
    if(result.id!==before.id || result.role!==before.role || BigInt(result.version)!==BigInt(before.version)+BigInt(1) || result.retiredAt===null
      || result.intervalSeconds!==before.intervalSeconds || result.windowSeconds!==before.windowSeconds || result.createdAt!==before.createdAt
      || JSON.stringify(result.reviewerUserIds)!==JSON.stringify(before.reviewerUserIds))return unconfirmed(); return result;
  },
  async self(userId: string,signal?: AbortSignal): Promise<{ userId: string; reviews: RoleReview[]; truncated: boolean }> {
    const { data,status }=await api.get(base+'/self',{ signal });
    if(status!==200 || !exact(data,['userId','reviews','truncated']) || data.userId!==canonicalRoleUser(userId) || !Array.isArray(data.reviews) || data.reviews.length>100 || typeof data.truncated!=='boolean')return unconfirmed();
    const reviews=data.reviews.map(review); if(new Set(reviews.map((item: RoleReview)=>item.id)).size!==reviews.length)return unconfirmed(); return { ...data,reviews };
  },
  async get(id: string,signal?: AbortSignal): Promise<RoleReview> {
    const { data,status }=await api.get(base+'/'+canonicalRoleUser(id),{ signal }); if(status!==200)return unconfirmed();
    const result=review(data); if(result.id!==id)return unconfirmed(); return result;
  },
  async decide(before: RoleReview,input: ReviewDecision): Promise<RoleReview> {
    const { data,status }=await api.post(`${base}/${before.id}/decisions`,input,{ headers:{ 'If-Match':`"od-role-review:${before.id}:${before.version}:${before.policyVersion}"` } });
    if(status!==200)return unconfirmed(); const result=review(data);
    if(['id','policyId','role','targetKind','targetId','userId','policyVersion','baseExpiresAt','policyRetired'].some(key=>result[key as keyof RoleReview]!==before[key as keyof RoleReview])
      || BigInt(result.version)!==BigInt(before.version)+BigInt(1))return unconfirmed();
    if(input.decision==='revoke') {
      if(result.state!=='denied' || result.cycle!==before.cycle)return unconfirmed();
    } else if(BigInt(result.cycle)!==BigInt(before.cycle)+BigInt(1) || (before.policyRetired ? result.state!=='exempt' : result.state!=='scheduled'))return unconfirmed();
    if(input.decision==='retain' && !before.policyRetired) {
      const interval=(Date.parse(result.dueAt!)-Date.parse(before.dueAt!))/1000; const window=(Date.parse(result.deadlineAt!)-Date.parse(result.dueAt!))/1000;
      if(interval<3600 || interval>31536000 || window<60 || window>604800 || window>=interval || Date.parse(result.dueAt!)<=Date.parse(before.deadlineAt!))return unconfirmed();
    }
    return result;
  },
};
export function roleReviewError(error: any): string {
  const code=error?.response?.data?.error;
  if(code==='fresh_mfa_required')return 'Eine höchstens fünf Minuten alte Anmeldung mit geprüftem OpenDirectory-TOTP ist erforderlich.';
  if(code==='review_changed' || code==='review_policy_changed')return 'Prüfung oder Richtlinie wurde geändert. Neu laden; nicht automatisch wiederholen.';
  if(code==='review_not_pending')return 'Diese Prüfung ist nicht mehr offen. Abgelaufene Rechte werden nicht wiederhergestellt.';
  if(code==='reviewer_unavailable')return 'Benannte Prüfer benötigen eine aktivierte kanonische Identität und aktuelle Prüfrechte.';
  if(code==='independent_reviewer_required')return 'Eigene Berechtigungen dürfen nicht selbst geprüft werden.';
  if(code==='global_administrator_required')return 'Geschützte Rollen erfordern globale Administration.';
  if(code==='review_policy_exists')return 'Für diese Rolle besteht bereits eine aktive Prüfrichtlinie.';
  return directoryError(error);
}
