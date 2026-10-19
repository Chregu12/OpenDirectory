'use strict';

const { createHash } = require('crypto');
const { LicenseError } = require('./LicenseError');
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const{SCHEMA_VERSION,CONTENT_HASH_SCHEMA,LEASE_SECONDS,MAX_MEMBERS,MAX_RESPONSE_BYTES,MAX_SOURCE_GRANT_SECONDS}=require('../../../../../packages/group-license-lease-contract');

function normalizeSnapshot(snapshot, groupId) {
  const invalid = () => { throw new LicenseError(503, 'Invalid authoritative group snapshot'); };
  const fields=['schemaVersion','groupId','name','revision','deleted','memberIds','inactiveMemberIds','unresolvedMemberIds','viewerUserId','viewerEnabled','observedAt','validUntil','memberships','sourceAuthorization'];
  if (!snapshot || typeof snapshot!=='object'||Array.isArray(snapshot)||fields.some(field=>!Object.hasOwn(snapshot,field))||Object.keys(snapshot).some(field=>!fields.includes(field)&&field!=='hash')
    || snapshot.schemaVersion !== SCHEMA_VERSION || snapshot.groupId !== groupId.toLowerCase() || !UUID.test(snapshot.groupId)
    || typeof snapshot.deleted !== 'boolean' || typeof snapshot.revision !== 'string' || !/^[1-9]\d{0,18}$/.test(snapshot.revision)
    || BigInt(snapshot.revision) > 9223372036854775807n) invalid();
  const arrays = ['memberIds', 'inactiveMemberIds', 'unresolvedMemberIds'];
  if (arrays.some(field => !Array.isArray(snapshot[field])) || arrays.reduce((total, field) => total + snapshot[field].length, 0) > MAX_MEMBERS) invalid();
  if (snapshot.unresolvedMemberIds.length) throw new LicenseError(503, 'Group contains unresolved identities');
  const members = [...snapshot.memberIds, ...snapshot.inactiveMemberIds];
  if (members.some(member => typeof member !== 'string' || !UUID.test(member) || member !== member.toLowerCase()) || new Set(members).size !== members.length) invalid();
  if (snapshot.deleted && members.length) invalid();
  if (!snapshot.deleted && (typeof snapshot.name !== 'string' || !snapshot.name.trim() || snapshot.name.length > 255)) invalid();
  const date=value=>typeof value==='string'&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value;
  if(!date(snapshot.observedAt)||!date(snapshot.validUntil)||Date.parse(snapshot.validUntil)-Date.parse(snapshot.observedAt)!==LEASE_SECONDS*1000
    ||!Array.isArray(snapshot.memberships)||snapshot.memberships.length!==snapshot.memberIds.length||snapshot.deleted&&snapshot.name!==null)invalid();
  const activeIds=new Set(snapshot.memberIds);
  const byUser=new Map();for(const member of snapshot.memberships){if(!member||Object.keys(member).length!==4||typeof member.userId!=='string'||!activeIds.has(member.userId)||byUser.has(member.userId)
    ||typeof member.membershipId!=='string'||!UUID.test(member.membershipId)||member.membershipId!==member.membershipId.toLowerCase()||typeof member.eligibilityRevision!=='string'||!/^[1-9]\d{0,18}$/.test(member.eligibilityRevision)||BigInt(member.eligibilityRevision)>9223372036854775807n
    ||member.reviewDeadlineAt!==null&&(!date(member.reviewDeadlineAt)||Date.parse(member.reviewDeadlineAt)<=Date.parse(snapshot.observedAt)))invalid();byUser.set(member.userId,{userId:member.userId,membershipId:member.membershipId,eligibilityRevision:member.eligibilityRevision,reviewDeadlineAt:member.reviewDeadlineAt});}
  if(new Set(snapshot.memberships.map(member=>member.membershipId)).size!==snapshot.memberships.length)invalid();
  const result = {schemaVersion:SCHEMA_VERSION,unresolvedMemberIds:[],groupId:snapshot.groupId,revision:snapshot.revision,deleted:snapshot.deleted,name:snapshot.name,
    memberIds:[...snapshot.memberIds].sort(),inactiveMemberIds:[...snapshot.inactiveMemberIds].sort(),memberships:[...byUser.values()].sort((first,second)=>first.userId.localeCompare(second.userId))};
  result.hash=createHash('sha256').update(JSON.stringify({...result,schemaVersion:CONTENT_HASH_SCHEMA,revision:undefined})).digest('hex');
  if(snapshot.hash!==undefined&&snapshot.hash!==result.hash)invalid();
  if (snapshot.viewerUserId !== null && (typeof snapshot.viewerUserId !== 'string' || !UUID.test(snapshot.viewerUserId) || snapshot.viewerUserId!==snapshot.viewerUserId.toLowerCase()||typeof snapshot.viewerEnabled !== 'boolean')||snapshot.viewerUserId===null&&snapshot.viewerEnabled!==null) invalid();
  result.viewerUserId = snapshot.viewerUserId || null;
  result.viewerEnabled = snapshot.viewerEnabled ?? null;
  result.observedAt=snapshot.observedAt;result.validUntil=snapshot.validUntil;
  const consent=snapshot.sourceAuthorization;
  if(consent!==null&&(result.viewerUserId!==null||result.viewerEnabled!==null))invalid();
  if(consent!==null&&(!consent||typeof consent!=='object'||Array.isArray(consent)||Object.keys(consent).length!==6||!UUID.test(consent.grantId)||consent.grantId!==consent.grantId.toLowerCase()
    ||typeof consent.version!=='string'||!/^[1-9]\d{0,18}$/.test(consent.version)||BigInt(consent.version)>9223372036854775807n
    ||typeof consent.clientRevision!=='string'||!/^[1-9]\d{0,18}$/.test(consent.clientRevision)||BigInt(consent.clientRevision)>9223372036854775807n
    ||typeof consent.clientId!=='string'||!/^(?!\.{1,2}$)[A-Za-z0-9._~-]{1,255}$/.test(consent.clientId)||typeof consent.issuer!=='string'||!consent.issuer||consent.issuer.length>2048||/\s/.test(consent.issuer)
    ||!date(consent.expiresAt)||Date.parse(consent.expiresAt)<=Date.parse(snapshot.observedAt)||Date.parse(consent.expiresAt)>Date.parse(snapshot.observedAt)+MAX_SOURCE_GRANT_SECONDS*1000))invalid();
  result.sourceAuthorization=consent===null?null:{grantId:consent.grantId,version:consent.version,issuer:consent.issuer,clientId:consent.clientId,clientRevision:consent.clientRevision,expiresAt:consent.expiresAt};
  return result;
}

class GroupSnapshotClient {
  constructor({ baseUrl = process.env.IDENTITY_SERVICE_URL || 'http://identity-service:3001', fetchImpl = global.fetch } = {}) {
    this.baseUrl = new URL(baseUrl);
    if (!['http:', 'https:'].includes(this.baseUrl.protocol) || this.baseUrl.username || this.baseUrl.password || this.baseUrl.search || this.baseUrl.hash || this.baseUrl.pathname !== '/') throw new Error('Invalid identity service URL');
    this.fetch = fetchImpl;
  }

  async read(path, authorization,maximumBytes=2*1024*1024) {
    if (typeof authorization !== 'string' || !/^Bearer [^\r\n]+$/.test(authorization)) throw new LicenseError(503, 'Group source credentials are unavailable');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await this.fetch(new URL(path, this.baseUrl), {
        headers: { Authorization: authorization }, redirect: 'error', cache: 'no-store', signal: controller.signal,
      });
      if(response.status===200 && path.endsWith('/snapshot') && response.headers.get('x-od-license-snapshot-protocol')!=='1')throw new LicenseError(503,'Tenant-bound identity snapshot receiver required');
      if (response.status === 401 || response.status === 403){const error=new LicenseError(403,'Group source access denied');error.upstreamStatus=response.status;throw error;}
      if (response.status === 404) throw new LicenseError(404, 'Authoritative group not found');
      if (response.status !== 200){const error=new LicenseError(503,'Group source unavailable');error.upstreamStatus=response.status;error.sourceUnavailable=response.status>=500;if(response.status===429){const value=response.headers.get('retry-after');const seconds=/^[1-9]\d*$/.test(value)?Number(value):Math.ceil((Date.parse(value)-Date.now())/1000);error.retryAfter=Number.isFinite(seconds)&&seconds>0?Math.min(3600,seconds):60;}throw error;}
      const chunks = []; let length = 0;
      for await (const chunk of response.body) {
        length += chunk.length;
        if (length > maximumBytes) { controller.abort(); throw new LicenseError(503, 'Group snapshot exceeds response limit'); }
        chunks.push(Buffer.from(chunk));
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) {
      if (error instanceof LicenseError) throw error;
      const unavailable=new LicenseError(503,'Group source unavailable');unavailable.sourceUnavailable=true;throw unavailable;
    } finally { clearTimeout(timer); }
  }

  async snapshot(groupId, authorization) {
    if (typeof groupId !== 'string' || !UUID.test(groupId)) throw new LicenseError(400, 'A canonical identity group UUID is required');
    const result=normalizeSnapshot(await this.read(`/api/license-groups/${groupId.toLowerCase()}/snapshot`, authorization,MAX_RESPONSE_BYTES), groupId);
    if(Date.parse(result.observedAt)>Date.now()+5000||Date.parse(result.validUntil)<=Date.now()||result.sourceAuthorization&&Date.parse(result.sourceAuthorization.expiresAt)<=Date.now()||result.memberships.some(member=>member.reviewDeadlineAt!==null&&Date.parse(member.reviewDeadlineAt)<=Date.now()))throw new LicenseError(503,'Group source observation is not current');return result;
  }

  async subject(authorization, expected) {
    let value;
    try { value = await this.read('/api/identity/subject', authorization); }
    catch (error) { if (error.status === 404) throw new LicenseError(503, 'Identity binding source unavailable'); throw error; }
    if (!value || value.schemaVersion !== 1 || typeof value.issuer !== 'string' || !value.issuer || typeof value.subject !== 'string' || !value.subject
      || value.issuer !== expected?.issuer || value.subject !== expected?.subject
      || (value.userId !== null && (typeof value.userId !== 'string' || !UUID.test(value.userId) || value.userId !== value.userId.toLowerCase() || typeof value.enabled !== 'boolean'))
      || (value.userId === null && value.enabled !== null)) throw new LicenseError(503, 'Invalid authoritative identity binding');
    return { issuer: value.issuer, subject: value.subject, userId: value.userId, enabled: value.enabled };
  }

  async user(userId, authorization) {
    if (typeof userId !== 'string' || !UUID.test(userId) || userId !== userId.toLowerCase()) throw new LicenseError(400, 'A canonical directory user UUID is required');
    try { return normalizeUserSnapshot(await this.read(`/api/license-users/${userId}/snapshot`, authorization), userId); }
    catch (error) { if (error.status === 404) throw new LicenseError(404, 'Authoritative identity user not found'); throw error; }
  }

  async reviewer(userId, authorization) {
    if (typeof userId !== 'string' || !UUID.test(userId) || userId !== userId.toLowerCase()) throw new LicenseError(400, 'Canonical reviewer UUID required');
    const value = await this.read(`/api/license-reviewers/${userId}/snapshot`, authorization);
    if (!value || Object.keys(value).length !== 5 || value.schemaVersion !== 1 || value.userId !== userId
      || ['enabled', 'linked', 'canReview'].some(field => typeof value[field] !== 'boolean')
      || value.canReview && (!value.enabled || !value.linked)) throw new LicenseError(503, 'Invalid authoritative reviewer snapshot');
    return value;
  }

  async scopeReviewer(userId,authorization){
    if(typeof userId!=='string'||!UUID.test(userId)||userId!==userId.toLowerCase())throw new LicenseError(400,'Canonical scope reviewer UUID required');
    const value=await this.read(`/api/license-scope-reviewers/${userId}/snapshot`,authorization);
    if(!value||Object.keys(value).length!==5||value.schemaVersion!==1||value.userId!==userId||typeof value.enabled!=='boolean'||typeof value.linked!=='boolean'||typeof value.canReview!=='boolean'||value.canReview&&(!value.enabled||!value.linked))throw new LicenseError(503,'Invalid scope reviewer snapshot');return value;
  }

  async activationReviewer(userId, authorization) {
    if (typeof userId !== 'string' || !UUID.test(userId) || userId !== userId.toLowerCase()) throw new LicenseError(400, 'Canonical reviewer UUID required');
    const value = await this.read(`/api/license-activation-reviewers/${userId}/snapshot`, authorization);
    if (!value || Object.keys(value).length !== 6 || value.schemaVersion !== 1 || value.userId !== userId || typeof value.enabled !== 'boolean'
      || typeof value.linked !== 'boolean' || typeof value.revision !== 'string' || !/^[1-9]\d{0,18}$/.test(value.revision) || BigInt(value.revision)>9223372036854775807n
      || value.reviewRevision!==null&&(typeof value.reviewRevision!=='string'||!/^[a-f0-9]{64}$/.test(value.reviewRevision)||!value.enabled||!value.linked)) throw new LicenseError(503, 'Invalid activation reviewer snapshot');
    return value;
  }

  async delegate(userId, authorization) {
    if (typeof userId !== 'string' || !UUID.test(userId) || userId !== userId.toLowerCase()) throw new LicenseError(400, 'Canonical delegate UUID required');
    const value = await this.read(`/api/license-delegates/${userId}/snapshot`, authorization);
    if (!value || Object.keys(value).length !== 6 || value.schemaVersion !== 1 || value.userId !== userId
      || typeof value.revision !== 'string' || !/^[1-9]\d{0,18}$/.test(value.revision) || BigInt(value.revision) > 9223372036854775807n
      || typeof value.enabled !== 'boolean' || typeof value.linked !== 'boolean'
      || value.delegationRevision !== null && (typeof value.delegationRevision !== 'string' || !/^[a-f0-9]{64}$/.test(value.delegationRevision) || !value.enabled || !value.linked)) throw new LicenseError(503, 'Invalid delegate authority snapshot');
    return value;
  }
}

function normalizeUserSnapshot(value, userId) {
  if (!value || value.schemaVersion !== 1 || typeof userId !== 'string' || !UUID.test(userId) || userId !== userId.toLowerCase() || value.userId !== userId
    || typeof value.revision !== 'string' || !/^[1-9]\d{0,18}$/.test(value.revision) || BigInt(value.revision) > 9223372036854775807n
    || typeof value.enabled !== 'boolean' || typeof value.deleted !== 'boolean' || (value.deleted && value.enabled)) throw new LicenseError(503, 'Invalid authoritative user eligibility snapshot');
  return { schemaVersion: 1, userId, revision: value.revision, enabled: value.enabled, deleted: value.deleted };
}

module.exports = { GroupSnapshotClient, normalizeSnapshot, normalizeUserSnapshot };
