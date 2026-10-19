import {api} from './api';
import {directoryUsers,DirectoryAccess} from './directoryUsers';

export interface DirectoryGroup {id:string;name:string;description?:string;members:string[];createdAt:string;revision:string}
export interface GroupProfile {name:string;description?:string|null}
export interface MembershipAdmission {required:true;membershipId:string;effective:boolean}
export interface GroupMembershipResult extends DirectoryGroup {membershipReview?:MembershipAdmission}

function identifier(value:string){if(typeof value!=='string'||value.length!==36||!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value))throw new Error('Ungültige kanonische Gruppen- oder Benutzer-ID.');return value;}
function version(value:unknown):value is string{return typeof value==='string'&&/^[1-9][0-9]{0,18}$/.test(value)&&!/[\s]/.test(value)&&(value.length<19||value<='9223372036854775807');}
export function groupEtag(group:DirectoryGroup){if(!version(group.revision))throw new Error('Ungültige Gruppenversion.');return `"group-${identifier(group.id)}-${group.revision}"`;}
export function parseGroup(value:any):DirectoryGroup{
 identifier(value?.id);
 if(typeof value.name!=='string'||!value.name.trim()||value.description!==undefined&&typeof value.description!=='string'
  ||!Array.isArray(value.members)||value.members.length>10000||new Set(value.members).size!==value.members.length||!version(value.revision)
  ||typeof value.createdAt!=='string'||!Number.isFinite(Date.parse(value.createdAt)))throw new Error('Gruppenantwort nicht bestätigt. Bitte neu laden.');
 value.members.forEach(identifier);return{id:value.id,name:value.name,description:value.description,members:[...value.members],createdAt:value.createdAt,revision:value.revision};
}
async function requireProtocol(field:'directoryReadProtocol'|'directoryCreationProtocol'|'directoryGroupMutationProtocol'){
 const access=await directoryUsers.access();if(access[field]!==1||access.userId===null||access.demoMode)throw new Error('Mandantengebundene Gruppenfunktion nicht bestätigt.');return access;
}
function changed(value:any,previous:DirectoryGroup){const result=parseGroup(value);if(result.id!==previous.id||BigInt(result.revision)<=BigInt(previous.revision))throw new Error('Gruppenänderung nicht bestätigt. Bitte neu laden.');return result;}

export const directoryGroups={
 access:():Promise<DirectoryAccess>=>directoryUsers.access(),
 async list():Promise<{groups:DirectoryGroup[];total:number}>{
  await requireProtocol('directoryReadProtocol');const {data}=await api.get('/api/groups');
  if(!Array.isArray(data?.groups)||data.groups.length>10000||!Number.isSafeInteger(data.total)||data.total!==data.groups.length)throw new Error('Gruppenliste nicht bestätigt.');
  const groups=data.groups.map(parseGroup);if(new Set(groups.map((group:DirectoryGroup)=>group.id)).size!==groups.length)throw new Error('Doppelte Gruppen-ID in der Verzeichnisantwort.');return{groups,total:data.total};
 },
 async get(groupId:string){const target=identifier(groupId);await requireProtocol('directoryReadProtocol');const group=parseGroup((await api.get('/api/groups/'+target)).data);if(group.id!==target)throw new Error('Gruppenantwort stimmt nicht überein.');return group;},
 async create(profile:GroupProfile){await requireProtocol('directoryCreationProtocol');const group=parseGroup((await api.post('/api/groups',profile)).data);if(group.members.length)throw new Error('Leere neue Gruppe nicht bestätigt.');return group;},
 async update(group:DirectoryGroup,patch:Partial<GroupProfile>){
  const target=identifier(group.id);const expected=groupEtag(group);await requireProtocol('directoryGroupMutationProtocol');const result=changed((await api.put('/api/groups/'+target,patch,{headers:{'If-Match':expected}})).data,group);
  if(patch.name!==undefined&&result.name!==patch.name.trim()||Object.hasOwn(patch,'description')&&(result.description||null)!==(patch.description?.trim()||null))throw new Error('Angefragte Gruppenfelder nicht bestätigt.');return result;
 },
 async remove(group:DirectoryGroup){const target=identifier(group.id);const expected=groupEtag(group);await requireProtocol('directoryGroupMutationProtocol');if((await api.delete('/api/groups/'+target,{headers:{'If-Match':expected}})).status!==204)throw new Error('Gruppenlöschung nicht bestätigt. Bitte neu laden.');},
 async add(group:DirectoryGroup,userId:string):Promise<GroupMembershipResult>{
  const target=identifier(group.id);const member=identifier(userId);const expected=groupEtag(group);await requireProtocol('directoryGroupMutationProtocol');const {data}=await api.post('/api/groups/'+target+'/members',{userId:member},{headers:{'If-Match':expected}});const result:GroupMembershipResult=changed(data,group);
  if(!result.members.includes(member))throw new Error('Mitgliedschaft nicht bestätigt.');if(data.membershipReview!==undefined){const review=data.membershipReview;if(!review||Object.keys(review).length!==3||review.required!==true||typeof review.effective!=='boolean')throw new Error('Gruppenprüfstatus nicht bestätigt.');identifier(review.membershipId);result.membershipReview={required:true,membershipId:review.membershipId,effective:review.effective};}return result;
 },
 async removeMember(group:DirectoryGroup,userId:string){const target=identifier(group.id);const member=identifier(userId);const expected=groupEtag(group);await requireProtocol('directoryGroupMutationProtocol');const result=changed((await api.delete('/api/groups/'+target+'/members/'+member,{headers:{'If-Match':expected}})).data,group);if(result.members.includes(member))throw new Error('Mitgliedschaftsentfernung nicht bestätigt.');return result;},
};
