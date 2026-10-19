'use strict';
const{createHash}=require('node:crypto');
function groupSnapshot(input,{now=Date.now(),revisions={}}={}){
 const memberIds=input.memberIds||[];const memberships=input.memberships||memberIds.map(userId=>{const hash=createHash('sha256').update(input.groupId+':'+userId).digest('hex');return{userId,membershipId:`${hash.slice(0,8)}-${hash.slice(8,12)}-4${hash.slice(13,16)}-8${hash.slice(17,20)}-${hash.slice(20,32)}`,eligibilityRevision:revisions[userId]||'1',reviewDeadlineAt:null};});
 return{schemaVersion:3,name:'Owned leased directory team',revision:'1',deleted:false,memberIds,inactiveMemberIds:[],unresolvedMemberIds:[],viewerUserId:null,viewerEnabled:null,sourceAuthorization:null,...input,schemaVersion:3,observedAt:new Date(now).toISOString(),validUntil:new Date(now+300000).toISOString(),memberships};
}
module.exports={groupSnapshot};
