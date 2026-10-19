'use strict';
const { readRoleState }=require('./RoleState');
const {createHash}=require('crypto');const{validRevision}=require('../../../../packages/identity-authorization-contract');
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
class LicenseActivationReviewerSnapshotStore {
  constructor(database){this.database=database;}
  async snapshot(userId,viewer,canReadAny){
    if(typeof userId!=='string'||!UUID.test(userId))throw Object.assign(new Error('Canonical activation reviewer UUID required'),{status:400});
    return this.database.transaction(async client=>{
      if(!canReadAny&&(await client.query('SELECT user_id FROM identity_subject_links WHERE issuer=$1 AND subject=$2',[viewer.issuer,viewer.subject])).rows[0]?.user_id!==userId)throw Object.assign(new Error('Activation reviewer snapshot denied'),{status:403});
      const row=(await client.query('SELECT identity_tenant_user_enabled(users.id) AS enabled,users.eligibility_revision,link.authorization_revision AS link_revision,link.user_id IS NOT NULL AS linked FROM users LEFT JOIN identity_subject_links link ON link.user_id=users.id AND link.issuer=$2 WHERE users.id=$1',[userId,viewer.issuer])).rows[0];
      if(!row)throw Object.assign(new Error('Activation reviewer not found'),{status:404});
      if(row.linked&&!validRevision(String(row.link_revision)))throw Object.assign(new Error('Reviewer link authority unavailable'),{status:503});
      const state=await readRoleState(client,userId,{scopeReviewerEvidence:true});
      return{schemaVersion:1,userId,revision:String(row.eligibility_revision),enabled:row.enabled,linked:row.linked,reviewRevision:row.enabled&&row.linked&&state.scopeReviewerRevision?createHash('sha256').update(JSON.stringify(['license-scope-reviewer-link-v1',viewer.issuer,String(row.link_revision),state.scopeReviewerRevision])).digest('hex'):null};
    },{readOnly:true});
  }
}
module.exports={LicenseActivationReviewerSnapshotStore};
