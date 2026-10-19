'use strict';
const{LicenseError}=require('./LicenseError');
const{isDeepStrictEqual}=require('node:util');
const fail=message=>{throw new LicenseError(409,message);};
class GroupDirectoryLeases{
 async assertCurrent(client,snapshot,members){
  const deadlines=[snapshot.validUntil,...(snapshot.sourceAuthorization?[snapshot.sourceAuthorization.expiresAt]:[]),...snapshot.memberships.filter(member=>members.includes(member.userId)&&member.reviewDeadlineAt!==null).map(member=>member.reviewDeadlineAt)];
  if(!(await client.query("SELECT 1 WHERE (SELECT min(deadline) FROM unnest($1::timestamptz[]) deadline)>license_now() AND $2::timestamptz<=license_now()+interval '5 seconds'",[deadlines,snapshot.observedAt])).rows.length)fail('group_directory_observation_expired');
 }
 async observe(client,rule,snapshot,members){
  const current=(await client.query('SELECT * FROM license_group_observations WHERE grant_id=$1 FOR UPDATE',[rule.grant_id])).rows[0];
  if(current&&(BigInt(snapshot.revision)<BigInt(current.source_revision)||snapshot.revision===String(current.source_revision)&&snapshot.hash!==current.source_hash||Date.parse(snapshot.observedAt)<current.observed_at.getTime()))fail('stale_group_directory_observation');
  if(!(await client.query("SELECT 1 WHERE $1::timestamptz>license_now() AND $2::timestamptz<=license_now()+interval '5 seconds'",[snapshot.validUntil,snapshot.observedAt])).rows.length)fail('group_directory_observation_expired');
  await client.query("SELECT set_config('opendirectory.group_snapshot',$1,true)",[JSON.stringify({...snapshot,licenseId:rule.license_id,grantId:rule.grant_id})]);
  let observation=current;
  if(!current||snapshot.revision!==String(current.source_revision)||snapshot.hash!==current.source_hash||Date.parse(snapshot.observedAt)!==current.observed_at.getTime()||!isDeepStrictEqual(current.source_authorization,snapshot.sourceAuthorization)){
   observation=(await client.query(`INSERT INTO license_group_observations(grant_id,license_id,group_id,source_revision,source_hash,observed_at,valid_until,source_authorization,source_authorization_deadline) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
    ON CONFLICT(grant_id) DO UPDATE SET version=license_group_observations.version+1,source_revision=EXCLUDED.source_revision,source_hash=EXCLUDED.source_hash,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until,source_authorization=EXCLUDED.source_authorization,source_authorization_deadline=EXCLUDED.source_authorization_deadline RETURNING *`,[rule.grant_id,rule.license_id,rule.group_id,snapshot.revision,snapshot.hash,snapshot.observedAt,snapshot.validUntil,snapshot.sourceAuthorization?JSON.stringify(snapshot.sourceAuthorization):null,snapshot.sourceAuthorization?.expiresAt||null])).rows[0];
  }
  for(const userId of members){const member=snapshot.memberships.find(value=>value.userId===userId);if(!member)fail('group_member_lease_missing');
   await client.query(`INSERT INTO license_group_member_leases(grant_id,user_id,membership_id,eligibility_revision,observation_version,source_revision,review_deadline_at,valid_until)
    VALUES($1,$2,$3,$4,$5,$6,$7,LEAST($8::timestamptz,$7::timestamptz,$9::timestamptz)) ON CONFLICT(grant_id,user_id) DO UPDATE SET membership_id=EXCLUDED.membership_id,eligibility_revision=EXCLUDED.eligibility_revision,
    observation_version=EXCLUDED.observation_version,source_revision=EXCLUDED.source_revision,review_deadline_at=EXCLUDED.review_deadline_at,valid_until=EXCLUDED.valid_until
    WHERE license_group_member_leases.observation_version<>EXCLUDED.observation_version`,[rule.grant_id,userId,member.membershipId,member.eligibilityRevision,observation.version,snapshot.revision,member.reviewDeadlineAt,snapshot.validUntil,snapshot.sourceAuthorization?.expiresAt||null]);
  }
  return observation;
 }
}
module.exports={GroupDirectoryLeases};
