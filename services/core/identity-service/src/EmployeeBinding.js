'use strict';
async function employeeBinding(client,userId){
 const row=(await client.query(`SELECT enrollment.id,enrollment.issuer,enrollment.subject,enrollment.user_id,enrollment.tenant_id,enrollment.console_client_id,enrollment.creation_event_id,enrollment.link_revision,
  identity_employee_valid(enrollment.id) AS valid,
  identity_tenant_user_enabled(enrollment.user_id) AND enrollment.tenant=jsonb_build_object('id',tenant.id,'version',tenant.version::text,'generation',tenant.generation::text)
   AND EXISTS(SELECT 1 FROM identity_subject_links WHERE issuer=enrollment.issuer AND subject=enrollment.subject AND user_id=enrollment.user_id AND authorization_revision=enrollment.link_revision) AS active
  FROM identity_employee_enrollments enrollment JOIN identity_tenants tenant ON tenant.id=enrollment.tenant_id WHERE enrollment.user_id=$1 AND enrollment.state='active'`,[userId])).rows[0];
 if(!row)return null;if(row.valid!==true)throw Object.assign(new Error('employee_enrollment_evidence_unavailable'),{status:503,code:'employee_enrollment_evidence_unavailable'});
 return{active:row.active===true,issuer:row.issuer,subject:row.subject,consoleClientId:row.console_client_id,
  binding:{schemaVersion:1,issuer:row.issuer,invitationId:row.id,subjectId:row.subject,userId:row.user_id,tenantId:row.tenant_id,acceptanceEventId:row.creation_event_id,linkRevision:String(row.link_revision)}};
}
module.exports={employeeBinding};
