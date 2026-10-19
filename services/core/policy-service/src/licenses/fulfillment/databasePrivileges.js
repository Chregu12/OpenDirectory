'use strict';

async function assertWorkerDatabase(database) {
  const role=(await database.query(`SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,current_user<>session_user AS assumed_role,
    EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) AS membership FROM pg_roles WHERE rolname=current_user`)).rows[0];
  if (!role || Object.values(role).some(value=>value!==false)) throw new Error('Fulfillment requires a dedicated nonadministrative database identity');
  const ownership=(await database.query("SELECT has_schema_privilege(current_user,current_schema(),'CREATE') OR has_database_privilege(current_user,current_database(),'CREATE') AS privileged")).rows[0];
  if (ownership.privileged) throw new Error('Fulfillment must not own or create its authorization schema');
  if (!(await database.query("SELECT has_column_privilege(current_user,'license_catalog','id','SELECT') AND has_column_privilege(current_user,'license_catalog','business_tenant_id','SELECT') AND has_column_privilege(current_user,'license_subjects','business_tenant_id','SELECT') AS allowed")).rows[0]?.allowed) throw new Error('Fulfillment requires legacy ownership read fences');
  for(const table of ['license_capacity_sources','license_capacity_runs','license_capacity_events','license_capacity_outbox','license_capacity_budgets','license_capacity_reservations','license_capacity_admission_events','license_capacity_admission_outbox']){
    if((await database.query("SELECT has_table_privilege(current_user,$1,'INSERT,UPDATE,DELETE,TRUNCATE') OR has_any_column_privilege(current_user,$1,'INSERT,UPDATE') AS privileged",[table])).rows[0].privileged)throw new Error('Fulfillment must not publish or configure capacity observations');
  }
  for (const table of ['license_catalog','license_assignments','license_assignment_sources','license_group_rules','license_group_observations','license_group_member_leases','license_group_lease_audit','license_grants','license_grant_events','license_review_policies','license_review_leases','license_review_audit','license_scope_grants','license_scope_audit','license_scope_eligibilities','license_scope_activation_requests','license_scope_pim_audit','license_scope_activation_policies','license_scope_policy_audit','license_scope_review_policies','license_scope_review_leases','license_scope_review_fences','license_scope_review_audit','license_subjects','license_requests','license_provider_connectors','license_provider_products','license_provider_subjects']) {
    const access=(await database.query("SELECT has_table_privilege(current_user,$1,'DELETE') OR has_table_privilege(current_user,$1,'TRUNCATE') OR has_any_column_privilege(current_user,$1,'INSERT,UPDATE') AS privileged",[table])).rows[0];
    if (access.privileged) throw new Error('Fulfillment may not change entitlement or provider configuration tables');
  }
}
module.exports = { assertWorkerDatabase };
