GRANT USAGE ON SCHEMA :"license_schema" TO :"worker_role";
GRANT SELECT(id,business_tenant_id) ON :"license_schema".license_catalog TO :"worker_role";
GRANT SELECT(id,license_id,assignee_type,assignee_id,expires_at,eligibility_revision)
  ON :"license_schema".license_assignments TO :"worker_role";
GRANT SELECT(user_id,disabled,directory_enabled,directory_deleted,directory_revision,business_tenant_id)
  ON :"license_schema".license_subjects TO :"worker_role";
GRANT SELECT ON :"license_schema".license_provider_connectors,:"license_schema".license_provider_products,:"license_schema".license_provider_subjects TO :"worker_role";
GRANT SELECT,INSERT,UPDATE ON :"license_schema".license_fulfillment_targets,:"license_schema".license_provider_limits TO :"worker_role";
GRANT INSERT ON :"license_schema".license_fulfillment_changes,:"license_schema".license_fulfillment_events TO :"worker_role";
GRANT EXECUTE ON FUNCTION :"license_schema".license_fulfillment_refresh(UUID,UUID,JSONB,BOOLEAN) TO :"worker_role";
GRANT EXECUTE ON FUNCTION :"license_schema".license_capacity_dispatch(UUID,UUID) TO :"worker_role";
