GRANT USAGE ON SCHEMA :"license_schema" TO :"collector_role";
GRANT SELECT ON :"license_schema".license_capacity_sources,:"license_schema".license_capacity_runs TO :"collector_role";
GRANT INSERT(id,source_id,source_version,connector_version) ON :"license_schema".license_capacity_runs TO :"collector_role";
GRANT UPDATE(status,payload,error,retry_after) ON :"license_schema".license_capacity_runs TO :"collector_role";
GRANT EXECUTE ON FUNCTION :"license_schema".license_capacity_source(UUID) TO :"collector_role";
