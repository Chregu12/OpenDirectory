BEGIN;
SELECT set_config('search_path',format('%I,pg_catalog,pg_temp',:'license_schema'),true);
SELECT set_config('opendirectory.capacity_source_reason',:'reason',true);
CREATE TEMP TABLE capacity_source_review_guard(valid BOOLEAN NOT NULL CHECK(valid)) ON COMMIT DROP;
INSERT INTO capacity_source_review_guard(valid)
SELECT COALESCE((SELECT true FROM license_provider_connectors WHERE id=:'connector_id'::uuid AND version=:'connector_version'::bigint AND enabled FOR SHARE),false);
INSERT INTO license_capacity_sources(id,connector_id,database_role,graph_client_id)
VALUES(:'source_id'::uuid,:'connector_id'::uuid,:'collector_role'::name,:'graph_client_id'::uuid)
RETURNING id,connector_id,database_role,graph_client_id,enabled,version;
COMMIT;
