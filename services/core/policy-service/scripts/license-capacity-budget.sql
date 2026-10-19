BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='15s';
SELECT set_config('search_path',format('%I,pg_catalog,pg_temp', :'license_schema'),true);
SELECT set_config('opendirectory.capacity_budget_review','external-usage-and-all-attempts-reviewed',true);
INSERT INTO :"license_schema".license_capacity_budgets(product_id,previous_id,run_id,product_version,reason,source_id,source_version,connector_version,units,reviewed_by)
VALUES(:'product_id'::uuid,NULLIF(:'previous_budget_id','')::uuid,:'run_id'::uuid,:'product_version'::bigint,:'reason',
 '00000000-0000-0000-0000-000000000000'::uuid,0,0,0,session_user)
RETURNING id,product_id,previous_id,run_id,units,source_id,source_version,connector_version,product_version,created_at;
COMMIT;
