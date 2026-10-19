BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='15s';
SELECT set_config('opendirectory.tenant_review','explicit-offline-owner-review',true),set_config('opendirectory.tenant_reason',:'reason',true);
SELECT :"identity_schema".identity_tenant_enable(:'tenant_id'::uuid,:'expected_version'::bigint,:'enabled'::boolean);
COMMIT;
