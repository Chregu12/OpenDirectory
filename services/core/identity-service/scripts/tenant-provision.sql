BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='15s';
SELECT set_config('opendirectory.tenant_review','explicit-offline-owner-review',true),set_config('opendirectory.tenant_reason',:'reason',true);
INSERT INTO :"identity_schema".identity_tenants(id,external_key,display_name)
VALUES(:'tenant_id'::uuid,:'external_key',:'display_name') RETURNING id,external_key,enabled,version,generation;
COMMIT;
