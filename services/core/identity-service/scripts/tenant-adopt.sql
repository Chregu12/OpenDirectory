BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='15s';
SELECT set_config('opendirectory.tenant_review','explicit-offline-owner-review',true),set_config('opendirectory.tenant_reason',:'reason',true);
SELECT :"identity_schema".identity_tenant_adopt(:'tenant_id'::uuid,:'expected_version'::bigint,:'manifest'::jsonb);
SELECT ownership.resource_kind,ownership.resource_id,ownership.tenant_id,ownership.reviewed_version,ownership.generation
FROM :"identity_schema".identity_tenant_ownership ownership JOIN jsonb_array_elements(:'manifest'::jsonb) item
ON ownership.resource_kind=item->>'kind' AND ownership.resource_id=(item->>'resourceId')::uuid WHERE ownership.tenant_id=:'tenant_id'::uuid;
COMMIT;
