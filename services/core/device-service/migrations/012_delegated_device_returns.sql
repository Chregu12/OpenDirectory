BEGIN;
-- Device identity remains independently live-checked; retain exact selected grant/PIM provenance.
CREATE OR REPLACE FUNCTION device_delegation_valid(source JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE grant_row JSONB;selected JSONB;ordinal BIGINT;keys TEXT[];
BEGIN
 IF NOT source ? 'delegation' THEN RETURN true;END IF;
 IF jsonb_typeof(source->'delegation') IS DISTINCT FROM 'object' OR (source->'delegation')-ARRAY['grants']<>'{}'::jsonb
  OR jsonb_typeof(source#>'{delegation,grants}') IS DISTINCT FROM 'array' OR jsonb_typeof(source->'permissions') IS DISTINCT FROM 'array'
  OR jsonb_array_length(source#>'{delegation,grants}')<>jsonb_array_length(source->'permissions') OR jsonb_array_length(source->'permissions')<1 THEN RETURN false;END IF;
 FOR grant_row,ordinal IN SELECT item,number FROM jsonb_array_elements(source#>'{delegation,grants}') WITH ORDINALITY AS grants(item,number) LOOP
  selected=grant_row->'source';keys=ARRAY['id','roleId','roleRevision','scopeType','ouId','targetType','targetId','membershipId','validUntil'];
  IF selected ? 'activationId' THEN keys=keys||ARRAY['activationId','mfaRevision','authTime','issuer','subject','actorContext'];END IF;
  IF jsonb_typeof(grant_row) IS DISTINCT FROM 'object' OR grant_row-ARRAY['permission','source']<>'{}'::jsonb
   OR grant_row->'permission' IS DISTINCT FROM source->'permissions'->(ordinal::int-1) OR jsonb_typeof(selected) IS DISTINCT FROM 'object'
   OR selected-keys<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(selected))<>cardinality(keys)
   OR selected->>'scopeType' IS DISTINCT FROM 'tenant' OR selected->'ouId' IS DISTINCT FROM 'null'::jsonb
   OR NOT coalesce(selected->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT coalesce(selected->>'roleId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT coalesce(selected->>'targetId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT coalesce(selected->>'roleRevision' ~ '^[1-9][0-9]{0,18}$',false)
   OR NOT coalesce(selected->>'validUntil' ~ '^[1-9][0-9]*$',false) OR (selected->>'validUntil')::numeric<(source->>'validUntil')::numeric
   OR (CASE WHEN selected->>'targetType'='user' THEN selected->>'targetId' IS DISTINCT FROM source->>'actorUserId' OR selected->'membershipId' IS DISTINCT FROM 'null'::jsonb
      WHEN selected->>'targetType'='group' THEN NOT coalesce(selected->>'membershipId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) ELSE true END)
   OR selected ? 'activationId' AND (NOT coalesce(selected->>'activationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) OR NOT coalesce(selected->>'mfaRevision' ~ '^[1-9][0-9]{0,18}$',false) OR NOT coalesce(selected->>'authTime' ~ '^[1-9][0-9]*$',false) OR selected->'actorContext' IS DISTINCT FROM source->'context' OR selected->>'issuer' IS DISTINCT FROM source->>'issuer' OR selected->>'subject' IS DISTINCT FROM source->>'subject')
   THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
 EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION device_returns_source(source JSONB,offboarding BOOLEAN,live BOOLEAN DEFAULT true) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent JSONB;target JSONB;expected_keys TEXT[];
BEGIN
 expected_keys=ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'];
 IF offboarding THEN expected_keys=expected_keys||ARRAY['deviceOffboardingReturnsProtocol','parent'];END IF;
 IF source ? 'delegation' THEN expected_keys=expected_keys||ARRAY['delegation'];END IF;
 IF jsonb_typeof(source) IS DISTINCT FROM 'object' OR source-expected_keys<>'{}'::jsonb OR (SELECT count(*) FROM jsonb_object_keys(source))<>cardinality(expected_keys)
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(source->'issuer') IS DISTINCT FROM 'string' OR length(source->>'issuer')=0
  OR jsonb_typeof(source->'subject') IS DISTINCT FROM 'string' OR length(source->>'subject')=0 OR jsonb_typeof(source->'tokenId') IS DISTINCT FROM 'string' OR length(source->>'tokenId')=0
  OR jsonb_typeof(source->'expiresAt') IS DISTINCT FROM 'number' OR jsonb_typeof(source->'validUntil') IS DISTINCT FROM 'number'
  OR NOT(source->>'expiresAt' ~ '^[1-9][0-9]*$') OR NOT(source->>'validUntil' ~ '^[1-9][0-9]*$')
  OR (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric
  OR (CASE WHEN source ? 'delegation' THEN NOT device_delegation_valid(source) OR NOT source->'permissions' ? 'devices.inventory.read'
    OR source->'permissions' IS DISTINCT FROM (SELECT jsonb_agg(permission ORDER BY ordinal) FROM jsonb_array_elements_text('["devices.inventory.read","devices.inventory.create","devices.inventory.assign"]'::jsonb) WITH ORDINALITY AS duties(permission,ordinal) WHERE source->'permissions' ? permission)
    ELSE source->'permissions' IS DISTINCT FROM '["devices.inventory.read","devices.inventory.create","devices.inventory.assign"]'::jsonb END)
  OR live AND NOT coalesce(source->'permissions' ? 'devices.inventory.assign',false)
  OR jsonb_typeof(source->'context') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(source->'context'))<>4
  OR (source->'context')-ARRAY['userId','revision','linkRevision','rolesRevision']<>'{}'::jsonb
  OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId' OR NOT(source->>'actorUserId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(source->'actorUserId') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,userId}') IS DISTINCT FROM 'string'
  OR jsonb_typeof(source#>'{context,revision}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,linkRevision}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{context,rolesRevision}') IS DISTINCT FROM 'string'
  OR NOT(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$')
  OR NOT(source#>>'{context,revision}' ~ '^[1-9][0-9]{0,18}$') OR NOT(source#>>'{context,linkRevision}' ~ '^[1-9][0-9]{0,18}$')
  OR (source#>>'{context,revision}')::numeric>9223372036854775807 OR (source#>>'{context,linkRevision}')::numeric>9223372036854775807
  OR jsonb_typeof(source->'tenant') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(source->'tenant'))<>3
  OR (source->'tenant')-ARRAY['id','version','generation']<>'{}'::jsonb OR NOT(source#>>'{tenant,id}' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(source#>'{tenant,id}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{tenant,version}') IS DISTINCT FROM 'string' OR jsonb_typeof(source#>'{tenant,generation}') IS DISTINCT FROM 'string'
  OR NOT(source#>>'{tenant,version}' ~ '^[1-9][0-9]{0,18}$') OR NOT(source#>>'{tenant,generation}' ~ '^[1-9][0-9]{0,18}$')
  OR (source#>>'{tenant,version}')::numeric>9223372036854775807 OR (source#>>'{tenant,generation}')::numeric>9223372036854775807
  OR live AND ((source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300)
  THEN RAISE EXCEPTION 'Exact original device return authority required' USING ERRCODE='42501';END IF;
 IF NOT offboarding THEN
  IF source->'target' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Untargeted inventory authority required' USING ERRCODE='42501';END IF;RETURN;
 END IF;
 parent=source->'parent';target=source->'target';
 IF source->'deviceOffboardingReturnsProtocol' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(target) IS DISTINCT FROM 'object'
  OR (SELECT count(*) FROM jsonb_object_keys(target))<>3 OR target-ARRAY['id','enabled','eligibilityRevision']<>'{}'::jsonb
  OR target->'enabled' IS DISTINCT FROM 'false'::jsonb OR NOT(target->>'id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR jsonb_typeof(target->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(target->'eligibilityRevision') IS DISTINCT FROM 'string'
  OR target->>'id'=source->>'actorUserId' OR NOT(target->>'eligibilityRevision' ~ '^[1-9][0-9]{0,18}$') OR (target->>'eligibilityRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(parent))<>9
  OR parent-ARRAY['workflowId','tenantId','userId','action','operationId','afterRevision','afterEligibilityRevision','createdAt','deliveryStatus']<>'{}'::jsonb
  OR jsonb_typeof(parent->'workflowId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'tenantId') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'userId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(parent->'action') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterRevision') IS DISTINCT FROM 'string' OR jsonb_typeof(parent->'afterEligibilityRevision') IS DISTINCT FROM 'string'
  OR NOT(parent->>'workflowId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') OR parent->>'tenantId' IS DISTINCT FROM source#>>'{tenant,id}'
  OR parent->>'userId' IS DISTINCT FROM target->>'id' OR parent->>'afterEligibilityRevision' IS DISTINCT FROM target->>'eligibilityRevision'
  OR parent->>'deliveryStatus' IS DISTINCT FROM 'pending' OR parent->>'action' NOT IN('disabled','already_disabled')
  OR parent->>'action'='disabled' AND NOT(parent->>'operationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$')
  OR parent->>'action'='disabled' AND jsonb_typeof(parent->'operationId') IS DISTINCT FROM 'string'
  OR parent->>'action'='already_disabled' AND parent->'operationId' IS DISTINCT FROM 'null'::jsonb
  OR NOT(parent->>'afterRevision' ~ '^[1-9][0-9]{0,18}$') OR (parent->>'afterRevision')::numeric>9223372036854775807
  OR jsonb_typeof(parent->'createdAt') IS DISTINCT FROM 'string' OR (parent->>'createdAt')::timestamptz>clock_timestamp()
  THEN RAISE EXCEPTION 'Retained disabled original parent authority required' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE signature TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY['device_delegation_valid(jsonb)','device_returns_source(jsonb,boolean,boolean)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog',signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
COMMIT;
