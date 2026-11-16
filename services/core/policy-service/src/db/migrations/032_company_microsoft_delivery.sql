-- Current local entitlement is checked independently from stored provider links.
CREATE TABLE IF NOT EXISTS company_microsoft_delivery_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION company_microsoft_local(pool_identity UUID,authority JSONB) RETURNS JSONB LANGUAGE plpgsql VOLATILE AS $$
DECLARE catalog license_catalog;allocation license_assignments;origins JSONB;
BEGIN
 PERFORM license_company_receiving();PERFORM company_blueprint_assignment_retirement_receiving();
 SELECT * INTO catalog FROM license_catalog WHERE id=pool_identity AND business_tenant_id=(authority#>>'{tenant,id}')::uuid;
 IF catalog.id IS NULL OR NOT license_company_pool_valid(catalog.id) OR authority->'target' IS NULL OR authority->'target'='null'::jsonb THEN
  RAISE EXCEPTION 'Current own company pool and canonical target required' USING ERRCODE='42501';END IF;
 SELECT * INTO allocation FROM license_assignments WHERE license_id=pool_identity AND assignee_type='user' AND assignee_id=authority#>>'{target,id}';
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sourceType',origin.source_type,'sourceId',origin.source_id,'grantId',origin.grant_id,
  'eligibilityRevision',grant_row.eligibility_revision::text,'live',expiry.value IS NULL OR expiry.value>clock_timestamp(),
  'deadline',CASE WHEN isfinite(expiry.value) THEN to_char(expiry.value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') ELSE NULL END,
  'bindingValid',CASE WHEN origin.source_type='direct' THEN true ELSE binding.id IS NOT NULL AND binding.status='active' AND company_blueprint_assignment_binding_valid(binding) END,
  'rule',CASE WHEN rule.id IS NULL THEN NULL ELSE jsonb_build_object('id',rule.id,'groupId',rule.group_id,'revision',rule.revision::text,'status',rule.status) END)
  ORDER BY origin.source_type,origin.source_id,origin.grant_id),'[]'::jsonb) INTO origins
 FROM license_assignment_sources origin JOIN license_grants grant_row ON grant_row.id=origin.grant_id
 CROSS JOIN LATERAL(SELECT license_member_source_expiry(origin.grant_id,origin.user_id,origin.expires_at) AS value) expiry
 LEFT JOIN company_blueprint_user_assignments binding ON origin.source_type='blueprint' AND binding.id::text=origin.source_id
  AND binding.tenant_id=catalog.business_tenant_id AND binding.user_id::text=origin.user_id
 LEFT JOIN company_license_groups rule ON rule.blueprint_id=binding.blueprint_id AND rule.tenant_id=catalog.business_tenant_id AND rule.pool_id=pool_identity
 WHERE origin.license_id=pool_identity AND origin.user_id=authority#>>'{target,id}';
 IF jsonb_array_length(origins)>10000 THEN RAISE EXCEPTION 'Bounded complete company origins required' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('poolId',catalog.id,'poolRevision',catalog.business_revision::text,'target',authority->'target',
  'assignment',CASE WHEN allocation.id IS NULL THEN NULL ELSE jsonb_build_object('id',allocation.id,'eligibilityRevision',allocation.eligibility_revision::text) END,'origins',origins);
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_delivery_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 PERFORM company_microsoft_receiving();
 IF (SELECT count(*) FROM company_microsoft_delivery_manifest)<>7 OR EXISTS(SELECT 1 FROM company_microsoft_delivery_manifest manifest
  WHERE to_regprocedure(manifest.signature) IS NULL OR manifest.digest<>md5(pg_get_functiondef(to_regprocedure(manifest.signature)))) THEN
  RAISE EXCEPTION 'Company Microsoft delivery evidence unavailable' USING ERRCODE='42501';END IF;
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_observation_valid(value JSONB) RETURNS BOOLEAN LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(license_company_exact(value,ARRAY['present','direct','active','plansMatch','inherited','accountEnabled'])
 AND NOT EXISTS(SELECT 1 FROM jsonb_each(value) item WHERE jsonb_typeof(item.value)<>'boolean')
 AND NOT(value->'direct'='true'::jsonb AND value->'present'<>'true'::jsonb)
 AND NOT(value->'active'='true'::jsonb AND value->'direct'<>'true'::jsonb)
 AND NOT(value->'plansMatch'='true'::jsonb AND value->'direct'<>'true'::jsonb)
 AND NOT(value->'inherited'='true'::jsonb AND value->'present'<>'true'::jsonb),false);
$$;

CREATE OR REPLACE FUNCTION company_microsoft_admission(authority JSONB,request JSONB,projection JSONB,capture JSONB) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE connection company_microsoft_connections;product company_microsoft_pools;person company_microsoft_users;raw JSONB;origin JSONB;proof JSONB;rule company_license_groups;
 eligible BOOLEAN;wanted BOOLEAN=false;required_groups UUID[]='{}';seen UUID[]='{}';
BEGIN
 PERFORM company_microsoft_delivery_receiving();
 IF NOT license_company_exact(request,ARRAY['poolId','userId','fingerprint','action','reason','confirm']) OR request->'confirm' IS DISTINCT FROM 'true'::jsonb
  OR request->>'action' IS NULL OR request->>'action' NOT IN('assign','remove','confirmed','conflict','review','verify','external_retained')
  OR jsonb_typeof(request->'fingerprint') IS DISTINCT FROM 'string' OR request->>'fingerprint' !~ '^[a-f0-9]{64}$' OR NOT company_microsoft_source_valid(authority,(capture#>>'{connection,id}')::uuid,request->>'reason')
  OR NOT license_company_exact(projection,ARRAY['raw','groups','desired']) OR jsonb_typeof(projection->'desired') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(projection->'groups') IS DISTINCT FROM 'array' OR jsonb_array_length(projection->'groups')>10000
  OR capture->>'tenantId' IS DISTINCT FROM authority#>>'{tenant,id}' OR capture->>'actorUserId' IS DISTINCT FROM authority->>'actorUserId'
  OR request->>'userId' IS DISTINCT FROM authority#>>'{target,id}' OR capture->>'userId' IS DISTINCT FROM request->>'userId'
  OR capture->>'poolId' IS DISTINCT FROM request->>'poolId' OR NOT company_microsoft_observation_valid(capture->'remote') THEN
  RAISE EXCEPTION 'Exact current company Microsoft admission required' USING ERRCODE='42501';END IF;
 SELECT * INTO connection FROM company_microsoft_connections WHERE id=(capture#>>'{connection,id}')::uuid AND tenant_id=(authority#>>'{tenant,id}')::uuid AND status='active' FOR SHARE;
 SELECT * INTO product FROM company_microsoft_pools WHERE id=(capture#>>'{pool,id}')::uuid AND connection_id=connection.id AND tenant_id=connection.tenant_id AND status='active' FOR SHARE;
 SELECT * INTO person FROM company_microsoft_users WHERE id=(capture#>>'{user,id}')::uuid AND connection_id=connection.id AND tenant_id=connection.tenant_id AND status='active' FOR SHARE;
 PERFORM 1 FROM license_catalog WHERE id=product.pool_id FOR SHARE;
 IF connection.id IS NULL OR product.id IS NULL OR person.id IS NULL OR connection.tenant_generation::text IS DISTINCT FROM authority#>>'{tenant,generation}'
  OR connection.revision::text IS DISTINCT FROM capture#>>'{connection,revision}' OR connection.microsoft_tenant_id::text IS DISTINCT FROM capture#>>'{connection,microsoftTenantId}'
  OR connection.read_client_id::text IS DISTINCT FROM capture#>>'{connection,readClientId}' OR connection.write_client_id::text IS DISTINCT FROM capture#>>'{connection,writeClientId}'
  OR product.pool_id::text IS DISTINCT FROM request->>'poolId' OR product.revision::text IS DISTINCT FROM capture#>>'{pool,revision}'
  OR product.sku_id::text IS DISTINCT FROM capture#>>'{pool,skuId}' OR product.disabled_plans IS DISTINCT FROM capture#>'{pool,disabledPlans}'
  OR person.user_id::text IS DISTINCT FROM request->>'userId' OR person.revision::text IS DISTINCT FROM capture#>>'{user,revision}'
  OR person.object_id::text IS DISTINCT FROM capture#>>'{user,objectId}' THEN RAISE EXCEPTION 'Microsoft mapping or company generation changed' USING ERRCODE='40001';END IF;
 raw=company_microsoft_local(product.pool_id,authority);
 IF raw IS DISTINCT FROM projection->'raw' OR raw IS DISTINCT FROM capture#>'{local,raw}' THEN RAISE EXCEPTION 'Current local license state changed' USING ERRCODE='40001';END IF;
 eligible=raw#>'{target,enabled}'='true'::jsonb AND raw#>'{target,deleted}'='false'::jsonb AND raw#>>'{assignment,eligibilityRevision}'=raw#>>'{target,eligibilityRevision}';
 FOR origin IN SELECT value FROM jsonb_array_elements(raw->'origins') LOOP
  IF origin->'bindingValid' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'Retained blueprint binding required' USING ERRCODE='42501';END IF;
  IF origin->'rule'<>'null'::jsonb THEN
   PERFORM company_license_group_receiving();
   SELECT item.* INTO rule FROM company_license_groups item WHERE item.id=(origin#>>'{rule,id}')::uuid AND item.tenant_id=connection.tenant_id
    AND EXISTS(SELECT 1 FROM company_license_group_events event JOIN company_license_group_outbox box ON box.id=event.id AND box.status='pending'
     WHERE event.rule_id=item.id AND event.result-'created_at'-'updated_at'=to_jsonb(item)-'created_at'-'updated_at'
      AND (event.result->>'created_at')::timestamptz=item.created_at AND (event.result->>'updated_at')::timestamptz=item.updated_at);
   IF rule.id IS NULL THEN RAISE EXCEPTION 'Original license group receipt required' USING ERRCODE='42501';END IF;
  END IF;
  IF eligible AND origin->'live'='true'::jsonb AND origin->>'eligibilityRevision'=raw#>>'{target,eligibilityRevision}' THEN
   IF origin->'rule'='null'::jsonb THEN wanted=true;
   ELSIF origin#>>'{rule,status}'='active' THEN required_groups=array_append(required_groups,(origin#>>'{rule,id}')::uuid);END IF;
  END IF;
 END LOOP;
 FOR proof IN SELECT value FROM jsonb_array_elements(projection->'groups') LOOP
  IF NOT license_company_exact(proof,ARRAY['ruleId','groupId','revision','hash','active','membershipId','eligibilityRevision','reviewDeadlineAt','validUntil'])
   OR jsonb_typeof(proof->'active') IS DISTINCT FROM 'boolean' OR jsonb_typeof(proof->'hash') IS DISTINCT FROM 'string' OR proof->>'hash' !~ '^[a-f0-9]{64}$'
   OR NOT license_company_uuid(proof->>'ruleId') OR NOT license_company_uuid(proof->>'groupId') OR NOT license_company_revision_valid(proof->'revision')
   OR jsonb_typeof(proof->'validUntil') IS DISTINCT FROM 'string'
   OR NOT((proof->>'ruleId')::uuid=ANY(required_groups)) OR (proof->>'ruleId')::uuid=ANY(seen)
   OR (proof->>'validUntil')::timestamptz<=clock_timestamp() OR (proof->>'validUntil')::timestamptz>clock_timestamp()+interval '305 seconds'
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(raw->'origins') item WHERE item#>>'{rule,id}'=proof->>'ruleId' AND item#>>'{rule,groupId}'=proof->>'groupId') THEN
   RAISE EXCEPTION 'Fresh exact company group membership proof required' USING ERRCODE='42501';END IF;
  seen=array_append(seen,(proof->>'ruleId')::uuid);
  IF proof->'active'='true'::jsonb THEN
   IF NOT license_company_uuid(proof->>'membershipId') OR proof->>'eligibilityRevision' IS DISTINCT FROM raw#>>'{target,eligibilityRevision}'
    OR proof->'reviewDeadlineAt'<>'null'::jsonb AND (proof->>'reviewDeadlineAt')::timestamptz<=clock_timestamp() THEN
    RAISE EXCEPTION 'Current group recipient eligibility and review required' USING ERRCODE='42501';END IF;
   wanted=true;
  END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM unnest(required_groups) id WHERE NOT id=ANY(seen)) OR wanted IS DISTINCT FROM (projection->>'desired')::boolean
  OR projection->'desired' IS DISTINCT FROM capture#>'{local,desired}' THEN RAISE EXCEPTION 'Complete current company entitlement proof required' USING ERRCODE='42501';END IF;
 RETURN wanted;
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_prepare(authority JSONB,operation UUID,nonce TEXT,resource UUID,request JSONB,projection JSONB,capture JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE original company_microsoft_targets;desired_state BOOLEAN;known_owned BOOLEAN=false;prior company_microsoft_operations;
BEGIN
 IF nonce IS NULL OR nonce !~ '^[a-f0-9]{64}$' OR NOT pg_try_advisory_xact_lock(hashtextextended('company-microsoft:'||resource::text,0)) THEN
  RAISE EXCEPTION 'Exclusive current Microsoft target permit required' USING ERRCODE='42501';END IF;
 desired_state=company_microsoft_admission(authority,request,projection,capture);
 SELECT * INTO original FROM company_microsoft_targets WHERE id=resource FOR UPDATE;
 IF original.id IS NULL AND capture->'target' IS DISTINCT FROM 'null'::jsonb OR original.id IS NOT NULL AND
  (original.tenant_id::text IS DISTINCT FROM authority#>>'{tenant,id}' OR original.pool_binding_id::text IS DISTINCT FROM capture#>>'{pool,id}'
   OR original.user_binding_id::text IS DISTINCT FROM capture#>>'{user,id}' OR original.revision::text IS DISTINCT FROM capture#>>'{target,revision}' OR original.status='processing') THEN
  RAISE EXCEPTION 'Exact reviewed Microsoft target changed or needs recovery' USING ERRCODE='40001';END IF;
 SELECT * INTO prior FROM company_microsoft_operations WHERE id=original.last_operation_id;
 IF prior.outcome->>'retryAfter' IS NOT NULL AND prior.finished_at+make_interval(secs=>(prior.outcome->>'retryAfter')::integer)>clock_timestamp() THEN
  RAISE EXCEPTION 'Microsoft retry window active' USING ERRCODE='55000';END IF;
 IF original.id IS NOT NULL THEN
  known_owned=original.owned;
  IF original.pending_operation_id IS NULL AND original.uncertain_operation_id IS NULL AND capture#>'{remote,direct}'='false'::jsonb THEN known_owned=false;END IF;
 END IF;
 PERFORM set_config('opendirectory.company_microsoft_operation',operation::text,true);PERFORM set_config('opendirectory.company_microsoft_permit',nonce,true);PERFORM set_config('opendirectory.company_microsoft_purpose','prepare',true);
 INSERT INTO company_microsoft_operations(id,tenant_id,connection_id,resource_id,action,source,request,permit_hash,phase,desired,local_state,before_state)
  VALUES(operation,(authority#>>'{tenant,id}')::uuid,(capture#>>'{connection,id}')::uuid,resource,'sync',authority,request,encode(sha256(convert_to(nonce,'UTF8')),'hex'),'prepared',desired_state,projection,jsonb_build_object('capture',capture,'previousTarget',to_jsonb(original)));
 IF original.id IS NULL THEN
  INSERT INTO company_microsoft_targets(id,tenant_id,connection_id,pool_binding_id,user_binding_id,status,last_operation_id,observation,checked_at)
   VALUES(resource,(authority#>>'{tenant,id}')::uuid,(capture#>>'{connection,id}')::uuid,(capture#>>'{pool,id}')::uuid,(capture#>>'{user,id}')::uuid,'processing',operation,capture->'remote',clock_timestamp());
 ELSE
  UPDATE company_microsoft_targets SET revision=revision+1,status='processing',owned=known_owned,last_operation_id=operation,observation=capture->'remote',checked_at=clock_timestamp(),error_code=NULL,updated_at=clock_timestamp() WHERE id=resource;
 END IF;
 PERFORM company_microsoft_audit(operation,'sync_prepared',jsonb_build_object('kind','human','userId',authority->>'actorUserId'),jsonb_build_object('source',authority,'desired',desired_state,'capture',capture));
 RETURN jsonb_build_object('operationId',operation,'targetId',resource);
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_dispatch(operation UUID,nonce TEXT) RETURNS TIMESTAMPTZ LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE original company_microsoft_operations;target company_microsoft_targets;remote JSONB;stock JSONB;deadline TIMESTAMPTZ;
BEGIN
 PERFORM set_config('opendirectory.company_microsoft_operation',operation::text,true);PERFORM set_config('opendirectory.company_microsoft_permit',nonce,true);PERFORM set_config('opendirectory.company_microsoft_purpose','dispatch',true);
 original=company_microsoft_scope();PERFORM 1 FROM company_microsoft_operations WHERE id=operation FOR UPDATE;
 SELECT * INTO target FROM company_microsoft_targets WHERE id=original.resource_id FOR UPDATE;
 remote=original.before_state#>'{capture,remote}';stock=original.before_state#>'{capture,stock}';
 IF original.action<>'sync' OR original.phase<>'prepared' OR original.created_at+interval '45 seconds'<=clock_timestamp()
  OR target.last_operation_id IS DISTINCT FROM operation OR target.status<>'processing' OR target.pending_operation_id IS NOT NULL OR target.uncertain_operation_id IS NOT NULL
  OR original.request->>'action' IS DISTINCT FROM (CASE WHEN original.desired THEN 'assign' ELSE 'remove' END)
  OR company_microsoft_admission(original.source,original.request,original.local_state,original.before_state->'capture') IS DISTINCT FROM original.desired THEN
  RAISE EXCEPTION 'Original fresh single-use Microsoft dispatch required' USING ERRCODE='42501';END IF;
 IF original.desired THEN
  IF remote->'present' IS DISTINCT FROM 'false'::jsonb OR remote->'accountEnabled' IS DISTINCT FROM 'true'::jsonb
   OR NOT license_company_exact(stock,ARRAY['skuId','skuPartNumber','appliesTo','capabilityStatus','prepaidUnits','consumedUnits'])
   OR NOT license_company_exact(stock->'prepaidUnits',ARRAY['enabled','warning','suspended','lockedOut'])
   OR EXISTS(SELECT 1 FROM jsonb_each((stock->'prepaidUnits')||jsonb_build_object('consumedUnits',stock->'consumedUnits')) item
    WHERE jsonb_typeof(item.value)<>'number' OR item.value::text !~ '^(0|[1-9][0-9]{0,9})$' OR (item.value::text)::numeric>2147483647)
   OR stock->>'skuId' IS DISTINCT FROM original.before_state#>>'{capture,pool,skuId}' OR stock->>'appliesTo' IS DISTINCT FROM 'User' OR stock->>'capabilityStatus' IS DISTINCT FROM 'Enabled'
   OR (stock#>>'{prepaidUnits,enabled}')::bigint<=(stock->>'consumedUnits')::bigint THEN RAISE EXCEPTION 'Available reviewed Microsoft user stock required' USING ERRCODE='23514';END IF;
 ELSE
  IF NOT target.owned OR remote->'direct' IS DISTINCT FROM 'true'::jsonb OR remote->'plansMatch' IS DISTINCT FROM 'true'::jsonb THEN
   RAISE EXCEPTION 'Only an original owned direct Microsoft license may be removed' USING ERRCODE='42501';END IF;
 END IF;
 deadline=clock_timestamp()+interval '10 seconds';
 UPDATE company_microsoft_operations SET phase='dispatched',updated_at=clock_timestamp() WHERE id=operation;
 PERFORM company_microsoft_audit(operation,'sync_dispatched',jsonb_build_object('kind','workload','operationId',operation),jsonb_build_object('dispatchBefore',deadline));
 RETURN deadline;
END $$;

CREATE OR REPLACE FUNCTION company_microsoft_finish(operation UUID,nonce TEXT,result JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER SET search_path FROM CURRENT AS $$
DECLARE original company_microsoft_operations;target company_microsoft_targets;attempt company_microsoft_operations;remote JSONB;kind TEXT=result->>'kind';
 status_name TEXT;error_name TEXT=result->>'errorCode';owned_state BOOLEAN;pending UUID;uncertain UUID;event_id UUID;finished TIMESTAMPTZ;
BEGIN
 PERFORM company_microsoft_delivery_receiving();
 PERFORM set_config('opendirectory.company_microsoft_operation',operation::text,true);PERFORM set_config('opendirectory.company_microsoft_permit',nonce,true);PERFORM set_config('opendirectory.company_microsoft_purpose','finish',true);
 original=company_microsoft_scope();PERFORM 1 FROM company_microsoft_operations WHERE id=operation FOR UPDATE;
 SELECT * INTO target FROM company_microsoft_targets WHERE id=original.resource_id FOR UPDATE;
 IF original.action<>'sync' OR original.phase='finished' OR target.last_operation_id IS DISTINCT FROM operation OR target.status<>'processing'
  OR NOT license_company_exact(result,ARRAY['kind','errorCode','retryAfter']) OR kind IS NULL OR kind NOT IN('observed','acknowledged','rejected','unknown','not_sent')
  OR result->'errorCode'<>'null'::jsonb AND (jsonb_typeof(result->'errorCode')<>'string' OR error_name !~ '^[a-z0-9_]{1,120}$')
  OR result->'retryAfter'<>'null'::jsonb AND (jsonb_typeof(result->'retryAfter')<>'number' OR (result->>'retryAfter')::numeric NOT BETWEEN 1 AND 3600 OR (result->>'retryAfter')::numeric<>trunc((result->>'retryAfter')::numeric))
  OR (kind IN('observed','not_sent') AND original.phase<>'prepared' OR kind IN('acknowledged','rejected','unknown') AND original.phase<>'dispatched') THEN
  RAISE EXCEPTION 'Exact original Microsoft delivery outcome required' USING ERRCODE='42501';END IF;
 remote=original.before_state#>'{capture,remote}';owned_state=target.owned;pending=target.pending_operation_id;uncertain=target.uncertain_operation_id;
 IF kind='acknowledged' THEN status_name='verifying';pending=operation;owned_state=owned_state OR original.desired;error_name='provider_verification_pending';
 ELSIF kind='unknown' THEN status_name='unknown';uncertain=operation;pending=NULL;error_name=COALESCE(error_name,'provider_write_uncertain');
 ELSIF kind IN('rejected','not_sent') THEN status_name='failed';error_name=COALESCE(error_name,CASE WHEN kind='not_sent' THEN 'provider_write_not_sent' ELSE 'provider_write_rejected' END);
 ELSIF uncertain IS NOT NULL THEN
  SELECT * INTO attempt FROM company_microsoft_operations WHERE id=uncertain AND resource_id=target.id AND phase='finished';
  IF attempt.id IS NULL THEN RAISE EXCEPTION 'Original uncertain Microsoft attempt missing' USING ERRCODE='42501';END IF;
  IF NOT attempt.desired AND remote->'direct'='false'::jsonb THEN
   uncertain=NULL;owned_state=false;status_name=CASE WHEN original.desired OR remote->'present'='true'::jsonb THEN 'conflict' ELSE 'confirmed' END;
   error_name=CASE WHEN original.desired THEN 'desired_changed' WHEN remote->'present'='true'::jsonb THEN 'external_assignment_retained' ELSE NULL END;
  ELSE status_name='unknown';error_name='uncertain_write_requires_review';END IF;
 ELSIF pending IS NOT NULL THEN
  SELECT * INTO attempt FROM company_microsoft_operations WHERE id=pending AND resource_id=target.id AND phase='finished' AND outcome->>'kind'='acknowledged';
  IF attempt.id IS NULL THEN RAISE EXCEPTION 'Original pending Microsoft acknowledgement missing' USING ERRCODE='42501';END IF;
  IF attempt.desired AND remote->'direct'='true'::jsonb AND remote->'active'='true'::jsonb AND remote->'plansMatch'='true'::jsonb THEN
   pending=NULL;owned_state=true;status_name=CASE WHEN original.desired THEN 'confirmed' ELSE 'conflict' END;error_name=CASE WHEN original.desired THEN NULL ELSE 'desired_changed' END;
  ELSIF NOT attempt.desired AND remote->'direct'='false'::jsonb THEN
   pending=NULL;owned_state=false;status_name=CASE WHEN original.desired OR remote->'present'='true'::jsonb THEN 'conflict' ELSE 'confirmed' END;
   error_name=CASE WHEN original.desired THEN 'desired_changed' WHEN remote->'present'='true'::jsonb THEN 'external_assignment_retained' ELSE NULL END;
  ELSE status_name='verifying';error_name='provider_verification_pending';END IF;
 ELSIF original.desired THEN
  IF remote->'accountEnabled'='false'::jsonb THEN status_name='conflict';error_name='provider_target_disabled';
  ELSIF remote->'present'='false'::jsonb THEN status_name='conflict';error_name='provider_assignment_required';
  ELSIF NOT owned_state OR remote->'direct'='false'::jsonb OR remote->'plansMatch'='false'::jsonb THEN status_name='conflict';error_name='unmanaged_assignment_retained';
  ELSE status_name=CASE WHEN remote->'active'='true'::jsonb THEN 'confirmed' ELSE 'verifying' END;error_name=CASE WHEN remote->'active'='true'::jsonb THEN NULL ELSE 'provider_verification_pending' END;END IF;
 ELSE
  IF remote->'direct'='false'::jsonb THEN owned_state=false;status_name=CASE WHEN remote->'present'='true'::jsonb THEN 'conflict' ELSE 'confirmed' END;error_name=CASE WHEN remote->'present'='true'::jsonb THEN 'external_assignment_retained' ELSE NULL END;
  ELSE status_name='conflict';error_name=CASE WHEN owned_state AND remote->'plansMatch'='true'::jsonb THEN 'provider_removal_required' ELSE 'unmanaged_assignment_retained' END;END IF;
 END IF;
 IF kind='observed' AND result->>'errorCode'='graph_assignment_error' AND uncertain IS NULL THEN status_name='failed';error_name='graph_assignment_error';END IF;
 UPDATE company_microsoft_targets SET revision=revision+1,status=status_name,owned=owned_state,pending_operation_id=pending,uncertain_operation_id=uncertain,
  error_code=error_name,observation=remote,checked_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=target.id;
 event_id=company_microsoft_audit(operation,'sync_finished',jsonb_build_object('kind','workload','operationId',operation),jsonb_build_object('result',result,'status',status_name,'owned',owned_state));
 finished=clock_timestamp();
 result=result||jsonb_build_object('operationId',operation,'poolId',original.request->>'poolId','userId',original.request->>'userId','action',original.request->>'action','targetId',target.id,'targetRevision',(SELECT revision::text FROM company_microsoft_targets WHERE id=target.id),
  'status',status_name,'owned',owned_state,'pendingOperationId',pending,'uncertainOperationId',uncertain,'errorCode',error_name,'eventId',event_id,
  'retryAt',CASE WHEN result->'retryAfter'='null'::jsonb THEN NULL ELSE to_char((finished+make_interval(secs=>(result->>'retryAfter')::integer)) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END);
 UPDATE company_microsoft_operations SET phase='finished',outcome=result,finished_at=finished,updated_at=finished WHERE id=operation;
 RETURN result;
END $$;

INSERT INTO company_microsoft_delivery_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'company_microsoft_local(uuid,jsonb)','company_microsoft_delivery_receiving()','company_microsoft_observation_valid(jsonb)',
 'company_microsoft_admission(jsonb,jsonb,jsonb,jsonb)','company_microsoft_prepare(jsonb,uuid,text,uuid,jsonb,jsonb,jsonb)',
 'company_microsoft_dispatch(uuid,text)','company_microsoft_finish(uuid,text,jsonb)']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
DO $$ DECLARE signature TEXT;BEGIN
 FOR signature IN SELECT manifest.signature FROM company_microsoft_delivery_manifest manifest LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',to_regprocedure(signature));
 END LOOP;
END $$;
