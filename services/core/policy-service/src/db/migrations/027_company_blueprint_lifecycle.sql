DO $install$ BEGIN
IF EXISTS(SELECT 1 FROM license_schema_versions WHERE version=27) THEN
 PERFORM company_blueprint_assignment_retirement_receiving();
ELSE
 EXECUTE $migration$
CREATE TABLE company_offboarding_v2_jobs (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,user_id UUID NOT NULL,created_by UUID NOT NULL,revision BIGINT NOT NULL CHECK(revision>0),
 intent JSONB NOT NULL,state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,UNIQUE(tenant_id,id)
);
CREATE TABLE company_offboarding_v2_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,workflow_id UUID NOT NULL REFERENCES company_offboarding_v2_jobs(id),revision BIGINT NOT NULL,
 actor_user_id UUID NOT NULL,before_state JSONB,after_state JSONB NOT NULL,authority JSONB NOT NULL,valid_until TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 UNIQUE(workflow_id,revision)
);
CREATE TABLE company_offboarding_v2_outbox (
 id UUID PRIMARY KEY REFERENCES company_offboarding_v2_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE company_offboarding_v2_requests (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,workflow_id UUID NOT NULL REFERENCES company_offboarding_v2_jobs(id),actor_user_id UUID NOT NULL,
 request JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL
);
CREATE TABLE company_offboarding_v2_receiver_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL,definer BOOLEAN NOT NULL);

CREATE FUNCTION company_blueprint_user_binding_manifest(tenant UUID,target UUID) RETURNS JSONB LANGUAGE plpgsql STABLE AS $$
DECLARE result JSONB;
BEGIN
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',binding.id,'revision',binding.revision::text,'blueprintId',binding.blueprint_id,'version',binding.version,
  'eligibilityRevision',binding.eligibility_revision::text,'poolIds',release.draft->'appPoolIds') ORDER BY binding.id),'[]'::jsonb) INTO result
 FROM company_blueprint_user_assignments binding JOIN company_blueprint_versions release ON release.blueprint_id=binding.blueprint_id AND release.tenant_id=binding.tenant_id AND release.version=binding.version
 WHERE binding.tenant_id=tenant AND binding.user_id=target AND binding.status='active' AND company_blueprint_assignment_binding_valid(binding);
 IF jsonb_array_length(result)<>(SELECT count(*) FROM company_blueprint_user_assignments WHERE tenant_id=tenant AND user_id=target AND status='active')
 OR jsonb_array_length(result)>10000 THEN RAISE EXCEPTION 'Complete bounded blueprint binding manifest required' USING ERRCODE='23514';END IF;
 RETURN result;
END; $$;

CREATE FUNCTION license_company_v1_sources_require(pool_id UUID,target UUID,tenant UUID) RETURNS VOID LANGUAGE plpgsql STABLE AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM license_assignment_sources source JOIN license_catalog catalog ON catalog.id=source.license_id
  WHERE catalog.business_tenant_id=tenant AND source.source_type='blueprint' AND(pool_id IS NULL OR source.license_id=pool_id) AND(target IS NULL OR source.user_id=target::text))
 OR target IS NOT NULL AND EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE tenant_id=tenant AND user_id=target AND status='active')
 OR pool_id IS NOT NULL AND EXISTS(SELECT 1 FROM license_company_commands WHERE license_id=pool_id AND protocol=2)
 THEN RAISE EXCEPTION 'upgrade_required' USING ERRCODE='23514';END IF;
END; $$;

CREATE FUNCTION company_offboarding_v2_capture(tenant UUID,target UUID) RETURNS JSONB LANGUAGE plpgsql VOLATILE AS $$
DECLARE items JSONB;bindings JSONB;inventory_row license_catalog;total BIGINT;
BEGIN
 SELECT count(*) INTO total FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
 WHERE catalog.business_tenant_id=tenant AND assignment.assignee_type='user' AND assignment.assignee_id=target::text;
 IF total>10000 OR (SELECT count(*) FROM license_assignment_sources source JOIN license_catalog catalog ON catalog.id=source.license_id WHERE catalog.business_tenant_id=tenant AND source.user_id=target::text)>10000
 THEN RAISE EXCEPTION 'Complete source capture exceeds the bounded atomic workflow' USING ERRCODE='23514';END IF;
 FOR inventory_row IN SELECT inventory.* FROM license_catalog inventory WHERE inventory.business_tenant_id=tenant AND EXISTS(SELECT 1 FROM license_assignments WHERE license_id=inventory.id AND assignee_type='user' AND assignee_id=target::text) ORDER BY inventory.id LOOP
  IF NOT license_company_pool_valid(inventory_row.id) THEN RAISE EXCEPTION 'Actual canonical source capture unavailable' USING ERRCODE='55000';END IF;
 END LOOP;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('poolId',catalog.id,'poolRevision',catalog.business_revision::text,'assignmentId',assignment.id,'name',catalog.name,'vendor',catalog.vendor,
 'eligibilityRevision',assignment.eligibility_revision::text,'assignedAt',to_char(assignment.assigned_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'sources',license_company_sources(catalog.id,target),'status','pending','eventId',NULL) ORDER BY catalog.id),'[]'::jsonb) INTO items
 FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id
 WHERE catalog.business_tenant_id=tenant AND assignment.assignee_type='user' AND assignment.assignee_id=target::text;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(items) item WHERE jsonb_array_length(item->'sources')=0) THEN RAISE EXCEPTION 'Complete actual allocation sources required' USING ERRCODE='23514';END IF;
 bindings=company_blueprint_user_binding_manifest(tenant,target);
 RETURN jsonb_build_object('items',items,'bindings',bindings);
END; $$;

CREATE FUNCTION company_offboarding_v2_state_valid(job company_offboarding_v2_jobs) RETURNS BOOLEAN LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE item JSONB;binding JSONB;legacy company_offboarding_jobs;seen TEXT[]='{}';grants TEXT[]='{}';source JSONB;
BEGIN
 IF NOT company_offboarding_intent_valid(job.intent) OR job.id::text IS DISTINCT FROM job.intent->>'workflowId' OR job.user_id::text IS DISTINCT FROM job.intent->>'userId'
 OR NOT license_company_exact(job.state,ARRAY['phase','requestedRevision','checkpoint','items','bindings','failure','retirementOperationId'])
 OR NOT license_company_revision_valid(job.state->'requestedRevision') OR job.state->>'phase' NOT IN('pending','licenses','paused','completed_local') THEN RETURN false;END IF;
 IF job.state->'checkpoint'<>'null'::jsonb THEN
  legacy.id=job.id;legacy.tenant_id=job.tenant_id;legacy.user_id=job.user_id;legacy.intent=job.intent;legacy.state=job.state;
  IF NOT company_offboarding_receipt_valid(job.state->'checkpoint',legacy) OR job.state#>>'{checkpoint,beforeEligibilityRevision}' IS DISTINCT FROM job.intent->>'eligibilityRevision' THEN RETURN false;END IF;
 END IF;
 IF job.state->>'phase'='paused' THEN
  IF NOT license_company_exact(job.state->'failure',ARRAY['code','step']) OR NOT COALESCE(job.state#>>'{failure,code}' ~ '^[45][0-9]{2}$',false)
   OR job.state#>>'{failure,step}' NOT IN('account','capture','licenses','verify') THEN RETURN false;END IF;
 ELSIF job.state->'failure'<>'null'::jsonb THEN RETURN false;END IF;
 IF job.state->'items'='null'::jsonb THEN RETURN job.state->'bindings'='null'::jsonb AND job.state->'retirementOperationId'='null'::jsonb AND job.state->>'phase' IN('pending','licenses','paused');END IF;
 IF job.state->'checkpoint'='null'::jsonb OR jsonb_typeof(job.state->'items')<>'array' OR jsonb_array_length(job.state->'items')>10000
 OR jsonb_typeof(job.state->'bindings')<>'array' OR jsonb_array_length(job.state->'bindings')>10000 THEN RETURN false;END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(job.state->'items') LOOP
  IF NOT license_company_exact(item,ARRAY['poolId','poolRevision','assignmentId','name','vendor','eligibilityRevision','assignedAt','sources','status','eventId'])
  OR NOT license_company_uuid(item->>'poolId') OR item->>'poolId'=ANY(seen) OR NOT license_company_uuid(item->>'assignmentId') OR NOT license_company_revision_valid(item->'poolRevision')
  OR NOT license_company_revision_valid(item->'eligibilityRevision') OR jsonb_typeof(item->'sources')<>'array' OR jsonb_array_length(item->'sources')<1
  OR item->>'status' NOT IN('pending','released','already_released') OR (CASE WHEN item->>'status'='pending' THEN item->'eventId'<>'null'::jsonb ELSE NOT license_company_uuid(item->>'eventId') END) THEN RETURN false;END IF;
  seen=array_append(seen,item->>'poolId');
  FOR source IN SELECT value FROM jsonb_array_elements(item->'sources') LOOP
   IF NOT license_company_exact(source,ARRAY['sourceType','sourceId','grantId']) OR NOT license_company_uuid(source->>'grantId') OR source->>'grantId'=ANY(grants)
   OR (CASE WHEN source->>'sourceType'='direct' THEN source->>'sourceId'<>'direct' WHEN source->>'sourceType'='blueprint' THEN NOT license_company_uuid(source->>'sourceId') ELSE true END) THEN RETURN false;END IF;
   grants=array_append(grants,source->>'grantId');
  END LOOP;
 END LOOP;
 IF cardinality(grants)>10000 THEN RETURN false;END IF;seen='{}';
 FOR binding IN SELECT value FROM jsonb_array_elements(job.state->'bindings') LOOP
  IF NOT license_company_exact(binding,ARRAY['id','revision','blueprintId','version','eligibilityRevision','poolIds']) OR NOT license_company_uuid(binding->>'id') OR binding->>'id'=ANY(seen)
   OR NOT license_company_revision_valid(binding->'revision') OR NOT license_company_revision_valid(binding->'eligibilityRevision') OR NOT license_company_uuid(binding->>'blueprintId')
   OR jsonb_typeof(binding->'poolIds')<>'array' THEN RETURN false;END IF;seen=array_append(seen,binding->>'id');
 END LOOP;
 RETURN job.state->'retirementOperationId'='null'::jsonb OR license_company_uuid(job.state->>'retirementOperationId');
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

CREATE FUNCTION company_blueprint_assignment_retirement_prepare(parent_id UUID) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;values JSONB;item JSONB;actual JSONB;job company_offboarding_v2_jobs;checkpoint JSONB;binding_manifest JSONB;source_count BIGINT;authority JSONB;
BEGIN
 parent=company_blueprint_assignment_parent();values=parent.command->'values';checkpoint=values->'checkpoint';authority=COALESCE(parent.source,parent.application_source);
 IF parent.id IS DISTINCT FROM parent_id OR parent.action<>'retire_sources' OR NOT license_company_exact(values,ARRAY['checkpoint','pools','bindings'])
 OR jsonb_typeof(values->'pools')<>'array' OR jsonb_array_length(values->'pools')>10000 OR jsonb_typeof(values->'bindings')<>'array' OR jsonb_array_length(values->'bindings')>10000
 OR authority#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb OR authority#>>'{target,eligibilityRevision}' IS DISTINCT FROM parent.command->>'eligibilityRevision'
 THEN RAISE EXCEPTION 'Exact negative source retirement authority required' USING ERRCODE='23514';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('company-blueprint-user:'||parent.tenant_id::text||':'||parent.user_id::text,19770026));
 PERFORM 1 FROM company_blueprint_user_assignments WHERE tenant_id=parent.tenant_id AND user_id=parent.user_id AND status='active' ORDER BY id FOR UPDATE;
 binding_manifest=company_blueprint_user_binding_manifest(parent.tenant_id,parent.user_id);
 IF values->'bindings' IS DISTINCT FROM (SELECT COALESCE(jsonb_agg(jsonb_build_object('id',value->'id','revision',value->'revision') ORDER BY value->>'id'),'[]'::jsonb) FROM jsonb_array_elements(binding_manifest))
 THEN RAISE EXCEPTION 'Complete original blueprint binding manifest changed' USING ERRCODE='40001';END IF;
 IF (SELECT COALESCE(jsonb_agg(jsonb_build_object('poolId',value->'poolId','poolRevision',value->'poolRevision') ORDER BY value->>'poolId'),'[]'::jsonb) FROM jsonb_array_elements(values->'pools'))
 IS DISTINCT FROM (SELECT COALESCE(jsonb_agg(value ORDER BY value->>'poolId'),'[]'::jsonb) FROM jsonb_array_elements(parent.command->'pools'))
 THEN RAISE EXCEPTION 'Exact parent retirement pools required' USING ERRCODE='23514';END IF;
 source_count=0;
 FOR item IN SELECT value FROM jsonb_array_elements(values->'pools') LOOP
  IF NOT license_company_exact(item,ARRAY['poolId','poolRevision','assignmentId','sources']) OR NOT license_company_uuid(item->>'assignmentId')
   OR jsonb_typeof(item->'sources')<>'array' OR jsonb_array_length(item->'sources')<1 THEN RAISE EXCEPTION 'Exact original source retirement capture required' USING ERRCODE='23514';END IF;
  actual=license_company_sources((item->>'poolId')::uuid,parent.user_id);source_count=source_count+jsonb_array_length(actual);
  IF actual IS DISTINCT FROM item->'sources' OR NOT EXISTS(SELECT 1 FROM license_assignments WHERE id=(item->>'assignmentId')::uuid AND license_id=(item->>'poolId')::uuid AND assignee_type='user' AND assignee_id=parent.user_id::text)
  THEN RAISE EXCEPTION 'Original projection or source incarnation changed' USING ERRCODE='40001';END IF;
 END LOOP;
 IF source_count>10000 THEN RAISE EXCEPTION 'Atomic retirement source bound exceeded' USING ERRCODE='23514';END IF;
 IF checkpoint='null'::jsonb THEN
  IF jsonb_array_length(binding_manifest)>0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(values->'pools') pool CROSS JOIN LATERAL jsonb_array_elements(pool->'sources') source WHERE source->>'sourceType'<>'direct')
  THEN RAISE EXCEPTION 'workflow_required' USING ERRCODE='23514';END IF;
 ELSE
  IF NOT license_company_uuid(checkpoint->>'workflowId') THEN RAISE EXCEPTION 'Original Identity 045 checkpoint required' USING ERRCODE='23514';END IF;
  SELECT * INTO job FROM company_offboarding_v2_jobs WHERE id=(checkpoint->>'workflowId')::uuid AND tenant_id=parent.tenant_id AND user_id=parent.user_id FOR UPDATE;
  IF job.id IS NULL OR NOT company_offboarding_v2_state_valid(job) OR job.state->'checkpoint' IS DISTINCT FROM checkpoint
   OR authority#>'{target,deleted}' IS DISTINCT FROM 'false'::jsonb
   OR authority#>>'{target,eligibilityRevision}' IS DISTINCT FROM checkpoint->>'afterEligibilityRevision'
   OR checkpoint->>'userId' IS DISTINCT FROM parent.user_id::text OR checkpoint->>'tenantId' IS DISTINCT FROM parent.tenant_id::text
   OR (SELECT COALESCE(jsonb_agg(jsonb_build_object('poolId',value->'poolId','assignmentId',value->'assignmentId','sources',value->'sources') ORDER BY value->>'poolId'),'[]'::jsonb) FROM jsonb_array_elements(job.state->'items'))
    IS DISTINCT FROM (SELECT COALESCE(jsonb_agg(value-'poolRevision' ORDER BY value->>'poolId'),'[]'::jsonb) FROM jsonb_array_elements(values->'pools'))
   OR job.state->'bindings' IS DISTINCT FROM binding_manifest
   OR (SELECT count(*) FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=parent.tenant_id AND assignment.assignee_type='user' AND assignment.assignee_id=parent.user_id::text)<>jsonb_array_length(values->'pools')
  THEN RAISE EXCEPTION 'Exact immutable complete negative workflow capture required' USING ERRCODE='23514';END IF;
 END IF;
END; $$;

CREATE FUNCTION company_offboarding_v2_job_valid(job company_offboarding_v2_jobs) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $$
DECLARE event company_offboarding_v2_events;previous JSONB;expected NUMERIC=1;parent company_blueprint_assignment_operations;result JSONB;item JSONB;
BEGIN
 IF NOT company_offboarding_v2_state_valid(job) THEN RETURN false;END IF;
 FOR event IN SELECT * FROM company_offboarding_v2_events WHERE workflow_id=job.id AND tenant_id=job.tenant_id ORDER BY revision LOOP
  IF event.revision<>expected OR event.before_state IS DISTINCT FROM previous OR event.after_state->>'id' IS DISTINCT FROM job.id::text
   OR event.after_state->>'tenant_id' IS DISTINCT FROM job.tenant_id::text OR event.after_state->>'user_id' IS DISTINCT FROM job.user_id::text
   OR event.after_state->>'revision' IS DISTINCT FROM event.revision::text OR event.after_state->'intent' IS DISTINCT FROM job.intent
   OR NOT company_offboarding_source_valid(event.authority,false) OR event.authority#>>'{tenant,id}' IS DISTINCT FROM job.tenant_id::text
   OR event.authority#>>'{target,id}' IS DISTINCT FROM job.user_id::text OR event.actor_user_id::text IS DISTINCT FROM event.authority->>'actorUserId'
   OR event.valid_until IS DISTINCT FROM to_timestamp((event.authority->>'validUntil')::double precision) OR event.created_at>=event.valid_until
   OR event.valid_until>event.created_at+interval '300 seconds'
   OR NOT EXISTS(SELECT 1 FROM company_offboarding_v2_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND created_at=event.created_at AND status='pending')
   OR NOT company_offboarding_v2_state_valid(jsonb_populate_record(NULL::company_offboarding_v2_jobs,event.after_state)) THEN RETURN false;END IF;
  previous=event.after_state;expected=expected+1;
 END LOOP;
 IF expected<>job.revision::numeric+1 OR previous-'created_at'-'updated_at' IS DISTINCT FROM to_jsonb(job)-'created_at'-'updated_at'
  OR (previous->>'created_at')::timestamptz IS DISTINCT FROM job.created_at OR (previous->>'updated_at')::timestamptz IS DISTINCT FROM job.updated_at THEN RETURN false;END IF;
 IF job.state->>'phase'='completed_local' THEN
  IF job.state->'items'='[]'::jsonb AND job.state->'bindings'='[]'::jsonb AND job.state->'retirementOperationId'='null'::jsonb THEN RETURN true;END IF;
  SELECT * INTO parent FROM company_blueprint_assignment_operations WHERE id=(job.state->>'retirementOperationId')::uuid AND tenant_id=job.tenant_id AND user_id=job.user_id AND action='retire_sources';
  SELECT receipt_event.result INTO result FROM company_blueprint_assignment_events receipt_event JOIN company_blueprint_assignment_outbox queue ON queue.id=receipt_event.id AND queue.status='pending'
   WHERE receipt_event.id=parent.id AND receipt_event.tenant_id=parent.tenant_id;
  IF parent.id IS NULL OR parent.command#>'{values,checkpoint}' IS DISTINCT FROM job.state->'checkpoint' OR result IS NULL
   OR jsonb_array_length(result->'pools')<>jsonb_array_length(job.state->'items') THEN RETURN false;END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(job.state->'items') LOOP
   IF item->>'status' NOT IN('released','already_released') OR NOT EXISTS(SELECT 1 FROM license_company_events child_event JOIN license_company_commands child ON child.id=child_event.id
    WHERE child_event.id=(item->>'eventId')::uuid AND child.parent_operation_id=parent.id AND child.license_id=(item->>'poolId')::uuid
    AND child_event.before_state#>>'{assignment,id}'=item->>'assignmentId' AND child_event.before_state->'sources'=item->'sources' AND child_event.after_state->'sources'='[]'::jsonb
    AND child_event.after_state->'assignment'='null'::jsonb AND license_company_event_valid(child_event)) THEN RETURN false;END IF;
  END LOOP;
 END IF;
 RETURN true;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;

CREATE FUNCTION company_offboarding_v2_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;job company_offboarding_v2_jobs;
BEGIN
 IF TG_OP='TRUNCATE' OR TG_TABLE_NAME='company_offboarding_v2_receiver_manifest' THEN RAISE EXCEPTION 'Retained V2 lifecycle evidence is immutable' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.company_offboarding_v2',true),'')::jsonb;
 IF proof IS NULL OR NOT company_offboarding_source_valid(proof) OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass)
  OR current_setting('role',true) NOT IN('none','') OR current_setting('session_replication_role')<>'origin'
  OR TG_OP='DELETE' OR TG_TABLE_NAME<>'company_offboarding_v2_jobs' AND TG_OP<>'INSERT'
 THEN RAISE EXCEPTION 'Original V2 lifecycle admission required' USING ERRCODE='42501';END IF;
 IF NEW.tenant_id::text IS DISTINCT FROM proof#>>'{tenant,id}' THEN RAISE EXCEPTION 'Original V2 lifecycle tenant required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_offboarding_v2_jobs' THEN
  IF NEW.user_id::text IS DISTINCT FROM proof#>>'{target,id}' OR NOT company_offboarding_v2_state_valid(NEW)
   OR TG_OP='UPDATE' AND (ROW(NEW.id,NEW.tenant_id,NEW.user_id,NEW.created_by,NEW.intent,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.tenant_id,OLD.user_id,OLD.created_by,OLD.intent,OLD.created_at)
    OR NEW.revision::numeric<>OLD.revision::numeric+1 OR OLD.state->>'phase'='completed_local'
    OR OLD.state->'checkpoint'<>'null'::jsonb AND NEW.state->'checkpoint' IS DISTINCT FROM OLD.state->'checkpoint'
    OR OLD.state->'items'<>'null'::jsonb AND (NEW.state->'bindings' IS DISTINCT FROM OLD.state->'bindings'
     OR (SELECT jsonb_agg(value-ARRAY['status','eventId'] ORDER BY value->>'poolId') FROM jsonb_array_elements(NEW.state->'items')) IS DISTINCT FROM (SELECT jsonb_agg(value-ARRAY['status','eventId'] ORDER BY value->>'poolId') FROM jsonb_array_elements(OLD.state->'items'))))
  THEN RAISE EXCEPTION 'Immutable original V2 workflow capture required' USING ERRCODE='23514';END IF;
  IF NEW.state->>'phase'<>'paused' AND NEW.state->'checkpoint'<>'null'::jsonb AND (proof#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb
    OR proof#>'{target,deleted}' IS DISTINCT FROM 'false'::jsonb OR proof#>>'{target,eligibilityRevision}' IS DISTINCT FROM NEW.state#>>'{checkpoint,afterEligibilityRevision}')
   THEN RAISE EXCEPTION 'Original 045 negative epoch changed' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='company_offboarding_v2_events' THEN
  SELECT * INTO job FROM company_offboarding_v2_jobs WHERE id=NEW.workflow_id;
  IF NEW.after_state IS DISTINCT FROM to_jsonb(job) OR NEW.revision<>job.revision OR NEW.actor_user_id::text IS DISTINCT FROM proof->>'actorUserId'
   OR NEW.authority IS DISTINCT FROM proof OR NEW.valid_until IS DISTINCT FROM to_timestamp((proof->>'validUntil')::double precision)
   OR NEW.before_state IS DISTINCT FROM (SELECT after_state FROM company_offboarding_v2_events WHERE workflow_id=job.id ORDER BY revision DESC LIMIT 1)
   THEN RAISE EXCEPTION 'Actual V2 lifecycle transition required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='company_offboarding_v2_outbox' THEN
  IF NOT EXISTS(SELECT 1 FROM company_offboarding_v2_events WHERE id=NEW.id AND tenant_id=NEW.tenant_id AND created_at=NEW.created_at) OR NEW.status<>'pending'
   THEN RAISE EXCEPTION 'Actual pending V2 lifecycle event required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='company_offboarding_v2_requests' THEN
  SELECT * INTO job FROM company_offboarding_v2_jobs WHERE id=NEW.workflow_id;
  IF job.user_id::text IS DISTINCT FROM proof#>>'{target,id}' OR NEW.actor_user_id::text IS DISTINCT FROM proof->>'actorUserId'
   OR NEW.valid_until IS DISTINCT FROM to_timestamp((proof->>'validUntil')::double precision) THEN RAISE EXCEPTION 'Original V2 workflow request required' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END; $$;

CREATE FUNCTION company_offboarding_v2_commit() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE job company_offboarding_v2_jobs;proof JSONB;
BEGIN
 PERFORM company_blueprint_assignment_retirement_receiving();proof=NULLIF(current_setting('opendirectory.company_offboarding_v2',true),'')::jsonb;
 IF NOT company_offboarding_source_valid(proof) THEN RAISE EXCEPTION 'Original V2 lifecycle deadline expired before commit' USING ERRCODE='42501';END IF;
 SELECT * INTO job FROM company_offboarding_v2_jobs WHERE id=CASE WHEN TG_TABLE_NAME='company_offboarding_v2_jobs' THEN NEW.id ELSE (to_jsonb(NEW)->>'workflow_id')::uuid END;
 IF job.id IS NULL OR NOT company_offboarding_v2_job_valid(job) THEN RAISE EXCEPTION 'Complete actual V2 lifecycle receipts required before commit' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;

CREATE FUNCTION company_offboarding_v2_write(source JSONB,workflow UUID,expected BIGINT,intent JSONB,state JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE previous company_offboarding_v2_jobs;job company_offboarding_v2_jobs;event UUID=gen_random_uuid();capture JSONB;
BEGIN
 PERFORM company_blueprint_assignment_retirement_receiving();
 IF NOT company_offboarding_source_valid(source) THEN RAISE EXCEPTION 'Original V2 workflow authority required' USING ERRCODE='42501';END IF;
 PERFORM company_blueprint_subject_locks(source);
 SELECT * INTO previous FROM company_offboarding_v2_jobs WHERE id=workflow FOR UPDATE;
 IF previous.id IS NULL THEN
  IF expected<>0 OR NOT company_offboarding_intent_valid(intent) OR intent->>'workflowId' IS DISTINCT FROM workflow::text OR intent->>'userId' IS DISTINCT FROM source#>>'{target,id}'
   OR state IS DISTINCT FROM jsonb_build_object('phase','pending','requestedRevision',intent->'userRevision','checkpoint',NULL,'items',NULL,'bindings',NULL,'failure',NULL,'retirementOperationId',NULL)
   OR source#>>'{target,eligibilityRevision}' IS DISTINCT FROM intent->>'eligibilityRevision' THEN RAISE EXCEPTION 'Exact original V2 workflow intent required' USING ERRCODE='23514';END IF;
  job.id=workflow;job.tenant_id=(source#>>'{tenant,id}')::uuid;job.user_id=(source#>>'{target,id}')::uuid;job.created_by=(source->>'actorUserId')::uuid;job.revision=1;job.intent=intent;job.created_at=clock_timestamp();
 ELSE
  IF previous.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR previous.user_id::text IS DISTINCT FROM source#>>'{target,id}' THEN RAISE EXCEPTION 'Own V2 workflow required' USING ERRCODE='P0002';END IF;
  IF previous.revision<>expected THEN RAISE EXCEPTION 'V2 workflow revision changed' USING ERRCODE='40001';END IF;
  job=previous;job.revision=previous.revision+1;
 END IF;
 job.state=state;job.updated_at=clock_timestamp();
 IF previous.id IS NOT NULL AND previous.state->'items'='null'::jsonb AND state->'items'<>'null'::jsonb THEN
  capture=company_offboarding_v2_capture(job.tenant_id,job.user_id);
  IF state->'items' IS DISTINCT FROM capture->'items' OR state->'bindings' IS DISTINCT FROM capture->'bindings' THEN RAISE EXCEPTION 'Complete actual V2 source capture required' USING ERRCODE='23514';END IF;
 END IF;
 IF state->>'phase'='completed_local' AND (EXISTS(SELECT 1 FROM license_assignments assignment JOIN license_catalog catalog ON catalog.id=assignment.license_id WHERE catalog.business_tenant_id=job.tenant_id AND assignment.assignee_type='user' AND assignment.assignee_id=job.user_id::text)
  OR EXISTS(SELECT 1 FROM license_assignment_sources source JOIN license_catalog catalog ON catalog.id=source.license_id WHERE catalog.business_tenant_id=job.tenant_id AND source.user_id=job.user_id::text)
  OR EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE tenant_id=job.tenant_id AND user_id=job.user_id AND status='active')) THEN RAISE EXCEPTION 'Uncaptured sources or bindings remain' USING ERRCODE='23514';END IF;
 PERFORM set_config('opendirectory.company_offboarding_v2',source::text,true);
 IF previous.id IS NULL THEN INSERT INTO company_offboarding_v2_jobs SELECT job.*;ELSE UPDATE company_offboarding_v2_jobs SET revision=job.revision,state=job.state,updated_at=job.updated_at WHERE id=job.id;END IF;
 INSERT INTO company_offboarding_v2_events VALUES(event,job.tenant_id,job.id,job.revision,(source->>'actorUserId')::uuid,CASE WHEN previous.id IS NULL THEN NULL ELSE to_jsonb(previous) END,to_jsonb(job),source,to_timestamp((source->>'validUntil')::double precision),job.updated_at);
 INSERT INTO company_offboarding_v2_outbox VALUES(event,job.tenant_id,'pending',job.updated_at);
 IF NOT company_offboarding_v2_job_valid(job) THEN RAISE EXCEPTION 'Actual V2 workflow state, history and outbox required' USING ERRCODE='23514';END IF;
 RETURN to_jsonb(job)||jsonb_build_object('revision',job.revision::text);
END; $$;

CREATE FUNCTION company_offboarding_v2_request(source JSONB,workflow UUID,request_id UUID,request JSONB) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER AS $$
#variable_conflict use_variable
DECLARE prior company_offboarding_v2_requests;job company_offboarding_v2_jobs;
BEGIN
 PERFORM company_blueprint_assignment_retirement_receiving();IF NOT company_offboarding_source_valid(source) THEN RAISE EXCEPTION 'Original V2 request authority required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(request_id::text,0));
 SELECT * INTO prior FROM company_offboarding_v2_requests WHERE id=request_id;
 IF prior.id IS NOT NULL THEN
  IF prior.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR prior.workflow_id<>workflow OR prior.actor_user_id::text IS DISTINCT FROM source->>'actorUserId' OR prior.request IS DISTINCT FROM request
  THEN RAISE EXCEPTION 'V2 idempotency key intent changed' USING ERRCODE='23505';END IF;RETURN false;
 END IF;
 SELECT * INTO job FROM company_offboarding_v2_jobs WHERE id=workflow FOR UPDATE;
 IF job.id IS NULL OR job.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR job.user_id::text IS DISTINCT FROM source#>>'{target,id}' THEN RAISE EXCEPTION 'Own V2 workflow required' USING ERRCODE='P0002';END IF;
 IF request->>'expectedRevision' IS DISTINCT FROM job.revision::text THEN RAISE EXCEPTION 'V2 workflow changed' USING ERRCODE='40001';END IF;
 PERFORM set_config('opendirectory.company_offboarding_v2',source::text,true);
 INSERT INTO company_offboarding_v2_requests VALUES(request_id,job.tenant_id,workflow,(source->>'actorUserId')::uuid,request,clock_timestamp(),to_timestamp((source->>'validUntil')::double precision));
 RETURN true;
END; $$;

CREATE FUNCTION company_blueprint_assignment_retirement_receiving() RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE specification RECORD;relation TEXT;
BEGIN
 PERFORM company_blueprint_assignment_receiving(false);
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass) OR current_setting('role',true) NOT IN('none','')
 OR NOT EXISTS(SELECT 1 FROM license_schema_versions WHERE version=27) OR current_setting('session_replication_role')<>'origin'
 OR (SELECT count(*) FROM company_offboarding_v2_receiver_manifest)<>12 THEN RAISE EXCEPTION 'Complete V2 lifecycle migration required' USING ERRCODE='42501';END IF;
 FOR specification IN SELECT * FROM company_offboarding_v2_receiver_manifest LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=to_regprocedure(specification.signature) AND md5(prosrc)=specification.digest AND prosecdef=specification.definer
   AND proowner=(SELECT relowner FROM pg_class WHERE oid='license_catalog'::regclass)) THEN RAISE EXCEPTION 'V2 lifecycle receiver changed: %',specification.signature USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['company_offboarding_v2_jobs','company_offboarding_v2_events','company_offboarding_v2_outbox','company_offboarding_v2_requests','company_offboarding_v2_receiver_manifest'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_guard' AND tgenabled='O' AND tgtype=31 AND tgqual IS NULL AND tgfoid='company_offboarding_v2_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_truncate' AND tgenabled='O' AND tgtype=34 AND tgfoid='company_offboarding_v2_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'V2 lifecycle evidence guard unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['company_offboarding_v2_jobs','company_offboarding_v2_requests'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname=relation||'_commit' AND tgenabled='O' AND tgtype=21 AND tgqual IS NULL AND tgdeferrable AND tginitdeferred AND tgfoid='company_offboarding_v2_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'V2 lifecycle commit receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;

CREATE FUNCTION company_blueprint_assignment_retirement_finish(parent_id UUID) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE parent company_blueprint_assignment_operations;binding JSONB;
BEGIN
 parent=company_blueprint_assignment_parent();IF parent.id IS DISTINCT FROM parent_id OR parent.action<>'retire_sources' THEN RAISE EXCEPTION 'Original retirement parent required' USING ERRCODE='42501';END IF;
 IF EXISTS(SELECT 1 FROM license_assignment_sources WHERE user_id=parent.user_id::text AND license_id IN(SELECT (value->>'poolId')::uuid FROM jsonb_array_elements(parent.command->'pools')))
 OR EXISTS(SELECT 1 FROM license_assignments WHERE assignee_type='user' AND assignee_id=parent.user_id::text AND license_id IN(SELECT (value->>'poolId')::uuid FROM jsonb_array_elements(parent.command->'pools')))
 THEN RAISE EXCEPTION 'All captured original sources and seats must be retired' USING ERRCODE='23514';END IF;
 FOR binding IN SELECT value FROM jsonb_array_elements(parent.command#>'{values,bindings}') LOOP
  IF EXISTS(SELECT 1 FROM license_assignment_sources WHERE source_type='blueprint' AND source_id=binding->>'id') THEN RAISE EXCEPTION 'A blueprint binding still has outstanding pool sources' USING ERRCODE='23514';END IF;
  UPDATE company_blueprint_user_assignments SET status='removed',revision=revision+1,removed_at=clock_timestamp(),removal_operation_id=parent.id
  WHERE id=(binding->>'id')::uuid AND tenant_id=parent.tenant_id AND user_id=parent.user_id AND status='active' AND revision::text=binding->>'revision';
  IF NOT FOUND THEN RAISE EXCEPTION 'Exact original blueprint binding retirement required' USING ERRCODE='40001';END IF;
 END LOOP;
 IF jsonb_array_length(parent.command#>'{values,bindings}')>0 AND EXISTS(SELECT 1 FROM company_blueprint_user_assignments WHERE tenant_id=parent.tenant_id AND user_id=parent.user_id AND status='active')
 THEN RAISE EXCEPTION 'Uncaptured active blueprint binding remains' USING ERRCODE='23514';END IF;
END; $$;

INSERT INTO company_offboarding_v2_receiver_manifest SELECT signature,md5(prosrc),prosecdef FROM unnest(ARRAY[
 'company_blueprint_user_binding_manifest(uuid,uuid)','license_company_v1_sources_require(uuid,uuid,uuid)','company_offboarding_v2_capture(uuid,uuid)',
 'company_offboarding_v2_state_valid(company_offboarding_v2_jobs)','company_blueprint_assignment_retirement_prepare(uuid)','company_blueprint_assignment_retirement_finish(uuid)',
 'company_offboarding_v2_job_valid(company_offboarding_v2_jobs)','company_offboarding_v2_guard()','company_offboarding_v2_commit()',
 'company_offboarding_v2_write(jsonb,uuid,bigint,jsonb,jsonb)','company_offboarding_v2_request(jsonb,uuid,uuid,jsonb)','company_blueprint_assignment_retirement_receiving()'
]) signature JOIN pg_proc ON oid=to_regprocedure(signature);
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['company_offboarding_v2_jobs','company_offboarding_v2_events','company_offboarding_v2_outbox','company_offboarding_v2_requests','company_offboarding_v2_receiver_manifest'] LOOP
  EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_offboarding_v2_guard()',relation||'_guard',relation);
  EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_offboarding_v2_guard()',relation||'_truncate',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['company_offboarding_v2_jobs','company_offboarding_v2_requests'] LOOP
  EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_offboarding_v2_commit()',relation||'_commit',relation);
 END LOOP;
END; $$;
INSERT INTO license_schema_versions(version) VALUES(27);
REVOKE ALL ON company_offboarding_v2_jobs,company_offboarding_v2_events,company_offboarding_v2_outbox,company_offboarding_v2_requests,company_offboarding_v2_receiver_manifest FROM PUBLIC;
 $migration$;
END IF;
END; $install$;
