CREATE TABLE IF NOT EXISTS company_offboarding_jobs (
 tenant_id UUID NOT NULL,id UUID NOT NULL,user_id UUID NOT NULL,created_by UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0),intent JSONB NOT NULL,state JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,updated_at TIMESTAMPTZ NOT NULL,PRIMARY KEY(tenant_id,id)
);
CREATE INDEX IF NOT EXISTS company_offboarding_job_page ON company_offboarding_jobs(tenant_id,created_at DESC,id);
CREATE TABLE IF NOT EXISTS company_offboarding_events (
 id UUID PRIMARY KEY,tenant_id UUID NOT NULL,workflow_id UUID NOT NULL,revision BIGINT NOT NULL CHECK(revision>0),
 actor_user_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 transaction_id BIGINT NOT NULL UNIQUE,authority JSONB NOT NULL,before_state JSONB,after_state JSONB NOT NULL,
 FOREIGN KEY(tenant_id,workflow_id) REFERENCES company_offboarding_jobs(tenant_id,id),UNIQUE(tenant_id,workflow_id,revision)
);
CREATE TABLE IF NOT EXISTS company_offboarding_outbox (
 id UUID PRIMARY KEY REFERENCES company_offboarding_events(id),tenant_id UUID NOT NULL,
 status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION company_offboarding_source_valid(source JSONB,physical BOOLEAN DEFAULT true) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE field TEXT;target JSONB;
BEGIN
 IF NOT license_company_exact(source,ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'])
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR source->'permissions' IS DISTINCT FROM '["company.apps.read","company.apps.create","company.apps.assign"]'::jsonb
  OR NOT license_company_exact(source->'context',ARRAY['userId','revision','linkRevision','rolesRevision'])
  OR NOT license_company_exact(source->'tenant',ARRAY['id','version','generation'])
  OR NOT license_company_uuid(source->>'actorUserId') OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
  OR NOT license_company_uuid(source#>>'{tenant,id}') OR NOT license_company_revision_valid(source#>'{context,revision}')
  OR NOT license_company_revision_valid(source#>'{context,linkRevision}') OR NOT license_company_revision_valid(source#>'{tenant,version}')
  OR NOT license_company_revision_valid(source#>'{tenant,generation}') OR jsonb_typeof(source#>'{context,rolesRevision}') IS DISTINCT FROM 'string'
  OR NOT COALESCE(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$',false)
  THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['issuer','subject','tokenId'] LOOP
  IF jsonb_typeof(source->field) IS DISTINCT FROM 'string' OR source->>field IS DISTINCT FROM btrim(source->>field)
   OR length(source->>field) NOT BETWEEN 1 AND (CASE WHEN field='issuer' THEN 2048 ELSE 255 END) OR source->>field ~ '[[:cntrl:]]' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['expiresAt','validUntil'] LOOP
  IF jsonb_typeof(source->field) IS DISTINCT FROM 'number' OR NOT COALESCE(source->>field ~ '^[0-9]{1,12}$',false) THEN RETURN false;END IF;
 END LOOP;
 IF (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric OR physical AND ((source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300) THEN RETURN false;END IF;
 target=source->'target';
 RETURN license_company_exact(target,ARRAY['id','revision','eligibilityRevision','enabled','deleted']) AND license_company_uuid(target->>'id')
  AND license_company_revision_valid(target->'eligibilityRevision') AND jsonb_typeof(target->'enabled')='boolean' AND jsonb_typeof(target->'deleted')='boolean'
  AND NOT(target->'deleted'='true'::jsonb AND target->'enabled'='true'::jsonb)
  AND CASE WHEN target->'deleted'='true'::jsonb THEN target->'revision'='null'::jsonb ELSE license_company_revision_valid(target->'revision') END;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_check_source(source JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='company_offboarding_jobs'::regclass)
  OR current_setting('role',true) NOT IN('none','') OR current_setting('session_replication_role')<>'origin'
  OR NOT COALESCE(company_offboarding_source_valid(source),false)
  OR NULLIF(current_setting('opendirectory.license_company',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current())
  THEN RAISE EXCEPTION 'Original bounded company offboarding authority required' USING ERRCODE='42501';END IF;
END; $$;
COMMENT ON FUNCTION company_offboarding_check_source(JSONB) IS 'The existing SQL owner is trusted to supply the original Identity source and fresh verification. Structural guards are not remote cryptographic proof. Journal writes never allocate or release licenses.';
CREATE OR REPLACE FUNCTION company_offboarding_intent_valid(intent JSONB) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(license_company_exact(intent,ARRAY['workflowId','userId','userRevision','eligibilityRevision','reason','confirm'])
  AND license_company_uuid(intent->>'workflowId') AND license_company_uuid(intent->>'userId')
  AND license_company_revision_valid(intent->'userRevision') AND license_company_revision_valid(intent->'eligibilityRevision')
  AND intent->'confirm'='true'::jsonb AND jsonb_typeof(intent->'reason')='string' AND intent->>'reason'=btrim(intent->>'reason')
  AND length(intent->>'reason') BETWEEN 10 AND 500 AND NOT intent->>'reason' ~ '[[:cntrl:]]',false);
$$;
CREATE OR REPLACE FUNCTION company_offboarding_receipt_valid(receipt JSONB,job company_offboarding_jobs) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE field TEXT;stamp TIMESTAMPTZ;
BEGIN
 IF NOT license_company_exact(receipt,ARRAY['schemaVersion','workflowId','tenantId','userId','actorUserId','operationId','action','beforeRevision','afterRevision','beforeEligibilityRevision','afterEligibilityRevision','createdAt','deliveryStatus'])
  OR receipt->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR receipt->>'workflowId' IS DISTINCT FROM job.id::text
  OR receipt->>'tenantId' IS DISTINCT FROM job.tenant_id::text OR receipt->>'userId' IS DISTINCT FROM job.user_id::text
  OR NOT license_company_uuid(receipt->>'actorUserId') OR NOT(receipt->'operationId'='null'::jsonb OR license_company_uuid(receipt->>'operationId'))
  OR NOT COALESCE(receipt->>'action' IN('disabled','already_disabled'),false) OR receipt->>'deliveryStatus' IS DISTINCT FROM 'pending'
  OR NOT COALESCE(receipt->>'createdAt' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$',false)
  THEN RETURN false;END IF;
 stamp=(receipt->>'createdAt')::timestamptz;
 IF to_char(stamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') IS DISTINCT FROM receipt->>'createdAt' THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['beforeRevision','afterRevision','beforeEligibilityRevision','afterEligibilityRevision'] LOOP
  IF NOT license_company_revision_valid(receipt->field) THEN RETURN false;END IF;
 END LOOP;
 RETURN receipt->>'beforeRevision'=job.state->>'requestedRevision'
  AND CASE WHEN receipt->>'action'='disabled' THEN license_company_uuid(receipt->>'operationId')
   AND (receipt->>'afterRevision')::numeric>(receipt->>'beforeRevision')::numeric AND (receipt->>'afterEligibilityRevision')::numeric>(receipt->>'beforeEligibilityRevision')::numeric
   ELSE receipt->'operationId'='null'::jsonb AND receipt->>'afterRevision'=receipt->>'beforeRevision' AND receipt->>'afterEligibilityRevision'=receipt->>'beforeEligibilityRevision' END;
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_state_valid(job company_offboarding_jobs) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE state JSONB;item JSONB;failure JSONB;field TEXT;
BEGIN
 state=job.state;failure=state->'failure';
 IF NOT license_company_exact(state,ARRAY['phase','requestedRevision','checkpoint','items','failure'])
  OR NOT COALESCE(state->>'phase' IN('pending','licenses','paused','completed_local'),false) OR NOT license_company_revision_valid(state->'requestedRevision')
  OR state->'checkpoint'<>'null'::jsonb AND NOT company_offboarding_receipt_valid(state->'checkpoint',job)
  OR state->'items'<>'null'::jsonb AND jsonb_typeof(state->'items') IS DISTINCT FROM 'array'
  OR state->'checkpoint'='null'::jsonb AND state->'items'<>'null'::jsonb
  OR state->>'phase'='pending' AND (state->'checkpoint'<>'null'::jsonb OR state->'items'<>'null'::jsonb)
  OR state->>'phase' IN('licenses','completed_local') AND state->'checkpoint'='null'::jsonb
  OR state->>'phase'='completed_local' AND state->'items'='null'::jsonb
  THEN RETURN false;END IF;
 IF state->>'phase'='paused' THEN
  IF NOT license_company_exact(failure,ARRAY['code','step']) OR jsonb_typeof(failure->'code') IS DISTINCT FROM 'number'
   OR NOT COALESCE(failure->>'code' ~ '^[45][0-9]{2}$',false) OR NOT COALESCE(failure->>'step' IN('account','capture','licenses','verify'),false) THEN RETURN false;END IF;
 ELSIF failure<>'null'::jsonb THEN RETURN false;END IF;
 IF state->'items'='null'::jsonb THEN RETURN true;END IF;
 FOR item IN SELECT * FROM jsonb_array_elements(state->'items') LOOP
  IF NOT license_company_exact(item,ARRAY['poolId','assignmentId','grantId','poolRevision','name','vendor','status','eventId'])
   OR NOT license_company_uuid(item->>'poolId') OR NOT license_company_uuid(item->>'assignmentId') OR NOT license_company_uuid(item->>'grantId')
   OR NOT license_company_revision_valid(item->'poolRevision') OR NOT COALESCE(item->>'status' IN('pending','released','already_released'),false)
   OR (CASE WHEN item->>'status'='pending' THEN item->'eventId'<>'null'::jsonb ELSE NOT license_company_uuid(item->>'eventId') END) THEN RETURN false;END IF;
  FOREACH field IN ARRAY ARRAY['name','vendor'] LOOP
   IF jsonb_typeof(item->field) IS DISTINCT FROM 'string' OR item->>field IS DISTINCT FROM btrim(item->>field)
    OR length(item->>field) NOT BETWEEN 1 AND 160 OR item->>field ~ '[[:cntrl:]]' THEN RETURN false;END IF;
  END LOOP;
 END LOOP;
 RETURN NOT EXISTS(SELECT 1 FROM jsonb_array_elements(state->'items') element GROUP BY element->>'poolId' HAVING count(*)>1)
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(state->'items') element GROUP BY element->>'assignmentId' HAVING count(*)>1)
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(state->'items') element GROUP BY element->>'grantId' HAVING count(*)>1);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_release_valid(job company_offboarding_jobs,item JSONB) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE event license_company_events;
BEGIN
 SELECT * INTO event FROM license_company_events WHERE id=(item->>'eventId')::uuid AND tenant_id=job.tenant_id AND license_id=(item->>'poolId')::uuid
  AND target_user_id=job.user_id AND type='app.license.released';
 RETURN event.id IS NOT NULL AND license_company_event_valid(event)
  AND event.before_state#>>'{assignment,id}'=item->>'assignmentId' AND event.before_state#>>'{source,grant_id}'=item->>'grantId'
  AND event.before_revision::text=item->>'poolRevision'
  AND (item->>'status'='already_released' OR item->>'status'='released' AND event.correlation_id=job.id);
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_transition(before_job company_offboarding_jobs,after_job company_offboarding_jobs,source JSONB) RETURNS void LANGUAGE plpgsql AS $$
DECLARE state JSONB;previous JSONB;item JSONB;old_item JSONB;catalog license_catalog;
BEGIN
 state=after_job.state;previous=before_job.state;
 IF NOT company_offboarding_intent_valid(after_job.intent) OR NOT company_offboarding_state_valid(after_job)
  OR after_job.id::text IS DISTINCT FROM after_job.intent->>'workflowId' OR after_job.user_id::text IS DISTINCT FROM after_job.intent->>'userId'
  OR after_job.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}' OR after_job.user_id::text IS DISTINCT FROM source#>>'{target,id}'
  THEN RAISE EXCEPTION 'Exact own company offboarding state required' USING ERRCODE='23514';END IF;
 IF before_job.id IS NULL THEN
  IF after_job.revision<>1 OR after_job.created_by::text IS DISTINCT FROM source->>'actorUserId'
   OR state IS DISTINCT FROM jsonb_build_object('phase','pending','requestedRevision',after_job.intent->'userRevision','checkpoint',NULL,'items',NULL,'failure',NULL)
   OR source#>>'{target,eligibilityRevision}' IS DISTINCT FROM after_job.intent->>'eligibilityRevision'
   THEN RAISE EXCEPTION 'Initial original company offboarding intent required' USING ERRCODE='23514';END IF;
 ELSE
  IF ROW(after_job.tenant_id,after_job.id,after_job.user_id,after_job.created_by,after_job.intent,after_job.created_at)
   IS DISTINCT FROM ROW(before_job.tenant_id,before_job.id,before_job.user_id,before_job.created_by,before_job.intent,before_job.created_at)
   OR after_job.revision::numeric<>before_job.revision::numeric+1 OR previous->>'phase'='completed_local'
   OR previous->'checkpoint'<>'null'::jsonb AND (state->'checkpoint' IS DISTINCT FROM previous->'checkpoint' OR state->'requestedRevision' IS DISTINCT FROM previous->'requestedRevision')
   OR state->'requestedRevision' IS DISTINCT FROM previous->'requestedRevision' AND (previous->'checkpoint'<>'null'::jsonb
    OR source#>>'{target,eligibilityRevision}' IS DISTINCT FROM after_job.intent->>'eligibilityRevision')
   THEN RAISE EXCEPTION 'Immutable company offboarding intent and checkpoint required' USING ERRCODE='23514';END IF;
 END IF;
 IF state->'checkpoint'<>'null'::jsonb THEN
  IF (previous IS NULL OR previous->'checkpoint'='null'::jsonb) AND (state#>>'{checkpoint,actorUserId}' IS DISTINCT FROM source->>'actorUserId'
   OR state#>>'{checkpoint,beforeEligibilityRevision}' IS DISTINCT FROM after_job.intent->>'eligibilityRevision')
   THEN RAISE EXCEPTION 'Original account checkpoint required' USING ERRCODE='23514';END IF;
  IF state->>'phase'<>'paused' AND (source#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb
   OR source#>>'{target,eligibilityRevision}' IS DISTINCT FROM state#>>'{checkpoint,afterEligibilityRevision}')
   THEN RAISE EXCEPTION 'Exact negative account eligibility checkpoint required' USING ERRCODE='23514';END IF;
  IF state->>'phase'='paused' AND (source#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb
   OR source#>>'{target,eligibilityRevision}' IS DISTINCT FROM state#>>'{checkpoint,afterEligibilityRevision}')
   AND state->'items' IS DISTINCT FROM COALESCE(previous->'items','null'::jsonb)
   THEN RAISE EXCEPTION 'Mismatched eligibility permits diagnostics only' USING ERRCODE='23514';END IF;
 END IF;
 IF before_job.id IS NOT NULL AND previous->'items'<>'null'::jsonb THEN
  IF state->'items'='null'::jsonb OR jsonb_array_length(state->'items')<>jsonb_array_length(previous->'items') THEN RAISE EXCEPTION 'Captured membership is immutable' USING ERRCODE='23514';END IF;
 END IF;
 IF state->'items'<>'null'::jsonb THEN
  FOR item IN SELECT * FROM jsonb_array_elements(state->'items') LOOP
   old_item=NULL;
   IF before_job.id IS NOT NULL AND previous->'items'<>'null'::jsonb THEN
    SELECT element INTO old_item FROM jsonb_array_elements(previous->'items') element WHERE element->>'poolId'=item->>'poolId';
    IF old_item IS NULL OR item-ARRAY['poolRevision','status','eventId'] IS DISTINCT FROM old_item-ARRAY['poolRevision','status','eventId']
     OR old_item->>'status'<>'pending' AND item IS DISTINCT FROM old_item
     OR old_item->>'status'='pending' AND item->>'status'='pending' AND item IS DISTINCT FROM old_item
     OR item->'poolRevision' IS DISTINCT FROM old_item->'poolRevision' AND item->>'status'<>'released'
     THEN RAISE EXCEPTION 'Captured license identity and outcomes are immutable' USING ERRCODE='23514';END IF;
   ELSE
    SELECT * INTO catalog FROM license_catalog WHERE id=(item->>'poolId')::uuid AND business_tenant_id=after_job.tenant_id FOR SHARE;
    IF item->>'status'<>'pending' OR catalog.id IS NULL OR NOT license_company_pool_valid(catalog.id)
     OR catalog.business_revision::text IS DISTINCT FROM item->>'poolRevision' OR catalog.name IS DISTINCT FROM item->>'name' OR catalog.vendor IS DISTINCT FROM item->>'vendor'
     OR NOT EXISTS(SELECT 1 FROM license_assignments assignment JOIN license_assignment_sources direct ON direct.license_id=assignment.license_id AND direct.user_id=assignment.assignee_id AND direct.source_type='direct'
      JOIN license_grants retained ON retained.id=direct.grant_id AND retained.license_id=assignment.license_id AND retained.recipient_id=assignment.assignee_id AND retained.kind='direct'
      WHERE assignment.id=(item->>'assignmentId')::uuid AND assignment.license_id=catalog.id AND assignment.assignee_type='user' AND assignment.assignee_id=after_job.user_id::text
       AND assignment.expires_at IS NULL AND direct.grant_id=(item->>'grantId')::uuid)
     THEN RAISE EXCEPTION 'Actual own retained assignment capture required' USING ERRCODE='23514';END IF;
   END IF;
   IF item->>'status'<>'pending' AND NOT COALESCE(company_offboarding_release_valid(after_job,item),false)
    THEN RAISE EXCEPTION 'Actual immutable allocator release receipt required' USING ERRCODE='23514';END IF;
  END LOOP;
 END IF;
 IF state->>'phase'='completed_local' THEN
  LOCK TABLE license_assignments IN SHARE MODE;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements(state->'items') captured WHERE captured->>'status'='pending')
   OR EXISTS(SELECT 1 FROM license_assignments assignment JOIN license_catalog inventory ON inventory.id=assignment.license_id
    WHERE inventory.business_tenant_id=after_job.tenant_id AND assignment.assignee_type='user' AND assignment.assignee_id=after_job.user_id::text)
   THEN RAISE EXCEPTION 'All actual own local license assignments must be released' USING ERRCODE='23514';END IF;
 END IF;
END; $$;

CREATE OR REPLACE FUNCTION company_offboarding_job_valid(job company_offboarding_jobs) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE event company_offboarding_events;previous JSONB;expected NUMERIC=1;snapshot company_offboarding_jobs;item JSONB;old_item JSONB;
BEGIN
 IF NOT company_offboarding_intent_valid(job.intent) OR NOT company_offboarding_state_valid(job) THEN RETURN false;END IF;
 FOR event IN SELECT * FROM company_offboarding_events WHERE tenant_id=job.tenant_id AND workflow_id=job.id ORDER BY revision LOOP
  IF event.revision<>expected OR event.before_state IS DISTINCT FROM previous OR event.after_state->>'revision' IS DISTINCT FROM event.revision::text
   OR event.after_state->>'tenant_id' IS DISTINCT FROM job.tenant_id::text OR event.after_state->>'id' IS DISTINCT FROM job.id::text
   OR event.after_state->'intent' IS DISTINCT FROM job.intent OR event.after_state->>'created_by' IS DISTINCT FROM job.created_by::text
   OR event.after_state->>'user_id' IS DISTINCT FROM job.user_id::text OR event.after_state->'created_at' IS DISTINCT FROM to_jsonb(job)->'created_at'
   OR event.created_at IS DISTINCT FROM (event.after_state->>'updated_at')::timestamptz
   OR event.valid_until<=event.created_at OR event.valid_until>event.created_at+interval '300 seconds'
   OR NOT company_offboarding_source_valid(event.authority||jsonb_build_object('tokenId','retained-identifier-omitted'),false)
   OR event.authority ? 'tokenId' OR event.actor_user_id::text IS DISTINCT FROM event.authority->>'actorUserId'
   OR event.authority#>>'{tenant,id}' IS DISTINCT FROM job.tenant_id::text OR event.authority#>>'{target,id}' IS DISTINCT FROM job.user_id::text
   OR event.valid_until IS DISTINCT FROM to_timestamp((event.authority->>'validUntil')::double precision)
   OR NOT EXISTS(SELECT 1 FROM company_offboarding_outbox queue WHERE queue.id=event.id AND queue.tenant_id=event.tenant_id AND queue.status='pending' AND queue.created_at=event.created_at)
   THEN RETURN false;END IF;
  snapshot=jsonb_populate_record(NULL::company_offboarding_jobs,event.after_state);
  IF NOT company_offboarding_state_valid(snapshot) OR expected=1 AND (snapshot.created_by<>event.actor_user_id
   OR snapshot.state IS DISTINCT FROM jsonb_build_object('phase','pending','requestedRevision',job.intent->'userRevision','checkpoint',NULL,'items',NULL,'failure',NULL))
   OR snapshot.state->>'phase'='completed_local' AND EXISTS(SELECT 1 FROM jsonb_array_elements(snapshot.state->'items') captured WHERE captured->>'status'='pending')
   THEN RETURN false;END IF;
  IF snapshot.state->'checkpoint'<>'null'::jsonb AND snapshot.state->>'phase'<>'paused'
   AND (event.authority#>'{target,enabled}' IS DISTINCT FROM 'false'::jsonb OR event.authority#>>'{target,eligibilityRevision}' IS DISTINCT FROM snapshot.state#>>'{checkpoint,afterEligibilityRevision}') THEN RETURN false;END IF;
  IF previous IS NOT NULL AND (previous#>>'{state,phase}'='completed_local'
   OR previous#>'{state,checkpoint}'<>'null'::jsonb AND (snapshot.state->'checkpoint' IS DISTINCT FROM previous#>'{state,checkpoint}' OR snapshot.state->'requestedRevision' IS DISTINCT FROM previous#>'{state,requestedRevision}')) THEN RETURN false;END IF;
  IF previous IS NOT NULL AND previous#>'{state,items}'<>'null'::jsonb AND (snapshot.state->'items'='null'::jsonb
   OR jsonb_array_length(snapshot.state->'items')<>jsonb_array_length(previous#>'{state,items}')) THEN RETURN false;END IF;
  IF snapshot.state->'items'<>'null'::jsonb THEN
   FOR item IN SELECT * FROM jsonb_array_elements(snapshot.state->'items') LOOP
    IF previous IS NOT NULL AND previous#>'{state,items}'<>'null'::jsonb THEN
     SELECT element INTO old_item FROM jsonb_array_elements(previous#>'{state,items}') element WHERE element->>'poolId'=item->>'poolId';
     IF old_item IS NULL OR item-ARRAY['poolRevision','status','eventId'] IS DISTINCT FROM old_item-ARRAY['poolRevision','status','eventId']
      OR old_item->>'status'<>'pending' AND item IS DISTINCT FROM old_item
      OR item->>'status'='pending' AND item IS DISTINCT FROM old_item
      OR item->'poolRevision' IS DISTINCT FROM old_item->'poolRevision' AND item->>'status'<>'released' THEN RETURN false;END IF;
    ELSIF item->>'status'<>'pending' THEN RETURN false;
    END IF;
    IF item->>'status'<>'pending' AND NOT COALESCE(company_offboarding_release_valid(snapshot,item),false) THEN RETURN false;END IF;
   END LOOP;
  END IF;
  previous=event.after_state;expected=expected+1;
 END LOOP;
 RETURN expected=job.revision::numeric+1 AND previous=to_jsonb(job);
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_view(job company_offboarding_jobs) RETURNS JSONB LANGUAGE sql STABLE AS $$
 SELECT jsonb_build_object('id',job.id,'tenantId',job.tenant_id,'userId',job.user_id,'createdBy',job.created_by,'revision',job.revision::text,'intent',job.intent,'state',job.state,
  'createdAt',to_char(job.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'updatedAt',to_char(job.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
$$;
CREATE OR REPLACE FUNCTION company_offboarding_read(tenant UUID,workflow UUID) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE job company_offboarding_jobs;
BEGIN
 PERFORM company_offboarding_receiving();SELECT * INTO job FROM company_offboarding_jobs WHERE tenant_id=tenant AND id=workflow;
 IF job.id IS NULL THEN RETURN NULL;END IF;
 IF NOT company_offboarding_job_valid(job) THEN RAISE EXCEPTION 'Complete retained company offboarding history unavailable' USING ERRCODE='55000';END IF;
 RETURN company_offboarding_view(job);
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_history(tenant UUID,workflow UUID,page INTEGER,maximum INTEGER) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE total INTEGER;events JSONB;
BEGIN
 IF page<1 OR page>1000000 OR maximum<1 OR maximum>100 THEN RAISE EXCEPTION 'Invalid company offboarding page' USING ERRCODE='22023';END IF;
 IF company_offboarding_read(tenant,workflow) IS NULL THEN RETURN NULL;END IF;
 SELECT count(*)::integer INTO total FROM company_offboarding_events WHERE tenant_id=tenant AND workflow_id=workflow;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('id',event.id,'revision',event.revision::text,'phase',event.after_state#>>'{state,phase}',
  'actorUserId',event.actor_user_id,'createdAt',to_char(event.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'deliveryStatus','pending',
  'failure',event.after_state#>'{state,failure}','completedLicenses',(SELECT count(*)::integer FROM jsonb_array_elements(CASE WHEN event.after_state#>'{state,items}'='null'::jsonb THEN '[]'::jsonb ELSE event.after_state#>'{state,items}' END) item WHERE item->>'status'<>'pending'),
  'totalLicenses',CASE WHEN event.after_state#>'{state,items}'='null'::jsonb THEN NULL ELSE jsonb_array_length(event.after_state#>'{state,items}') END) ORDER BY event.revision DESC),'[]'::jsonb)
 INTO events FROM(SELECT * FROM company_offboarding_events WHERE tenant_id=tenant AND workflow_id=workflow ORDER BY revision DESC LIMIT maximum OFFSET (page-1)*maximum) event;
 RETURN jsonb_build_object('events',events,'total',total,'page',page,'limit',maximum);
END; $$;

CREATE OR REPLACE FUNCTION company_offboarding_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;event company_offboarding_events;empty_job company_offboarding_jobs;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Company offboarding evidence is retained and append only' USING ERRCODE='42501';END IF;
 PERFORM company_offboarding_receiving();
 source=NULLIF(current_setting('opendirectory.company_offboarding_source',true),'')::jsonb;PERFORM company_offboarding_check_source(source);
 IF TG_TABLE_NAME='company_offboarding_jobs' THEN
  IF TG_OP='UPDATE' AND NOT company_offboarding_job_valid(OLD) THEN RAISE EXCEPTION 'Actual retained offboarding history required' USING ERRCODE='55000';END IF;
  IF EXISTS(SELECT 1 FROM company_offboarding_events WHERE transaction_id=txid_current()) THEN RAISE EXCEPTION 'Independent short journal transaction required' USING ERRCODE='42501';END IF;
  IF TG_OP='INSERT' THEN
   NEW.created_at=clock_timestamp();NEW.updated_at=NEW.created_at;PERFORM company_offboarding_transition(empty_job,NEW,source);
  ELSE
   NEW.updated_at=clock_timestamp();PERFORM company_offboarding_transition(OLD,NEW,source);
  END IF;RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Actual journal observation required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='company_offboarding_events' THEN
  IF NEW.transaction_id<>txid_current() OR NEW.authority IS DISTINCT FROM source-'tokenId' OR NEW.actor_user_id::text IS DISTINCT FROM source->>'actorUserId'
   OR NEW.valid_until IS DISTINCT FROM to_timestamp((source->>'validUntil')::double precision)
   OR NEW.tenant_id::text IS DISTINCT FROM source#>>'{tenant,id}'
   OR NEW.after_state IS DISTINCT FROM (SELECT to_jsonb(job) FROM company_offboarding_jobs job WHERE tenant_id=NEW.tenant_id AND id=NEW.workflow_id)
   OR NEW.before_state IS DISTINCT FROM (SELECT after_state FROM company_offboarding_events WHERE tenant_id=NEW.tenant_id AND workflow_id=NEW.workflow_id ORDER BY revision DESC LIMIT 1)
   OR NEW.after_state->>'revision' IS DISTINCT FROM NEW.revision::text OR NEW.created_at IS DISTINCT FROM (NEW.after_state->>'updated_at')::timestamptz
   THEN RAISE EXCEPTION 'Actual before and after journal effect required' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO event FROM company_offboarding_events WHERE id=NEW.id AND transaction_id=txid_current();
  IF event.id IS NULL OR NEW.tenant_id IS DISTINCT FROM event.tenant_id OR NEW.created_at IS DISTINCT FROM event.created_at OR NEW.status<>'pending'
   THEN RAISE EXCEPTION 'Actual mandatory pending journal outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_observe() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source JSONB;event_id UUID;outbox_id UUID;previous JSONB;
BEGIN
 source=NULLIF(current_setting('opendirectory.company_offboarding_source',true),'')::jsonb;
 IF TG_OP='UPDATE' THEN previous=to_jsonb(OLD);END IF;
 INSERT INTO company_offboarding_events(id,tenant_id,workflow_id,revision,actor_user_id,created_at,valid_until,transaction_id,authority,before_state,after_state)
  VALUES(gen_random_uuid(),NEW.tenant_id,NEW.id,NEW.revision,(source->>'actorUserId')::uuid,NEW.updated_at,to_timestamp((source->>'validUntil')::double precision),txid_current(),source-'tokenId',previous,to_jsonb(NEW)) RETURNING id INTO event_id;
 IF event_id IS NULL THEN RAISE EXCEPTION 'Journal recording was suppressed' USING ERRCODE='55000';END IF;
 INSERT INTO company_offboarding_outbox VALUES(event_id,NEW.tenant_id,'pending',NEW.updated_at) RETURNING id INTO outbox_id;
 IF outbox_id IS DISTINCT FROM event_id OR NOT company_offboarding_job_valid(NEW) THEN RAISE EXCEPTION 'Mandatory actual pending journal recording required' USING ERRCODE='55000';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE job company_offboarding_jobs;source JSONB;previous company_offboarding_jobs;
BEGIN
 PERFORM company_offboarding_receiving();source=NULLIF(current_setting('opendirectory.company_offboarding_source',true),'')::jsonb;
 PERFORM company_offboarding_check_source(source);
 SELECT * INTO job FROM company_offboarding_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.workflow_id;
 IF NEW.valid_until<=clock_timestamp() OR NEW.authority IS DISTINCT FROM source-'tokenId' OR NOT company_offboarding_job_valid(job)
  OR NEW.after_state IS DISTINCT FROM to_jsonb(job) THEN RAISE EXCEPTION 'Original physical journal commit checkpoint required' USING ERRCODE='42501';END IF;
 IF NEW.before_state IS NOT NULL THEN previous=jsonb_populate_record(NULL::company_offboarding_jobs,NEW.before_state);END IF;
 PERFORM company_offboarding_transition(previous,job,source);RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;specification RECORD;
BEGIN
 PERFORM license_company_receiving();
 IF current_setting('session_replication_role')<>'origin' THEN RAISE EXCEPTION 'Journal receivers require origin execution' USING ERRCODE='55000';END IF;
 FOREACH relation IN ARRAY ARRAY['company_offboarding_jobs','company_offboarding_events','company_offboarding_outbox'] LOOP
  IF to_regclass(relation) IS NULL OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='company_offboarding_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='company_offboarding_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='company_offboarding_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='company_offboarding_guard()'::regprocedure)
   OR EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass(relation) AND NOT convalidated)
   THEN RAISE EXCEPTION 'Mandatory company offboarding receiver unavailable' USING ERRCODE='55000';END IF;
 END LOOP;
 FOR specification IN SELECT * FROM(VALUES
  ('company_offboarding_jobs','tenant_id','uuid',true),('company_offboarding_jobs','id','uuid',true),('company_offboarding_jobs','user_id','uuid',true),('company_offboarding_jobs','created_by','uuid',true),
  ('company_offboarding_jobs','revision','bigint',true),('company_offboarding_jobs','intent','jsonb',true),('company_offboarding_jobs','state','jsonb',true),('company_offboarding_jobs','created_at','timestamp with time zone',true),('company_offboarding_jobs','updated_at','timestamp with time zone',true),
  ('company_offboarding_events','id','uuid',true),('company_offboarding_events','tenant_id','uuid',true),('company_offboarding_events','workflow_id','uuid',true),('company_offboarding_events','revision','bigint',true),
  ('company_offboarding_events','actor_user_id','uuid',true),('company_offboarding_events','created_at','timestamp with time zone',true),('company_offboarding_events','valid_until','timestamp with time zone',true),('company_offboarding_events','transaction_id','bigint',true),
  ('company_offboarding_events','authority','jsonb',true),('company_offboarding_events','before_state','jsonb',false),('company_offboarding_events','after_state','jsonb',true),
  ('company_offboarding_outbox','id','uuid',true),('company_offboarding_outbox','tenant_id','uuid',true),('company_offboarding_outbox','status','text',true),('company_offboarding_outbox','created_at','timestamp with time zone',true)
 ) columns(relation,name,kind,required) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass(specification.relation) AND attname=specification.name AND NOT attisdropped
   AND format_type(atttypid,atttypmod)=specification.kind AND attnotnull=specification.required)
   THEN RAISE EXCEPTION 'Mandatory journal column unavailable' USING ERRCODE='55000';END IF;
 END LOOP;
 FOR specification IN SELECT * FROM(VALUES
  ('company_offboarding_jobs','company_offboarding_observe','company_offboarding_observe()',21,false),
  ('company_offboarding_events','company_offboarding_commit','company_offboarding_commit()',5,true)
 ) receivers(relation,name,routine,kind,deferred) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(specification.relation) AND tgname=specification.name AND tgfoid=to_regprocedure(specification.routine)
   AND tgtype=specification.kind AND tgenabled='O' AND tgdeferrable=specification.deferred AND tginitdeferred=specification.deferred)
   THEN RAISE EXCEPTION 'Mandatory actual journal recording unavailable' USING ERRCODE='55000';END IF;
 END LOOP;
 FOR specification IN SELECT * FROM(VALUES
  ('company_offboarding_jobs','PRIMARY KEY (tenant_id, id)'),('company_offboarding_jobs','CHECK ((revision > 0))'),
  ('company_offboarding_events','PRIMARY KEY (id)'),('company_offboarding_events','UNIQUE (tenant_id, workflow_id, revision)'),('company_offboarding_events','UNIQUE (transaction_id)'),
  ('company_offboarding_events','CHECK ((revision > 0))'),('company_offboarding_events','FOREIGN KEY (tenant_id, workflow_id) REFERENCES company_offboarding_jobs(tenant_id, id)'),
  ('company_offboarding_outbox','PRIMARY KEY (id)'),('company_offboarding_outbox','CHECK ((status = ''pending''::text))'),('company_offboarding_outbox','FOREIGN KEY (id) REFERENCES company_offboarding_events(id)')
 ) constraints(relation,definition) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_constraint constraint_row WHERE constraint_row.conrelid=to_regclass(specification.relation) AND constraint_row.convalidated
   AND pg_get_constraintdef(constraint_row.oid)=specification.definition
   AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgconstraint=constraint_row.oid AND tgenabled<>'O'))
   THEN RAISE EXCEPTION 'Mandatory journal schema constraint unavailable' USING ERRCODE='55000';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_create(source JSONB,request JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE job company_offboarding_jobs;inserted BOOLEAN;
BEGIN
 PERFORM company_offboarding_receiving();PERFORM company_offboarding_check_source(source);
 IF NOT company_offboarding_intent_valid(request) OR source#>>'{target,id}' IS DISTINCT FROM request->>'userId' THEN RAISE EXCEPTION 'Exact own company offboarding intent required' USING ERRCODE='22023';END IF;
 SELECT * INTO job FROM company_offboarding_jobs WHERE tenant_id=(source#>>'{tenant,id}')::uuid AND id=(request->>'workflowId')::uuid;
 IF job.id IS NOT NULL THEN
  IF job.intent IS DISTINCT FROM request THEN RAISE EXCEPTION 'Workflow intent conflict' USING ERRCODE='23514';END IF;
  RETURN jsonb_build_object('job',company_offboarding_read(job.tenant_id,job.id),'created',false);
 END IF;
 PERFORM set_config('opendirectory.company_offboarding_source',source::text,true);
 INSERT INTO company_offboarding_jobs VALUES((source#>>'{tenant,id}')::uuid,(request->>'workflowId')::uuid,(request->>'userId')::uuid,(source->>'actorUserId')::uuid,1,request,
  jsonb_build_object('phase','pending','requestedRevision',request->'userRevision','checkpoint',NULL,'items',NULL,'failure',NULL),clock_timestamp(),clock_timestamp())
  ON CONFLICT(tenant_id,id) DO NOTHING RETURNING * INTO job;
 inserted=FOUND;
 IF NOT inserted THEN
  SELECT * INTO job FROM company_offboarding_jobs WHERE tenant_id=(source#>>'{tenant,id}')::uuid AND id=(request->>'workflowId')::uuid;
  IF job.id IS NULL THEN RAISE EXCEPTION 'Actual company offboarding write unavailable' USING ERRCODE='55000';END IF;
  IF job.intent IS DISTINCT FROM request THEN RAISE EXCEPTION 'Workflow intent conflict' USING ERRCODE='23514';END IF;
 END IF;
 IF job.id IS NULL THEN RAISE EXCEPTION 'Actual company offboarding write unavailable' USING ERRCODE='55000';END IF;
 RETURN jsonb_build_object('job',company_offboarding_read(job.tenant_id,job.id),'created',inserted);
END; $$;
CREATE OR REPLACE FUNCTION company_offboarding_save(source JSONB,workflow UUID,expected BIGINT,state JSONB) RETURNS JSONB LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE job company_offboarding_jobs;
BEGIN
 PERFORM company_offboarding_receiving();PERFORM company_offboarding_check_source(source);
 SELECT * INTO job FROM company_offboarding_jobs WHERE tenant_id=(source#>>'{tenant,id}')::uuid AND id=workflow FOR UPDATE;
 IF job.id IS NULL THEN RAISE EXCEPTION 'Own company offboarding workflow not found' USING ERRCODE='P0002';END IF;
 IF job.revision IS DISTINCT FROM expected OR expected=9223372036854775807 THEN RAISE EXCEPTION 'Company offboarding version conflict' USING ERRCODE='40001';END IF;
 PERFORM set_config('opendirectory.company_offboarding_source',source::text,true);
 UPDATE company_offboarding_jobs SET state=company_offboarding_save.state,revision=revision+1 WHERE tenant_id=job.tenant_id AND id=job.id RETURNING * INTO job;
 IF NOT FOUND THEN RAISE EXCEPTION 'Actual company offboarding save was suppressed' USING ERRCODE='55000';END IF;
 RETURN company_offboarding_read(job.tenant_id,job.id);
END; $$;
DO $$ DECLARE relation TEXT;routine RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['company_offboarding_jobs','company_offboarding_events','company_offboarding_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS company_offboarding_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER company_offboarding_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION company_offboarding_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS company_offboarding_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER company_offboarding_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION company_offboarding_guard()',relation);
 END LOOP;
 DROP TRIGGER IF EXISTS company_offboarding_observe ON company_offboarding_jobs;
 CREATE TRIGGER company_offboarding_observe AFTER INSERT OR UPDATE ON company_offboarding_jobs FOR EACH ROW EXECUTE FUNCTION company_offboarding_observe();
 DROP TRIGGER IF EXISTS company_offboarding_commit ON company_offboarding_events;
 CREATE CONSTRAINT TRIGGER company_offboarding_commit AFTER INSERT ON company_offboarding_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION company_offboarding_commit();
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'company_offboarding_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
 REVOKE ALL ON company_offboarding_jobs,company_offboarding_events,company_offboarding_outbox FROM PUBLIC;
END; $$;
COMMENT ON TABLE company_offboarding_jobs IS 'Durable execution checkpoints only. Actual license allocations and immutable release receipts remain owned by the existing license allocator. Retain jobs, history and pending outbox together.';
