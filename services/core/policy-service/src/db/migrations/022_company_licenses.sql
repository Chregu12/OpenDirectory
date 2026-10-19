ALTER TABLE license_catalog ADD COLUMN IF NOT EXISTS business_tenant_id UUID;
ALTER TABLE license_catalog ADD COLUMN IF NOT EXISTS business_revision BIGINT;
ALTER TABLE license_subjects ADD COLUMN IF NOT EXISTS business_tenant_id UUID;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='license_catalog'::regclass AND conname='license_company_revision') THEN
  ALTER TABLE license_catalog ADD CONSTRAINT license_company_revision CHECK((business_tenant_id IS NULL AND business_revision IS NULL) OR (business_tenant_id IS NOT NULL AND business_revision IS NOT NULL AND business_revision>0));
 END IF;
END; $$;
CREATE INDEX IF NOT EXISTS license_company_catalog_page ON license_catalog(business_tenant_id,name,id) WHERE business_tenant_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS license_company_commands (
 id UUID PRIMARY KEY,correlation_id UUID NOT NULL,license_id UUID NOT NULL REFERENCES license_catalog(id) DEFERRABLE INITIALLY DEFERRED,
 tenant_id UUID NOT NULL,actor_user_id UUID NOT NULL,target_user_id UUID,action TEXT NOT NULL CHECK(action IN('create','assign','revoke')),
 source JSONB NOT NULL,command JSONB NOT NULL,before_state JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 transaction_id BIGINT NOT NULL UNIQUE,new_subject_ids TEXT[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS license_company_origins (
 id UUID NOT NULL,ordinal BIGINT GENERATED ALWAYS AS IDENTITY,command_id UUID NOT NULL REFERENCES license_company_commands(id),
 relation TEXT NOT NULL,operation TEXT NOT NULL CHECK(operation IN('INSERT','UPDATE','DELETE')),before_state JSONB,after_state JSONB,PRIMARY KEY(id,ordinal),CHECK(id=command_id)
);
CREATE INDEX IF NOT EXISTS license_company_origin_command ON license_company_origins(command_id,relation,operation);
CREATE TABLE IF NOT EXISTS license_company_events (
 id UUID PRIMARY KEY REFERENCES license_company_commands(id),tenant_id UUID NOT NULL,license_id UUID NOT NULL REFERENCES license_catalog(id),
 type TEXT NOT NULL CHECK(type IN('app.license.pool.created','app.license.assigned','app.license.released')),version INTEGER NOT NULL CHECK(version=1),
 actor_user_id UUID NOT NULL,target_user_id UUID,correlation_id UUID NOT NULL,created_at TIMESTAMPTZ NOT NULL,
 before_revision BIGINT,after_revision BIGINT NOT NULL CHECK(after_revision>0),proof JSONB NOT NULL,before_state JSONB NOT NULL,after_state JSONB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS license_company_event_revision ON license_company_events(license_id,after_revision);
CREATE INDEX IF NOT EXISTS license_company_event_history ON license_company_events(tenant_id,license_id,created_at,id);
CREATE TABLE IF NOT EXISTS license_company_outbox (
 id UUID PRIMARY KEY REFERENCES license_company_events(id),tenant_id UUID NOT NULL,status TEXT NOT NULL CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL
);
CREATE OR REPLACE FUNCTION license_company_exact(data JSONB,fields TEXT[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(jsonb_typeof(data)='object' AND CASE WHEN jsonb_typeof(data)='object' THEN (SELECT count(*) FROM jsonb_object_keys(data))=cardinality(fields) ELSE false END AND data ?& fields,false);
$$;
CREATE OR REPLACE FUNCTION license_company_uuid(data TEXT) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(data ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false);
$$;
CREATE OR REPLACE FUNCTION license_company_revision_valid(data JSONB,zero_allowed BOOLEAN DEFAULT false) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(jsonb_typeof(data)='string' AND data#>>'{}' ~ '^(0|[1-9][0-9]{0,18})$' AND CASE WHEN data#>>'{}' ~ '^(0|[1-9][0-9]{0,18})$' THEN (data#>>'{}')::numeric BETWEEN CASE WHEN zero_allowed THEN 0 ELSE 1 END AND 9223372036854775807 ELSE false END,false);
$$;
CREATE OR REPLACE FUNCTION license_company_proof_valid(source JSONB,command JSONB) RETURNS boolean LANGUAGE plpgsql VOLATILE AS $$
DECLARE target JSONB;values JSONB;field TEXT;
BEGIN
 IF NOT license_company_exact(source,ARRAY['schemaVersion','issuer','subject','tokenId','expiresAt','context','tenant','actorUserId','permissions','validUntil','target'])
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR source->'permissions' IS DISTINCT FROM '["company.apps.read","company.apps.create","company.apps.assign"]'::jsonb
  OR NOT license_company_exact(source->'context',ARRAY['userId','revision','linkRevision','rolesRevision'])
  OR NOT license_company_exact(source->'tenant',ARRAY['id','version','generation'])
  OR NOT license_company_uuid(source->>'actorUserId') OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
  OR NOT license_company_uuid(source#>>'{tenant,id}') OR NOT license_company_revision_valid(source#>'{context,revision}')
  OR NOT license_company_revision_valid(source#>'{context,linkRevision}') OR NOT license_company_revision_valid(source#>'{tenant,version}')
  OR NOT license_company_revision_valid(source#>'{tenant,generation}') OR NOT COALESCE(source#>>'{context,rolesRevision}' ~ '^[a-f0-9]{64}$',false)
  OR NOT license_company_exact(command,ARRAY['id','correlationId','licenseId','action','expectedVersion','reason','values','assignmentId'])
  OR NOT license_company_uuid(command->>'id') OR NOT license_company_uuid(command->>'correlationId') OR NOT license_company_uuid(command->>'licenseId')
  OR NOT COALESCE(command->>'action' IN('create','assign','revoke'),false) OR NOT license_company_revision_valid(command->'expectedVersion',true)
  OR jsonb_typeof(command->'reason') IS DISTINCT FROM 'string' OR length(btrim(command->>'reason')) NOT BETWEEN 10 AND 500 OR command->>'reason' ~ '[[:cntrl:]]'
  THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['issuer','subject','tokenId'] LOOP
  IF jsonb_typeof(source->field) IS DISTINCT FROM 'string' OR length(btrim(source->>field)) NOT BETWEEN 1 AND (CASE WHEN field='issuer' THEN 2048 ELSE 255 END) OR source->>field ~ '[[:cntrl:]]' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['expiresAt','validUntil'] LOOP
  IF jsonb_typeof(source->field) IS DISTINCT FROM 'number' OR NOT COALESCE(source->>field ~ '^[0-9]{1,12}$',false) THEN RETURN false;END IF;
 END LOOP;
 IF (source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR (source->>'validUntil')::numeric>(source->>'expiresAt')::numeric
  OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300 THEN RETURN false;END IF;
 target=source->'target';values=command->'values';
 IF command->>'action'='create' THEN
  IF target IS DISTINCT FROM 'null'::jsonb OR command->>'expectedVersion'<>'0' OR command->'assignmentId' IS DISTINCT FROM 'null'::jsonb
   OR NOT license_company_exact(values,ARRAY['name','vendor','description','totalSeats']) THEN RETURN false;END IF;
  FOREACH field IN ARRAY ARRAY['name','vendor','description'] LOOP
   IF jsonb_typeof(values->field) IS DISTINCT FROM 'string' OR values->>field IS DISTINCT FROM btrim(values->>field)
    OR length(values->>field) NOT BETWEEN (CASE WHEN field='description' THEN 0 ELSE 1 END) AND (CASE WHEN field='description' THEN 2000 ELSE 160 END)
    OR values->>field ~ '[[:cntrl:]]' THEN RETURN false;END IF;
  END LOOP;
  RETURN COALESCE(jsonb_typeof(values->'totalSeats')='number' AND values->>'totalSeats' ~ '^[1-9][0-9]{0,4}$' AND (values->>'totalSeats')::integer BETWEEN 1 AND 10000,false);
 END IF;
 IF values IS DISTINCT FROM 'null'::jsonb OR NOT license_company_revision_valid(command->'expectedVersion')
  OR NOT license_company_exact(target,ARRAY['id','revision','eligibilityRevision','enabled','deleted']) OR NOT license_company_uuid(target->>'id')
  OR NOT license_company_revision_valid(target->'eligibilityRevision') OR jsonb_typeof(target->'enabled') IS DISTINCT FROM 'boolean'
  OR jsonb_typeof(target->'deleted') IS DISTINCT FROM 'boolean' OR target->'deleted'='true'::jsonb AND target->'enabled'='true'::jsonb
  OR NOT(CASE WHEN target->'deleted'='true'::jsonb THEN target->'revision'='null'::jsonb ELSE license_company_revision_valid(target->'revision') END)
  THEN RETURN false;END IF;
 IF command->>'action'='assign' THEN RETURN command->'assignmentId'='null'::jsonb AND target->'enabled'='true'::jsonb AND target->'deleted'='false'::jsonb;END IF;
 RETURN license_company_uuid(command->>'assignmentId');
END; $$;
CREATE OR REPLACE FUNCTION license_company_row(relation TEXT,data JSONB) RETURNS JSONB LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE field TEXT;
BEGIN
 IF data IS NULL THEN RETURN NULL;END IF;
 FOREACH field IN ARRAY CASE relation WHEN 'license_catalog' THEN ARRAY['business_revision'] WHEN 'license_subjects' THEN ARRAY['directory_revision']
  WHEN 'license_assignments' THEN ARRAY['eligibility_revision'] WHEN 'license_grants' THEN ARRAY['eligibility_revision'] WHEN 'license_grant_events' THEN ARRAY['version'] ELSE ARRAY[]::text[] END LOOP
  IF data->>field IS NOT NULL THEN data=jsonb_set(data,ARRAY[field],to_jsonb(data->>field));END IF;
 END LOOP;
 IF relation='license_assignments' AND data->>'assigned_at' IS NOT NULL THEN
  data=jsonb_set(data,'{assigned_at}',to_jsonb(to_char((data->>'assigned_at')::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
 END IF;RETURN data;
END; $$;
CREATE OR REPLACE FUNCTION license_company_relations() RETURNS TEXT[] LANGUAGE sql IMMUTABLE AS $$
 SELECT ARRAY['license_catalog','license_subjects','license_assignments','license_assignment_sources','license_grants','license_grant_events','license_audit_events',
 'license_requests','license_group_rules','license_review_policies','license_review_leases','license_review_audit','license_scope_grants','license_scope_audit',
 'license_scope_eligibilities','license_scope_activation_requests','license_scope_pim_audit','license_scope_activation_policies','license_scope_policy_audit',
 'license_scope_review_policies','license_scope_review_leases','license_scope_review_fences','license_scope_review_audit',
 'license_group_observations','license_group_member_leases','license_group_lease_audit','license_provider_connectors','license_provider_products','license_provider_subjects',
 'license_fulfillment_targets','license_fulfillment_changes','license_fulfillment_events','license_provider_limits','license_capacity_sources','license_capacity_runs',
 'license_capacity_events','license_capacity_outbox','license_capacity_budgets','license_capacity_reservations','license_capacity_admission_events','license_capacity_admission_outbox',
 'license_schema_versions','license_company_commands','license_company_origins','license_company_events','license_company_outbox'];
$$;
CREATE OR REPLACE FUNCTION license_company_parent(relation TEXT,data JSONB) RETURNS UUID LANGUAGE plpgsql STABLE AS $$
DECLARE result UUID;
BEGIN
 IF relation='license_catalog' THEN RETURN (data->>'id')::uuid;END IF;
 IF data->>'license_id' IS NOT NULL THEN RETURN (data->>'license_id')::uuid;END IF;
 IF relation IN('license_grant_events','license_group_member_leases','license_group_lease_audit') THEN
  SELECT license_id INTO result FROM license_grants WHERE id=(data->>'grant_id')::uuid;
 ELSIF relation IN('license_review_leases','license_review_audit') THEN SELECT license_id INTO result FROM license_review_policies WHERE id=(data->>'policy_id')::uuid;
 ELSIF relation IN('license_scope_audit','license_scope_review_fences') THEN SELECT license_id INTO result FROM license_scope_grants WHERE id=(data->>'grant_id')::uuid;
 ELSIF relation IN('license_scope_activation_requests','license_scope_pim_audit') THEN SELECT license_id INTO result FROM license_scope_eligibilities WHERE id=(data->>'eligibility_id')::uuid;
 ELSIF relation IN('license_scope_review_leases','license_scope_review_audit') THEN SELECT license_id INTO result FROM license_scope_review_policies WHERE id=(data->>'policy_id')::uuid;
 ELSIF relation IN('license_fulfillment_targets','license_capacity_budgets') THEN SELECT license_id INTO result FROM license_provider_products WHERE id=(data->>'product_id')::uuid;
 ELSIF relation IN('license_fulfillment_changes','license_fulfillment_events','license_capacity_reservations') THEN
  SELECT product.license_id INTO result FROM license_fulfillment_targets target JOIN license_provider_products product ON product.id=target.product_id WHERE target.id=(data->>'target_id')::uuid;
 ELSIF relation IN('license_capacity_admission_events','license_capacity_admission_outbox') THEN
  SELECT product.license_id INTO result FROM license_capacity_budgets budget JOIN license_provider_products product ON product.id=budget.product_id WHERE budget.id=(data->>'budget_id')::uuid;
 END IF;RETURN result;
END; $$;
CREATE OR REPLACE FUNCTION license_company_supported(pool_id UUID) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT 1 FROM license_review_policies WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_scope_activation_policies WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_scope_review_policies WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_scope_grants WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_scope_eligibilities WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_provider_products WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_group_rules WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_requests WHERE license_id=pool_id)
 AND NOT EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=pool_id AND (source_type<>'direct' OR source_id<>'direct' OR expires_at IS NOT NULL))
 AND NOT EXISTS(SELECT 1 FROM license_assignments WHERE license_id=pool_id AND (assignee_type<>'user' OR expires_at IS NOT NULL))
 AND NOT EXISTS(SELECT 1 FROM license_grants WHERE license_id=pool_id AND kind<>'direct');
$$;
CREATE OR REPLACE FUNCTION license_company_subject_unused(identifier TEXT,fresh BOOLEAN DEFAULT false,tenant UUID DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE relation TEXT;participates BOOLEAN;
BEGIN
 FOREACH relation IN ARRAY license_company_relations() LOOP
  IF relation IN('license_subjects','license_catalog','license_schema_versions','license_company_origins') THEN CONTINUE;END IF;
  IF fresh AND relation LIKE 'license_company_%' THEN
   IF EXISTS(SELECT 1 FROM license_company_commands WHERE tenant_id IS DISTINCT FROM tenant AND (actor_user_id::text=identifier OR target_user_id::text=identifier)) THEN RETURN false;END IF;
   CONTINUE;
  END IF;
  EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I actual WHERE %s strpos(to_jsonb(actual)::text,$1)>0)',relation,CASE WHEN relation='license_company_commands' THEN 'transaction_id<>txid_current() AND' ELSE '' END) INTO participates USING identifier;
  IF participates THEN RETURN false;END IF;
 END LOOP;RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION license_company_state(pool_id UUID,actor_id UUID,target_id UUID,previous_grant UUID DEFAULT NULL) RETURNS JSONB LANGUAGE sql VOLATILE AS $$
 SELECT jsonb_build_object(
 'catalog',(SELECT license_company_row('license_catalog',to_jsonb(catalog)) FROM license_catalog catalog WHERE id=pool_id),
 'subjects',COALESCE((SELECT jsonb_agg(license_company_row('license_subjects',to_jsonb(subject)) ORDER BY user_id) FROM license_subjects subject WHERE user_id=actor_id::text OR user_id=target_id::text),'[]'::jsonb),
 'assignment',(SELECT license_company_row('license_assignments',to_jsonb(assignment)) FROM license_assignments assignment WHERE license_id=pool_id AND assignee_type='user' AND assignee_id=target_id::text),
 'source',(SELECT to_jsonb(source) FROM license_assignment_sources source WHERE license_id=pool_id AND user_id=target_id::text AND source_type='direct'),
 'grant',(SELECT license_company_row('license_grants',to_jsonb(grants)) FROM license_grants grants WHERE id=COALESCE((SELECT grant_id FROM license_assignment_sources WHERE license_id=pool_id AND user_id=target_id::text AND source_type='direct'),previous_grant)),
 'grantEvent',(SELECT license_company_row('license_grant_events',to_jsonb(history)) FROM license_grant_events history WHERE grant_id=COALESCE((SELECT grant_id FROM license_assignment_sources WHERE license_id=pool_id AND user_id=target_id::text AND source_type='direct'),previous_grant) ORDER BY version DESC LIMIT 1));
$$;
CREATE OR REPLACE FUNCTION license_company_control_clean() RETURNS boolean LANGUAGE plpgsql STABLE AS $$
DECLARE setting TEXT;
BEGIN
 FOREACH setting IN ARRAY ARRAY['scope_pool','scope_proof','policy_configuration','policy_publication','group_snapshot','group_derivation','license_review_proof','provider_actor','capacity_protocol','capacity_budget_review'] LOOP
  IF NULLIF(current_setting('opendirectory.'||setting,true),'') IS NOT NULL THEN RETURN false;END IF;
 END LOOP;RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION license_company_scope() RETURNS license_company_commands LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;
BEGIN
 SELECT * INTO receipt FROM license_company_commands WHERE transaction_id=txid_current();
 IF receipt.id IS NULL OR receipt.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.license_company',true),'')
  OR receipt.valid_until<=clock_timestamp() OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass)
  OR current_setting('role',true) NOT IN('none','') OR NOT license_company_control_clean() THEN RAISE EXCEPTION 'Original company license admission required' USING ERRCODE='42501';END IF;
 RETURN receipt;
END; $$;
CREATE OR REPLACE FUNCTION license_company_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;before_data JSONB;after_data JSONB;payload JSONB;pool_id UUID;owned BOOLEAN;active BOOLEAN;target TEXT;expected JSONB;
BEGIN
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM license_company_commands) OR EXISTS(SELECT 1 FROM license_catalog WHERE business_tenant_id IS NOT NULL)
   OR EXISTS(SELECT 1 FROM license_subjects WHERE business_tenant_id IS NOT NULL) OR NULLIF(current_setting('opendirectory.license_company',true),'') IS NOT NULL
   THEN RAISE EXCEPTION 'Company license evidence cannot be truncated' USING ERRCODE='42501';END IF;
  PERFORM pg_advisory_xact_lock_shared(19770022,1);RETURN NULL;
 END IF;
 IF TG_OP<>'INSERT' THEN before_data=license_company_row(TG_TABLE_NAME,to_jsonb(OLD));END IF;
 IF TG_OP<>'DELETE' THEN after_data=license_company_row(TG_TABLE_NAME,to_jsonb(NEW));END IF;
 payload=COALESCE(after_data,before_data);active=EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current());
 IF TG_TABLE_NAME='license_company_commands' THEN
  IF TG_OP<>'INSERT' OR active OR session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass)
   OR current_setting('role',true) NOT IN('none','') OR NEW.id::text IS DISTINCT FROM NULLIF(current_setting('opendirectory.license_company',true),'')
   OR NEW.transaction_id<>txid_current() OR NOT license_company_proof_valid(NEW.source,NEW.command) OR NOT license_company_control_clean()
   OR EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=19770022::oid AND objid=1::oid AND objsubid=2 AND mode='ShareLock' AND granted)
   OR NEW.new_subject_ids IS DISTINCT FROM (CASE WHEN NEW.action='create' THEN ARRAY[]::text[] ELSE ARRAY(SELECT DISTINCT identifier FROM unnest(ARRAY[NEW.actor_user_id::text,NEW.target_user_id::text]) identifier WHERE NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=identifier) ORDER BY identifier) END)
   OR ROW(NEW.id::text,NEW.correlation_id::text,NEW.license_id::text,NEW.tenant_id::text,NEW.actor_user_id::text,NEW.action)
    IS DISTINCT FROM ROW(NEW.command->>'id',NEW.command->>'correlationId',NEW.command->>'licenseId',NEW.source#>>'{tenant,id}',NEW.source->>'actorUserId',NEW.command->>'action')
   OR NEW.target_user_id::text IS DISTINCT FROM NEW.source#>>'{target,id}'
   OR NEW.before_state IS DISTINCT FROM license_company_state(NEW.license_id,NEW.actor_user_id,NEW.target_user_id)
   OR NEW.valid_until IS DISTINCT FROM to_timestamp((NEW.source->>'validUntil')::double precision)
   THEN RAISE EXCEPTION 'Immutable original company command required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF TG_TABLE_NAME IN('license_company_origins','license_company_events','license_company_outbox') THEN
  receipt=license_company_scope();
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Company license evidence is append only' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='license_company_origins' THEN
   IF pg_trigger_depth()<2 OR NEW.command_id<>receipt.id OR NOT NEW.relation=ANY(ARRAY['license_catalog','license_subjects','license_assignments','license_assignment_sources','license_grants','license_grant_events','license_audit_events'])
    OR EXISTS(SELECT 1 FROM license_company_events WHERE id=receipt.id) THEN RAISE EXCEPTION 'Actual company license effect required' USING ERRCODE='42501';END IF;
  ELSIF TG_TABLE_NAME='license_company_events' THEN
   IF NEW.id<>receipt.id OR NEW.tenant_id<>receipt.tenant_id OR NEW.license_id<>receipt.license_id OR NEW.actor_user_id<>receipt.actor_user_id
    OR NEW.target_user_id IS DISTINCT FROM receipt.target_user_id OR NEW.correlation_id<>receipt.correlation_id OR NEW.version<>1
    OR NEW.type IS DISTINCT FROM (CASE receipt.action WHEN 'create' THEN 'app.license.pool.created' WHEN 'assign' THEN 'app.license.assigned' ELSE 'app.license.released' END)
    OR NEW.proof IS DISTINCT FROM jsonb_build_object('source',receipt.source,'command',receipt.command,'checkpoint',receipt.source)
    OR NEW.before_state IS DISTINCT FROM receipt.before_state OR NEW.after_state IS DISTINCT FROM license_company_state(receipt.license_id,receipt.actor_user_id,receipt.target_user_id,(receipt.before_state#>>'{source,grant_id}')::uuid)
    OR NEW.before_revision IS DISTINCT FROM (receipt.before_state#>>'{catalog,business_revision}')::bigint
    OR NEW.after_revision IS DISTINCT FROM COALESCE(NEW.before_revision+1,1)
    THEN RAISE EXCEPTION 'Exact company license final event required' USING ERRCODE='23514';END IF;
  ELSE
   IF after_data IS DISTINCT FROM (SELECT jsonb_build_object('id',event.id,'tenant_id',event.tenant_id,'status','pending','created_at',event.created_at) FROM license_company_events event WHERE id=receipt.id)
    THEN RAISE EXCEPTION 'Exact pending company license receipt required' USING ERRCODE='23514';END IF;
  END IF;RETURN NEW;
 END IF;
 pool_id=license_company_parent(TG_TABLE_NAME,payload);
 owned=EXISTS(SELECT 1 FROM license_catalog WHERE id IN(pool_id,license_company_parent(TG_TABLE_NAME,before_data)) AND business_tenant_id IS NOT NULL);
 IF TG_TABLE_NAME='license_catalog' THEN owned=owned OR before_data->>'business_tenant_id' IS NOT NULL OR after_data->>'business_tenant_id' IS NOT NULL;END IF;
 IF TG_TABLE_NAME='license_subjects' THEN owned=payload->>'business_tenant_id' IS NOT NULL OR EXISTS(SELECT 1 FROM license_subjects WHERE user_id=payload->>'user_id' AND business_tenant_id IS NOT NULL);END IF;
 IF NOT owned AND TG_TABLE_NAME<>'license_catalog' THEN
  owned=EXISTS(SELECT 1 FROM license_subjects WHERE business_tenant_id IS NOT NULL AND (strpos(payload::text,user_id)>0 OR strpos(before_data::text,user_id)>0));
 END IF;
 IF NOT active AND TG_TABLE_NAME='license_catalog' AND TG_OP='UPDATE' THEN
  IF before_data=after_data AND NEW.used_seats=(SELECT count(*) FROM license_assignments WHERE license_id=NEW.id AND (expires_at IS NULL OR expires_at>clock_timestamp())) THEN RETURN NEW;END IF;
 END IF;
 IF NOT owned AND NOT active AND NULLIF(current_setting('opendirectory.license_company',true),'') IS NULL THEN
  PERFORM pg_advisory_xact_lock_shared(19770022,1);IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
 END IF;
 receipt=license_company_scope();target=receipt.target_user_id::text;
 IF EXISTS(SELECT 1 FROM license_company_events WHERE id=receipt.id) THEN RAISE EXCEPTION 'Completed company command cannot write' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='license_subjects' THEN
  IF TG_OP='DELETE' OR payload->>'user_id' NOT IN(receipt.actor_user_id::text,COALESCE(target,receipt.actor_user_id::text))
   OR after_data->>'business_tenant_id' IS DISTINCT FROM receipt.tenant_id::text
   OR TG_OP='UPDATE' AND before_data->>'business_tenant_id' IS NOT NULL AND before_data->>'business_tenant_id' IS DISTINCT FROM receipt.tenant_id::text
   THEN RAISE EXCEPTION 'Original own company subject required' USING ERRCODE='42501';END IF;
  IF TG_OP='UPDATE' AND before_data->>'business_tenant_id' IS NULL THEN
   IF (before_data-'business_tenant_id') IS DISTINCT FROM (after_data-'business_tenant_id') OR before_data->'disabled' IS DISTINCT FROM 'false'::jsonb
    OR before_data->>'directory_revision' IS NOT NULL OR NOT license_company_subject_unused(payload->>'user_id',payload->>'user_id'=ANY(receipt.new_subject_ids),receipt.tenant_id) THEN RAISE EXCEPTION 'Unused empty subject requires controlled migration' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='INSERT' THEN
   IF EXISTS(SELECT 1 FROM license_subjects WHERE user_id=payload->>'user_id') THEN RETURN NEW;END IF;
   IF NOT payload->>'user_id'=ANY(receipt.new_subject_ids) OR after_data->'disabled' IS DISTINCT FROM 'false'::jsonb OR after_data->>'directory_revision' IS NOT NULL
    OR after_data->>'directory_enabled' IS NOT NULL OR after_data->>'directory_deleted' IS NOT NULL OR after_data->>'directory_checked_at' IS NOT NULL
    OR after_data->>'directory_attempted_at' IS NOT NULL OR after_data->>'directory_error' IS NOT NULL OR NOT license_company_subject_unused(payload->>'user_id',true,receipt.tenant_id)
    THEN RAISE EXCEPTION 'Exact empty original company subject required' USING ERRCODE='23514';END IF;
  ELSIF before_data IS DISTINCT FROM after_data THEN
   IF payload->>'user_id' IS DISTINCT FROM target
    OR (before_data-ARRAY['directory_revision','directory_enabled','directory_deleted','directory_checked_at','directory_attempted_at','directory_error']) IS DISTINCT FROM (after_data-ARRAY['directory_revision','directory_enabled','directory_deleted','directory_checked_at','directory_attempted_at','directory_error'])
    OR after_data->>'directory_revision' IS DISTINCT FROM receipt.source#>>'{target,eligibilityRevision}'
    OR after_data->'directory_enabled' IS DISTINCT FROM receipt.source#>'{target,enabled}' OR after_data->'directory_deleted' IS DISTINCT FROM receipt.source#>'{target,deleted}'
    OR after_data->>'directory_error' IS NOT NULL THEN RAISE EXCEPTION 'Exact captured company eligibility required' USING ERRCODE='23514';END IF;
  END IF;RETURN NEW;
 END IF;
 IF pool_id IS DISTINCT FROM receipt.license_id AND NOT(TG_TABLE_NAME='license_audit_events' AND pool_id IS NULL AND receipt.action='assign') THEN RAISE EXCEPTION 'Company write exceeds original pool' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='license_catalog' THEN
  IF TG_OP='INSERT' THEN
   expected=receipt.command->'values';
   IF receipt.action<>'create' OR NEW.business_tenant_id<>receipt.tenant_id OR NEW.business_revision<>1 OR NEW.name IS DISTINCT FROM expected->>'name'
    OR NEW.vendor IS DISTINCT FROM expected->>'vendor' OR NEW.description IS DISTINCT FROM expected->>'description' OR NEW.total_seats IS DISTINCT FROM (expected->>'totalSeats')::integer
    OR NEW.license_type IS DISTINCT FROM 'per_user' OR NEW.category IS DISTINCT FROM 'Software' OR NEW.auto_approve IS DISTINCT FROM false OR NEW.used_seats IS DISTINCT FROM 0
    OR NEW.cost_per_seat IS NOT NULL OR NEW.currency IS DISTINCT FROM 'CHF' OR NEW.renewal_date IS NOT NULL OR NEW.icon_url IS NOT NULL OR NEW.notes IS NOT NULL
    THEN RAISE EXCEPTION 'Exact finite original company pool required' USING ERRCODE='23514';END IF;
  ELSIF TG_OP='UPDATE' THEN
   IF receipt.action='create' OR (before_data-ARRAY['used_seats','updated_at','business_revision']) IS DISTINCT FROM (after_data-ARRAY['used_seats','updated_at','business_revision'])
    OR NEW.business_revision IS DISTINCT FROM OLD.business_revision AND (current_setting('opendirectory.license_company_finish',true) IS DISTINCT FROM receipt.id::text OR OLD.business_revision::text IS DISTINCT FROM receipt.command->>'expectedVersion' OR NEW.business_revision<>OLD.business_revision+1)
    OR NEW.used_seats<>(SELECT count(*) FROM license_assignments WHERE license_id=NEW.id)
    THEN RAISE EXCEPTION 'Exact derived company counter and revision required' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'Company pool is retained evidence' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='license_assignment_sources' THEN
  IF payload->>'user_id' IS DISTINCT FROM target OR payload->>'source_type' IS DISTINCT FROM 'direct' OR payload->>'source_id' IS DISTINCT FROM 'direct' OR payload->>'expires_at' IS NOT NULL
   OR TG_OP='INSERT' AND (receipt.action<>'assign' OR payload->>'assigned_by' IS DISTINCT FROM receipt.actor_user_id::text)
   OR TG_OP='DELETE' AND (receipt.action<>'revoke' OR before_data IS DISTINCT FROM receipt.before_state->'source') OR TG_OP='UPDATE'
   THEN RAISE EXCEPTION 'Exact direct company source required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='license_assignments' THEN
  IF payload->>'assignee_id' IS DISTINCT FROM target OR payload->>'assignee_type' IS DISTINCT FROM 'user' OR payload->>'expires_at' IS NOT NULL OR TG_OP='UPDATE'
   OR TG_OP='INSERT' AND (receipt.action<>'assign' OR payload->>'assigned_by' IS DISTINCT FROM receipt.actor_user_id::text OR payload->>'eligibility_revision' IS DISTINCT FROM receipt.source#>>'{target,eligibilityRevision}'
    OR NOT EXISTS(SELECT 1 FROM license_subjects WHERE user_id=target AND business_tenant_id=receipt.tenant_id AND NOT disabled AND directory_enabled AND NOT directory_deleted AND directory_revision::text=receipt.source#>>'{target,eligibilityRevision}'))
   OR TG_OP='DELETE' AND (receipt.action<>'revoke' OR before_data IS DISTINCT FROM receipt.before_state->'assignment')
   THEN RAISE EXCEPTION 'Exact company allocation effect required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='license_grants' THEN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 OR receipt.action<>'assign' OR NEW.kind<>'direct' OR NEW.recipient_id IS DISTINCT FROM target OR NEW.origin<>'allocated'
   OR NEW.eligibility_revision::text IS DISTINCT FROM receipt.source#>>'{target,eligibilityRevision}' THEN RAISE EXCEPTION 'Actual company allocator grant required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='license_grant_events' THEN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 OR NEW.expires_at IS NOT NULL OR NEW.changed_user_id IS NOT NULL
   OR ROW(NEW.actor_user_id,NEW.actor_issuer,NEW.actor_subject) IS DISTINCT FROM ROW(receipt.actor_user_id::text,receipt.source->>'issuer',receipt.source->>'subject')
   OR receipt.action='assign' AND (NEW.version<>1 OR NEW.state<>'active' OR NEW.event<>'source-created' OR NOT EXISTS(SELECT 1 FROM license_grants WHERE id=NEW.grant_id AND license_id=receipt.license_id AND recipient_id=target))
   OR receipt.action='revoke' AND (NEW.grant_id::text IS DISTINCT FROM receipt.before_state#>>'{source,grant_id}' OR NEW.version<>(receipt.before_state#>>'{grantEvent,version}')::bigint+1 OR NEW.state<>'revoked' OR NEW.event<>'source-removed')
   OR receipt.action='create' THEN RAISE EXCEPTION 'Exact allocator grant history required' USING ERRCODE='23514';END IF;
 ELSIF TG_TABLE_NAME='license_audit_events' THEN
  IF TG_OP<>'INSERT' OR ROW(NEW.actor_issuer,NEW.actor_subject) IS DISTINCT FROM ROW(receipt.source->>'issuer',receipt.source->>'subject') THEN RAISE EXCEPTION 'Original company audit actor required' USING ERRCODE='23514';END IF;
  IF NEW.action='directory-eligibility-changed' AND receipt.action='assign' THEN
   expected=jsonb_build_object('schemaVersion',1,'userId',target,'revision',receipt.source#>>'{target,eligibilityRevision}','enabled',receipt.source#>'{target,enabled}','deleted',receipt.source#>'{target,deleted}');
   IF NEW.actor<>'system:user-eligibility' OR NEW.details IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact company eligibility audit required' USING ERRCODE='23514';END IF;
  ELSIF receipt.action='assign' AND NEW.action='assigned' THEN
   IF NEW.actor<>receipt.actor_user_id::text OR NEW.details IS DISTINCT FROM (SELECT license_company_row('license_assignments',to_jsonb(assignment)) FROM license_assignments assignment WHERE license_id=receipt.license_id AND assignee_id=target AND assignee_type='user') THEN RAISE EXCEPTION 'Actual company assignment audit required' USING ERRCODE='23514';END IF;
  ELSIF receipt.action='revoke' AND NEW.action='direct-source-revoked' THEN
   IF NEW.actor<>receipt.actor_user_id::text OR NEW.details IS DISTINCT FROM jsonb_build_object('assignment',receipt.before_state->'assignment','effectiveAssignmentRetained',false) THEN RAISE EXCEPTION 'Actual company release audit required' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'Unrelated company audit forbidden' USING ERRCODE='42501';END IF;
 ELSE RAISE EXCEPTION 'Company operation cannot alter governed or external resources' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION license_company_observe() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;before_data JSONB;after_data JSONB;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current()) THEN RETURN NULL;END IF;
 receipt=license_company_scope();
 IF TG_OP<>'INSERT' THEN before_data=license_company_row(TG_TABLE_NAME,to_jsonb(OLD));END IF;
 IF TG_OP<>'DELETE' THEN after_data=license_company_row(TG_TABLE_NAME,to_jsonb(NEW));END IF;
 INSERT INTO license_company_origins(id,command_id,relation,operation,before_state,after_state) VALUES(receipt.id,receipt.id,TG_TABLE_NAME,TG_OP,before_data,after_data);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_company_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;receiver RECORD;
BEGIN
 FOREACH relation IN ARRAY license_company_relations() LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='zz_license_company_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='license_company_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='license_company_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='license_company_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Company license row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['license_catalog','license_subjects','license_assignments','license_assignment_sources','license_grants','license_grant_events','license_audit_events'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='zz_license_company_observe' AND tgtype=29 AND tgenabled='O' AND tgfoid='license_company_observe()'::regprocedure)
   THEN RAISE EXCEPTION 'Company license effect receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='license_company_commands'::regclass AND tgname='license_company_commit' AND tgtype=5 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='license_company_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Company license commit receiver unavailable' USING ERRCODE='42501';END IF;
 FOR receiver IN SELECT * FROM(VALUES
  ('license_catalog','license_capacity_guard','license_validate_capacity()',23),
  ('license_subjects','license_subject_directory_guard','license_subject_directory_guard()',23),
  ('license_assignment_sources','license_source_grant_before','license_source_grant_before()',23),
  ('license_assignment_sources','license_source_grant_after','license_source_grant_after()',29),
  ('license_assignments','license_assignment_capacity_guard','license_assignment_capacity()',23),
  ('license_assignments','license_assignment_eligibility_guard','license_assignment_eligibility_guard()',23),
  ('license_assignments','license_assignment_counter_sync','license_assignment_counter()',13),
  ('license_assignments','zz_license_lease_projection_guard','license_lease_projection_guard()',23),
  ('license_grants','license_grants_guard','license_grant_history_guard()',31),
  ('license_grants','b_license_review_grant_origin','license_review_grant_origin()',7),
  ('license_grant_events','license_grant_events_guard','license_grant_history_guard()',31),
  ('license_audit_events','license_audit_immutable','license_audit_append_only()',27),
  ('license_assignment_sources','a1_license_scope_business','license_scope_business_guard()',31),
  ('license_grants','a1_license_scope_business','license_scope_business_guard()',31)
 ) specification(relation,name,routine,kind) LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(receiver.relation) AND tgname=receiver.name AND tgfoid=to_regprocedure(receiver.routine) AND tgtype=receiver.kind AND tgenabled='O')
   THEN RAISE EXCEPTION 'Existing company allocator receiver unavailable: %',receiver.name USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION license_company_begin(source JSONB,command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;subject license_subjects;identifier TEXT;catalog license_catalog;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='license_catalog'::regclass) OR current_setting('role',true) NOT IN('none','')
  OR NOT license_company_proof_valid(source,command) OR NULLIF(current_setting('opendirectory.license_company',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM license_company_commands WHERE transaction_id=txid_current())
  OR EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=19770022::oid AND objid=1::oid AND objsubid=2 AND mode='ShareLock' AND granted)
  OR NOT license_company_control_clean()
  OR ROW(NULLIF(current_setting('opendirectory.license_actor_user',true),''),NULLIF(current_setting('opendirectory.license_actor_issuer',true),''),NULLIF(current_setting('opendirectory.license_actor_subject',true),''))
   IS DISTINCT FROM ROW(source->>'actorUserId',source->>'issuer',source->>'subject')
  THEN RAISE EXCEPTION 'Original bounded company authority required' USING ERRCODE='42501';END IF;
 PERFORM license_company_receiving();
 receipt.id=(command->>'id')::uuid;receipt.correlation_id=(command->>'correlationId')::uuid;receipt.license_id=(command->>'licenseId')::uuid;
 receipt.tenant_id=(source#>>'{tenant,id}')::uuid;receipt.actor_user_id=(source->>'actorUserId')::uuid;receipt.target_user_id=(source#>>'{target,id}')::uuid;receipt.action=command->>'action';
 receipt.new_subject_ids='{}';
 IF receipt.action<>'create' THEN
  FOR identifier IN SELECT DISTINCT item FROM unnest(ARRAY[receipt.actor_user_id::text,receipt.target_user_id::text]) item ORDER BY item LOOP
   SELECT * INTO subject FROM license_subjects WHERE user_id=identifier FOR UPDATE;
   IF NOT FOUND THEN
    receipt.new_subject_ids=array_append(receipt.new_subject_ids,identifier);
    IF NOT license_company_subject_unused(identifier,true,receipt.tenant_id) THEN RAISE EXCEPTION 'Subject history requires controlled migration' USING ERRCODE='23514';END IF;
    CONTINUE;
   END IF;
   IF subject.business_tenant_id IS NOT NULL AND subject.business_tenant_id<>receipt.tenant_id THEN RAISE EXCEPTION 'Foreign company subject' USING ERRCODE='42501';END IF;
   IF subject.business_tenant_id IS NULL AND (subject.disabled OR subject.directory_revision IS NOT NULL OR subject.directory_enabled IS NOT NULL OR subject.directory_deleted IS NOT NULL
    OR subject.directory_checked_at IS NOT NULL OR subject.directory_attempted_at IS NOT NULL OR subject.directory_error IS NOT NULL OR NOT license_company_subject_unused(identifier,identifier=ANY(receipt.new_subject_ids),receipt.tenant_id))
    THEN RAISE EXCEPTION 'Subject history requires controlled migration' USING ERRCODE='23514';END IF;
   IF identifier=receipt.actor_user_id::text AND (subject.disabled OR subject.directory_enabled=false OR subject.directory_deleted) THEN RAISE EXCEPTION 'Company actor is disabled' USING ERRCODE='42501';END IF;
  END LOOP;
 END IF;
 SELECT * INTO catalog FROM license_catalog WHERE id=receipt.license_id FOR UPDATE;
 IF receipt.action='create' THEN
  IF catalog.id IS NOT NULL OR EXISTS(SELECT 1 FROM license_company_commands WHERE license_id=receipt.license_id) THEN RAISE EXCEPTION 'New company pool namespace required' USING ERRCODE='23514';END IF;
 ELSE
  IF catalog.id IS NULL OR catalog.business_tenant_id IS DISTINCT FROM receipt.tenant_id THEN RAISE EXCEPTION 'Own company pool required' USING ERRCODE='42501';END IF;
  IF catalog.business_revision::text IS DISTINCT FROM command->>'expectedVersion' THEN RAISE EXCEPTION 'Company pool version changed' USING ERRCODE='40001';END IF;
  IF NOT license_company_pool_valid(catalog.id) THEN RAISE EXCEPTION 'Retained company pool receipt required' USING ERRCODE='23514';END IF;
  IF catalog.business_revision=9223372036854775807 OR catalog.license_type<>'per_user' OR catalog.total_seats NOT BETWEEN 1 AND 10000 OR NOT license_company_supported(catalog.id)
   THEN RAISE EXCEPTION 'Unsupported company pool requires controlled workflow' USING ERRCODE='23514';END IF;
 END IF;
 receipt.before_state=license_company_state(receipt.license_id,receipt.actor_user_id,receipt.target_user_id);
 IF receipt.action='assign' AND (receipt.before_state->>'assignment' IS NOT NULL OR receipt.before_state->>'source' IS NOT NULL) THEN RAISE EXCEPTION 'Company recipient already allocated' USING ERRCODE='23514';END IF;
 IF receipt.action='revoke' AND (receipt.before_state#>>'{assignment,id}' IS DISTINCT FROM command->>'assignmentId' OR receipt.before_state->>'source' IS NULL OR receipt.before_state#>>'{grantEvent,state}' IS DISTINCT FROM 'active')
  THEN RAISE EXCEPTION 'Exact current direct assignment required' USING ERRCODE='23514';END IF;
 receipt.source=source;receipt.command=command;receipt.created_at=clock_timestamp();receipt.valid_until=to_timestamp((source->>'validUntil')::double precision);receipt.transaction_id=txid_current();
 PERFORM set_config('opendirectory.license_company',receipt.id::text,true);INSERT INTO license_company_commands SELECT receipt.*;
 IF receipt.action<>'create' THEN
  FOR identifier IN SELECT unnest(receipt.new_subject_ids) LOOP
   INSERT INTO license_subjects(user_id,business_tenant_id) VALUES(identifier,receipt.tenant_id);
  END LOOP;
  UPDATE license_subjects SET business_tenant_id=receipt.tenant_id WHERE user_id IN(receipt.actor_user_id::text,receipt.target_user_id::text) AND business_tenant_id IS NULL;
 END IF;RETURN receipt.id;
END; $$;
CREATE OR REPLACE FUNCTION license_company_finish(command_id UUID,original_source JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;event license_company_events;state JSONB;expected INTEGER;actual INTEGER;
BEGIN
 PERFORM license_company_receiving();receipt=license_company_scope();
 IF receipt.id IS DISTINCT FROM command_id OR receipt.source IS DISTINCT FROM original_source OR EXISTS(SELECT 1 FROM license_company_events WHERE id=receipt.id)
  THEN RAISE EXCEPTION 'Original unchanged company checkpoint required' USING ERRCODE='42501';END IF;
 IF receipt.action<>'create' THEN
  PERFORM set_config('opendirectory.license_company_finish',receipt.id::text,true);
  UPDATE license_catalog SET business_revision=business_revision+1,updated_at=clock_timestamp() WHERE id=receipt.license_id AND business_revision::text=receipt.command->>'expectedVersion';
  IF NOT FOUND THEN RAISE EXCEPTION 'Company pool version changed' USING ERRCODE='40001';END IF;
 END IF;
 state=license_company_state(receipt.license_id,receipt.actor_user_id,receipt.target_user_id,(receipt.before_state#>>'{source,grant_id}')::uuid);
 IF state#>>'{catalog,business_tenant_id}' IS DISTINCT FROM receipt.tenant_id::text OR state#>>'{catalog,business_revision}' IS DISTINCT FROM (CASE WHEN receipt.action='create' THEN '1' ELSE ((receipt.command->>'expectedVersion')::bigint+1)::text END)
  OR NOT license_company_supported(receipt.license_id) OR (state#>>'{catalog,used_seats}')::integer IS DISTINCT FROM (SELECT count(*)::integer FROM license_assignments WHERE license_id=receipt.license_id)
  THEN RAISE EXCEPTION 'Actual company catalog effect required' USING ERRCODE='23514';END IF;
 SELECT count(*) INTO actual FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_catalog' AND operation='INSERT';
 IF actual<>(CASE WHEN receipt.action='create' THEN 1 ELSE 0 END) THEN RAISE EXCEPTION 'Original catalog creation effect required' USING ERRCODE='23514';END IF;
 IF receipt.action<>'create' THEN
  expected=CASE WHEN receipt.action='assign' THEN 1 ELSE 0 END;
  IF (SELECT count(*) FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_assignment_sources' AND operation=CASE WHEN receipt.action='assign' THEN 'INSERT' ELSE 'DELETE' END)<>1
   OR (SELECT count(*) FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_assignments' AND operation=CASE WHEN receipt.action='assign' THEN 'INSERT' ELSE 'DELETE' END)<>1
   OR (SELECT count(*) FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_grants')<>expected
   OR (SELECT count(*) FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_grant_events')<>1
   OR (SELECT count(*) FROM license_company_origins WHERE license_company_origins.command_id=receipt.id AND relation='license_audit_events' AND after_state->>'action'=CASE WHEN receipt.action='assign' THEN 'assigned' ELSE 'direct-source-revoked' END)<>1
   THEN RAISE EXCEPTION 'Actual allocator source, projection, grant and audit effects required' USING ERRCODE='23514';END IF;
  IF receipt.action='assign' AND (state->>'assignment' IS NULL OR state->>'source' IS NULL OR state#>>'{grantEvent,state}' IS DISTINCT FROM 'active')
   OR receipt.action='revoke' AND (state->>'assignment' IS NOT NULL OR state->>'source' IS NOT NULL OR state#>>'{grantEvent,state}' IS DISTINCT FROM 'revoked')
   THEN RAISE EXCEPTION 'Exact effective company allocation result required' USING ERRCODE='23514';END IF;
 END IF;
 event.id=receipt.id;event.tenant_id=receipt.tenant_id;event.license_id=receipt.license_id;event.type=CASE receipt.action WHEN 'create' THEN 'app.license.pool.created' WHEN 'assign' THEN 'app.license.assigned' ELSE 'app.license.released' END;
 event.version=1;event.actor_user_id=receipt.actor_user_id;event.target_user_id=receipt.target_user_id;event.correlation_id=receipt.correlation_id;event.created_at=clock_timestamp();
 event.before_revision=(receipt.before_state#>>'{catalog,business_revision}')::bigint;event.after_revision=(state#>>'{catalog,business_revision}')::bigint;
 event.proof=jsonb_build_object('source',receipt.source,'command',receipt.command,'checkpoint',original_source);event.before_state=receipt.before_state;event.after_state=state;
 INSERT INTO license_company_events SELECT event.*;INSERT INTO license_company_outbox VALUES(event.id,event.tenant_id,'pending',event.created_at);RETURN event.id;
END; $$;
CREATE OR REPLACE FUNCTION license_company_event_valid(event license_company_events) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;effect license_company_origins;expected TEXT;material JSONB;
BEGIN
 SELECT * INTO receipt FROM license_company_commands WHERE id=event.id;
 IF receipt.id IS NULL OR ROW(event.tenant_id,event.license_id,event.actor_user_id,event.target_user_id,event.correlation_id) IS DISTINCT FROM ROW(receipt.tenant_id,receipt.license_id,receipt.actor_user_id,receipt.target_user_id,receipt.correlation_id)
  OR event.version<>1 OR event.proof IS DISTINCT FROM jsonb_build_object('source',receipt.source,'command',receipt.command,'checkpoint',receipt.source)
  OR event.before_state IS DISTINCT FROM receipt.before_state OR event.before_revision IS DISTINCT FROM (receipt.before_state#>>'{catalog,business_revision}')::bigint
  OR event.after_revision::numeric IS DISTINCT FROM COALESCE(event.before_revision::numeric+1,1) OR event.after_revision::numeric<>(receipt.command->>'expectedVersion')::numeric+1
  OR event.type IS DISTINCT FROM (CASE receipt.action WHEN 'create' THEN 'app.license.pool.created' WHEN 'assign' THEN 'app.license.assigned' ELSE 'app.license.released' END)
  OR NOT EXISTS(SELECT 1 FROM license_company_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND status='pending' AND created_at=event.created_at)
  THEN RETURN false;END IF;
 IF receipt.action='create' THEN
  RETURN (SELECT count(*)=1 FROM license_company_origins WHERE command_id=receipt.id AND relation='license_catalog' AND operation='INSERT' AND before_state IS NULL AND after_state=event.after_state->'catalog');
 END IF;
 expected=CASE WHEN receipt.action='assign' THEN 'INSERT' ELSE 'DELETE' END;
 IF (SELECT count(*) FROM license_company_origins WHERE command_id=receipt.id AND relation='license_assignments' AND operation=expected
   AND (CASE WHEN receipt.action='assign' THEN after_state ELSE before_state END)=(CASE WHEN receipt.action='assign' THEN event.after_state->'assignment' ELSE event.before_state->'assignment' END))<>1
  OR (SELECT count(*) FROM license_company_origins WHERE command_id=receipt.id AND relation='license_assignment_sources' AND operation=expected
   AND (CASE WHEN receipt.action='assign' THEN after_state ELSE before_state END)=(CASE WHEN receipt.action='assign' THEN event.after_state->'source' ELSE event.before_state->'source' END))<>1
  OR (SELECT count(*) FROM license_company_origins WHERE command_id=receipt.id AND relation='license_grant_events' AND operation='INSERT' AND after_state=event.after_state->'grantEvent')<>1
  OR NOT EXISTS(SELECT 1 FROM license_company_origins WHERE command_id=receipt.id AND relation='license_catalog' AND operation='UPDATE' AND after_state=event.after_state->'catalog')
  THEN RETURN false;END IF;
 IF receipt.action='assign' AND (SELECT count(*) FROM license_company_origins WHERE command_id=receipt.id AND relation='license_grants' AND operation='INSERT' AND after_state=event.after_state->'grant')<>1 THEN RETURN false;END IF;
 expected=CASE WHEN receipt.action='assign' THEN 'assigned' ELSE 'direct-source-revoked' END;
 IF (SELECT count(*) FROM license_company_origins WHERE command_id=receipt.id AND relation='license_audit_events' AND after_state->>'action'=expected)<>1 THEN RETURN false;END IF;
 FOR effect IN SELECT * FROM license_company_origins WHERE command_id=receipt.id AND relation='license_audit_events' LOOP
  SELECT to_jsonb(audit) INTO material FROM license_audit_events audit WHERE id=(effect.after_state->>'id')::uuid;
  IF material IS DISTINCT FROM effect.after_state THEN RETURN false;END IF;
 END LOOP;RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION license_company_pool_valid(pool_id UUID) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE catalog license_catalog;event license_company_events;
BEGIN
 PERFORM license_company_receiving();SELECT * INTO catalog FROM license_catalog WHERE id=pool_id;
 IF catalog.id IS NULL OR catalog.business_tenant_id IS NULL OR catalog.business_revision IS NULL OR catalog.license_type<>'per_user' OR catalog.total_seats NOT BETWEEN 1 AND 10000
  OR EXISTS(SELECT 1 FROM license_assignments WHERE license_id=pool_id AND (assignee_type<>'user' OR expires_at IS NOT NULL))
  OR EXISTS(SELECT 1 FROM license_assignment_sources WHERE license_id=pool_id AND (source_type<>'direct' OR source_id<>'direct' OR expires_at IS NOT NULL)) THEN RETURN false;END IF;
 SELECT * INTO event FROM license_company_events WHERE license_id=pool_id ORDER BY after_revision DESC LIMIT 1;
 IF event.id IS NULL OR event.tenant_id<>catalog.business_tenant_id OR event.after_revision<>catalog.business_revision
  OR event.after_state->'catalog' IS DISTINCT FROM license_company_row('license_catalog',to_jsonb(catalog))
  OR NOT EXISTS(SELECT 1 FROM license_company_commands command JOIN license_company_outbox outbox ON outbox.id=command.id
   WHERE command.id=event.id AND command.tenant_id=event.tenant_id AND command.license_id=event.license_id AND outbox.tenant_id=event.tenant_id AND outbox.status='pending' AND outbox.created_at=event.created_at
    AND event.proof=jsonb_build_object('source',command.source,'command',command.command,'checkpoint',command.source) AND event.before_state=command.before_state)
  OR catalog.used_seats<>(SELECT count(*) FROM license_assignments WHERE license_id=pool_id)
  OR (SELECT count(*) FROM license_company_events WHERE license_id=pool_id)<>catalog.business_revision
  OR EXISTS(SELECT 1 FROM license_company_events history WHERE license_id=pool_id AND NOT license_company_event_valid(history))
  THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM license_assignments assignment LEFT JOIN license_subjects subject ON subject.user_id=assignment.assignee_id
  LEFT JOIN license_assignment_sources source ON source.license_id=assignment.license_id AND source.user_id=assignment.assignee_id AND source.source_type='direct'
  LEFT JOIN license_grants grants ON grants.id=source.grant_id
  LEFT JOIN LATERAL(SELECT * FROM license_grant_events WHERE grant_id=grants.id ORDER BY version DESC LIMIT 1) history ON true
  WHERE assignment.license_id=pool_id AND (subject.business_tenant_id IS DISTINCT FROM catalog.business_tenant_id OR source.grant_id IS NULL OR grants.kind IS DISTINCT FROM 'direct'
   OR grants.recipient_id IS DISTINCT FROM assignment.assignee_id OR grants.license_id IS DISTINCT FROM pool_id OR grants.origin IS DISTINCT FROM 'allocated'
   OR grants.eligibility_revision IS DISTINCT FROM assignment.eligibility_revision OR history.state IS DISTINCT FROM 'active'
   OR NOT EXISTS(SELECT 1 FROM license_company_events evidence WHERE evidence.license_id=pool_id AND evidence.type='app.license.assigned'
    AND evidence.after_state->'assignment'=license_company_row('license_assignments',to_jsonb(assignment)) AND evidence.after_state->'source'=to_jsonb(source)
    AND evidence.after_state->'grant'=license_company_row('license_grants',to_jsonb(grants)) AND evidence.after_state->'grantEvent'=license_company_row('license_grant_events',to_jsonb(history))))) THEN RETURN false;END IF;
 RETURN NOT EXISTS(SELECT 1 FROM license_assignment_sources source WHERE license_id=pool_id AND NOT EXISTS(SELECT 1 FROM license_assignments WHERE license_id=pool_id AND assignee_type='user' AND assignee_id=source.user_id));
END; $$;
CREATE OR REPLACE FUNCTION license_company_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE receipt license_company_commands;event license_company_events;
BEGIN
 PERFORM license_company_receiving();receipt=license_company_scope();SELECT * INTO event FROM license_company_events WHERE id=receipt.id;
 IF receipt IS DISTINCT FROM NEW OR event.id IS NULL OR NOT license_company_pool_valid(receipt.license_id)
  OR event.after_state IS DISTINCT FROM license_company_state(receipt.license_id,receipt.actor_user_id,receipt.target_user_id,(receipt.before_state#>>'{source,grant_id}')::uuid)
  THEN RAISE EXCEPTION 'Actual company final receipt required before commit' USING ERRCODE='23514';END IF;RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;routine RECORD;BEGIN
 FOREACH relation IN ARRAY license_company_relations() LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS zz_license_company_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER zz_license_company_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_company_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS license_company_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER license_company_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION license_company_guard()',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['license_catalog','license_subjects','license_assignments','license_assignment_sources','license_grants','license_grant_events','license_audit_events'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS zz_license_company_observe ON %I',relation);
  EXECUTE format('CREATE TRIGGER zz_license_company_observe AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_company_observe()',relation);
 END LOOP;
 DROP TRIGGER IF EXISTS license_company_commit ON license_company_commands;
 CREATE CONSTRAINT TRIGGER license_company_commit AFTER INSERT ON license_company_commands DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION license_company_commit();
 FOR routine IN SELECT oid::regprocedure AS signature FROM pg_proc WHERE pronamespace=current_schema()::regnamespace AND proname LIKE 'license_company_%' LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine.signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',routine.signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine.signature);
 END LOOP;
END; $$;
