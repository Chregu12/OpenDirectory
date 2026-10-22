CREATE TABLE IF NOT EXISTS identity_automation_enrollments (
 id UUID PRIMARY KEY,issuer TEXT NOT NULL,client_id TEXT NOT NULL,client_revision BIGINT NOT NULL CHECK(client_revision>0),name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 160),
 expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes')
);
CREATE TABLE IF NOT EXISTS identity_automation_grants (
 id UUID PRIMARY KEY,enrollment_id UUID NOT NULL UNIQUE REFERENCES identity_automation_enrollments(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 issuer TEXT NOT NULL,client_id TEXT NOT NULL,client_revision BIGINT NOT NULL CHECK(client_revision>0),actions TEXT[] NOT NULL CHECK(cardinality(actions) BETWEEN 1 AND 3),
 created_by UUID NOT NULL REFERENCES users(id),approval JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),expires_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL CHECK(status IN('active','revoked')),revision BIGINT NOT NULL DEFAULT 1,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(actions<@ARRAY['directory.users.export','directory.groups.export','directory.ous.export']::text[]),CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 days'),
 CHECK(status='active' AND revision=1 OR status='revoked' AND revision=2)
);
CREATE TABLE IF NOT EXISTS identity_automation_schedules (
 id UUID PRIMARY KEY,grant_id UUID NOT NULL REFERENCES identity_automation_grants(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),action TEXT NOT NULL,format TEXT NOT NULL CHECK(format IN('csv','json')),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2592000),enabled BOOLEAN NOT NULL DEFAULT true,next_run_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),revision BIGINT NOT NULL DEFAULT 1,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_automation_jobs (
 id UUID PRIMARY KEY,grant_id UUID NOT NULL REFERENCES identity_automation_grants(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),schedule_id UUID REFERENCES identity_automation_schedules(id),
 action TEXT NOT NULL,format TEXT NOT NULL CHECK(format IN('csv','json')),status TEXT NOT NULL CHECK(status IN('queued','running','retry_wait','succeeded','failed','cancelled')),
 revision BIGINT NOT NULL DEFAULT 1,attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 5),retry_count INTEGER NOT NULL DEFAULT 0 CHECK(retry_count>=0),
 available_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),lease_token UUID,lease_until TIMESTAMPTZ,error_code TEXT,
 artifact_content TEXT,artifact_type TEXT,artifact_sha256 TEXT,row_count INTEGER,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(status='running' AND lease_token IS NOT NULL AND lease_until IS NOT NULL OR status<>'running' AND lease_token IS NULL AND lease_until IS NULL),
 CHECK(status='succeeded' AND artifact_content IS NOT NULL AND artifact_type IS NOT NULL AND artifact_sha256 ~ '^[a-f0-9]{64}$' AND row_count BETWEEN 0 AND 10000
  OR status<>'succeeded' AND artifact_content IS NULL AND artifact_type IS NULL AND artifact_sha256 IS NULL AND row_count IS NULL),CHECK(octet_length(artifact_content)<=4194304)
);
CREATE INDEX IF NOT EXISTS identity_automation_job_due ON identity_automation_jobs(available_at,id) WHERE status IN('queued','retry_wait','running');
CREATE TABLE IF NOT EXISTS identity_automation_events (
 id UUID PRIMARY KEY,entity TEXT NOT NULL,entity_id UUID NOT NULL,tenant_id UUID,revision BIGINT NOT NULL,actor JSONB NOT NULL,snapshot JSONB NOT NULL,
 transaction_id BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),UNIQUE(entity,entity_id,revision)
);
CREATE TABLE IF NOT EXISTS identity_automation_outbox (
 id UUID PRIMARY KEY REFERENCES identity_automation_events(id),status TEXT NOT NULL DEFAULT 'pending' CHECK(status='pending'),created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS identity_automation_receiver_manifest(signature TEXT PRIMARY KEY,digest TEXT NOT NULL);

CREATE OR REPLACE FUNCTION identity_automation_owner(source JSONB) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE tenant UUID;
BEGIN
 PERFORM identity_authority_owner();
 IF source->>'schemaVersion' IS DISTINCT FROM '1' OR source->>'validUntil' IS NULL OR (source->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
  OR (source->>'validUntil')::numeric>extract(epoch FROM clock_timestamp())+300 OR source->>'actorUserId' IS DISTINCT FROM source#>>'{context,userId}'
  THEN RAISE EXCEPTION 'Current original automation owner proof required' USING ERRCODE='42501';END IF;
 tenant=identity_authority_actor_home((source->'context')||jsonb_build_object('issuer',source->>'issuer','subject',source->>'subject'));
 IF tenant::text IS DISTINCT FROM source#>>'{tenant,id}' OR NOT EXISTS(SELECT 1 FROM identity_tenants WHERE id=tenant AND enabled AND version::text=source#>>'{tenant,version}' AND generation::text=source#>>'{tenant,generation}')
  OR NOT EXISTS(SELECT 1 FROM identity_company_activations owner WHERE owner.user_id=(source->>'actorUserId')::uuid AND owner.tenant_id=tenant AND owner.issuer=source->>'issuer' AND owner.subject=source->>'subject' AND identity_company_owner_active(owner))
  THEN RAISE EXCEPTION 'Actual own-company automation owner required' USING ERRCODE='42501';END IF;
 RETURN tenant;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_grant_live(grant_id UUID) RETURNS BOOLEAN LANGUAGE sql STABLE AS $$
 SELECT COALESCE(EXISTS(SELECT 1 FROM identity_automation_grants permission JOIN identity_tenants tenant ON tenant.id=permission.tenant_id
  JOIN identity_company_activations owner ON owner.user_id=permission.created_by AND owner.tenant_id=tenant.id
  WHERE permission.id=grant_id AND permission.status='active' AND permission.expires_at>clock_timestamp() AND tenant.enabled
   AND tenant.version::text=permission.approval#>>'{tenant,version}' AND tenant.generation::text=permission.approval#>>'{tenant,generation}'
   AND identity_company_owner_active(owner)
   AND EXISTS(SELECT 1 FROM identity_automation_events event JOIN identity_automation_outbox box ON box.id=event.id AND box.status='pending'
    WHERE event.entity='grant' AND event.entity_id=permission.id AND event.revision=permission.revision AND event.snapshot=to_jsonb(permission))),false);
$$;
CREATE OR REPLACE FUNCTION identity_automation_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE actor JSONB;tenant UUID;permission identity_automation_grants;enrollment identity_automation_enrollments;data JSONB;entity_name TEXT;event identity_automation_events;
BEGIN
 PERFORM identity_authority_owner();
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_automation_events) THEN RAISE EXCEPTION 'Automation history retained' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 IF TG_TABLE_NAME IN('identity_automation_events','identity_automation_outbox') THEN
  IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Only actual automation effects create immutable evidence' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Automation history retained' USING ERRCODE='42501';END IF;
 actor=NULLIF(current_setting('opendirectory.company_automation',true),'')::jsonb;
 IF actor IS NULL OR actor->>'kind' NOT IN('owner','application') THEN RAISE EXCEPTION 'Original automation authority required' USING ERRCODE='42501';END IF;
 IF actor->>'kind'='owner' THEN tenant=identity_automation_owner(actor->'source');
 ELSE
  IF actor->>'issuer' IS NULL OR actor->>'clientId' IS NULL OR actor->>'clientRevision' IS NULL OR actor->>'tokenId' IS NULL OR actor->>'validUntil' IS NULL
   OR (actor->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Original app deadline expired' USING ERRCODE='42501';END IF;
 END IF;
 data=to_jsonb(NEW);entity_name=replace(TG_TABLE_NAME,'identity_automation_','');entity_name=CASE entity_name WHEN 'enrollments' THEN 'enrollment' WHEN 'grants' THEN 'grant' WHEN 'jobs' THEN 'job' ELSE 'schedule' END;
 IF TG_TABLE_NAME='identity_automation_enrollments' THEN
  IF TG_OP<>'INSERT' OR actor->>'kind'<>'application' OR NEW.issuer<>actor->>'issuer' OR NEW.client_id<>actor->>'clientId' OR NEW.client_revision::text<>actor->>'clientRevision'
   OR NEW.expires_at>clock_timestamp()+interval '10 minutes' THEN RAISE EXCEPTION 'Exact app enrollment required' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME='identity_automation_grants' THEN
  IF actor->>'kind'<>'owner' OR NEW.tenant_id<>tenant THEN RAISE EXCEPTION 'Own original grant approval required' USING ERRCODE='42501';END IF;
  IF TG_OP='INSERT' THEN
   SELECT * INTO enrollment FROM identity_automation_enrollments WHERE id=NEW.enrollment_id;
   IF enrollment.id IS NULL OR enrollment.expires_at<=clock_timestamp() OR NEW.issuer<>enrollment.issuer OR NEW.client_id<>enrollment.client_id OR NEW.client_revision<>enrollment.client_revision
    OR NEW.created_by::text<>actor#>>'{source,actorUserId}' OR NEW.approval IS DISTINCT FROM actor->'source' OR NEW.status<>'active' OR NEW.revision<>1
    THEN RAISE EXCEPTION 'Exact current app approval required' USING ERRCODE='42501';END IF;
  ELSIF to_jsonb(NEW)-ARRAY['status','revision','updated_at'] IS DISTINCT FROM to_jsonb(OLD)-ARRAY['status','revision','updated_at'] OR OLD.status<>'active' OR NEW.status<>'revoked' OR NEW.revision<>OLD.revision+1
   THEN RAISE EXCEPTION 'Automation grants are immutable except revocation' USING ERRCODE='42501';END IF;
 ELSE
  IF TG_WHEN='BEFORE' AND TG_OP='UPDATE' AND NOT EXISTS(SELECT 1 FROM identity_automation_events original JOIN identity_automation_outbox box ON box.id=original.id AND box.status='pending'
    WHERE original.entity=entity_name AND original.entity_id=OLD.id AND original.revision=OLD.revision AND original.snapshot=to_jsonb(OLD)-'artifact_content')
    THEN RAISE EXCEPTION 'Retained original job or schedule required' USING ERRCODE='42501';END IF;
  SELECT * INTO permission FROM identity_automation_grants WHERE id=NEW.grant_id FOR SHARE;
  IF permission.id IS NULL OR NEW.tenant_id<>permission.tenant_id OR NOT NEW.action=ANY(permission.actions)
   OR actor->>'kind'='owner' AND tenant<>permission.tenant_id
   OR actor->>'kind'='application' AND (permission.issuer<>actor->>'issuer' OR permission.client_id<>actor->>'clientId' OR permission.client_revision::text<>actor->>'clientRevision')
   THEN RAISE EXCEPTION 'Exact granted app action required' USING ERRCODE='42501';END IF;
  IF NOT identity_automation_grant_live(permission.id) AND NOT(TG_OP='UPDATE' AND actor->>'kind'='owner' AND
    (TG_TABLE_NAME='identity_automation_jobs' AND data->>'status'='cancelled' OR TG_TABLE_NAME='identity_automation_schedules' AND data->'enabled'='false'::jsonb))
    THEN RAISE EXCEPTION 'Automation grant inactive' USING ERRCODE='42501';END IF;
  IF TG_OP='UPDATE' AND (NEW.revision<>OLD.revision+1 OR NEW.id<>OLD.id OR NEW.grant_id<>OLD.grant_id OR NEW.tenant_id<>OLD.tenant_id OR NEW.action<>OLD.action OR NEW.format<>OLD.format OR NEW.created_at<>OLD.created_at)
   THEN RAISE EXCEPTION 'Exact automation version required' USING ERRCODE='42501';END IF;
  IF TG_TABLE_NAME='identity_automation_jobs' THEN
   IF TG_OP='INSERT' AND (NEW.status<>'queued' OR NEW.attempt_count<>0 OR NEW.revision<>1) THEN RAISE EXCEPTION 'New queued job required' USING ERRCODE='42501';END IF;
   IF TG_OP='UPDATE' THEN
    IF NOT (OLD.status IN('queued','retry_wait') AND NEW.status IN('running','cancelled')
      OR OLD.status='running' AND NEW.status IN('running','succeeded','retry_wait','failed','cancelled')
      OR OLD.status='failed' AND NEW.status='queued' AND NEW.retry_count=OLD.retry_count+1 AND NEW.attempt_count=0)
      OR NEW.schedule_id IS DISTINCT FROM OLD.schedule_id THEN RAISE EXCEPTION 'Invalid durable job transition' USING ERRCODE='42501';END IF;
    IF NEW.status IN('running','succeeded','retry_wait','failed') AND actor->>'kind'<>'application' THEN RAISE EXCEPTION 'Actual app worker required' USING ERRCODE='42501';END IF;
    IF NEW.status='running' AND (NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '50 seconds' OR NEW.lease_until>to_timestamp((actor->>'validUntil')::double precision) OR NEW.attempt_count<>OLD.attempt_count+1)
     OR OLD.status='running' AND OLD.lease_until<=clock_timestamp() AND NEW.status<>'running' AND NEW.status<>'cancelled'
      AND NOT(NEW.status='failed' AND OLD.attempt_count=5 AND NEW.error_code='lease_expired') THEN RAISE EXCEPTION 'Exact unexpired worker lease required' USING ERRCODE='42501';END IF;
   END IF;
  ELSIF TG_OP='UPDATE' AND (NEW.interval_seconds<>OLD.interval_seconds OR OLD.enabled=false AND NEW.enabled=true) THEN RAISE EXCEPTION 'Immutable schedule definition required' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_WHEN='BEFORE' THEN RETURN NEW;END IF;
 IF TG_WHEN='AFTER' AND TG_NAME='identity_automation_commit' THEN
  SELECT * INTO event FROM identity_automation_events WHERE entity=entity_name AND entity_id=NEW.id AND revision=COALESCE((data->>'revision')::bigint,1) AND transaction_id=txid_current();
  IF event.id IS NULL OR event.snapshot IS DISTINCT FROM data-'artifact_content' OR NOT EXISTS(SELECT 1 FROM identity_automation_outbox WHERE id=event.id AND status='pending')
   THEN RAISE EXCEPTION 'Retained original automation effect required' USING ERRCODE='42501';END IF;
 ELSE
  INSERT INTO identity_automation_events(id,entity,entity_id,tenant_id,revision,actor,snapshot,transaction_id)
   VALUES(gen_random_uuid(),entity_name,NEW.id,(data->>'tenant_id')::uuid,COALESCE((data->>'revision')::bigint,1),actor,data-'artifact_content',txid_current()) RETURNING * INTO event;
  INSERT INTO identity_automation_outbox(id) VALUES(event.id);
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_fence() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NULLIF(current_setting('opendirectory.company_automation',true),'') IS NULL AND NOT EXISTS(SELECT 1 FROM identity_automation_events WHERE transaction_id=txid_current())
  THEN IF TG_OP='TRUNCATE' THEN RETURN NULL;ELSIF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;END IF;
 IF TG_TABLE_NAME NOT IN('identity_automation_enrollments','identity_automation_grants','identity_automation_jobs','identity_automation_schedules','identity_automation_events','identity_automation_outbox') OR TG_OP='TRUNCATE'
  THEN RAISE EXCEPTION 'Automation cannot modify canonical identity or other authority state' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
DO $$ DECLARE relation TEXT; BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_automation_enrollments','identity_automation_grants','identity_automation_schedules','identity_automation_jobs'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_before ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_automation_before BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_event ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_automation_event AFTER INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_automation_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_automation_guard()',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['identity_automation_events','identity_automation_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_before ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_automation_before BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_guard()',relation);
 END LOOP;
 FOREACH relation IN ARRAY ARRAY['identity_automation_enrollments','identity_automation_grants','identity_automation_schedules','identity_automation_jobs','identity_automation_events','identity_automation_outbox','identity_automation_receiver_manifest'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_automation_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_automation_guard()',relation);
 END LOOP;
END; $$;
DO $$ DECLARE relation TEXT;hook RECORD;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_automation_enrollments','identity_automation_grants','identity_automation_schedules','identity_automation_jobs','identity_automation_events','identity_automation_outbox','identity_automation_receiver_manifest'] LOOP
  FOR hook IN SELECT * FROM identity_license_user_source_hooks() UNION ALL SELECT 'aaa_identity_license_user_source_fence','identity_license_user_source_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_groups_fence','identity_company_offboarding_groups_fence'
   UNION ALL SELECT 'aaa_identity_company_offboarding_access_fence','identity_company_offboarding_access_fence' LOOP
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('CREATE OR REPLACE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
  EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_company_automation_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_fence()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER aaa_identity_company_automation_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_automation_fence()',relation);
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM identity_automation_receiver_manifest)<>5 OR EXISTS(SELECT 1 FROM identity_automation_receiver_manifest WHERE to_regprocedure(signature) IS NULL OR md5(pg_get_functiondef(to_regprocedure(signature)))<>digest)
  OR EXISTS(SELECT 1 FROM pg_class relation CROSS JOIN (VALUES('aaa_identity_company_automation_fence',31),('aaa_identity_company_automation_no_truncate',34)) expected(name,kind)
    WHERE relation.relnamespace=current_schema()::regnamespace AND relation.relkind IN('r','p') AND (left(relation.relname,9)='identity_' OR relation.relname IN('users','groups','group_members','ous'))
     AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O' AND tgfoid='identity_automation_fence()'::regprocedure))
  OR (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_automation_guard()'::regprocedure AND
    ((tgname='identity_automation_before' AND tgtype=31 AND NOT tgdeferrable AND tgrelid IN('identity_automation_enrollments'::regclass,'identity_automation_grants'::regclass,'identity_automation_schedules'::regclass,'identity_automation_jobs'::regclass,'identity_automation_events'::regclass,'identity_automation_outbox'::regclass))
    OR(tgname='identity_automation_event' AND tgtype=21 AND NOT tgdeferrable AND tgrelid IN('identity_automation_enrollments'::regclass,'identity_automation_grants'::regclass,'identity_automation_schedules'::regclass,'identity_automation_jobs'::regclass))
    OR(tgname='identity_automation_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred AND tgrelid IN('identity_automation_enrollments'::regclass,'identity_automation_grants'::regclass,'identity_automation_schedules'::regclass,'identity_automation_jobs'::regclass))
    OR(tgname='identity_automation_truncate' AND tgtype=34 AND NOT tgdeferrable AND tgrelid IN('identity_automation_enrollments'::regclass,'identity_automation_grants'::regclass,'identity_automation_schedules'::regclass,'identity_automation_jobs'::regclass,'identity_automation_events'::regclass,'identity_automation_outbox'::regclass,'identity_automation_receiver_manifest'::regclass))))<>21
 THEN RAISE EXCEPTION 'Automation receiving evidence unavailable' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE signature TEXT; BEGIN
 FOREACH signature IN ARRAY ARRAY['identity_automation_owner(jsonb)','identity_automation_grant_live(uuid)','identity_automation_guard()','identity_automation_fence()','identity_automation_receiving()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
INSERT INTO identity_automation_receiver_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY['identity_automation_owner(jsonb)','identity_automation_grant_live(uuid)','identity_automation_guard()','identity_automation_fence()','identity_automation_receiving()']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
