CREATE TABLE IF NOT EXISTS identity_license_user_sources (
 id UUID PRIMARY KEY,issuer TEXT NOT NULL,client_id TEXT NOT NULL,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 client_revision BIGINT NOT NULL CHECK(client_revision>0),version BIGINT NOT NULL CHECK(version>0),enabled BOOLEAN NOT NULL,
 changed_at TIMESTAMPTZ NOT NULL,event_id UUID NOT NULL UNIQUE,UNIQUE(issuer,client_id)
);
CREATE TABLE IF NOT EXISTS identity_license_user_source_events (
 id UUID PRIMARY KEY,source_id UUID NOT NULL,tenant_id UUID NOT NULL REFERENCES identity_tenants(id),issuer TEXT NOT NULL,client_id TEXT NOT NULL,
 client_revision BIGINT NOT NULL CHECK(client_revision>0),source_version BIGINT NOT NULL CHECK(source_version>0),enabled BOOLEAN NOT NULL,
 type TEXT NOT NULL CHECK(type='license-user-source.changed'),version INTEGER NOT NULL CHECK(version=1),correlation_id UUID NOT NULL,
 operator NAME NOT NULL,actor JSONB NOT NULL,review JSONB NOT NULL,before_state JSONB,after_state JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,transaction_id BIGINT NOT NULL UNIQUE,UNIQUE(source_id,source_version)
);
CREATE TABLE IF NOT EXISTS identity_license_user_source_outbox (
 id UUID PRIMARY KEY REFERENCES identity_license_user_source_events(id),tenant_id UUID NOT NULL REFERENCES identity_tenants(id),
 status TEXT NOT NULL CHECK(status='pending'),type TEXT NOT NULL,version INTEGER NOT NULL,correlation_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL,payload JSONB NOT NULL
);
CREATE OR REPLACE FUNCTION identity_license_user_source_state_json(data identity_license_user_sources) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN (data).id IS NULL THEN NULL ELSE to_jsonb(data)||jsonb_build_object('client_revision',(data).client_revision::text,'version',(data).version::text) END;
$$;
CREATE OR REPLACE FUNCTION identity_license_user_source_event_json(data identity_license_user_source_events) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN (data).id IS NULL THEN NULL ELSE to_jsonb(data)||jsonb_build_object('client_revision',(data).client_revision::text,'source_version',(data).source_version::text,'transaction_id',(data).transaction_id::text) END;
$$;
CREATE OR REPLACE FUNCTION identity_license_user_source_owner() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF current_setting('role')<>'none' OR current_setting('session_replication_role')<>'origin'
  OR EXISTS(SELECT 1 FROM pg_class WHERE oid IN('identity_license_user_sources'::regclass,'identity_license_user_source_events'::regclass,'identity_license_user_source_outbox'::regclass)
   AND pg_get_userbyid(relowner)<>session_user)
  THEN RAISE EXCEPTION 'Actual table owner with SET ROLE none required for offline license user source review' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_input(review JSONB) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF jsonb_typeof(review) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Exact license user source review required' USING ERRCODE='23514';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(review))<>7 OR NOT review ?& ARRAY['issuer','clientId','tenantId','clientRevision','expectedVersion','enabled','reason']
  OR EXISTS(SELECT 1 FROM jsonb_each(review) entry WHERE jsonb_typeof(entry.value) IS DISTINCT FROM CASE WHEN entry.key='enabled' THEN 'boolean' ELSE 'string' END)
  OR length(review->>'issuer') NOT BETWEEN 8 AND 2048
  OR review->>'issuer' !~ '^https?://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?(/[A-Za-z0-9._~!$&''()*+,;=:@%/-]*)?$'
  OR review->>'clientId' !~ '^[A-Za-z0-9._~-]{1,255}$' OR review->>'clientId' IN('.','..')
  OR review->>'tenantId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  OR review->>'clientRevision' !~ '^[1-9][0-9]{0,18}$' OR review->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,18})$'
  OR length(review->>'reason') NOT BETWEEN 10 AND 500 OR btrim(review->>'reason') IS DISTINCT FROM review->>'reason' OR review->>'reason' ~ '[[:cntrl:]]'
  THEN RAISE EXCEPTION 'Canonical bounded exact license user source review required' USING ERRCODE='23514';END IF;
 IF (review->>'clientRevision')::numeric>9223372036854775807 OR (review->>'expectedVersion')::numeric>=9223372036854775807
  THEN RAISE EXCEPTION 'License user source revision or version exceeds BIGINT' USING ERRCODE='23514';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_hooks() RETURNS TABLE(trigger_name TEXT,routine TEXT) LANGUAGE sql IMMUTABLE AS $$
 VALUES ('aaa_identity_authority_stage_no_effects','identity_authority_stage_no_effects'),
 ('aaa_identity_authority_seal_no_effects','identity_authority_namespace_no_effects'),
 ('aaa_identity_authority_checkpoint_no_effects','identity_authority_checkpoint_no_effects'),
 ('aaa_identity_authority_source_set_no_effects','identity_authority_source_set_no_effects'),
 ('aaa_identity_organization_no_effects','identity_organization_no_effects'),
 ('aaa_identity_company_registration_fence','identity_company_registration_fence'),
 ('aaa_identity_company_review_no_effects','identity_company_review_no_effects'),
 ('aaa_identity_company_activation_fence','identity_company_activation_fence'),
 ('aaa_identity_directory_ou_fence','identity_directory_ou_fence');
$$;
CREATE OR REPLACE FUNCTION identity_license_user_source_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF current_setting('session_replication_role')<>'origin' OR EXISTS(
  SELECT 1 FROM pg_class relation CROSS JOIN (VALUES('aaa_identity_license_user_source_fence',31),('aaa_identity_license_user_source_no_truncate',34)) expected(name,kind)
  WHERE relation.relnamespace=current_schema()::regnamespace AND relation.relkind IN('r','p') AND (left(relation.relname,9)='identity_' OR relation.relname IN('users','groups','group_members','ous'))
   AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.oid AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
    AND NOT tgisinternal AND NOT tgdeferrable AND tgfoid='identity_license_user_source_fence()'::regprocedure)
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_license_user_sources','identity_license_user_source_events','identity_license_user_source_outbox']) relation(name)
  CROSS JOIN identity_license_user_source_hooks() hook CROSS JOIN (VALUES(false),(true)) truncation(enabled)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.name::regclass
   AND tgname=CASE WHEN truncation.enabled THEN regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate') ELSE hook.trigger_name END
   AND tgtype=CASE WHEN truncation.enabled THEN 34 ELSE 31 END AND tgenabled='O' AND NOT tgisinternal AND NOT tgdeferrable AND tgfoid=(hook.routine||'()')::regprocedure)
 ) OR EXISTS(
  SELECT 1 FROM unnest(ARRAY['identity_license_user_sources','identity_license_user_source_events','identity_license_user_source_outbox']) relation(name)
  CROSS JOIN (VALUES('identity_license_user_source_guard',31,false),('identity_license_user_source_no_truncate',34,false),('identity_license_user_source_commit',29,true)) expected(name,kind,deferred)
  WHERE NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=relation.name::regclass AND tgname=expected.name AND tgtype=expected.kind AND tgenabled='O'
   AND tgdeferrable=expected.deferred AND tginitdeferred=expected.deferred
   AND tgfoid=(CASE WHEN expected.deferred THEN 'identity_license_user_source_commit()' ELSE 'identity_license_user_source_guard()' END)::regprocedure)
 ) THEN RAISE EXCEPTION 'Complete license user source receiving guards required' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_valid(binding identity_license_user_sources) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actual identity_license_user_sources;event identity_license_user_source_events;previous identity_license_user_source_events;state JSONB;
BEGIN
 PERFORM identity_license_user_source_receiving();
 SELECT * INTO actual FROM identity_license_user_sources WHERE id=binding.id;
 IF actual.id IS NULL OR identity_license_user_source_state_json(actual) IS DISTINCT FROM identity_license_user_source_state_json(binding) THEN RETURN false;END IF;
 SELECT * INTO event FROM identity_license_user_source_events WHERE id=actual.event_id;
 IF event.id IS NULL THEN RETURN false;END IF;
 PERFORM identity_license_user_source_input(event.review);state=identity_license_user_source_state_json(actual);
 IF event.source_id<>actual.id OR event.tenant_id<>actual.tenant_id OR event.issuer<>actual.issuer OR event.client_id<>actual.client_id
  OR event.client_revision<>actual.client_revision OR event.source_version<>actual.version OR event.enabled<>actual.enabled OR event.created_at<>actual.changed_at
  OR event.after_state IS DISTINCT FROM state OR event.type<>'license-user-source.changed' OR event.version<>1 OR event.correlation_id<>event.id
  OR event.actor IS DISTINCT FROM jsonb_build_object('kind','offline-license-user-source','databaseRole',event.operator)
  OR event.review IS DISTINCT FROM jsonb_build_object('issuer',actual.issuer,'clientId',actual.client_id,'tenantId',actual.tenant_id,'clientRevision',actual.client_revision::text,
   'expectedVersion',(actual.version-1)::text,'enabled',actual.enabled,'reason',event.review->>'reason')
  OR NOT isfinite(event.created_at) OR NOT EXISTS(SELECT 1 FROM identity_tenants WHERE id=actual.tenant_id)
  OR NOT EXISTS(SELECT 1 FROM identity_license_user_source_outbox WHERE id=event.id AND tenant_id=event.tenant_id AND status='pending'
   AND type=event.type AND version=event.version AND correlation_id=event.correlation_id AND created_at=event.created_at AND payload=identity_license_user_source_event_json(event))
  OR EXISTS(SELECT 1 FROM identity_license_user_source_events WHERE source_id=actual.id AND source_version>actual.version) THEN RETURN false;END IF;
 IF actual.version=1 THEN RETURN event.before_state IS NULL;END IF;
 SELECT * INTO previous FROM identity_license_user_source_events WHERE source_id=actual.id AND source_version=actual.version-1;
 RETURN previous.id IS NOT NULL AND event.before_state IS NOT DISTINCT FROM previous.after_state
  AND event.before_state-ARRAY['client_revision','version','enabled','changed_at','event_id'] IS NOT DISTINCT FROM state-ARRAY['client_revision','version','enabled','changed_at','event_id']
  AND event.before_state->>'event_id'=previous.id::text AND event.before_state->>'version'=(actual.version-1)::text
  AND (event.before_state->>'client_revision')::bigint<=actual.client_revision
  AND EXISTS(SELECT 1 FROM identity_license_user_source_outbox WHERE id=previous.id AND tenant_id=previous.tenant_id AND status='pending' AND payload=identity_license_user_source_event_json(previous));
EXCEPTION WHEN OTHERS THEN RETURN false;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_fence() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event identity_license_user_source_events;
BEGIN
 SELECT * INTO event FROM identity_license_user_source_events WHERE transaction_id=txid_current();
 IF event.id IS NOT NULL OR NULLIF(current_setting('opendirectory.license_user_source',true),'') IS NOT NULL THEN
  IF TG_OP='TRUNCATE' OR TG_TABLE_NAME NOT IN('identity_license_user_sources','identity_license_user_source_events','identity_license_user_source_outbox')
   THEN RAISE EXCEPTION 'Only exact license user source effects allowed in this transaction' USING ERRCODE='42501';END IF;
 ELSIF TG_TABLE_NAME NOT IN('identity_license_user_sources','identity_license_user_source_events','identity_license_user_source_outbox') THEN
  PERFORM pg_advisory_xact_lock_shared(1948783475,1819501427);
 END IF;
 IF TG_OP='TRUNCATE' THEN RETURN NULL;END IF;IF TG_OP='DELETE' THEN RETURN OLD;ELSE RETURN NEW;END IF;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE scope JSONB;event identity_license_user_source_events;data JSONB;
BEGIN
 PERFORM identity_license_user_source_owner();
 IF TG_OP='TRUNCATE' THEN
  IF EXISTS(SELECT 1 FROM identity_license_user_sources) OR EXISTS(SELECT 1 FROM identity_license_user_source_events) OR EXISTS(SELECT 1 FROM identity_license_user_source_outbox)
   OR NULLIF(current_setting('opendirectory.license_user_source',true),'') IS NOT NULL THEN RAISE EXCEPTION 'License user source evidence cannot be truncated' USING ERRCODE='42501';END IF;RETURN NULL;
 END IF;
 scope=NULLIF(current_setting('opendirectory.license_user_source',true),'')::jsonb;
 IF scope IS NULL OR TG_OP='DELETE' OR TG_TABLE_NAME<>'identity_license_user_sources' AND TG_OP<>'INSERT'
  THEN RAISE EXCEPTION 'Original offline license user source command required; evidence is append only' USING ERRCODE='42501';END IF;
 SELECT * INTO event FROM identity_license_user_source_events WHERE transaction_id=txid_current();
 IF TG_TABLE_NAME='identity_license_user_source_events' THEN
  IF event.id IS NOT NULL OR identity_license_user_source_event_json(NEW) IS DISTINCT FROM scope OR NEW.transaction_id<>txid_current() OR NEW.operator<>session_user
   THEN RAISE EXCEPTION 'Single original offline license user source event required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF event.id IS NULL OR identity_license_user_source_event_json(event) IS DISTINCT FROM scope THEN RAISE EXCEPTION 'Retained original license user source event required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_license_user_sources' THEN
  IF identity_license_user_source_state_json(NEW) IS DISTINCT FROM event.after_state
   OR TG_OP='INSERT' AND event.before_state IS NOT NULL OR TG_OP='UPDATE' AND identity_license_user_source_state_json(OLD) IS DISTINCT FROM event.before_state
   THEN RAISE EXCEPTION 'Exact immutable tenant, issuer and client transition required' USING ERRCODE='23514';END IF;
 ELSE
  data=jsonb_build_object('id',event.id,'tenant_id',event.tenant_id,'status','pending','type',event.type,'version',event.version,'correlation_id',event.correlation_id,
   'created_at',event.created_at,'payload',identity_license_user_source_event_json(event));
  IF to_jsonb(NEW) IS DISTINCT FROM data THEN RAISE EXCEPTION 'Exact pending license user source outbox required' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event identity_license_user_source_events;binding identity_license_user_sources;
BEGIN
 PERFORM identity_license_user_source_owner();PERFORM identity_license_user_source_receiving();
 SELECT * INTO event FROM identity_license_user_source_events WHERE transaction_id=txid_current();
 SELECT * INTO binding FROM identity_license_user_sources WHERE id=event.source_id;
 IF event.id IS NULL OR event.operator<>session_user OR identity_license_user_source_event_json(event) IS DISTINCT FROM NULLIF(current_setting('opendirectory.license_user_source',true),'')::jsonb
  OR NOT identity_license_user_source_valid(binding) OR binding.id IS NULL
  THEN RAISE EXCEPTION 'Exact committed license user source row, event and pending outbox required' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION identity_license_user_source_change(review JSONB) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE before_row identity_license_user_sources;after_row identity_license_user_sources;event identity_license_user_source_events;
BEGIN
 PERFORM identity_license_user_source_owner();PERFORM identity_license_user_source_input(review);PERFORM identity_license_user_source_receiving();
 IF EXISTS(SELECT 1 FROM identity_license_user_source_events WHERE transaction_id=txid_current()) OR NULLIF(current_setting('opendirectory.license_user_source',true),'') IS NOT NULL
  OR EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND classid=1948783475::oid AND objid=1819501427::oid AND objsubid=2 AND mode='ShareLock' AND granted)
  THEN RAISE EXCEPTION 'One original offline source review without mixed canonical writes per transaction required' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('identity-license-user-source:'||(review->>'issuer')||chr(10)||(review->>'clientId'),0));
 PERFORM id FROM identity_tenants WHERE id=(review->>'tenantId')::uuid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Existing exact source tenant required' USING ERRCODE='23503';END IF;
 SELECT * INTO before_row FROM identity_license_user_sources WHERE issuer=review->>'issuer' AND client_id=review->>'clientId' FOR UPDATE;
 IF before_row.id IS NULL THEN
  IF review->>'expectedVersion'<>'0' THEN RAISE EXCEPTION 'Source creation requires expectedVersion zero' USING ERRCODE='40001';END IF;
  after_row.id=gen_random_uuid();after_row.issuer=review->>'issuer';after_row.client_id=review->>'clientId';after_row.tenant_id=(review->>'tenantId')::uuid;after_row.version=1;
 ELSE
  IF before_row.version::text IS DISTINCT FROM review->>'expectedVersion' THEN RAISE EXCEPTION 'Source version conflict' USING ERRCODE='40001';END IF;
  IF before_row.tenant_id::text IS DISTINCT FROM review->>'tenantId' OR (review->>'clientRevision')::bigint<before_row.client_revision
   THEN RAISE EXCEPTION 'Source tenant is immutable and client revision cannot decrease' USING ERRCODE='23514';END IF;
  IF NOT identity_license_user_source_valid(before_row) THEN RAISE EXCEPTION 'Existing source evidence is invalid' USING ERRCODE='23514';END IF;
  after_row=before_row;after_row.version=before_row.version+1;
 END IF;
 event.id=gen_random_uuid();event.source_id=after_row.id;event.tenant_id=after_row.tenant_id;event.issuer=after_row.issuer;event.client_id=after_row.client_id;
 event.client_revision=(review->>'clientRevision')::bigint;event.source_version=after_row.version;event.enabled=(review->>'enabled')::boolean;
 event.type='license-user-source.changed';event.version=1;event.correlation_id=event.id;event.operator=session_user;
 event.actor=jsonb_build_object('kind','offline-license-user-source','databaseRole',session_user);event.review=review;event.created_at=clock_timestamp();event.transaction_id=txid_current();
 after_row.client_revision=event.client_revision;after_row.enabled=event.enabled;after_row.changed_at=event.created_at;after_row.event_id=event.id;
 event.before_state=identity_license_user_source_state_json(before_row);event.after_state=identity_license_user_source_state_json(after_row);
 PERFORM set_config('opendirectory.license_user_source',identity_license_user_source_event_json(event)::text,true);
 INSERT INTO identity_license_user_source_events SELECT event.*;
 IF before_row.id IS NULL THEN INSERT INTO identity_license_user_sources SELECT after_row.*;
 ELSE UPDATE identity_license_user_sources SET client_revision=after_row.client_revision,version=after_row.version,enabled=after_row.enabled,changed_at=after_row.changed_at,event_id=after_row.event_id WHERE id=before_row.id;END IF;
 INSERT INTO identity_license_user_source_outbox VALUES(event.id,event.tenant_id,'pending',event.type,event.version,event.correlation_id,event.created_at,identity_license_user_source_event_json(event));
 RETURN event.id;
END; $$;
DO $$ DECLARE relation TEXT;hook RECORD;routine TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_license_user_sources','identity_license_user_source_events','identity_license_user_source_outbox'] LOOP
  FOR hook IN SELECT * FROM identity_license_user_source_hooks() LOOP
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',hook.trigger_name,relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION %s()',hook.trigger_name,relation,hook.routine);
   EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation);
   EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION %s()',regexp_replace(hook.trigger_name,'(_no_effects|_fence)$','_no_truncate'),relation,hook.routine);
  END LOOP;
  EXECUTE format('DROP TRIGGER IF EXISTS identity_license_user_source_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_license_user_source_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_license_user_source_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_license_user_source_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER identity_license_user_source_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_license_user_source_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_license_user_source_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_license_user_source_commit AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_license_user_source_commit()',relation);
  EXECUTE format('REVOKE ALL ON TABLE %I FROM PUBLIC',relation);
 END LOOP;
 FOR relation IN SELECT relname FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relkind IN('r','p') AND (left(relname,9)='identity_' OR relname IN('users','groups','group_members','ous')) LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_license_user_source_fence ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_license_user_source_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION identity_license_user_source_fence()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS aaa_identity_license_user_source_no_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER aaa_identity_license_user_source_no_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION identity_license_user_source_fence()',relation);
 END LOOP;
 FOREACH routine IN ARRAY ARRAY['identity_license_user_source_state_json(identity_license_user_sources)','identity_license_user_source_event_json(identity_license_user_source_events)',
  'identity_license_user_source_owner()','identity_license_user_source_input(jsonb)','identity_license_user_source_hooks()','identity_license_user_source_receiving()',
  'identity_license_user_source_valid(identity_license_user_sources)','identity_license_user_source_fence()','identity_license_user_source_guard()',
  'identity_license_user_source_commit()','identity_license_user_source_change(jsonb)'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',routine,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO ''UTC''',routine);EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',routine);
 END LOOP;
END; $$;
