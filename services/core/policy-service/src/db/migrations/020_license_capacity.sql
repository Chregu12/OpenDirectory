CREATE OR REPLACE FUNCTION license_capacity_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE TABLE IF NOT EXISTS license_capacity_sources (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),connector_id UUID NOT NULL REFERENCES license_provider_connectors(id),
 database_role NAME NOT NULL,graph_client_id UUID NOT NULL,enabled BOOLEAN NOT NULL DEFAULT false,version BIGINT NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS license_capacity_one_source ON license_capacity_sources(connector_id) WHERE enabled;
CREATE UNIQUE INDEX IF NOT EXISTS license_capacity_one_collector ON license_capacity_sources(database_role) WHERE enabled;
CREATE INDEX IF NOT EXISTS license_capacity_connector_sources ON license_capacity_sources(connector_id,id);
CREATE TABLE IF NOT EXISTS license_capacity_runs (
 id UUID PRIMARY KEY,run_number BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,source_id UUID NOT NULL REFERENCES license_capacity_sources(id),
 source_version BIGINT NOT NULL,connector_version BIGINT NOT NULL,status TEXT NOT NULL DEFAULT 'checking' CHECK(status IN('checking','complete','failed')),
 version INTEGER NOT NULL DEFAULT 1,started_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now(),finished_at TIMESTAMPTZ,
 valid_until TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now()+interval '300 seconds',payload JSONB,payload_hash TEXT,error TEXT,retry_after INTEGER NOT NULL DEFAULT 60
);
CREATE TABLE IF NOT EXISTS license_capacity_events (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),source_id UUID NOT NULL REFERENCES license_capacity_sources(id),run_id UUID REFERENCES license_capacity_runs(id),
 action TEXT NOT NULL,actor JSONB NOT NULL,details JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now()
);
CREATE INDEX IF NOT EXISTS license_capacity_latest ON license_capacity_runs(source_id,run_number DESC);
CREATE INDEX IF NOT EXISTS license_capacity_throttle ON license_capacity_runs(source_id,finished_at) WHERE error='graph_capacity_http_429';
CREATE TABLE IF NOT EXISTS license_capacity_outbox (
 id UUID PRIMARY KEY REFERENCES license_capacity_events(id),source_id UUID NOT NULL,run_id UUID,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT license_capacity_now()
);
CREATE OR REPLACE FUNCTION license_capacity_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Capacity evidence requires its actual transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE explanation TEXT;role_state RECORD;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Capacity source history is retained' USING ERRCODE='42501';END IF;
 explanation=NULLIF(current_setting('opendirectory.capacity_source_reason',true),'');
 IF explanation IS NULL OR length(btrim(explanation)) NOT BETWEEN 10 AND 500 THEN RAISE EXCEPTION 'Reviewed offline capacity-source reason required' USING ERRCODE='42501';END IF;
 SELECT rolsuper,rolcreaterole,rolcreatedb,rolbypassrls,EXISTS(SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) AS membership INTO role_state FROM pg_roles WHERE rolname=NEW.database_role;
 IF role_state IS NULL OR role_state.rolsuper OR role_state.rolcreaterole OR role_state.rolcreatedb OR role_state.rolbypassrls OR role_state.membership
  OR has_schema_privilege(NEW.database_role,current_schema(),'CREATE') OR has_database_privilege(NEW.database_role,current_database(),'CREATE') THEN RAISE EXCEPTION 'Dedicated nonadministrative collector identity required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.enabled THEN RAISE EXCEPTION 'Review a disabled source before explicit enablement' USING ERRCODE='23514';END IF;NEW.version=1;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['enabled','version']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['enabled','version']) OR NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'Capacity source binding is immutable and enablement conditional' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_source_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE event UUID;
BEGIN
 INSERT INTO license_capacity_events(source_id,action,actor,details) VALUES(NEW.id,'source-configured',jsonb_build_object('kind','offline-provisioner','databaseRole',session_user),
 jsonb_build_object('connectorId',NEW.connector_id,'graphClientId',NEW.graph_client_id,'databaseRole',NEW.database_role,'enabled',NEW.enabled,'version',NEW.version,'reason',current_setting('opendirectory.capacity_source_reason',true))) RETURNING id INTO event;
 INSERT INTO license_capacity_outbox(id,source_id,action) VALUES(event,NEW.id,'source-configured');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_source(identity UUID) RETURNS jsonb LANGUAGE sql SECURITY DEFINER STABLE AS $$
 SELECT jsonb_build_object('sourceId',source.id,'connectorId',connector.id,'tenantId',connector.tenant_id,'graphClientId',source.graph_client_id,
 'sourceVersion',source.version::text,'connectorVersion',connector.version::text,'sourceEnabled',source.enabled,'connectorEnabled',connector.enabled,
 'retryUntil',(SELECT max(run.finished_at+run.retry_after*interval '1 second') FROM license_capacity_runs run JOIN license_capacity_sources previous ON previous.id=run.source_id
  WHERE previous.connector_id=connector.id AND run.error='graph_capacity_http_429' AND run.finished_at+run.retry_after*interval '1 second'>license_capacity_now()))
 FROM license_capacity_sources source JOIN license_provider_connectors connector ON connector.id=source.connector_id
 WHERE source.id=identity AND source.database_role=session_user AND current_setting('role')='none';
$$;
CREATE OR REPLACE FUNCTION license_capacity_payload_valid(payload JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE item JSONB;units JSONB;field TEXT;seen TEXT[]='{}';
BEGIN
 IF payload IS NULL OR jsonb_typeof(payload)<>'array' OR jsonb_array_length(payload)>1000 OR octet_length(payload::text)>524288 THEN RETURN false;END IF;
 FOR item IN SELECT * FROM jsonb_array_elements(payload) LOOP
  IF jsonb_typeof(item)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>6
   OR NOT COALESCE(item->>'skuId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) OR item->>'skuId'=ANY(seen)
   OR NOT COALESCE(jsonb_typeof(item->'skuPartNumber')='string' AND length(item->>'skuPartNumber') BETWEEN 1 AND 255,false)
   OR NOT COALESCE(item->>'appliesTo' IN('User','Company'),false) OR NOT COALESCE(item->>'capabilityStatus' IN('Enabled','Warning','Suspended','Deleted','LockedOut'),false)
   OR NOT COALESCE(item->>'consumedUnits' ~ '^(0|[1-9][0-9]{0,9})$',false) OR (item->>'consumedUnits')::numeric>2147483647 THEN RETURN false;END IF;
  seen=array_append(seen,item->>'skuId');units=item->'prepaidUnits';
  IF jsonb_typeof(units) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(units))<>4 THEN RETURN false;END IF;
  FOREACH field IN ARRAY ARRAY['enabled','warning','suspended','lockedOut'] LOOP
   IF NOT COALESCE(units->>field ~ '^(0|[1-9][0-9]{0,9})$',false) OR (units->>field)::numeric>2147483647 OR jsonb_typeof(units->field)<>'number' THEN RETURN false;END IF;
  END LOOP;
  IF jsonb_typeof(item->'consumedUnits')<>'number' THEN RETURN false;END IF;
 END LOOP;RETURN true;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_run_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE source license_capacity_sources%ROWTYPE;connector license_provider_connectors%ROWTYPE;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Capacity runs are retained' USING ERRCODE='42501';END IF;
 SELECT * INTO source FROM license_capacity_sources WHERE id=NEW.source_id FOR UPDATE;
 SELECT * INTO connector FROM license_provider_connectors WHERE id=source.connector_id FOR SHARE;
 IF source.id IS NULL OR source.database_role<>session_user OR current_setting('role')<>'none' THEN RAISE EXCEPTION 'Actual bound collector identity required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF NOT source.enabled OR NOT connector.enabled OR NEW.source_version<>source.version OR NEW.connector_version<>connector.version OR NEW.status<>'checking'
   OR NEW.payload IS NOT NULL OR NEW.error IS NOT NULL OR NEW.finished_at IS NOT NULL OR NEW.payload_hash IS NOT NULL THEN RAISE EXCEPTION 'Current explicit capacity source required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM license_capacity_runs run JOIN license_capacity_sources previous ON previous.id=run.source_id WHERE previous.connector_id=connector.id
   AND run.error='graph_capacity_http_429' AND run.finished_at+run.retry_after*interval '1 second'>license_capacity_now()) THEN RAISE EXCEPTION 'Connector capacity throttle remains active' USING ERRCODE='23514';END IF;
  NEW.started_at=license_capacity_now();NEW.valid_until=NEW.started_at+interval '300 seconds';NEW.version=1;NEW.retry_after=60;
 ELSE
  IF OLD.status<>'checking' OR NEW.status NOT IN('complete','failed') OR (to_jsonb(NEW)-ARRAY['status','payload','error','retry_after']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','payload','error','retry_after'])
   THEN RAISE EXCEPTION 'One original capacity result required' USING ERRCODE='23514';END IF;
  IF NEW.status='complete' THEN
   IF NOT source.enabled OR NOT connector.enabled OR source.version<>OLD.source_version OR connector.version<>OLD.connector_version
    OR OLD.started_at+interval '30 seconds'<=license_capacity_now() OR NOT license_capacity_payload_valid(NEW.payload) OR NEW.error IS NOT NULL THEN RAISE EXCEPTION 'Complete bounded current capacity observation required' USING ERRCODE='23514';END IF;
   NEW.payload_hash=encode(sha256(convert_to(NEW.payload::text,'UTF8')),'hex');NEW.retry_after=60;
  ELSE
   IF NEW.payload IS NOT NULL OR NEW.error IS NULL OR NEW.error!~'^[a-z][a-z0-9_]{0,99}$' OR NEW.retry_after NOT BETWEEN 60 AND 3600 THEN RAISE EXCEPTION 'Bounded explicit observation failure required' USING ERRCODE='23514';END IF;
  END IF;
  NEW.finished_at=license_capacity_now();NEW.version=2;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_run_changed() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE event UUID;
BEGIN
 INSERT INTO license_capacity_events(source_id,run_id,action,actor,details) VALUES(NEW.source_id,NEW.id,NEW.status,jsonb_build_object('kind','capacity-collector','databaseRole',session_user),
 jsonb_build_object('sourceVersion',NEW.source_version::text,'connectorVersion',NEW.connector_version::text,'validUntil',NEW.valid_until,'payloadHash',NEW.payload_hash,'error',NEW.error)) RETURNING id INTO event;
 INSERT INTO license_capacity_outbox(id,source_id,run_id,action) VALUES(event,NEW.source_id,NEW.id,NEW.status);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION license_capacity_commit_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF NEW.status='complete' AND (NEW.started_at+interval '30 seconds'<=license_capacity_now() OR NOT EXISTS(SELECT 1 FROM license_capacity_sources source JOIN license_provider_connectors connector ON connector.id=source.connector_id
  WHERE source.id=NEW.source_id AND source.enabled AND connector.enabled AND source.version=NEW.source_version AND connector.version=NEW.connector_version))
  THEN RAISE EXCEPTION 'Capacity observation admission expired or changed' USING ERRCODE='23514';END IF;RETURN NULL;
END; $$;
DROP TRIGGER IF EXISTS license_capacity_source_guard ON license_capacity_sources;
CREATE TRIGGER license_capacity_source_guard BEFORE INSERT OR UPDATE OR DELETE ON license_capacity_sources FOR EACH ROW EXECUTE FUNCTION license_capacity_source_guard();
DROP TRIGGER IF EXISTS license_capacity_source_changed ON license_capacity_sources;
CREATE TRIGGER license_capacity_source_changed AFTER INSERT OR UPDATE ON license_capacity_sources FOR EACH ROW EXECUTE FUNCTION license_capacity_source_changed();
DROP TRIGGER IF EXISTS license_capacity_run_guard ON license_capacity_runs;
CREATE TRIGGER license_capacity_run_guard BEFORE INSERT OR UPDATE OR DELETE ON license_capacity_runs FOR EACH ROW EXECUTE FUNCTION license_capacity_run_guard();
DROP TRIGGER IF EXISTS license_capacity_run_changed ON license_capacity_runs;
CREATE TRIGGER license_capacity_run_changed AFTER INSERT OR UPDATE ON license_capacity_runs FOR EACH ROW EXECUTE FUNCTION license_capacity_run_changed();
DROP TRIGGER IF EXISTS license_capacity_commit_guard ON license_capacity_runs;
CREATE CONSTRAINT TRIGGER license_capacity_commit_guard AFTER INSERT OR UPDATE ON license_capacity_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION license_capacity_commit_guard();
ALTER TABLE license_capacity_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE license_capacity_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS license_capacity_own_source ON license_capacity_sources;
CREATE POLICY license_capacity_own_source ON license_capacity_sources FOR SELECT USING(database_role=current_user);
DROP POLICY IF EXISTS license_capacity_own_runs ON license_capacity_runs;
CREATE POLICY license_capacity_own_runs ON license_capacity_runs USING(EXISTS(SELECT 1 FROM license_capacity_sources source WHERE source.id=source_id AND source.database_role=current_user)) WITH CHECK(EXISTS(SELECT 1 FROM license_capacity_sources source WHERE source.id=source_id AND source.database_role=current_user));
DO $$ DECLARE table_name TEXT;function_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['license_capacity_events','license_capacity_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS license_capacity_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER license_capacity_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION license_capacity_evidence_guard()',table_name);
 END LOOP;
 FOREACH function_name IN ARRAY ARRAY['license_capacity_source(uuid)','license_capacity_run_guard()','license_capacity_run_changed()','license_capacity_commit_guard()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path=%I,pg_catalog,pg_temp',function_name,current_schema());EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',function_name);
 END LOOP;
END; $$;
