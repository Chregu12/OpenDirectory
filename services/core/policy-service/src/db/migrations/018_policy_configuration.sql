CREATE OR REPLACE FUNCTION policy_configuration_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE blueprints ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);
CREATE TABLE IF NOT EXISTS policy_configuration_origins (
 resource_kind TEXT NOT NULL CHECK(resource_kind IN('policy','blueprint')),resource_id UUID NOT NULL,observed_version INTEGER NOT NULL CHECK(observed_version>0),
 origin TEXT NOT NULL CHECK(origin IN('legacy-observed','created')),observed_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),PRIMARY KEY(resource_kind,resource_id)
);
INSERT INTO policy_configuration_origins(resource_kind,resource_id,observed_version,origin)
 SELECT 'policy',id,version,'legacy-observed' FROM policies WHERE NOT EXISTS(SELECT 1 FROM policy_configuration_origins WHERE resource_kind='policy' AND resource_id=policies.id);
INSERT INTO policy_configuration_origins(resource_kind,resource_id,observed_version,origin)
 SELECT 'blueprint',id,version,'legacy-observed' FROM blueprints WHERE NOT EXISTS(SELECT 1 FROM policy_configuration_origins WHERE resource_kind='blueprint' AND resource_id=blueprints.id);
CREATE TABLE IF NOT EXISTS policy_configuration_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),resource_kind TEXT NOT NULL,resource_id UUID NOT NULL,version INTEGER NOT NULL CHECK(version>0),action TEXT NOT NULL,
 actor JSONB NOT NULL,reason TEXT NOT NULL CHECK(length(reason) BETWEEN 10 AND 500),previous JSONB,current JSONB,scope JSONB,created_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),
 UNIQUE(resource_kind,resource_id,version)
);
CREATE TABLE IF NOT EXISTS policy_configuration_outbox (
 id UUID PRIMARY KEY REFERENCES policy_configuration_audit(id),resource_kind TEXT NOT NULL,resource_id UUID NOT NULL,version INTEGER NOT NULL,action TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT policy_configuration_now(),UNIQUE(resource_kind,resource_id,version)
);
CREATE OR REPLACE FUNCTION policy_configuration_fresh(proof JSONB) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(jsonb_typeof(proof)='object' AND proof->>'permission' IN('policies.manage','policies.deploy') AND proof->'acknowledgeScope'='true'::jsonb
  AND proof->>'resourceKind' IN('policy','blueprint') AND proof->>'expectedVersion' ~ '^(0|[1-9][0-9]{0,9})$'
  AND proof->>'action' IN('created','updated','deleted','activated','deactivated','assigned','linked','unlinked','configuration_added','configuration_removed')
  AND length(proof->>'reason') BETWEEN 10 AND 500 AND proof->'actor'->>'userId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
  AND length(proof->'actor'->>'issuer') BETWEEN 1 AND 2048 AND length(proof->'actor'->>'subject') BETWEEN 1 AND 255
  AND length(proof->'actor'->>'clientId') BETWEEN 1 AND 255 AND length(proof->'actor'->>'tokenId') BETWEEN 1 AND 255
  AND proof->'actor'->>'expiresAt' ~ '^[0-9]{1,12}$' AND (proof->'actor'->>'expiresAt')::numeric>floor(EXTRACT(epoch FROM policy_configuration_now()))
  AND proof->'actor'->>'rolesRevision' ~ '^[a-f0-9]{64}$' AND proof->'actor'->>'revision' ~ '^[1-9][0-9]{0,18}$'
  AND proof->'actor'->>'linkRevision' ~ '^[1-9][0-9]{0,18}$' AND proof->'actor'->>'mfaRevision' ~ '^[1-9][0-9]{0,18}$'
  AND proof->'actor'->>'authTime' ~ '^[0-9]{1,12}$' AND (proof->'actor'->>'authTime')::numeric
   BETWEEN floor(EXTRACT(epoch FROM policy_configuration_now()))-300 AND floor(EXTRACT(epoch FROM policy_configuration_now()))+5,false);
$$;
CREATE OR REPLACE FUNCTION policy_configuration_summary(row_data JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN row_data IS NULL THEN NULL ELSE jsonb_build_object('version',row_data->'version','status',row_data->'status',
  'contentHash',encode(sha256(convert_to((row_data-ARRAY['id','version','created_at','updated_at','activated_at','created_by','status'])::text,'UTF8')),'hex')) END;
$$;
CREATE OR REPLACE FUNCTION policy_configuration_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;kind TEXT;identity UUID;current_version INTEGER;action TEXT;permission TEXT;child_state JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;
 kind=CASE WHEN TG_TABLE_NAME='policies' THEN 'policy' ELSE 'blueprint' END;
 IF NOT policy_configuration_fresh(proof) THEN RAISE EXCEPTION 'Current fresh canonical policy authority required' USING ERRCODE='42501';END IF;
 identity=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;action=proof->>'action';permission=proof->>'permission';
 IF proof->>'resourceKind' IS DISTINCT FROM kind THEN RAISE EXCEPTION 'Exact policy resource kind required' USING ERRCODE='42501';END IF;
 IF TG_OP='INSERT' THEN
  IF action<>'created' OR permission<>'policies.manage' OR proof->>'expectedVersion'<>'0' OR proof->>'resourceId' IS NOT NULL
   OR NEW.version<>1 OR NEW.created_by IS DISTINCT FROM proof->'actor'->>'userId'
   OR EXISTS(SELECT 1 FROM policy_configuration_origins WHERE resource_kind=kind AND resource_id=identity)
   THEN RAISE EXCEPTION 'New immutable policy origin required' USING ERRCODE='23514';END IF;
  IF kind='policy' AND to_jsonb(NEW)->>'status'<>'draft' THEN RAISE EXCEPTION 'Explicit draft creation required' USING ERRCODE='23514';END IF;
  NEW.created_at=date_trunc('milliseconds',policy_configuration_now());NEW.updated_at=NEW.created_at;
  proof=jsonb_set(proof,'{resourceId}',to_jsonb(identity::text));PERFORM set_config('opendirectory.policy_configuration',proof::text,true);
 ELSE
  IF proof->>'resourceId' IS DISTINCT FROM identity::text OR proof->>'expectedVersion' IS DISTINCT FROM OLD.version::text
   THEN RAISE EXCEPTION 'Exact policy version required' USING ERRCODE='23514',CONSTRAINT='policy_configuration_version';END IF;
  IF OLD.version>=2147483647 THEN RAISE EXCEPTION 'Policy version exhausted' USING ERRCODE='23514';END IF;
  IF TG_OP='DELETE' THEN
   IF action<>'deleted' OR permission<>'policies.manage' THEN RAISE EXCEPTION 'Policy deletion duty required' USING ERRCODE='42501';END IF;
   IF kind='policy' THEN
    SELECT jsonb_build_object('assignments',COALESCE((SELECT jsonb_agg(to_jsonb(assignment)) FROM policy_assignments assignment WHERE policy_id=identity),'[]'::jsonb),
      'links',COALESCE((SELECT jsonb_agg(to_jsonb(link)) FROM policy_links link WHERE policy_id=identity),'[]'::jsonb)) INTO child_state;
   ELSE
    SELECT jsonb_build_object('assignments',COALESCE((SELECT jsonb_agg(to_jsonb(assignment)) FROM blueprint_assignments assignment WHERE blueprint_id=identity),'[]'::jsonb),
      'configurations',COALESCE((SELECT jsonb_agg(jsonb_build_object('id',configuration.id,'configType',configuration.config_type,'contentHash',encode(sha256(convert_to(configuration.payload::text,'UTF8')),'hex'))) FROM blueprint_configurations configuration WHERE blueprint_id=identity),'[]'::jsonb)) INTO child_state;
   END IF;
   PERFORM set_config('opendirectory.policy_scope',child_state::text,true);RETURN OLD;
  END IF;
  IF NEW.id<>OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.created_by IS DISTINCT FROM OLD.created_by
   OR NEW.version NOT IN(OLD.version,OLD.version+1) THEN RAISE EXCEPTION 'Policy identity and lineage are immutable' USING ERRCODE='23514';END IF;
  IF action='updated' THEN
   IF permission<>'policies.manage' OR kind='policy' AND (to_jsonb(NEW)->'status' IS DISTINCT FROM to_jsonb(OLD)->'status'
    OR to_jsonb(NEW)->'type' IS DISTINCT FROM to_jsonb(OLD)->'type' OR to_jsonb(NEW)->'activated_at' IS DISTINCT FROM to_jsonb(OLD)->'activated_at')
    THEN RAISE EXCEPTION 'Configuration cannot replace policy deployment or type' USING ERRCODE='42501';END IF;
  ELSIF action IN('activated','deactivated') THEN
   IF kind<>'policy' OR permission<>'policies.deploy' OR (to_jsonb(NEW)-ARRAY['version','updated_at','activated_at','status']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','updated_at','activated_at','status'])
    OR to_jsonb(NEW)->>'status' IS DISTINCT FROM (CASE WHEN action='activated' THEN 'active' ELSE 'inactive' END)
    THEN RAISE EXCEPTION 'Exact policy status transition required' USING ERRCODE='42501';END IF;
  ELSIF action IN('assigned','linked','unlinked','configuration_added','configuration_removed') THEN
   IF pg_trigger_depth()<2 OR NULLIF(current_setting('opendirectory.policy_scope',true),'') IS NULL
    OR permission<>(CASE WHEN action IN('configuration_added','configuration_removed') THEN 'policies.manage' ELSE 'policies.deploy' END)
    OR (to_jsonb(NEW)-ARRAY['version','updated_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','updated_at'])
    THEN RAISE EXCEPTION 'Original child transition required' USING ERRCODE='42501';END IF;
  ELSE RAISE EXCEPTION 'Known policy transition required' USING ERRCODE='42501';END IF;
  NEW.version=OLD.version+1;NEW.updated_at=date_trunc('milliseconds',policy_configuration_now());
 END IF;
 IF length(NEW.name) NOT BETWEEN 1 AND 255 OR NEW.platform NOT IN('windows','macos','linux','all') OR octet_length(to_jsonb(NEW)::text)>1048576
  OR kind='policy' AND (jsonb_typeof(to_jsonb(NEW)->'settings')<>'object' OR jsonb_typeof(to_jsonb(NEW)->'rules')<>'array' OR to_jsonb(NEW)->>'status' NOT IN('draft','active','inactive','archived'))
  THEN RAISE EXCEPTION 'Bounded canonical policy configuration required' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;kind TEXT;identity UUID;next_version INTEGER;event UUID;previous_row JSONB;current_row JSONB;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;kind=proof->>'resourceKind';
 IF TG_OP='INSERT' THEN INSERT INTO policy_configuration_origins(resource_kind,resource_id,observed_version,origin) VALUES(kind,NEW.id,NEW.version,'created');END IF;
 previous_row=CASE WHEN TG_OP='INSERT' THEN NULL ELSE to_jsonb(OLD) END;current_row=CASE WHEN TG_OP='DELETE' THEN NULL ELSE to_jsonb(NEW) END;
 identity=CASE WHEN TG_OP='DELETE' THEN OLD.id ELSE NEW.id END;next_version=CASE WHEN TG_OP='DELETE' THEN OLD.version+1 ELSE NEW.version END;
 INSERT INTO policy_configuration_audit(resource_kind,resource_id,version,action,actor,reason,previous,current,scope)
  VALUES(kind,identity,next_version,proof->>'action',proof->'actor',proof->>'reason',policy_configuration_summary(previous_row),policy_configuration_summary(current_row),NULLIF(current_setting('opendirectory.policy_scope',true),'')::jsonb) RETURNING id INTO event;
 INSERT INTO policy_configuration_outbox(id,resource_kind,resource_id,version,action) VALUES(event,kind,identity,next_version,proof->>'action');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_child_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;kind TEXT;identity UUID;parent_version INTEGER;expected_action TEXT;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;
 kind=CASE WHEN TG_TABLE_NAME IN('policy_links','policy_assignments') THEN 'policy' ELSE 'blueprint' END;
 identity=CASE WHEN kind='policy' THEN CASE WHEN TG_OP='DELETE' THEN (to_jsonb(OLD)->>'policy_id')::uuid ELSE (to_jsonb(NEW)->>'policy_id')::uuid END
  ELSE CASE WHEN TG_OP='DELETE' THEN (to_jsonb(OLD)->>'blueprint_id')::uuid ELSE (to_jsonb(NEW)->>'blueprint_id')::uuid END END;
 IF TG_OP='DELETE' AND pg_trigger_depth()>1 AND proof->>'action'='deleted' AND proof->>'resourceKind'=kind AND proof->>'resourceId'=identity::text THEN RETURN OLD;END IF;
 IF NOT policy_configuration_fresh(proof) OR TG_OP='UPDATE' OR proof->>'resourceKind' IS DISTINCT FROM kind OR proof->>'resourceId' IS DISTINCT FROM identity::text
  THEN RAISE EXCEPTION 'Original versioned policy child operation required' USING ERRCODE='42501';END IF;
 IF kind='policy' THEN SELECT version INTO parent_version FROM policies WHERE id=identity FOR UPDATE;ELSE SELECT version INTO parent_version FROM blueprints WHERE id=identity FOR UPDATE;END IF;
 IF parent_version IS NULL OR proof->>'expectedVersion' IS DISTINCT FROM parent_version::text THEN RAISE EXCEPTION 'Exact parent version required' USING ERRCODE='23514',CONSTRAINT='policy_configuration_version';END IF;
 expected_action=CASE WHEN TG_TABLE_NAME='blueprint_configurations' THEN CASE WHEN TG_OP='INSERT' THEN 'configuration_added' ELSE 'configuration_removed' END
  WHEN TG_TABLE_NAME='policy_links' THEN CASE WHEN TG_OP='INSERT' THEN 'linked' ELSE 'unlinked' END ELSE 'assigned' END;
 IF proof->>'action' IS DISTINCT FROM expected_action OR TG_OP='DELETE' AND TG_TABLE_NAME IN('policy_assignments','blueprint_assignments')
  OR proof->>'permission' IS DISTINCT FROM (CASE WHEN TG_TABLE_NAME='blueprint_configurations' THEN 'policies.manage' ELSE 'policies.deploy' END)
  THEN RAISE EXCEPTION 'Exact policy child duty required' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 IF TG_TABLE_NAME='blueprint_configurations' THEN
  IF jsonb_typeof(NEW.payload)<>'object' OR octet_length(NEW.payload::text)>262144 OR length(NEW.config_name) NOT BETWEEN 1 AND 255
   OR NEW.config_type NOT IN('wifi','vpn','filevault','gatekeeper','software_update','screen_lock','certificate','webfilter','airdrop') THEN RAISE EXCEPTION 'Bounded blueprint configuration required' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_TABLE_NAME<>'blueprint_configurations' THEN
  IF NEW.target_type NOT IN('device','group','ou','site','domain') OR length(NEW.target_id) NOT BETWEEN 1 AND 255 THEN RAISE EXCEPTION 'Exact deployment target required' USING ERRCODE='23514';END IF;
  IF TG_TABLE_NAME='blueprint_assignments' AND NEW.target_type NOT IN('device','group') THEN RAISE EXCEPTION 'Exact blueprint target required' USING ERRCODE='23514';END IF;
  IF TG_TABLE_NAME='policy_assignments' AND EXISTS(SELECT 1 FROM policy_assignments WHERE policy_id=identity AND target_type=NEW.target_type AND target_id=NEW.target_id) THEN RAISE EXCEPTION 'Policy target is already configured' USING ERRCODE='23505';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_child_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;scope_row JSONB;identity UUID;
BEGIN
 proof=NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb;IF proof->>'action'='deleted' THEN RETURN NULL;END IF;
 scope_row=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 IF TG_TABLE_NAME='blueprint_configurations' THEN scope_row=(scope_row-'payload')||jsonb_build_object('contentHash',encode(sha256(convert_to((scope_row->'payload')::text,'UTF8')),'hex'));END IF;
 PERFORM set_config('opendirectory.policy_scope',jsonb_build_object('table',TG_TABLE_NAME,'operation',TG_OP,'record',scope_row)::text,true);
 identity=(proof->>'resourceId')::uuid;
 IF proof->>'resourceKind'='policy' THEN UPDATE policies SET version=version+1 WHERE id=identity;ELSE UPDATE blueprints SET version=version+1 WHERE id=identity;END IF;
 PERFORM set_config('opendirectory.policy_scope','',true);RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb->'actor'->>'expiresAt')::numeric<=floor(EXTRACT(epoch FROM policy_configuration_now()))
  THEN RAISE EXCEPTION 'Original policy token expired before commit' USING ERRCODE='23514',CONSTRAINT='policy_configuration_token_expired';END IF;
 IF NOT policy_configuration_fresh(NULLIF(current_setting('opendirectory.policy_configuration',true),'')::jsonb)
  THEN RAISE EXCEPTION 'Policy authority expired before commit' USING ERRCODE='23514',CONSTRAINT='policy_configuration_lease';END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Policy evidence requires its actual resource transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_configuration_legacy_audit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Legacy policy audit is retained, not a new authority' USING ERRCODE='42501';END; $$;
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['policies','blueprints'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_changed AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_changed()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_commit_guard ON %I',table_name);
  EXECUTE format('CREATE CONSTRAINT TRIGGER policy_configuration_commit_guard AFTER INSERT OR UPDATE OR DELETE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION policy_configuration_commit_guard()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['policy_links','policy_assignments','blueprint_configurations','blueprint_assignments'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_child_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_child_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_child_guard()',table_name);
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_child_changed ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_child_changed AFTER INSERT OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_child_changed()',table_name);
 END LOOP;
 FOREACH table_name IN ARRAY ARRAY['policy_configuration_origins','policy_configuration_audit','policy_configuration_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_configuration_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_configuration_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_configuration_evidence_guard()',table_name);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS policy_configuration_legacy_audit_guard ON policy_audit_log;
CREATE TRIGGER policy_configuration_legacy_audit_guard BEFORE INSERT OR UPDATE OR DELETE ON policy_audit_log FOR EACH ROW EXECUTE FUNCTION policy_configuration_legacy_audit_guard();
