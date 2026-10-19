BEGIN;
CREATE OR REPLACE FUNCTION policy_device_now() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp(); $$;
CREATE OR REPLACE FUNCTION policy_device_schema_version() RETURNS integer LANGUAGE sql IMMUTABLE AS $$ SELECT 1; $$;
CREATE SEQUENCE IF NOT EXISTS policy_device_generation_seq;
ALTER TABLE enrolled_devices ADD COLUMN IF NOT EXISTS policy_generation BIGINT NOT NULL DEFAULT nextval('policy_device_generation_seq');
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_context JSONB;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_actor JSONB;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_operation_id UUID;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_item_key TEXT;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_generation BIGINT;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_version INTEGER;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_admission_until TIMESTAMPTZ;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_delivery_until TIMESTAMPTZ;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_dispatched_at TIMESTAMPTZ;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_delivery_actor JSONB;
ALTER TABLE mdm_commands ADD COLUMN IF NOT EXISTS policy_report_actor JSONB;
CREATE UNIQUE INDEX IF NOT EXISTS policy_device_command_once ON mdm_commands(policy_operation_id,device_id,policy_item_key) WHERE command='update_policy' AND policy_context IS NOT NULL;
CREATE TABLE IF NOT EXISTS policy_device_operations (
 id UUID PRIMARY KEY,actor JSONB NOT NULL,scope JSONB NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT policy_device_now()
);
CREATE TABLE IF NOT EXISTS policy_device_command_audit (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),command_id VARCHAR(255) NOT NULL REFERENCES mdm_commands(id),version INTEGER NOT NULL,
 operation_id UUID NOT NULL REFERENCES policy_device_operations(id),device_id VARCHAR(255) NOT NULL,device_generation BIGINT NOT NULL,
 action TEXT NOT NULL CHECK(action IN('queued','dispatched','reported')),actor JSONB NOT NULL,evidence JSONB NOT NULL,
 previous_state TEXT,current_state TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT policy_device_now(),UNIQUE(command_id,version)
);
CREATE TABLE IF NOT EXISTS policy_device_command_outbox (
 id UUID PRIMARY KEY REFERENCES policy_device_command_audit(id),command_id VARCHAR(255) NOT NULL,version INTEGER NOT NULL,action TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT policy_device_now(),UNIQUE(command_id,version)
);
CREATE OR REPLACE FUNCTION policy_device_enrollment_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='INSERT' THEN NEW.policy_generation=nextval('policy_device_generation_seq');
 ELSE
  IF NEW.id IS DISTINCT FROM OLD.id THEN RAISE EXCEPTION 'Device identity is immutable' USING ERRCODE='23514';END IF;
  IF NEW.platform IS DISTINCT FROM OLD.platform OR NEW.token IS DISTINCT FROM OLD.token OR NEW.status IS DISTINCT FROM OLD.status THEN NEW.policy_generation=nextval('policy_device_generation_seq');
  ELSE NEW.policy_generation=OLD.policy_generation;END IF;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_user_fresh(actor JSONB) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(actor->>'kind'='user' AND actor->>'userId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
 AND length(actor->>'issuer') BETWEEN 1 AND 2048 AND length(actor->>'subject') BETWEEN 1 AND 255
 AND length(actor->>'clientId') BETWEEN 1 AND 255 AND length(actor->>'tokenId') BETWEEN 1 AND 255 AND actor->>'tokenHash' ~ '^[a-f0-9]{64}$'
 AND actor->>'revision' ~ '^[1-9][0-9]{0,18}$' AND actor->>'linkRevision' ~ '^[1-9][0-9]{0,18}$' AND actor->>'rolesRevision' ~ '^[a-f0-9]{64}$'
 AND actor->>'mfaRevision' ~ '^[1-9][0-9]{0,18}$' AND actor->>'expiresAt' ~ '^[0-9]{1,12}$'
 AND (actor->>'expiresAt')::numeric>floor(EXTRACT(epoch FROM policy_device_now())) AND actor->>'authTime' ~ '^[0-9]{1,12}$'
 AND (actor->>'authTime')::numeric BETWEEN floor(EXTRACT(epoch FROM policy_device_now()))-300 AND floor(EXTRACT(epoch FROM policy_device_now()))+5,false);
$$;
CREATE OR REPLACE FUNCTION policy_device_agent_fresh(actor JSONB,identity TEXT,generation BIGINT) RETURNS boolean LANGUAGE sql VOLATILE AS $$
 SELECT COALESCE(actor->>'kind'='device' AND actor->>'deviceId'=identity AND actor->>'generation'=generation::text
 AND actor->>'platform' IN('windows','macos','linux') AND length(actor->>'issuer') BETWEEN 1 AND 2048
 AND length(actor->>'tokenId') BETWEEN 1 AND 255 AND actor->>'tokenHash' ~ '^[a-f0-9]{64}$' AND actor->>'expiresAt' ~ '^[0-9]{1,12}$'
 AND (actor->>'expiresAt')::numeric>floor(EXTRACT(epoch FROM policy_device_now())),false);
$$;
CREATE OR REPLACE FUNCTION policy_device_command_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;frame JSONB;actor JSONB;device enrolled_devices%ROWTYPE;reference JSONB;observed TIMESTAMPTZ;
BEGIN
 IF TG_OP='DELETE' THEN IF OLD.command='update_policy' THEN RAISE EXCEPTION 'Policy command history is retained' USING ERRCODE='42501';END IF;RETURN OLD;END IF;
 IF TG_OP='UPDATE' AND (NEW.id<>OLD.id OR NEW.device_id<>OLD.device_id OR NEW.command<>OLD.command) THEN RAISE EXCEPTION 'Command identity and kind are immutable' USING ERRCODE='23514';END IF;
 IF NEW.command<>'update_policy' THEN
  IF NEW.policy_context IS NOT NULL OR NEW.policy_actor IS NOT NULL OR NEW.policy_operation_id IS NOT NULL OR NEW.policy_generation IS NOT NULL
   OR NEW.policy_version IS NOT NULL OR NEW.policy_item_key IS NOT NULL OR NEW.policy_admission_until IS NOT NULL OR NEW.policy_delivery_until IS NOT NULL
   OR NEW.policy_dispatched_at IS NOT NULL OR NEW.policy_delivery_actor IS NOT NULL OR NEW.policy_report_actor IS NOT NULL
   THEN RAISE EXCEPTION 'Only an approved policy command carries policy evidence' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 proof=NULLIF(current_setting('opendirectory.policy_device_command',true),'')::jsonb;actor=proof->'actor';
 SELECT * INTO device FROM enrolled_devices WHERE id=NEW.device_id FOR UPDATE;
 IF device.id IS NULL OR NOT COALESCE(device.status IN('active','flagged','quarantined'),false) THEN RAISE EXCEPTION 'Current enrolled device required' USING ERRCODE='23514',CONSTRAINT='policy_device_binding';END IF;
 IF TG_OP='INSERT' THEN
  frame=proof->'frame';reference=frame->'reference';
  IF proof->>'action' IS DISTINCT FROM 'queued' OR NOT policy_device_user_fresh(actor) OR proof->>'generation' IS DISTINCT FROM device.policy_generation::text
   OR frame->'schemaVersion'<>'1'::jsonb OR frame->>'deviceId' IS DISTINCT FROM NEW.device_id OR frame->>'platform' IS DISTINCT FROM device.platform
   OR frame->>'operatorUserId' IS DISTINCT FROM actor->>'userId' OR frame->>'operationId' IS DISTINCT FROM proof->>'operationId'
   OR NOT COALESCE(proof->>'operationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR reference->>'resourceKind' NOT IN('policy','blueprint') OR NOT COALESCE(reference->>'resourceId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT COALESCE(reference->>'publicationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false)
   OR NOT COALESCE(reference->>'resourceVersion' ~ '^[1-9][0-9]{0,9}$',false) OR NOT COALESCE(frame->>'configurationVersion' ~ '^[1-9][0-9]{0,9}$',false)
   OR (frame->>'configurationVersion')::numeric>(reference->>'resourceVersion')::numeric OR NOT COALESCE(frame->>'configurationHash' ~ '^[a-f0-9]{64}$',false)
   OR NOT COALESCE(frame->>'publicationVersion' ~ '^[1-9][0-9]{0,9}$',false) OR (frame->>'publicationVersion')::numeric<2
   OR NOT COALESCE(frame->>'payloadHash' ~ '^[a-f0-9]{64}$',false) OR NEW.payload IS DISTINCT FROM frame->'payload' OR jsonb_typeof(NEW.payload)<>'object'
   OR octet_length(NEW.payload::text)>262144 OR encode(sha256(convert_to(NEW.payload::text,'UTF8')),'hex') IS DISTINCT FROM frame->>'payloadHash'
   OR NEW.status<>'pending' OR NEW.result IS NOT NULL OR NEW.completed_at IS NOT NULL
   THEN RAISE EXCEPTION 'Original approved content-bound command required' USING ERRCODE='42501';END IF;
  IF reference->>'resourceKind'='policy' THEN
   IF reference->'configurationId' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'Exact GPO reference required' USING ERRCODE='23514';END IF;
  ELSE
   IF NOT COALESCE(reference->>'configurationId' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$',false) THEN RAISE EXCEPTION 'Exact blueprint configuration required' USING ERRCODE='23514';END IF;
  END IF;
  observed=(frame->>'observedAt')::timestamptz;NEW.policy_admission_until=(frame->>'admissionValidUntil')::timestamptz;NEW.policy_delivery_until=(frame->>'deliverUntil')::timestamptz;
  IF observed>policy_device_now()+interval '5 seconds' OR NEW.policy_admission_until<=policy_device_now() OR NEW.policy_admission_until>observed+interval '30 seconds'
   OR NEW.policy_delivery_until<=policy_device_now() OR NEW.policy_delivery_until>observed+interval '300 seconds' OR NEW.policy_admission_until>NEW.policy_delivery_until
   OR NEW.policy_delivery_until>(frame->>'publicationExpiresAt')::timestamptz OR NEW.policy_delivery_until>to_timestamp((actor->>'expiresAt')::double precision)
   OR NEW.policy_delivery_until>to_timestamp((actor->>'authTime')::double precision)+interval '300 seconds'
   THEN RAISE EXCEPTION 'Known bounded command lease required' USING ERRCODE='23514',CONSTRAINT='policy_device_admission_expired';END IF;
  NEW.policy_context=frame-'payload';NEW.policy_actor=actor;NEW.policy_generation=device.policy_generation;NEW.policy_version=1;
  NEW.policy_operation_id=(proof->>'operationId')::uuid;NEW.policy_item_key=COALESCE(reference->>'configurationId','gpo');NEW.issued_at=date_trunc('milliseconds',policy_device_now());
  NEW.policy_dispatched_at=NULL;NEW.policy_delivery_actor=NULL;NEW.policy_report_actor=NULL;
 ELSE
  IF OLD.policy_context IS NULL OR OLD.policy_generation<>device.policy_generation OR NOT policy_device_agent_fresh(actor,NEW.device_id,device.policy_generation)
   OR actor->>'platform' IS DISTINCT FROM device.platform OR proof->>'commandId' IS DISTINCT FROM OLD.id
   THEN RAISE EXCEPTION 'Original bound device command report required' USING ERRCODE='42501';END IF;
  IF (to_jsonb(NEW)-ARRAY['status','result','completed_at','policy_dispatched_at','policy_delivery_actor','policy_report_actor','policy_version'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['status','result','completed_at','policy_dispatched_at','policy_delivery_actor','policy_report_actor','policy_version'])
   OR OLD.policy_version>=2147483647 THEN RAISE EXCEPTION 'Approved command content and lineage are immutable' USING ERRCODE='23514';END IF;
  IF proof->>'action'='dispatched' THEN
   IF OLD.status<>'pending' OR NEW.status<>'pending' OR OLD.policy_delivery_until<=policy_device_now()
    OR NEW.result IS DISTINCT FROM OLD.result OR NEW.completed_at IS DISTINCT FROM OLD.completed_at OR NEW.policy_report_actor IS DISTINCT FROM OLD.policy_report_actor
    THEN RAISE EXCEPTION 'One bounded device dispatch required' USING ERRCODE='23514';END IF;
   NEW.policy_dispatched_at=COALESCE(OLD.policy_dispatched_at,date_trunc('milliseconds',policy_device_now()));NEW.policy_delivery_actor=COALESCE(OLD.policy_delivery_actor,actor);
  ELSIF proof->>'action'='reported' THEN
   IF OLD.status<>'pending' OR NEW.status NOT IN('completed','failed') OR OLD.policy_dispatched_at IS NULL OR octet_length(COALESCE(NEW.result,'null'::jsonb)::text)>65536
    OR NEW.policy_dispatched_at IS DISTINCT FROM OLD.policy_dispatched_at OR NEW.policy_delivery_actor IS DISTINCT FROM OLD.policy_delivery_actor
    THEN RAISE EXCEPTION 'A delivered command has one terminal device report' USING ERRCODE='23514';END IF;
   NEW.completed_at=date_trunc('milliseconds',policy_device_now());NEW.policy_report_actor=actor;
  ELSE RAISE EXCEPTION 'Known original device transition required' USING ERRCODE='42501';END IF;
  NEW.policy_version=OLD.policy_version+1;
 END IF;RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_command_changed() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;scope JSONB;origin policy_device_operations%ROWTYPE;event UUID;
BEGIN
 IF NEW.command<>'update_policy' OR NEW.policy_context IS NULL THEN RETURN NULL;END IF;
 proof=NULLIF(current_setting('opendirectory.policy_device_command',true),'')::jsonb;
 scope=jsonb_build_object('resourceKind',NEW.policy_context->'reference'->'resourceKind','resourceId',NEW.policy_context->'reference'->'resourceId',
  'resourceVersion',NEW.policy_context->'reference'->'resourceVersion','publicationId',NEW.policy_context->'reference'->'publicationId',
  'configurationVersion',NEW.policy_context->'configurationVersion','configurationHash',NEW.policy_context->'configurationHash','publicationVersion',NEW.policy_context->'publicationVersion');
 IF TG_OP='INSERT' THEN
  INSERT INTO policy_device_operations(id,actor,scope) VALUES(NEW.policy_operation_id,NEW.policy_actor,scope) ON CONFLICT(id) DO NOTHING;
  SELECT * INTO origin FROM policy_device_operations WHERE id=NEW.policy_operation_id;
  IF origin.actor IS DISTINCT FROM NEW.policy_actor OR origin.scope IS DISTINCT FROM scope THEN RAISE EXCEPTION 'Captured policy operation cannot exchange actor or content' USING ERRCODE='23514',CONSTRAINT='policy_device_operation';END IF;
 END IF;
 INSERT INTO policy_device_command_audit(command_id,version,operation_id,device_id,device_generation,action,actor,evidence,previous_state,current_state)
 VALUES(NEW.id,NEW.policy_version,NEW.policy_operation_id,NEW.device_id,NEW.policy_generation,proof->>'action',proof->'actor',
  NEW.policy_context-ARRAY['observedAt','admissionValidUntil'],CASE WHEN TG_OP='INSERT' THEN NULL ELSE OLD.status END,NEW.status) RETURNING id INTO event;
 INSERT INTO policy_device_command_outbox(id,command_id,version,action) VALUES(event,NEW.id,NEW.policy_version,proof->>'action');RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_command_commit_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE proof JSONB;actor JSONB;
BEGIN
 IF NEW.command<>'update_policy' OR NEW.policy_context IS NULL THEN RETURN NULL;END IF;
 proof=NULLIF(current_setting('opendirectory.policy_device_command',true),'')::jsonb;actor=proof->'actor';
 IF (actor->>'expiresAt')::numeric<=floor(EXTRACT(epoch FROM policy_device_now())) THEN RAISE EXCEPTION 'Original command credential expired' USING ERRCODE='23514',CONSTRAINT='policy_device_token_expired';END IF;
 IF proof->>'action'='queued' THEN
  IF NOT policy_device_user_fresh(actor) THEN RAISE EXCEPTION 'Original command MFA expired' USING ERRCODE='23514',CONSTRAINT='policy_device_mfa_expired';END IF;
  IF NEW.policy_admission_until<=policy_device_now() OR NEW.policy_delivery_until<=policy_device_now() THEN RAISE EXCEPTION 'Command admission expired' USING ERRCODE='23514',CONSTRAINT='policy_device_admission_expired';END IF;
 ELSE
  IF NOT policy_device_agent_fresh(actor,NEW.device_id,NEW.policy_generation) THEN RAISE EXCEPTION 'Original device credential expired' USING ERRCODE='23514',CONSTRAINT='policy_device_token_expired';END IF;
  IF proof->>'action'='dispatched' AND NEW.policy_delivery_until<=policy_device_now() THEN RAISE EXCEPTION 'Command delivery expired' USING ERRCODE='23514',CONSTRAINT='policy_device_admission_expired';END IF;
 END IF;RETURN NULL;
END; $$;
CREATE OR REPLACE FUNCTION policy_device_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' OR pg_trigger_depth()<2 THEN RAISE EXCEPTION 'Command evidence requires the actual command transition' USING ERRCODE='42501';END IF;RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS policy_device_enrollment_guard ON enrolled_devices;
CREATE TRIGGER policy_device_enrollment_guard BEFORE INSERT OR UPDATE ON enrolled_devices FOR EACH ROW EXECUTE FUNCTION policy_device_enrollment_guard();
DROP TRIGGER IF EXISTS policy_device_command_guard ON mdm_commands;
CREATE TRIGGER policy_device_command_guard BEFORE INSERT OR UPDATE OR DELETE ON mdm_commands FOR EACH ROW EXECUTE FUNCTION policy_device_command_guard();
DROP TRIGGER IF EXISTS policy_device_command_changed ON mdm_commands;
CREATE TRIGGER policy_device_command_changed AFTER INSERT OR UPDATE ON mdm_commands FOR EACH ROW EXECUTE FUNCTION policy_device_command_changed();
DROP TRIGGER IF EXISTS policy_device_command_commit_guard ON mdm_commands;
CREATE CONSTRAINT TRIGGER policy_device_command_commit_guard AFTER INSERT OR UPDATE ON mdm_commands DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION policy_device_command_commit_guard();
DO $$ DECLARE table_name TEXT;BEGIN
 FOREACH table_name IN ARRAY ARRAY['policy_device_operations','policy_device_command_audit','policy_device_command_outbox'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS policy_device_evidence_guard ON %I',table_name);
  EXECUTE format('CREATE TRIGGER policy_device_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION policy_device_evidence_guard()',table_name);
 END LOOP;
END; $$;
COMMIT;
