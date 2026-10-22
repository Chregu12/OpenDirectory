ALTER TABLE identity_automation_jobs ADD COLUMN IF NOT EXISTS rule_id UUID;
ALTER TABLE identity_automation_jobs ADD COLUMN IF NOT EXISTS progress JSONB;
ALTER TABLE identity_automation_schedules ADD COLUMN IF NOT EXISTS rule_id UUID;
ALTER TABLE identity_automation_grants DROP CONSTRAINT IF EXISTS identity_automation_grants_actions_check;
ALTER TABLE identity_automation_grants DROP CONSTRAINT IF EXISTS identity_automation_grants_actions_check1;
DO $$ DECLARE constraint_name TEXT;BEGIN
 FOR constraint_name IN SELECT conname FROM pg_constraint WHERE conrelid='identity_automation_grants'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%actions%' LOOP
  EXECUTE format('ALTER TABLE identity_automation_grants DROP CONSTRAINT %I',constraint_name);
 END LOOP;
END; $$;
ALTER TABLE identity_automation_grants ADD CONSTRAINT identity_automation_grants_actions_check CHECK(cardinality(actions) BETWEEN 1 AND 4 AND actions<@ARRAY['directory.users.export','directory.groups.export','directory.ous.export','licenses.groups.reconcile']::text[]);
ALTER TABLE identity_automation_jobs DROP CONSTRAINT IF EXISTS identity_automation_jobs_status_check;
ALTER TABLE identity_automation_jobs ADD CONSTRAINT identity_automation_jobs_status_check CHECK(status IN('queued','running','retry_wait','succeeded','partial','failed','cancelled'));
DO $$ DECLARE constraint_name TEXT;BEGIN
 FOR constraint_name IN SELECT conname FROM pg_constraint WHERE conrelid='identity_automation_jobs'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%artifact_content IS NOT NULL%' LOOP
  EXECUTE format('ALTER TABLE identity_automation_jobs DROP CONSTRAINT %I',constraint_name);
 END LOOP;
END; $$;
ALTER TABLE identity_automation_jobs DROP CONSTRAINT IF EXISTS identity_automation_artifact_state;
ALTER TABLE identity_automation_jobs ADD CONSTRAINT identity_automation_artifact_state CHECK(
 status IN('succeeded','partial') AND artifact_content IS NOT NULL AND artifact_type IS NOT NULL AND artifact_sha256 IS NOT NULL AND artifact_sha256~'^[a-f0-9]{64}$' AND row_count IS NOT NULL AND row_count BETWEEN 0 AND 10000
 OR status NOT IN('succeeded','partial') AND artifact_content IS NULL AND artifact_type IS NULL AND artifact_sha256 IS NULL AND row_count IS NULL);

CREATE OR REPLACE FUNCTION identity_automation_snapshot(data JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT (data-'artifact_content')-CASE WHEN data->'rule_id'='null'::jsonb THEN 'rule_id' ELSE '' END-CASE WHEN data->'progress'='null'::jsonb THEN 'progress' ELSE '' END;
$$;
CREATE OR REPLACE FUNCTION identity_automation_license_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE actor JSONB;data JSONB;previous JSONB;
BEGIN
 PERFORM identity_authority_owner();data=to_jsonb(NEW);actor=NULLIF(current_setting('opendirectory.company_automation',true),'')::jsonb;
 IF (NEW.action='licenses.groups.reconcile') IS DISTINCT FROM (NEW.rule_id IS NOT NULL) OR NEW.rule_id IS NOT NULL AND NEW.format<>'json'
  THEN RAISE EXCEPTION 'Exact license group job target required' USING ERRCODE='42501';END IF;
 IF TG_OP='UPDATE' AND NEW.rule_id IS DISTINCT FROM OLD.rule_id THEN RAISE EXCEPTION 'Immutable license group job target' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='identity_automation_schedules' THEN RETURN NEW;END IF;
 IF NEW.action<>'licenses.groups.reconcile' THEN
  IF NEW.progress IS NOT NULL OR NEW.status='partial' OR TG_OP='UPDATE' AND OLD.status='running' AND NEW.status='queued'
   THEN RAISE EXCEPTION 'License-only continuation state required' USING ERRCODE='42501';END IF;RETURN NEW;
 END IF;
 IF NEW.progress IS NOT NULL THEN
  IF jsonb_typeof(NEW.progress)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.progress))<>6
   OR NOT NEW.progress ?& ARRAY['runId','retryCount','cycle','completed','total','blocked'] OR NEW.progress->>'runId'<>NEW.id::text
   OR EXISTS(SELECT 1 FROM jsonb_each(NEW.progress) field WHERE field.key<>'runId' AND jsonb_typeof(field.value)<>'number')
   OR NOT(NEW.progress->>'retryCount'~'^[0-9]+$') OR (NEW.progress->>'retryCount')::numeric>NEW.retry_count
   OR NOT(NEW.progress->>'cycle'~'^[1-5]$') OR NOT(NEW.progress->>'completed'~'^[0-9]{1,5}$') OR NOT(NEW.progress->>'total'~'^[0-9]{1,5}$') OR NOT(NEW.progress->>'blocked'~'^[0-9]{1,5}$')
   OR (NEW.progress->>'total')::integer>10000 OR (NEW.progress->>'completed')::integer>(NEW.progress->>'total')::integer OR (NEW.progress->>'blocked')::integer>(NEW.progress->>'completed')::integer
   THEN RAISE EXCEPTION 'Bounded durable license progress required' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_OP='INSERT' AND NEW.progress IS NOT NULL THEN RAISE EXCEPTION 'New license job has no invented progress' USING ERRCODE='42501';END IF;
 IF TG_OP='UPDATE' AND NEW.progress IS DISTINCT FROM OLD.progress THEN
  IF actor->>'kind'<>'application' OR OLD.status<>'running' OR OLD.lease_until<=clock_timestamp() OR NEW.progress IS NULL
   OR (NEW.progress->>'retryCount')::numeric<>NEW.retry_count
   OR OLD.progress IS NOT NULL AND NEW.progress->>'retryCount'=OLD.progress->>'retryCount' AND ((NEW.progress->>'cycle')::integer<(OLD.progress->>'cycle')::integer
    OR NEW.progress->>'cycle'=OLD.progress->>'cycle' AND (NEW.progress->>'completed')::integer<(OLD.progress->>'completed')::integer)
   THEN RAISE EXCEPTION 'Original app lease required for durable progress' USING ERRCODE='42501';END IF;
 END IF;
 IF TG_OP='UPDATE' AND OLD.status='running' AND NEW.status='queued' AND (NEW.progress IS NULL OR actor->>'kind'<>'application' OR NEW.attempt_count<>0
  OR (NEW.progress->>'completed')::integer>=(NEW.progress->>'total')::integer) THEN RAISE EXCEPTION 'Actual unfinished license continuation required' USING ERRCODE='42501';END IF;
 IF NEW.status IN('succeeded','partial') AND (NEW.progress IS NULL OR NEW.progress->>'completed'<>NEW.progress->>'total' OR (NEW.progress->>'retryCount')::numeric<>NEW.retry_count
  OR (NEW.status='partial') IS DISTINCT FROM ((NEW.progress->>'blocked')::integer>0)) THEN RAISE EXCEPTION 'Actual complete or partial license result required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_automation_jobs','identity_automation_schedules'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_automation_license_before BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_license_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_license_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_automation_license_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_automation_license_guard()',relation);
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_license_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_automation_license_guard()'::regprocedure
  AND tgrelid IN('identity_automation_jobs'::regclass,'identity_automation_schedules'::regclass)
  AND (tgname='identity_automation_license_before' AND tgtype=23 AND NOT tgdeferrable OR tgname='identity_automation_license_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred))<>4
 THEN RAISE EXCEPTION 'License automation receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE definition TEXT;BEGIN
 definition=pg_get_functiondef('identity_automation_guard()'::regprocedure);
 definition=replace(definition,'to_jsonb(OLD)-''artifact_content''','identity_automation_snapshot(to_jsonb(OLD))');
 definition=replace(definition,'data-''artifact_content''','identity_automation_snapshot(data)');
 definition=replace(definition,'NEW.status IN(''running'',''succeeded'',''retry_wait'',''failed'',''cancelled'')','NEW.status IN(''running'',''queued'',''succeeded'',''partial'',''retry_wait'',''failed'',''cancelled'')');
 definition=replace(definition,'OLD.status=''failed'' AND NEW.status=''queued''','OLD.status IN(''failed'',''partial'') AND NEW.status=''queued''');
 definition=replace(definition,'NEW.status IN(''running'',''succeeded'',''retry_wait'',''failed'')','NEW.status IN(''running'',''succeeded'',''partial'',''retry_wait'',''failed'')');
 IF strpos(definition,'identity_automation_snapshot(data)')=0 OR strpos(definition,'NEW.status IN(''running'',''queued'',''succeeded'',''partial''')=0 THEN RAISE EXCEPTION 'Original automation receiver required';END IF;
 EXECUTE definition;
 definition=pg_get_functiondef('identity_automation_receiving()'::regprocedure);
 definition=replace(definition,'identity_automation_receiver_manifest)<>5','identity_automation_receiver_manifest)<>8');
 IF strpos(definition,'PERFORM identity_automation_license_receiving();')=0 THEN definition=replace(definition,E'BEGIN\n',E'BEGIN\n PERFORM identity_automation_license_receiving();\n');END IF;
 EXECUTE definition;
END; $$;
DO $$ DECLARE signature TEXT;BEGIN
 FOREACH signature IN ARRAY ARRAY['identity_automation_snapshot(jsonb)','identity_automation_license_guard()','identity_automation_license_receiving()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());
  EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
INSERT INTO identity_automation_receiver_manifest(signature,digest)
 SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY['identity_automation_owner(jsonb)','identity_automation_grant_live(uuid)','identity_automation_guard()','identity_automation_fence()','identity_automation_receiving()',
 'identity_automation_snapshot(jsonb)','identity_automation_license_guard()','identity_automation_license_receiving()']) signature
 ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
