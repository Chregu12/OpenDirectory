ALTER TABLE identity_automation_schedules ADD COLUMN IF NOT EXISTS on_change BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE identity_automation_schedules ADD COLUMN IF NOT EXISTS source_checkpoint JSONB;
ALTER TABLE identity_automation_schedules ADD COLUMN IF NOT EXISTS source_job_id UUID;
ALTER TABLE identity_automation_schedules ALTER COLUMN interval_seconds DROP NOT NULL;
ALTER TABLE identity_automation_jobs ADD COLUMN IF NOT EXISTS event_source JSONB;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='identity_automation_schedules'::regclass AND conname='identity_automation_change_definition') THEN
  ALTER TABLE identity_automation_schedules ADD CONSTRAINT identity_automation_change_definition CHECK(
   on_change AND action IN('directory.groups.reconcile','licenses.groups.reconcile') AND interval_seconds IS NULL
   OR NOT on_change AND interval_seconds IS NOT NULL AND interval_seconds BETWEEN 60 AND 2592000 AND source_checkpoint IS NULL AND source_job_id IS NULL);
  ALTER TABLE identity_automation_schedules ADD CONSTRAINT identity_automation_change_job FOREIGN KEY(source_job_id) REFERENCES identity_automation_jobs(id) DEFERRABLE INITIALLY DEFERRED;
 END IF;
END; $$;
CREATE UNIQUE INDEX IF NOT EXISTS identity_automation_change_target ON identity_automation_schedules(grant_id,action,rule_id) WHERE enabled AND on_change;
CREATE OR REPLACE FUNCTION identity_automation_snapshot(data JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT (data-'artifact_content')-CASE WHEN data->'rule_id'='null'::jsonb THEN 'rule_id' ELSE '' END-CASE WHEN data->'progress'='null'::jsonb THEN 'progress' ELSE '' END
 -CASE WHEN data->'on_change'='false'::jsonb THEN 'on_change' ELSE '' END-CASE WHEN data->'source_checkpoint'='null'::jsonb THEN 'source_checkpoint' ELSE '' END
 -CASE WHEN data->'source_job_id'='null'::jsonb THEN 'source_job_id' ELSE '' END-CASE WHEN data->'event_source'='null'::jsonb THEN 'event_source' ELSE '' END;
$$;
CREATE OR REPLACE FUNCTION identity_automation_change_identity(collection UUID,tenant UUID) RETURNS JSONB LANGUAGE plpgsql VOLATILE SECURITY DEFINER AS $$
DECLARE revision TEXT;cutoffs TEXT;
BEGIN
 IF identity_tenant_id('group',collection) IS DISTINCT FROM tenant THEN RAISE EXCEPTION 'Actual own change source required' USING ERRCODE='42501';END IF;
 revision=identity_group_source_revision(collection);
 SELECT count(*)::text INTO cutoffs FROM identity_membership_review_audit audit JOIN identity_membership_review_policies policy ON policy.id=audit.policy_id
  WHERE policy.group_id=collection AND jsonb_typeof(audit.details->'deadline_at')='string' AND (audit.details->>'deadline_at')::timestamptz<=identity_membership_review_now();
 RETURN jsonb_build_object('groupId',collection,'revision',revision,'deadlineRevision',cutoffs);
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_change_key(source JSONB) RETURNS JSONB LANGUAGE sql IMMUTABLE AS $$
 SELECT jsonb_build_object('identity',source->'identity','policy',CASE WHEN source->'policy'='null'::jsonb THEN 'null'::jsonb ELSE (source->'policy')-ARRAY['grantId','scheduleId','scheduleRevision','tokenIdentifierHash','validUntil'] END);
$$;
CREATE OR REPLACE FUNCTION identity_automation_change_guard() RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE actor JSONB;plan identity_automation_schedules;job identity_automation_jobs;permission identity_automation_grants;source JSONB;policy JSONB;captured BIGINT;
BEGIN
 IF TG_TABLE_NAME='identity_automation_schedules' THEN
  IF TG_OP='UPDATE' AND NEW.on_change IS DISTINCT FROM OLD.on_change THEN RAISE EXCEPTION 'Immutable change subscription required' USING ERRCODE='42501';END IF;
  IF NOT NEW.on_change THEN RETURN NEW;END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.source_checkpoint IS NOT NULL OR NEW.source_job_id IS NOT NULL THEN RAISE EXCEPTION 'No invented initial change receipt' USING ERRCODE='42501';END IF;RETURN NEW;
  END IF;
  IF NEW.source_checkpoint IS NOT DISTINCT FROM OLD.source_checkpoint AND NEW.source_job_id IS NOT DISTINCT FROM OLD.source_job_id THEN RETURN NEW;END IF;
  IF NOT OLD.enabled OR NOT NEW.enabled OR NEW.source_checkpoint IS NULL OR NEW.source_job_id IS NULL
   OR identity_automation_change_key(NEW.source_checkpoint) IS NOT DISTINCT FROM identity_automation_change_key(OLD.source_checkpoint)
   THEN RAISE EXCEPTION 'Actual changed source required' USING ERRCODE='42501';END IF;
  plan=OLD;source=NEW.source_checkpoint;captured=OLD.revision;
  SELECT * INTO job FROM identity_automation_jobs WHERE id=NEW.source_job_id;
  IF job.id IS NULL OR job.schedule_id<>plan.id OR job.event_source IS DISTINCT FROM source
   OR NOT EXISTS(SELECT 1 FROM identity_automation_events event JOIN identity_automation_outbox box ON box.id=event.id AND box.status='pending'
    WHERE event.entity='job' AND event.entity_id=job.id AND event.revision=1 AND event.transaction_id=txid_current() AND event.snapshot->'event_source'=source)
   THEN RAISE EXCEPTION 'Atomic original change job and checkpoint required' USING ERRCODE='42501';END IF;
 ELSE
  IF TG_OP='UPDATE' AND NEW.event_source IS DISTINCT FROM OLD.event_source THEN RAISE EXCEPTION 'Immutable original job change source required' USING ERRCODE='42501';END IF;
  IF TG_OP='UPDATE' THEN RETURN NEW;END IF;
  IF NEW.event_source IS NULL THEN
   IF EXISTS(SELECT 1 FROM identity_automation_schedules WHERE id=NEW.schedule_id AND on_change) THEN RAISE EXCEPTION 'Change jobs require original source evidence' USING ERRCODE='42501';END IF;RETURN NEW;
  END IF;
  job=NEW;source=NEW.event_source;
  SELECT * INTO plan FROM identity_automation_schedules WHERE id=job.schedule_id;
  IF plan.id IS NULL OR NOT plan.on_change OR NOT plan.enabled OR plan.action<>job.action OR plan.rule_id<>job.rule_id OR plan.grant_id<>job.grant_id
   OR plan.tenant_id<>job.tenant_id OR job.status<>'queued' OR TG_WHEN='AFTER' AND(plan.source_job_id IS DISTINCT FROM job.id OR plan.source_checkpoint IS DISTINCT FROM source)
   THEN RAISE EXCEPTION 'Exact live change subscription required' USING ERRCODE='42501';END IF;
  captured=CASE WHEN TG_WHEN='AFTER' THEN plan.revision-1 ELSE plan.revision END;
 END IF;
 actor=NULLIF(current_setting('opendirectory.company_automation',true),'')::jsonb;
 SELECT * INTO permission FROM identity_automation_grants WHERE id=plan.grant_id;
 IF actor->>'kind' IS DISTINCT FROM 'application' OR permission.issuer IS DISTINCT FROM actor->>'issuer' OR permission.client_id IS DISTINCT FROM actor->>'clientId'
  OR permission.client_revision::text IS DISTINCT FROM actor->>'clientRevision' OR NOT identity_automation_grant_live(permission.id)
  OR (actor->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR jsonb_typeof(source)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(source))<>4
  OR source->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR source->>'scheduleRevision' IS DISTINCT FROM captured::text
  OR source->'identity' IS DISTINCT FROM identity_automation_change_identity((source#>>'{identity,groupId}')::uuid,plan.tenant_id)
  THEN RAISE EXCEPTION 'Current original app change observation required' USING ERRCODE='42501';END IF;
 IF plan.action='directory.groups.reconcile' THEN
  IF source->'policy' IS DISTINCT FROM 'null'::jsonb OR source#>>'{identity,groupId}' IS DISTINCT FROM plan.rule_id::text
   OR NOT EXISTS(SELECT 1 FROM identity_company_group_rules setting JOIN identity_company_group_rule_events event ON event.id=setting.last_event_id
    JOIN identity_company_group_rule_outbox box ON box.id=event.id AND box.status='pending' AND box.fingerprint=encode(sha256(convert_to(to_jsonb(event)::text,'UTF8')),'hex')
    WHERE setting.group_id=plan.rule_id AND setting.tenant_id=plan.tenant_id AND event.result=to_jsonb(setting))
   THEN RAISE EXCEPTION 'Actual original saved group rule required' USING ERRCODE='42501';END IF;
 ELSE
  policy=source->'policy';
  IF jsonb_typeof(policy) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(policy))<>16
   OR NOT policy ?& ARRAY['schemaVersion','companyAutomationChangeProtocol','allocationMode','grantId','scheduleId','scheduleRevision','ruleId','tenantId','groupId','poolId','ruleRevision','ruleStatus','poolRevision','availableSeats','validUntil','tokenIdentifierHash']
   OR EXISTS(SELECT 1 FROM jsonb_each(policy) field WHERE field.key NOT IN('schemaVersion','companyAutomationChangeProtocol','availableSeats','validUntil') AND jsonb_typeof(field.value)<>'string')
   OR policy->'schemaVersion' IS DISTINCT FROM '1'::jsonb OR policy->'companyAutomationChangeProtocol' IS DISTINCT FROM '1'::jsonb
   OR policy->>'allocationMode' IS DISTINCT FROM 'local-only' OR policy->>'ruleStatus' NOT IN('active','unlinked')
   OR policy->>'grantId' IS DISTINCT FROM plan.grant_id::text OR policy->>'scheduleId' IS DISTINCT FROM plan.id::text OR policy->>'scheduleRevision' IS DISTINCT FROM captured::text
   OR policy->>'ruleId' IS DISTINCT FROM plan.rule_id::text OR policy->>'tenantId' IS DISTINCT FROM plan.tenant_id::text OR policy->>'groupId' IS DISTINCT FROM source#>>'{identity,groupId}'
   OR NOT(policy->>'poolId'~'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$') OR NOT(policy->>'ruleRevision'~'^[1-9][0-9]{0,18}$') OR NOT(policy->>'poolRevision'~'^[1-9][0-9]{0,18}$')
   OR (policy->>'ruleRevision')::numeric>9223372036854775807 OR (policy->>'poolRevision')::numeric>9223372036854775807
   OR jsonb_typeof(policy->'availableSeats') IS DISTINCT FROM 'number' OR NOT(policy->>'availableSeats'~'^[0-9]{1,5}$') OR (policy->>'availableSeats')::integer>10000
   OR jsonb_typeof(policy->'validUntil') IS DISTINCT FROM 'number' OR (policy->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp())
   OR (policy->>'validUntil')::numeric>(actor->>'validUntil')::numeric OR to_timestamp((policy->>'validUntil')::double precision)>permission.expires_at
   OR policy->>'tokenIdentifierHash' IS DISTINCT FROM encode(sha256(convert_to(actor->>'tokenId','UTF8')),'hex')
   THEN RAISE EXCEPTION 'Original bounded local pool observation required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION identity_automation_change_receiving() RETURNS VOID LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgfoid='identity_automation_change_guard()'::regprocedure
  AND tgrelid IN('identity_automation_jobs'::regclass,'identity_automation_schedules'::regclass)
  AND(tgname='identity_automation_change_before' AND tgtype=23 AND NOT tgdeferrable OR tgname='identity_automation_change_commit' AND tgtype=21 AND tgdeferrable AND tginitdeferred))<>4
  THEN RAISE EXCEPTION 'Original change dispatch receiving unavailable' USING ERRCODE='42501';END IF;
END; $$;
DO $$ DECLARE relation TEXT;definition TEXT;signature TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['identity_automation_jobs','identity_automation_schedules'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER identity_automation_change_before BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION identity_automation_change_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS identity_automation_change_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER identity_automation_change_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION identity_automation_change_guard()',relation);
 END LOOP;
 definition=pg_get_functiondef('identity_automation_receiving()'::regprocedure);
 definition=replace(definition,'identity_automation_receiver_manifest)<>8','identity_automation_receiver_manifest)<>12');
 IF strpos(definition,'PERFORM identity_automation_change_receiving();')=0 THEN definition=replace(definition,E'BEGIN\n',E'BEGIN\n PERFORM identity_automation_change_receiving();\n');END IF;EXECUTE definition;
 FOREACH signature IN ARRAY ARRAY['identity_automation_snapshot(jsonb)','identity_automation_change_identity(uuid,uuid)','identity_automation_change_key(jsonb)','identity_automation_change_guard()','identity_automation_change_receiving()'] LOOP
  EXECUTE format('ALTER FUNCTION %s SET search_path TO %I,pg_catalog,pg_temp',signature,current_schema());EXECUTE format('ALTER FUNCTION %s SET timezone TO %L',signature,'UTC');EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',signature);
 END LOOP;
END; $$;
INSERT INTO identity_automation_receiver_manifest SELECT signature,md5(pg_get_functiondef(to_regprocedure(signature))) FROM unnest(ARRAY[
 'identity_automation_change_identity(uuid,uuid)','identity_automation_change_key(jsonb)','identity_automation_change_guard()','identity_automation_change_receiving()']) signature ON CONFLICT(signature) DO UPDATE SET digest=EXCLUDED.digest;
UPDATE identity_automation_receiver_manifest SET digest=md5(pg_get_functiondef(to_regprocedure(signature)));
