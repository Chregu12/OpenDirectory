BEGIN;

-- Agent credentials are separate from inventory ownership and never authenticate people.
CREATE TABLE IF NOT EXISTS device_agent_connections (
 device_id TEXT PRIMARY KEY REFERENCES devices(id), tenant_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0), bootstrap_hash TEXT UNIQUE,
 bootstrap_expires_at TIMESTAMPTZ, credential_hash TEXT UNIQUE, credential_expires_at TIMESTAMPTZ,
 enrolled_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ, last_seen TIMESTAMPTZ,
 hostname TEXT, platform TEXT, architecture TEXT, os_version TEXT, agent_version TEXT,
 CHECK(bootstrap_hash IS NULL OR bootstrap_hash ~ '^[a-f0-9]{64}$'),
 CHECK(credential_hash IS NULL OR credential_hash ~ '^[a-f0-9]{64}$'),
 CHECK((bootstrap_hash IS NULL)=(bootstrap_expires_at IS NULL)),
 CHECK((credential_hash IS NULL)=(credential_expires_at IS NULL))
);
CREATE TABLE IF NOT EXISTS device_agent_events (
 id UUID PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), tenant_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN('issue','register','revoke')), actor_user_id UUID,
 reason TEXT, correlation_id UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL, source JSONB,
 before_state JSONB, after_state JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS device_agent_events_history ON device_agent_events(tenant_id,device_id,created_at DESC,id DESC);

CREATE OR REPLACE FUNCTION device_agent_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual JSONB;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Retained agent records cannot be removed' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  THEN RAISE EXCEPTION 'Original unexpired agent command required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='device_agent_connections' THEN
  IF to_jsonb(NEW) IS DISTINCT FROM proof->'after' OR (TG_OP='UPDATE' AND to_jsonb(OLD) IS DISTINCT FROM proof->'before')
   THEN RAISE EXCEPTION 'Exact agent state required' USING ERRCODE='42501';END IF;
 ELSE
  IF TG_OP<>'INSERT' OR to_jsonb(NEW) IS DISTINCT FROM proof->'event' THEN RAISE EXCEPTION 'Exact immutable agent event required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_agent_connections;
BEGIN
 PERFORM device_agent_receiving();
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 SELECT * INTO actual FROM device_agent_connections WHERE device_id=NEW.device_id;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  OR to_jsonb(actual) IS DISTINCT FROM proof->'after' OR NOT EXISTS(SELECT 1 FROM devices WHERE id=actual.device_id AND tenant_id=actual.tenant_id)
  OR (proof->'event'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_agent_events WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(device_agent_events)=proof->'event'))
  THEN RAISE EXCEPTION 'Actual agent effect and original deadline required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM device_inventory_receiving();
 FOREACH relation IN ARRAY ARRAY['device_agent_connections','device_agent_events'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_agent_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_agent_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_agent_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_agent_guard()'::regprocedure)
   THEN RAISE EXCEPTION 'Agent row receiver unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='device_agent_connections'::regclass AND tgname='device_agent_commit' AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_agent_commit()'::regprocedure)
  THEN RAISE EXCEPTION 'Agent commit receiver unavailable' USING ERRCODE='42501';END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='devices'::regclass AND tgname='device_agent_inventory_guard' AND tgenabled='O' AND tgfoid='device_agent_inventory_guard()'::regprocedure)
  THEN RAISE EXCEPTION 'Agent inventory receiver unavailable' USING ERRCODE='42501';END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_change(command JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_agent_connections; next_state device_agent_connections; unit devices;
 source JSONB; event device_agent_events; envelope JSONB; moment TIMESTAMPTZ; deadline DOUBLE PRECISION; action TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  OR NULLIF(current_setting('opendirectory.device_agent',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Original agent database owner command required' USING ERRCODE='42501';END IF;
 PERFORM device_agent_receiving();action=command->>'action';source=command->'source';
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' FOR UPDATE;
 SELECT * INTO previous FROM device_agent_connections WHERE device_id=unit.id FOR UPDATE;
 IF unit.id IS NULL OR unit.tenant_id IS NULL THEN RAISE EXCEPTION 'Agent device unavailable' USING ERRCODE='42501';END IF;
 moment=clock_timestamp();next_state=previous;
 next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=coalesce(previous.revision,0)+1;
 IF action IN('issue','revoke') THEN
  deadline=(source->>'validUntil')::double precision;
  IF source->>'schemaVersion' IS DISTINCT FROM '1' OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
   OR source#>>'{tenant,id}' IS DISTINCT FROM unit.tenant_id::text OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId'
   OR deadline IS NULL OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::double precision OR deadline<=extract(epoch FROM moment)
   OR command->>'expectedRevision' IS DISTINCT FROM coalesce(previous.revision,0)::text OR length(command->>'reason') NOT BETWEEN 10 AND 500
   THEN RAISE EXCEPTION 'Original inventory authority and exact agent revision required' USING ERRCODE='42501';END IF;
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;next_state.credential_hash=NULL;next_state.credential_expires_at=NULL;
  next_state.revoked_at=moment;
  IF action='issue' THEN
   IF unit.platform NOT IN('windows','macos','linux') OR unit.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Available desktop platform required' USING ERRCODE='23514';END IF;
   next_state.bootstrap_hash=command->>'newHash';next_state.bootstrap_expires_at=moment+interval '10 minutes';
  END IF;
 ELSIF action='register' THEN
  deadline=extract(epoch FROM previous.bootstrap_expires_at);
  IF previous.bootstrap_hash IS NULL OR previous.bootstrap_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'One-time agent enrollment rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
  next_state.bootstrap_hash=NULL;next_state.bootstrap_expires_at=NULL;
  next_state.credential_hash=command->>'newHash';next_state.credential_expires_at=moment+interval '90 days';next_state.enrolled_at=moment;next_state.revoked_at=NULL;
 ELSIF action='heartbeat' THEN
  deadline=extract(epoch FROM previous.credential_expires_at);
  IF previous.credential_hash IS NULL OR previous.credential_hash IS DISTINCT FROM command->>'tokenHash' OR deadline<=extract(epoch FROM moment)
   OR previous.revoked_at IS NOT NULL OR unit.inventory_lifecycle NOT IN('available','assigned') OR command#>>'{report,platform}' IS DISTINCT FROM unit.platform
   THEN RAISE EXCEPTION 'Agent credential rejected' USING ERRCODE='28000';END IF;
  deadline=least(deadline,extract(epoch FROM moment)+30);
 ELSE RAISE EXCEPTION 'Unsupported agent command' USING ERRCODE='42501';END IF;
 IF action IN('register','heartbeat') THEN
  next_state.last_seen=moment;next_state.hostname=command#>>'{report,hostname}';next_state.platform=command#>>'{report,platform}';
  next_state.architecture=command#>>'{report,architecture}';next_state.os_version=command#>>'{report,osVersion}';next_state.agent_version=command#>>'{report,agentVersion}';
  IF next_state.hostname IS NULL OR length(next_state.hostname) NOT BETWEEN 1 AND 255 OR length(next_state.architecture) NOT BETWEEN 1 AND 40
   OR length(next_state.os_version)>120 OR length(next_state.agent_version) NOT BETWEEN 1 AND 40 THEN RAISE EXCEPTION 'Bounded agent report required' USING ERRCODE='23514';END IF;
 END IF;
 IF deadline IS NULL OR deadline<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Agent deadline elapsed' USING ERRCODE='42501';END IF;
 IF action<>'heartbeat' THEN
  event.id=(command->>'eventId')::uuid;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.action=action;
  event.actor_user_id=(source->>'actorUserId')::uuid;event.reason=command->>'reason';event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;
  event.source=source;
  event.before_state=CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous)-ARRAY['bootstrap_hash','credential_hash'] END;
  event.after_state=to_jsonb(next_state)-ARRAY['bootstrap_hash','credential_hash'];
 END IF;
 envelope=jsonb_build_object('before',CASE WHEN previous.device_id IS NULL THEN NULL ELSE to_jsonb(previous) END,'after',to_jsonb(next_state),'event',CASE WHEN action='heartbeat' THEN NULL ELSE to_jsonb(event) END,'validUntil',deadline,'transactionId',txid_current()::text);
 PERFORM set_config('opendirectory.device_agent',envelope::text,true);
 IF previous.device_id IS NULL THEN INSERT INTO device_agent_connections SELECT next_state.*;
 ELSE UPDATE device_agent_connections SET (tenant_id,revision,bootstrap_hash,bootstrap_expires_at,credential_hash,credential_expires_at,enrolled_at,revoked_at,last_seen,hostname,platform,architecture,os_version,agent_version)=
  (next_state.tenant_id,next_state.revision,next_state.bootstrap_hash,next_state.bootstrap_expires_at,next_state.credential_hash,next_state.credential_expires_at,next_state.enrolled_at,next_state.revoked_at,next_state.last_seen,next_state.hostname,next_state.platform,next_state.architecture,next_state.os_version,next_state.agent_version) WHERE device_id=unit.id;END IF;
 IF action<>'heartbeat' THEN INSERT INTO device_agent_events SELECT event.*;END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_inventory_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 IF (NEW.platform IS DISTINCT FROM OLD.platform OR NEW.inventory_lifecycle IN('maintenance','retired')) AND EXISTS(
  SELECT 1 FROM device_agent_connections WHERE device_id=OLD.id AND
  (bootstrap_hash IS NOT NULL AND bootstrap_expires_at>clock_timestamp() OR credential_hash IS NOT NULL AND credential_expires_at>clock_timestamp() AND revoked_at IS NULL))
  THEN RAISE EXCEPTION 'Revoke the agent connection before changing its platform or retiring the device' USING ERRCODE='23514';END IF;
 RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['device_agent_connections','device_agent_events'] LOOP
  EXECUTE format('DROP TRIGGER IF EXISTS device_agent_guard ON %I',relation);
  EXECUTE format('CREATE TRIGGER device_agent_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION device_agent_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS device_agent_truncate ON %I',relation);
  EXECUTE format('CREATE TRIGGER device_agent_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION device_agent_guard()',relation);
 END LOOP;
END; $$;
DROP TRIGGER IF EXISTS device_agent_commit ON device_agent_connections;
CREATE CONSTRAINT TRIGGER device_agent_commit AFTER INSERT OR UPDATE ON device_agent_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION device_agent_commit();
DROP TRIGGER IF EXISTS device_agent_inventory_guard ON devices;
CREATE TRIGGER device_agent_inventory_guard BEFORE UPDATE ON devices FOR EACH ROW EXECUTE FUNCTION device_agent_inventory_guard();
REVOKE ALL ON FUNCTION device_agent_change(JSONB) FROM PUBLIC;
COMMIT;
