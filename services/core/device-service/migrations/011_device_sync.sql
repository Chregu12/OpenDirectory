BEGIN;
CREATE TABLE IF NOT EXISTS device_sync_requests (
 id UUID PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), tenant_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0), generation TEXT NOT NULL CHECK(generation ~ '^[a-f0-9]{32}$'),
 status TEXT NOT NULL CHECK(status IN('queued','claimed','completed','cancelled')), attempts INT NOT NULL CHECK(attempts BETWEEN 0 AND 3),
 actor_user_id UUID NOT NULL, reason TEXT NOT NULL, source JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
 lease_hash TEXT CHECK(lease_hash ~ '^[a-f0-9]{64}$'), lease_expires_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ, result JSONB,
 CHECK((lease_hash IS NULL)=(lease_expires_at IS NULL)),
 CHECK((status='completed')=(completed_at IS NOT NULL)),
 CHECK((status='completed')=(result IS NOT NULL)),
 CHECK((status='claimed')=(lease_hash IS NOT NULL)),
 CHECK(status<>'claimed' OR attempts>0),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX IF NOT EXISTS device_sync_history ON device_sync_requests(tenant_id,device_id,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS device_sync_events (
 id UUID PRIMARY KEY, request_id UUID NOT NULL REFERENCES device_sync_requests(id), device_id TEXT NOT NULL REFERENCES devices(id), tenant_id UUID NOT NULL,
 action TEXT NOT NULL CHECK(action IN('queued','claimed','completed','cancelled')), actor_user_id UUID, reason TEXT,
 correlation_id UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL, before_state JSONB, after_state JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS device_sync_event_history ON device_sync_events(tenant_id,request_id,created_at,id);
CREATE OR REPLACE FUNCTION device_sync_generation(connection device_agent_connections) RETURNS TEXT LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN connection.enrolled_at IS NULL THEN NULL ELSE md5(jsonb_build_object('deviceId',connection.device_id,'tenantId',connection.tenant_id,'enrolledAt',connection.enrolled_at,'expiresAt',connection.credential_expires_at)::text) END;
$$;
CREATE OR REPLACE FUNCTION device_sync_status(request device_sync_requests,connection device_agent_connections,moment TIMESTAMPTZ) RETURNS TEXT LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN request.status IN('completed','cancelled') THEN request.status
 WHEN connection.credential_hash IS NULL OR connection.revoked_at IS NOT NULL OR connection.credential_expires_at<=moment OR request.generation IS DISTINCT FROM device_sync_generation(connection) THEN 'connection_changed'
 WHEN request.expires_at<=moment THEN 'expired'
 WHEN request.status='claimed' AND request.lease_expires_at<=moment AND request.attempts>=3 THEN 'failed'
 WHEN request.status='claimed' AND request.lease_expires_at<=moment THEN 'queued' ELSE request.status END;
$$;
CREATE OR REPLACE FUNCTION device_sync_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB;
BEGIN
 IF TG_OP IN('DELETE','TRUNCATE') THEN RAISE EXCEPTION 'Sync history is retained' USING ERRCODE='42501';END IF;
 proof=NULLIF(current_setting('opendirectory.device_sync',true),'')::jsonb;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) THEN RAISE EXCEPTION 'Original sync command required' USING ERRCODE='42501';END IF;
 IF TG_TABLE_NAME='device_sync_requests' THEN
  IF to_jsonb(NEW) IS DISTINCT FROM proof->'after' OR (TG_OP='UPDATE' AND to_jsonb(OLD) IS DISTINCT FROM proof->'before') THEN RAISE EXCEPTION 'Exact sync effect required' USING ERRCODE='42501';END IF;
 ELSE
  IF TG_OP<>'INSERT' OR to_jsonb(NEW) IS DISTINCT FROM proof->'event' THEN RAISE EXCEPTION 'Exact immutable sync event required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION device_sync_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE relation TEXT;
BEGIN
 PERFORM device_compliance_receiving();
 FOREACH relation IN ARRAY ARRAY['device_sync_requests','device_sync_events'] LOOP
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_sync_guard' AND tgtype=31 AND tgenabled='O' AND tgfoid='device_sync_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_sync_truncate' AND tgtype=34 AND tgenabled='O' AND tgfoid='device_sync_guard()'::regprocedure)
   OR NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass(relation) AND tgname='device_sync_commit' AND tgtype=21 AND tgenabled='O' AND tgdeferrable AND tginitdeferred AND tgfoid='device_sync_commit()'::regprocedure) THEN RAISE EXCEPTION 'Sync receivers unavailable' USING ERRCODE='42501';END IF;
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION device_sync_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_sync_requests; connection device_agent_connections;
BEGIN
 PERFORM device_sync_receiving();proof=NULLIF(current_setting('opendirectory.device_sync',true),'')::jsonb;
 SELECT * INTO actual FROM device_sync_requests WHERE id=(proof#>>'{after,id}')::uuid;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::numeric<=extract(epoch FROM clock_timestamp()) OR to_jsonb(actual) IS DISTINCT FROM proof->'after'
  OR NOT EXISTS(SELECT 1 FROM device_sync_events event WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(event)=proof->'event') THEN RAISE EXCEPTION 'Actual sync state and retained event required' USING ERRCODE='42501';END IF;
 IF actual.status='completed' THEN
  SELECT * INTO connection FROM device_agent_connections WHERE device_id=actual.device_id;
  IF actual.generation IS DISTINCT FROM device_sync_generation(connection) OR actual.result IS DISTINCT FROM jsonb_build_object('agentRevision',connection.revision::text,'receivedAt',connection.last_seen,'inventory',connection.inventory_report,'security',connection.security_report,'compliance',connection.compliance_report) THEN RAISE EXCEPTION 'Actual atomic agent reports required' USING ERRCODE='42501';END IF;
 END IF;
 RETURN NEW;
END; $$;
DO $$ DECLARE relation TEXT;BEGIN
 FOREACH relation IN ARRAY ARRAY['device_sync_requests','device_sync_events'] LOOP
  EXECUTE format('CREATE OR REPLACE TRIGGER device_sync_guard BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION device_sync_guard()',relation);
  EXECUTE format('CREATE OR REPLACE TRIGGER device_sync_truncate BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION device_sync_guard()',relation);
  EXECUTE format('DROP TRIGGER IF EXISTS device_sync_commit ON %I',relation);
  EXECUTE format('CREATE CONSTRAINT TRIGGER device_sync_commit AFTER INSERT OR UPDATE ON %I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION device_sync_commit()',relation);
 END LOOP;
END; $$;
CREATE OR REPLACE FUNCTION device_sync_change(command JSONB) RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_sync_requests; next_state device_sync_requests; event device_sync_events; connection device_agent_connections; unit devices;
 source JSONB=command->'source'; action TEXT=command->>'action'; moment TIMESTAMPTZ; deadline NUMERIC; agent_proof JSONB; active TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','') OR NULLIF(current_setting('opendirectory.device_sync',true),'') IS NOT NULL THEN RAISE EXCEPTION 'Original database owner sync command required' USING ERRCODE='42501';END IF;
 PERFORM device_sync_receiving();
 SELECT * INTO unit FROM devices WHERE id=command->>'deviceId' FOR UPDATE;
 SELECT * INTO connection FROM device_agent_connections WHERE device_id=unit.id FOR UPDATE;
 moment=clock_timestamp();
 IF unit.id IS NULL OR unit.tenant_id IS NULL THEN RAISE EXCEPTION 'Sync device unavailable' USING ERRCODE='28000';END IF;
 IF action IN('queued','cancelled') THEN
  deadline=(source->>'validUntil')::numeric;
  IF source->>'schemaVersion' IS DISTINCT FROM '1' OR source#>>'{tenant,id}' IS DISTINCT FROM unit.tenant_id::text OR source#>>'{context,userId}' IS DISTINCT FROM source->>'actorUserId' OR source->'target' IS DISTINCT FROM 'null'::jsonb OR NOT coalesce(source->'permissions' ? 'devices.inventory.create',false)
   OR deadline IS NULL OR deadline<=extract(epoch FROM moment) OR deadline>extract(epoch FROM moment)+300 OR deadline>(source->>'expiresAt')::numeric OR length(command->>'reason') NOT BETWEEN 10 AND 500 THEN RAISE EXCEPTION 'Original sync human authority required' USING ERRCODE='42501';END IF;
 ELSE
  IF connection.credential_hash IS NULL OR connection.credential_hash IS DISTINCT FROM command->>'tokenHash' OR connection.revoked_at IS NOT NULL OR connection.credential_expires_at<=moment THEN RAISE EXCEPTION 'Current device credential required' USING ERRCODE='28000';END IF;
  deadline=least(extract(epoch FROM connection.credential_expires_at),extract(epoch FROM moment)+30);
 END IF;
 IF action='claimed' THEN
  SELECT * INTO previous FROM device_sync_requests WHERE device_id=unit.id AND tenant_id=unit.tenant_id AND device_sync_status(device_sync_requests,connection,moment)='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE;
  IF previous.id IS NULL THEN RETURN NULL;END IF;
 ELSE
  IF action<>'queued' THEN SELECT * INTO previous FROM device_sync_requests WHERE id=(command->>'id')::uuid AND device_id=unit.id AND tenant_id=unit.tenant_id FOR UPDATE;IF previous.id IS NULL THEN RAISE EXCEPTION 'Sync request unavailable' USING ERRCODE='23514';END IF;END IF;
 END IF;
 IF action='queued' THEN
  IF connection.credential_hash IS NULL OR connection.revoked_at IS NOT NULL OR connection.credential_expires_at<=moment OR command->>'generation' IS DISTINCT FROM device_sync_generation(connection) OR unit.inventory_lifecycle NOT IN('available','assigned') THEN RAISE EXCEPTION 'Current enrolled connection required' USING ERRCODE='23514';END IF;
  IF EXISTS(SELECT 1 FROM device_sync_requests request WHERE request.device_id=unit.id AND request.tenant_id=unit.tenant_id AND device_sync_status(request,connection,moment) IN('queued','claimed')) THEN RAISE EXCEPTION 'A current sync request already exists' USING ERRCODE='23514';END IF;
  next_state.id=(command->>'id')::uuid;next_state.device_id=unit.id;next_state.tenant_id=unit.tenant_id;next_state.revision=1;next_state.generation=device_sync_generation(connection);next_state.status='queued';next_state.attempts=0;next_state.actor_user_id=(source->>'actorUserId')::uuid;next_state.reason=command->>'reason';next_state.source=source;next_state.created_at=moment;next_state.expires_at=least(to_timestamp(deadline),connection.credential_expires_at,moment+interval '5 minutes');
 ELSE
  next_state=previous;next_state.revision=previous.revision+1;next_state.status=action;
  active=device_sync_status(previous,connection,moment);
  IF action='cancelled' THEN
   IF command->>'expectedRevision' IS DISTINCT FROM previous.revision::text OR previous.status NOT IN('queued','claimed') THEN RAISE EXCEPTION 'Current cancellable sync revision required' USING ERRCODE='23514';END IF;
   next_state.lease_hash=NULL;next_state.lease_expires_at=NULL;
  ELSIF action='claimed' THEN
   IF active<>'queued' OR previous.attempts>=3 OR command->>'leaseHash' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'Eligible sync lease required' USING ERRCODE='23514';END IF;
   next_state.attempts=previous.attempts+1;next_state.lease_hash=command->>'leaseHash';next_state.lease_expires_at=least(previous.expires_at,moment+interval '45 seconds');deadline=least(deadline,extract(epoch FROM previous.expires_at));
  ELSIF action='completed' THEN
   IF active<>'claimed' OR previous.lease_hash IS DISTINCT FROM command->>'leaseHash' OR previous.lease_expires_at<=moment THEN RAISE EXCEPTION 'Current sync lease required' USING ERRCODE='23514';END IF;
   agent_proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
   IF agent_proof IS NULL OR agent_proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR agent_proof->'after' IS DISTINCT FROM to_jsonb(connection)
    OR connection.inventory_report IS NULL OR connection.security_report IS NULL OR connection.compliance_report IS NULL
    OR (connection.inventory_report->>'receivedAt')::timestamptz IS DISTINCT FROM connection.last_seen OR (connection.security_report->>'receivedAt')::timestamptz IS DISTINCT FROM connection.last_seen
    OR (connection.inventory_report->>'enrolledAt')::timestamptz IS DISTINCT FROM connection.enrolled_at OR (connection.security_report->>'enrolledAt')::timestamptz IS DISTINCT FROM connection.enrolled_at
    OR connection.inventory_report->>'revision' IS DISTINCT FROM connection.revision::text OR connection.security_report->>'revision' IS DISTINCT FROM connection.revision::text THEN RAISE EXCEPTION 'New actual reports in the same transaction required' USING ERRCODE='42501';END IF;
   deadline=least(deadline,extract(epoch FROM previous.expires_at),extract(epoch FROM previous.lease_expires_at));next_state.completed_at=moment;next_state.lease_hash=NULL;next_state.lease_expires_at=NULL;
   next_state.result=jsonb_build_object('agentRevision',connection.revision::text,'receivedAt',connection.last_seen,'inventory',connection.inventory_report,'security',connection.security_report,'compliance',connection.compliance_report);
  ELSE RAISE EXCEPTION 'Unsupported sync operation' USING ERRCODE='42501';END IF;
 END IF;
 next_state.updated_at=moment;event.id=(command->>'eventId')::uuid;event.request_id=next_state.id;event.device_id=unit.id;event.tenant_id=unit.tenant_id;event.action=action;event.actor_user_id=CASE WHEN action IN('queued','cancelled') THEN (source->>'actorUserId')::uuid END;event.reason=CASE WHEN action IN('queued','cancelled') THEN command->>'reason' END;event.correlation_id=(command->>'correlationId')::uuid;event.created_at=moment;event.before_state=CASE WHEN previous.id IS NULL THEN NULL ELSE to_jsonb(previous)-ARRAY['lease_hash','source'] END;event.after_state=to_jsonb(next_state)-ARRAY['lease_hash','source'];
 PERFORM set_config('opendirectory.device_sync',jsonb_build_object('transactionId',txid_current()::text,'validUntil',deadline,'before',CASE WHEN previous.id IS NULL THEN NULL ELSE to_jsonb(previous) END,'after',to_jsonb(next_state),'event',to_jsonb(event))::text,true);
 IF previous.id IS NULL THEN INSERT INTO device_sync_requests SELECT next_state.*;ELSE UPDATE device_sync_requests SET (revision,status,attempts,updated_at,lease_hash,lease_expires_at,completed_at,result)=(next_state.revision,next_state.status,next_state.attempts,next_state.updated_at,next_state.lease_hash,next_state.lease_expires_at,next_state.completed_at,next_state.result) WHERE id=next_state.id;END IF;
 INSERT INTO device_sync_events SELECT event.*;RETURN next_state.id;
END; $$;
REVOKE ALL ON FUNCTION device_sync_generation(device_agent_connections),device_sync_status(device_sync_requests,device_agent_connections,TIMESTAMPTZ),device_sync_receiving(),device_sync_change(JSONB) FROM PUBLIC;
COMMIT;
