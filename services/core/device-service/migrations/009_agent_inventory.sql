BEGIN;
ALTER TABLE device_agent_connections ADD COLUMN IF NOT EXISTS inventory_report JSONB;

CREATE OR REPLACE FUNCTION device_agent_inventory_valid(facts JSONB) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE part JSONB; field TEXT; value TEXT;
BEGIN
 IF facts IS NULL OR jsonb_typeof(facts) IS DISTINCT FROM 'object' THEN RETURN false;END IF;
 IF NOT facts ?& ARRAY['schemaVersion','cpu','memory','systemDisk','uptimeSeconds'] OR facts-ARRAY['schemaVersion','cpu','memory','systemDisk','uptimeSeconds']<>'{}'::jsonb OR facts->'schemaVersion' IS DISTINCT FROM '1'::jsonb THEN RETURN false;END IF;
 part=facts->'cpu';
 IF part<>'null'::jsonb THEN
  IF jsonb_typeof(part) IS DISTINCT FROM 'object' OR NOT part ?& ARRAY['model','logicalProcessors'] OR part-ARRAY['model','logicalProcessors']<>'{}'::jsonb
   OR jsonb_typeof(part->'model') IS DISTINCT FROM 'string' OR length(part->>'model')>200 OR btrim(part->>'model') IS DISTINCT FROM part->>'model' OR part->>'model' ~ U&'[\0001-\001F\007F-\009F]'
   OR jsonb_typeof(part->'logicalProcessors') IS DISTINCT FROM 'number' THEN RETURN false;END IF;
  IF (part->>'logicalProcessors')::numeric NOT BETWEEN 1 AND 65536 OR trunc((part->>'logicalProcessors')::numeric)<>(part->>'logicalProcessors')::numeric THEN RETURN false;END IF;
 END IF;
 FOREACH field IN ARRAY ARRAY['memory','systemDisk'] LOOP
  part=facts->field;
  IF part<>'null'::jsonb THEN
   IF jsonb_typeof(part) IS DISTINCT FROM 'object' OR NOT part ?& ARRAY['totalBytes','availableBytes'] OR part-ARRAY['totalBytes','availableBytes']<>'{}'::jsonb THEN RETURN false;END IF;
   FOREACH value IN ARRAY ARRAY['totalBytes','availableBytes'] LOOP
    IF jsonb_typeof(part->value) IS DISTINCT FROM 'string' OR part->>value !~ '^(0|[1-9][0-9]{0,18})$' THEN RETURN false;END IF;
    IF (part->>value)::numeric>9223372036854775807 OR (part->>value)::numeric::text IS DISTINCT FROM part->>value THEN RETURN false;END IF;
   END LOOP;
   IF (part->>'totalBytes')::numeric<=0 OR (part->>'availableBytes')::numeric>(part->>'totalBytes')::numeric THEN RETURN false;END IF;
  END IF;
 END LOOP;
 IF facts->'uptimeSeconds'<>'null'::jsonb THEN
  IF jsonb_typeof(facts->'uptimeSeconds') IS DISTINCT FROM 'string' OR facts->>'uptimeSeconds' !~ '^(0|[1-9][0-9]{0,18})$' THEN RETURN false;END IF;
  IF (facts->>'uptimeSeconds')::numeric>9223372036854775807 OR (facts->>'uptimeSeconds')::numeric::text IS DISTINCT FROM facts->>'uptimeSeconds' THEN RETURN false;END IF;
 END IF;
 RETURN true;
END; $$;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_agent_connections'::regclass AND conname='device_agent_inventory_shape') THEN
  ALTER TABLE device_agent_connections ADD CONSTRAINT device_agent_inventory_shape CHECK(inventory_report IS NULL OR (
   jsonb_typeof(inventory_report)='object' AND inventory_report ?& ARRAY['schemaVersion','facts','receivedAt','enrolledAt','revision','platform','agentVersion']
   AND inventory_report-ARRAY['schemaVersion','facts','receivedAt','enrolledAt','revision','platform','agentVersion']='{}'::jsonb
   AND inventory_report->'schemaVersion'='1'::jsonb AND device_agent_inventory_valid(inventory_report->'facts')
   AND jsonb_typeof(inventory_report->'receivedAt')='string' AND jsonb_typeof(inventory_report->'enrolledAt')='string'
   AND jsonb_typeof(inventory_report->'revision')='string' AND inventory_report->>'revision' ~ '^[1-9][0-9]{0,18}$'
   AND inventory_report->>'platform' IN('macos','windows','linux') AND jsonb_typeof(inventory_report->'agentVersion')='string' AND length(inventory_report->>'agentVersion') BETWEEN 1 AND 40));
 END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_inventory_receiving() RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
 PERFORM device_agent_receiving();
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='device_agent_connections'::regclass AND conname='device_agent_inventory_shape' AND contype='c' AND convalidated)
  THEN RAISE EXCEPTION 'Agent inventory shape receiver unavailable' USING ERRCODE='42501';END IF;
END; $$;

CREATE OR REPLACE FUNCTION device_agent_change(command JSONB) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE previous device_agent_connections; next_state device_agent_connections; unit devices;
 source JSONB; event device_agent_events; envelope JSONB; moment TIMESTAMPTZ; deadline DOUBLE PRECISION; action TEXT;
BEGIN
 IF session_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='devices'::regclass) OR current_setting('role',true) NOT IN('none','')
  OR NULLIF(current_setting('opendirectory.device_agent',true),'') IS NOT NULL
  THEN RAISE EXCEPTION 'Original agent database owner command required' USING ERRCODE='42501';END IF;
 PERFORM device_agent_inventory_receiving();action=command->>'action';source=command->'source';
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
 IF command ? 'inventory' THEN
  IF action<>'heartbeat' OR NOT device_agent_inventory_valid(command->'inventory') THEN RAISE EXCEPTION 'Exact bounded agent inventory required' USING ERRCODE='23514';END IF;
  next_state.inventory_report=jsonb_build_object('schemaVersion',1,'facts',command->'inventory','receivedAt',moment,'enrolledAt',next_state.enrolled_at,'revision',next_state.revision::text,'platform',next_state.platform,'agentVersion',next_state.agent_version);
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
 ELSE UPDATE device_agent_connections SET (tenant_id,revision,bootstrap_hash,bootstrap_expires_at,credential_hash,credential_expires_at,enrolled_at,revoked_at,last_seen,hostname,platform,architecture,os_version,agent_version,inventory_report)=
  (next_state.tenant_id,next_state.revision,next_state.bootstrap_hash,next_state.bootstrap_expires_at,next_state.credential_hash,next_state.credential_expires_at,next_state.enrolled_at,next_state.revoked_at,next_state.last_seen,next_state.hostname,next_state.platform,next_state.architecture,next_state.os_version,next_state.agent_version,next_state.inventory_report) WHERE device_id=unit.id;END IF;
 IF action<>'heartbeat' THEN INSERT INTO device_agent_events SELECT event.*;END IF;
END; $$;
CREATE OR REPLACE FUNCTION device_agent_commit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE proof JSONB; actual device_agent_connections;
BEGIN
 PERFORM device_agent_inventory_receiving();
 proof=NULLIF(current_setting('opendirectory.device_agent',true),'')::jsonb;
 SELECT * INTO actual FROM device_agent_connections WHERE device_id=NEW.device_id;
 IF proof IS NULL OR proof->>'transactionId' IS DISTINCT FROM txid_current()::text OR (proof->>'validUntil')::double precision<=extract(epoch FROM clock_timestamp())
  OR to_jsonb(actual) IS DISTINCT FROM proof->'after' OR NOT EXISTS(SELECT 1 FROM devices WHERE id=actual.device_id AND tenant_id=actual.tenant_id)
  OR (proof->'event'<>'null'::jsonb AND NOT EXISTS(SELECT 1 FROM device_agent_events WHERE id=(proof#>>'{event,id}')::uuid AND to_jsonb(device_agent_events)=proof->'event'))
  THEN RAISE EXCEPTION 'Actual agent effect and original deadline required' USING ERRCODE='42501';END IF;
 RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION device_agent_inventory_valid(JSONB),device_agent_inventory_receiving(),device_agent_change(JSONB) FROM PUBLIC;
COMMIT;
